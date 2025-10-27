//PLEASE READ "read_me.md" BEFORE RUNNING SCRIPT//
//THIS IS AN INTEGRATED PYTHON SCRIPT THAT DEFEND AGAINST BRUTE FORCE, DOS AND SQLI INJECTION ATTACK//
//RUN IT IN A SAFE ENVIRONMENT//
//ENJOY!!!//

#!/usr/bin/env python3
"""
edr_manager.py
Merged EDR manager integrating:
 - brute-force detector (Scapy-based packet sniffing)
 - simple DoS detector (ss-based connection counting + ufw blocking)
 - SQLi detector (Scapy-based heuristic detector)
Usage:
  sudo python3 edr_manager.py [--no-dry-run] [--verbose]
Notes:
 - Default is dry-run (no iptables/ufw changes). Use --no-dry-run to allow actual blocking.
 - Scapy sniffing usually requires root privileges.
"""
import argparse
import logging
import json
import time
import threading
import queue
import os
import shlex
import subprocess
import re
import urllib.parse
import html
from datetime import datetime
from collections import Counter, defaultdict

# Import scapy for packet sniffing
try:
    from scapy.all import sniff, TCP, IP, Raw
except Exception:
    sniff = None  # handle later if not installed

# -----------------------------
# Configuration (edit as needed)
# -----------------------------
EVENT_LOG = "/tmp/edr_events.jsonl"   # local JSONL event store
DRY_RUN_DEFAULT = True
POLL_INTERVAL = 1.0  # seconds

# Brute-force detector config (based on your script)
BF_PORT = 3000              # Juice Shop port
BF_THRESHOLD = 10           # max login attempts in WINDOW
BF_WINDOW = 60              # seconds for counting attempts

# DoS detector config (based on your script)
JUICE_PORT = 3000
CHECK_INTERVAL = 5
CONN_THRESHOLD = 30
BLOCK_DURATION = 3600
UFW_BLOCK_CMD = "ufw insert 1 deny from {ip} to any"
LOG_PATH = "/var/log/ufw-dos-guard.log"

# SQLi detector config / patterns
SQLI_PATTERNS = [
    r"(?i)\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",   # or 1=1
    r"(?i)['\"].*--",                                             # ' ... --
    r"(?i)union\s+select",                                        # union select
    r"(?i)exec\(",                                                # exec(
    r"(?i)information_schema",                                    # reference to information_schema
    r"(?i)benchmark\(",                                           # mysql benchmark-based injection
    r"(?i)drop\s+table",                                          # destructive keywords (flag but don't execute)
    r"(?i)\bselect\b.*\bfrom\b"                                   # select ... from
]
SQLI_COMPILED = [re.compile(p) for p in SQLI_PATTERNS]

# -----------------------------
# Utilities
# -----------------------------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def write_event(event):
    """Append event as JSONL"""
    try:
        os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
    except Exception:
        pass
    with open(EVENT_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")

def make_event(source, evt_type, severity, data):
    return {
        "timestamp": now_iso(),
        "source": source,
        "type": evt_type,
        "severity": severity,
        "data": data
    }

def run_cmd(cmd):
    """Run shell command and return stdout (text)."""
    try:
        result = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        return result.stdout
    except Exception as e:
        # best-effort local logging for the dos detector
        try:
            with open(LOG_PATH, "a") as f:
                f.write(f"{time.ctime()}: Command failure: {e}\n")
        except Exception:
            pass
        return ""

# -----------------------------
# Responder (centralised safe actions)
# -----------------------------
class Responder:
    def __init__(self, dry_run=True, logger=None):
        self.dry_run = dry_run
        self.logger = logger or logging.getLogger("responder")

    def block_ip(self, ip, reason="blocked-by-edr", duration=3600):
        event = make_event("responder", "block_ip", "high", {"ip": ip, "reason": reason, "duration": duration})
        write_event(event)
        self.logger.info("Request to block IP: %s (dry_run=%s)", ip, self.dry_run)
        if not self.dry_run:
            # Use UFW by default for blocking (matches the DoS script's approach).
            cmd = UFW_BLOCK_CMD.format(ip=ip)
            self.logger.info("Running: %s", cmd)
            try:
                subprocess.run(shlex.split(cmd), check=False)
            except Exception as e:
                self.logger.exception("Failed to run block command: %s", e)

    def alert(self, message, meta=None):
        event = make_event("responder", "alert", "medium", {"message": message, "meta": meta or {}})
        write_event(event)
        self.logger.warning("ALERT: %s | meta=%s", message, meta)

    def quarantine_file(self, path):
        event = make_event("responder", "quarantine", "high", {"path": path})
        write_event(event)
        self.logger.info("Quarantine requested for %s (dry_run=%s)", path, self.dry_run)
        if not self.dry_run:
            qdir = "/opt/edr/quarantine"
            os.makedirs(qdir, exist_ok=True)
            basename = os.path.basename(path)
            dst = os.path.join(qdir, f"{int(time.time())}_{basename}")
            try:
                os.rename(path, dst)
                self.logger.info("Moved %s -> %s", path, dst)
            except Exception as e:
                self.logger.exception("Failed to quarantine: %s", e)

# -----------------------------
# Event queue for inter-module comms
# -----------------------------
event_q = queue.Queue()

# -----------------------------
# Brute-force detector (adapted from provided script)
# -----------------------------
def run_bruteforce_detector(event_q, responder, config):
    """
    Scapy-based sniffing to detect many POST /rest/user/login attempts from same IP.
    Expects scapy installed and usually requires root to sniff.
    On detection, an event is enqueued and responder.block_ip() is called (subject to dry-run).
    """
    logger = logging.getLogger("bruteforce")
    if sniff is None:
        logger.error("Scapy is not available. Install scapy to enable brute-force detection.")
        return

    port = config.get("port", BF_PORT)
    threshold = config.get("threshold", BF_THRESHOLD)
    window = config.get("window", BF_WINDOW)

    ip_attempts = defaultdict(list)
    blocked_ips = set()

    def process_packet(packet):
        now = time.time()
        try:
            if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
                tcp = packet[TCP]
                ip_layer = packet[IP]
                payload = packet[Raw].load.decode(errors='ignore')

                # Only consider POST requests to /rest/user/login
                if tcp.dport == port and "POST /rest/user/login" in payload:
                    src_ip = ip_layer.src
                    if src_ip.startswith("::ffff:"):
                        src_ip = src_ip.replace("::ffff:", "")

                    # Skip if already blocked
                    if src_ip in blocked_ips:
                        return

                    ip_attempts[src_ip].append(now)
                    # Remove old timestamps outside the window
                    ip_attempts[src_ip] = [t for t in ip_attempts[src_ip] if now - t <= window]

                    logger.info("[WARNING] %s has %d login attempts in the last %d seconds", src_ip, len(ip_attempts[src_ip]), window)

                    # Check threshold
                    if len(ip_attempts[src_ip]) > threshold:
                        # create event
                        evt = make_event("bruteforce", "login_failure_threshold", "high", {"ip": src_ip, "count": len(ip_attempts[src_ip])})
                        write_event(evt)
                        event_q.put(evt)
                        # Respond (will respect dry-run)
                        responder.block_ip(src_ip, reason="brute-force", duration=config.get("block_duration", 3600))
                        blocked_ips.add(src_ip)
                        ip_attempts[src_ip] = []  # reset after blocking
        except Exception as e:
            logger.exception("Exception in process_packet: %s", e)

    logger.info("Brute-force detector: starting sniff on TCP port %s (threshold=%s, window=%s)", port, threshold, window)
    try:
        sniff(filter=f"tcp port {port}", prn=process_packet, store=0)
    except Exception as e:
        logger.exception("Sniffing failed: %s", e)
        return

# -----------------------------
# DoS detector (adapted from ufw_dos_guard.py)
# -----------------------------
def parse_ss_for_port(port):
    cmd = f"ss -tn state established '( sport = :{port} or dport = :{port} )'"
    out = run_cmd(cmd)
    ips = []
    for line in out.splitlines():
        # Skip header
        if line.strip().startswith("Netid") or line.strip() == "":
            continue
        parts = line.split()
        # Last token is peer address like 192.168.56.1:54321
        peer = parts[-1]
        if ":" in peer:
            ip = peer.rsplit(":", 1)[0]
            # filter out local or empty
            if ip and ip != "127.0.0.1" and not ip.startswith("::1"):
                ips.append(ip)
    return ips

def already_blocked_ufw(ip):
    out = run_cmd("ufw status")
    return ip in out

def run_dos_protector(event_q, responder, config):
    logger = logging.getLogger("dos_protector")
    port = config.get("port", JUICE_PORT)
    conn_threshold = config.get("conn_threshold", CONN_THRESHOLD)
    check_interval = config.get("check_interval", CHECK_INTERVAL)
    block_duration = config.get("block_duration", BLOCK_DURATION)

    # Ensure log exists (best-effort)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    except Exception:
        pass
    try:
        open(LOG_PATH, "a").close()
    except Exception:
        pass

    blocked = {}  # ip -> timestamp blocked

    logger.info("Starting DoS protector (port=%s, threshold=%s)", port, conn_threshold)
    while True:
        try:
            ips = parse_ss_for_port(port)
            counts = Counter(ips)
            for ip, count in counts.items():
                if count >= conn_threshold and not already_blocked_ufw(ip):
                    # create event
                    evt = make_event("dos_protector", "syn_flood", "high", {"ip": ip, "syn_rate": count})
                    write_event(evt)
                    event_q.put(evt)
                    # use responder to block
                    responder.block_ip(ip, reason="syn-flood", duration=block_duration)
                    blocked[ip] = time.time()
            # Expire internal tracking map (this does not remove UFW rules)
            nowt = time.time()
            expired = [ip for ip, ts in blocked.items() if nowt - ts > block_duration]
            for ip in expired:
                del blocked[ip]
        except Exception as e:
            # log to LOG_PATH if possible
            try:
                with open(LOG_PATH, "a") as f:
                    f.write(f"{time.ctime()}: Exception: {e}\n")
            except Exception:
                pass
            logger.exception("Exception in DoS protector loop: %s", e)
        time.sleep(check_interval)

# -----------------------------
# SQLi detector (newly integrated)
# -----------------------------
def normalise_http_payload(payload_bytes):
    """Attempt to decode and url-decode a payload to a string for matching."""
    try:
        txt = payload_bytes.decode(errors="ignore")
    except Exception:
        txt = str(payload_bytes)
    # attempt URL decode and HTML unescape to expose hidden payloads
    try:
        txt = urllib.parse.unquote_plus(txt)
    except Exception:
        pass
    try:
        txt = html.unescape(txt)
    except Exception:
        pass
    return txt

def sqli_score(text):
    """Return integer score (# of pattern matches) for a given text."""
    score = 0
    for rx in SQLI_COMPILED:
        if rx.search(text):
            score += 1
    return score

def run_sqli_detector(event_q, responder, config):
    """
    Scapy-based SQLi detector.
    - inspects HTTP requests (GET/POST) on the configured port
    - heuristically scores payloads using regex rules
    - if score >= threshold, emits event and triggers response (block_ip / alert)
    Config keys:
      - port (default 3000)
      - score_threshold (default 1)
      - throttle_seconds (min interval per IP to re-alert)
      - block_on_detect (bool) - will call responder.block_ip if True
    """
    logger = logging.getLogger("sqli_detector")
    if sniff is None:
        logger.error("Scapy is not available. Install scapy to enable SQLi detection.")
        return

    port = config.get("port", BF_PORT)
    score_threshold = config.get("score_threshold", 1)
    throttle_seconds = config.get("throttle_seconds", 30)
    block_on_detect = config.get("block_on_detect", False)  # default False per your request

    last_alert = defaultdict(float)  # ip -> timestamp last alert

    def process_packet(packet):
        nowt = time.time()
        try:
            if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
                tcp = packet[TCP]
                ip_layer = packet[IP]

                # Only inspect requests destined to the Juice port
                if tcp.dport != port:
                    return

                raw = packet[Raw].load
                text = normalise_http_payload(raw)

                # Look for SQLi indicators in HTTP request line, headers and body
                score = sqli_score(text)

                if score >= score_threshold:
                    src_ip = ip_layer.src
                    if src_ip.startswith("::ffff:"):
                        src_ip = src_ip.replace("::ffff:", "")

                    # Throttle alerts per IP
                    if nowt - last_alert[src_ip] < throttle_seconds:
                        logger.debug("SQLi detected but throttled: %s", src_ip)
                        return
                    last_alert[src_ip] = nowt

                    evt = make_event("sqli_detector", "sqli_suspected", "high", {
                        "ip": src_ip,
                        "score": score,
                        "snippet": text[:512]
                    })
                    write_event(evt)
                    event_q.put(evt)
                    logger.warning("SQLi suspicion from %s (score=%s)", src_ip, score)

                    if block_on_detect:
                        responder.block_ip(src_ip, reason="sqli-detected", duration=config.get("block_duration", 3600))
        except Exception as e:
            logger.exception("Exception in sqli detector packet processing: %s", e)

    logger.info("SQLi detector starting on port %s (threshold=%s)", port, score_threshold)
    try:
        sniff(filter=f"tcp port {port}", prn=process_packet, store=0)
    except Exception as e:
        logger.exception("Sniffing failed in SQLi detector: %s", e)
        return

# -----------------------------
# Event consumer - central decision point
# -----------------------------
def event_consumer(event_q, responder, stop_event):
    logger = logging.getLogger("event_consumer")
    while not stop_event.is_set():
        try:
            evt = event_q.get(timeout=1)
        except queue.Empty:
            continue
        logger.info("Event consumed: %s", evt)
        # Example rule: if source indicates high severity, escalate
        severity = evt.get("severity", "low") if isinstance(evt, dict) else "low"
        if severity in ("high", "critical"):
            responder.alert(f"High severity event: {evt['type']}" if isinstance(evt, dict) and "type" in evt else "High severity event", meta=evt)
        # persist consumer record
        write_event({"timestamp": now_iso(), "source": "consumer", "data": evt})
        event_q.task_done()

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="EDR manager (merged detectors)")
    parser.add_argument("--no-dry-run", action="store_true", default=False, help="Allow blocking actions (ufw/iptables) to be executed")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    dry_run = not args.no_dry_run
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
    logger = logging.getLogger("edr_manager")
    logger.info("Starting EDR manager (dry_run=%s)", dry_run)

    responder = Responder(dry_run=dry_run, logger=logging.getLogger("responder"))
    stop_event = threading.Event()

    # create and start threads
    threads = []
    # Brute-force detector thread (scapy sniff runs in thread)
    t_bf = threading.Thread(
        target=run_bruteforce_detector,
        args=(event_q, responder, {"port": BF_PORT, "threshold": BF_THRESHOLD, "window": BF_WINDOW, "block_duration": 3600}),
        daemon=True,
        name="bruteforce"
    )
    # DoS protector thread
    t_dos = threading.Thread(
        target=run_dos_protector,
        args=(event_q, responder, {"port": JUICE_PORT, "conn_threshold": CONN_THRESHOLD, "check_interval": CHECK_INTERVAL, "block_duration": BLOCK_DURATION}),
        daemon=True,
        name="dos_protector"
    )
    # SQLi detector thread
    t_sqli = threading.Thread(
        target=run_sqli_detector,
        args=(event_q, responder, {"port": BF_PORT, "score_threshold": 1, "throttle_seconds": 30, "block_on_detect": False, "block_duration": 3600}),
        daemon=True,
        name="sqli_detector"
    )
    # Event consumer
    t_consumer = threading.Thread(target=event_consumer, args=(event_q, responder, stop_event), daemon=True, name="consumer")

    for t in (t_bf, t_dos, t_sqli, t_consumer):
        t.start()
        threads.append(t)
        logger.info("Started thread %s", t.name)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Stopping EDR manager...")
        stop_event.set()
        # threads are daemon; give them a moment
        time.sleep(1)
        logger.info("Stopped.")

if __name__ == "__main__":
    main()

