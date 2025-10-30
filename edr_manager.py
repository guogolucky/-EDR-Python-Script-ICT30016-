//PLEASE READ "read_me.md" BEFORE RUNNING SCRIPT TO KNOW WHAT NEEDS TO BE DONE TO MINIMIZE TROUBLESHOOTING//
//THIS IS AN INTEGRATED PYTHON SCRIPT THAT DEFEND AGAINST BRUTE FORCE, DoS, SQLI INJECTION AND SSH ATTACK//
//RUN IT IN A SAFE ENVIRONMENT //
//ENJOY!!!//


#!/usr/bin/env python3
"""
EDR Manager (Juice Shop) — Brute-force + DoS + SQLi + SSH defender

• Default is DRY-RUN (no firewall changes). Pass --no-dry-run to enable blocking.
• New: SSH Brute-Force Defender that tails /var/log/auth.log.
• Uses a shared Responder (UFW by default) and a JSONL event log.

Tested on Ubuntu 20.04+/22.04 with python3-scapy.
"""
import argparse
import contextlib
import json
import os
import queue
import re
import shlex
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

# scapy (installed via apt: python3-scapy)
from scapy.all import sniff, TCP, IP, Raw  # type: ignore

# ------------------ Config defaults ------------------
EVENT_LOG = "/tmp/edr_events.jsonl"
JUICE_PORT = 3000

# Brute-force
BF_THRESHOLD = 10
BF_WINDOW = 60  # seconds

# DoS
CONN_THRESHOLD = 30
CHECK_INTERVAL = 5  # seconds
UFW_BLOCK_CMD = "ufw insert 1 deny from {ip} to any"

# SQLi
SQLI_SCORE_THRESHOLD = 1   # keep 1 for demo; raise to 2+ to reduce FP
SQLI_BLOCK_ON_DETECT = False  # per user request: default False
SQLI_THROTTLE_SECONDS = 60

# SSH defender
SSH_MAX_ATTEMPTS = 5
SSH_WINDOW_SEC = 60
SSH_BLOCK_ON_DETECT = False  # safe default
SSH_THROTTLE_SECONDS = 120
SSH_LOG_FILE = "/var/log/auth.log"


# ------------------ Helpers ------------------
def iso_now():
    return datetime.utcnow().isoformat(timespec="microseconds") + "Z"


def safe_run(cmd: str) -> subprocess.CompletedProcess: 
    """Run a shell command safely, capture output; never raise."""
    try:
        return subprocess.run(shlex.split(cmd), check=False,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    except Exception as e:
        cp = subprocess.CompletedProcess(cmd, 1, "", str(e))
        return cp


def write_event(ev: dict):
    os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
    with open(EVENT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev) + "\n")


# ------------------ Responder ------------------ 
class Responder:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._last_block = {}  # ip -> ts

    def block_ip(self, ip: str, reason: str, duration: int = 3600):
        ev = {
            "timestamp": iso_now(),
            "source": "responder",
            "type": "block_ip" if not self.dry_run else "block_ip_dryrun",
            "severity": "high",
            "data": {"ip": ip, "reason": reason, "duration": duration},
        }
        write_event(ev)
        if self.dry_run:
            return
        cmd = UFW_BLOCK_CMD.format(ip=ip)
        safe_run(cmd)


# ------------------ Event consumer ------------------
def consumer_loop(evq: "queue.Queue[dict]"):
    while True:
        ev = evq.get()
        if ev is None:
            return
        if "timestamp" not in ev:
            ev["timestamp"] = iso_now()
        write_event(ev)


# ------------------ Detectors ------------------
# Brute-force (HTTP login)
def run_bruteforce_detector(evq, responder: Responder, cfg: dict):  # [4]
    port = int(cfg.get("port", JUICE_PORT))
    threshold = int(cfg.get("threshold", BF_THRESHOLD))
    window = int(cfg.get("window", BF_WINDOW))

    attempts = defaultdict(list)  # ip -> [ts]

    def handle(pkt):
        now = time.time()
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            tcp = pkt[TCP]
            if tcp.dport != port:
                return
            try:
                payload = pkt[Raw].load.decode(errors='ignore')
            except Exception:
                return
            if "POST /rest/user/login" in payload:
                ip = pkt[IP].src
                if ip.startswith("::ffff:"):
                    ip = ip.replace("::ffff:", "")
                arr = attempts[ip]
                arr.append(now)
                # purge
                cutoff = now - window
                while arr and arr[0] < cutoff:
                    arr.pop(0)
                evq.put({
                    "timestamp": iso_now(),
                    "source": "bruteforce",
                    "type": "login_attempt_observed",
                    "severity": "low",
                    "data": {"ip": ip, "recent_count": len(arr)}
                })
                if len(arr) > threshold:
                    evq.put({
                        "timestamp": iso_now(),
                        "source": "bruteforce",
                        "type": "login_failure_threshold",
                        "severity": "high",
                        "data": {"ip": ip, "count": len(arr)}
                    })
                    responder.block_ip(ip, reason="brute-force")

    sniff(filter=f"tcp port {port}", prn=handle, store=0)


# DoS (connection flood via ss)
def parse_ss_for_port(port: int):
    cmd = f"ss -tn state established '( sport = :{port} or dport = :{port} )'"
    res = safe_run(cmd)
    ips = []
    for line in res.stdout.splitlines():
        if line.strip().startswith("Netid") or not line.strip():
            continue
        parts = line.split()
        if not parts:
            continue
        peer = parts[-1]  # like 192.168.77.20:54321
        if ":" in peer:
            ip = peer.rsplit(":", 1)[0]
            if ip and ip != "127.0.0.1" and not ip.startswith("::1"):
                ips.append(ip)
    return ips


def run_dos_protector(evq, responder: Responder, cfg: dict):
    port = int(cfg.get("port", JUICE_PORT))
    threshold = int(cfg.get("conn_threshold", CONN_THRESHOLD))
    interval = int(cfg.get("interval", CHECK_INTERVAL))
    blocked_recent = {}
    while True:
        try:
            ips = parse_ss_for_port(port)
            counts = Counter(ips)
            now = time.time()
            for ip, c in counts.items():
                if c >= threshold and (ip not in blocked_recent or now - blocked_recent[ip] > 60):
                    evq.put({
                        "timestamp": iso_now(),
                        "source": "dos_protector",
                        "type": "high_conn_rate",
                        "severity": "high",
                        "data": {"ip": ip, "conn": c, "threshold": threshold}
                    })
                    responder.block_ip(ip, reason="dos-connection-flood")
                    blocked_recent[ip] = now
        except Exception as e:
            evq.put({"timestamp": iso_now(), "source": "dos_protector", "type": "exception", "severity": "medium", "data": {"error": str(e)}})
        time.sleep(interval)


# SQLi detector (payload heuristics)
SQLI_PATTERNS = [
    re.compile(r"\bOR\b\s+\b1\b\s*=\s*\b1\b", re.I),
    re.compile(r"--\s*$", re.M),
    re.compile(r";\s*DROP\s+TABLE", re.I),
    re.compile(r"\bUNION\b\s+\bSELECT\b", re.I),
    re.compile(r"'\s*or\s*'\w+'='\w+'", re.I),
]


def run_sqli_detector(evq, responder: Responder, cfg: dict):  
    port = int(cfg.get("port", JUICE_PORT))
    score_threshold = int(cfg.get("score_threshold", SQLI_SCORE_THRESHOLD))
    block_on_detect = bool(cfg.get("block_on_detect", SQLI_BLOCK_ON_DETECT))
    throttle = int(cfg.get("throttle_seconds", SQLI_THROTTLE_SECONDS))
    last_block = {}

    def handle(pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
            return
        if pkt[TCP].dport != port:
            return
        try:
            payload = pkt[Raw].load.decode(errors='ignore')
        except Exception:
            return
        score = 0
        for pat in SQLI_PATTERNS:
            if pat.search(payload):
                score += 1
        if score >= score_threshold:
            ip = pkt[IP].src
            if ip.startswith("::ffff:"):
                ip = ip.replace("::ffff:", "")
            snippet = payload[:256]
            evq.put({
                "timestamp": iso_now(),
                "source": "sqli_detector",
                "type": "sqli_suspected",
                "severity": "high",
                "data": {"ip": ip, "score": score, "snippet": snippet}
            })
            now = time.time()
            if block_on_detect and (ip not in last_block or now - last_block[ip] > throttle):
                responder.block_ip(ip, reason="sqli-detected")
                last_block[ip] = now

    sniff(filter=f"tcp port {port}", prn=handle, store=0)


# SSH brute-force defender (log tail)
SSH_PATTERNS = [
    re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"PAM: Authentication failure .* rhost=(\d+\.\d+\.\d+\.\d+)"),
]


def run_ssh_defender(evq, responder: Responder, cfg: dict):
    log_file = cfg.get("log_file", SSH_LOG_FILE)
    max_attempts = int(cfg.get("max_attempts", SSH_MAX_ATTEMPTS))
    window_sec = int(cfg.get("window_sec", SSH_WINDOW_SEC))
    block_on_detect = bool(cfg.get("block_on_detect", SSH_BLOCK_ON_DETECT))
    throttle_seconds = int(cfg.get("throttle_seconds", SSH_THROTTLE_SECONDS))

    attempts = defaultdict(lambda: deque(maxlen=max_attempts * 2))
    last_block_ts = {}

    proc = subprocess.Popen(["tail", "-F", log_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    try:
        for raw in proc.stdout:  # type: ignore
            line = raw.strip()
            ip = None
            for pat in SSH_PATTERNS:
                m = pat.search(line)
                if m:
                    ip = m.group(1)
                    break
            if not ip:
                continue
            now = datetime.utcnow()
            dq = attempts[ip]
            dq.append(now)
            cutoff = now - timedelta(seconds=window_sec)
            while dq and dq[0] < cutoff:
                dq.popleft()
            # observation (low)
            evq.put({
                "timestamp": iso_now(),
                "source": "ssh_defender",
                "type": "ssh_failed_login_observed",
                "severity": "low",
                "data": {"ip": ip, "recent_count": len(dq)}
            })
            if len(dq) >= max_attempts:
                evq.put({
                    "timestamp": iso_now(),
                    "source": "ssh_defender",
                    "type": "ssh_bruteforce_detected",
                    "severity": "high",
                    "data": {"ip": ip, "count": len(dq), "window_sec": window_sec, "threshold": max_attempts}
                })
                now_s = int(time.time())
                last = last_block_ts.get(ip, 0)
                if block_on_detect and (now_s - last >= throttle_seconds):
                    responder.block_ip(ip, reason="ssh-bruteforce")
                    last_block_ts[ip] = now_s
    except Exception as e:
        evq.put({"timestamp": iso_now(), "source": "ssh_defender", "type": "exception", "severity": "medium", "data": {"error": str(e)}})
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()


# ------------------ Main ------------------
def main(): 
    ap = argparse.ArgumentParser(description="EDR Manager for Juice Shop (Brute-force, DoS, SQLi, SSH)")
    ap.add_argument("--no-dry-run", action="store_true", help="enable real firewall blocking (UFW)")
    ap.add_argument("--verbose", action="store_true", help="print status messages to stdout")
    ap.add_argument("--enable-sqli-block", action="store_true", help="enable auto-blocking on SQLi detection")
    ap.add_argument("--enable-ssh-block", action="store_true", help="enable auto-blocking on SSH brute-force detection")
    args = ap.parse_args()

    dry_run = not args.no_dry_run

    # Event queue + consumer
    evq: "queue.Queue[dict]" = queue.Queue()
    t_cons = threading.Thread(target=consumer_loop, args=(evq,), daemon=True, name="consumer")
    t_cons.start()

    # Announce start
    start_ev = {"timestamp": iso_now(), "source": "edr_manager", "type": "start", "severity": "low",
                "data": {"dry_run": dry_run, "sqliblock": args.enable_sqli_block, "sshblock": args.enable_ssh_block}}
    write_event(start_ev)

    responder = Responder(dry_run=dry_run)

    # Threads 
    t_bf = threading.Thread(target=run_bruteforce_detector,
                            args=(evq, responder, {"port": JUICE_PORT, "threshold": BF_THRESHOLD, "window": BF_WINDOW}),
                            daemon=True, name="bruteforce")
    t_bf.start()

    t_dos = threading.Thread(target=run_dos_protector,
                             args=(evq, responder, {"port": JUICE_PORT, "conn_threshold": CONN_THRESHOLD, "interval": CHECK_INTERVAL}),
                             daemon=True, name="dos_protector")
    t_dos.start()

    t_sqli = threading.Thread(target=run_sqli_detector,
                              args=(evq, responder, {"port": JUICE_PORT, "score_threshold": SQLI_SCORE_THRESHOLD,
                                                     "block_on_detect": bool(args.enable_sqli_block),
                                                     "throttle_seconds": SQLI_THROTTLE_SECONDS}),
                              daemon=True, name="sqli_detector")
    t_sqli.start()

    t_ssh = threading.Thread(target=run_ssh_defender,
                             args=(evq, responder, {"log_file": SSH_LOG_FILE,
                                                    "max_attempts": SSH_MAX_ATTEMPTS,
                                                    "window_sec": SSH_WINDOW_SEC,
                                                    "block_on_detect": bool(args.enable_ssh_block),
                                                    "throttle_seconds": SSH_THROTTLE_SECONDS}),
                             daemon=True, name="ssh_defender")
    t_ssh.start()

    if args.verbose:
        print(f"EDR running (dry_run={dry_run}) — threads: bruteforce, dos_protector, sqli_detector, ssh_defender")
        print(f"Events: {EVENT_LOG}")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        write_event({"timestamp": iso_now(), "source": "edr_manager", "type": "stop", "severity": "low", "data": {}})


if __name__ == "__main__":
    main()

