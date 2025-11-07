//PLEASE READ "READ_ME.md" BEFORE RUNNING SCRIPT TO KNOW WHAT NEEDS TO BE DONE TO MINIMIZE TROUBLESHOOTING//
//THIS IS AN INTEGRATED PYTHON SCRIPT THAT DEFEND AGAINST BRUTE FORCE, DoS, SQLI INJECTION AND SSH BRUTE-FORCE ATTACK//
//RUN IT IN A SAFE ENVIRONMENT//
//ENJOY!!!//


#!/usr/bin/env python3
"""
edr_menu.py — TUI manager aligned with the updated edr_manager.py

Paths / flags match the EDR manager I provided:
  EDR_MANAGER = /opt/edr/edr_manager.py
  EVENT_LOG   = /tmp/edr_events.jsonl
  PROC_LOG    = /opt/edr/edr_out.log
  PID_FILE    = /tmp/edr_manager.pid

Features:
- Start/Stop EDR with toggles (dry-run, SQLi block, SSH block, verbose)
- Status panel: running?, PID/cmdline, recent event summary
- Logs: follow event log & process log
- UFW snapshots: status, numbered rules; quick unblock by IP or rule number
- Utilities: last errors, rotate or clear event log
- Config persistence: /opt/edr/edr_menu_config.json

Run as root:
  sudo python3 /opt/edr/edr_menu.py
"""
from __future__ import annotations

import contextlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

# ---------- Paths (aligned with edr_manager.py) ----------
EDR_MANAGER = Path("/opt/edr/edr_manager.py")
EVENT_LOG   = Path("/tmp/edr_events.jsonl")
PROC_LOG    = Path("/opt/edr/edr_out.log")
PID_FILE    = Path("/tmp/edr_manager.pid")
CONF_FILE   = Path("/opt/edr/edr_menu_config.json")

# ---------- Defaults ----------
DEFAULT_CONF: Dict[str, Any] = {
    "dry_run": True,              # default safe = no firewall changes
    "enable_sqli_block": False,   # --enable-sqli-block
    "enable_ssh_block": False,    # --enable-ssh-block
    "verbose": True               # --verbose
}

# ---------- ANSI helpers ----------
def c(s, code): return f"\033[{code}m{s}\033[0m"
def green(s):   return c(s, "32")
def red(s):     return c(s, "31")
def yellow(s):  return c(s, "33")
def blue(s):    return c(s, "34")
def bold(s):    return c(s, "1")

# ---------- Shell helpers ----------
def run(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-lc", cmd], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def require_root():
    if os.geteuid() != 0:
        print(red("Please run as root: sudo python3 /opt/edr/edr_menu.py"))
        sys.exit(1)

# ---------- Config ----------
def load_conf() -> Dict[str, Any]:
    if CONF_FILE.exists():
        with contextlib.suppress(Exception):
            return json.loads(CONF_FILE.read_text())
    return DEFAULT_CONF.copy()

def save_conf(conf: Dict[str, Any]):
    with contextlib.suppress(Exception):
        CONF_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONF_FILE.write_text(json.dumps(conf, indent=2))

# ---------- PID / process ----------
def edr_is_running() -> bool:
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
    except Exception:
        return False
    if not Path(f"/proc/{pid}").exists():
        return False
    # confirm it really is edr_manager.py
    with contextlib.suppress(Exception):
        cmdline = Path(f"/proc/{pid}/cmdline").read_text().replace("\x00", " ")
        return "edr_manager.py" in cmdline
    return True

def edr_cmdline() -> str:
    if not PID_FILE.exists():
        return ""
    with contextlib.suppress(Exception):
        pid = int(PID_FILE.read_text().strip())
        return Path(f"/proc/{pid}/cmdline").read_text().replace("\x00", " ")
    return ""

def edr_start(conf: Dict[str, Any]) -> str:
    if not EDR_MANAGER.exists():
        return f"Not found: {EDR_MANAGER}. Edit EDR_MANAGER path in edr_menu.py if needed."
    if edr_is_running():
        return "EDR already running."
    flags = []
    if conf.get("verbose", True): flags.append("--verbose")
    if conf.get("enable_sqli_block", False): flags.append("--enable-sqli-block")
    if conf.get("enable_ssh_block", False):  flags.append("--enable-ssh-block")
    if not conf.get("dry_run", True):        flags.append("--no-dry-run")

    PROC_LOG.parent.mkdir(parents=True, exist_ok=True)
    cmd = f"nohup python3 {shlex.quote(str(EDR_MANAGER))} {' '.join(flags)} >> {shlex.quote(str(PROC_LOG))} 2>&1 & echo $!"
    res = run(cmd)
    if res.returncode != 0 or not res.stdout.strip().isdigit():
        return f"Failed to launch EDR:\n{res.stderr.strip() or res.stdout.strip()}"
    pid = int(res.stdout.strip())
    PID_FILE.write_text(str(pid))
    return f"Started edr_manager (pid {pid}).\nLogs: {PROC_LOG}\nTip: tail -f {EVENT_LOG}"

def edr_stop() -> str:
    if not PID_FILE.exists():
        return "No PID file; EDR not running."
    try:
        pid = int(PID_FILE.read_text().strip())
    except Exception:
        with contextlib.suppress(Exception): PID_FILE.unlink()
        return "PID file invalid; cleaned."
    if not Path(f"/proc/{pid}").exists():
        with contextlib.suppress(Exception): PID_FILE.unlink()
        return "Process already gone; cleaned."
    # graceful stop
    with contextlib.suppress(Exception):
        os.kill(pid, signal.SIGTERM)
    for _ in range(10):
        time.sleep(0.5)
        if not Path(f"/proc/{pid}").exists():
            with contextlib.suppress(Exception): PID_FILE.unlink()
            return "Stopped."
    # force
    with contextlib.suppress(Exception):
        os.kill(pid, signal.SIGKILL)
    if not Path(f"/proc/{pid}").exists():
        with contextlib.suppress(Exception): PID_FILE.unlink()
        return "Stopped (SIGKILL)."
    return "Could not terminate process."

# ---------- Event & UFW helpers ----------
def summarize_events(max_lines: int = 2000) -> str:
    if not EVENT_LOG.exists():
        return "No event log found."
    try:
        lines = EVENT_LOG.read_text(encoding="utf-8", errors="ignore").splitlines()
        tail = lines[-max_lines:]
        by_type = Counter()
        by_ip   = Counter()
        last_ts = ""
        for ln in tail:
            with contextlib.suppress(Exception):
                obj = json.loads(ln)
                t = obj.get("type", "unknown")
                by_type[t] += 1
                data = obj.get("data", {})
                ip = data.get("ip")
                if ip:
                    by_ip[(t, ip)] += 1
                last_ts = obj.get("timestamp", last_ts)
        top_types = "\n".join([f"  {k}: {v}" for k, v in by_type.most_common(10)]) or "  (none)"
        # top offenders across detections
        top_ips = Counter()
        for (t, ip), n in by_ip.items():
            top_ips[ip] += n
        top_ip_lines = "\n".join([f"  {ip}: {n}" for ip, n in top_ips.most_common(10)]) or "  (none)"
        return (f"Recent events (last {len(tail)} lines; last ts: {last_ts}):\n"
                f"{top_types}\n\nTop IPs:\n{top_ip_lines}")
    except Exception as e:
        return f"Error reading events: {e}"

def ufw_status() -> str:
    r = run("ufw status verbose")
    if r.returncode != 0:
        return "(ufw not available or insufficient privileges)"
    return r.stdout.strip() or "(no output)"

def ufw_rules_numbered(limit: int = 30) -> str:
    r = run("ufw status numbered")
    if r.returncode != 0:
        return "(ufw not available or insufficient privileges)"
    lines = r.stdout.strip().splitlines()
    return "\n".join(lines[:limit]) or "(no rules)"

def ufw_unblock_by_ip(ip: str) -> str:
    # remove any rule that matches "from <ip>"
    r = run(f"yes | ufw delete deny from {shlex.quote(ip)} to any")
    if r.returncode == 0:
        return f"Unblocked {ip}."
    # fallback: try allow from ip (if deny not found)
    if "Could not find a rule" in r.stdout + r.stderr:
        return f"No explicit deny rule found for {ip}."
    return f"Failed to unblock {ip}:\n{(r.stderr or r.stdout).strip()}"

def ufw_unblock_by_number(num: str) -> str:
    r = run(f"yes | ufw delete {shlex.quote(num)}")
    if r.returncode == 0:
        return f"Deleted UFW rule #{num}."
    return f"Failed to delete rule #{num}:\n{(r.stderr or r.stdout).strip()}"

def show_last_errors() -> str:
    # search both logs
    chunks = []
    if PROC_LOG.exists():
        r1 = run(f"grep -iE 'error|exception|block_failed|ss_failed|tail_failed' {shlex.quote(str(PROC_LOG))} | tail -n 40")
        if r1.stdout.strip():
            chunks.append("From process log:\n" + r1.stdout.strip())
    if EVENT_LOG.exists():
        r2 = run(f"grep -iE '\"type\":\"(exception|block_failed|ss_failed|tail_failed)\"' {shlex.quote(str(EVENT_LOG))} | tail -n 40")
        if r2.stdout.strip():
            chunks.append("From event log:\n" + r2.stdout.strip())
    return "\n\n".join(chunks) if chunks else "(no recent errors found)"

def rotate_event_log() -> str:
    if not EVENT_LOG.exists():
        return "No event log to rotate."
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = EVENT_LOG.with_name(f"{EVENT_LOG.name}.{ts}.bak")
    with contextlib.suppress(Exception):
        EVENT_LOG.rename(dst)
        return f"Rotated: {EVENT_LOG} -> {dst}"
    return "Failed to rotate event log."

def clear_event_log() -> str:
    with contextlib.suppress(Exception):
        EVENT_LOG.write_text("")
        return "Event log cleared."
    return "Failed to clear event log."

# ---------- Status ----------
def show_status(conf: Dict[str, Any]):
    print(bold("\n== EDR Status =="))
    print(f"Config: dry_run={conf.get('dry_run', True)}, "
          f"sqli_block={conf.get('enable_sqli_block', False)}, "
          f"ssh_block={conf.get('enable_ssh_block', False)}, "
          f"verbose={conf.get('verbose', True)}")
    print("Process:", green("running") if edr_is_running() else red("stopped"))
    if edr_is_running():
        print("Cmdline:", edr_cmdline())
    print("\n" + summarize_events())
    print("\nUFW status:")
    print(ufw_status())
    print("\nUFW rules (numbered):")
    print(ufw_rules_numbered())
    print()

# ---------- Menu ----------
def menu_loop():
    conf = load_conf()
    while True:
        print(bold("\n=== EDR Control Menu ==="))
        print(f"1) Start EDR   [{green('running') if edr_is_running() else red('stopped')}]")
        print("2) Stop EDR")
        print(f"3) Toggle dry-run           (now: {'ON' if conf.get('dry_run', True) else 'OFF'})")
        print(f"4) Toggle SQLi auto-block   (now: {'ON' if conf.get('enable_sqli_block', False) else 'OFF'})")
        print(f"5) Toggle SSH auto-block    (now: {'ON' if conf.get('enable_ssh_block', False) else 'OFF'})")
        print(f"6) Toggle verbose logging   (now: {'ON' if conf.get('verbose', True) else 'OFF'})")
        print("7) Status (events + UFW)")
        print("8) View event log (follow)")
        print("9) View process log (follow)")
        print("10) Show last errors")
        print("11) Rotate event log")
        print("12) Clear event log")
        print("13) UFW: show status")
        print("14) UFW: show numbered rules")
        print("15) UFW: unblock by IP")
        print("16) UFW: delete rule by number")
        print("q) Quit")
        choice = input(blue("\nSelect > ")).strip().lower()

        if choice == "1":
            print(green(edr_start(conf)))
        elif choice == "2":
            print(yellow(edr_stop()))
        elif choice == "3":
            conf["dry_run"] = not conf.get("dry_run", True); save_conf(conf)
            print(green(f"dry_run now {'ON' if conf['dry_run'] else 'OFF'}"))
        elif choice == "4":
            conf["enable_sqli_block"] = not conf.get("enable_sqli_block", False); save_conf(conf)
            print(green(f"SQLi auto-block now {'ON' if conf['enable_sqli_block'] else 'OFF'}"))
        elif choice == "5":
            conf["enable_ssh_block"]  = not conf.get("enable_ssh_block", False); save_conf(conf)
            print(green(f"SSH auto-block now {'ON' if conf['enable_ssh_block'] else 'OFF'}"))
        elif choice == "6":
            conf["verbose"] = not conf.get("verbose", True); save_conf(conf)
            print(green(f"verbose now {'ON' if conf['verbose'] else 'OFF'}"))
        elif choice == "7":
            show_status(conf)
        elif choice == "8":
            if EVENT_LOG.exists():
                os.system(f"bash -lc 'less +F {shlex.quote(str(EVENT_LOG))}'")
            else:
                print(yellow("No event log yet."))
        elif choice == "9":
            if PROC_LOG.exists():
                os.system(f"bash -lc 'less +F {shlex.quote(str(PROC_LOG))}'")
            else:
                print(yellow("No process log yet. Start EDR first."))
        elif choice == "10":
            print(show_last_errors())
        elif choice == "11":
            print(rotate_event_log())
        elif choice == "12":
            print(clear_event_log())
        elif choice == "13":
            print(ufw_status())
        elif choice == "14":
            print(ufw_rules_numbered())
        elif choice == "15":
            ip = input("IP to unblock: ").strip()
            if ip:
                print(ufw_unblock_by_ip(ip))
        elif choice == "16":
            num = input("Rule number to delete (from 'ufw status numbered'): ").strip()
            if num:
                print(ufw_unblock_by_number(num))
        elif choice in ("q", "quit", "exit"):
            print("bye!")
            break
        else:
            print(yellow("Invalid choice."))

# ---------- main ----------
if __name__ == "__main__":
    require_root()
    if not EDR_MANAGER.exists():
        print(red(f"edr_manager.py not found at {EDR_MANAGER}"))
        print("Edit EDR_MANAGER path in this script if you keep it elsewhere.")
        sys.exit(1)
    try:
        menu_loop()
    except KeyboardInterrupt:
        print("\nexiting…")
