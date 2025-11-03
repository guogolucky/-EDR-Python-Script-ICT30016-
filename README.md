# -EDR-Python-Script-ICT30016-(S2,2025 - GROUP 11)
This repository contains a lightweight Python-based EDR script for  OWASP Juice Shop hosted in Ubuntu VM mainly to defend against attacks such as Brute Force, DoS and SQL Injection and SSH attacks.

Python scripts is divided into two parts:
1. The backbone (edr_manager.py) - where all the code functionalies and mechanism is at
2. The EDR menu interface (edr_menu.py) - user interface for easy readability and usability



# EDR Manager (Juice Shop) — Prototype

Lightweight EDR prototype for the OWASP Juice Shop VM.  
Detects & responds to: **Brute-force (HTTP login)**, **DoS (connection floods)**, **SQL-injection (heuristic)** and **SSH brute-force**.  
Includes a small operator TUI (`edr_menu.py`) to start/stop and monitor the manager (`edr_manager.py`).

> **Safe by default:** the system runs in **dry-run** mode (no firewall changes) unless started with `--no-dry-run`.

---

## Contents

- `edr_manager.py` — core engine (sniffing, detectors, event queue, responder)
- `edr_menu.py` — operator menu: start/stop, toggles, log tails, UFW helpers
- `README.md` — this file

---

## Quick features

- Packet capture via **Scapy** for HTTP/packet inspection
- SSH log tailing (`/var/log/auth.log`) for SSH brute-force detection
- DoS detection using `ss` connection counts
- SQLi heuristic detection (URL-decode + regex patterns)
- Structured JSONL events: `/tmp/edr_events.jsonl`
- UFW-based responder for blocking (real blocking only if enabled)
- Simple text UI to control and monitor the EDR

---

## Requirements

- Python 3.8+
- `python3-scapy` (or `scapy` Python package)
- `jq` (optional, for pretty event viewing)
- `ufw` (for blocking)
- (Optional) `hping3` for lab DoS testing

On Ubuntu:
```bash
sudo apt update
sudo apt install -y python3-scapy jq ufw
# optionally for DoS testing:
sudo apt install -y hping3



