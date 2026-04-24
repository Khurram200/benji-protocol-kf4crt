"""
================================================================================
COM5413 — The Benji Protocol
Task 2: The Network Cartographer
File:   scan.py
================================================================================

MISSION BRIEF
-------------
Ethan cannot go in blind. Benji maps every door, every service, every version
number. The scan is not the attack — it is the intelligence that makes the
attack possible. A missed service or a wrong version assumption costs the
mission.

Your job is to build a threaded TCP port scanner that identifies open ports and
grabs the service banner from each one. The banner is the service telling you
exactly what it is and what version it is running. Listen carefully.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a target IP and port range/list as command-line arguments.
2. Attempt a TCP connection to each port using Python's socket library.
3. If the port is open, attempt to receive the service banner (the greeting
   text the service sends on connection).
4. Use threading (ThreadPoolExecutor) to scan multiple ports concurrently.
5. Implement a connection timeout (default 0.5s) — hanging the scanner is not
   an option in the field.
6. Output results as JSON: printed to stdout AND saved to recon_results.json.

CONSTRAINTS
-----------
- Python 3.10+ only.
- Use socket — do NOT wrap nmap or any external scanner.
- NO use of input() — all input via argparse.
- Timeout must be configurable via --timeout argument.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
JSON structure:
{
    "target": "192.168.x.x",
    "scan_time": "YYYY-MM-DD HH:MM:SS",
    "open_ports": [
        {"port": 21, "banner": "220 (vsFTPd 2.3.4)"},
        {"port": 22, "banner": "SSH-2.0-OpenSSH_4.7p1"},
        {"port": 80, "banner": ""}
    ]
}
"banner" must always be present — use empty string if no banner received.

EXAMPLE USAGE
-------------
    python scan.py 192.168.56.101 --ports 1-1024
    python scan.py 192.168.56.101 --ports 21,22,80,443
    python scan.py 192.168.56.101 --ports 1-65535 --timeout 1.0 --threads 100

BUILD LOG
---------
Use docs/build.md to record your development notes, decisions, and reflections
as you build this tool. Pay particular attention to documenting what you observe
in the banner output when scanning Metasploitable — this feeds directly into
the Vulnerability Hunt.
================================================================================
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP connect scanner with banner grabbing."
    )
    parser.add_argument("target", help="Target IP address.")
    parser.add_argument(
        "--ports", default="1-1024", help="Ports to scan (e.g., 22,80,443,1000-1010)."
    )
    parser.add_argument(
        "--threads", default=10, type=int, help="Number of threads for scanning."
    )
    parser.add_argument(
        "--output", default="output.json", help="Path to output JSON file."
    )
    parser.add_argument(
        "--timeout",
        default=0.5,
        type=float,
        help="Timeout for socket connections in seconds.",
    )
    return parser.parse_args()


def parse_port_input(port_str: str) -> List[int]:
    """Convert port string to sorted, unique list of ints."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def scan_port(target: str, port: int, timeout: float) -> Optional[Dict]:
    """Scan a single port: check if open and grab banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((target, port)) == 0:
                # Port is open, try grabbing banner
                banner = ""
                try:
                    # Send newline to trigger banner if server expects it
                    sock.sendall(b"\n")
                    time.sleep(0.1)
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                return {"port": port, "banner": banner}
    except Exception:
        return None
    return None


def main() -> None:
    args = parse_arguments()
    ports = parse_port_input(args.ports)
    open_ports: List[Dict] = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_port = {
            executor.submit(scan_port, args.target, port, args.timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                # Always ensure banner key exists
                if "banner" not in result or result["banner"] is None:
                    result["banner"] = ""
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    output_data = {"target": args.target, "open_ports": open_ports}

    # Ensure directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON file
    output_path.write_text(json.dumps(output_data, indent=2))

    # Print JSON to stdout
    print(json.dumps(output_data, indent=2))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
