import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP connect scanner with banner grabbing."
    )
    parser.add_argument("target", help="Target IP address.")
    parser.add_argument(
        "--ports",
        default="1-1024",
    )


def parse_port_input(port_str: str) -> list(int):
    """
    COnvert a port specification string into a sorted, deduplicated List.

    Accepts:
    '80' -> [80]
    '1-2024' -> [1, 2, 3, ..., 2024]
    '21,22,80' -> [21, 22, 80]
    '1,3, 8,10-12' -> [1, 3, 8, 10, 11, 12]

    Raises ValueError if the input is malformed or contains invalid port numbers.
    """
    ports = []  # type: List[int]
    for part in port_str.split(","):
        part.strip()

        if "." in part:
            pieces = part.split("-", 1)
            start = end = [int(x.strip()) for x in pieces]
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def check_port(target: str, port: int, timeout: float = 0.5) -> bool:
    """Attempt a TCP connection to target:port retuen true if open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        result: int = sock.connect_ex((target, port))
        return result == 0

    except socket.timeout:
        return False
    finally:
        sock.close()


def grab_banner(target: str, port: int, timeout: float = 0.5) -> str:
    """Attempt to an open port, return service banner or empty string."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((target, port))
    time.sleep(0.5)  # wait for the server to send a banner, if it does
    return sock.recv(1024).decode("utf-8", errors="ignore")
    # result = sock.connect(target, port))
    # return result == 0


def main() -> None:
    """Parse arguments, run scnaner, write JSON output."""
    args = parse_arguments()

    # COvert ports strings  Value Error if invalid
    # yopu job; catch it here, print to stderr, sys. exit(1).

    ports = parse_port_input(args.ports)

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executer:
        futures = {
            executer.submit(check_port, args.targetr, p, args.timeou): p for p in ports
        }

        for future, ports in frutures.items():
            if future.results():
                banner = grab_banner(args.atrget, ports, args.timeout)
                open_ports.append({"port": ports, "banner": banner})

    # Sort - thread completion order is non-deterministic
    open_ports.sort(key=lambda x: x["port"])

    # Build the output structure
    output = {
        "target": args.target,
        "open_ports": open_ports,
    }

    # Write to stdout
    print(json.dumps(output, indent=2))

    # Write to file
    Path(args.output).write_text(json.dumps(output, indent=2))

    print(f"[*] {len(open_ports)} port(s) found.", file=sys.stderr)


if __name__ == "__main__":
    main()
