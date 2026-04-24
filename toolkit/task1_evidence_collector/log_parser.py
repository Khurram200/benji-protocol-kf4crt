"""
COM5413 — The Benji Protocol
Task 1: The Evidence Collector
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Regex for failed password or invalid user attempts
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) .*?: "
    r"(?:Failed password for (?:invalid user )?(?P<failed_user>\S+)|Invalid user (?P<invalid_user>\S+)) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Configuration for brute-force detection
TIME_WINDOW_MINUTES = 5  # Time window to track repeated attempts
ATTEMPT_THRESHOLD = 3  # Minimum attempts in the window to flag


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Parses the log file and extracts suspicious login attempts."
    )
    parser.add_argument("input_file", help="Path to the log file to be parsed")
    parser.add_argument(
        "-o",
        "--output",
        default="suspect.csv",
        help="Path to the detailed output CSV file",
    )
    parser.add_argument(
        "-s",
        "--summary",
        default="summary.csv",
        help="Path to the summary CSV file",
    )
    parser.add_argument(
        "-b",
        "--bruteforce",
        default="bruteforce.csv",
        help="Path to the brute force alert CSV file",
    )
    return parser.parse_args()


def parse_log(file_path):
    path = Path(file_path)
    if not path.exists():
        print(f"Error: file {file_path} does not exist", file=sys.stderr)
        sys.exit(1)

    records = []
    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                user = match.group("failed_user") or match.group("invalid_user")
                record = {
                    "Timestamp": match.group("timestamp"),
                    "IP_Address": match.group("ip"),
                    "User_Account": user,
                }
                records.append(record)

    # Deduplicate based on IP + User only (keep the first occurrence)
    seen = set()
    unique_records = []
    for rec in records:
        key = (rec["IP_Address"], rec["User_Account"])
        if key not in seen:
            seen.add(key)
            unique_records.append(rec)

    return unique_records


def write_csv(records, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as csvfile:
        fieldnames = ["Timestamp", "IP_Address", "User_Account"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)


def main():
    args = parse_arguments()
    records = parse_log(args.input_file)
    write_csv(records, args.output)


if __name__ == "__main__":
    main()
