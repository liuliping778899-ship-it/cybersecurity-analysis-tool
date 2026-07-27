"""Simple cybersecurity log analysis tool.

Student: Liping Liu
Purpose: Detect repeated failed login attempts in a security log.
"""

import re
import sys
from collections import Counter
from pathlib import Path


FAILED_LOGIN_PATTERN = re.compile(
    r"FAILED_LOGIN.*from\s+(\d{1,3}(?:\.\d{1,3}){3})"
)

ALERT_THRESHOLD = 3


def analyze_log(file_path: str) -> None:
    """Analyze a security log and report suspicious login attempts."""

    log_path = Path(file_path)

    if not log_path.exists():
        print(f"Error: The file '{file_path}' was not found.")
        return

    failed_attempts: Counter[str] = Counter()
    error_count = 0
    processed_lines = 0

    try:
        with log_path.open("r", encoding="utf-8") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                line = line.strip()

                if not line:
                    continue

                processed_lines += 1

                if "ERROR" in line:
                    error_count += 1

                match = FAILED_LOGIN_PATTERN.search(line)

                if match:
                    ip_address = match.group(1)
                    failed_attempts[ip_address] += 1

    except OSError as error:
        print(f"Error reading the log file: {error}")
        return

    print("Cybersecurity Log Analysis Report")
    print("----------------------------------")
    print(f"File analyzed: {log_path.name}")
    print(f"Lines processed: {processed_lines}")
    print(f"System errors found: {error_count}")
    print()

    if not failed_attempts:
        print("No failed login attempts were found.")
        return

    print("Failed Login Summary:")

    for ip_address, attempts in failed_attempts.items():
        print(f"- {ip_address}: {attempts} failed attempt(s)")

        if attempts >= ALERT_THRESHOLD:
            print(
                f"  ALERT: Possible brute-force activity from {ip_address}."
            )


def main() -> None:
    """Validate command-line input and start the analysis."""

    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <log_file>")
        sys.exit(1)

    analyze_log(sys.argv[1])


if __name__ == "__main__":
    main()