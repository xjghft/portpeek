
#!/usr/bin/env python3
"""
PortPeek — Lightweight TCP Port Scanner
Author: Your GitHub Username
Dependencies: None (Python 3.8+)

Scan ports on hosts you own or have permission to test.
"""

import socket
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Terminal colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Common service names
SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

BANNER = f"""
{CYAN}{BOLD}
  ╔══════════════════════════════════════════╗
  ║                                          ║
  ║       P O R T P E E K   v1.0            ║
  ║                                          ║
  ║       Fast • Simple • Pure Python        ║
  ╚══════════════════════════════════════════╝
{RESET}"""


def scan_port(host, port, timeout):
    """Check whether a TCP port accepts connections."""
    try:
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                service = SERVICES.get(port, "Unknown")
                return port, service

    except (socket.error, OSError):
        pass

    return None


def scan_host(host, start_port, end_port, threads, timeout):
    """Scan a host using a thread pool."""
    print(BANNER)

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{RED}[!] Could not resolve host.{RESET}")
        return

    print(f"{BOLD}  Target    : {RESET}{host}")
    print(f"{BOLD}  IP        : {RESET}{ip}")
    print(f"{BOLD}  Ports     : {RESET}{start_port}-{end_port}")
    print(f"{BOLD}  Threads   : {RESET}{threads}")
    print(f"{BOLD}  Started   : {RESET}{datetime.now():%H:%M:%S}")

    print(f"\n{DIM}{'─' * 48}{RESET}")
    print(f"  {BOLD}PORT        SERVICE             STATUS{RESET}")
    print(f"{DIM}{'─' * 48}{RESET}")

    start_time = time.perf_counter()
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(scan_port, ip, port, timeout)
            for port in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            result = future.result()

            if result:
                open_ports.append(result)
                port, service = result

                print(
                    f"  {CYAN}{port:<12}{RESET}"
                    f"{service:<20}"
                    f"{GREEN}OPEN{RESET}"
                )

    duration = time.perf_counter() - start_time

    print(f"{DIM}{'─' * 48}{RESET}")
    print(f"\n{BOLD}  SCAN SUMMARY{RESET}")
    print(f"  Open ports  : {GREEN}{len(open_ports)}{RESET}")
    print(f"  Ports tested: {end_port - start_port + 1}")
    print(f"  Duration    : {duration:.2f}s")

    if not open_ports:
        print(f"\n  {YELLOW}No open TCP ports found.{RESET}")

    print(f"\n{GREEN}  ✓ Scan completed.{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="PortPeek — Fast Python TCP Port Scanner"
    )

    parser.add_argument(
        "host",
        help="Hostname or IPv4 address to scan"
    )

    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range (default: 1-1024)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help="Concurrent threads (default: 100)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds"
    )

    args = parser.parse_args()

    try:
        parts = args.ports.split("-")
        if len(parts) == 1:
            start_port = end_port = int(parts[0])
        elif len(parts) == 2:
            start_port, end_port = map(int, parts)
        else:
            raise ValueError

        if not 1 <= start_port <= end_port <= 65535:
            raise ValueError

        if not 1 <= args.threads <= 500:
            parser.error("Threads must be between 1 and 500")

        if args.timeout <= 0:
            parser.error("Timeout must be positive")

    except ValueError:
        parser.error(
            "Invalid port range. Use 80 or 1-1024."
        )

    try:
        scan_host(
            args.host,
            start_port,
            end_port,
            args.threads,
            args.timeout
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted.{RESET}")


if __name__ == "__main__":
    main()
