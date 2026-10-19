# Simple port scanner program using the built-in Socket module.
# Port scanner tested on Virtual Box Linux machine.

import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


def check_port(target_ip, port):
    """Try to connect to one port. Return the port number if open, otherwise None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((target_ip, port)) # 0 means the connection succeeded
    sock.close()
    return port if result == 0 else None


def scan_ports(target_host, starting_port, ending_port):
    """Scan a range of TCP ports and return the IP and a list of open ports."""
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"Could not resolve host: {target_host}")
        return None, []

    ports = range(starting_port, ending_port + 1)

    # Check up to 100 ports at the same time instead of one by one.
    with ThreadPoolExecutor(max_workers=100) as pool:
        results = pool.map(lambda port: check_port(target_ip, port), ports)

    open_ports = [port for port in results if port is not None]
    return target_ip, open_ports


def load_baseline(path="baseline.json"):
    """Read the expected-state file. Return an empty dict if it doesn't exist."""
    baseline_file = Path(path)
    if not baseline_file.exists():
        print(f"No baseline file found at {path}")
        return {}
    return json.loads(baseline_file.read_text())


def compare_to_baseline(target_ip, open_ports, baseline):
    """Compare a scan to the baseline and describe any drift."""
    if target_ip not in baseline:
        return {"status": "NO_BASELINE", "unexpected_open": [], "missing_expected": []}

    expected = set(baseline[target_ip]["expected_open_ports"])
    actual = set(open_ports)

    unexpected_open = sorted(actual - expected) # open now, but shouldn't be
    missing_expected = sorted(expected - actual) # should be open, but isn't

    status = "DRIFT" if unexpected_open or missing_expected else "PASS"
    return {
        "status": status,
        "unexpected_open": unexpected_open,
        "missing_expected": missing_expected,
    }


def save_scan(target_host, target_ip, starting_port, ending_port, open_ports, elapsed, drift):
    """Save one scan result, including its drift check, as a timestamped JSON file in the scans folder."""
    scanned_at = datetime.now(timezone.utc)

    record = {
        "target": target_host,
        "ip": target_ip,
        "port_range": [starting_port, ending_port],
        "open_ports": open_ports,
        "scanned_at": scanned_at.isoformat(),
        "duration_seconds": round(elapsed, 1),
        "drift": drift,
    }

    scans_dir = Path("scans")
    scans_dir.mkdir(exist_ok=True) # create the folder the first time

    # Windows doesn't allow colons in filenames, so use a compact timestamp.
    filename = scans_dir / f"scan_{target_ip}_{scanned_at.strftime('%Y%m%dT%H%M%SZ')}.json"
    filename.write_text(json.dumps(record, indent=2))
    return filename


if __name__ == "__main__":
    host = input("Target host or IP: ")
    start = int(input("Starting port: "))
    end = int(input("Ending port: "))

    began = time.perf_counter()
    ip, ports = scan_ports(host, start, end)
    elapsed = time.perf_counter() - began

    if not ip:
        sys.exit(2) # couldn't resolve the host

    print(f"Open ports on {ip}: {ports}")
    print(f"Scanned {end - start + 1} ports in {elapsed:.1f} seconds")

    drift = compare_to_baseline(ip, ports, load_baseline())

    if drift["status"] == "PASS":
        print("PASS: host matches its baseline.")
    elif drift["status"] == "DRIFT":
        print("DRIFT DETECTED:")
        if drift["unexpected_open"]:
            print(f" Unexpected open ports: {drift['unexpected_open']}")
        if drift["missing_expected"]:
            print(f" Expected ports not open: {drift['missing_expected']}")
    else:
        print(f"No baseline entry for {ip}; nothing to compare against.")

    saved = save_scan(host, ip, start, end, ports, elapsed, drift)
    print(f"Saved results to {saved}")

    # Exit code 1 signals drift, so a scheduler or pipeline can alert on it.
    sys.exit(1 if drift["status"] == "DRIFT" else 0)