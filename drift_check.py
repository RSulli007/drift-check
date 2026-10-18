# Simple port scanner program using the built-in Socket module.
# Port scanner tested on Virtual Box Linux machine.

import socket
import time
from concurrent.futures import ThreadPoolExecutor

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


if __name__ == "__main__":
        host = input("Target host or IP: ")
        start = int(input("Starting port: "))
        end = int(input("Ending port: "))

        began = time.perf_counter()
        ip, ports = scan_ports(host, start, end)
        elapsed = time.perf_counter() - began

        print(f"Open ports on {ip}: {ports}")
        print(f"Scanned {end - start + 1} ports in {elapsed:.1f} seconds")