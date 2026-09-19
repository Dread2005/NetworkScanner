#!/usr/bin/env python3
"""
Network Scanner - A Python script to scan networks for live hosts, open ports, and service banners.

This script uses socket programming to perform network scanning operations.
"""

import socket
import sys
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import ipaddress


def is_host_alive(host: str, timeout: float = 1.0) -> bool:
    """
    Check if a host is alive by attempting to connect to port 80 or 443.

    Args:
        host: Target host IP address
        timeout: Connection timeout in seconds

    Returns:
        True if host responds, False otherwise
    """
    # Try common ports first
    for port in [80, 443]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except socket.error:
            continue
    return False


def scan_port(host: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
    """
    Scan a single port on a host and attempt to grab service banner.

    Args:
        host: Target host IP address
        port: Port number to scan
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with port info and banner if successful, None otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result == 0:
            # Port is open, try to grab banner
            banner = ""
            try:
                sock.settimeout(2.0)  # Slightly longer timeout for banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except socket.error:
                banner = "No banner retrieved"
            finally:
                sock.close()

            return {
                "port": port,
                "status": "open",
                "banner": banner if banner else "No banner retrieved"
            }
        else:
            sock.close()
            return None

    except socket.error:
        return None

def scan_host(host: str, ports: List[int], timeout: float = 1.0) -> Dict:
    """
    Scan all specified ports on a single host.

    Args:
        host: Target host IP address
        ports: List of port numbers to scan
        timeout: Connection timeout in seconds

    Returns:
        Dictionary containing host information and scan results
    """
    print(f"Scanning host: {host}")

    # First check if host is alive
    if not is_host_alive(host, timeout):
        return {
            "host": host,
            "alive": False,
            "ports": []
        }

    # Scan ports using thread pool for efficiency
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    # Sort results by port number
    open_ports.sort(key=lambda x: x["port"])

    return {
        "host": host,
        "alive": True,
        "ports": open_ports
    }


if __name__ == "__main__":
    main()