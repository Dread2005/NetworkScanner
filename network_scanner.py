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

def scan_network(network: str, ports: List[int], timeout: float = 1.0) -> List[Dict]:
    """
    Scan an entire network for live hosts and open ports.

    Args:
        network: Network in CIDR notation (e.g., '192.168.1.0/24')
        ports: List of port numbers to scan
        timeout: Connection timeout in seconds

    Returns:
        List of dictionaries containing scan results for each host
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    except ValueError:
        # If not CIDR notation, treat as single host or range
        if '-' in network:
            start_ip, end_ip = network.split('-')
            start = int(ipaddress.ip_address(start_ip))
            end = int(ipaddress.ip_address(end_ip))
            hosts = [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
        else:
            hosts = [network]

    print(f"Scanning {len(hosts)} hosts in network {network}")
    print(f"Scanning ports: {ports}")

    results = []
    # Use thread pool to scan multiple hosts concurrently
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_host = {
            executor.submit(scan_host, host, ports, timeout): host
            for host in hosts
        }

        for future in as_completed(future_to_host):
            result = future.result()
            results.append(result)

            # Print progress
            alive_count = sum(1 for r in results if r["alive"])
            print(f"Progress: {len(results)}/{len(hosts)} hosts scanned, {alive_count} alive")

    return results


def format_output_text(results: List[Dict]) -> str:
    """
    Format scan results as human-readable text.

    Args:
        results: List of scan result dictionaries

    Returns:
        Formatted text string
    """
    output = []
    output.append("=" * 60)
    output.append("NETWORK SCAN RESULTS")
    output.append("=" * 60)

    alive_hosts = [r for r in results if r["alive"]]
    output.append(f"Total hosts scanned: {len(results)}")
    output.append(f"Live hosts found: {len(alive_hosts)}")
    output.append("")

    for host_result in alive_hosts:
        output.append(f"Host: {host_result['host']}")
        output.append("-" * 40)

        if host_result["ports"]:
            for port_info in host_result["ports"]:
                output.append(f"  Port {port_info['port']:5d} - {port_info['status']:6s} - Banner: {port_info['banner'][:50]}")
        else:
            output.append("  No open ports found")
        output.append("")

    return "\n".join(output)

def main():
    """Main function to handle command line arguments and execute scan."""
    parser = argparse.ArgumentParser(
        description="Network Scanner - Scan networks for live hosts, open ports, and service banners",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py -n 192.168.1.0/24 -p 80,443,22
  python network_scanner.py -n 10.0.0.1-10.0.0.10 -p 1-1000 --timeout 2.0
  python network_scanner.py -n 192.168.1.100 -p 80,443 --output json
        """
    )

    parser.add_argument(
        "-n", "--network",
        required=True,
        help="Network to scan (CIDR notation, IP range, or single IP)"
    )

    parser.add_argument(
        "-p", "--ports",
        required=True,
        help="Ports to scan (comma-separated or range, e.g., '80,443,22' or '1-1000')"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--output-file",
        help="Save results to specified file"
    )

    args = parser.parse_args()

    # Parse ports
    ports = []
    try:
        if '-' in args.ports and ',' not in args.ports:
            # Port range like 1-1000
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            # Comma-separated ports
            ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print("Error: Invalid port format. Use comma-separated values or range (e.g., '80,443' or '1-1000')")
        sys.exit(1)

    # Validate timeout
    if args.timeout <= 0:
        print("Error: Timeout must be positive")
        sys.exit(1)

    # Perform scan
    try:
        results = scan_network(args.network, ports, args.timeout)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)

    # Format and output results
    if args.output == "json":
        output_data = json.dumps(results, indent=2)
    else:
        output_data = format_output_text(results)

    # Output to file or stdout
    if args.output_file:
        try:
            with open(args.output_file, 'w') as f:
                f.write(output_data)
            print(f"Results saved to {args.output_file}")
        except IOError as e:
            print(f"Error writing to file: {e}")
            sys.exit(1)
    else:
        print(output_data)
git

if __name__ == "__main__":
    main()