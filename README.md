# NetworkScanner
WTC-7PNTKR9N
This project scanns a network for live hosts, open ports and service banners

## Overview
A Python-based network scanning tool that discovers live hosts, identifies open ports, and retrieves service banners using socket programming.

## Features
- Scan networks in CIDR notation, IP ranges, or single hosts
- Concurrent scanning for improved performance
- Service banner grabbing for open ports
- Multiple output formats (human-readable text or JSON)
- Save results to file
- Docker containerization support

## Installation
### Prerequisites
- Python 3.7+
- No external dependencies required (uses only standard library)

### Direct Installation
1. Clone or download this repository
2. Ensure you have Python 3.7+ installed
3. The script is ready to run - no installation needed!

### Docker Installation
1. Build the Docker image:
   ```bash
   docker build -t network-scanner .
   ```

## Usage
### Direct Execution
```bash
# Scan a subnet for common web and SSH ports
python network_scanner.py -n 192.168.1.0/24 -p 80,443,22

# Scan a range of IPs for first 1000 ports with 2-second timeout
python network_scanner.py -n 10.0.0.1-10.0.0.10 -p 1-1000 --timeout 2.0

# Scan a single host and output JSON
python network_scanner.py -n 192.168.1.100 -p 80,443 --output json

# Save results to a file
python network_scanner.py -n 192.168.1.0/24 -p 22,80,443 --output-file scan_results.txt
```

### Docker Execution
```bash
# Scan using Docker (same arguments apply)
docker run --rm network-scanner -n 192.168.1.0/24 -p 80,443,22

# Scan and save results to host machine
docker run --rm -v $(pwd)/output:/app/output network-scanner -n 10.0.0.0/24 -p 22,80 --output-file /app/output/results.json
```

## Output Formats
### Text Format (Default)
Human-readable output with clear formatting:
```
============================================================
NETWORK SCAN RESULTS
============================================================
Total hosts scanned: 254
Live hosts found: 3

Host: 192.168.1.1
----------------------------------------
  Port    80 - open   - Banner: HTTP/1.1 200 OK
  Port   443 - open   - Banner: HTTP/1.1 200 OK
  Port    22 - open   - Banner: SSH-2.0-OpenSSH_7.9

Host: 192.168.1.10
----------------------------------------
  Port    22 - open   - Banner: SSH-2.0-OpenSSH_7.4
  Port   3306 - open   - Banner: MySQL 5.7.25

Host: 192.168.1.50
----------------------------------------
  No open ports found
```

### JSON Format
Machine-readable output for further processing:
```json
[
  {
    "host": "192.168.1.1",
    "alive": true,
    "ports": [
      {
        "port": 80,
        "status": "open",
        "banner": "HTTP/1.1 200 OK"
      },
      {
        "port": 443,
        "status": "open",
        "banner": "HTTP/1.1 200 OK"
      },
      {
        "port": 22,
        "status": "open",
        "banner": "SSH-2.0-OpenSSH_7.9"
      }
    ]
  },
  {
    "host": "192.168.1.10",
    "alive": true,
    "ports": [
      {
        "port": 22,
        "status": "open",
        "banner": "SSH-2.0-OpenSSH_7.4"
      },
      {
        "port": 3306,
        "status": "open",
        "banner": "MySQL 5.7.25"
      }
    ]
  }
]
```

## Arguments
- `-n, --network`: Network to scan (CIDR notation, IP range like 10.0.0.1-10.0.0.10, or single IP)
- `-p, --ports`: Ports to scan (comma-separated like 80,443,22 or range like 1-1000)
- `-t, --timeout`: Connection timeout in seconds (default: 1.0)
- `-o, --output`: Output format - "text" or "json" (default: text)
- `--output-file`: Save results to specified file instead of stdout

## Examples
### Common Scenarios
1. **Home network scan** (check for common services):
   ```bash
   python network_scanner.py -n 192.168.1.0/24 -p 22,80,443,3306,5432
   ```

2. **Quick port scan** (well-known ports):
   ```bash
   python network_scanner.py -n 10.0.0.0/24 -p 1-1024 --timeout 0.5
   ```

3. **Web server audit**:
   ```bash
   python network_scanner.py -n 172.16.0.0/16 -p 80,443,8080,8443 --output json --output-file web_servers.json
   ```

4. **Containerized scan** (using Docker):
   ```bash
   docker run --rm network-scanner -n 172.17.0.0/16 -p 23,80,443 --timeout 2.0
   ```

## How It Works
1. **Host Discovery**: The scanner first checks if hosts are alive by attempting connections to ports 80 and 443
2. **Port Scanning**: For each live host, it scans specified ports using concurrent threads
3. **Banner Grabbing**: On open ports, it attempts to read service banners to identify running services
4. **Results Aggregation**: Results are collected and formatted according to the selected output format

## Performance Notes
- Timeout values affect scan speed - lower timeouts scan faster but may miss slow responses
- Thread pools are used for concurrent host and port scanning
- Large networks (/16 or larger) may take considerable time - consider scanning in smaller chunks
- Docker containerization may add slight overhead but provides consistent execution environment

## Legal and Ethical Notice
This tool should only be used on networks and systems you own or have explicit permission to scan. Unauthorized network scanning may violate laws and regulations in your jurisdiction. Use responsibly and ethically.

## License
MIT License - feel free to modify and distribute as needed.