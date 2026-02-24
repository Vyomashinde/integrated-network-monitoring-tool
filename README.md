# Integrated Network Monitoring and Analysis Tool

This is a comprehensive web-based tool for network monitoring and analysis, built with Python and Flask. It provides real-time network diagnostics, device discovery, traffic analysis, and system monitoring capabilities through a user-friendly web interface.

## Architecture and Technology Stack

### Backend Framework
- **Flask**: A lightweight WSGI web application framework in Python. Used for building the REST API and serving the web interface.
  - Handles routing for web pages and API endpoints
  - Manages request/response cycles
  - Provides template rendering for the frontend

### Core Python Libraries
- **Scapy**: A powerful packet manipulation library for network analysis.
  - Used for packet sniffing and capture (`sniff()` function)
  - Implements ARP scanning for LAN device discovery (`arping()`)
  - Performs traceroute operations (`traceroute()`)
  - Handles low-level network packet analysis

- **Speedtest-cli**: A command-line interface for testing internet bandwidth.
  - Measures download and upload speeds
  - Finds the best server for accurate testing
  - Returns results in Mbps

- **Python-nmap**: A Python wrapper for the Nmap network scanner.
  - Performs port scanning on target hosts
  - Identifies open ports and associated services
  - Supports various scan types (TCP, UDP, etc.)

- **Netifaces**: A library for accessing network interface information.
  - Retrieves IP addresses and MAC addresses for all network interfaces
  - Provides detailed network configuration data

- **Psutil**: A cross-platform library for system and process utilities.
  - Monitors CPU usage percentage
  - Tracks network I/O statistics (bytes sent/received)
  - Provides real-time system performance metrics

- **Subprocess**: Standard Python library for running external commands.
  - Executes system ping commands for latency testing
  - Handles command output parsing and error management

- **Socket**: Standard Python library for network communications.
  - Performs DNS lookups (`gethostbyname()`)
  - Retrieves local IP address for network scanning
  - Provides low-level network utilities

### Frontend Technologies
- **HTML/CSS/JavaScript**: Basic web technologies for the user interface.
  - HTML templates rendered by Flask (`render_template()`)
  - CSS for styling (located in `static/css/`)
  - JavaScript for client-side interactions (located in `static/js/`)

### Additional Dependencies
- **Threading**: For concurrent execution of network operations
- **Datetime**: For timestamping captured packets and logs
- **JSON**: For API response formatting

## Features and Functionalities

### 1. Latency Measurement (`/api/latency/<host>`)
**Purpose**: Measures network latency, packet loss, and jitter to a target host.

**How it works**:
- Uses `subprocess` to execute system ping command (`ping -n 10 <host>`)
- Parses the output to extract individual ping times
- Calculates average latency, packet loss percentage, and jitter (max-min difference)
- Returns JSON with metrics or error message

**Use case**: Diagnose network connectivity issues and performance.

### 2. LAN Device Discovery (`/api/devices`)
**Purpose**: Scans the local network to discover active devices.

**How it works**:
- Determines local IP address using `socket.gethostbyname()`
- Constructs network range (e.g., 192.168.1.0/24)
- Uses Scapy's `arping()` to send ARP requests and collect responses
- Extracts IP and MAC addresses from ARP replies
- Returns list of active devices with their network information

**Use case**: Network inventory and security monitoring.

### 3. Packet Capture and Analysis (`/api/start_capture`, `/api/logs`, `/api/protocol_analysis`)
**Purpose**: Captures network packets and analyzes traffic patterns.

**How it works**:
- `start_capture`: Initiates packet sniffing for 10 seconds using Scapy's `sniff()`
- Runs in a separate thread to avoid blocking the main application
- `packet_callback`: Processes each captured packet, extracting source/destination IPs, protocol, and timestamp
- Stores packet information in an in-memory list (`logs`)
- `protocol_analysis`: Aggregates packet counts by protocol (TCP, UDP, ICMP)

**Use case**: Network traffic monitoring and protocol distribution analysis.

### 4. Bandwidth Testing (`/api/bandwidth`)
**Purpose**: Measures internet connection speed.

**How it works**:
- Initializes Speedtest client
- Finds the best test server automatically
- Performs download and upload speed tests
- Converts results from bits to Mbps
- Returns formatted speed measurements

**Use case**: Internet connection performance evaluation.

### 5. Port Scanning (`/api/port_scan/<host>`)
**Purpose**: Identifies open ports and services on a target host.

**How it works**:
- Uses python-nmap to interface with Nmap scanner
- Scans ports 1-1024 on the target host
- Adds `-Pn --host-timeout 10s` arguments to limit how long the scan
  will wait for a response, preventing long hang-ups on remote or
  unreachable addresses.
- Parses scan results to identify open ports
- Retrieves service names associated with open ports
- If no hosts are returned (timeout/unreachable) returns an error message
- Returns list of open ports with service information

**Use case**: Network security assessment and service discovery.
### 6. DNS Lookup (`/api/dns_lookup/<domain>`)
**Purpose**: Resolves domain names to IP addresses.

**How it works**:
- Uses `socket.gethostbyname()` to perform DNS resolution
- Returns the resolved IP address or error message

**Use case**: Domain name resolution testing and troubleshooting.

### 7. Traceroute (`/api/traceroute/<host>`)
**Purpose**: Maps the network path to a destination host.

**How it works**:
- Uses Scapy's `traceroute()` function
- Sends packets with increasing TTL values (1-20)
- Records IP addresses and round-trip times for each hop
- Returns list of network hops with timing information

**Use case**: Network path analysis and routing diagnostics.

### 8. Network Interface Information (`/api/interfaces`)
**Purpose**: Displays information about network interfaces.

**How it works**:
- Uses netifaces to query all network interfaces
- Extracts IP addresses and MAC addresses for each interface
- Returns structured data about network configuration

**Use case**: Network configuration review and troubleshooting.

### 9. System Statistics (`/api/system_stats`)
**Purpose**: Monitors system performance metrics.

**How it works**:
- Uses psutil to measure CPU usage over 1-second interval
- Retrieves network I/O counters (bytes sent/received)
- Returns real-time system performance data

**Use case**: System resource monitoring during network operations.

### 10. Result Verification (`/api/verify/<host>`)
**Purpose**: Provides raw ping output for manual verification.

**How it works**:
- Executes ping command and returns raw output
- Useful for detailed analysis of ping results

**Use case**: Advanced troubleshooting and manual verification.

## API Endpoints

All endpoints return JSON responses. Error handling is implemented for each endpoint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serves the main web interface |
| `/api/latency/<host>` | GET | Get latency, packet loss, and jitter |
| `/api/devices` | GET | Scan and list LAN devices |
| `/api/start_capture` | GET | Start packet capture (10 seconds) |
| `/api/logs` | GET | Retrieve captured packet logs |
| `/api/protocol_analysis` | GET | Get protocol distribution statistics |
| `/api/bandwidth` | GET | Measure download/upload speeds |
| `/api/port_scan/<host>` | GET | Scan open ports on target host |
| `/api/dns_lookup/<domain>` | GET | Resolve domain to IP address |
| `/api/traceroute/<host>` | GET | Perform traceroute to host |
| `/api/interfaces` | GET | Get network interface information |
| `/api/system_stats` | GET | Get system performance metrics |
| `/api/verify/<host>` | GET | Get raw ping output |

## Installation

1. Install Python 3.x
2. Install dependencies: `pip install -r requirements.txt`
3. **Install Nmap**: Download and install from https://nmap.org/download.html (required for port scanning)
4. For packet capture and device discovery, install Npcap (https://nmap.org/npcap/)
5. Run the application as administrator (for packet capture and ARP scanning)
6. Run: `python app.py`
7. Open browser to http://localhost:5000

## Requirements

- Python 3.6+
- Administrator privileges (for packet capture)
- Nmap installed and in PATH
- Npcap for Windows packet capture

## Security Considerations

- This tool performs network scanning and packet capture
- Run with appropriate permissions and only on networks you own or have permission to scan
- Debug mode is enabled for development; disable for production use
- Consider implementing authentication for production deployments