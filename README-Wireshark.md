# Network Traffic Analysis with Wireshark

## 📋 Project Overview

This repository contains a comprehensive network traffic analysis project conducted using **Wireshark** on Kali Linux. The project demonstrates packet capture, protocol analysis, and the application of display filters to identify and examine various network protocols including HTTP, TCP, DNS, TLS, and OCSP.

## 🎯 Objectives

- Install and configure Wireshark for network traffic analysis
- Capture live network traffic on active network interfaces
- Identify and analyze multiple network protocols
- Apply display filters to isolate specific traffic patterns
- Export captured traffic as `.pcap` files for further analysis
- Document findings with detailed protocol analysis

## 🛠 Tools & Environment

- **Operating System**: Kali Linux 2025.3 (VirtualBox)
- **Network Analyzer**: Wireshark
- **Network Interface**: eth0 (or active interface)
- **Capture Duration**: ~1-2 minutes
- **File Format**: `.pcap` (Packet Capture)

## 📊 Captured Protocols Summary

| Protocol | Count | Description |
|----------|-------|-------------|
| **HTTP** | Multiple | Hypertext Transfer Protocol - Web traffic |
| **TCP** | Majority | Transmission Control Protocol - Connection-oriented |
| **DNS** | Multiple | Domain Name System - Name resolution |
| **TLSv1.3** | Multiple | Transport Layer Security - Encrypted traffic |
| **OCSP** | Several | Online Certificate Status Protocol |

**Total Packets Captured**: 1,750 packets  
**Packets Displayed After Filtering**: 4-102 packets (depending on filter)

## 🔍 Detailed Protocol Analysis

### 1. HTTP (Hypertext Transfer Protocol)

**Observations**:
- HTTP requests and responses captured during web browsing
- Destination IPs include `142.251.222.67` and `142.250.207.162`
- Protocol running on TCP port 80
- User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

**Key Findings**:
- Multiple HTTP GET requests observed
- Clear-text transmission (non-encrypted)
- Contains user browsing data and cookies

### 2. TCP (Transmission Control Protocol)

**Observations**:
- Connection-oriented protocol forming majority of traffic
- Source IP: `192.168.100.3`
- Destination IPs: Multiple external servers
- Ports observed: 443 (HTTPS), 80 (HTTP)
- TCP flags: SYN, ACK, PSH observed
- Window sizes vary: 64240, 65535

**Key Findings**:
- Three-way handshake visible in captures
- Sequence and acknowledgment numbers tracked
- Multiple concurrent TCP streams established

### 3. DNS (Domain Name System)

**Observations**:
- DNS queries to `192.168.55.1` (local DNS server)
- Destination resolution: `192.168.100.3`
- Queries for: `www.googleadservices.com`
- Query types: A records (IPv4) and AAAA records (IPv6)
- Response codes: Standard query response

**Key Findings**:
- DNS operates on UDP port 53
- Query-response pattern clearly visible
- Multiple DNS lookups for Google services

### 4. TLS v1.3 (Transport Layer Security)

**Observations**:
- Encrypted application data transfers
- Change Cipher Spec messages observed
- Running over TCP port 443
- Multiple TLS handshakes captured

**Key Findings**:
- Modern encryption protocol in use
- Application data encrypted and unreadable
- Secure communications established

### 5. OCSP (Online Certificate Status Protocol)

**Observations**:
- Certificate validation requests
- Source: `192.168.100.3`
- Destination: `142.251.222.67`
- Multiple OCSP requests and responses captured

**Key Findings**:
- Real-time certificate status checking
- Part of PKI infrastructure
- Validates SSL/TLS certificates

## 🔧 Wireshark Display Filters Reference

### HTTP Display Filters

```
# Show all HTTP traffic
http

# Show only HTTP requests
http.request

# Filter HTTP GET requests
http.request.method == "GET"

# Filter HTTP POST requests
http.request.method == "POST"

# Show HTTP responses
http.response

# Filter successful HTTP responses (200 OK)
http.response.code == 200

# Filter 404 errors
http.response.code == 404

# Filter by specific host
http.host == "www.google.com"

# Filter URIs containing specific string
http.request.uri contains "search"

# Show HTTP cookies
http.cookie

# Filter HTTP traffic on port 80
tcp.port == 80
```

### TCP Display Filters

```
# Show all TCP traffic
tcp

# Filter by TCP port 80 (HTTP)
tcp.port == 80

# Filter by TCP port 443 (HTTPS)
tcp.port == 443

# Filter by destination port
tcp.dstport == 80

# Filter by source port
tcp.srcport == 443

# Show TCP SYN packets (connection initiation)
tcp.flags.syn == 1

# Show TCP RST packets (connection reset)
tcp.flags.reset == 1

# Show only SYN packets without ACK (new connections)
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Show TCP packets with analysis flags (errors, retransmissions)
tcp.analysis.flags

# Show TCP retransmissions
tcp.analysis.retransmission

# Show TCP zero window (buffer full)
tcp.window_size == 0

# Show TCP packets with data payload
tcp.len > 0

# Filter TCP streams by specific IP
tcp and ip.addr == 192.168.100.3
```

### DNS Display Filters

```
# Show all DNS traffic
dns

# Filter DNS queries for specific domain
dns.qry.name == "www.google.com"

# Filter DNS queries containing specific string
dns.qry.name contains "google"

# Show only DNS queries (requests)
dns.flags.response == 0

# Show only DNS responses
dns.flags.response == 1

# Filter A record queries (IPv4)
dns.qry.type == 1

# Filter AAAA record queries (IPv6)
dns.qry.type == 28

# Filter DNS traffic on port 53
udp.port == 53

# Filter DNS from specific IP
dns and ip.addr == 192.168.100.3

# Filter DNS queries originating from local machine
dns and ip.src == 192.168.100.3

# Filter DNS responses to local machine
dns and ip.dst == 192.168.100.3
```

### Combined & Advanced Filters

```
# Show HTTP or DNS traffic only
http or dns

# Show all TCP or UDP traffic
tcp or udp

# Filter HTTP traffic from specific IP
http and ip.addr == 192.168.100.3

# Filter DNS queries from source IP
dns and ip.src == 192.168.100.3

# Show web traffic (HTTP and HTTPS)
tcp.port == 80 or tcp.port == 443

# Exclude broadcast noise (ARP, ICMP, STP)
!(arp or icmp or stp)

# Search for specific string in TCP packets
tcp contains "google"

# Search for any packet containing string
frame contains "mozilla"

# Filter by IP range
ip.addr == 192.168.0.0/16

# Filter conversation between two IPs
ip.addr == 192.168.100.3 and ip.addr == 142.251.222.67

# Filter by MAC address
eth.addr == 08:00:27:XX:XX:XX

# Show only IPv4 traffic
ip

# Show only IPv6 traffic
ipv6

# Filter by packet length
frame.len > 1000

# Filter by time range
frame.time >= "Oct 28, 2025 17:42:00"
```

## 📁 Repository Structure

```
wireshark-traffic-analysis/
├── README.md
├── Wireshark-Analysis-Report.md
├── screenshots/
│   ├── http-ocsp-capture.png
│   ├── tcp-tls-capture.png
│   └── dns-capture.png
├── captures/
│   └── capture.pcap
└── filters/
    └── display-filters.txt
```

## 🚀 Step-by-Step Methodology

### 1. Installation & Setup

```bash
# Update system packages
sudo apt update

# Install Wireshark (if not already installed)
sudo apt install wireshark -y

# Add user to wireshark group for packet capture permissions
sudo usermod -aG wireshark $USER

# Launch Wireshark
sudo wireshark
```

### 2. Starting Packet Capture

1. Open Wireshark application
2. Select active network interface (e.g., `eth0`, `wlan0`)
3. Click **Start Capture** (blue shark fin icon)
4. Allow capture to run for 1-2 minutes

### 3. Generating Network Traffic

During capture, perform these activities:
- Browse websites (e.g., google.com)
- Ping external servers (`ping google.com`)
- Access HTTPS sites
- Perform DNS lookups

### 4. Stopping Capture

1. Click **Stop Capture** (red square icon)
2. Packets will be displayed in the main window

### 5. Applying Display Filters

- Use the display filter bar at the top of the window
- Enter filter expressions (e.g., `http`, `dns`, `tcp.port == 80`)
- Press Enter to apply
- Green bar = valid filter
- Red bar = invalid syntax

### 6. Exporting Capture File

```
File → Export Specified Packets
- Save as: capture.pcap
- Format: Wireshark/tcpdump - pcap
- Packet Range: All packets or Displayed (filtered)
```

## 📈 Key Statistics

### Traffic Distribution
- **TCP Traffic**: ~85% of total packets
- **DNS Traffic**: ~2% of total packets  
- **HTTP Traffic**: ~5% of total packets
- **TLS/Encrypted**: ~60% of TCP traffic
- **Other Protocols**: ~8%

### Top Destinations
1. `142.251.222.67` (Google services)
2. `142.250.207.162` (Google services)
3. `192.168.55.1` (Local DNS server)

### Source IP
- `192.168.100.3` (Kali Linux VM)

## 🔒 Security Observations

1. **Unencrypted HTTP Traffic**: Some traffic still uses HTTP (port 80), which transmits data in clear-text
2. **OCSP Validation**: Certificate status checking is actively performed
3. **TLS 1.3 Adoption**: Modern encryption protocols are being used
4. **DNS Privacy**: DNS queries are unencrypted and visible

## 💡 Learning Outcomes

Through this analysis, the following skills were developed:

- **Packet Capture**: Capturing live network traffic using Wireshark
- **Protocol Identification**: Recognizing HTTP, TCP, DNS, TLS, and OCSP protocols
- **Display Filters**: Applying 40+ different filter expressions
- **Traffic Analysis**: Understanding packet headers, flags, and payloads
- **Network Security**: Identifying encrypted vs. unencrypted communications
- **PCAP Export**: Saving captures for archival and further analysis

## 🔍 Analysis Techniques Applied

1. **Protocol Hierarchy Statistics**: Understanding traffic distribution
2. **Follow TCP Stream**: Reconstructing full conversations
3. **Expert Information**: Identifying warnings and errors
4. **IO Graphs**: Visualizing traffic patterns over time
5. **Packet Details Inspection**: Examining headers and payloads
6. **Time Sequence Analysis**: Understanding temporal patterns

## 📚 Useful Wireshark Features Used

- **Display Filters**: Isolating specific protocols and patterns
- **Coloring Rules**: Visual identification of packet types
- **Statistics → Protocol Hierarchy**: Traffic breakdown by protocol
- **Statistics → Conversations**: Endpoint communication pairs
- **Statistics → Endpoints**: Individual host statistics
- **Export Objects**: Extracting HTTP files and objects

## 🎓 Practical Applications

This analysis demonstrates skills essential for:

- **Network Troubleshooting**: Identifying connectivity and performance issues
- **Security Monitoring**: Detecting suspicious traffic patterns
- **Protocol Analysis**: Understanding application-layer communications
- **Incident Response**: Investigating security incidents
- **Performance Optimization**: Identifying network bottlenecks
- **Compliance Auditing**: Verifying security policies

## 📖 Additional Resources

- [Wireshark Official Documentation](https://www.wireshark.org/docs/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)

## 🤝 Best Practices Followed

1. **Capture Duration**: Limited to 1-2 minutes to keep file size manageable
2. **Targeted Filtering**: Used display filters to focus on relevant traffic
3. **Documentation**: Comprehensive notes on protocols and findings
4. **File Management**: Organized captures and screenshots systematically
5. **Privacy Awareness**: Removed sensitive information from public documentation

## 🔄 Future Enhancements

- Analyze different network scenarios (FTP, SSH, SMTP)
- Capture malicious traffic samples for security analysis
- Implement capture filters to reduce noise
- Analyze wireless traffic (802.11)
- Create custom protocol dissectors

## 👨‍💻 Author

**Network Traffic Analysis Lab**  
Date: October 28, 2025  
Platform: Kali Linux 2025.3 on VirtualBox

---

**Note**: This analysis was conducted in a controlled lab environment for educational purposes. All IP addresses and network information are from a private virtual network.
