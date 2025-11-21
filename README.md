# Network Packet Sniffer

A network protocol analyzer built in C that captures and dissects network packets in real-time, similar to Wireshark.

## Overview
This packet sniffer captures raw network packets at Layer 2 (Ethernet) and parses protocol headers across multiple layers of the TCP/IP stack, providing detailed analysis of network traffic.

## Features
- **Raw Socket Programming**: Captures packets directly from network interfaces using AF_PACKET sockets
- **Multi-Protocol Support**: Parses Ethernet, IP, TCP, UDP, and ICMP headers
- **Real-Time Analysis**: Processes and displays packets as they arrive
- **Detailed Header Inspection**: Shows all protocol fields including:
  - MAC addresses (source/destination)
  - IP addresses and routing information
  - TCP flags, sequence numbers, ports
  - UDP ports and checksums
  - ICMP types and codes
- **Statistics Tracking**: Maintains counters for different protocol types
- **Professional Output**: Clean, formatted display of packet information

## Technical Implementation

### Key Technologies
- **Raw Sockets (AF_PACKET)**: Direct access to Layer 2 frames
- **Protocol Headers**: Uses standard Linux network headers (`netinet/ip.h`, `netinet/tcp.h`, etc.)
- **Binary Data Parsing**: Manual parsing of network byte order data
- **Signal Handling**: Graceful shutdown with Ctrl+C

### Network Protocols Parsed
- **Ethernet (Layer 2)**: Frame headers, MAC addresses
- **IP (Layer 3)**: IPv4 headers, routing information, TTL
- **TCP (Layer 4)**: Ports, flags (SYN, ACK, FIN, etc.), sequence numbers
- **UDP (Layer 4)**: Ports, length, checksums
- **ICMP (Layer 3)**: Ping requests/replies, error messages

## Compilation
```bash
gcc -Wall sniffer.c -o sniffer
```

## Usage

**Requires root privileges** (raw sockets need elevated permissions):
```bash
sudo ./sniffer
```

The sniffer will capture all packets on all network interfaces. Press `Ctrl+C` to stop and view statistics.

### Generating Test Traffic

Open another terminal and run:
```bash
# ICMP packets
ping google.com

# TCP/HTTP packets  
curl https://google.com

# DNS packets
nslookup google.com
```

## Sample Output
```
═══════════════════════════════════════════════════════════════
                    PACKET #42 (Size: 1340 bytes)
═══════════════════════════════════════════════════════════════

╔════════════════════════════════════════════════════════════╗
║                       IP HEADER                            ║
╠════════════════════════════════════════════════════════════╣
║ Source IP:       185.125.190.81
║ Dest IP:         172.21.97.64
║ Protocol:        6 (TCP)
║ TTL:             50
╚════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════╗
║                      TCP HEADER                            ║
╠════════════════════════════════════════════════════════════╣
║ Source Port:     80
║ Dest Port:       55776
║ Flags:           ACK PSH
║ Sequence:        1037162066
╚════════════════════════════════════════════════════════════╝
```

## Skills Demonstrated
- Low-level network programming in C
- Understanding of TCP/IP protocol stack
- Binary data manipulation and parsing
- Network byte order conversion (big-endian/little-endian)
- Raw socket programming
- Linux system programming
- Signal handling and resource cleanup

## Use Cases
- Network debugging and troubleshooting
- Protocol learning and education
- Traffic analysis and monitoring
- Security auditing
- Understanding how tools like Wireshark work internally

## Requirements
- Linux/WSL environment
- GCC compiler
- Root/sudo privileges
- Network interface

## Future Enhancements
- [ ] Packet filtering (by protocol, port, IP)
- [ ] TCP stream reassembly
- [ ] HTTP request/response parsing
- [ ] DNS query analysis
- [ ] Save captured packets to PCAP format
- [ ] GUI interface
- [ ] Performance optimization with ring buffers

## Author
Built as a networking systems project demonstrating deep understanding of network protocols and low-level C programming.
