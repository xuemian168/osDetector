## [中文](./README_CN.md)| English

# OS Detector

## Description
This is an operating system detection tool based on TCP/IP stack fingerprinting technology, implemented in Go. The tool references the operating system detection principles of nmap and can identify the operating system type of the target host by analyzing the characteristics of network packets.

## Features

- Supports host alive detection via ICMP and TCP
- Supports operating system detection via TCP fingerprinting
- Supports operating system detection via SMB protocol
- Analyzes TCP header characteristics (window size)
- Supports identification of multiple operating systems (Windows, Linux, macOS)
- Provides detailed detection process logs

## Usage
```bash
# Install dependencies
go mod tidy

# Run (Pls Run with sudo, otherwise maybe u dont have permission to send ICMP req)
sudo go run main.go -t 192.168.1.1  # Specify target IP address
sudo go run main.go -t 192.168.1.1 -v  # Show detailed information
```

## Implementation Principle
This tool uses multiple detection methods to identify the target operating system:

1. Host Alive Detection
   - ICMP ping
   - TCP port scanning
2. TCP Fingerprinting
   - TCP window size analysis
   - Common port scanning (80, 443, 22, 445, etc.)
3. SMB Protocol Analysis
   - SMB version detection
   - Operating system information extraction

### Detection Process

1. Host alive detection using ICMP and TCP
2. TCP fingerprinting analysis
3. SMB protocol detection (if available)
4. Combine results and determine final OS type

## References
- [NMAP](https://nmap.org/nmap-fingerprinting-article.txt)
- [RFC 793](https://datatracker.ietf.org/doc/html/rfc761)
- [RFC 9293](https://www.rfc-editor.org/info/rfc9293)

## TODO LIST
- [ ] Support for Bunch of IPs
- [ ] Support more Portocol Detection