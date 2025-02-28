# capture.py

## Description
capture.py is a network traffic analyzer that captures packets either live from a network interface or from a previously saved trace file (tcpdump format). The tool is designed to recognize HTTP, TLS, and DNS traffic, regardless of the destination port number. It parses and displays key details from:

- **HTTP traffic:** It detects GET and POST requests and extracts the HTTP method, destination host (from the "Host:" header), and the Request URI.
- **TLS traffic:** It parses the Client Hello message to extract the destination host from the Server Name Indication (SNI) field.
- **DNS traffic:** It parses A record requests (with optional support for AAAA requests) and prints the requested domain name.

For all types of traffic, the tool prints a timestamp, source IP:port, and destination IP:port.

This tool does not perform TCP stream reassembly; it simply analyzes each packet individually. This makes it lightweight and ideal for quickly detecting traffic from “hidden” HTTP, TLS, or DNS servers running on non-standard ports.

## Usage

python3 capture.py [-i interface] [-r tracefile] expression

- `-i interface`  
  Live capture from the specified network device (e.g., `eth0`).  
  If not specified, the program will automatically select a default interface (e.g., `eth0`).

- `-r tracefile`  
  Read packets from a previously captured tcpdump file. This is useful for offline analysis. The -r option is prioritized over -i if both are provided.git 

- `expression`  
  A BPF filter expression (similar to tcpdump) to restrict the captured traffic to a subset (e.g., "host 192.168.0.123").

## Installation

### Prerequistes
- **Python 3.x**
- **pip** (Python package manager)

### **Required Dependencies**
The tool relies on **Scapy** for packet capture and analysis.

#### **Installation Steps**
1. **Clone the Repository**
  ```sh
  git clone https://github.com/kailash-anand/network-sniffer.git
  cd network-sniffer
  ```

2. **(Optional) Create a Virtual Environment**
  ```sh
  python3 -m venv venv
  source venv/bin/activate
  ```

3. **Install Dependencies**
  ```sh
  pip install -r requirements.txt
  ```

## Notes
- The tool will automatically select the default network interface eth0 if none is specified.
- The provided BPF filter syntax follows tcpdump standards.
- The tool is designed to parse only the request portions of the traffic (e.g., HTTP GET/POST, TLS Client Hello, and DNS queries) and does not process responses.
- Creating a virtual environment is neccessary for mac users

