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
  pip install scapy
  pip install cryptography
  ```

## Test Runs
```sh
python3 capture.py
```
2025-02-28 17:50:22.403320 DNS 192.168.151.128:41182 -> 192.168.151.2:53 www.youtube.com.
2025-02-28 17:50:22.412461 DNS 192.168.151.2:53 -> 192.168.151.128:41182 www.youtube.com.
2025-02-28 17:50:22.434212 TLS 192.168.151.128:58616 -> 142.251.179.190:443 www.youtube.com
2025-02-28 17:50:31.555284 DNS 192.168.151.128:35569 -> 192.168.151.2:53 www.google.com.
2025-02-28 17:50:31.564033 DNS 192.168.151.2:53 -> 192.168.151.128:35569 www.google.com.
2025-02-28 17:50:31.584963 HTTP 192.168.151.128:57736 -> 142.251.179.147:80 www.google.com GET /
2025-02-28 17:51:16.393594 DNS 192.168.151.128:57761 -> 192.168.151.2:53 www.aniwatch.com.
2025-02-28 17:51:16.397924 DNS 192.168.151.2:53 -> 192.168.151.128:57761 www.aniwatch.com.

```sh
python3 capture.py -i lo
``` 
2025-02-28 17:54:40.160422 HTTP 127.0.0.1:34164 -> 127.0.0.1:9000 localhost GET
2025-02-28 17:54:40.160423 HTTP 127.0.0.1:34164 -> 127.0.0.1:9000 localhost GET
2025-02-28 17:54:43.578907 HTTP 127.0.0.1:34176 -> 127.0.0.1:9000 localhost GET
2025-02-28 17:54:43.578908 HTTP 127.0.0.1:34176 -> 127.0.0.1:9000 localhost GET

## Notes
- The tool will automatically select the default network interface eth0 if none is specified.
- The provided BPF filter syntax follows tcpdump standards.
- The tool is designed to parse only the request portions of the traffic (e.g., HTTP GET/POST, TLS Client Hello, and DNS queries) and does not process responses.
- Creating a virtual environment is neccessary for mac users

