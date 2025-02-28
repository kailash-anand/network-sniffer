from scapy.all import *

def tcp_parser(packet):
    items = {}

    if packet.haslayer('Raw'):
        raw_data = packet[Raw].load.decode(errors='ignore') 
        if "HTTP" in raw_data and raw_data.startswith(("GET ", "POST ", "HEAD ")):
            items['hostname'] = "localhost"
            items['protocol'] = "HTTP"

            requests = raw_data.split('\r\n')
            if requests:
                line = requests[0].split()
                if len(line) >= 2 and line[0] in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}:
                    method = line[0]
                    items['method'] = str(method)

    return items

