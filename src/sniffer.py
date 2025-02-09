from scapy.all import * 
from src.parsers.http_parsper import http_parser
from src.parsers.dns_parser import dns_parser
from src.parsers.tls_parser import tls_parser
from datetime import datetime
import cryptography

PROTOCOL_TABLE = {
    "DNS": "DNS",
    "TLS": "TLS",
    "HTTP": "HTTP",
    "TCP": "TCP",
    "UDP": "UDP",
    "ICMP": "ICMP"
}

PARSER_MAP = {
    "DNS" : dns_parser,
    "TLS" : tls_parser,
    "HTTP" : http_parser
}

def start_sniff(interface: str, tracefile: str, expression: str) -> None:
    try:
        load_dependencies()
        sniff(iface=interface, filter=expression, prn=process_packet, store=False) 
    
    except Exception as e:
        print(str(e))

def load_dependencies():
    load_layer('tls')
    load_layer('http')

def process_packet(packet) -> None:
    timestamp = datetime.fromtimestamp(packet.time)
    protocol = get_protocol(packet)
    source_IP = packet[IP].src
    dest_IP = packet[IP].dst
    if packet.haslayer('TCP') or packet.haslayer('UDP'):
        source_port = packet[TCP].sport if packet.haslayer('TCP') else packet[UDP].sport
        dest_port = packet[TCP].dport if packet.haslayer('TCP') else packet[UDP].dport
    else:
        source_port = ""
        dest_port = ""

    parser = PARSER_MAP.get(protocol, lambda _: {})
    additional_info = parser(packet)
    additional_info = " ".join(f"{v}" for v in additional_info.values())

    output = f"{timestamp} {protocol} {source_IP}:{source_port} -> {dest_IP}:{dest_port}"
    if additional_info:
        output += f" {additional_info}"

    print(output)

def get_protocol(packet) -> str:
    for layer in reversed(packet.layers()):
        if layer.__name__ in PROTOCOL_TABLE:
            return layer.__name__
    
    



