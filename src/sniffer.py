from scapy.all import * 
from src.parsers.http_parsper import http_parser
from src.parsers.dns_parser import dns_parser
from src.parsers.tls_parser import tls_parser
import cryptography

def start_sniff(interface: str, tracefile: str, expression: str) -> None:
    try:
        load_dependencies()
        sniff(iface=interface, filter=expression, prn=process_packet, store=False) 

        if tracefile is None:
            print("Tracefile")
    
    except Exception as e:
        print(str(e))

def load_dependencies():
    load_layer('tls')
    load_layer('http')

def process_packet(packet) -> None:
    if packet.haslayer('DNS'):
        dns_parser(packet)
    elif packet.haslayer('TLS'):
        tls_parser(packet)
    



