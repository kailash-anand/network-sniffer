from scapy.all import *
from datetime import datetime
import socket

def tls_parser(packet) -> None:
    timestamp = datetime.fromtimestamp(packet.time)
    protocol = 'TLS'
    source_IP = packet[IP].src
    dest_IP = packet[IP].dst
    hostname = "Unknown"

    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        servernames = client_hello.ext[0].servernames
        server_name = servernames[0].servername.decode()
        hostname = str(server_name)       

    print(str(timestamp) + " " + protocol + " " + source_IP + " -> " + dest_IP + " " + (hostname if hostname != "Unknown" else ""))    





    