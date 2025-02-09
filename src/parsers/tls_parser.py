from scapy.all import *
from datetime import datetime
import socket

def tls_parser(packet) -> None:
    info = {}

    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        servernames = client_hello.ext[0].servernames
        server_name = servernames[0].servername.decode()
        info["hostname"] = str(server_name)

    return info
             





    