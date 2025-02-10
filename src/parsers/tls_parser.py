from scapy.all import *
from datetime import datetime
import socket

def tls_parser(packet) -> None:
    info = {}

    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        extensions = client_hello.ext

        for x in extensions:
            if x.type == 0:
                info["hostname"] = x.servernames[0].servername.decode()

    return info
             





    