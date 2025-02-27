from scapy.all import *
from datetime import datetime
import socket

def tls_parser(packet) -> None:
    info = {}

    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        extensions = getattr(client_hello, 'ext', [])

        for x in extensions:
            if hasattr(x, 'type') and x.type == 0:
                if hasattr(x, 'servernames') and x.servernames:
                    try:
                        info["hostname"] = x.servernames[0].servername.decode(errors="ignore")
                    except IndexError:
                        pass

    return info
             





    