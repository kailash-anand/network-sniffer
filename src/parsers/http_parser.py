from scapy.all import *

def http_parser(packet):
    items = {}

    if packet.haslayer('HTTPRequest'):
        try:
            method = packet[HTTPRequest].Method.decode(errors="ignore")
            hostname = packet[HTTPRequest].Host.decode(errors="ignore")
            path = packet[HTTPRequest].Path.decode(errors="ignore")
            
            items["hostname"] = str(hostname)
            items["method"] = str(method)
            items["Path"] = str(path)
        except AttributeError:
            pass

    return items