from scapy.all import *

def http_parser(packet):
    items = {}

    if packet.haslayer('HTTPRequest'):
        method = packet[HTTPRequest].Method.decode()
        hostname = packet[HTTPRequest].Host.decode()
        path = packet[HTTPRequest].Path.decode()
        items["hostname"] = str(hostname)
        items["method"] = str(method)
        items["Path"] = str(path)

    return items