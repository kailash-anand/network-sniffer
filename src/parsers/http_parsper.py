from scapy.all import *

def http_parser(packet):
    items = {}

    if packet.haslayer('HTTPRequest'):
        method = packet[HTTPRequest].Method.decode()
        hostname = packet[HTTPRequest].Host.decode()
        items["method"] = str(method)
        items["hostname"] = str(hostname)

    return items