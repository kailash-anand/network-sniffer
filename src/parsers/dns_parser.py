from scapy.all import *

DNS_QUERY_TYPES = {
    1: "A",  # IPv4 Address
    2: "NS",  # Name Server
    5: "CNAME",  # Canonical Name
    12: "PTR",  # Pointer Record (used in mDNS)
    15: "MX",  # Mail Exchange
    16: "TXT",  # Text Record
    28: "AAAA"  # IPv6 Address
}

def dns_parser(packet):
    items = {}

    if packet.haslayer('DNS'):
        record_type = packet[DNS].qd.qtype

        if record_type in DNS_QUERY_TYPES and DNS_QUERY_TYPES[record_type] == "A":
            hostname = packet[DNS].qd.qname.decode()
            items["hostname"] = hostname

    return items