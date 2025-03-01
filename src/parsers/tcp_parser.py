from scapy.all import *

def tcp_parser(packet):
    items = {}

    if packet.haslayer('Raw'):
        raw_payload = packet[Raw].load
    
        try:
            raw_text = raw_payload.decode(errors='ignore')
        except Exception:
            raw_text = ""

        if "HTTP" in raw_text and raw_text.startswith(("GET ", "POST ", "HEAD ")):
            items['hostname'] = "localhost"
            items['protocol'] = "HTTP"

            requests = raw_text.split('\r\n')
            if requests:
                line = requests[0].split()
                if len(line) >= 2 and line[0] in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}:
                    method = line[0]
                    items['method'] = str(method)
        elif len(raw_payload) >= 5:
            content_type = raw_payload[0]
            
            if content_type in [20, 21, 22, 23]:
                version_major = raw_payload[1]

                if version_major == 3:
                    sni = parse_tls_sni(raw_payload)

                    if sni:
                        items['hostname'] = sni
                        items['protocol'] = "TLS"

    return items

def parse_tls_sni(payload):
    """
    Parse the TLS ClientHello for the SNI hostname.
    Assumes payload is the raw TLS record (starting at the TLS record header).
    """
    if len(payload) < 5:
        return None

    content_type = payload[0]
    if content_type != 22:  
        return None

    if len(payload) < 5 + 4:
        return None

    handshake_type = payload[5]
    if handshake_type != 1:
        return None

    offset = 5 + 4 
    offset += 2 + 32

    if len(payload) < offset + 1:
        return None
    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if len(payload) < offset + 2:
        return None
    cipher_suites_length = int.from_bytes(payload[offset:offset+2], "big")
    offset += 2 + cipher_suites_length

    if len(payload) < offset + 1:
        return None
    compression_methods_length = payload[offset]
    offset += 1 + compression_methods_length

    if len(payload) < offset + 2:
        return None
    extensions_length = int.from_bytes(payload[offset:offset+2], "big")
    offset += 2
    end_extensions = offset + extensions_length

    while offset + 4 <= end_extensions:
        ext_type = int.from_bytes(payload[offset:offset+2], "big")
        ext_length = int.from_bytes(payload[offset+2:offset+4], "big")
        offset += 4
        if ext_type == 0:
            if len(payload) < offset + 2:
                return None
            sni_list_length = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            
            if len(payload) < offset + 3:
                return None
            name_type = payload[offset]
            offset += 1
            name_length = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            if name_type == 0 and len(payload) >= offset + name_length:
                return payload[offset:offset+name_length].decode("utf-8", errors="ignore")
            else:
                return None
        else:
            offset += ext_length
    return None