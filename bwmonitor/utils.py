__author__ = 'mac'

def get_protocol(pkt,protocol) :
    dst = pkt.get_protocols(protocol)
    if dst :
        return dst[0]
    return None

def get_application_type(match):
    src_port = None
    dst_port = None
    if 'tcp_src' in match : 
        src_port = match['tcp_src']
        dst_port = match['tcp_dst']
        if src_port == 21 or dst_port == 21 or src_port == 20 or dst_port == 20:
            return 'FTP'
        if src_port == 22 or dst_port == 22:
            return 'SSH'
        if src_port == 80 or dst_port == 80:
            return 'HTTP'
        if (src_port - 8000 > 0 and src_port - 8000 < 1000) or (dst_port - 8000 > 0 and dst_port - 8000 < 1000):
            return 'HTTP'
    elif 'udp_src' in match:
        pass
    return None


