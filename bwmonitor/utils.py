__author__ = 'mac'

def get_protocol(pkt,protocol) :
    dst = pkt.get_protocols(protocol)
    if dst :
        return dst[0]
    return None

