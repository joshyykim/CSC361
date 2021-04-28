from datetime import *
from struct import *


class global_Header:
    magic_num = None
    this_zone = None

    def __init__(self):
        magic_num = None
        this_zone = 0

    def set_magic_num(self, buffer):
        self.magic_num = buffer

    def set_this_zone(self, buffer):
        self.this_zone = unpack('BBBB', buffer)

class packet_header:
    # 16 bytes : ts_sec(4 bytes), ts_usec(4 bytes), incl_len(4 bytes), orig_len(4 bytes)
    ts_sec = None
    ts_usec = None
    incl_len = None

    def __init__(self):
        self.ts_sec = 0
        self.ts_usec = 0
        self.incl_len = 0

    def set_ts_sec(self, buffer):
        # ts_sec = unpack('BBBB', buffer)
        self.ts_sec = buffer[0] + buffer[1] * (2 ** 8) + buffer[2] * (2 ** 16) + buffer[3] * (2 ** 24)

    def get_ts_sec(self):
        return self.ts_sec  #in seconds

    def set_ts_usec(self, buffer):
        # ts_usec = unpack('BBBB', buffer)
        self.ts_usec = (buffer[0] + buffer[1] * (2 ** 8) + buffer[2] * (2 ** 16) + buffer[3] * (2 ** 24)) * (10 ** (-9))

    def get_ts_usec(self):
        return self.ts_usec     # in milliseconds

    def set_incl_len(self, buffer):
        incl_len = unpack('BBBB', buffer)
        self.incl_len = incl_len[3] * (2 ** 24) + incl_len[2] * (2 ** 16) + incl_len[1] * (2 ** 8) + incl_len[0]

class IP_header:
    ip_header_len = None
    total_len = 0
    id = 0
    flags = 0
    fragment_offset = 0
    ttl_value = 0
    protocol = 0
    src_ip = None
    dst_ip = None

    def __init__(self):
        self.ip_header_len = None
        self.total_len = 0
        self.id = 0
        self.flags = 0
        self.fragment_offset = 0
        self.ttl_value = 0
        self.protocol = 0
        self.src_ip = None
        self.dst_ip = None

    def set_ip_header_len(self, buffer):
        # ip_header_len = unpack('B', buffer)
        self.ip_header_len = (buffer % 16) * 4

    def set_total_len(self, buffer):
        total_len = unpack('>H', buffer)
        self.total_len = total_len[0]

    def set_ID(self, buffer):
        id = unpack('>H', buffer)
        self.id = id[0]

    def set_flags(self, buffer):
        # 0 : last fragment, 1 : More, 2 : Don't fragment, 4: Unused
        self.flags = buffer // (2 ** 4)

    def set_fragment_offset(self, buffer):
        offset = unpack('>H', buffer)
        self.fragment_offset = (offset[0] % (2 ** 13)) * 8
        # print(offset[0], self.fragment_offset)

    def set_TTL(self, buffer):
        self.ttl_value = buffer

    def set_protocol(self, buffer):
        self.protocol = buffer

    def set_src_IP(self, buffer):
        self.src_ip = unpack('BBBB', buffer)

    def get_src_IP(self):
        return str(self.src_ip[0]) + "." + str(self.src_ip[1]) + "." + str(self.src_ip[2]) + "." + str(self.src_ip[3])

    def set_dst_IP(self, buffer):
        self.dst_ip = unpack('BBBB', buffer)

    def get_dst_IP(self):
        return str(self.dst_ip[0]) + "." + str(self.dst_ip[1]) + "." + str(self.dst_ip[2]) + "." + str(self.dst_ip[3])

class UDP_header:
    src_port = 0
    dst_port = 0
    udp_header_len = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.udp_header_len = 0

    def set_src_port(self, buffer):
        self.src_port = buffer[0] * (2 ** 8) + buffer[1]

    def set_dst_port(self, buffer):
        self.dst_port = buffer[0] * (2 ** 8) + buffer[1]

    def set_udp_header_len(self, buffer):
        length = unpack('>H', buffer)
        self.udp_header_len = length[0]

class ICMP_header:
    type = 0
    code = 0
    seq = 0
    orig_src_IP = None
    orig_dst_IP = None
    orig_src_port = 0
    orig_dst_port = 0
    orig_protocol = 0
    orig_seq = 0


    def __init__(self):
        self.type = 0
        self.code = 0
        self.seq = 0
        self.orig_src_IP = None
        self.orig_dst_IP = None
        self.orig_src_port = 0
        self.orig_dst_port = 0
        self.orig_protocol = 0
        self.orig_seq = 0

    def set_type(self, buffer):
        self.type = buffer

    def set_code(self, buffer):
        self.code = buffer

    def set_seq_number(self, buffer):
        seq_num = unpack('>H', buffer)
        self.seq = seq_num[0]

    def set_orig_src_IP(self, buffer):
        self.src_ip = unpack('BBBB', buffer)

    def get_orig_src_IP(self):
        return str(self.orig_src_IP[0]) + "." + str(self.orig_src_IP[1]) + "." + str(self.orig_src_IP[2]) + "." + str(self.orig_src_IP[3])

    def set_orig_dst_IP(self, buffer):
        self.dst_ip = unpack('BBBB', buffer)

    def get_orig_dst_IP(self):
        return str(self.orig_dst_IP[0]) + "." + str(self.orig_dst_IP[1]) + "." + str(self.orig_dst_IP[2]) + "." + str(self.orig_dst_IP[3])

    def set_orig_src_port(self, buffer):
        self.orig_src_port = buffer[0] * (2 ** 8) + buffer[1]

    def set_orig_dst_port(self, buffer):
        self.orig_dst_port = buffer[0] * (2 ** 8) + buffer[1]

    def set_orig_protocol(self, buffer):
        self.orig_protocol = buffer

    def set_orig_seq(self, buffer):
        orig_seq = unpack('>H', buffer)
        self.orig_seq = orig_seq[0]



class packets:
    # packet header (16 bytes), Ethernet header(14 bytes), IPv4(20 bytes)

    packet_header = None
    IP_header = None
    UDP_header = None
    ICMP_header = None
    packet_number = 0
    timestamp = 0
    payload = 0

    def __init__(self):
        self.packet_header = packet_header()
        self.IP_header = IP_header()
        self.UDP_header = UDP_header()
        self.ICMP_header = ICMP_header()
        self.packet_number = 0
        self.payload = 0
        self.timestamp = 0

    def get_timestamp(self):
        self.timestamp = (self.packet_header.ts_sec + self.packet_header.ts_usec) * (10 ** 3)
        return self.timestamp

    def set_packet_number(self, packet_num):
        self.packet_number = packet_num

    def get_RTT(self, packet):
        return float(self.get_timestamp() - packet.get_timestamp())

    def set_payload_len(self, payload):
        self.payload = payload