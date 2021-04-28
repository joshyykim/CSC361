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
        self.ts_usec = (buffer[0] + buffer[1] * (2 ** 8) + buffer[2] * (2 ** 16) + buffer[3] * (2 ** 24)) * (10 ** (-6))

    def get_ts_usec(self):
        return self.ts_usec     # in milliseconds

    def set_incl_len(self, buffer):
        incl_len = unpack('BBBB', buffer)
        self.incl_len = incl_len[3] * (2 ** 24) + incl_len[2] * (2 ** 16) + incl_len[1] * (2 ** 8) + incl_len[0]

class IP_header:
    src_ip = None
    dst_ip = None
    ip_header_len = None

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0

    def set_src_IP(self, buffer):
        self.src_ip = unpack('BBBB', buffer)

    def get_src_IP(self):
        return str(self.src_ip[0]) + "." + str(self.src_ip[1]) + "." + str(self.src_ip[2]) + "." + str(self.src_ip[3])

    def set_dst_IP(self, buffer):
        self.dst_ip = unpack('BBBB', buffer)

    def get_dst_IP(self):
        return str(self.dst_ip[0]) + "." + str(self.dst_ip[1]) + "." + str(self.dst_ip[2]) + "." + str(self.dst_ip[3])

    def set_ip_header_len(self, buffer):
        # ip_header_len = unpack('B', buffer)
        self.ip_header_len = (buffer % 16) * 4

class TCP_header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    tcp_header_len = 0
    flags = {}
    window_size = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.tcp_header_len = 0
        self.flags = {}
        self.window_size = 0

    def set_src_port(self, buffer):
        self.src_port = buffer

    def get_src_port(self):
        return self.src_port[0] * (2 ** 8) + self.src_port[1]

    def set_dst_port(self, buffer):
        self.dst_port = buffer

    def get_dst_port(self):
        return self.dst_port[0] * (2 ** 8) + self.dst_port[1]

    def set_seq_num(self, buffer):
        seq_num = unpack('BBBB', buffer)
        self.seq_num = seq_num[3] + seq_num[2] * (2 ** 8) + seq_num[1] * (2 ** 16) + seq_num[0] * (2 ** 24)
        # print(self.seq_num, buffer)
    def set_ack_num(self, buffer):
        ack_num = unpack('BBBB', buffer)
        self.ack_num = ack_num[3] + ack_num[2] * (2 ** 8) + ack_num[1] * (2 ** 16) + ack_num[0] * (2 ** 24)

    def set_tcp_header_len(self, buffer):
        self.tcp_header_len = buffer // 4

    def set_window_size(self, buffer):
        window_size = unpack('BB', buffer)
        self.window_size = window_size[1] + window_size[0] * (2 ** 8)

    def set_flags(self, buffer):
        # flags = unpack('B', buffer)
        fin = (buffer & 0b00000001)
        syn = (buffer & 0b00000010) >> 1
        rst = (buffer & 0b00000100) >> 2
        psh = (buffer & 0b00001000) >> 3
        ack = (buffer & 0b00010000) >> 4
        urg = (buffer & 0b00100000) >> 5
        ece = (buffer & 0b01000000) >> 6
        cwr = (buffer & 0b10000000) >> 7
        self.flags = (fin, syn, rst, psh, ack, urg, ece, cwr)

    def relative_seq_num(self, orig_seq_num):
        return self.seq_num - orig_seq_num

    def relative_ack_num(self, orig_ack_num):
        return self.ack_num - orig_ack_num

class packets:
    # packet header (16 bytes), Ethernet header(14 bytes), IPv4(20 bytes), TCP/UDP header(20~60 bytes)
    # rest of data is payload (no need for this analysis)
    packet_header = None
    IP_header = None
    TCP_header = None
    packet_number = 0
    timestamp = 0
    payload = 0


    def __init__(self):
        self.packet_header = packet_header()
        self.IP_header = IP_header()
        self.TCP_header = TCP_header()
        self.packet_number = 0
        self.payload = 0
        self.timestamp = 0

    def get_timestamp(self):
        self.timestamp = self.packet_header.ts_sec + self.packet_header.ts_usec
        return self.timestamp

    def set_packet_number(self, packet_num):
        self.packet_number = packet_num

    def get_RTT(self, packet):
        return self.get_timestamp() - packet.get_timestamp()

    def set_payload_len(self, payload):
        self.payload = payload
