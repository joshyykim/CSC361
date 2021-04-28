import sys
from headers import *


class FileEndError(Exception):
    pass


def read_global_header(file):
    """
    :param file: a pcap file entered as argument when user run this program
    :return None:
    """
    # reading global header
    buffer = file.read(24)
    global_header = global_Header()
    global_header.set_magic_num(buffer[0:4])
    global_header.set_this_zone(buffer[8:12])


def read_packet(file, packet_number):
    """
    :param file: a pcap file entered as argument when user run this program
    :param packet_number: literally numbering packets in pcap file
    :return packet: decoded packet data
    """
    # read packet header
    buffer = file.read(16)
    packet = packets()
    packet.set_packet_number(packet_number)
    packet.packet_header.set_ts_sec(buffer[0:4])
    packet.packet_header.set_ts_usec(buffer[4:8])
    packet.packet_header.set_incl_len(buffer[8:12])

    # read Ethernet header, since it doesn't need for this analysis
    file.read(14)

    # read IP header
    buffer = file.read(20)
    packet.IP_header.set_ip_header_len(buffer[0])
    packet.IP_header.set_src_IP(buffer[12:16])
    packet.IP_header.set_dst_IP(buffer[16:20])
    if packet.IP_header.ip_header_len > 20:
        file.read(packet.IP_header.ip_header_len - 20)

    # read TCP/UDP Header
    buffer = file.read(20)
    packet.TCP_header.set_src_port(buffer[0:2])
    packet.TCP_header.set_dst_port(buffer[2:4])
    packet.TCP_header.set_seq_num(buffer[4:8])
    packet.TCP_header.set_ack_num(buffer[8:12])
    packet.TCP_header.set_tcp_header_len(buffer[12])
    packet.TCP_header.set_flags(buffer[13])
    packet.TCP_header.set_window_size(buffer[14:16])
    if packet.TCP_header.tcp_header_len > 20:
        file.read(packet.TCP_header.tcp_header_len - 20)

    payload = packet.packet_header.incl_len - (14 + packet.IP_header.ip_header_len + packet.TCP_header.tcp_header_len)

    file.read(payload)
    packet.set_payload_len(payload)

    # print(packet.IP_header.get_dst_IP())

    return packet


def packet_distribution_into_connection(packets):
    """
    Packets from pcap file distinguish a list for a same connection
    by using unique 4-tuples (source IP, source port, destination IP, and destination port)
    :param packets: A list of decoded packet from read packet function
    :return connections: a two-dimensional list includes distributed packets into each connection
    """
    connections = []
    for packet in packets:
        if packet.TCP_header.flags[1] == 1 and packet.TCP_header.flags[4] == 0:
            new_conn = True
            for conn in connections:
                if (conn[0].TCP_header.src_port == packet.TCP_header.src_port
                        and conn[0].TCP_header.dst_port == packet.TCP_header.dst_port
                        and conn[0].IP_header.src_ip == packet.IP_header.src_ip
                        and conn[0].IP_header.dst_ip == packet.IP_header.dst_ip):
                    conn.append(packet)
                    new_conn = False
            if new_conn:
                new_connection = [packet]
                connections.append(new_connection)
        else:
            for conn in connections:
                if (conn[0].TCP_header.src_port == packet.TCP_header.dst_port
                        and conn[0].TCP_header.dst_port == packet.TCP_header.src_port
                        and conn[0].IP_header.src_ip == packet.IP_header.dst_ip
                        and conn[0].IP_header.dst_ip == packet.IP_header.src_ip):
                    conn.append(packet)
                elif (conn[0].TCP_header.src_port == packet.TCP_header.src_port
                      and conn[0].TCP_header.dst_port == packet.TCP_header.dst_port
                      and conn[0].IP_header.src_ip == packet.IP_header.src_ip
                      and conn[0].IP_header.dst_ip == packet.IP_header.dst_ip):
                    conn.append(packet)
    return connections


def print_IP_ports(conn, connection):
    """
    printing out the number of connection, IPs, ports for Output part B)
    :param conn: an index+1 of packet list from 'connections' list
    :param connection: a packet list from one connection
    :return None:
    """
    print("Connection : {}".format(conn))
    print("Source Address : {}".format(connection[0].IP_header.get_src_IP()))
    print("Destination Address : {}".format(connection[0].IP_header.get_dst_IP()))
    print("Source Port : {}".format(connection[0].TCP_header.get_src_port()))
    print("Destination Port : {}".format(connection[0].TCP_header.get_dst_port()))


def print_general_statistics(complete_conn, reset_conn, connections):
    """
    print output part C)
    :param complete_conn: a list of connections that includes only completed connections
    :param reset_conn: the number of connections tha have at least one reset flag
    :param connections: a two-dimensional list includes distributed packets into each connection
    :return:
    """
    print("\nC) General Statistics : ")
    print("Total number of complete TCP connections : {}".format(len(complete_conn)))
    print("Number of reset TCP connections : {}".format(reset_conn))
    print("Number of TCP connections that were still open when the trace capture ended : {}".format(
        len(connections) - len(complete_conn)))


def print_complete_TCP_connections(complete_conn, connections, durations):
    """
    print output part D)
    the information of the TCP completed connections which include
    statistics of duration, RTT value, the number of packets and window size

    :param complete_conn: a list of connections that includes only completed connections
    :param connections: a two-dimensional list includes distributed packets into each connection
    :param durations: a list of the time period from a connection started to finished
    :return None:
    """
    # Three lists below for analysis of part D)
    window_size = []
    rtt_value = []
    packet_count = []

    print("\nD) Completete TCP connections : \n")
    print("Minimum time duration : {0:.6f} seconds".format(min(durations)))
    print("Mean time duration : {0:.6f} seconds".format(sum(durations) / len(durations)))
    print("Maximum time duration : {0:.6f} seconds\n".format(max(durations)))

    """RTT value calculation part
    by checking RTT value a time different between a packet (client->server) and a packet(server->client)
    Three kinds of cases exist 1) synchronous connection 2) corresponding data 3) connection finish"""
    for i in complete_conn:
        for p in connections[i]:
            client_IP = connections[i][0].IP_header.get_src_IP()
            orig_seq_num = connections[i][0].TCP_header.seq_num
            orig_ack_num = connections[i][1].TCP_header.seq_num
            rtt_start_seq_num = p.TCP_header.relative_seq_num(orig_seq_num)

            # case 1) synchronous connection
            if p.payload == 0 and p.TCP_header.flags[1] == 1:
                # print(p.packet_number)
                expected_ack_num = rtt_start_seq_num + 1
                for new_p in connections[i]:
                    if new_p.IP_header.get_dst_IP() == client_IP and new_p.TCP_header.relative_ack_num(orig_seq_num) == expected_ack_num:
                        rtt_value.append(new_p.get_RTT(p))
                        break
            # case 2) corresponding data
            elif p.payload != 0:
                expected_ack_num = rtt_start_seq_num + p.payload
                for new_p in connections[i]:
                    if new_p.IP_header.get_dst_IP() == client_IP and new_p.TCP_header.relative_ack_num(orig_seq_num) == expected_ack_num:
                        rtt_value.append(new_p.get_RTT(p))
                        break
            # case 3) connection finish
            elif p.payload == 0 and p.TCP_header.flags[0] == 1:
                expected_ack_num = rtt_start_seq_num + 1
                for new_p in connections[i]:
                    if new_p.IP_header.get_dst_IP() == client_IP and new_p.TCP_header.relative_ack_num(orig_seq_num) == expected_ack_num:
                        rtt_value.append(new_p.get_RTT(p))
                        break

            window_size.append(p.TCP_header.window_size)

        packet_count.append(len(connections[i]))

    print("Minimum RTT value : {0:.6f} seconds".format(min(rtt_value)))
    print("Mean RTT value : {0:.6f} seconds".format(sum(rtt_value)/len(rtt_value)))
    print("Maximum RTT value : {0:.6f} seconds\n".format(max(rtt_value)))

    print("Minimum number of packets including both send/received : {}".format(min(packet_count)))
    print("Mean number of packets including both send/received : {}".format(sum(packet_count) / len(packet_count)))
    print("Maximum number of packets including both send/received : {}\n".format(max(packet_count)))

    print("Minimum receive window size including both send/received : {} bytes".format(min(window_size)))
    print("Mean receive window size including both send/received : {0:.6f} bytes".format(sum(window_size) / len(window_size)))
    print("Maxinum receive window size including both send/received : {} bytes".format(max(window_size)))


def connection_analysis(connections):
    """
    Mainly for output part B) Connection Details that include
    connection status, start and end timestamp, count packets by direction,
    and data bytes by direction.
    :param connections: a two-dimensional list includes distributed packets into each connection
    :return None:
    """
    conn = 0
    reset_conn = 0
    complete_conn = []
    packet_count = []
    durations = []
    standard_time = connections[0][0].get_timestamp()       # timestamp when the connection initialised

    print("A) Total number of connections : {}\n".format(len(connections)))
    print("-" * 60, end="\n\n")

    print("B) Connections' details :\n")
    for connection in connections:
        # syn, fin, rst are flags from TCP_header used for connection status
        syn = 0
        fin = 0
        rst = 0
        fin_packet = 0
        data_bytes_to_client = 0
        data_bytes_to_server = 0
        packet_count_to_client = 0
        packet_count_to_server = 0

        conn += 1

        print_IP_ports(conn, connection)
        for p in connection:
            if p.TCP_header.flags[0] == 1:
                fin_packet = packet_count_to_client + packet_count_to_server
                fin += 1
            if p.TCP_header.flags[1] == 1:
                syn += 1
            if p.TCP_header.flags[2] == 1:
                rst += 1
            if p.IP_header.get_src_IP() == connection[0].IP_header.get_src_IP():
                packet_count_to_server += 1
                data_bytes_to_server += p.payload
            elif p.IP_header.get_dst_IP() == connection[0].IP_header.get_src_IP():
                packet_count_to_client += 1
                data_bytes_to_client += p.payload

        if rst == 0:
            print("Status : S{}F{}".format(syn, fin))
        else:
            reset_conn += 1
            print("Status : S{}F{}\R".format(syn, fin))
        # when syn and fin > 0, a connection considered as a completed connection
        if syn > 0 and fin > 0:
            complete_conn.append(conn - 1)
            start_time = connection[0].get_timestamp() - standard_time
            end_time = connection[fin_packet].get_timestamp() - standard_time
            print("Start Time : {0:.6f} seconds".format(start_time))
            print("End Time : {0:.6f} seconds".format(end_time))
            print("Duration : {0:.6f} seconds".format(end_time - start_time))
            print("Number of Packets sent from Source to Destination : {}".format(packet_count_to_server))
            print("Number of Packets sent from Destination to Source : {}".format(packet_count_to_client))
            print("Total number of packets : {}".format(packet_count_to_client + packet_count_to_server))
            print("Number of data bytes sent from Source to Destination : {}".format(data_bytes_to_server))
            print("Number of data bytes sent from Destination to Source : {}".format(data_bytes_to_client))
            print("Total number of data bytes : {}".format(data_bytes_to_client + data_bytes_to_server))
            packet_count.append(packet_count_to_client + packet_count_to_server)
            durations.append(end_time - start_time)
        print("END\n", "-" * 60, sep="")            # seperate between connections
    print_general_statistics(complete_conn, reset_conn, connections)
    print_complete_TCP_connections(complete_conn, connections, durations)


def main():
    packets = []
    packet_number = 1
    argc = len(sys.argv)

    if argc < 2 or argc > 2:
        print("please provide right file name")
    file_name = sys.argv[1]

    with open(file_name, "rb") as file:
        read_global_header(file)
        while True:
            try:
                packets.append(read_packet(file, packet_number))
                packet_number += 1
            except:
                # EoF
                break
    connections = packet_distribution_into_connection(packets)
    connection_analysis(connections)


if __name__ == "__main__":
    main()
