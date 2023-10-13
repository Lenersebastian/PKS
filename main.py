import argparse
import packet_analyzer
import ruamel.yaml

pcap_file = 'trace-27.pcap'
yaml_file_path = 'output_arp.yaml'


def two_way_handshakes():
    success_starts = []
    for packet_syn_a_index in range(len(valid_packets_tcp)):
        packet_syn_a = valid_packets_tcp[packet_syn_a_index]
        if make_binary_form_flags(packet_syn_a['hexa_frame'])[10] == "1":
            syn_a_src_ip = packet_syn_a.get('src_ip')
            syn_a_dst_ip = packet_syn_a.get('dst_ip')
            from_the_start = False
            for packet_syn_b_index in range(packet_syn_a_index + 1, len(valid_packets_tcp), 1):
                packet_syn_b = valid_packets_tcp[packet_syn_b_index]
                if make_binary_form_flags(packet_syn_b['hexa_frame'])[10] == "1":
                    syn_b_src_ip = packet_syn_b.get('src_ip')
                    syn_b_dst_ip = packet_syn_b.get('dst_ip')
                    if syn_a_src_ip == syn_b_dst_ip and syn_a_dst_ip == syn_b_src_ip:
                        for packet_ack_a_index in range(packet_syn_a_index + 1, len(valid_packets_tcp), 1):
                            packet_ack_a = valid_packets_tcp[packet_ack_a_index]
                            if make_binary_form_flags(packet_ack_a['hexa_frame'])[7] == "1":
                                ack_a_src_ip = packet_ack_a.get('src_ip')
                                ack_a_dst_ip = packet_ack_a.get('dst_ip')
                                for packet_ack_b_index in range(packet_ack_a_index + 1, len(valid_packets_tcp), 1):
                                    packet_ack_b = valid_packets_tcp[packet_ack_b_index]
                                    if make_binary_form_flags(packet_ack_b['hexa_frame'])[7] == "1":
                                        ack_b_src_ip = packet_syn_b.get('src_ip')
                                        ack_b_dst_ip = packet_syn_b.get('dst_ip')
                                        if ack_a_src_ip == ack_b_dst_ip and ack_a_dst_ip == ack_b_src_ip:
                                            success_starts.append([packet_syn_a, packet_syn_b, packet_ack_a, packet_ack_b])
                                            from_the_start = True
                                            break
                                if from_the_start:
                                    break
                    if from_the_start:
                        break
    return success_starts


def make_binary_form_flags(string):
    string = string[141:143]
    output = str(bin(int(string)))[2:]
    while len(output) != 12:
        output = '0' + output
    return output


def three_way_handshake():
    success_starts = []
    for packet_syn_index in range(len(valid_packets_tcp)):
        packet_syn = valid_packets_tcp[packet_syn_index]
        if make_binary_form_flags(packet_syn['hexa_frame'])[10] == "1":  # syn flag set to 1
            syn_src_ip = packet_syn.get('src_ip')
            syn_src_port = packet_syn.get('src_port')
            syn_dst_ip = packet_syn.get('dst_ip')
            syn_dst_port = packet_syn.get('dst_port')
            for packet_syn_plus_ack_index in range(packet_syn_index + 1, len(valid_packets_tcp), 1):
                packet_syn_plus_ack = valid_packets_tcp[packet_syn_plus_ack_index]
                if make_binary_form_flags(packet_syn_plus_ack['hexa_frame'])[10] == "1" and \
                        make_binary_form_flags(packet_syn_plus_ack['hexa_frame'])[7] == "1":  # syn and ack flag set to 1
                    syn_plus_ack_src_ip = packet_syn_plus_ack.get('src_ip')
                    syn_plus_ack_src_port = packet_syn_plus_ack.get('src_port')
                    syn_plus_ack_dst_ip = packet_syn_plus_ack.get('dst_ip')
                    syn_plus_ack_dst_port = packet_syn_plus_ack.get('dst_port')
                    if syn_src_ip == syn_plus_ack_dst_ip and syn_src_port == syn_plus_ack_dst_port and \
                            syn_dst_ip == syn_plus_ack_src_ip and syn_dst_port == syn_plus_ack_src_port:
                        for packet_ack_index in range(packet_syn_plus_ack_index + 1,
                                                      len(valid_packets_tcp), 1):
                            packet_ack = valid_packets_tcp[packet_ack_index]
                            if make_binary_form_flags(packet_syn_plus_ack['hexa_frame'])[7] == "1":  # ack flag set to 1
                                ack_src_ip = packet_ack.get('src_ip')
                                ack_src_port = packet_ack.get('src_port')
                                ack_dst_ip = packet_ack.get('dst_ip')
                                ack_dst_port = packet_ack.get('dst_port')
                                if ack_src_ip == syn_plus_ack_dst_ip and ack_src_port == syn_plus_ack_dst_port and \
                                        ack_dst_ip == syn_plus_ack_src_ip and ack_dst_port == syn_plus_ack_src_port:
                                    success_starts.append([packet_syn, packet_syn_plus_ack, packet_ack])
                                    break
                        break
    return success_starts


def only_valid_app_protocols_tcp():
    output_array = []
    for packet in packet_analyzer.yaml_dump_arr_packets:
        if packet.get('app_protocol') == 'HTTP' or packet.get('app_protocol') == 'HTTPS' or packet.get(
                'app_protocol') == 'TELNET' or packet.get('app_protocol') == 'SSH' or packet.get(
                    'app_protocol') == 'FTP-CONTROL' or packet.get('app_protocol') == 'FTP-DATA':
            output_array.append(packet)
    return output_array


def only_arp():
    output_array = []
    for packet in packet_analyzer.yaml_dump_arr_packets:
        if packet.get('ether_type') == 'ARP':
            output_array.append(packet)
    return output_array


def tcp_f():
    pass


def arp_f():
    requests = []
    replies = []
    request_reply_pairs = []
    for packet in valid_packets_arp:
        string = packet.get('hexa_frame')[60:65]
        string = string[:2] + string[3:]
        opcode = int(string)
        if opcode == 1:
            requests.append(packet)
        elif opcode == 2:
            replies.append(packet)
    request_index = 0
    while requests:
        sender_ip = requests[request_index].get('hexa_frame')[84:95]
        reply_index = 0
        while replies:
            target_ip = replies[reply_index].get('hexa_frame')[114:125]
            if sender_ip == target_ip:
                request_reply_pairs.append(requests[request_index])
                request_reply_pairs.append(replies[reply_index])
                requests.remove(requests[request_index])
                replies.remove(replies[request_index])
                reply_index -= 1
                request_index -= 1
            reply_index += 1
        request_index += 1
    new_yaml_output(request_reply_pairs, requests, replies)


def new_yaml_output(r_r_pairs, req, rep):
    op_index = 0
    for p in r_r_pairs:
        if op_index % 2 == 0:
            arp_opcode = 'REQUEST'
        else:
            arp_opcode = 'REPLY'
        packet = {
            'frame_number': p.get('frame_number'),
            'len_frame_pcap': p.get('len_frame_pcap'),
            'len_frame_medium': p.get('len_frame_medium'),
            'frame_type': p.get('frame_type'),
            'src_mac': p.get('src_mac'),
            'dst_mac': p.get('dst_mac'),
            'ether_type':  p.get('ether_type'),
            'arp_opcode':  arp_opcode,
            'src_ip': p.get('src_ip'),
            'dst_ip': p.get('dst_ip'),
            'hexa_frame': p.get('hexa_frame')
        }
        op_index += 1
# tuto pokracuj


def switch_p():
    parser = argparse.ArgumentParser()

    # Add a command-line switch (-p or --parameter)
    parser.add_argument('-p', '--parameter')

    args = parser.parse_args()

    if args.parameter == "TCP":
        tcp_f()
    elif args.parameter == "ARP":
        arp_f()
    else:
        print("Zle")


def create_output_file():

    yaml_dump = {"name": "PKS2023/24", "pcap_name": pcap_file, "filter_name": "ARP", "complete_comms": complete_comms,
                 "partial_comms": partial_comms, }
    with open(yaml_file_path, 'w') as yaml_file:
        ruamel.yaml.dump(yaml_dump, yaml_file, Dumper=ruamel.yaml.RoundTripDumper)


# if __name__ == "__main__":
#     switch_p()
valid_packets_tcp = only_valid_app_protocols_tcp()
# three_way_handshake()
# two_way_handshakes()

valid_packets_arp = only_arp()
complete_comms, partial_comms = arp_f()
