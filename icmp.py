import packet_analyzer
import ruamel.yaml

pcap_file = packet_analyzer.pcap_file
yaml_file_path = 'output_icmp.yaml'


def only_icmp():
    output_array = []
    for packet in packet_analyzer.yaml_dump_arr_packets:
        if packet.get('protocol') == 'ICMP':
            output_array.append(packet)
    return output_array


def icmp_f():
    echo_requests = []
    echo_replies = []
    echo_request_reply_pairs = []
    incompleted_comms = []
    for packet in valid_packets_icmp:
        type_echo = int(packet.get('hexa_frame')[103:105])
        if type_echo == 8:
            echo_requests.append(packet)
        elif type_echo == 0:
            echo_replies.append(packet)
        elif type_echo == 3:
            incompleted_comms.append(packet)
    echo_request_index = 0
    while echo_request_index != len(echo_requests):
        src_ip = echo_requests[echo_request_index].get('src_ip')
        identifier_1 = echo_requests[echo_request_index].get('hexa_frame')[114:119]
        echo_reply_index = 0
        while echo_reply_index != len(echo_replies):
            dst_ip = echo_replies[echo_reply_index].get('dst_ip')
            identifier_2 = echo_replies[echo_reply_index].get('hexa_frame')[114:119]
            if src_ip == dst_ip and identifier_1 == identifier_2:
                echo_request_reply_pairs.append(echo_requests[echo_request_index])
                echo_request_reply_pairs.append(echo_replies[echo_reply_index])
                echo_requests.remove(echo_requests[echo_request_index])
                echo_replies.remove(echo_replies[echo_reply_index])
                echo_request_index -= 1
                break
            echo_reply_index += 1
        echo_request_index += 1
    return new_yaml_output(echo_request_reply_pairs, echo_requests, echo_replies, incompleted_comms)


def new_yaml_output(r_r_pairs, req, rep, incompleted_comms):
    icmp_index = 0
    c_comms = []
    for pair in r_r_pairs:
        icmp_id = pair.get('hexa_frame')[114:119]
        icmp_id = int(icmp_id[:2] + icmp_id[3:], 16)
        icmp_seq = pair.get('hexa_frame')[120:125]
        icmp_seq = int(icmp_seq[:2] + icmp_seq[3:], 16)
        if icmp_index % 2 == 0:
            icmp_type = 'ECHO REQUEST'
        else:
            icmp_type = 'ECHO REPLY'
        packet = {
            'frame_number': pair.get('frame_number'),
            'len_frame_pcap': pair.get('len_frame_pcap'),
            'len_frame_medium': pair.get('len_frame_medium'),
            'frame_type': pair.get('frame_type'),
            'src_mac': pair.get('src_mac'),
            'dst_mac': pair.get('dst_mac'),
            'ether_type':  pair.get('ether_type'),
            'src_ip': pair.get('src_ip'),
            'dst_ip': pair.get('dst_ip'),
            'protocol': pair.get('protocol'),
            'icmp_type': icmp_type,
            'icmp_id': icmp_id,
            'icmp_seq': icmp_seq,
            'hexa_frame': pair.get('hexa_frame')
        }
        append_at_the_end = True
        for comm_index in range(len(c_comms)):
            if (packet.get('src_ip') == c_comms[comm_index][0].get('dst_ip') and
                packet.get('dst_ip') == c_comms[comm_index][0].get('src_ip')) or \
                    (packet.get('src_ip') == c_comms[comm_index][0].get('src_ip') and
                     packet.get('dst_ip') == c_comms[comm_index][0].get('dst_ip')):
                c_comms[comm_index].append(packet)
                append_at_the_end = False
                break
        if append_at_the_end:
            c_comms.append([packet])
        icmp_index += 1
    p_comms = []
    for ic in incompleted_comms:
        packet = {
            'frame_number': ic.get('frame_number'),
            'len_frame_pcap': ic.get('len_frame_pcap'),
            'len_frame_medium': ic.get('len_frame_medium'),
            'frame_type': ic.get('frame_type'),
            'src_mac': ic.get('src_mac'),
            'dst_mac': ic.get('dst_mac'),
            'ether_type':  ic.get('ether_type'),
            'src_ip': ic.get('src_ip'),
            'dst_ip': ic.get('dst_ip'),
            'protocol': ic.get('protocol'),
            'icmp_type': 'Destination unreachable',
            'hexa_frame': ic.get('hexa_frame')
        }
        append_at_the_end = True
        for comm_index in range(len(p_comms)):
            if (packet.get('src_ip') == p_comms[comm_index][0].get('dst_ip') and
                packet.get('dst_ip') == p_comms[comm_index][0].get('src_ip')) or \
                    (packet.get('src_ip') == p_comms[comm_index][0].get('src_ip') and
                     packet.get('dst_ip') == p_comms[comm_index][0].get('dst_ip')):
                p_comms[comm_index].append(packet)
                append_at_the_end = False
                break
        if append_at_the_end:
            p_comms.append([packet])
    for q in req:
        packet = {
            'frame_number': q.get('frame_number'),
            'len_frame_pcap': q.get('len_frame_pcap'),
            'len_frame_medium': q.get('len_frame_medium'),
            'frame_type': q.get('frame_type'),
            'src_mac': q.get('src_mac'),
            'dst_mac': q.get('dst_mac'),
            'ether_type':  q.get('ether_type'),
            'src_ip': q.get('src_ip'),
            'dst_ip': q.get('dst_ip'),
            'protocol': q.get('protocol'),
            'icmp_type': 'ECHO REQUEST',
            'hexa_frame': q.get('hexa_frame')
        }
        append_at_the_end = True
        for comm_index in range(len(p_comms)):
            if (packet.get('src_ip') == p_comms[comm_index][0].get('dst_ip') and
                packet.get('dst_ip') == p_comms[comm_index][0].get('src_ip')) or \
                    (packet.get('src_ip') == p_comms[comm_index][0].get('src_ip') and
                     packet.get('dst_ip') == p_comms[comm_index][0].get('dst_ip')):
                p_comms[comm_index].append(packet)
                append_at_the_end = False
                break
        if append_at_the_end:
            p_comms.append([packet])
    for p in rep:
        packet = {
            'frame_number': p.get('frame_number'),
            'len_frame_pcap': p.get('len_frame_pcap'),
            'len_frame_medium': p.get('len_frame_medium'),
            'frame_type': p.get('frame_type'),
            'src_mac': p.get('src_mac'),
            'dst_mac': p.get('dst_mac'),
            'ether_type':  p.get('ether_type'),
            'src_ip': p.get('src_ip'),
            'dst_ip': p.get('dst_ip'),
            'protocol': p.get('protocol'),
            'icmp_type': 'ECHO REPLY',
            'hexa_frame': p.get('hexa_frame')
        }
        append_at_the_end = True
        for comm_index in range(len(p_comms)):
            if (packet.get('src_ip') == p_comms[comm_index][0].get('dst_ip') and
                packet.get('dst_ip') == p_comms[comm_index][0].get('src_ip')) or \
                    (packet.get('src_ip') == p_comms[comm_index][0].get('src_ip') and
                     packet.get('dst_ip') == p_comms[comm_index][0].get('dst_ip')):
                p_comms[comm_index].append(packet)
                append_at_the_end = False
                break
        if append_at_the_end:
            p_comms.append([packet])
    output_c = []
    for i in range(len(c_comms)):
        dict_i = {
            'number_comm': i+1,
            'packets': c_comms[i]
        }
        output_c.append(dict_i)
    output_p = []
    for i in range(len(p_comms)):
        dict_i = {
            'number_comm': i+1,
            'packets': p_comms[i]
        }
        output_p.append(dict_i)
    return output_c, output_p


def create_output_file():
    yaml_dump = {"name": "PKS2023/24", "pcap_name": pcap_file, "filter_name": "ICMP", "complete_comms": complete_comms,
                 "partial_comms": partial_comms}
    with open(yaml_file_path, 'w') as yaml_file:
        ruamel.yaml.dump(yaml_dump, yaml_file, Dumper=ruamel.yaml.RoundTripDumper)


valid_packets_icmp = only_icmp()
complete_comms, partial_comms = icmp_f()
create_output_file()
