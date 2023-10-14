import packet_analyzer
import ruamel.yaml

pcap_file = packet_analyzer.pcap_file
yaml_file_path = 'output_arp.yaml'


def only_arp():
    output_array = []
    for packet in packet_analyzer.yaml_dump_arr_packets:
        if packet.get('ether_type') == 'ARP':
            output_array.append(packet)
    return output_array


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
    while request_index != len(requests):
        sender_ip = requests[request_index].get('hexa_frame')[84:95]
        reply_index = 0
        while reply_index != len(replies):
            target_ip = replies[reply_index].get('hexa_frame')[114:125]
            if sender_ip == target_ip:
                request_reply_pairs.append(requests[request_index])
                request_reply_pairs.append(replies[reply_index])
                requests.remove(requests[request_index])
                replies.remove(replies[reply_index])
                request_index -= 1
                break
            reply_index += 1
        request_index += 1
    return new_yaml_output(request_reply_pairs, requests, replies)


def new_yaml_output(r_r_pairs, req, rep):
    op_index = 0
    complete_cms = []
    for pair in r_r_pairs:
        if op_index % 2 == 0:
            arp_opcode = 'REQUEST'
        else:
            arp_opcode = 'REPLY'
        packet = {
            'frame_number': pair.get('frame_number'),
            'len_frame_pcap': pair.get('len_frame_pcap'),
            'len_frame_medium': pair.get('len_frame_medium'),
            'frame_type': pair.get('frame_type'),
            'src_mac': pair.get('src_mac'),
            'dst_mac': pair.get('dst_mac'),
            'ether_type':  pair.get('ether_type'),
            'arp_opcode':  arp_opcode,
            'src_ip': pair.get('src_ip'),
            'dst_ip': pair.get('dst_ip'),
            'hexa_frame': pair.get('hexa_frame')
        }
        append_at_the_end = True
        for comm_index in range(len(complete_cms)):
            if (packet.get('src_ip') == complete_cms[comm_index][0].get('dst_ip') and
                packet.get('dst_ip') == complete_cms[comm_index][0].get('src_ip')) or \
                    (packet.get('src_ip') == complete_cms[comm_index][0].get('src_ip') and
                     packet.get('dst_ip') == complete_cms[comm_index][0].get('dst_ip')):
                complete_cms[comm_index].append(packet)
                append_at_the_end = False
                break
        if append_at_the_end:
            complete_cms.append([packet])
        op_index += 1
    partial_cms = []
    for q in req:
        packet = {
            'frame_number': q.get('frame_number'),
            'len_frame_pcap': q.get('len_frame_pcap'),
            'len_frame_medium': q.get('len_frame_medium'),
            'frame_type': q.get('frame_type'),
            'src_mac': q.get('src_mac'),
            'dst_mac': q.get('dst_mac'),
            'ether_type':  q.get('ether_type'),
            'arp_opcode': 'REQUEST',
            'src_ip': q.get('src_ip'),
            'dst_ip': q.get('dst_ip'),
            'hexa_frame': q.get('hexa_frame')
        }
        append_at_the_end = True
        for comm_index in range(len(partial_cms)):
            if (packet.get('src_ip') == partial_cms[comm_index][0].get('dst_ip') and
                packet.get('dst_ip') == partial_cms[comm_index][0].get('src_ip')) or \
                    (packet.get('src_ip') == partial_cms[comm_index][0].get('src_ip') and
                     packet.get('dst_ip') == partial_cms[comm_index][0].get('dst_ip')):
                partial_cms[comm_index].append(packet)
                append_at_the_end = False
                break
        if append_at_the_end:
            partial_cms.append([packet])
    for p in rep:
        packet = {
            'frame_number': p.get('frame_number'),
            'len_frame_pcap': p.get('len_frame_pcap'),
            'len_frame_medium': p.get('len_frame_medium'),
            'frame_type': p.get('frame_type'),
            'src_mac': p.get('src_mac'),
            'dst_mac': p.get('dst_mac'),
            'ether_type': p.get('ether_type'),
            'arp_opcode': 'REPLY',
            'src_ip': p.get('src_ip'),
            'dst_ip': p.get('dst_ip'),
            'hexa_frame': p.get('hexa_frame')
        }
        append_at_the_end = True
        for comm_index in range(len(partial_cms)):
            if (packet.get('src_ip') == partial_cms[comm_index][0].get('dst_ip') and
                packet.get('dst_ip') == partial_cms[comm_index][0].get('src_ip')) or \
                    (packet.get('src_ip') == partial_cms[comm_index][0].get('src_ip') and
                     packet.get('dst_ip') == partial_cms[comm_index][0].get('dst_ip')):
                partial_cms[comm_index].append(packet)
                append_at_the_end = False
                break
        if append_at_the_end:
            partial_cms.append([packet])
    output_c = []
    for i in range(len(complete_cms)):
        dict_i = {
            'number_comm': i + 1,
            'packets': complete_cms[i]
        }
        output_c.append(dict_i)
    output_p = []
    for i in range(len(partial_cms)):
        dict_i = {
            'number_comm': i + 1,
            'packets': partial_cms[i]
        }
        output_p.append(dict_i)
    return output_c, output_p


def create_output_file():
    yaml_dump = {"name": "PKS2023/24", "pcap_name": pcap_file, "filter_name": "ARP", "complete_comms": complete_comms,
                 "partial_comms": partial_comms}
    with open(yaml_file_path, 'w') as yaml_file:
        ruamel.yaml.dump(yaml_dump, yaml_file, Dumper=ruamel.yaml.RoundTripDumper)


valid_packets_arp = only_arp()
complete_comms, partial_comms = arp_f()
create_output_file()
