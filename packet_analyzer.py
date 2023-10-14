from scapy.all import rdpcap
import ruamel.yaml
from ruamel.yaml.scalarstring import PreservedScalarString
import ipaddress


pcap_file = 'trace-27.pcap'
packets = rdpcap(pcap_file)

yaml_file_path = 'output.yaml'


def create_values_dictionaries():
    with open('decimal_values', 'r') as file:
        content = file.read()
        list_of_lines = content.split("\n")
        counter = 0
        saps = {}
        pids = {}
        ether_types = {}
        protocols = {}
        tcp_protocols = {}
        udp_protocols = {}
    for line in list_of_lines:
        if '|' in line:
            counter += 1
        if ':' in line:
            pair = line.split(": ")
            if counter == 1:
                pids[int(pair[0])] = pair[1]
            elif counter == 2:
                saps[int(pair[0])] = pair[1]
            elif counter == 3:
                ether_types[int(pair[0])] = pair[1]
            elif counter == 4:
                protocols[int(pair[0])] = pair[1]
            elif counter == 5:
                tcp_protocols[int(pair[0])] = pair[1]
            elif counter == 6:
                udp_protocols[int(pair[0])] = pair[1]
    return pids, saps, ether_types, protocols, tcp_protocols, udp_protocols


def ether_type_f():
    return Ether_types.get(int(hex_data[24:28], 16))


def hex_data_edit():
    arr = []
    for j in range(0, len(hex_data), 2):
        arr.append(hex_data[j:j + 2])
    output = '\n'.join([' '.join(arr[j:j + 16]) for j in range(0, len(arr), 16)])
    if not output.endswith("\n"):
        output += "\n"
    return PreservedScalarString(output)


def mac_addresses_edit():
    data_destination_mac_address = hex_data[0:12]
    data_source_mac_address = hex_data[12:24]
    src = ''
    dst = ''
    for j in range(12):
        if j % 2 == 0 and j != 0:
            src += ':'
            dst += ':'
        src += data_source_mac_address[j]
        dst += data_destination_mac_address[j]
    return src, dst


def frame_type_f():
    data_ether_type_or_length = hex_data[24:28]
    if int(data_ether_type_or_length, 16) > 1499:
        return 'ETHERNET II'
    else:
        data_4_array = hex_data[28:30]
        if data_4_array == "ff":
            return 'IEEE 802.3 RAW'
        elif data_4_array == "aa":
            return 'IEEE 802.3 LLC & SNAP'
        else:
            return 'IEEE 802.3 LLC'


def pid_f():
    return PIDs.get(int(hex_data[40:44], 16))


def sap_f():
    return SAPs.get(int(hex_data[32:34], 16))


def ip_addresses_f():
    si_list = []
    di_list = []
    ip_src_output = ""
    ip_dst_output = ""
    if ether_type == 'IPv6':
        source_ip_hex = hex_data[44:76]
        dst_ip_hex = hex_data[76:108]
    elif ether_type == 'ARP':
        source_ip_hex = hex_data[56:64]
        dst_ip_hex = hex_data[76:84]
    else:
        source_ip_hex = hex_data[52:60]
        dst_ip_hex = hex_data[60:68]
    if ether_type == 'IPv6':
        for b in range(0, len(source_ip_hex), 4):
            si_list.append(source_ip_hex[b:b + 4])
            di_list.append(dst_ip_hex[b:b + 4])
        for b in range(len(si_list)):
            if b != 0:
                ip_src_output += ':'
                ip_dst_output += ':'
            ip_src_output += si_list[b]
            ip_dst_output += di_list[b]

        ip_src_output = ipaddress.IPv6Address(ip_src_output)
        ip_src_output = ip_src_output.compressed

        ip_dst_output = ipaddress.IPv6Address(ip_dst_output)
        ip_dst_output = ip_dst_output.compressed
    else:
        for b in range(0, len(source_ip_hex), 2):
            si_list.append(source_ip_hex[b:b + 2])
            di_list.append(dst_ip_hex[b:b + 2])
        for n in range(len(si_list)):
            ip_src_output += str(int(si_list[n], 16))
            ip_dst_output += str(int(di_list[n], 16))
            if n != 3:
                ip_src_output += '.'
                ip_dst_output += '.'
    return ip_src_output, ip_dst_output


def protocol_f():
    return Protocols.get(int(hex_data[46:48], 16))


def port_f():
    return int(hex_data[68:72], 16), int(hex_data[72:76], 16)


def app_protocol_f():
    if protocol == 'UDP':
        if UDP_protocols.get(src_port) is not None:
            return UDP_protocols.get(src_port)
        elif UDP_protocols.get(dst_port) is not None:
            return UDP_protocols.get(dst_port)
    if protocol == 'TCP':
        if TCP_protocols.get(src_port) is not None:
            return TCP_protocols.get(src_port)
        elif TCP_protocols.get(dst_port) is not None:
            return TCP_protocols.get(dst_port)
    return None


def create_output_dictionary_packets():
    if frame_type == 'ETHERNET II':
        if ether_type == 'IPv4':
            if protocol == 'TCP' or protocol == 'UDP':
                if app_protocol is not None:
                    packet_o = {
                        'frame_number': frame_number,
                        'len_frame_pcap': len_pcap,
                        'len_frame_medium': len_pcap_medium,
                        'frame_type': frame_type,
                        'src_mac': src_mac,
                        'dst_mac': dst_mac,
                        'ether_type': ether_type,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': protocol,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'app_protocol': app_protocol,
                        'hexa_frame': hex_data_final_form
                    }
                else:
                    packet_o = {
                        'frame_number': frame_number,
                        'len_frame_pcap': len_pcap,
                        'len_frame_medium': len_pcap_medium,
                        'frame_type': frame_type,
                        'src_mac': src_mac,
                        'dst_mac': dst_mac,
                        'ether_type': ether_type,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': protocol,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'hexa_frame': hex_data_final_form
                    }
            else:
                packet_o = {
                    'frame_number': frame_number,
                    'len_frame_pcap': len_pcap,
                    'len_frame_medium': len_pcap_medium,
                    'frame_type': frame_type,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'ether_type': ether_type,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'hexa_frame': hex_data_final_form
                }
        else:
            packet_o = {
                'frame_number': frame_number,
                'len_frame_pcap': len_pcap,
                'len_frame_medium': len_pcap_medium,
                'frame_type': frame_type,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'ether_type': ether_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'hexa_frame': hex_data_final_form
            }
    elif frame_type == 'IEEE 802.3 RAW':
        packet_o = {
            'frame_number': frame_number,
            'len_frame_pcap': len_pcap,
            'len_frame_medium': len_pcap_medium,
            'frame_type': frame_type,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'hexa_frame': hex_data_final_form
        }
    elif frame_type == 'IEEE 802.3 LLC & SNAP':
        packet_o = {
            'frame_number': frame_number,
            "len_frame_pcap": len_pcap,
            'len_frame_medium': len_pcap_medium,
            'frame_type': frame_type,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'pin': data_pin,
            'hexa_frame': hex_data_final_form
        }
    else:
        packet_o = {
            'frame_number': frame_number,
            "len_frame_pcap": len_pcap,
            'len_frame_medium': len_pcap_medium,
            'frame_type': frame_type,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'sap': data_sap,
            'hexa_frame': hex_data_final_form
        }
    return packet_o


def ipv4_ip_addresses():
    if ether_type == 'IPv4':
        if src_ip not in array_of_ipv4_ip_addresses:
            array_of_ipv4_ip_addresses.append(src_ip)
            array_of_ipv4_ip_addresses_counter.append(1)
        else:
            array_of_ipv4_ip_addresses_counter[array_of_ipv4_ip_addresses.index(src_ip)] += 1


def create_output_dictionary_ipv4_senders():
    arr = []
    for j in range(len(array_of_ipv4_ip_addresses)):
        dict_of_node = {
            'node': array_of_ipv4_ip_addresses[j],
            'number_of_sent_packets': array_of_ipv4_ip_addresses_counter[j]
        }
        arr.append(dict_of_node)
    return arr


def create_max_array():
    max_used_ip = []
    max_value = max(array_of_ipv4_ip_addresses_counter)
    max_indexes = [j for j, value in enumerate(array_of_ipv4_ip_addresses_counter) if value == max_value]
    for j in range(len(array_of_ipv4_ip_addresses)):
        for m in max_indexes:
            if j == m:
                max_used_ip.append(array_of_ipv4_ip_addresses[j])
    return max_used_ip


def create_output_file():
    yaml_dump = {"name": "PKS2023/24", "pcap_name": pcap_file, "packets": yaml_dump_arr_packets,
                 "ipv4_senders": yaml_dump_arr_ip, "max_send_packets_by": yaml_dump_arr_max_ip}
    with open(yaml_file_path, 'w') as yaml_file:
        ruamel.yaml.dump(yaml_dump, yaml_file, Dumper=ruamel.yaml.RoundTripDumper)


yaml_dump_arr_packets = []
frame_number = 0
array_of_ipv4_ip_addresses = []
array_of_ipv4_ip_addresses_counter = []
PIDs, SAPs, Ether_types, Protocols, TCP_protocols, UDP_protocols = create_values_dictionaries()
for i in packets:
    frame_number += 1
    hex_data = (i.build()).hex()

    len_pcap = len(bytes(i))
    if len_pcap < 64:
        len_pcap_medium = 64
    else:
        len_pcap_medium = len(bytes(i)) + 4
    frame_type = frame_type_f()

    data_pin = pid_f()

    data_sap = sap_f()

    hex_data_final_form = hex_data_edit()

    src_mac, dst_mac = mac_addresses_edit()

    ether_type = ether_type_f()

    protocol = protocol_f()

    src_ip, dst_ip = ip_addresses_f()

    src_port, dst_port = port_f()

    app_protocol = app_protocol_f()

    ipv4_ip_addresses()

    packet = create_output_dictionary_packets()
    yaml_dump_arr_packets.append(packet)  # vhodenie paketu do yaml_dumper_arr_packets
yaml_dump_arr_ip = create_output_dictionary_ipv4_senders()
yaml_dump_arr_max_ip = create_max_array()
create_output_file()

