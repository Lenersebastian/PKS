import socket
import struct
import crcmod
import os


def calculate_crc(data):
    crc_function = crcmod.predefined.mkCrcFun('crc-16')
    crc_value = crc_function(data) & 0xFFFF
    return crc_value


def create_packet(data, number_of_fragments, fragment_num, message_type):
    if isinstance(data, str):
        packet = struct.pack('!BHHHH', message_type, len(data), calculate_crc(data.encode()),
                             number_of_fragments, fragment_num) + data.encode()
    else:
        packet = struct.pack('!BHHHH', message_type, len(data), calculate_crc(data),
                             number_of_fragments, fragment_num) + data
    return packet


def establishing_connection():
    con = False
    address = 0, 0
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not con:
        ip = input("IP: ")
        port = int(input("Port: "))
        # ip = '127.0.0.1'
        # port = 12345
        server.bind(('', port))
        print("Receiver is waiting for the initialization packet...")
        server.settimeout(5)
        counter = 0
        while True:
            if counter == 6:
                print("Initializing packet did not arrived")
                break
            try:
                message, address = server.recvfrom(1024)
                server.settimeout(None)
                if int.from_bytes(message[:1], byteorder='big') == 3 and right_crc(message):  # initializing packet
                    print(message[9:])
                    con = True
                    break
            except socket.timeout:
                counter += 1
                print("Retrying...")
    answer_packet = create_packet("Yep im here", 1, 0, 3)
    server.sendto(answer_packet, address)
    print("Connection established")
    return server


def right_crc(message):
    if calculate_crc(message[9:]) == int.from_bytes(message[3:5], byteorder='big'):
        return True
    else:
        return False


def potential_switch(server, address):
    switch = input("Do you want to switch roles(yes/no)? ")
    if switch == "yes":
        server.sendto(create_packet("Switch", 1, 0, 5), address)
        return 1
    else:
        server.sendto(create_packet("ACK", 1, 0, 1), address)


def receive_info_packets(server, frag_size):
    while True:
        try:
            message, address = server.recvfrom(frag_size)
            server.settimeout(None)
            # switch
            if int.from_bytes(message[:1], byteorder='big') == 5 and right_crc(message):
                server.sendto(create_packet("Switch", 1, 0, 5), address)
                return 1
            elif int.from_bytes(message[:1], byteorder='big') == 7 and right_crc(message):
                server.sendto(create_packet("Receiving message", 1, 0, 1), address)
                receiving_message(server, frag_size)
                if potential_switch(server, address):
                    return 1
                break
            elif int.from_bytes(message[:1], byteorder='big') == 8 and right_crc(message):
                server.sendto(create_packet("Receiving file", 1, 0, 1), address)
                receiving_file(server, frag_size)
                if potential_switch(server, address):
                    return 1
                break
            # keepalive
            elif int.from_bytes(message[:1], byteorder='big') == 4 and right_crc(message):
                # print(message)
                server.sendto(create_packet("Yes, i am alive", 1, 0, 4), address)
                break
            # corrupted data
            else:
                server.sendto(create_packet("Corrupted data", 1, 0, 2), address)
                break
        except socket.timeout:
            break
    server.settimeout(5)


def receive_data_packet(server, message, address):
    # data transfer
    if int.from_bytes(message[:1], byteorder='big') == 6 and right_crc(message):
        ack_packet = create_packet("Packet successfully arrived", int.from_bytes(message[5:7], byteorder='big'),
                                   int.from_bytes(message[7:9], byteorder='big'), 1)
        server.sendto(ack_packet, address)
        return True
    # corrupted data
    else:
        server.sendto(create_packet("Corrupted data", int.from_bytes(message[5:7], byteorder='big'),
                                    int.from_bytes(message[7:9], byteorder='big'), 2), address)
        return False


def receiving_message(server, frag_size):
    parts_of_mess = []
    indexes_of_parts = []
    unsuccessful_packets = 0
    server.settimeout(5)
    while True:
        try:
            message, address = server.recvfrom(frag_size)
            server.settimeout(None)
            if receive_data_packet(server, message, address):  # successful transfer
                if message[9:].decode() not in parts_of_mess:
                    parts_of_mess.append(message[9:].decode())
                    indexes_of_parts.append(int.from_bytes(message[7:9], byteorder='big'))
            else:
                unsuccessful_packets += 1
            print(message)
            if len(parts_of_mess) == int.from_bytes(message[5:7], byteorder='big'):
                whole_mess = ""
                for i in range(len(parts_of_mess)):
                    whole_mess += parts_of_mess[indexes_of_parts.index(i)]
                print(f"Whole message: {whole_mess}")
                print(f"Received {len(parts_of_mess)} successful packets and "
                      f"{unsuccessful_packets} unsuccessful packets")
                break
        except socket.timeout:
            pass


def receiving_file(server, frag_size):
    parts_of_file_name = []
    indexes_of_parts = []
    server.settimeout(5)
    while True:
        try:
            message, address = server.recvfrom(frag_size)
            server.settimeout(None)
            if receive_data_packet(server, message, address):  # successful transfer
                parts_of_file_name.append(message[9:].decode())
                indexes_of_parts.append(int.from_bytes(message[7:9], byteorder='big'))
            if len(parts_of_file_name) == int.from_bytes(message[5:7], byteorder='big'):
                file_name = ""
                for i in range(len(parts_of_file_name)):
                    file_name += parts_of_file_name[indexes_of_parts.index(i)]
                print(f"Received {len(parts_of_file_name)} packets (name of file)")
                break
        except socket.timeout:
            print("socket timeout")
            return
    parts_of_file = []
    indexes_of_parts = []
    while True:
        try:
            message, address = server.recvfrom(frag_size)
            if receive_data_packet(server, message, address):  # successful transfer
                parts_of_file.append(message[9:])
                indexes_of_parts.append(int.from_bytes(message[7:9], byteorder='big'))
            if len(parts_of_file) == int.from_bytes(message[5:7], byteorder='big'):
                file_bytes = b''
                for i in range(len(parts_of_file)):
                    file_bytes += parts_of_file[indexes_of_parts.index(i)]
                print(f"Received successful {len(parts_of_file)} packets (file data)")
                break
        except socket.timeout:
            print("socket timeout")
            return
    path = os.getcwd()
    print(path)
    file_path = path + file_name
    print(file_name)
    print(file_path)
    with open(file_path, "wb") as file:
        file.write(file_bytes)


def main_f(server_socket):
    fragment_size = 1024
    while True:
        try:
            if receive_info_packets(server_socket, fragment_size) == 1:
                break
        except socket.timeout:
            pass
