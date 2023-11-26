import socket
import struct
import crcmod
import os


def calculate_crc(data):
    crc_function = crcmod.predefined.mkCrcFun('crc-32')
    crc_value = crc_function(data.encode('utf-8')) % 512
    return crc_value


def create_packet(data, number_of_fragments, fragment_num, message_type):
    packet = struct.pack('!B', message_type) + struct.pack('!H', len(data)) + \
             struct.pack('!H', calculate_crc(data)) + struct.pack('!H', number_of_fragments) + \
             struct.pack('!H', fragment_num) + struct.pack('!{}s'.format(len(data)), data.encode('utf-8'))
    return packet


def establishing_connection(frag_size):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    con = False
    address = 0, 0
    while not con:
        # ip = input("IP: ")
        # port = int(input("Port: "))
        ip = '127.0.0.1'
        port = 12345
        server.bind((ip, port))
        print("Receiver is waiting for the initialization packet...")
        server.settimeout(5)
        counter = 0
        while True:
            if counter == 6:
                print("Initializing packet did not arrived")
                break
            try:
                message, address = server.recvfrom(frag_size)
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
    return server, address


def right_crc(message):
    if calculate_crc(message[9:].decode('utf-8')) == int.from_bytes(message[3:5], byteorder='big'):
        return True
    else:
        return False


def receive_info_packets(server, frag_size):
    message, address = server.recvfrom(frag_size)
    # end of connection
    if int.from_bytes(message[:1], byteorder='big') == 5 and right_crc(message):
        return 1
    elif int.from_bytes(message[:1], byteorder='big') == 7 and right_crc(message):
        server.sendto(create_packet("Receiving message", 1, 0, 1), address)
        receiving_message(server, frag_size)
    elif int.from_bytes(message[:1], byteorder='big') == 8 and right_crc(message):
        server.sendto(create_packet("Receiving file", 1, 0, 1), address)
        receiving_file(server, frag_size)
    # keepalive
    elif int.from_bytes(message[:1], byteorder='big') == 4 and right_crc(message):
        server.sendto(create_packet("Yes, i am alive", 1, 0, 4), address)
    # corrupted data
    else:
        server.sendto(create_packet("Corrupted data", 1, 0, 2), address)


def receive_data_packet(server, message, address):
    # data transfer
    if int.from_bytes(message[:1], byteorder='big') == 6 and right_crc(message):
        server.sendto(create_packet("Packet successfully arrived", int.from_bytes(message[5:7], byteorder='big'),
                                    int.from_bytes(message[7:9], byteorder='big'), 1), address)
        return True
    # corrupted data
    else:
        server.sendto(create_packet("Corrupted data", 1, 0, 2), address)
        return False


def receiving_message(server, frag_size):
    parts_of_mess = []
    indexes_of_parts = []
    while True:
        try:
            message, address = server.recvfrom(frag_size)
            if receive_data_packet(server, message, address):  # successful transfer
                print(message)
                parts_of_mess.append(message[9:].decode())
                indexes_of_parts.append(int.from_bytes(message[7:9], byteorder='big'))
            if len(parts_of_mess) == int.from_bytes(message[5:7], byteorder='big'):
                whole_mess = ""
                for i in range(len(parts_of_mess)):
                    whole_mess += parts_of_mess[indexes_of_parts.index(i)]
                print(f"Whole message: {whole_mess}")
                break
        except socket.timeout:
            pass


def receiving_file(server, frag_size):
    parts_of_file_name = []
    indexes_of_parts = []
    while True:
        try:
            message, address = server.recvfrom(frag_size)
            if receive_data_packet(server, message, address):  # successful transfer
                print(message)
                parts_of_file_name.append(message[9:].decode())
                indexes_of_parts.append(int.from_bytes(message[7:9], byteorder='big'))
            if len(parts_of_file_name) == int.from_bytes(message[5:7], byteorder='big'):
                file_name = ""
                for i in range(len(parts_of_file_name)):
                    file_name += parts_of_file_name[indexes_of_parts.index(i)]
                break
        except socket.timeout:
            pass
    parts_of_file = []
    indexes_of_parts = []
    while True:
        try:
            message, address = server.recvfrom(frag_size)
            if receive_data_packet(server, message, address):  # successful transfer
                print(message)
                parts_of_file.append(message[9:])
                indexes_of_parts.append(int.from_bytes(message[7:9], byteorder='big'))
            if len(parts_of_file) == int.from_bytes(message[5:7], byteorder='big'):
                file_bytes = b''
                for i in range(len(parts_of_file)):
                    file_bytes += parts_of_file[indexes_of_parts.index(i)]
                break
        except socket.timeout:
            pass
    path = os.getcwd()
    file_path = os.path.join(path, file_name)
    with open(file_path, "wb") as file:
        file.write(file_bytes)


def main():
    while True:
        fragment_size = 1024
        server_socket, address = establishing_connection(fragment_size)
        while True:
            try:
                receive_info_packets(server_socket, fragment_size)
            except socket.timeout:
                pass

#######chyba dakde v serveri asi pri posielani fileov dake ze: UnicodeDecodeError: 'utf-8' codec can't decode byte 0x89 in position 0: invalid start byte
