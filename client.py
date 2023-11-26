import socket
import struct
import time
import crcmod
import math
import threading


def keep_alive(client, stop_flag):
    no_answer = 0
    while not stop_flag.is_set():
        time.sleep(5)
        are_you_alive_packet = create_packet("Are you alive?", 1, 0, 4)
        client.send(are_you_alive_packet)
        try:
            message, address = client.recvfrom(1024)
            if int.from_bytes(message[:1], byteorder='big') == 4 and right_crc(message):
                # print(message[9:])
                no_answer = 0
        except socket.timeout:
            no_answer += 1
            # if no_answer == 4:
            #     # connection lost


def calculate_crc(data):
    crc_function = crcmod.predefined.mkCrcFun('crc-32')
    crc_value = crc_function(data) % 512
    return crc_value


def create_packet(data, number_of_fragments, fragment_num, message_type):
    if isinstance(data, bytes):
        data_packed = struct.pack('!{}s'.format(len(data)), data)
        crc = struct.pack('!H', calculate_crc(data))
    else:
        data_packed = struct.pack('!{}s'.format(len(data)), data.encode('utf-8'))
        crc = struct.pack('!H', calculate_crc(data.encode('utf-8')))
    packet = struct.pack('!B', message_type) + struct.pack('!H', len(data)) + crc + struct.pack(
        '!H', number_of_fragments) + struct.pack('!H', fragment_num) + data_packed
    return packet


def how_many_fragments(data, frag_length):
    if isinstance(data, bytes):
        num_of_fragments = math.ceil(len(data) / (frag_length - 9))
    else:
        num_of_fragments = math.ceil(len(data.encode('utf-8')) / (frag_length - 9))
    # minus bytes of my header, UDP header, IP header
    return num_of_fragments


def send_fragments(client, message):
    frag_size = 0
    while frag_size < 9:
        frag_size = int(input("Fragment size (more than 9 Bytes, because of header): "))
    frags = how_many_fragments(message, frag_size)
    frag_index = 0
    for i in range(frags):
        packet = create_packet(message[frag_index:frag_size + frag_index - 9], frags, i, 6)
        client.send(packet)
        frag_index += (frag_size - 9)


def establishing_connection():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # ip = input("IP: ")
    # port = int(input("Port: "))
    ip = '127.0.0.1'
    port = 12345
    in_packet = create_packet("Hello, are you there?", 1, 0, 3)
    client.connect((ip, port))
    client.settimeout(5)
    while True:
        client.send(in_packet)
        try:
            message, address = client.recvfrom(100)
            if int.from_bytes(message[:1], byteorder='big') == 3 and right_crc(message):
                print(message[9:])
                print("Connection established")
            break
        except ConnectionError or socket.timeout:
            print("Waiting for an answer")
            time.sleep(5)
    return client, (ip, port)


def right_crc(message):
    if calculate_crc(message[9:]) == int.from_bytes(message[3:5], byteorder='big'):
        return True
    else:
        return False


def check_if_right_answer(message):
    if int.from_bytes(message[:1], byteorder='big') == 5 and right_crc(message):  # switch user
        return False, True
    elif int.from_bytes(message[:1], byteorder='big') == 1 and right_crc(message):  # packet arrived
        return True, True
    else:  # corrupted data or packet did not arrive
        return True, False


def sending_message(client):
    info_packet = create_packet("Message", 1, 0, 7)
    client.send(info_packet)
    while True:
        try:
            message, address = client.recvfrom(100)
            con, check = check_if_right_answer(message)
            if not check:
                # send invalid packets again
                pass
            else:
                break
        except socket.timeout:
            pass
    message = input("Write your message: ")
    send_fragments(client, message)
    successful_fragments = 0
    while True:
        try:
            message, address = client.recvfrom(100)
            print(message[9:])
            con, check = check_if_right_answer(message)
            if not check:
                # send invalid packets again
                pass
            else:
                successful_fragments += 1
            # receive till the last packet was sent
            if successful_fragments == int.from_bytes(message[5:7], byteorder='big'):
                break
        except socket.timeout:
            pass


def name_of_file(path):
    name = ""
    for char in reversed(path):
        name = char + name
        if char == "\\":
            break
    return name


def sending_files(client):
    path = input("Path: ")
    info_packet = create_packet("File", 1, 0, 8)
    with open(path, 'rb') as file:
        data = file.read()
    client.send(info_packet)
    while True:
        try:
            message, address = client.recvfrom(100)
            con, check = check_if_right_answer(message)
            if not check:
                # send invalid packets again
                pass
            else:
                break
        except socket.timeout:
            pass
    send_fragments(client, name_of_file(path))
    successful_fragments = 0
    while True:
        try:
            message, address = client.recvfrom(100)
            print(message[9:])
            con, check = check_if_right_answer(message)
            if not check:
                # send invalid packets again
                pass
            else:
                successful_fragments += 1
            # receive till the last packet was sent
            if successful_fragments == int.from_bytes(message[5:7], byteorder='big'):
                break
        except socket.timeout:
            pass
    send_fragments(client, data)
    while True:
        try:
            message, address = client.recvfrom(100)
            print(message[9:])
            con, check = check_if_right_answer(message)
            if not check:
                # send invalid packets again
                pass
            else:
                successful_fragments += 1
            # receive till the last packet was sent
            if successful_fragments == int.from_bytes(message[5:7], byteorder='big'):
                break
        except socket.timeout:
            pass


def main():
    while True:
        client_socket, address = establishing_connection()
        stop_flag_thread = threading.Event()
        thread_keep_alive = threading.Thread(target=keep_alive, args=(client_socket, stop_flag_thread))
        main_thread = threading.Thread()
        thread_keep_alive.start()
        main_thread.start()
        con = True
        while con:
            m_or_f = int(input("File(0) or message(1): "))
            if m_or_f:
                stop_flag_thread.set()
                thread_keep_alive.join()
                sending_message(client_socket)
                stop_flag_thread = threading.Event()
                thread_keep_alive = threading.Thread(target=keep_alive, args=(client_socket, stop_flag_thread))
                thread_keep_alive.start()
            else:
                stop_flag_thread.set()
                thread_keep_alive.join()
                sending_files(client_socket)
                stop_flag_thread = threading.Event()
                thread_keep_alive = threading.Thread(target=keep_alive, args=(client_socket, stop_flag_thread))
                thread_keep_alive.start()

# "C:\Users\lener\Desktop\macka_more.png"
