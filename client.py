import socket
import struct
import time
import crcmod
import math
import threading


def keep_alive(client, stop_flag):
    no_answer = 0
    client.settimeout(5)
    while not stop_flag.is_set():
        time.sleep(5)
        are_you_alive_packet = create_packet("Are you alive?", 1, 0, 4)
        client.send(are_you_alive_packet)
        try:
            message, address = client.recvfrom(1024)
            # print(message)
            if int.from_bytes(message[:1], byteorder='big') == 4 and right_crc(message):
                no_answer = 0
        except ConnectionResetError:
            # connection lost
            print("Connection lost")
            exit()
        except socket.timeout:
            no_answer += 1
            if no_answer == 4:
                # connection lost
                print("Socket timeout")
                exit()


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


def how_many_fragments(data, frag_length):
    num_of_fragments = math.ceil(len(data) / frag_length)
    return num_of_fragments


def establishing_connection():
    ip = input("IP: ")
    port = int(input("Port: "))
    # ip = '127.0.0.1'
    # port = 12345
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    in_packet = create_packet("Hello, are you there?", 1, 0, 3)
    client.connect((ip, port))
    client.settimeout(5)
    while True:
        client.send(in_packet)
        try:
            message, address = client.recvfrom(100)
            client.settimeout(None)
            if int.from_bytes(message[:1], byteorder='big') == 3 and right_crc(message):
                print(message[9:])
                print("Connection established")
            break
        except (ConnectionResetError, socket.timeout):
            print("Waiting for an answer")
            time.sleep(5)
    return client


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


def corrupted_packets():
    wrong_packets = input("Which fragments should be corrupted (starting from 0, if none write x): ")
    if wrong_packets == "x":
        return [-1]
    else:
        return list(map(int, wrong_packets.split()))


def sending_message(client):
    info_packet = create_packet("Message", 1, 0, 7)
    client.send(info_packet)
    while True:
        try:
            message, address = client.recvfrom(1024)
            client.settimeout(None)
            con, check = check_if_right_answer(message)
            if not check:
                # send invalid packets again
                client.send(info_packet)
            else:
                break
        except socket.timeout:
            print("Socket timeout")
            return
    client.settimeout(5)
    message_send = input("Write your message: ")
    frag_size = int(input("Fragment size: "))
    successful_fragments = 0
    counter = 0
    indexes_of_corrupted_packets = corrupted_packets()
    frags = how_many_fragments(message_send, frag_size)
    frag_index = 0
    print(f"Sent {frags} packets")
    all_packets = []
    for i in range(frags):
        packet = create_packet(message_send[frag_index:frag_size + frag_index], frags, i, 6)
        all_packets.append(packet)
        frag_index += frag_size
    while True:
        packet = all_packets[counter]
        if counter in indexes_of_corrupted_packets:
            packet = packet[:3] + b'\x00\x00' + packet[5:]  # wrong crc
            indexes_of_corrupted_packets.remove(counter)
        client.send(packet)
        try:
            message_received, address = client.recvfrom(1024)
            print(message_received)
            client.settimeout(None)
            con, check = check_if_right_answer(message_received)
            if check:
                successful_fragments += 1
                counter += 1
            else:
                packet = all_packets[counter]
                for i in range(5):
                    client.send(packet)
            # receive till the last packet was sent
            if successful_fragments == int.from_bytes(message_received[5:7], byteorder='big'):
                break
        except socket.timeout:
            exit("Socket timeout")
    client.settimeout(5)


def name_of_file(path):
    name = ""
    for char in reversed(path):
        name = char + name
        if char == "\\":
            break
    return name


def sending_files(client):
    while True:
        path = input("Path: ")
        try:
            with open(path, 'rb') as file:
                data = file.read()
                break
        except FileNotFoundError:
            print("File not found")
    info_packet = create_packet("File", 1, 0, 8)
    client.send(info_packet)
    while True:
        try:
            message, address = client.recvfrom(1024)
            client.settimeout(None)
            con, check = check_if_right_answer(message)
            if check:
                break
        except socket.timeout:
            exit("Socket timeout")
    client.settimeout(5)
    file_name = name_of_file(path)
    counter = 0
    frags = 1
    frag_index = 0
    frag_size = 1024
    successful_fragments = 0
    while True:  # cycle for filename
        packet = create_packet(file_name[frag_index:frag_size + frag_index], frags, counter, 6)
        client.send(packet)
        frag_index += frag_size
        counter += 1
        try:
            message, address = client.recvfrom(frag_size)
            client.settimeout(None)
            con, check = check_if_right_answer(message)
            if check:
                successful_fragments += 1
            # receive till the last packet was sent
            if successful_fragments == int.from_bytes(message[5:7], byteorder='big'):
                print(f"Received {successful_fragments} ACK packets")
                break
        except socket.timeout:
            exit("Socket timeout")
    print(f"File name sent")
    client.settimeout(5)
    counter = 0
    frag_size = int(input("Fragment size: "))
    frags = how_many_fragments(data, frag_size)
    frag_index = 0
    successful_fragments = 0
    indexes_of_corrupted_packets = corrupted_packets()
    print(f"Sending {frags} fragments of file data")
    all_packets = []
    for i in range(frags):
        packet = create_packet(data[frag_index:frag_size + frag_index], frags, i, 6)
        all_packets.append(packet)
        frag_index += frag_size
    while True:  # cycle for file
        packet = all_packets[counter]
        if counter in indexes_of_corrupted_packets:
            packet = packet[:3] + b'\x00\x00' + packet[5:]  # wrong crc
            indexes_of_corrupted_packets.remove(counter)
        client.send(packet)
        try:
            message, address = client.recvfrom(frag_size)
            client.settimeout(None)
            con, check = check_if_right_answer(message)
            if check:
                successful_fragments += 1
                counter += 1
            else:
                packet = all_packets[counter]
                for i in range(4):
                    client.send(packet)
            # receive till the last packet was sent
            if successful_fragments == int.from_bytes(message[5:7], byteorder='big'):
                print(f"File was send, received {successful_fragments} ACK packets")
                break
        except socket.timeout:
            exit("Socket timeout")
    client.settimeout(5)


def switch(client):
    client.send(create_packet("Switch", 1, 0, 5))
    while True:
        try:
            message, address = client.recvfrom(1024)
            client.settimeout(None)
            con, check = check_if_right_answer(message)
            if not con:
                break
        except socket.timeout:
            exit("Socket timeout")


def main_f(client_socket):
    stop_flag_thread = threading.Event()
    thread_keep_alive = threading.Thread(target=keep_alive, args=(client_socket, stop_flag_thread))
    thread_keep_alive.start()
    while True:
        m_or_f = int(input("File(0) or message(1) or switch(2): "))
        if m_or_f == 1:
            stop_flag_thread.set()
            thread_keep_alive.join()
            sending_message(client_socket)
            sw = False
            while True:  # switch??
                try:
                    message, address = client_socket.recvfrom(1024)
                    print(message)
                    if int.from_bytes(message[:1], byteorder='big') == 5:
                        sw = True
                    break
                except socket.timeout:
                    pass
            if sw:
                break
            else:
                stop_flag_thread = threading.Event()
                thread_keep_alive = threading.Thread(target=keep_alive, args=(client_socket,
                                                                              stop_flag_thread))
                thread_keep_alive.start()
        elif m_or_f == 0:
            stop_flag_thread.set()
            thread_keep_alive.join()
            sending_files(client_socket)
            sw = False
            while True:  # switch??
                try:
                    message, address = client_socket.recvfrom(1024)
                    print(message)
                    if int.from_bytes(message[:1], byteorder='big') == 5:
                        sw = True
                    break
                except socket.timeout:
                    pass
            if sw:
                break
            else:
                stop_flag_thread = threading.Event()
                thread_keep_alive = threading.Thread(target=keep_alive, args=(client_socket, stop_flag_thread))
                thread_keep_alive.start()
        else:
            stop_flag_thread.set()
            thread_keep_alive.join()
            switch(client_socket)
            break

# C:\Users\lener\Desktop\macka.png
