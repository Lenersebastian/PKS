import server
import client

c_or_s = int(input("Receiver(0) or sender?(1): "))
while True:
    c_or_s += 1
    if c_or_s % 2 == 0:
        c_socket = client.establishing_connection()
        client.main_f(c_socket)
        c_socket.close()
    else:
        s_socket = server.establishing_connection()
        server.main_f(s_socket)
        s_socket.close()
