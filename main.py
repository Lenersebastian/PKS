import server
import client

c_or_s = int(input("Receiver(0) or sender?(1): "))
if c_or_s:
    client.main()
else:
    server.main()
