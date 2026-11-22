# udp_echo.py
import socket

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 7008))
print("UDP echo listening on 7008")
while True:
    data, addr = srv.recvfrom(1024)
    srv.sendto(data, addr)
