# tcp_echo.py
import socket

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 7007))
srv.listen(5)
print("TCP echo listening on 7007")
while True:
    conn, addr = srv.accept()
    data = conn.recv(1024)
    conn.sendall(data)
    conn.close()
