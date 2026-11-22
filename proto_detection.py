import socket
import struct
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.all import sr1


ECHO_PROBE = b"portscan-echo-probe-42\n"


def _try_http(ip, port, timeout):
    """HTTP поверх TCP: HEAD / → ожидаем строку, начинающуюся с 'HTTP/'."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
            sock.sendall(request)
            response = sock.recv(4096)
            if response.startswith(b"HTTP/"):
                return "HTTP"
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def _try_dns_udp(ip, port, timeout):
    """DNS поверх UDP через Scapy: шлём A-запрос, ждём валидный ответ."""
    query = IP(dst=ip) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    try:
        response = sr1(query, timeout=timeout, verbose=0)
    except OSError:
        return None
    if response is not None and DNS in response and response[DNS].qr == 1:
        return "DNS"
    return None

DNS_HEADER_SIZE = 12
DATA_LEN = 2

def _try_dns_tcp(ip, port, timeout):
    dns_query = DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
    raw = bytes(dns_query)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack("!H", len(raw)) + raw)
            length_data = sock.recv(DATA_LEN)
            if len(length_data) < DATA_LEN:
                return None
            length = struct.unpack("!H", length_data)[0]
            data = b""
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) >= DNS_HEADER_SIZE:
                resp = DNS(data)
                if resp.id == 0x1234 and resp.qr == 1:
                    return "DNS"
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def _try_echo_tcp(ip, port, timeout):
    """TCP ECHO: ответ должен точно совпасть с отправленным маркером."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(ECHO_PROBE)
            response = sock.recv(4096)
            if response == ECHO_PROBE:
                return "ECHO"
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def _try_echo_udp(ip, port, timeout):
    """UDP ECHO: тот же принцип, но через SOCK_DGRAM."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(ECHO_PROBE, (ip, port))
            data, _ = sock.recvfrom(4096)
            if data == ECHO_PROBE:
                return "ECHO"
    except (socket.timeout, OSError):
        pass
    return None


def detect_protocol(ip, proto, port, timeout):
    """Возвращает 'HTTP' / 'DNS' / 'ECHO' / None."""
    if proto == "tcp":
        for probe in (_try_http, _try_dns_tcp, _try_echo_tcp):
            result = probe(ip, port, timeout)
            if result:
                return result
    elif proto == "udp":
        for probe in (_try_dns_udp, _try_echo_udp):
            result = probe(ip, port, timeout)
            if result:
                return result
    return None
