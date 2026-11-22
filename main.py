import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.all import sr1
import time

from proto_detection import detect_protocol


def main():
    arg_parser = configure_cli()
    args = arg_parser.parse_args()

    try:
        ipaddress.ip_address(args.ip_address)
    except ValueError:
        arg_parser.error(f"invalid IP address: {args.ip_address!r}")

    specs: list[tuple[str, list[int]]] = []
    for s in args.ports:
        try:
            specs.extend(parse_port_spec(s))
        except argparse.ArgumentTypeError as e:
            arg_parser.error(str(e))

    open_ports = get_open_ports(args, specs)
    protocols = get_protocols(args, open_ports)
    print_answer(args, open_ports, protocols)


def configure_cli():
    parser = argparse.ArgumentParser(prog="portscan")
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="таймаут ожидания ответа (по умолчанию 2)",
    )
    parser.add_argument(
        "-j", "--num-threads", type=int, default=1, help="число потоков"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="подробный режим")
    parser.add_argument(
        "-g",
        "--guess",
        action="store_true",
        help="определение протокола прикладного уровня",
    )
    parser.add_argument("ip_address")
    parser.add_argument("ports", nargs="+", help="[{tcp|udp}[/[PORT|PORT-PORT],...]]")

    return parser


def parse_port_spec(spec: str) -> list[tuple[str, list[int]]]:
    """
    Возвращает список пар (proto, ports).
    """
    if "/" in spec:
        proto_part, _, ports_part = spec.partition("/")
    elif spec.lower() in ("tcp", "udp"):
        proto_part, ports_part = spec.lower(), ""
    else:
        proto_part, ports_part = None, spec

    if proto_part is not None:
        proto_part = proto_part.lower()
        if proto_part not in ("tcp", "udp"):
            raise argparse.ArgumentTypeError(f"unknown protocol: {proto_part!r}")

    ports = parse_ports(spec, ports_part)

    if proto_part is None:
        return [("tcp", ports), ("udp", ports)]
    return [(proto_part, ports)]


def parse_ports(spec, ports_part: str):
    if not ports_part:
        ports = list(range(1, 65536))  # все порты
    else:
        ports_set = set()
        for chunk in ports_part.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                lo, hi = chunk.split("-", 1)
                try:
                    lo, hi = int(lo), int(hi)
                except ValueError:
                    raise argparse.ArgumentTypeError(f"bad range: {chunk!r}")
                if not (0 < lo <= hi <= 65535):
                    raise argparse.ArgumentTypeError(f"invalid range: {chunk!r}")
                ports_set.update(range(lo, hi + 1))
            else:
                try:
                    p = int(chunk)
                except ValueError:
                    raise argparse.ArgumentTypeError(f"bad port: {chunk!r}")
                if not (0 < p <= 65535):
                    raise argparse.ArgumentTypeError(f"invalid port: {chunk!r}")
                ports_set.add(p)
        if not ports_set:
            raise argparse.ArgumentTypeError(f"empty port list in {spec!r}")
        ports = sorted(ports_set)
    return ports


def get_open_ports(args, specs):
    open_ports = []
    for proto, ports in specs:
        for port in ports:
            if proto == "tcp":
                state, response_time = tcp_syn_scan(args.ip_address, port, args.timeout)
            else:
                state, response_time = udp_scan(args.ip_address, port, args.timeout)
            if state == "open":
                open_ports.append((proto, port, response_time))
    return open_ports


def tcp_syn_scan(target_ip, port, timeout=2.0):
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

    start_time = time.perf_counter()
    response = sr1(syn_packet, timeout=timeout, verbose=0)
    response_time = (time.perf_counter() - start_time) * 1000  # в миллисекундах

    if response is None:
        # Ответа нет — порт, вероятно, фильтруется
        return "filtered", None

    if TCP in response:
        flags = response.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK
            # Порт открыт! Отправляем RST, чтобы закрыть полуоткрытое соединение
            rst_packet = IP(dst=target_ip) / TCP(
                dport=port, flags="R", seq=response[TCP].ack
            )
            sr1(rst_packet, timeout=1, verbose=0)
            return "open", response_time
        elif flags == 0x14:  # RST-ACK
            # Порт закрыт
            return "closed", response_time

    return "unknown", response_time


def udp_scan(target_ip, port, timeout=2.0):
    udp_packet = IP(dst=target_ip) / UDP(dport=port)

    response = sr1(udp_packet, timeout=timeout, verbose=0)

    if response is None:
        return "open|filtered", None

    if UDP in response:
        return "open", None

    if ICMP in response:
        icmp = response[ICMP]
        if icmp.type == 3 and icmp.code == 3:      # Port Unreachable
            return "closed", None
        return "filtered", None

    return "unknown", None


def get_protocols(args, open_ports):
    protocols = {}
    if args.guess and open_ports:
        probe_timeout = min(args.timeout, 2.0)  # проба должна быть быстрой
        workers_num = min(max(1, args.num_threads), len(open_ports) or 1)

        def worker(item):
            proto, port, _ = item
            name = detect_protocol(args.ip_address, proto, port, probe_timeout)
            return (proto, port), name

        with ThreadPoolExecutor(max_workers=workers_num) as pool:
            for key, name in pool.map(worker, open_ports):
                protocols[key] = name
    return protocols


def print_answer(args, open_ports, protocols):
    for proto, port, rtt in open_ports:
        parts = [proto.upper(), str(port)]
        if args.verbose and rtt is not None:
            parts.append(f"[{rtt:.1f} ms]")
        if args.guess:
            parts.append(f"[{protocols.get((proto, port)) or '-'}]")
        print(" ".join(parts))


if __name__ == "__main__":
    main()
