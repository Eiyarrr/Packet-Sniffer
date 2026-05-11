import socket
from scapy.all import sniff


# storage for all packet summaries and duplicate counts
seen = {}

# storage for seen hosts/ip combos as DNS lookups are expensive
resolved_hosts = {}


def create_summary(packet, fields=None):
    if fields is None:
        fields = ["IP.src", "IP.dst", "IP.proto"]
    # %'s make parsable by sprintf
    elements = "%" + "% - %".join([f for f in fields]) + "%"
    return packet[0].sprintf(elements)


def resolve_ip(ip):
    if ip in resolved_hosts:
        return resolved_hosts[ip]

    try:
        hostname = socket.gethostbyaddr(ip)[0]

    # if no hostname from given IP addr, pretend the addr
    # is a hostname to prevent further unnecessary lookups
    except (socket.herror, socket.gaierror, TimeoutError):
        hostname = ip

    resolved_hosts[ip] = hostname
    return hostname


def print_packet(summary, fields):
    ip = seen[summary]["packet"]
    count = seen[summary]["count"]

    target = ip

    SHOULD_RESOLVE = fields[5]
    if SHOULD_RESOLVE:
        target = resolve_ip(target)

    print(f"{target} [x{count}]")


def process_packet(packet, fields):
    summary = create_summary(packet)
    seen[summary] = {"count": 0, "packet": None}

    seen[summary]["count"] += 1
    seen[summary]["packet"] = summary

    SHOULD_PRINT = fields[1]
    if SHOULD_PRINT:
        print_packet(summary, fields)


def get_packets(fields):
    print("start")
    sniff(prn=lambda packet: process_packet(packet, fields), count=fields[0])
