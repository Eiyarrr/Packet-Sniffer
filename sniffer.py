import socket
from scapy.all import sniff


# storage for all packet summaries and duplicate counts
seen = {}


def create_summary(packet, fields=None):
    if fields is None:
        fields = ["IP.src", "IP.dst", "IP.proto"]
    # %'s make parsable by sprintf
    elements = "%" + "% - %".join([f for f in fields]) + "%"
    return packet[0].sprintf(elements)


def print_packet(summary, fields):

    ip = seen[summary]['packet']
    count = seen[summary]['count']

    SHOULD_RESOLVE = fields[5]
    if SHOULD_RESOLVE:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            print(f"{hostname} [x{count}]")
            return
        # if there is no resolvable hostname, just print IP addr
        except (socket.herror, socket.gaierror, TimeoutError):
            pass

    print(f"{ip} [x{count}]")


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
