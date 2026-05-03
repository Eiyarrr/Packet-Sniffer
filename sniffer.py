from scapy.all import sniff


# storage for all packet summaries and duplicate counts
seen = {}


def create_summary(packet, fields=None):
    if fields is None:
        fields = ["IP.src", "IP.dst", "IP.proto"]
    # %'s make parsable by sprintf
    elements = "%" + "% - %".join([f for f in fields]) + "%"
    return packet[0].sprintf(elements)


def process_packet(packet):
    summary = create_summary(packet)

    if summary not in seen:
        seen[summary] = {"count": 0, "packet": None}

    seen[summary]["count"] += 1
    seen[summary]["packet"] = summary

    print(f"{seen[summary]['packet']} [x{seen[summary]['count']}]")


def get_packets(fields):
    print("start")
    sniff(prn=process_packet, count=fields[0])
