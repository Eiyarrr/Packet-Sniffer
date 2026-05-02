from scapy.all import sniff
import argparse


def create_summary(packet, fields=None):
    if fields is None:
        fields = ["IP.src", "IP.dst", "IP.proto"]
    # %'s make parsable by sprintf
    elements = "%" + "% - %".join([f for f in fields]) + "%"
    return packet[0].sprintf(elements)


seen = {}


def process_packet(packet):
    summary = create_summary(packet)
    seen[summary] = seen.get(summary, 0) + 1
    print(f"{summary} [x{seen[summary]}]")


def get_packets(count):
    print("start")
    sniff(prn=process_packet, count=count)


# Make store -src, -dst, -proto
# Also must make more options (presets?)
def parse_user_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-src",
        help="Include the source IP of the packet when printing summaries",
        action="store_true",
    )
    parser.add_argument(
        "-dst",
        help="Include the destination IP of the packet when printing summaries",
        action="store_true",
    )
    parser.add_argument(
        "-proto",
        help="Include the IP protocol of the packet when printing summaries",
        action="store_true",
    )
    parser.add_argument(
        "quantity",
        nargs="?",
        help="The quantity of packets to give (default = 50)",
        type=int,
        default=50,
    )
    args = parser.parse_args()

    return args.quantity


def main():
    count = parse_user_args()
    get_packets(count)


if __name__ == "__main__":
    main()
