from scapy.all import sniff
import time
import argparse


def create_summary(packet, fields=None):
    if fields is None:
        fields = ["IP.src", "IP.dst", "IP.proto"]
    # %'s make parsable by sprintf
    elements = "%" + "% - %".join([f for f in fields]) + "%"
    return packet[0].sprintf(elements)


def get_packets(count):
    print("start")
    current = sniff(prn=create_summary, count=1)
    duplicates = 0
    for _ in range(0, count):
        print("loop")
        previous = current
        current = sniff(prn=create_summary, count=1)
        # Eventually -> [x#] after summary
        if create_summary(current) == create_summary(previous):
            duplicates += 1
            print("Duplicate of srcIP, dstIP, IPproto: #" + str(duplicates))
        else:
            duplicates = 0
            previous = current
        time.sleep(0.2)


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
