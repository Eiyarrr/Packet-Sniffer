import argparse


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

    return parser.parse_args()


def get_fields():
    args = parse_user_args()
    fields = [args.quantity]

    if args.src:
        fields.append("IP.src")
    if args.dst:
        fields.append("IP.src")
    if args.proto:
        fields.append("IP.src")

    return fields
