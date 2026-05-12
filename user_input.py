import argparse


# Also must make more options (presets?)
def parse_user_args():
    parser = argparse.ArgumentParser()
    parser.add_argument( # 0
        "quantity",
        nargs="?",
        help="The quantity of packets to give (default = 50)",
        type=int,
        default=50,
    )
    parser.add_argument( # 1
        "-p",
        "-print",
        help="Print output of sniffer to terminal",
        action="store_true",
    )
    parser.add_argument( # 2
        "-src",
        help="Include the source IP of the packet when printing summaries",
        action="store_true",
    )
    parser.add_argument( # 3
        "-dst",
        help="Include the destination IP of the packet when printing summaries",
        action="store_true",
    )
    parser.add_argument( # 4
        "-proto",
        help="Include the IP protocol of the packet when printing summaries",
        action="store_true",
    )
    parser.add_argument( # 5
        "-dns",
        help="parse IP addresses in printouts to domains",
        action="store_true",
    )
    parser.add_argument( # 6
        "-r",
        "-read",
        metavar="PCAP_FILE",
        help="Read from given pcap file",
    )


    return parser.parse_args()


def get_fields():
    args = parse_user_args()
    fields = []

    for a in vars(args).values():
        fields.append(a)

    return fields
