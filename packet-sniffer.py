from scapy.all import sniff
import time
import sys

def print_packet(packet):
    return packet.summary()

def packet_loop(range):
    print("start")
    prev = 0
    for _ in range(1, range):
        print("loop")
        capture = sniff(prn=print_packet, count = 1)
        if capture == prev: # -> "[x#]" at the end of packet summaries
            print(1)
        prev = capture
        time.sleep(0.1)

def parse_argv():
    if len(sys.argv) != 2:
        print("Invalid number of arguments")
        sys.exit(-1)

    range = sys.argv[1]
    try:
        range = int(range)
    except ValueError:
        print("Range must be an integer")

    if int(range) <= 0:
        print("Range must be > 0")
        sys.exit(-1)
    return range

def main():
    range = parse_argv()
    packet_loop(range)

if __name__ == "__main__":
    main()
