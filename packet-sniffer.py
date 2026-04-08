from scapy.all import sniff
import time
import sys

def print_packet(packet):
    return packet.summary()

def packet_loop(user_range):
    print("start")
    prev = 0
    for _ in range(1, user_range):
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

    user_range = sys.argv[1]
    try:
        user_range = int(user_range)
    except ValueError:
        print("Range must be an integer")
        sys.exit(-1)

    if user_range <= 0:
        print("Range must be > 0")
        sys.exit(-1)
    return user_range

def main():
    user_range = parse_argv()
    packet_loop(user_range)

if __name__ == "__main__":
    main()
