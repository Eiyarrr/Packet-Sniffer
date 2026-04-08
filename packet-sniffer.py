from scapy.all import sniff
import time
import sys

# Stops the packet from returning "{PACKET}\nNone" when called with summary()
def print_packet(packet):
    return packet.summary()

def get_packets(count):
    print("start")
    current = sniff(prn=print_packet, count = 1)
    duplicates = 0
    for _ in range(0, count):
        print("loop")
        previous = current
        current = sniff(prn=print_packet, count = 1)
        if (current[0].sprintf("%IP.src% %IP.dst% %IP.proto%") == 
        previous[0].sprintf("%IP.src% %IP.dst% %IP.proto%")): # -> "[x#]" at the end of packet summaries
            duplicates += 1
            print("Duplicate of srcIP, dstIP, IPproto" + str(duplicates))
        else:
            duplicates = 0
            previous = current
        time.sleep(0.2)

def parse_user_args():
    if len(sys.argv) != 2:
        print("Invalid number of arguments")
        sys.exit(-1)

    count = sys.argv[1]
    try:
        count = int(count)
    except ValueError:
        print("Range must be an integer")
        sys.exit(-1)

    if count <= 0:
        print("Range must be > 0")
        sys.exit(-1)
    return count

def main():
    count = parse_user_args()
    get_packets(count)

if __name__ == "__main__":
    main()
