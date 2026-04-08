from scapy.all import sniff
import time

def print_packet(packet):
    return packet.summary()

print("start")
prev = 0
for _ in range(0, 10):
    print("loop")
    capture = sniff(prn=print_packet, count = 1)
    if capture == prev: # -> "[x#]" at the end of packet summaries
        print(1)
    prev = capture
    time.sleep(0.1)
