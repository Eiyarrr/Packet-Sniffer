from scapy.all import sniff
import time

def foo(packet):
    print(packet.summary())

while True:
    sniff(prn=foo, count = 1)
    time.sleep(0.2)
