from sniffer import packets, process_packet
from scapy.all import wrpcap, rdpcap


def write_pcap():
    wrpcap("capture.pcap", packets)


def read_pcap(fields):
    FILE = fields[6]
    read_packets = rdpcap(FILE)
    for p in read_packets:
        process_packet(p, fields)
