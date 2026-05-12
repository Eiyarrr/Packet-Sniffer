from sniffer import packets, process_packet
from scapy.all import wrpcap, rdpcap


def write_data():
    wrpcap("capture.pcap", packets)


def read_data(fields):
    FILE = fields[6]
    read_packets = rdpcap(FILE)
    for packet in read_packets:
        process_packet(packet, fields)
