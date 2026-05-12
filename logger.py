from sniffer import packets
from scapy.all import wrpcap, rdpcap


def write_data():
    wrpcap("capture.pcap", packets)


def read_data(fields):
    FILE = fields[6]
    rdpcap(FILE)
