from sniffer import packets
from scapy.all import wrpcap


def write_data():
    wrpcap("capture.pcap", packets)
