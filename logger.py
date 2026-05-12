from sniffer import packets
from scapy.all import wrpcap


def write_data():
    data = []
    for p in packets:
        data.append(p)
    
    wrpcap("capture.pcap", data)
