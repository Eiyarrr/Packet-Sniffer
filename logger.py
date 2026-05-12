from sniffer import seen
from scapy.all import wrpcap


def write_data():
    data = []
    for s in seen:
        data.append((seen[s]["packet"], seen[s]["count"]))
    
    wrpcap("capture.pcap", data)
