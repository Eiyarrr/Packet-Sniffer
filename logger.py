from sniffer import seen
import json

def write_data():
    data = []
    for s in seen:
        data.append((seen[s]["packet"], seen[s]["count"]))

    file = open("packets.json", "w")
    json.dump(data, file, indent=4)
