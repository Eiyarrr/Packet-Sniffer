from user_input import get_fields
from sniffer import get_packets
from logger import write_data


def main():
    fields = get_fields()
    get_packets(fields)
    write_data()


if __name__ == "__main__":
    main()
