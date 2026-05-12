from user_input import get_fields
from sniffer import get_packets
from logger import write_data, read_data


def main():
    fields = get_fields()

    READ_FILE = fields[6]
    if READ_FILE:
        read_data(fields)
        return

    get_packets(fields)
    write_data()


if __name__ == "__main__":
    main()
