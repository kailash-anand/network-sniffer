import argparse
from src.sniffer import start_sniff

interface = None
read = None
expression = None

def parse_args() -> None:
    parser = argparse.ArgumentParser(description="Network Sniffing")

    parser.add_argument('-i', '--interface', default='eth0')
    parser.add_argument('-r', '--read')
    parser.add_argument('expression', nargs='?')

    args = parser.parse_args()

    global interface
    global read
    global expression

    interface = args.interface
    read = args.read
    expression = args.expression

parse_args()
start_sniff(interface, read, expression)
