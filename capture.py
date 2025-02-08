import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="Network Sniffing")

    parser.add_argument('-i', '--interface', default='eth0')
    parser.add_argument('-r', '--read')
    parser.add_argument('expression', nargs='?')

    args = parser.parse_args()

    print(args.interface)
    print(args.read)
    print(args.expression)

parse_args()