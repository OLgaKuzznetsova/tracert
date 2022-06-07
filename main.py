from tracert import Tracert

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Route output (traceroute) and numbers of '
                                                 'autonomous systems of intermediate nodes')
    parser.add_argument("-a", "--address", type=str, required=True, help="IP address (or DNS name)")
    try:
        args = parser.parse_args()
        ip = args.address
        Tracert(ip)
    except:
        parser.print_help()
        exit(0)
