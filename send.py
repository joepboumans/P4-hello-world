#!/usr/bin/python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, randstring
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        print(i)
        if "eth0" in i:
            iface=i
            break
    if not iface:
        exit(1)
    return iface

def main():
    dst_addr = "10.0.0.1"
    src_addr = "10.0.0.2"
    iface = "veth6"

    print("sending on interface %s to %s" % (iface, str(src_addr)))
    pkt =  Ether(dst=get_if_hwaddr(iface), src='ff:ff:ff:ff:ff:ff', type=0x800)
    pkt1 = pkt /IP(dst=dst_addr, src=src_addr, tos=46, proto=17) / UDP(dport=1234, sport=random.randint(49152,65535)) / Raw(randstring(length=128)) # / sys.argv[2]
    pkt1.show2()
    sendp(pkt1, iface=iface, verbose=False)



if __name__ == "__main__":
    main()
