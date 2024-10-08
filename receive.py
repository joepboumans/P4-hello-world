#!/usr/bin/python3
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR

cpkt = 0

def handle_pkt(pkt):
    global counter1, counter2, cpkt
    # bind_layers( TCP, Stragflow, dport=1234 )
    cpkt += 1
    print("got a packet, num: {}".format(cpkt))
    

    
    pkt.show2()
    sys.stdout.flush()


def main():
    iface = 'veth6'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
