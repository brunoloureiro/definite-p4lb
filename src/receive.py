#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    IP,
    TCP,
    Ether,
    get_if_hwaddr,
    get_if_addr,
    get_if_list
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    print("got a packet")
    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()
    #print("IP in packet:" + str(IP in pkt))
    #print("Src IP from packet: {}\nIP from hwaddr(iface): {}".format(pkt[IP].src, get_if_addr(iface)))


def filter_sent_pkts(pkt):
    if IP in pkt and pkt[IP].src == get_if_addr(iface):
        return False
    else:
        return True

ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
iface = ifaces[0]

def main():    
    
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(lfilter=filter_sent_pkts, iface = iface,
          prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
