#!/usr/bin/env python3
import random
import socket
import sys, os, struct

from scapy.all import IP, TCP, UDP, Raw, Ether, get_if_hwaddr, get_if_list, sendp
from scapy.all import sniff, hexdump, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Field, ShortField, IntField, LongField, BitField, BitFieldLenField, FieldListField, FieldLenField, StrLenField, ByteEnumField
from scapy.layers.inet import _IPOption_HDR


TYPE_REQ = 0x1212
TYPE_IPV4 = 0x0800

def str2hex(s):
    return ''.join('%02x' % ord(b) for b in s)

def str2hex_spaced(s):
    return ' '.join('%02x' % ord(b) for b in s)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

request_op_codes = {0:'NO_OP', 1:'PULL_BYTES', 3:'PULL_PACKETS'}

#Class.field.s2i['NO_OP'] -> 0
#Class.field.i2s[0] -> 'NO_OP'

class ControllerRequest(Packet):
	name = "controller_request"
	fields_desc = [
		ByteEnumField(name="op", enum=request_op_codes),
		BitField(name="idx", size=16),
		FieldListField(name="values", length_from=48, count_from=10)
	]

	def mysummary(self):
		return self.sprintf("op=%ControllerRequest.i2s[op]%, idx=%idx%, vals...")

bind_layers(Ether, ControllerRequest, type=TYPE_REQ)
#bind_layers(ControllerRequest, IP)


def main():

    if len(sys.argv) < 2:
        print 'pass the following argument: <port_number>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
