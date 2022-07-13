#!/usr/bin/env python3
import random
import socket
import sys, os, struct
import threading, time

from scapy.all import IP, TCP, UDP, Raw, Ether, get_if_hwaddr, get_if_list, sendp
from scapy.all import sniff, hexdump, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Field, ShortField, IntField, LongField, BitField, BitFieldLenField, FieldListField, FieldLenField, StrLenField, ByteEnumField
from scapy.layers.inet import _IPOption_HDR


TYPE_REQ = 0x1212
TYPE_REPLY = 0x1213
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
        print("Cannot find eth0 interface")
        exit(1)
    return iface

request_op_codes = {0:'NO_OP', 1:'PULL_BYTES', 3:'PULL_PACKETS'}

reply_codes = {0:'NO_REPLY', 1:'PULL_OK'}
'''
request_op_codes_vals = {}

for k in request_op_codes:
    request_op_codes_vals[request_op_codes[k]] = k

reply_codes_vals = {}

for k in reply_codes:
    reply_codes_vals[reply_codes[k]] = k    
'''
#Class.field.s2i['NO_OP'] -> 0
#Class.field.i2s[0] -> 'NO_OP'

class ControllerRequest(Packet):
	name = "controller_request"
	fields_desc = [
		ByteEnumField(name="op", default=0, enum=request_op_codes),
		BitField(name="idx", default=0, size=16),
		FieldListField(name="values", default=[0]*10, field=BitField(name="",default=0, size=48), count_from=lambda c:10)
	]

	def mysummary(self):
		return self.sprintf("op=%ControllerRequest.op.i2s[op]%, idx=%idx%, vals...")

class ControllerReply(Packet):
    name = "controller_reply"
    fields_desc = [
        ByteEnumField(name="op", default=0, enum=request_op_codes),
        BitField(name="idx", default=0, size=16),
        FieldListField(name="values", default=[0]*10, field=BitField(name="",default=0, size=48), count_from=lambda c:10),
        ByteEnumField(name="reply_code", default=0, enum=reply_codes)
    ]

    def mysummary(self):
        return self.sprintf("op=%ControllerReply.op.i2s[op]%, idx=%idx%, vals..., reply code=%ControllerReply.reply_code.i2s[reply_code]%")

bind_layers(Ether, ControllerRequest, type=TYPE_REQ)
bind_layers(Ether, ControllerReply, type=TYPE_REPLY)
#bind_layers(ControllerRequest, IP)

class ReplyThread (threading.Thread):
    def __init__(self, thread_id, iface):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.iface = iface

    def run(self):
        sniff_replies(iface=self.iface)


def sniff_replies(iface):
    sniff(lfilter = filter_reply, count=2, iface=iface,
          prn = lambda x: handle_pkt(x))
          #, stop_filter=filter_reply)

def handle_pkt(pkt):
    print("got a packet")
    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()

def filter_reply(pkt):
    if pkt[Ether].type == TYPE_REPLY:
        return True
    else:
        return False

def main():
    if len(sys.argv) < 2:
        print('pass the following argument: <idx>')
        print('Note: to pull the first 10 registers (ports 0..9), pass idx = 0, to pull ports 10..19 pass idx = 1, and so on.')
        exit(1)

    req_port = int(sys.argv[1])
    #addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    reply_thread = ReplyThread(thread_id=0, iface=iface)
    reply_thread.start()

    print("sending on interface %s to pull bytes from port %s" % (iface, str(req_port)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    #pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt = pkt / ControllerRequest(op=ControllerRequest.op.s2i['PULL_BYTES'], idx=req_port)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / ControllerRequest(op=ControllerRequest.op.s2i['PULL_PACKETS'], idx=req_port)
    sendp(pkt, iface=iface, verbose=False)
    

if __name__ == '__main__':
    main()
