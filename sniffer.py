import socket, struct, os, array, time
from apscheduler.scheduler import Scheduler
from pymongo import MongoClient
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU

flow_to_byte = {}

class IPSniff:
 
    def __init__(self, interface_name, on_ip_incoming, on_ip_outgoing):
 
        self.interface_name = interface_name
        self.on_ip_incoming = on_ip_incoming
        self.on_ip_outgoing = on_ip_outgoing
        
        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))
 
    def __process_ipframe(self, pkt_type, ip_header, payload):
 
        # Extract the 20 bytes IP header, ignoring the IP options
        fields = struct.unpack("!BBHHHBBHII", ip_header)
 
        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]
 
        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:iplen]
 
        if pkt_type == socket.PACKET_OUTGOING:
            if self.on_ip_outgoing is not None:
                self.on_ip_outgoing(ip_src, ip_dst, ip_frame)
 
        else:
            if self.on_ip_incoming is not None:
                self.on_ip_incoming(ip_src, ip_dst, ip_frame)
 
    def recv(self):
        while True:
            pkt, sa_ll = self.ins.recvfrom(MTU)
 
            if type == socket.PACKET_OUTGOING and self.on_ip_outgoing is None:
                continue
            elif self.on_ip_outgoing is None:
                continue
 
            if len(pkt) <= 0:
                break
 
            eth_header = struct.unpack("!6s6sH", pkt[0:14])
 
            dummy_eth_protocol = socket.ntohs(eth_header[2])
 
            if eth_header[2] != 0x800 :
                continue
 
            ip_header = pkt[14:34]
            payload = pkt[14:]
 
            self.__process_ipframe(sa_ll[2], ip_header, payload)
 
#Example code to use IPSniff
def test_incoming_callback(src, dst, frame):
  #pass
    print("incoming - src=%s, dst=%s, frame len = %d"
        %(socket.inet_ntoa(src), socket.inet_ntoa(dst), len(frame)))
 
def test_outgoing_callback(src, dst, frame):
  #pass
    ip_src = socket.inet_ntoa(src)
    ip_dst = socket.inet_ntoa(dst)
    counter = len(frame)
    key = ip_src + '-' + ip_dst
    
    if key in flow_to_byte.keys():
        flow_to_byte[key] += counter
    else:
        flow_to_byte[key] = counter

    print("outgoing - src=%s, dst=%s, frame len = %d"
        %(ip_src, ip_dst, counter))

sched = Scheduler()

@sched.interval_schedule(seconds=1)
def insert_samples():
    s = time.strftime("%Y%m%d%H%M%S")
    client= MongoClient('localhost', 27017)
    db = client.samples
    allkeys = flow_to_byte.keys()

    for key in allkeys:
        ip_length = flow_to_byte[key]
        ipv4 = key.split('-')
        ip_src = ipv4[0]
        ip_dst = ipv4[1]
        db.sampleinfo.update_many({'ip_src':ip_src,'ip_dst':ip_dst}, {'$set': {'bytes':ip_length}}, True)
    
    print "insert into samples"

sched.start()

ip_sniff = IPSniff('eth1', test_incoming_callback, test_outgoing_callback)
ip_sniff.recv()  
