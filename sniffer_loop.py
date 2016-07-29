import time
import pcapy
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP
from apscheduler.scheduler import Scheduler
from pymongo import MongoClient

dev = "eth1"
decoder = EthDecoder()

flow_to_byte = {}
flow_to_pkt = {}
	
def read_packet(hdr, data):
	ether = decoder.decode(data)
	if ether.get_ether_type() == IP.ethertype:
		counter = hdr.getlen()
		iphdr = ether.child()
		tcphdr = iphdr.child()
		ip_src = iphdr.get_ip_src()
		ip_dst = iphdr.get_ip_dst()

		key = ip_src + '-' + ip_dst
		if key in flow_to_byte.keys():
			flow_to_byte[key] += counter
			flow_to_pkt[key] += 1
		else:
			flow_to_byte[key] = counter
			flow_to_pkt[key] = 1

		print ip_src + "->" + ip_dst + " length: " + str(counter)
		

sched = Scheduler()

@sched.interval_schedule(seconds=1)
def insert_samples():
    s = time.strftime("%Y%m%d%H%M%S")
    client = MongoClient('localhost', 27017)
    db = client.samples
    allkeys = flow_to_byte.keys()

    for key in allkeys:
        ip_length = flow_to_byte[key]
        pkt_counter = flow_to_pkt[key]
        ipv4 = key.split('-')
        ip_src = ipv4[0]
        ip_dst = ipv4[1]
        db.sampleinfo.update_many({'ip_src':ip_src,'ip_dst':ip_dst}, {'$set': {'bytes':ip_length,'packets':pkt_counter}}, True)
    
    print "insert into samples"

sched.start()


pcap = pcapy.open_live(dev, 1500,0,100)
pcap.loop(0, read_packet)