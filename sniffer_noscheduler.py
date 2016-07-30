import pcap as pcap
import time
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP
from pymongo import MongoClient

dev = "eth1"
decoder = EthDecoder()	
def read_packet(db, hdr, data):
	ether = decoder.decode(data)
	if ether.get_ether_type() == IP.ethertype:
		counter = hdr['len']

		iphdr = ether.child()
		tcphdr = iphdr.child()

		ip_src = iphdr.get_ip_src()
		ip_dst = iphdr.get_ip_dst()

		db.sampleinfo.update_one({'ip_src':ip_src,'ip_dst':ip_dst}, {'$inc': {'bytes':counter,'packets':1}}, True)

		print ip_src + "->" + ip_dst + " length: " + str(counter)

def run_sniffer():
	try: 
		pc = pcap.pcap(dev, 1500, 0, 100)
		pc.setdirection(pcap.PCAP_D_OUT)
		#pc.setnonblock(True)
		db = client.samples
		pc.loop(0, read_packet,db)
	except KeyboardInterrupt:
		pc.breakloop()

try:
	client = MongoClient('localhost', 27017)
	client.drop_database("samples")
	print "connection success"
except:
	print "connection fails"

run_sniffer()