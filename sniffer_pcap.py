import pcap as pcap
import logging
import datetime, time
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.jobstores.mongodb import MongoDBJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
#from apscheduler.scheduler import Scheduler
from pymongo import MongoClient

logging.basicConfig()

dev = "eth1"
decoder = EthDecoder()

flow_to_byte = {}
flow_to_pkt = {}
	
def read_packet(sh, hdr, data):
	ether = decoder.decode(data)
	if ether.get_ether_type() == IP.ethertype:
		counter = hdr['len']
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

def run_sniffer():
	try: 
		pc = pcap.pcap(dev, 1500, 0, 100)
		pc.setdirection(pcap.PCAP_D_OUT)
		pc.setnonblock(True)
		#cnt = 999999 pcap.PCAP_D_OUT pcap.PCAP_D_INOUT pcap.PCAP_D_IN
		pc.loop(0, read_packet)
	except KeyboardInterrupt:
		pc.breakloop()

#sched = Scheduler()
#scheduler = BackgroundScheduler()

#@sched.interval_schedule(seconds=1)
def insert_samples():
    s = time.strftime("%Y%m%d%H%M%S")
    db = client.samples
    allkeys = flow_to_byte.keys()
    for key in allkeys:
        ip_length = flow_to_byte[key]
        pkt_counter = flow_to_pkt[key]
        ipv4 = key.split('-')
        ip_src = ipv4[0]
        ip_dst = ipv4[1]
        db.sampleinfo.update_many({'ip_src':ip_src,'ip_dst':ip_dst}, {'$set': {'bytes':ip_length,'packets':pkt_counter}}, True)
    	#,'Date':s
    print "insert into samples"

def start_scheduler():
	executors = {'main_jobstore': ThreadPoolExecutor(5),}
	job_defaults = {'coalesce': True, 'max_instances': 10,}
	jobstores = {'main_jobstore': MemoryJobStore()}
	#jobstores = {'mongo': MongoDBJobStore(),}
	sched = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults)
	startTime = datetime.datetime.now() + datetime.timedelta(seconds=3)
	sched.add_job(insert_samples,
				trigger            = 'interval',
				seconds            = 1,
				start_date         = startTime,
				id                 = 0,
				max_instances      = 10,
				replace_existing   = True,
				jobstore           = "main_jobstore",
				misfire_grace_time = 100)
	try:
		sched.start()
	except (KeyboardInterrupt, SystemExit):
		sched.shutdown()	

#sched.start()
try:
	client = MongoClient('localhost', 27017)
	print "connection success"
except:
	print "connection fails"

start_scheduler()
run_sniffer()