# tmap - Network Recon Tool 

# Author: Tyler Price

# Version 1.0

from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import threading
from Queue import Queue
import sys
from socket import gethostbyname

class Scanner(object):

	def __init__(self, dst_ip, src_port, dst_port):

		self.dst_ip = dst_ip
		self.src_port = src_port
		self.dst_port = dst_port

	def fin(self):

		'''TCP FIN Scan'''

		fin_scan_resp = sr1(IP(dst=self.dst_ip)/TCP(dport=self.dst_port,flags="F"),timeout=10, verbose= False)

		if (str(type(fin_scan_resp))== "<type 'NoneType'>"):
			print "PORT: %d Open|Filtered" % self.dst_port

		elif(fin_scan_resp.haslayer(TCP)):
			if(fin_scan_resp.getlayer(TCP).flags == 0x14):
				#print "PORT: %d Closed" % self.dst_port
				pass
		
		elif(fin_scan_resp.haslayer(ICMP)):
			if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "PORT: %d Filtered" % self.dst_port

	def null(self):

		'''TCP NULL Scan'''

		null_scan_resp = sr1(IP(dst=self.dst_ip)/TCP(dport=self.dst_port,flags=""),timeout=10, verbose=False)

		if (str(type(null_scan_resp))== "<type 'NoneType'>"):
			print "PORT: %d Open|Filtered" % self.dst_port

		elif(null_scan_resp.haslayer(TCP)):
			if(null_scan_resp.getlayer(TCP).flags == 0x14):
				#print "PORT: %d Closed" % self.dst_port
				pass

		elif(null_scan_resp.haslayer(ICMP)):
			if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "PORT: %d Filtered" % self.dst_port

	def tcp_ack(self):

		'''TCP ACK Scan'''

		ack_flag_scan_resp = sr1(IP(dst=self.dst_ip)/TCP(dport=self.dst_port,flags="A"),timeout=10, verbose=False)

		if (str(type(ack_flag_scan_resp))== "<type 'NoneType'>"):
			print "PORT: %d Stateful Firewall Present: (Filtered)" % self.dst_port

		elif(ack_flag_scan_resp.haslayer(TCP)):
			if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
				print "PORT: %d No Firewall: (Unfiltered)" % self.dst_port

		elif(ack_flag_scan_resp.haslayer(ICMP)):
			if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "PORT: %d Stateful Firewall Present: (Filtered)" % self.dst_port
		

	def tcp_connect(self):

		'''TCP Connect Scan'''

		tcp_connect_scan_resp = sr1(IP(dst=self.dst_ip)/TCP(sport=self.src_port,dport=self.dst_port,flags="S"),timeout=10, verbose=False)

		if(str(type(tcp_connect_scan_resp)) == "<type 'NoneType'>"):
			#print "PORT: %d Closed" % self.dst_port
			pass

		elif(tcp_connect_scan_resp.haslayer(TCP)):
			if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=self.dst_ip)/TCP(sport=self.src_port,dport=self.dst_port,flags="AR"),timeout=10, verbose=False)
				print "PORT: %d Open" % self.dst_port

			elif(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
				#print "PORT: %d Closed" % self.dst_port
				pass

	def tcp_stealth(self):

		'''TCP Stealth Scan'''

		stealth_scan_resp = sr1(IP(dst=self.dst_ip)/TCP(sport=self.src_port,dport=self.dst_port,flags="S"),timeout=10, verbose=False)

		if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
			print "PORT: %d Filtered" % self.dst_port

		elif(stealth_scan_resp.haslayer(TCP)):
			if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=self.dst_ip)/TCP(sport=self.src_port,dport=self.dst_port,flags="R"),timeout=10, verbose=False)
				print "PORT: %d Open" % self.dst_port

			elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
				#print "PORT: %d Closed" % self.dst_port
				pass

			elif(stealth_scan_resp.haslayer(ICMP)):
				if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					print "PORT: %d Filtered" % self.dst_port

	def tcp_window(self):

		'''TCP Window Scan'''

		window_scan_resp = sr1(IP(dst=self.dst_ip)/TCP(dport=self.dst_port,flags="A"),timeout=10, verbose=False)

		if (str(type(window_scan_resp)) == "<type 'NoneType'>"):
			print "PORT: %d No response" % self.dst_port

		elif(window_scan_resp.haslayer(TCP)):
			if(window_scan_resp.getlayer(TCP).window == 0):
				#print "PORT: %d Closed" % self.dst_port
				pass

			elif(window_scan_resp.getlayer(TCP).window > 0):
				print "PORT: %d Open" % self.dst_port

	def tcp_xmas(self):

		'''TCP XMAS Scan'''

		xmas_scan_resp = sr1(IP(dst=self.dst_ip)/TCP(dport=self.dst_port,flags="FPU"),timeout=10, verbose=False)

		if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
			print "PORT: %d Open|Filtered" % self.dst_port

		elif(xmas_scan_resp.haslayer(TCP)):
			if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
				#print "PORT: %d Closed" % self.dst_port
				pass

			elif(xmas_scan_resp.haslayer(ICMP)):
				if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					print "PORT: %d Filtered" % self.dst_port


'''Controls'''


def Start(ports):

	lock = threading.RLock()

	scan = Scanner(host, RandShort(), ports)

	try:

		with lock:

			if method == "FIN":

				scan.fin()

			elif method == "NULL":

				scan.null()

			elif method == "ACK":

				scan.ack()

			elif method == "CONNECT":

				scan.tcp_connect()

			elif method == "STEALTH":

				scan.tcp_stealth()

			elif method == "WINDOW":

				scan.tcp_window()

			elif method == "XMAS":

				scan.tcp_xmas()

			else:

				pass
			
	except:

		pass

def Worker():

	while True:

		ports = q.get()

		Start(ports)

		q.task_done()

print """

	Usage:     FIN = FIN Scan
		   NULL = NULL Scan
		   ACK = ACK Scan
		   CONNECT = Connect Scan
		   STEALTH = Stealth Scan
		   WINDOW = Window Scan
		   XMAS = XMAS Scan
	"""
host = raw_input("[+] Enter Host to Scan: ")

gethostbyname(host)

method = raw_input("[+] Enter Scanning Method: ")

threads = int(raw_input("[+] Enter Number of Threads: "))

port1 = int(raw_input("[+] Enter Starting Port Range (ex: 10): "))

port2 = int(raw_input("[+] Enter Ending Port Range (ex: 20): "))

print "[+] Scanning Host %s with %d Threads" % (host, threads)

print "[+] Using %s Method" % method

q = Queue()

for x in range(threads + 1):

	t = threading.Thread(target=Worker, args=())
	t.daemon = True
	t.start()

for ports in range(port1, port2 + 1):

	q.put(ports)

q.join()

print "[+] Scan Complete!"


#Methods

#scan.fin()
#scan.null()
#scan.tcp_ack()
#scan.tcp_connect()
#scan.tcp_stealth()
#scan.tcp_window()
#scan.tcp_xmas()