from scapy.all import *
from datetime import datetime

from collections import defaultdict
import time

ip_count = {}

WINDOW_SIZE = 10 
THRESHOLD = 80 
alerted_ips = set()  

ip_timestamps = defaultdict(list)


def combined_callback(pkt):
	if IP not in pkt:
		return
	print_packet_info(pkt)
	packet_callback(pkt)




def protocol(pkt):
	if IP not in pkt:
		return "NON-IP"

	if TCP in pkt:
		return "TCP"
	elif UDP in pkt:
		return "UDP"
	elif ICMP in pkt:
		return "ICMP"
	else:
		return "Other"


def packet_callback(pkt):
	if IP not in pkt:
    	return


	time_stamp= datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	proto = protocol(pkt)

	sport = dport = '-'
	if TCP in pkt:
		sport = pkt[TCP].sport
		dport = pkt[TCP].dport
	elif UDP in pkt:
		sport = pkt[UDP].sport
		dport = pkt[UDP].dport

	log = f"{time_stamp} | {pkt[IP].src} | {pkt[IP].dst} | {proto} | {sport} | {dport}"
	with open("logs/traffic_log.log", "a") as f:
		f.write(log + "\n")

def detect_anomaly(src_ip):
	current_time = time.time()
	ip_timestamps[src_ip].append(current_time)

	ip_timestamps[src_ip] = [
	    t for t in ip_timestamps[src_ip]
	    if current_time - t <= WINDOW_SIZE
	]

	if len(ip_timestamps[src_ip]) > THRESHOLD and src_ip not in alerted_ips:
	    print(f"[ALERT] High traffic rate from {src_ip} "
	          f"({len(ip_timestamps[src_ip])} packets in {WINDOW_SIZE}s)")
	    alerted_ips.add(src_ip)


def print_packet_info(pkt):

	proto = protocol(pkt)

	src_ip = pkt[IP].src

	detect_anomaly(src_ip)

	if src_ip in ip_count:
		ip_count[src_ip] += 1
	else:
		ip_count[src_ip] = 1

	if TCP in pkt:
		print(f"SRC: {pkt[IP].src}:{pkt[TCP].sport} ->  DST: {pkt[IP].dst}:{pkt[TCP].dport} | {proto} ")
	elif UDP in pkt:
		print(f"SRC: {pkt[IP].src}:{pkt[UDP].sport} ->  DST: {pkt[IP].dst}:{pkt[UDP].dport} | {proto} ")
	elif ICMP in pkt:
		print(f"SRC: {pkt[IP].src} ->  DST: {pkt[IP].dst} | {proto} ")
	else:
		print(f"SRC: {pkt[IP].src} ->  DST: {pkt[IP].dst} | {proto} ")
	

frames = sniff(prn = combined_callback, timeout=60)

print("\n Traffic Summary:")
for ip,count in ip_count.items():
	print(f"{ip} -> {count} packets")