from scapy.all import *

def proto(pkt):
	if TCP in pkt: return "TCP"
	elif UDP in pkt: return"UDP"
	elif ICMP in pkt: return "ICMP"
	else: return "Other"

def print_packet_info(frames):
	if IP not in frames:
		return
	print("SRC: " + frames[IP].src + " ->  DST: " + frames[IP].dst + " | " + proto(frames))

frames = sniff(prn = print_packet_info)