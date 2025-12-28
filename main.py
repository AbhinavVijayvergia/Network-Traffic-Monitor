from scapy.all import *

def print_packet_info(pkt):
	if IP not in pkt:
		return

	if TCP in pkt:
		print(f"SRC: {pkt[IP].src}:{pkt[TCP].sport} ->  DST: {pkt[IP].dst}:{pkt[TCP].dport} | TCP ")
	elif UDP in pkt:
		print(f"SRC: {pkt[IP].src}:{pkt[UDP].sport} ->  DST: {pkt[IP].dst}:{pkt[UDP].dport} | UDP ")
	elif ICMP in pkt:
		print(f"SRC: {pkt[IP].src} ->  DST: {pkt[IP].dst} | ICMP ")
	else:
		print(f"SRC: {pkt[IP].src} ->  DST: {pkt[IP].dst} | Other ")
	

frames = sniff(prn = print_packet_info, timeout=10)