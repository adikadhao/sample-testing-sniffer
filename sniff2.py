#summary to show ip address
from scapy.all import *

def sniffer(pkt):
	#print(pkt.summary())   #summary()/show()FOR DISPLAYING ALL PACKETS IN YOUR NETWORK
	print("Source IP:%s -------- Dest IP:%s"%(pkt[IP].src,pkt[IP].dst))#TO DISPLAY IP ADDRESS OF SOURCE AND DESTINATION 
	
sniff(filter='tcp', count=10, prn=sniffer)
