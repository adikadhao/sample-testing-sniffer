#import scapy
'''
1st sniff basics
from scapy.all import *
pkts=sniff(filter ='ip',count=10)
for i in range (10):
	pkts[i].show()
'''

#2nd prg funct()

from scapy.all import *

def sniffing(pkts):
	#pkts.show()
	
	#print ("Sorce : %s  <-----> Dest: %s"%(pkts[IP].src,pkts[IP].dst)) PRINT IP SRC DST
	#	print ("Sorce : %  <--HTTP--> Dest:%s"%(pkts[Ether].src,pkts[Ether].dst))) mac address
	
	print ("Sorce : {}   <--HTTP--> Dest: {} Dest port: {} \n payload : {}  %s".format(pkts[IP].src,pkts[IP].dst,pkt[TCP].dport,pkts[TCP].payload)) 
	
# sniff(filter='ip',prn=sniffing) IP FILTER

sniff(filter='cp port 80',prn=sniffing) #from port 80
