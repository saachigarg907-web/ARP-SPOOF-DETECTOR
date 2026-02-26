from scapy.all import sniff,ARP
#import sniff=allows to capture packets
#import ARP= allows to recognise arp packets
from datetime import datetime
#used to add timestamps to alerts
arp_table={}#empty dictionary to store IP->MAC
#ACTS LIKE MEMORY FOR DETECTOR

def arp_packet(packet):#whenever any packet arrives snappy sends the packet to this function
    if packet.haslayer(ARP):#checks if the packet is arp..ignores all other packets
        ip=packet[ARP].psrc
        mac=packet[ARP].hwsrc
        time=datetime.now().strftime("%H:%M:%S")
    if ip in arp_table and arp_table[ip]!=mac:
        print("ARP SPOOFING DETECTED!!!")
        print("Time=",time)
        print("IP=",ip)
        print("Old Mac=",arp_table[ip])
        print("New mac=",mac)
    else:
        arp_table[ip]=mac#that means the ip is new and store it in the arp table
    

print("ARP sniffer started")
sniff(filter="arp",prn=arp_packet,store=False,count=5)
#this filter is to filter only arp packets
#prn is to send the packet input or to call the arp function whenever the packet is recieved
#store=false is for storing the value into the memory
#count =50 is to count or scan only 50 arp packets 
print("all the possible arp spoofing packets were mentioned above")
print("if none were then the network is free of ARP SPOOFING ATTACK!!")
