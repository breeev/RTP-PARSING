from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *
from scapy.all import RTP

pkts = sniff(offline="forensic.pcap")
pkts[5].show()

for pkt in pkts:
        if pkt[UDP].dport==5690 or pkt[UDP].dport==7078: # Make sure its actually RTP
            print("**************** RTP packet **************")
            pkt["UDP"].payload = RTP(pkt["Raw"].load)
        else:
            print("No RTP packet")
            print("no rtp")
for pkt in pkts[5]:
    IPsrc = pkt[IP].src
    IPdst = pkt[IP].dst

print(f"IP source : {IPsrc}\n")
print(f"IP dest : {IPdst}\n")
