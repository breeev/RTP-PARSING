from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

pkts = sniff(offline="forensic.pcap")
pkts[0].show()

for pkt in pkts:
    IPdst = pkt[IP].src
    IPsrc = pkt[IP].dst

for pkt in pkts[0]:
    udp_sport = pkt[UDP].sport
    udp_dport = pkt[UDP].dport

print(f"IP source : {IPsrc}")
print(f"IP destination : {IPdst}")
print(f"Port source SIP: {udp_sport}")
print(f"Port destination SIP: {udp_dport}")