from scapy.all import *

# fichier = rdpcap("interception.pcapng")

# def infos_sip(fichier):

#     for pkt in fichier:
#         packet_strs = pkt["Raw"].load.decode("latin1")  

#         if "INVITE sip" in packet_strs:
#             invite = packet_strs.split()[0]
#             invite = invite + " " + packet_strs.split()[1]
#             print(invite, "\n")

#         elif "100 Trying" in packet_strs:
#             trying = packet_strs[0:20]
#             print(trying, "\n")

#         elif "180 Ringing" in packet_strs:
#             ringing = packet_strs[0:19]
#             print(ringing, "\n")

#         elif "200 OK" in packet_strs:
#             ok = packet_strs[0:14]
#             print(ok, "\n")

#         if "BYE sip" in packet_strs:
#             bye = packet_strs.split()[0]
#             bye = bye + " " + packet_strs.split()[1]
#             print(bye, "\n")

# infos_sip(fichier)

pkts = sniff(offline="forensic.pcap")
pkts[1301].show()

for pkt in pkts:
    packet_strs = pkt["Raw"].load.decode("latin1")
        if "INVITE" in pkt: