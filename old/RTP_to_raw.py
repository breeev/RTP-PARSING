import pyshark

rtp_list = []
cap = pyshark.FileCapture('forensic.pcap', display_filter='rtp and ip.src==172.25.105.40')
raw_audio = open('my_audio2.g711u','wb')
for i in cap:
    try:
        rtp = i[3]
        if rtp.payload:
            #  print(rtp.payload)
             rtp_list.append(rtp.payload.split(":"))
    except:
        pass

for rtp_packet in rtp_list:
    packet = " ".join(rtp_packet)
    # print(packet)
    audio = bytes.fromhex(packet)
    print(audio)
    raw_audio.write(audio)