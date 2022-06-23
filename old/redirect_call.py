from random import randrange
from scapy.all import *
from scapy.layers.inet import *


new_sip ="1101"
new_ip = "192.168.66.66"

caller_ip = "192.168.77.77"
caller_sip = "1102"
call_id = "34ui3H5I3UOIiOP3ioH3ipH3"
fs = 8000

dstIP = "192.68.1.125"

forged_packet =(
    f'INVITE sip:{new_sip}@{new_ip};user=phone;uniq=E04784589605A88765A939C2CA2A7 SIP/2.0\r\n'
    'Max-Forwards: 59\r\n'
    f'Via: SIP/2.0/UDP {caller_ip}:5060;branch=z9hG4bKg3Zqkv7i1tg6jule4zo2e7ndqkj1zfut6\r\n'
    f'To: "{new_sip}" <sip:{new_sip}@telekom.de;transport=udp;user=phone>\r\n'
    f'From: <sip:{caller_sip}@dtag-gn.de;transport=udp;user=phone>;tag=h7g4Esbg_p65557t1573829978m943109c168405915s1_3637842016-655695229\r\n'
    f'Call-ID: {call_id}\r\n'
    'CSeq: 1 INVITE\r\n'
    f'Contact: <sip:sgc_c@{caller_ip};transport=udp>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"\r\n'

    f'a=rtpmap:101 telephone-event/{fs}\r\n'
).format(dstIP)

non_needed_fieds=(

    f'Record-Route: <sip:{caller_ip};transport=udp;lr>'
    'Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"'
    'Min-Se: 900'
    f'P-Asserted-Identity: <sip:{caller_sip}@dtag-gn.de;transport=udp;user=phone>'
    'Session-Expires: 1800'
    'Supported: timer'
    'Supported: 100rel'
    'Supported: histinfo'
    'Supported: 199'
    'Content-Type: application/sdp'
    'Content-Length: 294'
    'Session-ID: e51df1bba3dd5608c44474e798aeeeae'
    'Allow: REGISTER, REFER, NOTIFY, SUBSCRIBE, INFO, PRACK, UPDATE, INVITE, ACK, OPTIONS, CANCEL, BYE'

    'v=0'
    f'o=- 1167338284 3637841791 IN IP4 {caller_ip}'
    's=SBC call'
    'c=IN IP4 217.0.5.215'
    't=0 0'
    'm=audio 5690 RTP/AVP 8 101 0 18 4 109'
    'a=rtpmap:8 PCMA/8000'
    'a=rtpmap:0 PCMU/8000'
    'a=rtpmap:18 G729/8000'
    'a=rtpmap:4 G723/8000'
    'a=rtpmap:109 G726-16/8000'
    'a=ptime:20'
)

ip = IP(src="192.168.1.125",dst="192.168.1.125")

udp = UDP(sport = randrange(80,65535),dport=6789)

send(ip/udp/forged_packet)