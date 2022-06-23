from email.mime import base
from posixpath import basename
import re

header='Via: SIP/2.0/UDP 172.25.105.3:43204;branch=z9hG4bK-d8754z-188e560b22cd118b-1---d8754z-;rport  Max-Forwards: 70  Contact: <sip:555@172.25.105.3:43204>  To: <sip:1000@172.25.105.40>  From: <sip:555@172.25.105.40>;tag=a6a39689  Call-ID: MzI4NzE5ZDVmNDk0OTBkN2M2MzVhNDI3NTkxZDgzN2M.  CSeq: 2 INVITE  Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO  Content-Type: application/sdp  User-Agent: X-Lite Beta release 4.0 Beta 2 stamp 56233  Authorization: Digest username="555",realm="asterisk",nonce="70fbfdae",uri="sip:1000@172.25.105.40",response="aa533f6efa2b2abac675c1ee6cbde327",algorithm=MD5  Content-Length: 264    v=0  o=- 9 2 IN IP4 172.25.105.3  s=CounterPath X-Lite 4.0  c=IN IP4 172.25.105.3  t=0 0  m=audio 63184 RTP/AVP 107 0 8 101  a=sendrecv  a=rtpmap:107 BV32/16000  a=rtpmap:101 telephone-event/8000  a=fmtp:101 0-15  a=alt:1 1 : wV0EQB9i 7LGM6I+1 172.25.105.3 63184  '
res = re.sub(".*/", "", header).split()[0]

print(res)
print(type(res))