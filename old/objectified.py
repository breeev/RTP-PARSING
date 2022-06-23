<<<<<<< HEAD
from pyshark import FileCapture
=======
from pyshark import LiveCapture, FileCapture
>>>>>>> a97e4c2dff8572e51fd718623fbf24256b537b8c
from console import getTerminalSize
from os import system
from re import search

# BLACK
# PRE-COMMIT
# https://pypi.org/project/g711/

<<<<<<< HEAD
clean=True # only leave the last merged wave file
=======
clean=False # only leave the last merged wave file
>>>>>>> a97e4c2dff8572e51fd718623fbf24256b537b8c

sizex = getTerminalSize()[0]
CID='undefined'
fs=8000
started=False
m = 4 # margin
PileAssignment={}

class Pile:
    def __init__(self,ip):
        self.list=[]
        self.t=None
        self.ip=ip
    def add(self,p):
        """:param p: packet object"""
        if not self.list:self.t=p.time
        self.list.insert(int((p.time-self.t)/160),p.data)
        return 1
    def write(self):
        with open(f'{self.ip}.g711u','wb') as f:
            for rtp in self.list:f.write(bytearray.fromhex(" ".join(rtp)))

class Packet:
    def __init__(self,p):
        global CID,fs
        self.sip=self.getsip(p)
        self.rtp=self.getrtp(p)
        self.ip=self.getip(p)
        # SIP info
        self.method=self.getmethod()
        self.desc=self.getdesc()
        self.isok=self.getisok()
        # see getdate()
        #self.date=self.getdate()
        # RTP info
        self.time=self.gettime()
        self.data=self.getdata()
        # GLOBALS
        if CID=='undefined':CID=self.getcid()
        if self.getfs():fs=self.getfs()
    def getsip(self,p):return None if not hasattr(p,'sip') else p.sip._all_fields
    def getrtp(self,p):return None if self.sip or not hasattr(p,'rtp') else p.rtp._all_fields
    def getip(self,p):return p['IP'].src
    def gettime(self):return None if not self.rtp else int(self.rtp['rtp.timestamp'])
<<<<<<< HEAD
    def getmethod(self):return None if self.rtp or (not 'sip.Method' in self.sip) else self.sip['sip.Method']
=======
    def getmethod(self):return None if self.rtp or (not self.sip) or (not 'sip.Method' in self.sip) else self.sip['sip.Method']
>>>>>>> a97e4c2dff8572e51fd718623fbf24256b537b8c
    def getdesc(self):
        if self.sip:
            a=list(self.sip.values())[0].replace('SIP/2.0 ','').replace('SIP/2.0','')
            return (' '*m+('{:->'+str(sizex-m*2)+'}' if a[0].isdigit() else '{}')+'\n').format(a)
        return ''
    def getisok(self):return None if (not self.sip) or self.method else self.sip['sip.Status-Code']=='200'
    # pyshark does not detect dates
    #def getdate(self):return None if not self.isok else self.sip['sip.Date']
    def getdata(self):return None if (not self.rtp) or (not 'rtp.payload' in self.rtp) else self.rtp['rtp.payload'].split(":")
    def getcid(self):return None if not self.sip else self.sip['sip.Call-ID']
<<<<<<< HEAD
    def getfs(self):return None if self.method!='INVITE' else search(r"telephone-event/([0-9])\w+",self.sip['sip.msg_hdr']).group().split('/')[-1]

def fill(pile):pile.list.append(b'')

capture=FileCapture(r"F:\blabla\forensic.pcap",display_filter='sip or rtp')
for packet in capture:
    p=Packet(packet)
    #print(vars(p))
    #print(p.desc,end='')
    if p.method=='INVITE':print(p.sip['sip.from.user']+' --> '+p.sip['sip.to.user'])
    if p.ip and p.data:
        if not p.ip in PileAssignment:PileAssignment[p.ip]=Pile(p.ip)
        if PileAssignment[p.ip].add(p) and not started:
            started=True
            #print(' '*m+('{:█^'+str(sizex-m*2)+'}').format(' CALL STARTED '))

from sys import platform
from os import remove,listdir
if platform=='win32':
    for ip in PileAssignment:PileAssignment[ip].write()
    from subprocess import call
    with open('temp.bat','w') as f:f.write('set PATH="C:\\Program Files (x86)\\sox-14-4-2"\nsox --type raw --rate 8000 -e u-law %1.g711u %1.wav\nsox --type raw --rate 8000 -e u-law %2.g711u %2.wav\nsox -M %1.wav %2.wav %3.wav')
    ips=list(ip for ip in PileAssignment)
    call(['temp.bat',ips[0],ips[1],CID])
    remove("temp.bat")
else:
    cmd='sox -'+('M' if len(PileAssignment)==2 else 'm')
    for ip in PileAssignment:
        PileAssignment[ip].write()
        system(f'sox --type raw --rate {fs} -e u-law {ip}.g711u {ip}.wav')
        cmd+=f' {ip}.wav'
    cmd+=f' {CID}.wav'
if clean:
    for item in listdir():
        if item.endswith(".g711u") or len(item.split('.'))==5:remove(item)
=======
    def getfs(self):return None if self.method!='INVITE' else search(r"telephone-event/([0-9])\w+",self.sip['sip.msg_hdr']).group().split('/')[1]

capture = LiveCapture(input("Nom de l'interface: "), bpf_filter='sip or rtp')
try:
    for packet in capture.sniff_continuously():
        p=Packet(packet)
        #print(vars(p))
        print(p.desc,end='')
        if p.ip and p.data:
            if not p.ip in PileAssignment:PileAssignment[p.ip]=Pile(p.ip)
            if PileAssignment[p.ip].add(p) and not started:
                started=True
                print(' '*m+('{:█^'+str(sizex-m*2)+'}').format(' CALL STARTED '))
except KeyboardInterrupt:
    # PileAssignment['blabla']=Pile('ip')
    # PileAssignment['blabla'].list=['ok']
    # print(all(list(a.list for a in PileAssignment.values())))
    # PileAssignment=False
    if PileAssignment and all(list(a.list for a in PileAssignment.values())):
        from sys import platform
        from os import remove,listdir
        if platform=='win32':
            for ip in PileAssignment:PileAssignment[ip].write()
            from subprocess import call
            with open('temp.bat','w') as f:f.write('set PATH="C:\\Program Files (x86)\\sox-14-4-2"\nsox --type raw --rate 8000 -e u-law %1.g711u %1.wav\nsox --type raw --rate 8000 -e u-law %2.g711u %2.wav\nsox -M %1.wav %2.wav %3.wav')
            ips=list(ip for ip in PileAssignment)
            call(['temp.bat',ips[0],ips[1],CID])
            remove("temp.bat")
        else:
            cmd='sox -'+('M' if len(PileAssignment)==2 else 'm')
            for ip in PileAssignment:
                PileAssignment[ip].write()
                system(f'sox --type raw --rate {fs} -e u-law {ip}.g711u {ip}.wav')
                cmd+=f' {ip}.wav'
            cmd+=f' {CID}.wav'
            system(cmd)
        if clean:
            for item in listdir():
                if item.endswith(".g711u") or len(item.split('.'))==5:remove(item)
>>>>>>> a97e4c2dff8572e51fd718623fbf24256b537b8c
