from netifaces import interfaces
from pyshark import LiveCapture
from console import getTerminalSize
from os import system
from re import search
from datetime import datetime
from threading import Thread,Event
from queue import SimpleQueue
from g711 import decode_ulaw
from pygame import *

# BLACK
# PRE-COMMIT
# https://pypi.org/project/g711/

sizex = getTerminalSize()[0]
CID='undefined'
started=False
m = 4 # margin
PileAssignment={}
SIP1=0
SIP2=0

def worker(i):
    while 1:
        release.wait(5)
        ips=list(b for b in PileAssignment)
        if i<len(ips):
            rtp=PileAssignment[ips[i]].get()
            rtp=decode_ulaw(bytearray.fromhex(" ".join(rtp)))
            sound=mixer.Sound(rtp)
            sound.play(0)


class Packet:
    def __init__(self,p):
        global CID,fs,SIP1,SIP2
        self.sip=None if not hasattr(p,'sip') else p.sip._all_fields
        self.rtp=None if self.sip or not hasattr(p,'rtp') else p.rtp._all_fields
        self.ip=p['IP'].dst
        del p
        # SIP info
        self.method=None if self.rtp or (not self.sip) or (not 'sip.Method' in self.sip) else self.sip['sip.Method']
        a=None if not self.sip else list(self.sip.values())[0].replace('SIP/2.0 ','')
        self.desc='' if not self.sip else (' '*m+('{:->'+str(sizex-m*2)+'}' if a[0].isdigit() else '{}')+'\n').format(a)
        del a
        self.isok=None if (not self.sip) or self.method else self.sip['sip.Status-Code']=='200'
        # RTP info
        self.data=None if not (self.rtp and 'rtp.payload' in self.rtp) else self.rtp['rtp.payload'].split(":")
        # GLOBALS
        if CID=='undefined':CID=None if not self.sip else self.sip['sip.Call-ID']
        if not SIP1:SIP1=None if self.method!='INVITE' else self.sip['sip.from.user']
        if not SIP2:SIP2=None if not SIP1 else self.sip['sip.to.user']

print('''
Created by Breee and Spectra
21/06/2022

  ██████  ██▓███ ▓██   ██▓    ▄████▄   ▄▄▄       ██▓     ██▓    (live📢)
▒██    ▒ ▓██░  ██▒▒██  ██▒   ▒██▀ ▀█  ▒████▄    ▓██▒    ▓██▒    
░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░   ▒▓█    ▄ ▒██  ▀█▄  ▒██░    ▒██░    
  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░   ▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██░    ▒██░    
▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░   ▒ ▓███▀ ░ ▓█   ▓██▒░██████▒░██████▒
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒    ░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░
░ ░▒  ░ ░░▒ ░     ▓██ ░▒░      ░  ▒     ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░
░  ░  ░  ░░       ▒ ▒ ░░     ░          ░   ▒     ░ ░     ░ ░   
      ░           ░ ░        ░ ░            ░  ░    ░  ░    ░  ░
                  ░ ░        ░                                  
'''
)
print(interfaces())
from sys import argv
iface=(' '.join(argv[1:]))
if not iface:iface=input('Input your interface name: ')
if not iface:exit('No iface selected.')
mixer.init(size=32)
format='%d/%m/%Y %H:%M:%S'
release=Event()
w1=Thread(target=worker,args=[0]).start()
w2=Thread(target=worker,args=[1]).start()
capture = LiveCapture(interface=iface, display_filter='sip or rtp')
print("[+] Démarrage du sniffing...")
# print(capture.set_debug())
start=datetime.now().strftime(format)
for packet in capture.sniff_continuously():
    p=Packet(packet)
    print(p.desc,end='')
    if p.ip and p.data:
        release.set()
        release.clear()
        if not p.ip in PileAssignment:PileAssignment[p.ip]=SimpleQueue()
        PileAssignment[p.ip].put(p.data)
        if not started:
            started=True
            print(' '*m+('{:█^'+str(sizex-m*2)+'}').format(' CALL STARTED '))
    if p.method=='BYE':break
end=datetime.now().strftime(format)
with open('infos_call.txt', 'w') as f:f.write("{} --> {}\nDate de début : {: >}\nDate de fin :   {: >}\nCall ID :       {}".format(SIP1,SIP2,start,end,CID))