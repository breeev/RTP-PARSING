print('''
Created by Breee and Spectra
21/06/2022

  ██████  ██▓███ ▓██   ██▓    ▄████▄   ▄▄▄       ██▓     ██▓    
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
from netifaces import interfaces
from pyshark import LiveCapture
from console import getTerminalSize
from os import system
from re import search
from datetime import datetime

# some left over to-dos
# BLACK
# PRE-COMMIT
# https://pypi.org/project/g711/

# SETTINGS
clean=True # only leave the last merged wave file

sizex = getTerminalSize()[0] # this function is from a script found on StackOverflow. Very obvious purpose.
CID='undefined' # Call ID set to a default value safe for prints and file placeholder
fs=8000 # Sample Frequency, default value (for G711μ)
started=False # global bool to print "call started" for the first RTP packet found
m = 4 # margin (for cool formatted prints)
PileAssignment={} # dic to keep a Pile object for each IP found
SIP1=0 # caller SIP number
SIP2=0 # called SIP number

# the next class is an intelligent container for a specific IP adress.
class Pile:
    def __init__(self,ip):
        self.list=[] # RTP data in hex format (lists of hex values) is stored there
        self.t=None # the first timestamp found in an RTP packet for this ip, will be used to find the index of the list to insert the RTP data at
        self.ip=ip # stores the IP associated with the Pile
    def add(self,p): # add an RTP data list (p) to the Pile list at the right index
        """:param p: packet object""" # that's very nice
        if not self.list:self.t=p.time # if that's the first element in the list, then take its timestamp
        self.list.insert(int((p.time-self.t)/160),p.data) # insert the data at the index found from the first timestamp. Timestamps get incremented by 160 for each packet.
        return 1 # in case I want to use it in an if to save space (we do a little bit of golfing)
    def write(self): # write all the data in the Pile to a raw file
        with open(f'{self.ip}.g711u','wb') as f: # with statements closes the file after use (golfing again)
            for rtp in self.list:f.write(bytearray.fromhex(" ".join(rtp))) # as weird as it sounds, the file doesn't get overwritten even if it's not in append mode.
            # write bytes from hex data stored in a list

# now this class is used to get a dictionnary and basic info from the original pyshark object and then close its mouth with a del! Take this!
# why? pyshark is cool (and works whereas scapy doesn't on my setup) but some attributes aren't callable.
# In short, it appears as some aren't hard-coded and you have to get them manually from the private dictionnary anyway.
# This object makes things more simple (and attributes shorter) and can help for a port / conversion from pyshark to scapy. It's also a good way to clean ifs in the main loop.
# But enough talk.
class Packet:
    def __init__(self,p): # takes a pyshark packet
        global CID,fs,SIP1,SIP2
        # hasattr = has attribute
        # _all_fields is a pyshark private dictionnary
        self.sip=None if not hasattr(p,'sip') else p.sip._all_fields
        self.rtp=None if self.sip or not hasattr(p,'rtp') else p.rtp._all_fields
        self.ip=p['IP'].dst # only the destination or source matter, we actually just had to change source to destination to resolve conflicts with the Asterisk server
        del p # take this! (it could make the script faster?)
        # the rest of this init function has attributes that rely on the non-None-lyness (how cute) of other attributes so they're all linked together and it goes fast
        # SIP info (we do a very slight amount of golfing)
        # (I'm actually pretty sure some tests could be simplified)
        # last thing to say : you have to start with Nones so it doesn't look for something that doesn't exist just to find that it won't be used because of a following if
        self.method=None if self.rtp or (not self.sip) or (not 'sip.Method' in self.sip) else self.sip['sip.Method'] # RTP or non-SIP packet = no method to find
        a=None if not self.sip else list(self.sip.values())[0].replace('SIP/2.0 ','') # just to store the description found at the start of the SIP dictionnary cause it's used multiple times
        self.desc='' if not self.sip else (' '*m+('{:->'+str(sizex-m*2)+'}' if a[0].isdigit() else '{}')+'\n').format(a) # format using the margin and the size of the console (super cool + great golfing)
        del a # I heard it's automatic in Python cause garbage collected
        self.isok=None if (not self.sip) or self.method else self.sip['sip.Status-Code']=='200' # bool to know if it's an 'ok' response (don't remember why)
        # RTP info
        self.time=None if not self.rtp else int(self.rtp['rtp.timestamp']) # just read the line
        self.data=None if not (self.rtp and 'rtp.payload' in self.rtp) else self.rtp['rtp.payload'].split(":") # it's originally a string with ':' caracters separating hex values
        # GLOBALS
        if CID=='undefined':CID=None if not self.sip else self.sip['sip.Call-ID'] # nothing to see here
        a=None if self.method!='INVITE' else search(r"telephone-event/([0-9])\w+",self.sip['sip.msg_hdr']).group().split('/')[1] # Colin loves regex now thanks to me (I love it too cause it looks like GOLF yers I like GOLFING)
        if not SIP1:SIP1=None if not a else self.sip['sip.from.user'] # keep reading
        if not SIP2:SIP2=None if not SIP1 else self.sip['sip.to.user'] # these comments are funny haha
        if a:fs=a # anyway the sample rate is found after 'telephone-event/' in the SIP message header
        del a # I'm gonna stop making useless comments now I promise

print(interfaces()) # netifaces can print your interfaces! Great on linous, useless on Windows!
from sys import argv # argv is a list with every inline argument after 'python' including (at index 0) the python file called
iface=(' '.join(argv[1:])) # as the script only takes one argument, if your interface name has a space this will safely get it entirely
if not iface:iface=input('Input your interface name: ') # no arg found
if not iface:exit('No iface selected.') # can't go any further without an interface
capture = LiveCapture(interface=iface, display_filter='sip or rtp') # pyshark enters the ring
print("[+] Démarrage du sniffing...")
# this next line prints LiveCapture logs
# print(capture.set_debug())
format='%d/%m/%Y %H:%M:%S' # for the date
start=datetime.now().strftime(format) # get the time when the call starts (why use SIP dates? pyshark don't like em anyway, it shows them only on Linux)
for packet in capture.sniff_continuously(): # works like this with pyshark
    p=Packet(packet) # convert the object
    print(p.desc,end='') # if the desc is empty, this just won't print anything
    if p.ip and p.data: # remember, Packet.data holds RTP payloads
        if not p.ip in PileAssignment:PileAssignment[p.ip]=Pile(p.ip) # creates a Pile for the IP and reference it to the dict if it's not already in it
        if PileAssignment[p.ip].add(p) and not started: # this will just add the RTP data to the corresponding Pile
            started=True
            print(' '*m+('{:█^'+str(sizex-m*2)+'}').format(' CALL STARTED '))
    if p.method=='BYE':break # the loop ends when someone hangs up the phone
end=datetime.now().strftime(format) # end of the call
# PileAssignment['blabla']=Pile('ip')
# PileAssignment['blabla'].list=['ok']
# print(all(list(a.list for a in PileAssignment.values())))
# PileAssignment=False
for key in PileAssignment:
    if not PileAssignment[key].list:del PileAssignment[key]
if PileAssignment and all(list(a.list for a in PileAssignment.values())): # the all() is unnecessary but will double-check if no value in the lists of every Pile returns False (is empty)
    from sys import platform # get the OS env to resolve differences
    from os import remove,listdir
    if platform=='win32': # Windows user, Breval
        for ip in PileAssignment:PileAssignment[ip].write()
        from subprocess import call # call executes a command inline with args
        # create a batch script with the sox commands using the path where sox is installed because my PATH env variable is nuts and needs temporary support via 'set PATH'
        with open('temp.bat','w') as f:f.write('set PATH="C:\\Program Files (x86)\\sox-14-4-2"\nsox --type raw --rate 8000 -e u-law %1.g711u %1.wav\nsox --type raw --rate 8000 -e u-law %2.g711u %2.wav\nsox -M %1.wav %2.wav %3.wav')
        ips=list(ip for ip in PileAssignment)
        call(['temp.bat',ips[0],ips[1],CID]) # considering there are only two IPs, they will take the place of '%1','%2' and '%3'
        remove("temp.bat") # don't need it anymore
    else: # Linous (Ubuntu and Kali under VirtualBox) user, Colin
        cmd='sox -'+('M' if len(PileAssignment)==2 else 'm')
        for ip in PileAssignment:
            PileAssignment[ip].write()
            system(f'sox --type raw --rate {fs} -e u-law {ip}.g711u {ip}.wav')
            cmd+=f' {ip}.wav'
        cmd+=f' {CID}.wav'
        system(cmd)
    if clean: # in the settings
        for item in listdir():
            if search(r"^(\d{1,3}.){4}(g711u|wav)",item):remove(item) # removes files with an IP adress as name, leaving only the final wav file
with open('infos_call.txt', 'w') as f:f.write("{} --> {}\nDate de début : {: >}\nDate de fin :   {: >}\nCall ID :       {}".format(SIP1,SIP2,start,end,CID))
# nice formatting there, {: >} is also an ASCII drawing of a Roblox face. It means ':' fill ' ' with spaces '>' to the right WAIT IT'S USELESS