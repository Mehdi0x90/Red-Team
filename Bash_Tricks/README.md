# Bash Tricks
### Search command history on bash
```bash
Ctrl+r

```
### Generate random password
Generate a random password `30` characters long
```bash
tr -c -d "a-zA-Z0-9" </dev/urandom | dd bs=30 count=1 2>/dev/null;echo

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
### Scan all open ports without any required program
```bash
for i in {1..65535}; do (echo < /dev/tcp/192.168.0.1/$i) &>/dev/null && printf "\n[+] Open Port at\n: \t%d\n" "$i" || printf "."; done

```

