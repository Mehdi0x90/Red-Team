# Bash Tricks
## Search command history on bash
```bash
Ctrl+r

```
## Generate random password
Generate a random password `30` characters long
```bash
tr -c -d "a-zA-Z0-9" </dev/urandom | dd bs=30 count=1 2>/dev/null;echo

```
## Generate SSH public key from the private key
```bash
ssh-keygen -y -f privatekey.pem > publickey.pem

```
## Capture all plaintext username and password
```bash
sudo tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '

```
## Capture SMTP / POP3 Email
```bash
sudo tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'

```


