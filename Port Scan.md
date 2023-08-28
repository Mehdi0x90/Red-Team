# Port Scan

### Port scan a range of hosts with Netcat
```bash
for i in {21..29}; do nc -v -n -z -w 1 192.168.0.$i 443; done

```
### Scan all open ports without any required program
```bash
$ for i in {1..65535}; do (echo < /dev/tcp/127.0.0.1/$i) &>/dev/null && printf "\n[+] Open Port at\n: \t%d\n" "$i" || printf "."; done

```


























