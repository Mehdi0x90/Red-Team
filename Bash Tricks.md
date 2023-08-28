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





