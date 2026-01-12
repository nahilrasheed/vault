---
tags:
  - NBBC
  - CyberSec
---
curl  is  a tool for transferring data from or to a server using URLs. 
It supports these protocols: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, POP3, POP3S, RTMP, RTMPS, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS.

**Basic Request:**
You can use the command below to make a basic request to a website.

```
curl https://example.com
```

**Choosing a Path:**
If you wish to view a different website path, you can use the command below.

```
curl https://example.com/endpoint_1
```

**Query Strings:**
As we learned earlier in the module, arguments can be passed to a web application using query strings. You can try this using the command below.

```
curl https://example.com/endpoint_2?show=flag 
```

**Method Type:**
You can change your method by using the -X switch.
```
curl -X POST https://example.com/endpoint_3
```

**Post Data:**
We can send data to the web application using the -d switch.
```
curl -X POST https://example.com/endpoint_4 -d "show=flag"
```

**Headers:**
You can set headers can be achieved by using the -H switch.
```
curl https://example.com/endpoint_5 -H "Show: flag"
```
- To specify a custom user-agent, we can use the `-A` flag: `curl -A "internalcomputer" http://example.com`
**Cookies:**
You can set cookies using two different methods; as cookies are technically a header, you can use something similar to the above example:
```
curl https://example.com/endpoint_6 -H "Cookie: show=flag"
```

Or by using the proper -b switch that curl reserves for setting cookies.
```
curl https://example.com/endpoint_6 -b "show=flag"
```

To save cookies use `-c` flag.
```
curl -c cookies.txt -d "username=admin&password=admin" http://example.com/session.php
```
and then to use it: `curl -b cookies.txt http://example.com/session.php`
### **URL Encoding:**

Some characters in requests are reserved for letting the web server know where data starts and ends, such as the & and = characters. 

For example, if you wanted to set the field **show** to have the value **fl&ag**, this would confuse the webserver as it would think **show** has the value **fl,** and then the & character is signifying the start of the next field. 

You can circumvent this by URL encoding special characters. This looks like a percent sign (%) followed by two hexadecimal digits, and these digits represent the character's value in the ASCII character set ([https://www.w3schools.com/charsets/ref_html_ascii.asp](https://www.w3schools.com/charsets/ref_html_ascii.asp)).

So to properly make the request, we'd use the example below.

```
curl https://example.com/endpoint_7?show=fl%26ag
```

### **Authorization:**

Websites that require authorization can have a username and password passed to them in two methods, either by using the -u switch:

```
curl -u admin:password https://example.com/endpoint_8
```

Or by using the Authorization header. In this example, the username and password is concatenated together using a colon and then encoded using base64.

```
curl https://example.com/endpoint_8 -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ="
```

## Other 
Silent request (No headers): `curl -s website.com`
Include headers in response : `curl -i website.com`