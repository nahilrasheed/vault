---
tags:
  - CyberSec
  - NBBC
  - Vulns/Web
---
Open redirects happens when the application takes an untrusted input and redirects a user from the web application to an untrusted site or resource that will be used further for malicious purposes.
The impact of an open redirect is usually set to low unless you're using it to escalate another vulnerability.
Open redirect can be chained with other vulnerabilities. 
- eg: To bypass white listing controls in [[SSRF - Server-Side Request Forgery]] attack
- Use as entry point for XSS. we can try to escape out of the redirect logic and inject malicious script

## Bypasses
- Try changing the url in redirect field (appending a domain)
- add a same domain url which has redirect builtin
- Try to trick the regex (By adding a `//` to confuse the redirect domain)
- Add `@hacker.com` at the en of redirect url , now original url is considered as username

https://github.com/payloadbox/open-redirect-payload-list