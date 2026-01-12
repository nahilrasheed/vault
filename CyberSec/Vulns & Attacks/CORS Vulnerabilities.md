---
tags:
  - NBBC
  - Vulns/Web
  - CyberSec
---
## What is CORS?
**CORS** (Cross-Origin Resource Sharing) is a browser security feature that restricts web applications from making requests to a domain different from the one that served the web page, unless explicitly allowed by the server using CORS headers (e.g., `Access-Control-Allow-Origin`).
### Why Does CORS Exist?
To prevent **malicious websites** from reading sensitive data from another site using the browser's credentials (like cookies or tokens). Without CORS, any site could make requests to another and read responses, leading to **data theft, account takeover, or CSRF-like attacks**.
### CORS Headers Explained
| Header                             | Purpose                                         |
| ---------------------------------- | ----------------------------------------------- |
| `Access-Control-Allow-Origin`      | Specifies which origin can access the resource. |
| `Access-Control-Allow-Methods`     | Lists allowed HTTP methods (e.g., GET, POST).   |
| `Access-Control-Allow-Headers`     | Lists allowed request headers.                  |
| `Access-Control-Allow-Credentials` | Allows cookies/auth headers. Must be `true`.    |
| `Access-Control-Max-Age`           | Caches the preflight response.                  |

## Common CORS Misconfigurations
### 1. **Wildcard `*` with Credentials**
- **Issue**: `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` together.
- **Impact**: This violates the CORS specification. Browsers should block it, but misconfigured servers might still behave unexpectedly.
- **Risk**: If allowed, it enables an attacker to make authenticated cross-origin requests.
### 2. **Reflecting Origin Header**
- **Issue**: Server blindly reflects the value of `Origin` in `Access-Control-Allow-Origin`.
```http
Origin: https://evil.com
Access-Control-Allow-Origin: https://evil.com
```
- **Impact**: An attacker can abuse this to access sensitive data using a malicious domain.
### 3. **Whitelisted Subdomains with Wildcards**
- **Issue**: Using wildcard subdomains like `*.victim.com` allows attacker-controlled subdomains.
- **Impact**: If the attacker can host content on `evil.victim.com`, they can bypass origin restrictions.
### 4. **Overly Permissive Headers**
- Headers like:
```http
 Access-Control-Allow-Origin: *
 Access-Control-Allow-Methods: GET, POST, PUT, DELETE
 Access-Control-Allow-Headers: *
```
- These make the API broadly accessible and could lead to **data exposure or abuse**.
## How to Test for CORS Vulnerabilities
### 1. **Using curl or Burp Suite**
**Example: curl**
```bash
curl -i -H "Origin: https://evil.com" https://target.com/api/data
```
Check if `Access-Control-Allow-Origin: https://evil.com` is reflected in the response.
### 2. **Using a Simple JavaScript Payload**
Run this in the browser console or embed it in an attacker’s site:
```javascript
fetch("https://target.com/api/secret", {
  method: "GET",
  credentials: "include"
}).then(res => res.text())
  .then(data => console.log(data));
```
If the response succeeds and returns sensitive information, **CORS is misconfigured**.
### 3. **Tools**
- **CORScanner**: Automated CORS misconfiguration scanner
- **Burp Suite’s CORS plugin**
- **Postman**: For manual testing with different headers
## Example Scenario
- A banking API has the following response:
```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
- Attacker tricks a logged-in user into visiting `evil.com`.
- Malicious JS sends a request to `https://bank.com/account/balance`.
- Because cookies are sent (`credentials: include`), the server treats it as authenticated and responds with data visible to the attacker. 
## Note
When dealing with CORS (Cross-Origin Resource Sharing) issues, it's important to note that not all browsers handle CORS requests the same way. For CORS to function correctly, browsers must support third-party cookies, which are being phased out due to privacy concerns.

Third-party cookies are used when a website (Website A) makes a request to another website (Website B). The cookies from Website B are sent along with the request. For these cookies to be sent, the original website must set the cookie with specific attributes: it must be secure (only sent over HTTPS), httponly (not accessible via JavaScript), and have the samesite policy set to None.
 