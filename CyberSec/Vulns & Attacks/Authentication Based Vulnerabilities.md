---
tags:
  - CyberSec
  - CiscoEH
---
## Broken Access Control (BAC)
## Session Hijacking
Applications can create [[Web Sessions|sessions]] to keep track of users before and after authentication. Once an authenticated session has been established, the session ID (or token) is temporarily equivalent to the strongest authentication method used by the application, such as username and password, one-time password, client-based digital certificate, and so on.
One of the most widely used session ID exchange mechanisms is cookies. Cookies offer advanced capabilities that are not available in other methods.
There are several ways an attacker can perform session hijacking and several ways a session token may be compromised:
- **Predicting session tokens:** This is why it is important to use non-predictable tokens, as previously discussed in this section.
- **Session sniffing:** This can occur through collecting packets of unencrypted web sessions.
- **On-path attack (formerly known as man-in-the-middle attack):** With this type of attack, the attacker sits in the path between the client and the web server. In addition, a browser (or an extension or a plugin) can be compromised and used to intercept and manipulate web sessions between the user and the web server. This browser-based attack was previously known as a man-in-the-browser attack.
If web applications do not validate and filter out invalid session ID values, they can potentially be used to exploit other web vulnerabilities, such as SQL injection (if the session IDs are stored on a relational database) or persistent XSS (if the session IDs are stored and reflected back afterward by the web application).

## Redirect Attacks
Unvalidated redirects and forwards are vulnerabilities that an attacker can use to attack a web application and its clients. The attacker can exploit such vulnerabilities when a web server accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. The attacker can modify the untrusted URL input and redirect the user to a malicious site to either install malware or steal sensitive information.

It is also possible to use unvalidated redirect and forward vulnerabilities to craft a URL that can bypass application access control checks. This, in turn, allows an attacker to access privileged functions that he or she would normally not be permitted to access.

**NOTE** Unvalidated redirect and forward attacks often require a little bit of social engineering.
## Default Credentials
Attackers can easily identify and access systems that use shared default passwords. It is extremely important to always change default manufacturer passwords and restrict network access to critical systems. A lot of manufacturers now require users to change the default passwords during initial setup, but some don’t.

Attackers can easily obtain default passwords and identify Internet-connected target systems. Passwords can be found in product documentation and compiled lists available on the Internet. An example is [_http://www.defaultpassword.com_](http://www.defaultpassword.com/), but there are dozens of other sites that contain default passwords and configurations on the Internet. It is easy to identify devices that have default passwords and that are exposed to the Internet by using search engines such as Shodan ([_https://www.shodan.io_](https://www.shodan.io/)).

## Kerberos Vulnerabilities
One of the most common attacks against Windows systems is the Kerberos golden ticket attack. An attacker can use such an attack to manipulate Kerberos tickets based on available hashes. The attacker only needs to compromise a vulnerable system and obtain the local user credentials and password hashes. If the system is connected to a domain, the attacker can identify a Kerberos ticket-granting ticket (KRBTGT) password hash to get the golden ticket.

Another weakness in Kerberos implementations is the use of unconstrained _Kerberos_ _delegation_, a feature that allows an application to reuse the end-user credentials to access resources hosted on a different server. Typically, you should only allow Kerberos delegation on an application server that is ultimately trusted. However, this could have negative security consequences if abused, so Active Directory has Kerberos delegation turned off by default.

### [[Password Attacks|Password Cracking]]