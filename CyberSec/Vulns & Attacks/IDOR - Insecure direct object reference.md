---
tags:
  - CyberSec
  - CiscoEH
  - Vulns/Web
---
> Occurs when an application exposes internal object identifiers, like database keys or file paths, to users without proper access controls. This can happen when user input, like an account number, is directly linked to an application's object without any checking mechanism to stop unauthorized users from accessing it.

Insecure Direct Object Reference vulnerabilities can be exploited when web applications allow direct access to objects based on user input. Successful exploitation could allow attackers to bypass authorization and access resources that should be protected by the system (for example, database records, system files). This type of vulnerability occurs when an application does not sanitize user input and does not perform appropriate authorization checks.

IDOR comes under **[Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)** in OWASP top10 2021 where it ranked #1 in terms of web application security risk.

## Exploit 
An attacker can take advantage of Insecure Direct Object References vulnerabilities by modifying the value of a parameter used to directly point to an object. In order to exploit this type of vulnerability, an attacker needs to map out all locations in the application where user input is used to reference objects directly.

Sometimes application use UUID's instead of numeric id's. UUID's are unpredictable long strings. They look like this: bfe5c6a8-9afa-11ea-bb37-0242ac130002. They don't protect against IDOR's but they do make it harder to exploit. Sometimes applications leak the UUID, on purpose or by accident. For example, when you visit another user's profile, they may have a profile photo that's stored on the website in a folder the same as their UUID: `<img src="/assets/profile_picture/bfe5c6a8-9afa-11ea-bb37-0242ac130002/avatar.png">`

- Try different http methods


## Mitigations
Mitigations for this type of vulnerability include input validation, the use of per-user or session Indirect Object References, and access control checks to make sure the user is authorized for the requested object.