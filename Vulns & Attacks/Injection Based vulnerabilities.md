---
tags:
  - CyberSec
  - Vulns/Web
---
## [[SQLi]]

## Command injection Vulnerabilities 
A **_command injection_** is an attack in which an attacker tries to execute commands that he or she is not supposed to be able to execute on a system via a vulnerable application. Command injection attacks are possible when an application does not validate data supplied by the user (for example, data entered in web forms, cookies, HTTP headers, and other elements). The vulnerable system passes that data into a system shell.
With command injection, an attacker tries to send operating system commands so that the application can execute them with the privileges of the vulnerable application.
>Command injection is not the same as code execution and code injection, which involve exploiting a buffer overflow or similar vulnerability.

## Lightweight Directory Access Protocol (LDAP) Injection Vulnerabilities
_LDAP injection vulnerabilities_ are input validation vulnerabilities that an attacker uses to inject and execute queries to LDAP servers. A successful **_LDAP injection_** attack can allow an attacker to obtain valuable information for further attacks on databases and internal applications.

**NOTE** LDAP is an open application protocol that many organizations use to access and maintain directory services in a network. The LDAP protocol is defined in RFC 4511.

Similar to SQL injection and other injection attacks, LDAP injection attacks leverage vulnerabilities that occur when an application inserts unsanitized user input (that is, input that is not validated) directly into an LDAP statement. By sending crafted LDAP packets, attackers can cause the LDAP server to execute a variety of queries and other LDAP statements. LDAP injection vulnerabilities could, for example, allow an attacker to modify the LDAP tree and modify business-critical information.

There are two general types of LDAP injection attacks:

- **Authentication bypass:** The most basic LDAP injection attacks are launched to bypass password and credential checking.
- **Information disclosure:** An attacker could inject crafted LDAP packets to list all resources in an organization’s directory and perform reconnaissance.