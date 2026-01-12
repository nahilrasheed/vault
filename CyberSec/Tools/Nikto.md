---
tags:
  - CyberSec/tools
---
Nikto is a popular web vulnerability scanner that can find SQL injection, XSS, and other common vulnerabilities in websites. It can identify installed software using page headers and files. Nikto supports both HTTP and HTTPS protocols.

**_Nikto_** is an open-source web vulnerability scanner that can be downloaded from [_https://github.com/sullo/nikto_](https://github.com/sullo/nikto). 
Nikto’s official documentation can be accessed at [_https://cirt.net/nikto2-docs_](https://cirt.net/nikto2-docs)


> [!tip] Basic usage: 
> ```
> nikto -h [target]
> ```


```
NAME
         nikto - Scan web server for known vulnerabilities
SYNOPSIS
       /usr/local/bin/nikto [options...]
DESCRIPTION
       Examine a web server to find potential problems and security
vulnerabilities, including:
    · Server and software misconfigurations
    · Default files and programs
    · Insecure files and programs
    · Outdated servers and programs
 Nikto is built on LibWhisker (by RFP) and can run on any platform
which has a Perl environment. It supports SSL, proxies, host
authentication, IDS evasion and more. It can be updated automatically
from the command-line, and supports the optional submission of updated
version data back to the maintainers.
```
### Params
- Nikto scans for port 80 web services. To scan domains with HTTPS enabled, you must specify the **-ssl** flag to scan port 443:
	`nikto -h https://nmap.org -ssl`

- `-Tuning+`           
	- Scan tuning:
	    1      Interesting File / Seen in logs
	    2     Misconfiguration / Default File
	    3     Information Disclosure
	    4     Injection (XSS/Script/HTML)
	    5     Remote File Retrieval - Inside Web Root
	    6     Denial of Service
	    7     Remote File Retrieval - Server Wide
	    8     Command Execution / Remote Shell
	    9     SQL Injection
	    0     File Upload
	    a     Authentication Bypass
	    b     Software Identification
	    c     Remote Source Inclusion
	    d     WebService
	    e     Administrative Console
	    x     Reverse Tuning Options (i.e., include all except specified)

### Investigate
Nikto provides some information about the vulnerabilities that it uncovers during its scans. Some vulnerabilities are associated with an OSVDB number (an older Open Source Vulnerability Database), a [[CVE, CWE, CVSS|CWE]]. OSVDB was discontinued in 2016. You can use the CVE reference tool to translate the OSVDB identifier to a CVE entry so you can research the vulnerability further.
Use the National Vulnerability Database ([https://nvd.nist.gov](https://nvd.nist.gov/)) to find additional information on the CVEs.
### Export
Nikto can output the results of a scan in various formats including CSV, HTML, SQL, txt, and XML. In addition, Nikto can be paired with Metasploit to launch exploits against the vulnerabilities that you uncover.
1. To export a scan result, use the **-o** flag followed by the file name. Export the results of a scan to an HTML report file named **scan_results.htm**. The output file type is determined from the file extension.
	`nikto -h 172.17.0.2 -o scan_results.htm`
2. To specify a text file output format that is independent of the file extension, use the **-Format** flag. Use the **-Format csv** option to save the file in .csv format to import into other analysis applications.
	`nikto -h 172.17.0.2 -o scan_results.txt -Format csv`

---
You can automate the scanning of multiple hosts by using Nmap and Nikto together. For example, you can scan the 10.1.1.0/24 subnet with Nmap and then pipe the results to Nikto, as demonstrated in Example 10-20.

```
root@kali:~# nmap -p 80 10.1.1.0/24 -oG - | nikto -h -
- Nikto v2.1.6
----------------------------------------------------------------------
+ nmap Input Queued: 10.1.1.11:80
+ nmap Input Queued: 10.1.1.12:80
+ nmap Input Queued: 10.1.1.14:80
+ Target IP:               10.1.1.12
+ Target Hostname:       10.1.1.12
+ Target Port:            80
+ Start Time:          2018-06-23 22:56:15 (GMT-4)
<output omitted for brevity>
+ 22798 requests: 0 error(s) and 29 item(s) reported on remote host
+ End Time:             2018-06-23 22:57:00 (GMT-4) (30 seconds)
----------------------------------------------------------------------
+ 3 host(s) tested
```

