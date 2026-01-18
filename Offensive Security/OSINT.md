---
tags:
  - CiscoEH
  - CyberSec
---
OSINT (Open-source intelligence)  is the collection and analysis of information from publicly available sources to generate usable intelligence. It's commonly used to support cybersecurity activities, like identifying potential threats and vulnerabilities.
### Google Dorking
| Operator   | Description                                                                    |
| ---------- | ------------------------------------------------------------------------------ |
| allintext: | Restricts results to pages with all query words in the page text.              |
| filetype:  | Restricts results to pages of the specified file type (.pdf, .ppt, .doc, etc.) |
| intitle:   | Restricts results to pages with a certain word (or words) in the title.        |
| inurl:     | Restricts results to pages with a certain word (or words) in the URL.          |
| site:      | Restricts results to pages from the specified domain.                          |
The [GHDB](https://www.exploit-db.com/google-hacking-database) is an index of search queries (we call them dorks) used to find publicly available information, intended for pentesters and security researchers. It is an index of user-created dorks that are designed to uncover interesting, and potentially sensitive, information that was unintentionally made publicly available on the internet.

## Other Tools
- [Sherlock](https://github.com/sherlock-project/sherlock) : is an osint tool for searching a particular user id in all the available social media platforms
- [R3C0Nizer](https://github.com/Anon-Artist/R3C0Nizer)
- [Osintgram](https://github.com/Datalux/Osintgram)
- [theHarvester](https://github.com/laramies/theHarvester)  : is a simple to use, yet  powerful tool designed to be used during  the reconnaissance stage of a red  team assessment or penetration test. It  performs open source intelligence  (OSINT) gathering to help determine  a domain's external threat landscape.
- [Maltego](https://www.maltego.com/) :is an open source intelligence and forensics application. It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format.
- The [OSINT Framework](https://osintframework.com/) :is a useful way to visualize the OSINT tools and resources that are available.
- [VirusTotal](https://www.virustotal.com/gui/home/upload) :is a service that allows anyone to analyze suspicious files, domains, URLs, and IP addresses for malicious content.
- [MITRE ATT&CK®](https://attack.mitre.org/) : is a knowledge base of adversary tactics and techniques based on real-world observations.
- [Have I been Pwned](https://haveibeenpwned.com/) : is a tool that can be used to search for breached email accounts.
### SpiderFoot
SpiderFoot is an automated OSINT scanner. It is included with Kali. SpiderFoot queries over 1000 open-information sources and presents the results in an easy-to-use GUI. SpiderFoot can also be run from a console.
SpiderFoot seeds its scan with one of the following:
- Domain names
- IP addresses
- Subnet addresses
- Autonomous System Numbers (ASN)
- Email addresses
- Phone numbers
- Personal names
SpiderFoot offers the option of choosing scans based on use case, required data, and by SpiderFoot module. The use cases are:
- All – Get every possible piece of information about the target. This use case can take a very long time to complete.
- Footprint – Understand the target’s network perimeter, associated identities and other information that is yielded by extensive web crawling and search engine use.
- Investigate – This is or targets that you suspect of malicious behavior. Footprinting, blacklist lookups, and other sources that report on malicious sites will be returned.
- Passive – This type of scan is used if it is undesirable for the target to suspect that it is being scanned. This is a form of passive OSINT.

- [[recon-ng]]

## Discovering email addresses
- hunter.io
- phonebook.cz
- voilanorbert.com
- clearbit connect extension in gmail
	To verify email address
- emailhippo - (tools.verifyemailaddress.io)
- email-checker.net/validate

## find web app infos / Fingerprinting
- wappalyser extension
- react developer tools
- https://w3techs.com
- [builtwith](https://builtwith.com)
- whatweb
	- tool built in kali
- wpscan 
	- to get info wordpress web apps
	- `wpscan --url [url] -e ap --plugin-detection aggressive`
- Netcat
- Nmap
- Censys2
	**_Censys_**, a tool developed by researchers at the University of Michigan, can be used for passive reconnaissance to find information about devices and networks on the Internet. It can be accessed at [_https://censys.io_](https://censys.io/). Censys provides a free web and API access plan that limits the number of queries a user can perform. It also provides several other paid plans that allow for premium support and additional queries.
## Finding Information from SSL Certificates
During the reconnaissance phase, attackers often can inspect Secure Sockets Layer (SSL) certificates to obtain information about the organization, potential cryptographic flaws, and weak implementations. You can find a lot inside digital certificates: the certificate serial number, the subject common name, the uniform resource identifier (URI) of the server it was assigned to, the organization name, Online Certificate Status Protocol (OCSP) information, the certificate revocation list (CRL) URI, and so on.

Certificate Transparency (CT) is an open framework for monitoring and auditing the issuance of SSL/TLS certificates. CT requires that all publicly trusted certificate authorities (CAs) log all issued certificates in publicly available, tamper-evident, and auditable logs. These logs can be monitored to detect any fraudulent or malicious issuance of SSL/TLS certificates, including certificates issued for domains that the attacker does not control.
https://crt.sh/

| Tool     | Description                                                   | Recon, Exploitation, or Utility |
| -------- | ------------------------------------------------------------- | ------------------------------- |
| sslscan  | Queries SSL services to determine what cyphers are supported  | Reconnaissance                  |
| ssldump  | Analyze and decode SSL traffic                                | Exploitation                    |
| sslh     | Running multiple services on port 443                         | Utility                         |
| sslsplit | Enable MitM attacks on SSL encrypted network connections      | Exploitation                    |
| sslyze   | Analyze the SSL configuration of a server by connecting to it | Reconnaissance                  |
use sslscan to gather information about certificates and use another utility, called `aha`, to output the results to an HTML file.
## File Metadata
You can obtain a lot of information from metadata in files such as images, Microsoft Word documents, Excel files, PowerPoint files, and more. For instance, Exchangeable Image File Format (Exif) is a specification that defines the formats for images, sound, and supplementary tags used by digital cameras, mobile phones, scanners, and other systems that process image and sound files.
- Exiftool
- FOCA
	**_Fingerprinting Organization with Collected Archives (FOCA)_** is a tool designed to find metadata and hidden information in documents. FOCA can analyze websites as well as Microsoft Office, Open Office, PDF, and other documents. You can download FOCA from _[https://github.com/ElevenPaths/FOCA](https://github.com/ElevenPaths/FOCA)_. FOCA analyzes files by extracting **_EXIF_** (exchangeable image file format) information from graphics files, as well as information discovered through the URL of a scanned website.
## Password OSINT 
>Gathering breached passwords
- Using [Breach-parse](https://github.com/hmaverickadams/breach-parse)
	- this is ~44gb
	- not required/recommended
- Using [Dehashed](https://dehashed.com)
	- paid subscription required
- Weleakinfo 
	- maybe shutdown
- Hashes.org
- HavelBeenPwned

### Breaches
tools that allow you to search for breach data dumps:
- h8mail
- **WhatBreach:** _[https://github.com/Ekultek/WhatBreach](https://github.com/Ekultek/WhatBreach)_
- **LeakLooker:** _[https://github.com/woj-ciech/LeakLooker](https://github.com/woj-ciech/LeakLooker)_
- **Buster:** _[https://github.com/sham00n/buster](https://github.com/sham00n/buster)_
- **Scavenger:** _[https://github.com/rndinfosecguy/Scavenger](https://github.com/rndinfosecguy/Scavenger)_
- **PwnDB:** _[https://github.com/davidtavarez/pwndb](https://github.com/davidtavarez/pwndb)_

 Several online services provide the ability to search on individual email addresses and entire domains to reveal breaches. Some of those sites are:
- haveibeenpwned.com
- f-secure.com
- hacknotice.com
- breachdirectory.com
- keepersecurity.com

## Shodan
**_Shodan_** is an organization that scans the Internet 24 hours a day, 365 days a year. The results of those scans are stored in a database that can be queried at shodan.io or by using an API. You can use Shodan to query for vulnerable hosts, Internet of Things (IoT) devices, and many other systems that should not be exposed or connected to the public Internet. Figure 3-5 shows different categories of systems found by Shodan scans, including industrial control systems (ICS), databases, network infrastructure devices, and video games.
**_Shodan_** is a search engine for devices connected to the Internet.