---
tags:
  - CyberSec
  - RedTeam
---
A **_port scan_** is an active scan in which the scanning tool sends various types of probes to the target IP address and then examines the responses to determine whether the service is actually listening.
-  [[Nmap]]

Enumeration is _the process of systematically probing a target for information_.
[[Enumeration]]
### Identify ip
- use   `arp-scan -l ` 
- use `netdiscover -r 192.168.50.0/24` (put the first 3 parts of your ip & .0/24)
### [[Nikto]]
- web vulnerabilty scanner
- usage: `nikto -h [web address (eg: http://192.168.57.8)] `  
### Directory Busting

- dirbuster usage: `dirbuster&` opens gui
- dirb usage: `dirb [uri (http://192.168.60.6)]` 
- **gobuster:** written in Go - [_https://github.com/OJ/gobuster_](https://github.com/OJ/gobuster).
- ffuf usage: `ffuf -w [wordlist]:FUZZ -u [uri]/FUZZ`
			wordlist - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
- dirsearch : `dirsearch -u [url]`
- **feroxbuster:** This web application reconnaissance fuzzer is written in Rust. You can download feroxbuster from [_https://github.com/epi052/feroxbuster_](https://github.com/epi052/feroxbuster).
### SMB Enumeration
- use [[Metasploit]]
- connecting to SMB
	- `smbclient -L \\\\[ip]\\`
### We can use [[Nessus]] to scan for vulnerabilities

## Research
Google for vulnerabilties in various services with version no
### Searchsploit
