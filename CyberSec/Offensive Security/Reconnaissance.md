---
tags:
  - CyberSec
  - RedTeam
---
## Active reconnaissance
**_Active reconnaissance_** is a method of information gathering in which the tools used actually send out probes to the target network or systems in order to elicit responses that are then used to determine the posture of the network or system. These probes can use various protocols and multiple levels of aggressiveness, typically based on what is being scanned and when. For example, you might be scanning a device such as a printer that does not have a very robust TCP/IP stack or network hardware. By sending active probes, you might crash such a device. Most modern devices do not have this problem; however, it is possible, so when doing active scanning, you should be conscious of this and adjust your scanner settings accordingly.

Common active reconnaissance tools and methods include the following:
- Host enumeration
- Network enumeration
- User enumeration
- Group enumeration
- Network share enumeration
- Web page enumeration
- Application enumeration
- Service enumeration
- Packet crafting
## Passive reconnaissance
**_Passive reconnaissance_** is a method of information gathering in which the tools do not interact directly with the target device or network. There are multiple methods of passive reconnaissance. Some involve using third-party databases to gather information. Others also use tools in such a way that they will not be detected by the target. These tools, in particular, work by simply listening to the traffic on the network and using intelligence to deduce information about the device communication on the network. This approach is much less invasive on a network, and it is highly unlikely for this type of reconnaissance to crash a system such as a printer. Because it does not produce any traffic, it is also unlikely to be detected and does not raise any flags on the network that it is surveying. Another scenario in which a passive scanner would come in handy would be for a penetration tester who needs to perform analysis on a production network that cannot be disrupted. The passive reconnaissance technique that you use depends on the type of information that you wish to obtain. One of the most important aspects of learning about penetration testing is developing a good methodology that will help you select the appropriate tools and technologies to use during the engagement.

Common passive reconnaissance tools and methods include the following:
- Domain enumeration
- Packet inspection
- Open-source intelligence :: [[OSINT]]
- [[recon-ng|Recon-ng]]
- Eavesdropping

---
# Reconnaissance tools
## Domain Info
- nslookup
	- `nslookup [domain]`
	- gives ip address
	- `> set type=any` to get all info or we can specify record types
- whois
	- `whois [domain]`
	- gives info on domain by querying the whois database
- dig : to find subdomains
	- basic usage : `dig [domain]`
	- utilise zone tranfer
	- `dig axfr @[ip] [domain]`
	-  to perform a query using a different DNS server is `dig [_hostname_] @[_DNS server IP_] [_type_]`
	- Enter the **dig** command using the -x option to retrieve the hostname and record type of the DNS server with ip. `dig -x [ip]`
	> Reverse DNS (rDNS) lookups use the IP address to query for the host names of the services that resolve to that address.
- host
	- The Host utility is a function in Linux that performs lookups to convert IP addresses to host names. we can use this utility to find another host on the network.
	- Host can also be used to perform a quick IP address lookup for a known hostname.
	- `host [ip]` or `host [domain]`
- dnsrecon
- theharvester
	- **_theHarvester_** is a tool that can be used to enumerate DNS information about a given hostname or IP address. It can query several data sources, including Baidu, Google, LinkedIn, public Pretty Good Privacy (PGP) servers, Twitter, vhost, Virus Total, ThreatCrowd, CRT.SH, Netcraft, and Yahoo.
	- `theHarvester -d [domain.com] -b [source|google]`
- crt.sh
	- https://crt.sh
## Finding valid subdomains
- Subfinder
	   - to find subdomains
       - `subfinder -d website.com`
- sublist3r
	- `apt install sublist3r`
	- for subdomains : `sublist3r -d site.com`
	- slow
- Amass - github.com/OWASP/Amass
	- to find subdomains
	- faster/ preferred
	- `amass enum -passive -d domain.com`
   - httpx helps you to get different list of data from a website
       - `subfinder -d example.com | httpx -title -ports 443,8443`
- waybacktool
	- https://github.com/tomnomnom/waybackurls
	- `cd ~/go/bins`
	- `cat [domains.txt] | ./waybackurls > [domain.urls]`
- waymore
- waybackurl - https://github.com/tomnomnom/waybackurls
- getallurl
- httprobe
	- github.com/tomnomnom/httprobe
	- check if the pages in the wayback tool are valid
	- `cat [domain.urls] | httprobe 
	- use `httprobe -t 1000` to reduce time

- **Maltego**
	**_Maltego_**, which gathers information from public records, is one of the most popular tools for passive reconnaissance. It supports numerous third-party integrations. There are several versions of Maltego, including a community edition (which is free) and several commercial Maltego client and server options. You can download and obtain more information about Maltego from [_https://www.paterva.com_](https://www.paterva.com/). Maltego can be used to find information about companies, individuals, gangs, educational institutions, political movement groups, religious groups, and so on. Maltego organizes query entities within the Entity Palette, and the search options are called “transforms.” Figure 10-6 shows a screenshot of the search results for a Person entity (in this case a search against this book’s coauthor Omar Santos). The results are hierarchical in nature, and you can perform additional queries/searches on the results (entities).


## Active recon
- [[Nmap]] / zenmap
- [[enum4linux]]
- 