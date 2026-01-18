---
tags:
  - NBBC
  - CyberSec
  - Networking
---
## What is DNS?
Devices talk to each other using their IP addresses, but the problem is that these IP addresses aren't very memorable and could also change over time. 
Domain Name System (DNS) is the protocol responsible for resolving hostnames, such as google.com, to their respective [[IP and MAC Addresses|IP Address]] .
## Domain Heirarchy
#### What is a domain name?
Anybody can pay a nominal fee and register their own domain name. There are three different types of domain names that can be registered:
#### Top-Level Domain - TLD
A TLD is the most righthand part of a domain name. So, for example, the google.com's TLD is **.com**. 
There are two types of TLD, gTLD (Generic Top Level) and ccTLD (Country Code Top Level Domain).
**Generic Top Level Domain - gTLD**
Historically a gTLD was meant to tell the user the domain name's purpose; for example, a .com would be for commercial purposes, .org for an organisation, .edu for education and .gov for government.
**Country Code Top-Level Domain - ccTLD**
These domain names are geographically based, such as .co.uk for the U.K, .fr for French domains, .au for Australian domains, etc. Even if you don't reside in those countries, you can usually register the domains anyway.
**Sponsored Top-Level Domain - sTLD**
These domains are usually more restricted and can only be registered by institutions; these include domains such as .edu, .gov, .mil, etc.
#### Second-Level Domain
Taking google.com as an example, the .com part is the TLD, and google is the Second Level Domain. When registering a domain name, the second-level domain is limited to 63 characters + the TLD and can only use a-z 0-9 and hyphens (cannot start or end with hyphens or have consecutive hyphens).
#### Subdomains
A subdomain is any text which sits before the domain name and is separated with a period (.) a subdomain is also referred to as a label.
 A subdomain name has the same creation restrictions as a Second-Level Domain, being limited to 63 characters and can only use a-z 0-9 and hyphens (cannot start or end with hyphens or have consecutive hyphens). You can use multiple subdomains split with periods to create longer names. But the length must be kept to 253 characters or less. There is no limit to the number of subdomains you can create for your domain name.
 
## How does it work?
When you request a website, quite a lot of things happen in the background to get the IP address.
1. When you request a domain name, your computer first checks its local cache to see if you've previously looked up the address recently; if not, a request to your Recursive DNS Server will be made.
2. A Recursive DNS Server is usually provided by your ISP, but you can also choose your own. This server also has a local cache of recently looked up domain names. If a result is found locally, this is sent back to your computer, and your request ends here (this is common for popular and heavily requested services such as Google, Facebook, Twitter). If the request cannot be found locally, a journey begins to find the correct answer, starting with the internet's root DNS servers.
3. The root servers act as the DNS backbone of the internet; their job is to redirect you to the correct Top Level Domain Server, depending on your request. If, for example, you request example.com , the root server will recognise the Top Level Domain of .com and refer you to the correct TLD server that deals with .com addresses.
4. The TLD server holds records for where to find the authoritative server to answer the DNS request. The authoritative server is often also known as the nameserver for the domain. You'll often find multiple nameservers for a domain name to act as a backup in case one goes down.
5. An authoritative DNS server is the server that is responsible for storing the DNS records for a particular domain name and where any updates to your domain name DNS records would be made. Depending on the record type, the DNS record is then sent back to the Recursive DNS Server, where a local copy will be cached for future requests and then relayed back to the original client that made the request. DNS records all come with a TTL (Time To Live) value. This value is a number represented in seconds that the response should be saved for locally until you have to look it up again. Caching saves on having to make a DNS request every time you communicate with a server.

![[DNS-img-202510091530.png]]

#### DNS Record types:
**A Type**
This is the record type that contains an IPv4 response such as 1.2.3.4
**AAAA Type**
This record type contains an IPv6 response for hosts that support IPv6.
**MX Type**
This record advises the address of the server that handles the domain's email.
**CNAME Type**
This response points us to another DNS record. For example, if we had a shop hosted by Shopify we might have the address `shopify.website.com` with points to `shops.myshopify.com` then Shopify's DNS server will handle the request.
**NS Type**
This record advised the addresses of the name servers for the domain. A subdomain might handle its own DNS records so this is a useful record to point to other servers.
**TXT Type**
These records can contain textual information and can be used for multiple reasons, some common ones are providing confirmation that you have ownership over a domain for 3rd party services or the prevention of SPAM email.
**PTR Type**
A PTR record is like a reverse lookup for IP addresses. So you can search for an IP address and find the domain name which is associated with it.

#### DNS Status Codes
NOERROR - The query was successful, and data is returned. 
NXDOMAIN - The queried domain does not exist. **(Non-Existent Domain)**
SERVFAIL - The server failed to process the query.
REFUSED -The server refused to provide an answer.

