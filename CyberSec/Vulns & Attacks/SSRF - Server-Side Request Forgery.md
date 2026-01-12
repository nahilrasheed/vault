Server-Side Request Forgery (SSRF) is a web security vulnerability where an attacker tricks a server-side application into making an HTTP request to an unintended location. This can allow attackers to access internal resources, potentially leading to unauthorized actions, data breaches, and even remote code execution. 
How it works:
- Exploiting User Input:
	SSRF vulnerabilities often arise when applications take user-supplied URLs or other input that is then used to make HTTP requests without proper validation.
- Internal Resource Access:
	Attackers can manipulate these requests to access internal services, databases, or other resources that are not directly exposed to the internet.
- Bypassing Security Measures:
	SSRF can allow attackers to bypass firewalls, VPNs, or other security measures that protect internal networks. 
Consequences of SSRF:
- Unauthorized Data Access: Attackers can access sensitive information stored on internal servers. 
- System Compromise: In some cases, SSRF can be leveraged to gain remote code execution on the target server. 
- Further Attacks: SSRF can be used as a stepping stone to launch other attacks, such as cross-site scripting (XSS) or SQL injection. 

In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources. An SSRF vulnerability allows an attacker to make requests originating from the server.
Types:
- Blind SSRF - Allows to scan for accessible hosts and ports
- Full Response - Allows you to see the entire response from the server
- Limited or No Response - Shows a portion of the response like the title of the page or No Response or you have access to resources but can't see them directly

Potential Blockers:
- Whitelisting - Only allows a few domain names to be used in the request
- Blacklisting - Block access to internal IP addresses, domains or keywords
- Restricted Content-Type, extensions, or characters - Only allows a particular file type
- No Response - You may not be able to see the response from the request to fetch data from domains

Potential Solutions:
- Whitelisting - Finding an open redirect
- Blacklisting - Creating a custom CNAME and pointing it to our internal IP address on our target
- Restricted Content-Type, extensions, or characters - Manual fuzzing and creating a bypass
- No Response - JavaScript XHR request to retrieve file contents

Things to keep in mind while fuzzing for SSRF:
- You are making a server side request
- You are browsing content that is rendering on the host machine
- There are different ways to look for content on localhost other than “localhost” or 127.0.0.1
- You may need to use an open redirect to redirect the machine to your destination host
- The current host may be able to communicate with other machines on the network (that may require being on corporate VPN)
- Make sure the request comes from the remote server and not your personal IP address
Tldr: You have a “browser” that's rendering web pages for you on the host machine.

What IP address can be used to find meta data information from cloud machines?
The IP address 169.254.169.254 is a well-known, non-routable address used by cloud platforms like Google Cloud, AWS, and Azure to provide instance metadata to virtual machines. This address acts as a local endpoint within the cloud environment, allowing instances to retrieve information about themselves, such as their ID, configuration, and other relevant data. 