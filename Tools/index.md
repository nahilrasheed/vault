# Asset Discovery
- subfinder
- amass
# Information Gathering
- httpx
- httprobe
- waymore
- waybackurl - https://github.com/tomnomnom/waybackurls
- getallurl
# Proxy / fuzzing
- [[Burpsuite]]
- [[Caido]]
# Content Discovery
-  [[ffuf]]
# Efficiency
- anew - https://github.com/tomnomnom/anew
# JS
- linkfinder - https://github.com/GerbenJavado/LinkFinder
- sourcemapper 
# Social Enginnering
- [[Social-Engineer Toolkit (SET)|Social-Engineer Toolkit (SET)]]
- AdvPhishing - [GitHub - Ignitetch/AdvPhishing: This is Advance Phishing Tool ! OTP PHISHING](https://github.com/Ignitetch/AdvPhishing)

---
# Vulnerability scanners

- OpenVAS
	- OpenVAS is an open-source vulnerability scanner that was created by Greenbone Networks. The OpenVAS framework includes several services and tools that enable you to perform detailed vulnerability scanning against hosts and networks.
	- [[Greenbone Vulnerability Management (GVM)|Greenbone Vulnerability Management (GVM)]] 
- [[Nessus]]
- Nexpose
	- Nexpose is a vulnerability scanner created by Rapid7 that is very popular among professional penetration testers. It supports integrations with other security products.
	- Rapid7 also has several vulnerability scanning solutions that are used for vulnerability management, continuous monitoring, and secure development lifecycle.
- Qualys
	- Qualys is a security company that created one of the most popular vulnerability scanners in the industry. It also has a cloud-based service that performs continuous monitoring, vulnerability management, and compliance checking. This cloud solution interacts with cloud agents, virtual scanners, scanner appliances, and Internet scanners.
	- [https://www.qualys.com](https://www.qualys.com/)
- [[SQLmap]]
- [[Nikto]]
- OWASP Zed Attack Proxy (ZAP)
	- According to OWASP, **_OWASP Zed Attack Proxy (ZAP)_** “is one of the world’s most popular free security tools and is actively maintained by hundreds of international volunteers.” Many offensive and defensive security engineers around the world use ZAP, which not only provides web vulnerability scanning capabilities but also can be used as a sophisticated web proxy. ZAP comes with an API and also can be used as a fuzzer. You can download and obtain more information about OWASP ZAP from [_https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project_](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project).
- w3af
	- Another popular open-source web application vulnerability scanner is **_w3af_**. w3af can be downloaded from [_https://w3af.org_](https://w3af.org/), and its documentation can be obtained from [_https://w3af.org/howtos_](https://w3af.org/howtos).
	- The w3af tool has a plugins menu that allows you to configure and enable mangle, crawl, bruteforce, audit, and other plugins. When you are in the plugins mode, you can use the **list audit** command to list all the available audit plugins.
	- w3af tool being configured to perform an SQL injection audit against the web server with IP address 10.1.1.14.
		```
		w3af/plugins>>> audit sqli
		w3af/plugins>>> back
		w3af>>> target
		w3af/config:target>>> set target http://10.1.1.14
		w3af/config:target>>> back
		The configuration has been saved.
		w3af>>> start
		```
- DirBuster
	- _DirBuster_ is a tool that was designed to brute force directory names and filenames on web application servers. DirBuster is currently an inactive project, and its functionality has been integrated into and enhanced in OWASP ZAP as an add-on.
	- DirBuster is a Java application designed to brute force directories and filenames on web/application servers. Often what looks like a web server with a default installation actually has pages and applications hidden within it. DirBuster attempts to find these. 
	- Two few additional alternatives to DirBuster are **_gobuster_** ([_https://github.com/OJ/gobuster_](https://github.com/OJ/gobuster)) and ffuf ([_https://github.com/ffuf/ffuf_](https://github.com/ffuf/ffuf)). 
- Brakeman - [https://brakemanscanner.org/](https://brakemanscanner.org/)  
- Open Security Content Automation Protocol (SCAP) scanners - [https://www.open-scap.org/](https://www.open-scap.org/)  
- Wapiti - [https://wapiti.sourceforge.io/](https://wapiti.sourceforge.io/)  
- Scout Suite - [https://github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)  
- WPScan - [https://wpscan.org/?](https://wpscan.org/?)

OWASP lists additional vulnerability scanning tools at [_https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools_](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools).
# Credential Attacks / Bruteforce attack
- [[John the Ripper]]
- Cain and Abel
	- **_Cain_** (or Cain and Abel) is a tool that can be used to “recover” passwords of Windows-based systems. Cain and Abel can be used to decipher and recover user credentials by performing packet captures (sniffing); cracking encrypted passwords by using dictionary, brute-force, and cryptanalysis attacks; and using many other techniques. Cain and Abel is a legacy tool, and archived information about it can be obtained from [_https://sectools.org/tool/cain/_](https://sectools.org/tool/cain/).
- [[Hashcat]]
- [[Hydra]]
- [[rainbowcrack]]
- Medusa and Ncrack
	- The **_Medusa_** and Ncrack tools, which are similar to Hydra, can be used to perform brute-force credential attacks against a system. You can install Medusa by using the **apt install medusa** command in a Debian-based Linux system (such as Ubuntu, Kali Linux, or Parrot OS). You can download Ncrack from [_https://nmap.org/ncrack_](https://nmap.org/ncrack) or install it by using the **apt install ncrack** command.
	- how Ncrack can be used to perform a brute-force attack with the username chris and the wordlist my_list against an SSH server with IP address 172.18.104.166.
		- ` ncrack -p 22 --user chris -P my_list 172.18.104.166`
	- Using Medusa to Perform a Brute-Force Attack
		- `medusa -u chris -P my_list -h 172.18.104.166 -M ssh`
- CeWL
	- **_CeWL_** is a great tool that can be used to create wordlists. You can use CeWL to crawl websites and retrieve words. 
	- You can download CeWL from [_https://digi.ninja/projects/cewl.php_](https://digi.ninja/projects/cewl.php).
	- Using CeWL to Create Wordlists: `cewl -d 2 -m 5 -w words.txt [website url]`
- Mimikatz
	- **_Mimikatz_** is a tool that many penetration testers and attackers (and even malware) use for retrieving password hashes from memory. It is also a useful post-exploitation tool. 
	- The Mimikatz tool can be downloaded from [_https://github.com/gentilkiwi/mimikatz_](https://github.com/gentilkiwi/mimikatz). 
	- Metasploit also includes Mimikatz as a Meterpreter script to facilitate exploitation without the need to upload any files to the disk of the compromised host. You can obtain more information about the Mimikatz and Metasploit integration at [_https://www.offsec.com/metasploit-unleashed/mimikatz/_](https://www.offsec.com/metasploit-unleashed/mimikatz/).
- Patator
	- **_Patator_** is another tool that can be used for brute-force attacks on enumerations of SNMPv3 usernames, VPN passwords, and other types of credential attacks. 
	- You can download Patator from [_https://github.com/lanjelot/patator_](https://github.com/lanjelot/patator).
- pdfcrack
	- crack password protected pdfs
	- `pdfcrack -f file.pdf -w /usr/share/wordlists/rockyou.txt`
- fcrackzip
	- crack password protected zip files
	- 
#  Persistence 
- [[Netcat]]
- Powershell
- **_PowerSploit_** 
	- is a collection of PowerShell modules that can be used for post- exploitation and other phases of an assessment. 
	- PowerSploit can be downloaded from [_https://github.com/PowerShellMafia/PowerSploit_](https://github.com/PowerShellMafia/PowerSploit).
- Empire
	- Empire is a PowerShell-based post-exploitation framework that is very popular among pen testers. Empire is an open-source framework that includes a PowerShell Windows agent and a Python Linux agent.
	- You can download Empire from [_https://github.com/EmpireProject/Empire_](https://github.com/EmpireProject/Empire).
	- Empire implements the ability to run PowerShell agents without the need for powershell.exe. It allows you to rapidly deploy post-exploitation modules including keyloggers, reverse shells, Mimikatz, and adaptable communications to evade detection.
- Remote Access Protocols
	- Microsoft’s Remote Desktop Protocol (RDP)
	- Apple Remote Desktop
	- VNC
	- X server forwarding
# Evasion
- [[Veil]]
- Tor
	- Many people use tools such as Tor for privacy. Tor is a free tool that enables its users to surf the Web anonymously. Tor works by “routing” IP traffic through a free worldwide network consisting of thousands of Tor relays. It constantly changes the way it routes traffic in order to obscure a user’s location from anyone monitoring the network. Tor’s name is an acronym of the original software project’s name, “The Onion Router.”
	- Tor enables users to evade and circumvent security monitoring and controls because it’s hard to attribute and trace back the traffic to the user. Its “onion routing” is accomplished by encrypting the application layer of a communication protocol stack that’s “nested” much like the layers of an onion. The Tor client encrypts the data multiple times and sends it through a network or circuit that includes randomly selected Tor relays. Each of the relays decrypts a layer of the onion to reveal only the next relay so that the remaining encrypted data can be routed on to it.
	- A Tor exit node is basically the last Tor node, or the “gateway,” where the Tor encrypted traffic “exits” to the Internet. A Tor exit node can be targeted to monitor Tor traffic. Many organizations block Tor exit nodes in their environment. The Tor project has a dynamic list of Tor exit nodes that makes this task a bit easier.
- Proxychains
	- Proxychains can be used for evasion, as it is a tool that forces any TCP connection made by a specified application to use Tor or any other SOCKS4, SOCKS5, HTTP, or HTTPS proxy. 
	- You can download Proxychains from https://github.com/haad/proxychains.
- Encryption
### Encapsulation and Tunneling Using DNS and Protocols Such as NTP
Threat actors have used many different nontraditional techniques to steal data from corporate networks without being detected. For example, they have sent stolen credit card data, intellectual property, and confidential documents over DNS by using tunneling. As you probably know, DNS is a protocol that enables systems to resolve domain names (for example, theartofhacking.org) into IP addresses (for example, 104.27.176.154). DNS is not intended for a command channel or even tunneling. However, attackers have developed software that enables tunneling over DNS. These threat actors like to use protocols that are not designed for data transfer because they are less inspected in terms of security monitoring. Undetected DNS tunneling (also known as _DNS exfiltration_ ) presents a significant risk to any organization.

In many cases, malware uses Base64 encoding to put sensitive data (such as credit card numbers and personally identifiable information) in the payload of DNS packets to cybercriminals. The following are some examples of encoding methods that attackers may use:
- Base64 encoding
- Binary (8-bit) encoding
- NetBIOS encoding
- Hex encoding

Several utilities have been created to perform DNS tunneling (for good reasons as well as harmful). The following are a few examples:
- **DeNiSe:** This Python tool is for tunneling TCP over DNS. You can download DeNiSe from [_https://github.com/mdornseif/DeNiSe_](https://github.com/mdornseif/DeNiSe).
- **dns2tcp:** Written by Olivier Dembour and Nicolas Collignon in C, dns2tcp supports KEY and TXT request types. You can download dns2tcp from [_https://github.com/alex-sector/dns2tcp_](https://github.com/alex-sector/dns2tcp).
- **DNScapy:** Created by Pierre Bienaimé, this Python-based Scapy tool for packet generation even supports SSH tunneling over DNS, including a SOCKS proxy. You can download DNScapy from [_https://github.com/FedericoCeratto/dnscapy_](https://github.com/FedericoCeratto/dnscapy).
- **DNScat or DNScat-P:** This Java-based tool, created by Tadeusz Pietraszek, supports bidirectional communication through DNS. You can download DNScat from [_https://github.com/iagox86/dnscat2_](https://github.com/iagox86/dnscat2).
- **DNScat2 (DNScat-B):** Written by Ron Bowes, this tool runs on Linux, macOS, and Windows. DNScat2 encodes DNS requests in NetBIOS encoding or hex encoding. You can download DNScat2 from [_https://github.com/iagox86/dnscat2_](https://github.com/iagox86/dnscat2).
- **Heyoka:** This Windows-based tool written in C supports bidirectional tunneling for data exfiltration. You can download Heyoka from [_http://heyoka.sourceforge.net_](http://heyoka.sourceforge.net/).
- **iodine:** Written by Bjorn Andersson and Erik Ekman in C, iodine runs on Linux, macOS, and Windows, and it can even be ported to Android. You can download iodine from [_https://code.kryo.se/iodine/_](https://code.kryo.se/iodine/).
- **sods:** Originally written in Perl by Dan Kaminsky, this tool is used to set up an SSH tunnel over DNS or for file transfer. The requests are Base32 encoded, and responses are Base64-encoded TXT records. You can download sods from [_https://github.com/msantos/sods_](https://github.com/msantos/sods).
- **psudp:** Developed by Kenton Born, this tool injects data into existing DNS requests by modifying the IP/UDP header lengths. You can obtain additional information about psudp from [_https://pdfs.semanticscholar.org/0e28/637370748803bcefa5b89ce8b48cf0422adc.pdf_](https://pdfs.semanticscholar.org/0e28/637370748803bcefa5b89ce8b48cf0422adc.pdf).
- **Feederbot and Moto:** Attackers have used this malware with DNS to steal sensitive information from many organizations. You can obtain additional information about these tools from [_https://chrisdietri.ch/post/feederbot-botnet-using-dns-command-and-control/_](https://chrisdietri.ch/post/feederbot-botnet-using-dns-command-and-control/).
Some of these tools were not created for stealing data, but cybercriminals have appropriated them for their own purposes.
# Exploitation Frameworks
- [[Metasploit]]
- [[Browser Exploitation Framework (BeEF)|Browser Exploitation Framework (BeEF)]]
# Decompilation, Disassembly, and Debugging Tools
- The GNU Project Debugger (GDB)
	- The GNU Project Debugger (**_GDB_**) is one of the most popular debuggers among software developers and security professionals. With a debugger like GDB, you can troubleshoot and find software bugs, understand what a program was doing at the moment it crashed, make a program stop on specified conditions, and modify elements of a program to experiment or to correct problems.
	- Traditionally, GDB has mainly been used to debug programs written in C and C++; however, several other programming languages – such as Go, Objective-C, and OpenCL C – are also supported.
	-  [https://www.gnu.org/software/gdb](https://www.gnu.org/software/gdb)
	- The website [_https://www.cprogramming.com/gdb.html_](https://www.cprogramming.com/gdb.html) includes additional examples of how to use GDB for debugging applications.
- Windows Debugger
	- You can use the Windows Debugger (**_WinDbg_**) to debug kernel and user mode code. You can also use it to analyze crash dumps and to analyze the CPU registers as code executes. 
	- You can get debugging tools from Microsoft via the following methods:
		- By downloading and installing the Windows Driver Kit (WDK)
		- As a standalone tool set
		- By downloading the Windows Software Development Kit (SDK)
		- By downloading Microsoft Visual Studio
	- Refer to the “Getting Started with Windows Debugging Microsoft” whitepaper to learn how to use WinDbg and related tools; see [_https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windows-debugging_](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windows-debugging). You can obtain additional information about Windows debugging and symbols from [_https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols_](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols).
- OllyDbg
	- **_OllyDbg_** is a debugger created to analyze Windows 32-bit applications. It is included in Kali Linux and other penetration testing distributions.
	- It can also be downloaded from [_https://www.ollydbg.de_](https://www.ollydbg.de/).
- edb Debugger
	- The edb debugger (often called Evan’s debugger) is a cross-platform debugger that supports AArch32, x86, and x86-64 architectures. 
	- It comes by default with Kali Linux, and it can be downloaded from [_https://github.com/eteran/edb-debugger_](https://github.com/eteran/edb-debugger).
- Ghidra
	- **_Ghidra_** is a powerful and free tool popular among security researchers for reverse engineering and binary analysis. Developed by the NSA, Ghidra provides comprehensive capabilities for dissecting and understanding complex software, including malware analysis and vulnerability research. 
	- Its standout feature is a built-in decompiler that makes analyzing binary code more accessible. While it does not directly support exploit development, Ghidra's extensive scripting capabilities (with Java and Python-based APIs) allow users to create custom analysis scripts. 
	- You can download Ghidra from [_https://www.ghidra-sre.org/_](https://www.ghidra-sre.org/).
- Interactive Disassembler (IDA)
	- **_Interactive Disassembler (IDA)_** is one of the most popular disassemblers, debuggers, and decompilers on the market. 
	- IDA is a commercial product of Hex-Rays, and it can be purchased from [_https://www.hex-rays.com/products/ida/index.shtml_](https://www.hex-rays.com/products/ida/index.shtml).
	- Introduction to IDA: [_https://resources.infosecinstitute.com/basics-of-ida-pro-2/_](https://resources.infosecinstitute.com/basics-of-ida-pro-2/).
- Objdump
	- Objdump is a Linux program that can be used to display information about one or more object files. You can use Objdump to do quick checks and disassembly of binaries
- BinaryNinja
	- Binary Ninja is a reverse-engineering platform developed by Vector 35 Inc. It allows users to disassemble a binary file and visualize the disassembly in both linear and graph-based views. The software performs automated, in-depth code analysis, generating information that helps to analyze a binary. 
	- Better UI compared to ghidra.
	- [https://binary.ninja](https://binary.ninja/)
- list of numerous tools that can be used for reverse engineering: [_https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/reverse_engineering_](https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/reverse_engineering).
# Forensics
- **ADIA (Appliance for Digital Investigation and Analysis)**: ADIA is a VMware-based appliance used for digital investigation and acquisition that is built entirely from public domain software. Among the tools contained in ADIA are Autopsy, the Sleuth Kit, the Digital Forensics Framework, log2timeline, Xplico, and Wireshark. Most of the system maintenance uses Webmin. ADIA is designed for small to medium-sized digital investigations and acquisitions. The appliance runs under Linux, Windows, and macOS. Both i386 (32-bit) and x86_64 (64-bit) versions are available. You can download ADIA from [[https://forensics.cert.org/#ADIA_](https://forensics.cert.org/#ADIA_](https://forensics.cert.org/#ADIA_](https://forensics.cert.org/#ADIA_](https://forensics.cert.org/#ADIA]].
- **CAINE**: The Computer Aided Investigative Environment (CAINE) contains numerous tools that help investigators with analyses, including forensic evidence collection. You can download CAINE from [_http://www.caine-live.net/index.html_](http://www.caine-live.net/index.html).
- **Skadi**: This all-in-one solution to parsing collected data makes the data easily searchable with built-in common searches and enables searching of single and multiple hosts simultaneously. You can download Skadi from [_https://github.com/orlikoski/Skadi_](https://github.com/orlikoski/Skadi).
- **PALADIN**: PALADIN is a modified Linux distribution for performing various evidence collection tasks in a forensically sound manner. It includes many open source forensics tools. You can download PALADIN from [_https://sumuri.com/software/paladin/_](https://sumuri.com/software/paladin/).
- **Security Onion**: Security Onion, a Linux distro aimed at network security monitoring, features advanced analysis tools, some of which can help in forensic investigations. You can download Security Onion from [_https://github.com/Security-Onion-Solutions/security-onion_](https://github.com/Security-Onion-Solutions/security-onion).
- **SIFT Workstation**: The SANS Investigative Forensic Toolkit (SIFT) Workstation demonstrates that advanced incident response capabilities and deep-dive digital forensic techniques to intrusions can be accomplished using cutting-edge open source tools that are freely available and frequently updated. You can download SIFT Workstation from [_https://digital-forensics.sans.org/community/downloads_](https://digital-forensics.sans.org/community/downloads).

A list of numerous tools that can be used for forensics: [_https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/dfir_](https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/dfir).
# Software Assurance
to perform software and protocol robustness tests, including fuzzers and code analysis tools.
- SpotBugs, Findsecbugs, and SonarQube
	- _SpotBugs_ (previously known as Findbugs) is a static analysis tool designed to find bugs in applications created in the Java programming language. You can download and obtain more information about SpotBugs at [_https://spotbugs.github.io_](https://spotbugs.github.io/).
	- _Findsecbugs_ is another tool designed to find bugs in applications created in the Java programming language. It can be used with continuous integration systems such as Jenkins and SonarQube. Findsecbugs provides support for popular Java frameworks, including Spring-MCV, Apache Struts, and Tapestry. You can download and obtain more information about Findbugs at [_https://find-sec-bugs.github.io_](https://find-sec-bugs.github.io/).
	- _SonarQube_ is a tool that can be used to find vulnerabilities in code, and it provides support for continuous integration and DevOps environments. You can obtain additional information about SonarQube at [_https://www.sonarqube.org_](https://www.sonarqube.org/).
- Fuzzers and Fuzz Testing
	- _Fuzz testing_, or _fuzzing_ , is a technique that can be used to find software errors (or bugs) and security vulnerabilities in applications, operating systems, infrastructure devices, IoT devices, and other computing device. Fuzzing involves sending random data to the unit being tested in order to find input validation issues, program failures, buffer overflows, and other flaws. Tools that are used to perform fuzzing are referred to as _fuzzers_. Examples of popular fuzzers are Peach, Mutiny Fuzzing Framework, and American Fuzzy Lop.
- Peach
	- Peach is one of the most popular fuzzers in the industry. There is a free (open-source) version, the Peach Fuzzer Community Edition, and a commercial version. You can download the Peach Fuzzer Community Edition and obtain additional information about the commercial version at [_https://osdn.net/projects/sfnet_peachfuzz/releases/_](https://osdn.net/projects/sfnet_peachfuzz/releases/).
- Mutiny Fuzzing Framework
	- The Mutiny Fuzzing Framework is an open-source fuzzer created by Cisco. It works by replaying packet capture files (pcaps) through a mutational fuzzer. You can download and obtain more information about Mutiny Fuzzing Framework at [_https://github.com/Cisco-Talos/mutiny-fuzzer_](https://github.com/Cisco-Talos/mutiny-fuzzer).
	- The Mutiny Fuzzing Framework uses Radamsa to perform mutations. Radamsa is a tool that can be used to generate test cases for fuzzers. You can download and obtain additional information about Radamsa at [_https://gitlab.com/akihe/radamsa_](https://gitlab.com/akihe/radamsa).
- American Fuzzy Lop
	- American Fuzzy Lop (AFL) is a tool that provides features of compile-time instrumentation and genetic algorithms to automatically improve the functional coverage of fuzzing test cases. You can obtain information about AFL from [_https://lcamtuf.coredump.cx/afl/_](https://lcamtuf.coredump.cx/afl/).
# Wireless Tools
- [[Aircrack-ng]]
- Wifite2: 
	- This is a Python program to test wireless networks that can be downloaded from [_https://github.com/derv82/wifite2_](https://github.com/derv82/wifite2).
- Rogue access points: 
	- You can easily create rogue access points by using open-source tools such as hostapd. Omar Santos has a description of how to build your own wireless hacking lab and use hostapd at [_https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless_resources/virtual_adapters.md_](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless_resources/virtual_adapters.md).
- EAPHammer: 
	- This tool, which you can use to perform evil twin attacks, can be downloaded from [_https://github.com/s0lst1c3/eaphammer_](https://github.com/s0lst1c3/eaphammer).
- mdk4: 
	- This tool is used to perform fuzzing, IDS evasions, and other wireless attacks. mdk4 can be downloaded from [_https://github.com/aircrack-ng/mdk4_](https://github.com/aircrack-ng/mdk4).
- Spooftooph: 
	- This tool is used to spoof and clone Bluetooth devices. It can be downloaded from [_https://gitlab.com/kalilinux/packages/spooftooph_](https://gitlab.com/kalilinux/packages/spooftooph).
- Reaver: 
	- This tool is used to perform brute-force attacks against Wi-Fi Protected Setup (WPS) implementations. Reaver can be downloaded from [_https://gitlab.com/kalilinux/packages/reaver_](https://gitlab.com/kalilinux/packages/reaver).
- Wireless Geographic Logging Engine (WiGLE): 
	- You can learn about this war driving tool at [_https://wigle.net_](https://wigle.net/).
- Fern Wi-Fi Cracker: 
	- This tool is used to perform different attacks against wireless networks, including cracking WEP, WPA, and WPS keys. You can download Fern Wi-Fi Cracker from [_https://gitlab.com/kalilinux/packages/fern-wifi-cracker_](https://gitlab.com/kalilinux/packages/fern-wifi-cracker).
# Steganography Tools
- Soteghide
	- Steghide is a steganography program used to hide data within various image and audio file formats. It allows users to embed secret information, like text files or other data, into seemingly ordinary files, making it difficult to detect the hidden content. Steghide supports encryption of embedded data, compression, and verification using a checksum. 
- **OpenStego:** You can download this steganography tool from [_https://www.openstego.com_](https://www.openstego.com/).
- **snow:** This is a text-based steganography tool that can be downloaded from [_https://github.com/mattkwan-zz/snow_](https://github.com/mattkwan-zz/snow).
- **Coagula:** This program, which can be used to make sound from an image, can be downloaded from [_https://www.abc.se/~re/Coagula/Coagula.html_](https://www.abc.se/~re/Coagula/Coagula.html).
- **Sonic Visualiser:** This tool can be used to analyze embedded information in music or audio recordings. It can be downloaded from [_https://www.sonicvisualiser.org_](https://www.sonicvisualiser.org/).
- **TinEye:** This is a reverse image search website at [_https://tineye.com_](https://tineye.com/).
- **metagoofil:** This tool can be used to extract metadata information from documents and images. You can download metagoofil from [_https://github.com/laramies/metagoofil_](https://github.com/laramies/metagoofil).
# Cloud Tools
- **ScoutSuite:** This collection of tools can be used to reveal vulnerabilities in AWS, Azure, Google Cloud Platform, and other cloud platforms. You can download ScoutSuite from [_https://github.com/nccgroup/ScoutSuite_](https://github.com/nccgroup/ScoutSuite).
- **CloudBrute:** You can download this cloud enumeration tool from [_https://github.com/0xsha/CloudBrute_](https://github.com/0xsha/CloudBrute).
- **Pacu:** This is a framework for AWS exploitation that can be downloaded from [_https://github.com/RhinoSecurityLabs/pacu_](https://github.com/RhinoSecurityLabs/pacu).
- **Cloud Custodian:** This cloud security, governance, and management tool can be downloaded from [_https://cloudcustodian.io_](https://cloudcustodian.io/).
