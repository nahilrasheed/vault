---
tags:
  - CyberSec
  - RedTeam
  - CiscoEH
---
# Types of Enumeration

- Host Enumeration
- User Enumeration
- Group Enumeration
- Network Share Enumeration
- Additional SMB Enumeration Examples
- Web Page Enumeration/Web Application Enumeration
- Service Enumeration
- Exploring Enumeration via Packet Crafting

## Host Enumeration
The enumeration of hosts is one of the first tasks you need to perform in the information-gathering phase of a penetration test. **_Host enumeration_** is performed internally and externally. When performed externally, you typically want to limit the IP addresses you are scanning to just the ones that are part of the scope of the test. This reduces the chance of inadvertently scanning an IP address that you are not authorized to test. When performing an internal host enumeration, you typically scan the full subnet or subnets of IP addresses being used by the target. Host enumeration is usually performed using a tool such as Nmap or Masscan; however, vulnerability scanners also perform this task as part of their automated testing. 

## User Enumeration
Gathering a valid list of users is the first step in cracking a set of credentials. When you have the username, you can then begin brute-force attempts to get the account password. You perform **_user enumeration_** when you have gained access to the internal network. On a Windows network, you can do this by manipulating the Server Message Block (SMB) protocol, which uses TCP port 445. 

The information contained in the responses to these messages enables you to reveal information about the server:
- **SMB_COM_NEGOTIATE:** This message allows the client to tell the server what protocols, flags, and options it would like to use. The response from the server is also an SMB_COM_NEGOTIATE message. This response is relayed to the client about which protocols, flags, and options it prefers. This information can be configured on the server itself. A misconfiguration sometimes reveals information that you can use in penetration testing. For instance, the server might be configured to allow messages without signatures. You can determine if the server is using share- or user-level authentication mechanisms and whether the server allows plaintext passwords. The response from the server also provides additional information, such as the time and time zone the server is using. This is necessary information for many penetration testing tasks.
- **SMB_COM_SESSION_SETUP_ANDX** : After the client and server have negotiated the protocols, flags, and options they will use for communication, the authentication process begins. Authentication is the primary function of the SMB_COM_SESSION_SETUP_ANDX message. The information sent in this message includes the client username, password, and domain. If this information is not encrypted, it is easy to sniff it right off the network. Even if it is encrypted, if the mechanism being used is not sufficient, the information can be revealed using tools such as Lanman and NTLM in the case of Microsoft Windows implementations. The following example shows this message being used with the smb-enum-users.nse script:
`nmap --script smb-enum-users.nse <host>_`

## Group Enumeration

For a penetration tester, **_group enumeration_** is helpful in determining the authorization roles that are being used in the target environment. The Nmap NSE script for enumerating SMB groups is **smb-enum-groups**. This script attempts to pull a list of groups from a remote Windows machine. You can also reveal the list of users who are members of those groups. The syntax of the command is as follows:

`nmap --script smb-enum-groups.nse -p445 <host>_`

### **Network Share Enumeration**

Identifying systems on a network that are sharing files, folders, and printers is helpful in building out an attack surface of an internal network. The Nmap **smb-enum-shares** NSE script uses Microsoft Remote Procedure Call (MSRPC) for **_network share enumeration_**. The syntax of the Nmap **smb-enum-shares.nse** script is as follows:

`nmap --script smb-enum-shares.nse -p 445 <host>_`

**Additional SMB Enumeration Examples**

The system used in earlier examples (with the IP address 192.168.88.251) is running Linux and Samba. However, it is not easy to determine that it is a Linux system from the results of previous scans. An easy way to perform additional enumeration and fingerprinting of the applications and operating system running on a host is by using the **nmap -sC** command. The - **sC** option runs the most common NSE scripts based on the ports found to be open on the target system.

**NOTE** You can locate the installed NSE scripts in Kali Linux and Parrot OS by simply using the **locate *.nse** command. The site _[https://nmap.org/book/man-nse.html](https://nmap.org/book/man-nse.html)_ includes a detailed explanation of the NSE and how to create new scripts using the Lua programming language.

You can also use tools such as [[enum4linux]] to enumerate Samba shares, including user accounts, shares, and other configurations. 
There is a Python-based enum4linux implementation called enum4linux-ng that can be downloaded from _[https://github.com/cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng)_.

### Web Page Enumeration/Web Application Enumeration

Once you have identified that a web server is running on a target host, the next step is to take a look at the web application and begin to map out the attack surface performing **_web page enumeration_** or often referred to as **_web application enumeration_**. You can map out the attack surface of a web application in a few different ways. The handy Nmap tool actually has an NSE script available for brute forcing the directory and file paths of web applications. Armed with a list of known files and directories used by common web applications, it probes the server for each of the items on the list. Based on the response from the server, it can determine whether those paths exist. This is handy for identifying things like the Apache or Tomcat default manager page that are commonly left on web servers and can be potential paths for exploitation. The syntax of the http-enum NSE script is as follows:

`nmap -sV --script=http-enum <target>_`

Another web server enumeration tool we should talk about is [[Nikto]]. Nikto is an open-source web vulnerability scanner that has been around for many years. It’s not as robust as the commercial web vulnerability scanners; however, it is very handy for running a quick script to enumerate information about a web server and the applications it is hosting. Because of the speed at which Nikto works to scan a web server, it is very noisy. It provides a number of options for scanning, including the capability to authenticate to a web application that requires a username and password.

### Service Enumeration

**_Service enumeration_** is the process of identifying the services running on a remote system, and it is a primary focus of what Nmap does as a port scanner. Earlier discussion in this module highlights the various scan types and how they can be used to bypass filters. When you are connected to a system that is on a directly connected network segment, you can run some additional scripts to enumerate further. A port scan takes the perspective of a credentialed remote user. The Nmap **smb-enum-processes** NSE script enumerates services on a Windows system, and it does so by using credentials of a user who has access to read the status of services that are running. This is a handy tool for remotely querying a Windows system to determine the exact list of services running. The syntax of the command is as follows:

`nmap --script smb-enum-processes.nse --script-args smbusername=<username>_**, smbpass=**_<password>_ **-p445** _<host>_`

---
- [[Nmap]]
- Exploring Enumeration via Packet Crafting using [[scapy]] 
