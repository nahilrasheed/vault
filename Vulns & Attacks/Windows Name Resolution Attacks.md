## Windows Name Resolution
Name resolution is one of the most fundamental aspects of networking, operating systems and applications. There are several name-to-IP address resolution technologies and protocols, including Network Basic Input/Output System (NetBIOS), Link-Local Multicast Name Resolution (LLMNR) and Domain Name System (DNS). The sections that follow cover vulnerabilities and exploits related to these protocols.

**NetBIOS** and **LLMNR** are protocols that are used primarily by Microsoft Windows for host identification. LLMNR, which is based on the DNS protocol format, allows hosts on the same local link to perform name resolution for other hosts. For example, a Windows host trying to communicate to a printer or to a network shared folder may use NetBIOS.

NetBIOS provides three different services:
- NetBIOS Name Service (NetBIOS-NS) for name registration and resolution
- Datagram Service (NetBIOS-DGM) for connectionless communication
- Session Service (NetBIOS-SSN) for connection-oriented communication

NetBIOS-related operations use the following ports and protocols:
- TCP port 135: Microsoft Remote Procedure Call (MS-RPC) endpoint mapper, used for client-to-client and server-to-client communication
- UDP port 137: NetBIOS Name Service
- UDP port 138: NetBIOS Datagram Service
- TCP port 139: NetBIOS Session Service
- TCP port 445: SMB protocol, used for sharing files between different operating systems, including Windows and Unix-based systems

**NOTE** Traditionally, a NetBIOS name was a 16-character name assigned to a computer in a workgroup by WINS for name resolution of an IP address to a NetBIOS name. Microsoft now uses DNS for name resolution.

In Windows, a workgroup is a local area network (LAN) peer-to-peer network that can support a maximum of 10 hosts in the same subnet. A workgroup has no centralized administration. Basically, each user controls the resources and security locally on his or her system. A domain-based implementation, on the other hand, is a client-to-server network that can support thousands of hosts that are geographically dispersed across many subnets. A user with an account on the domain can log on to any computer system without having an account on that computer. It does this by authenticating to a domain controller.

## WNR vulns
Historically, there have been dozens of vulnerabilities in NetBIOS, SMB and LLMNR. Let’s take a look at a simple example. The default workgroup name in Windows is the WORKGROUP. Many users leave their workgroup configured with this default name and configure file or printer sharing with weak credentials. It is very easy for an attacker to enumerate the machines and potentially compromise the system by brute-forcing passwords or leveraging other techniques.

A common vulnerability in LLMNR involves an attacker spoofing an authoritative source for name resolution on a victim system by responding to LLMNR traffic over UDP port 5355 and NBT-NS traffic over UDP port 137. The attacker basically poisons the LLMNR service to manipulate the victim’s system. If the requested host belongs to a resource that requires identification or authentication, the username and NTLMv2 hash are sent to the attacker. The attacker can then gather the hash sent over the network by using tools such as sniffers. Subsequently, the attacker can brute-force or crack the hashes offline to get the plaintext passwords.

> [!tldr] tldr
> Link-Local Multicast Name Resolution (LLMNR) and Netbios Name Service (NBT-NS) are two components of Microsoft Windows. They allow computers on the same subnet to help each other identify hosts when DNS fails. If one computer tries to resolve a particular host, but DNS resolution fails, the computer will then attempt to ask all others on the local network for the correct address via LLMNR or NBT-NS. An attacker can listen on the network for these LLMNR (UDP/5355) or NBT-NS (UDP/137) broadcasts and respond to them with false information, thus pretending that the attacker knows the location of the requested host. The attacker poisons the LLMNR service to manipulate the victim’s system. If the requested host belongs to a resource that requires identification or authentication, the username, and NTLMv2 hash are sent to the attacker. Subsequently, the attacker can brute-force or crack the hashes offline to discover the plaintext passwords.

Several tools can be used to conduct this type of attack, such as NBNSpoof, Metasploit, and Responder. Metasploit, of course, is one of the most popular tools and frameworks used by penetration testers and attackers. Another open-source tool that is very popular and has even been used by malware is Pupy, which is available on GitHub. Pupy is a Python-based cross-platform remote administration and post-exploitation tool that works on Windows, Linux, macOS and even Android.

> **TIP** One of the common mitigations for these types of attacks is to disable LLMNR and NetBIOS in local computer security settings or to configure a group policy. In addition, you can configure additional network- or host-based access controls policies (rules) to block LLMNR/NetBIOS traffic if these protocols are not needed. One of the common detection techniques for LLMNR poisoning attacks is to monitor the registry key HKLMSoftwarePolicies MicrosoftWindows NTDNSClient for changes to the EnableMulticast DWORD value. If you see a zero (0) for the value of that key, you know that LLMNR is disabled.