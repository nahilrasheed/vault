---
tags:
  - CyberSec/tools
  - CiscoEH
---
[Nmap](https://nmap.org/) (Network Mapper) is a powerful, open-source tool used for network discovery, security auditing, and network inventory. Nmap can be used to scan networks, discover hosts, identify open ports, detect operating systems, and even run scripts to automate tasks.

## nmap usage

	nmap -T4 -p- -A [ip]

- -p -> ports to scan 
	- -p- -> scan all ports
	- blank -> scans top 1000 ports
	- -p 443,80

| Option           | Description                                                                                              |
| ---------------- | -------------------------------------------------------------------------------------------------------- |
| -A               | Aggressive scan that enables OS detection, version detection, script scanning and traceroute             |
| -O               | Enables OS detection                                                                                     |
| -p <port ranges> | Allows for specific ports or port ranges to be scanned                                                   |
| -sF              | Performs TCP FIN scan                                                                                    |
| -sn              | Performs host discovery scan                                                                             |
| -sS              | Performs TCP SYN scan                                                                                    |
| -sT              | Performs TCP Connect scan                                                                                |
| -sU              | Performs UDP scan                                                                                        |
| -sV              | Probes open ports to determine service/version info                                                      |
| -T<0-5>          | Sets the timing of the scan. Higher numbers produce results faster. Slower scans elude detection better. |
| -v               | Increases the verbosity of the output                                                                    |
| --open           | Only reports open (or possibly open) ports                                                               |

---
## Nmap Scan Types
### Nmap SYN scan (-sS)
With an Nmap SYN scan, the tool sends a TCP SYN packet to the TCP port it is probing. This process is also referred to as half-open scanning because it does not open a full TCP connection.
 #### **SYN Scan Responses** 
| Nmap Port Status Reported | Response from Target                                    | Nmap Analysis                             |
| ------------------------- | ------------------------------------------------------- | ----------------------------------------- |
| Open                      | TCP SYN-ACK                                             | The service is listening on the port.     |
| Closed                    | TCP RST                                                 | The service is not listening on the port. |
| Filtered                  | No response from target or ICMP destination unreachable | The port is firewalled.                   |
###  TCP Connect Scan (**-sT**)
A TCP connect scan actually makes use of the underlying operating system’s networking mechanism to establish a full TCP connection with the target device being scanned. Because it creates a full connection, it creates more traffic (and thus takes more time to run). This is the default scan type that is used if no scan type is specified with the **nmap** command. However, it should typically be used only when a SYN scan is not an option, such as when a user who is running the **nmap** command does not have raw packet privileges on the operating system because many of the Nmap scan types rely on writing raw packets. 
 #### **TCP Connect Scan Responses** 
|**Nmap Port Status Reported**|**Response from Target**|**Nmap Analysis**|
|---|---|---|
|Open|TCP SYN-ACK|The service is listening on the port.|
|Closed|TCP RST|The service is not listening on the port.|
|Filtered|No response from target|The port is firewalled.|
A full TCP connect scan requires the scanner to send an additional packet per scan, which increases the amount of noise on the network and may trigger alarms that a half-open scan wouldn’t trigger. Security tools and the underlying targeted system are more likely to log a full TCP connection.
### UDP Scan ( -sU )
The majority of the time, you will be scanning for TCP ports, as this is how you connect to most services running on target systems. However, you might encounter some instances in which you need to scan for UDP ports – for example, if you are trying to enumerate a DNS, SNMP, or DHCP server. These services all use UDP for communication between client and server. To scan UDP ports, Nmap sends a UDP packet to all ports specified in the command-line configuration. It waits to hear back from the target. If it receives an ICMP port unreachable message back from a target, that port is marked as closed. If it receives no response from the target UDP port, Nmap marks the port as open/filtered. 
 #### **UDP Scan Responses**
| **Nmap Port Status Reported** | **Response from Target**     | **Nmap Analysis**                         |
| ----------------------------- | ---------------------------- | ----------------------------------------- |
| Open                          | Data returned from port      | The service is listening on the port.     |
| Closed                        | ICMP error message received  | The service is not listening on the port. |
| Open/filtered                 | No ICMP response from target | The port is firewalled or timed out.      |
### TCP FIN Scan ( -sF )
There are times when a SYN scan might be picked up by a network filter or firewall. In such a case, you need to employ a different type of packet in a port scan. With the TCP FIN scan, a FIN packet is sent to a target port. If the port is actually closed, the target system sends back an RST packet. If nothing is received from the target port, you can consider the port open because the normal behavior would be to ignore the FIN packet.
>**NOTE** A TCP FIN scan is not useful when scanning Windows-based systems, as they respond with RST packets, regardless of the port state.

 #### **TCP FIN Scan Responses**
| **Nmap Port Status Reported** | **Response from Target**        | **Nmap Analysis**                    |
| ----------------------------- | ------------------------------- | ------------------------------------ |
| Filtered                      | ICMP unreachable error received | Closed port should respond with RST. |
| Closed                        | RST packet received             | Closed port should respond with RST. |
| Open/Filtered                 | No response received            | Open port should drop FIN.           |
### Host Discovery Scan ( -sn )
A host discovery scan is one of the most common types of scans used to enumerate hosts on a network because it can use different types of ICMP messages to determine whether a host is online and responding on a network.
>**NOTE** The default for the -sn scan option is to send an ICMP echo request packet to the target, a TCP SYN to port 443, a TCP ACK to port 80, and an ICMP timestamp request. This is documented at _[https://nmap.org/book/man-host-discovery.html](https://nmap.org/book/man-host-discovery.html)_. If the target responds to the ICMP echo or the aforementioned packets, then it is considered alive.
### Timing Options ( -T 0-5 )
The Nmap scanner provides six timing templates that can be specified with the **-T** option and the template number (0 through 5) or name. Nmap timing templates enable you to dictate how aggressive a scan will be, while leaving Nmap to pick the exact timing values. These are the timing options:
- **-T0 (Paranoid)** : Very slow, used for IDS evasion
- **-T1 (Sneaky)** : Quite slow, used for IDS evasion
- **-T2 (Polite)** : Slows down to consume less bandwidth, runs about 10 times slower than the default
- **-T3 (Normal)** : Default, a dynamic timing model based on target responsiveness
- **-T4 (Aggressive)** : Assumes a fast and reliable network and may overwhelm targets
- **-T5 (Insane)** : Very aggressive; will likely overwhelm targets or miss open ports

## Nmap Scripting Engine
Nmap contains the powerful Nmap Scripting Engine (NSE), which enables the programming of various Nmap options and conditional actions to be taken as a result of the responses. NSE has built-in scripts that enumerate users, groups, and network shares. 
- In Kali Linux, the NSE scripts are located at /usr/share/nmap/scripts by default.
- One of the more commonly used scripts for SMB discovery is the smb-enum-users.nse script. 
- You can enumerate the network shares using another NSE script, **smb-enum-shares.nse.** To discover shared directories on the target computer.  `nmap --script smb-enum-shares.nse -p445 [ip]`
	Examine the output created by the smb-enum-shares script. In the output, share names that end with a “$” character represent hidden shares that include system and administrative shares.
## Nmap Vulners script to scan for vulnerabilities.
The Vulners script displays known vulnerabilities and the corresponding CVE. The Vulners script uses the open port and software version information to search for common platform enumeration (CPE) names that relate to the identified service. It then makes a request to a remote server to find out if any known vulnerabilities exist for that CPE.

Use the `nmap –script` command to launch the **vulners** script. The syntax for the command is `nmap -sV --script vulners [--script-args mincvss=<arg_val>] <target>` where the script argument **mincvss** restricts the output to only those CVEs that have a higher CVSS score than the one specified in the argument.

eg:
1. There are multiple scripts available to find valid usernames using Nmap. One of the most common is the SMB username script. It is a common practice to synchronize OS Users with SMB (Samba or Windows) users. Use the Nmap script **smb-brute** to find users and to attempt to brute force passwords.
	`sudo nmap -sV -p 445 -script smb-brute 172.17.0.2`
	-  Locate the **Host script results** section in the command output. Username and password combinations that were uncovered with the Nmap script are listed in this section.

---
## Scan for ips
to scan for ip's in the network, we can use 
	- `arp-scan -l` 
	- `netdiscover -r [ip range (eg: 192.168.57.0/24)]`