Network monitoring is essential in maintaining situational awareness of any activity on a network. By collecting and analyzing network traffic, organizations can detect suspicious network activity.

Network Traffic Analysis (NTA) is a process that encompasses capturing, inspecting, and analyzing data as it flows in a network. Its goal is to have complete visibility and understand what is communicated inside and outside the network.

Generally, we will use network traffic analysis to:
- Monitor network performance
- Check for abnormalities in the network. E.g., sudden performance peaks, slow network, etc
- Inspect the content of suspicious communication internally and externally. E.g., exfiltration via DNS, download of a malicious ZIP file over HTTP, lateral movement, etc
From a SOC perspective, network traffic analysis helps:
- Detecting suspicious or malicious activity
- Reconstructing attacks during incident response
- Verifying and validating alerts

### Sources
**Intermediary Sources**  
These are devices through which traffic mostly passes. While they generate some traffic, it is significantly lower than what endpoint devices generate. Under this category, we can find firewalls, switches, web proxies, IDS, IPS, routers, access points, wireless LAN controllers, and many more. Maybe less relevant for us, but all the infrastructure of Internet Service Providers is also considered part of this category.

The traffic that originates from these devices comes from services like routing protocols (EIGRP, OSPF, BGP), management protocols (SNMP, PING), logging protocols (SYSLOG), and other supporting protocols (ARP, STP, DHCP).

**Endpoint Sources**  
These are devices where traffic originates and ends. Endpoint devices take the bulk of the network bandwidth. Devices that fall under this category are servers, hosts, IoT devices, printers, virtual machines, cloud resources, mobile phones, tablets, and many more
### Flow
A network traffic flow is typically determined by the services available in the network, such as Active Directory, SMB, HTTPS, and so on. In a typical corporate network, we can group these flows into North-South and East-West traffic.
**North-South Traffic**  
NS traffic is often monitored closely as it flows from the LAN to the WAN and vice versa. The most well-known services in this category are client-server protocols like HTTPS, DNS, SSH, VPN, SMTP, RDP, and many more. Each of these protocols has two streams: ingress (inbound) and egress (outbound). All of this traffic passes the firewall in one way or another. Configuring firewall rules and logging properly are key to visibility.
**East-West Traffic**  
EW traffic stays within the corporate LAN, so it is often monitored less. However, it is important to keep track of these flows. When the network is compromised, an attacker will often exploit different services internally to move laterally within the network. As we see below, there are many services within this category. 
- Directory, Authentication & Identity Services
	- Kerberos / LDAP: Authentication/queries to Active Directory
	- RADIUS / TACACS+: Network access control
	- Certificate Authority issuing internal certifications
- File shares & print services
	- SMB/CIFS: Accessing network drives
	- IPP/LPD: Printing over the network
- Router, switching, and infrastructure services
	- DHCP traffic between hosts and the DHCP server
	- ARP broadcast messages
	- Internal DNS
	- Routing protocol messages
- Application Communication
	- Database Connections: SQL over TCP
	- Microservices APIs: REST or gRPC calls between services
- Backup & Replication
	- File Replication: Between data centers or to backup servers
	- Database Replication: MySQL binlog replication, PostgreSQL streaming, and more
- Monitoring & Management
	- SNMP: Device health metrics
	- Syslog: Centralized logging
	- NetFlow/IPFIX: Traffic flow telemetry
	- Other endpoint logs sent to a central logging server

## Logs
Logs are our first entry into acquiring information about what is going on in the network. Each system and protocol in the network includes a way of logging information. It is essential to know that there is no universal standard for implementing logging on each system and protocol. Each vendor chooses how to implement logging for themselves. For example, Microsoft implements Windows Event Logs. Also, the data that is logged is up to the vendor. Most vendors will not log a full packet as it enters or exits the system. They will log some fields that they deem useful, such as a source IP address and a destination IP address.

## Full Packet Capture
**Network Tap**  
A network tap is a physical device you place inline in your network. These devices create a copy of all the network traffic that passes without affecting performance. That copied data is then forwarded to a packet capture box, IDS, or other system using the dedicated monitoring port. It is interesting to know that a TAP operates only on the link layer of the TCP-IP model; it does not need a MAC or IP address, because it copies the electrical/light signals and sends them to its monitoring port. This way, there is no added delay to the network.
**Port Mirroring**  
Port mirroring is a software approach to copying packets from one port on an intermediary device to another that is attached to, for example, an IDS, packet capture box, or other systems. Each vendor has its own name. Cisco, for example, calls it SPAN.

## Network Statistics
Another great way to find anomalies in your network is to gather metadata about the data flowing through the network, such as counting the number of DNS requests that a host sends out. A few protocols facilitate this.
**NetFlow** is a protocol developed by Cisco that collects metadata about traffic flowing in a network. It is a great way to detect things like C2 traffic, data exfiltration, and lateral movement
**The Internet Protocol Flow Information Export protocol (IPFIX)** can be considered as the successor to NetFlow. NetFlow was initially a proprietary protocol from Cisco. This means that the protocol was designed for Cisco systems only. Only from NetFlow v9 on did Cisco include templating, so other vendors could adapt it to their devices. In collaboration with Cisco and other vendors, the IETF created IPFIX and released it as a vendor-neutral standard. It offers features similar to NetFlow, but includes more flexibility in configuring which fields to capture.

## Packet payload information
Network packets contain components related to the transmission of the packet. This includes details like source and destination IP address, and the packet payload information, which is the actual data that’s transmitted. Often, this data is encrypted and requires decryption for it to be readable. Organizations can monitor the payload information of packets to uncover unusual activity, such as sensitive data transmitting outside of the network, which could indicate a possible data exfiltration attack.
## Temporal patterns
Network packets contain information relating to time. This information is useful in understanding time patterns. For example, a company operating in North America experiences bulk traffic flows between 9 a.m. to 5 p.m., which is the baseline of normal network activity. If large volumes of traffic are suddenly outside of the normal hours of network activity, then this is considered _off baseline_ and should be investigated.


- If you would like to learn more about network components organizations can monitor, check out [network traffic - MITRE ATT&CK®](https://attack.mitre.org/datasources/DS0029/)
    
- Attackers can leverage different techniques to exfiltrate data, should you like to learn more, check out [data exfiltration techniques - MITRE ATT&CK®](https://attack.mitre.org/tactics/TA0010/)