---
tags:
  - CiscoIntro2Cyber
---
Router
Intrusion prevention system
VPN
Antivirus
# Firewall
In computer networking, a firewall is designed to control or filter which communications are allowed in and which are allowed out of a device or network. A firewall can be installed on a single computer with the purpose of protecting that one computer (host-based firewall) or it can be a standalone network device that protects an entire network of computers and all of the host devices on that network (network-based firewall).

As computer and network attacks have become more sophisticated, new types of firewalls have been developed, which serve different purposes.
## Network layer firewall
This filters communications based on source and destination IP addresses.
## Transport layer firewall
Filters communications based on source and destination data ports, as well as connection states.
## Application layer firewall
Filters communications based on an application, program or service.
## Context aware layer firewall
Filters communications based on the user, device, role, application type and threat profile.
## Proxy server
Filters web content requests like URLs, domain names and media types.
## Reverse proxy server
Placed in front of web servers, reverse proxy servers protect, hide, offload and distribute access to web servers.
## Network address translation (NAT) firewall
This firewall hides or masquerades the private addresses of network hosts.
## Host-based firewall
Filters ports and system service calls on a single computer operating system.

# Incident Detection and Prevention Systems
## IDS
An IDS (Intrusion Detection Systems) can either be a dedicated network device or one of several tools in a server, firewall or even a host computer operating system, such as Windows or Linux, that scans data against a database of rules or attack signatures, looking for malicious traffic.
If a match is detected, the IDS will log the detection and create an alert for a network administrator. It will not take action and therefore it will not prevent attacks from happening. The job of the IDS is to detect, log and report.
The scanning performed by the IDS slows down the network (known as latency). To prevent network delay, an IDS is usually placed offline, separate from regular network traffic. Data is copied or mirrored by a switch and then forwarded to the IDS for offline detection.
## IPS
An IPS can block or deny traffic based on a positive rule or signature match. One of the most well-known IPS/IDS systems is Snort. The commercial version of Snort is Cisco’s Sourcefire. Sourcefire can perform real-time traffic and port analysis, logging, content searching and matching, as well as detect probes, attacks and execute port scans. It also integrates with other third-party tools for reporting, performance and log analysis.
## [[SIEM]]
A Security Information and Event Management (SIEM) system collects and analyzes security alerts, logs and other real-time and historical data from security devices on the network to facilitate early detection of cyber attacks.
## DLP
A Data Loss Prevention (DLP) system is designed to stop sensitive data from being stolen from or escaping a network. It monitors and protects data in three different states: data in use (data being accessed by a user), data in motion (data traveling through the network) and data at rest (data stored in a computer network or device).
# Security Best Practices
Many national and professional organizations have published lists of security best practices. Some of the most helpful guidelines are found in organizational repositories such as the National Institute of Standards and Technology (NIST) Computer Security Resource Center.
### Perform a risk assessment
Knowing and understanding the value of what you are protecting will help to justify security expenditures.
### Create a security policy
Create a policy that clearly outlines the organization’s rules, job roles, and responsibilities and expectations for employees.
### Physical security measures
Restrict access to networking closets and server locations, as well as fire suppression.
### Human resources security measures
Background checks should be completed for all employees.
### Perform and test backups
Back up information regularly and test data recovery from backups.
### Maintain security patches and updates
Regularly update server, client and network device operating systems and programs.
### Employ access controls
Configure user roles and privilege levels as well as strong user authentication.
### Regularly test incident response
Employ an incident response team and test emergency response scenarios.
### Implement a network monitoring, analytics and management tool
Choose a security monitoring solution that integrates with other technologies.
### Implement network security devices
Use next generation routers, firewalls and other security appliances.
### Implement a comprehensive endpoint security solution
Use enterprise level antimalware and antivirus software.
### Educate users
Provide training to employees in security procedures.
### Encrypt data
Encrypt all sensitive organizational data, including email.