# Denial of Service
A denial of service attack is an attack that targets a network or server and floods it with network traffic. The objective of a denial of service attack, or a DoS attack, is to disrupt normal business operations by overloading an organization's network. Denial-of-Service (DoS) attacks are a type of network attack that is relatively simple to carry out, even by an unskilled attacker. A DoS attack results in some sort of interruption of network service to users, devices or applications.
**2 types of DOS attacks:** 
#### Overwhelming quantity of traffic
This is when a network, host or application is sent an enormous amount of data at a rate which it cannot handle. This causes a slowdown in transmission or response, or the device or service to crash.
#### Maliciously formatted packets
A packet is a collection of data that flows between a source and a receiver computer or application over a network, such as the Internet. When a maliciously formatted packet is sent, the receiver will be unable to handle it.
For example, if an attacker forwards packets containing errors or improperly formatted packets that cannot be identified by an application, this will cause the receiving device to run very slowly or crash.
## Direct DoS Attacks
A direct DoS attack occurs when the source of the attack generates the packets, regardless of protocol, application, and so on, that are sent directly to the victim of the attack.
The attacker launches a direct DoS attack to a web server (the victim) by sending numerous TCP SYN packets. This type of attack is aimed at flooding the victim with an overwhelming number of packets in order to oversaturate its connection bandwidth or deplete the target’s system resources. This type of attack is also known as a _SYN flood attack_.  
  
Cybercriminals can also use DoS and DDoS attacks to produce added costs for the victim when the victim is using cloud services. In most cases, when you use a cloud service such as Amazon Web Services (AWS), Microsoft Azure, or Digital Ocean, you pay per usage. Attackers can launch DDoS attacks to cause you to pay more for usage and resources.  
  
Another type of DoS attack involves exploiting vulnerabilities such as buffer overflows to cause a server or even a network infrastructure device to crash, subsequently causing a DoS condition.
## Distributed DoS
A distributed denial of service attack, or DDoS, is a kind of DoS attack that uses multiple devices or servers in different locations to flood the target network with unwanted traffic. Use of numerous devices makes it more likely that the total amount of traffic sent will overwhelm the target server. For example:
- An attacker builds a network (botnet) of infected hosts called zombies, which are controlled by handler systems.
- The zombie computers will constantly scan and infect more hosts, creating more and more zombies.
- When ready, the hacker will instruct the handler systems to make the botnet of zombies carry out a DDoS attack.
## Botnet
A bot computer is typically infected by visiting an unsafe website or opening an infected email attachment or infected media file. 
A botnet is a collection of such compromised machines (bots) connected through the Internet, that can be controlled by a malicious individual or group to participate in a DDoS attack, send spam emails, and perform other illicit activities. It can have tens of thousands, or even hundreds of thousands, of bots that are typically controlled through a command and control server.
These bots can be activated to distribute malware, launch DDoS attacks, distribute spam email, or execute brute-force password attacks. Cybercriminals will often rent out botnets to third parties for nefarious purposes.

## Reflected DoS and DDoS Attacks 
With reflected DoS and DDoS attacks, attackers send to sources spoofed packets that appear to be from the victim, and then the sources become unwitting participants in the reflected attack by sending the response traffic back to the intended victim. UDP is often used as the transport mechanism in such attacks because it is more easily spoofed due to the lack of a three-way handshake. For example, if the attacker decides he wants to attack a victim, he can send packets (for example, Network Time Protocol [NTP] requests) to a source that thinks these packets are legitimate. The source then responds to the NTP requests by sending the responses to the victim, who was not expecting these NTP packets from the source.

## Amplification DDoS Attacks  
An amplification attack is a form of reflected DoS attack in which the response traffic (sent by the unwitting participant) is made up of packets that are much larger than those that were initially sent by the attacker (spoofing the victim). An example of this type of attack is an attacker sending DNS queries to a DNS server configured as an open resolver. Then the DNS server (open resolver) replies with responses much larger in packet size than the initial query packets. The end result is that the victim’s machine gets flooded by large packets for which it never actually issued queries.
## 3 common network level DoS attacks.
A SYN flood attack is a type of DoS attack that simulates the TCP connection and floods the server with SYN packets.
The first step in the handshake is for the device to send a SYN, or synchronize, request to the server. Then, the server responds with a SYN/ACK packet to acknowledge the receipt of the device's request and leaves a port open for the final step of the handshake. Once the server receives the final ACK packet from the device, a TCP connection is established. Malicious actors can take advantage of the protocol by flooding a server with SYN packet requests for the first part of the handshake. But if the number of SYN requests is larger than the number of available ports on the server, then the server will be overwhelmed and become unable to function.

An ICMP flood attack is a type of DoS attack performed by an attacker repeatedly sending ICMP packets to a network server. This forces the server to send an ICMP packet. This eventually uses up all the bandwidth for incoming and outgoing traffic and causes the server to crash.

A ping of death attack is a type of DoS attack that is caused when a hacker pings a system by sending it an oversized ICMP packet that is bigger than 64 kilobytes, the maximum size for a correctly formed ICMP packet. Pinging a vulnerable network server with an oversized ICMP packet will overload the system and cause it to crash. 