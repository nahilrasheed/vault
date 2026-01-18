## DHCP Starvation Attacks and Rogue DHCP Servers
Most organizations run DHCP servers. The two most popular attacks against DHCP servers and infrastructure are _DHCP starvation_ and _DHCP spoofing_ (which involves rogue DHCP servers). In a DHCP starvation attack, an attacker broadcasts a large number of DHCP REQUEST messages with spoofed source MAC addresses.

If the DHCP server responds to all these fake DHCP REQUEST messages, available IP addresses in the DHCP server scope are depleted within a few minutes or seconds. After the available number of IP addresses in the DHCP server is depleted, the attacker can then set up a **rogue DHCP server** and respond to new DHCP requests from network DHCP clients. Then the attacker can set the IP address of the default gateway and DNS server to itself so that it can intercept the traffic from the network hosts.

A tool called Yersenia can be used to create a rogue DHCP server and launch DHCP starvation and spoofing attacks.

You have setup a rogue DHCP server. A rogue DHCP server is a server that network administration does not control and is unaware of. It offers users host, default gateway, and DNS server addresses when their DHCP settings renew. By setting the default gateway IP address to its own address in the DHCP offers that it sends out, the rogue server can receive all the traffic that clients send to non-local networks. It can also barrage the real DHCP server with spoofed DHCP discover messages. The attacker can thereby use the server to launch DoS (DHCP starvation) and MITM (DHCP spoofing) attacks.

