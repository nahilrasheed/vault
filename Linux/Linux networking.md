## Networking commands

- for IP address and details 
	use  `ip a` or `ifconfig`  / `iwconfig` (for wireless)
- Address resolution Protocol - to know ip corresponded with MAC address
	`ip n`  or `arp -a`
- routing table
	`ip r` or `route`
- to check for open ports and services
	`netstat`
- List open ports
	`ss -tunlp`
- DNS query
	`dig domain.com`
- `traceroute`:  A network diagnostic tool for displaying the route and measuring transit delays of packets
- `mtr` : Combines `ping` and `trace route` to show real-time packet loss and latency.
- 