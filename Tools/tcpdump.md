---
tags:
  - CyberSec/tools
  - GCPC
  - Networking
---
**tcpdump** is a command-line network protocol analyzer. It is popular, lightweight–meaning it uses little memory and has a low CPU usage–and uses the open-source libpcap library. tcpdump is text based, meaning all commands in tcpdump are executed in the terminal. It can also be installed on other Unix-based operating systems, such as macOS®. It is preinstalled on many Linux distributions.

tcpdump provides a brief packet analysis and converts key information about network traffic into formats easily read by humans. It prints information about each packet directly into your terminal. tcpdump also displays the source IP address, destination IP addresses, and the port numbers being used in the communications.

## Interpreting output
tcpdump prints the output of the command as the sniffed packets in the command line, and optionally to a log file, after a command is executed. The output of a packet capture contains many pieces of important information about the network traffic. 

Some information you receive from a packet capture includes: 
- **Timestamp**: The output begins with the timestamp, formatted as hours, minutes, seconds, and fractions of a second.  
- **Source IP**: The packet’s origin is provided by its source IP address.
- **Source port**: This port number is where the packet originated.
- **Destination IP**: The destination IP address is where the packet is being transmitted to.
- **Destination port**: This port number is where the packet is being transmitted to.

**Note:** By default, tcpdump will attempt to resolve host addresses to hostnames. It'll also replace port numbers with commonly associated services that use these ports.

## Common uses
tcpdump and other network protocol analyzers are commonly used to capture and view network communications and to collect statistics about the network, such as troubleshooting network performance issues. They can also be used to:
- Establish a baseline for network traffic patterns and network utilization metrics.
- Detect and identify malicious traffic
- Create customized alerts to send the right notifications when network issues or security threats arise.
- Locate unauthorized instant messaging (IM), traffic, or wireless access points.

However, attackers can also use network protocol analyzers maliciously to gain information about a specific network. For example, attackers can capture data packets that contain sensitive information, such as account usernames and passwords. As a cybersecurity analyst, It’s important to understand the purpose and uses of network protocol analyzers.

## Usage
[Manpage](https://www.tcpdump.org/manpages/tcpdump.1.html)
```bash
sudo tcpdump [-i interface] [option(s)] [expression(s)]
```
eg: `sudo tcpdump -i eth0 -s 0 -w packetdump.pcap`

- The **-i** command option allows you to specify the interface. If not specified or or `-i any`, tcpdump will capture all traffic on all interfaces.
**Options**
- The **-s** command option specifies the length of the snapshot for each packet. Setting this option to 0 sets it to the default of 262144.
- The **-w** command option is used to write the result of the **tcpdump** command to a file. Adding the extension **.pcap** ensures that operating systems and applications will be able to read the file. All recorded traffic will be printed to the file **packetdump.pcap**.
- Using the **-r** flag, you can read a packet capture file by specifying the file name as a parameter.
- **-v** : for verbosity. By default, tcpdump will not print out all of a packet's information. There are three levels of verbosity you can use depending on how much packet information you want tcpdump to print out: -v, -vv, and -vvv.
- The **-c** option stands for count. This option lets you control how many packets tcpdump will capture. For example, specifying -c 1 will only print out one single packet, whereas -c 10 prints out 10 packets.
- **-n** : Using the -n flag disables the automatic mapping of numbers to names and is considered to be best practice when sniffing or analyzing traffic. Using -n will not resolve hostnames, whereas -nn will not resolve _both_ hostnames or ports. By default, tcpdump will perform name resolution. This means that tcpdump automatically converts IP addresses to names. It will also resolve ports to commonly associated services that use these ports. This can be problematic because tcpdump isn’t always accurate in name resolution.
**Expressions**
You can also use filter expressions in tcpdump commands.
- you can use filter expressions to isolate network packets.
- You can also use boolean operators like and, or, or not to further filter network traffic for specific IP addresses, ports, and more.
- eg: sudo tcpdump -r packetcapture.pcap -n 'ip and port 80'
- You can also use parentheses to group and prioritize different expressions.

- You can use the -D flag to list the network interfaces available on a system. OR In the `ifconfig` output, find the interface name that corresponds to the Ethernet adapter (usually eth0).
## Interpreting output
eg: `sudo tcpdump -i any -v -c 1`
![[tcpdump-1765191949803.png|691x149]]
1. **Timestamp**: The output begins with the timestamp, which starts with hours, minutes, seconds, and fractions of a second. 
2. **Source IP:** The packet’s origin is provided by its source IP address.
3. **Source port:** This port number is where the packet originated.
4. **Destination IP:** The destination IP address is where the packet is being transmitted to.
5. **Destination port:** This port number is where the packet is being transmitted to.
