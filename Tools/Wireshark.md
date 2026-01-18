---
tags:
  - CyberSec/tools
---
**Wireshark** is an open-source network protocol analyzer. It uses a graphical user interface (GUI), which makes it easier to visualize network communications for packet analysis purposes.

- Wireshark can analyze traffic and display the information in an easy-to-navigate format regardless of the protocols used (e.g., HTTP, TCP, DNS).
- Wireshark can reconstruct back-and-forth conversations in a network.
- Wireshark allows easy filtering to narrow down essential details.
- Wireshark can also export and analyze objects that are transferred over the network.

### Display filters
Wireshark's display filters let you apply filters to packet capture files. This is helpful when you are inspecting packet captures with large volumes of information. Display filters will help you find specific information that's most relevant to your investigation. You can filter packets based on information such as protocols, IP addresses, ports, and virtually any other property found in a packet.
- You can apply filters to a packet capture using Wireshark's filter toolbar.

**Comparison operators**
You can use different comparison operators to locate specific header fields and values. Comparison operators can be expressed using either abbreviations or symbols. For example, this filter using the == equal symbol in this filter ip.src == 8.8.8.8 is identical to using the eq abbreviation in this filter ip.src eq 8.8.8.8.
This table summarizes the different types of comparison operators you can use for display filtering.

| **Operator type**        | **Symbol** | **Abbreviation** |
| ------------------------ | ---------- | ---------------- |
| Equal                    | ==         | eq               |
| Not equal                | !=         | ne               |
| Greater than             | >          | gt               |
| Less than                | <          | lt               |
| Greater than or equal to | >=         | ge               |
| Less than or equal to    | <=         | le               |

- You can combine comparison operators with Boolean logical operators like and and or to create complex display filters. Parentheses can also be used to group expressions and to prioritize search terms.
**Contains operator**
The contains operator is used to filter packets that contain an exact match of a string of text.
**Matches operator**
The matches operator is used to filter packets based on the regular expression (regex) that's specified. Regular expression is a sequence of characters that forms a pattern.

### Filter for protocols
Protocol filtering is one of the simplest ways you can use display filters. You can simply enter the name of the protocol to filter. For example, to filter for DNS packets simply type dns in the filter toolbar. 
Some protocols you can filter for:dns, http, ftp, ssh, arp, telnet, icmp

### Filter for an IP address
You can use display filters to locate packets with a specific IP address. 
- If you would like to filter packets that contain a specific IP address use ip.addr, followed by a space, the equal == comparison operator, and the IP address. eg: `ip.addr == 172.21.224.2`
- To filter for packets originating from a specific source IP address, you can use the ip.src filter. eg: `ip.src == 10.10.10.10`
- To filter for packets delivered to a specific destination IP address, you can use the ip.dst filter. eg: `ip.dst == 4.4.4.4`
### Filter for a MAC address
You can also filter packets according to the **Media Access Control (MAC) address**.
eg: `eth.addr == 00:70:f4:23:18:c4`

### Filter for ports
Port filtering is used to filter packets based on port numbers. This is helpful when you want to isolate specific types of traffic. DNS traffic uses TCP or UDP port 53 so this will list traffic related to DNS queries and responses only.

For example, if you would like to filter for a UDP port: `udp.port == 53`
Likewise, you can filter for TCP ports as well: `tcp.port == 25`

## Follow streams
Wireshark provides a feature that lets you filter for packets specific to a protocol and view streams. A stream or conversation is the exchange of data between devices using a protocol. Wireshark reassembles the data that was transferred in the stream in a way that's simple to read.
Following a protocol stream is useful when trying to understand the details of a conversation. For example, you can examine the details of an HTTP conversation to view the content of the exchanged request and response messages.

 Coloring rules are used to provide high-level visual cues to help you quickly classify the different types of data.
 DNS : light blue
 TCP HTTP : light green

## Sections in a packet
Frame
This provides you with details about the overall network packet, or frame, including the frame length and the arrival time of the packet. At this level, you’re viewing information about the entire packet of data.
Ethernet II
This item contains details about the packet at the Ethernet level, including the source and destination MAC addresses and the type of internal protocol that the Ethernet packet contains.
IPv4
This provides packet data about the Internet Protocol (IP) data contained in the Ethernet packet. It contains information such as the source and destination IP addresses and the Internal Protocol (for example, TCP or UDP), which is carried inside the IP packet.
TCP
This provides detailed information about the TCP packet, including the source and destination TCP ports, the TCP sequence numbers, and the TCP flags.



---
## Resources
- [Wireshark Official User Guide](https://www.wireshark.org/docs/wsug_html/) 
THM Rooms
- [Wireshark: The Basics](https://tryhackme.com/r/room/wiresharkthebasics)  
- [Wireshark: Packet Operations](https://tryhackme.com/r/room/wiresharkpacketoperations)  
- [Wireshark: Traffic Analysis](https://tryhackme.com/r/room/wiresharktrafficanalysis)