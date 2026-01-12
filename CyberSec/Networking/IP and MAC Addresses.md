---
tags:
  - GCPC
  - CyberSec
  - Networking
---
# IP address
An internet protocol address, or IP address, is a unique string of characters that identifies a location of a device on the internet.
2 Types of IP addresses
- IPv4 
- IPv6
## Difference between IPv4 and IPv6
In an earlier part of this course, you learned about the history of IP addressing. As the internet grew, it became clear that all of the IPv4 addresses would eventually be depleted; this is called IPv4 address exhaustion. At the time, no one had anticipated how many computing devices would need an IP address. IPv6 was developed to mitigate IPv4 address exhaustion and other related concerns. 

Some of the key differences between IPv4 and IPv6 include the length and the format of the addresses. IPv4 addresses are made up of four decimal numbers separated by periods, each number ranging from 0 to 255. Together the numbers span 4 bytes, and allow for up to 4.3 billion possible addresses. An example of an IPv4 address would be: 198.51.100.0. 

IPv6 addresses are made of eight hexadecimal numbers separated by colons, each number consisting of up to four hexadecimal digits. Together, all numbers span 16 bytes, and allow for up to 340 undecillion addresses (340 followed by 36 zeros). An example of an IPv6 address would be: 2002:0db8:0000:0000:0000:ff21:0023:1234.

_**Note:**_ _to represent one or more consecutive sets of all zeros, you can replace the zeros with a double colon "::", so the above IPv6 address would be "_2002:0db8::ff21:0023:1234."

There are also some differences in the layout of an IPv6 packet header. The IPv6 header format is much simpler than IPv4. For example, the IPv4 Header includes the IHL, Identification, and Flags fields, whereas the IPv6 does not. The IPv6 header only introduces the Flow Label field, where the Flow Label identifies a packet as requiring special handling by other IPv6 routers. 

![[IP and MAC Addresses-img-202510091530 2.png]]
There are some important security differences between IPv4 and IPv6. IPv6 offers more efficient routing and eliminates private address collisions that can occur on IPv4 when two devices on the same network are attempting to use the same address.
![[IP and MAC Addresses-img-202510091530 3.png]]
# MAC address
A MAC address is a unique alphanumeric identifier that is assigned to each physical device on a network. When a switch receives a data packet, it reads the MAC address of the destination device and maps it to a port. It then keeps this information in a MAC address table. Think of the MAC address table like an address book that the switch uses to direct data packets to the appropriate device.
Format of MAC address
![[IP and MAC Addresses-img-202510091530 4.png]]
The first three blocks of characters represent the manufacturer of the device. In the above example, the device is Apple, and the last three blocks are random numbers that should be unique to the device.

If IP address 192.168.1.15 wanted to talk to 192.168.1.22, it would first have to send out an ARP (Address Resolution Protocol) request. This request would get sent to every device on the network. Once the device with the IP address 192.168.1.22 received the request, it would send back an ARP Reply message saying 192.168.1.22 has the hardware address 44:F2:1B:83:11:7A. Now communication can commence. Once devices have received an ARP Reply message, they don't need to keep on asking for the MAC address as the computer keeps it in a local database called an ARP Cache.
![[IP and MAC Addresses-img-202510091530 5.png]]
