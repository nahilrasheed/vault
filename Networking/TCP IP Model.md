---
tags:
  - GCPC
  - CyberSec
  - Networking
---
### TCP/IP Model
Transmission Control Protocol and Internet Protocol (TCP/IP) is the standard model used for network communication. 
TCP, or Transmission Control Protocol, is an internet communication protocol that allows two devices to form a connection and stream data. 
- The protocol includes a set of instructions to organize data, so it can be sent across a network. 
- It also establishes a connection between two devices and makes sure that packets reach their appropriate destination.
The IP in TCP/IP stands for [[Internet Protocol (IP)]] . 
- IP has a set of standards used for routing and addressing data packets as they travel between devices on a network. Included in the Internet Protocol (IP) is the IP address that functions as an address for each private network.
- Port: Within the operating system of a network device, a port is a software-based location that organizes the sending and receiving of data between devices on a network.
The TCP/IP model is a framework that is used to visualize how data is organized and transmitted across the network. 
4 layers
1. Network access layer: deals with creation of data packets and their transmission across a network. This includes hardware devices connected to physical cables and switches that direct data to its destination.
2. Internet layer: The internet layer is where IP addresses are attached to data packets to indicate the location of the sender and receiver. The internet layer also focuses on how networks connect to each other.
3. Transport layer: includes protocols to control the flow of traffic across a network.  These protocols permit or deny communication with other devices and include information about the status of the connection. Activities of this layer include error control, which ensures data is flowing smoothly across the network.
4. Application layer: protocols determine how the data packets will interact with receiving devices. Functions that are organized at application layer include file transfers and email services.

>[!important] 
[[OSI Model]]
[[IP and MAC Addresses]]

![[TCP IP Model-img-202510091531.png|0x0]]
### Network access layer 
The network access layer, sometimes called the data link layer, deals with the creation of data packets and their transmission across a network. This layer corresponds to the physical hardware involved in network transmission. Hubs, modems, cables, and wiring are all considered part of this layer. The address resolution protocol (ARP) is part of the network access layer. Since MAC addresses are used to identify hosts on the same physical network, ARP is needed to map IP addresses to MAC addresses for local network communication.

### Internet layer
The internet layer, sometimes referred to as the network layer, is responsible for ensuring the delivery to the destination host, which potentially resides on a different network. It ensures IP addresses are attached to data packets to indicate the location of the sender and receiver. The internet layer also determines which protocol is responsible for delivering the data packets and ensures the delivery to the destination host. Here are some of the common protocols that operate at the internet layer:

- **Internet Protocol (IP)**. IP sends the data packets to the correct destination and relies on the Transmission Control Protocol/User Datagram Protocol (TCP/UDP) to deliver them to the corresponding service. IP packets allow communication between two networks. They are routed from the sending network to the receiving network. TCP in particular retransmits any data that is lost or corrupt.
- **Internet Control Message Protocol (ICMP)**. The ICMP shares error information and status updates of data packets. This is useful for detecting and troubleshooting network errors. The ICMP reports information about packets that were dropped or that disappeared in transit, issues with network connectivity, and packets redirected to other routers.
## Transport layer
The transport layer is responsible for delivering data between two systems or networks and includes protocols to control the flow of traffic across a network. TCP and UDP are the two transport protocols that occur at this layer. 
#### Transmission Control Protocol 
The **Transmission Control Protocol (TCP)** is an internet communication protocol that allows two devices to form a connection and stream data. It ensures that data is reliably transmitted to the destination service. TCP contains the port number of the intended destination service, which resides in the TCP header of a TCP/IP packet.
#### User Datagram Protocol
The **User Datagram Protocol (UDP)** is a connectionless protocol that does not establish a connection between devices before transmissions. It is used by applications that are not concerned with the reliability of the transmission. Data sent over UDP is not tracked as extensively as data sent using TCP. Because UDP does not establish network connections, it is used mostly for performance sensitive applications that operate in real time, such as video streaming.

## Application layer
The application layer in the TCP/IP model is similar to the application, presentation, and session layers of the OSI model. The application layer is responsible for making network requests or responding to requests. This layer defines which internet services and applications any user can access. Protocols in the application layer determine how the data packets will interact with receiving devices. Some common protocols used on this layer are: 
- Hypertext transfer protocol (HTTP)
- Simple mail transfer protocol (SMTP)
- Secure shell (SSH)
- File transfer protocol (FTP)
- Domain name system (DNS)
Application layer protocols rely on underlying layers to transfer the data across the network.
## TCP/IP model versus OSI model

![[TCP IP Model-img-202510091531 1.png]]

The **OSI** visually organizes network protocols into different layers. Network professionals often use this model to communicate with each other about potential sources of problems or security threats when they occur.

The TCP/IP model combines multiple layers of the OSI model. There are many similarities between the two models. Both models define standards for networking and divide the network communication process into different layers. The TCP/IP model is a simplified version of the OSI model.
![[TCP IP Model-img-202510091531 2.png|798x449]]

![[TCP IP Model-img-202510091531 3.png|797x448]]

---
- [https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)

