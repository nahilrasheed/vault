---
tags:
  - GCPC
  - CyberSec
---
## Network
A network is a group of connected devices
Two types of networks:
- LAN: A local area network, or LAN, spans a small area like an office building, a school, or a home.
- WAN: A wide area network or WAN spans a large geographical area like a city, state, or country.
### Common devices that make up a network
- Hub: a network device that broadcasts information to every device on the network.
- Switch: A switch makes connections between specific devices on a network by sending and receiving data between them. A switch is more intelligent than a hub. It only passes data to the intended destination. This makes switches more secure than hubs, and enables them to control the flow of traffic and improve network performance.
- Router: a network device that connects multiple networks together.
- Modem: a device that connects your router to the internet, and brings internet access to the LAN.
![[Network-img-202510091530.png|724x300]]
- Firewall is a security device that monitors incoming and outgoing traffic on your network.
- Wireless access point: sends and receives digital signals over radio waves creating a wireless network. Devices with wireless adapters connect to the access point using Wi-Fi. Wi-Fi refers to a set of standards that are used by network devices to communicate wirelessly.
### Cloud networks
Cloud computing is the practice of using remote servers, applications, and network services that are hosted on the internet instead of on local physical devices. 
A cloud network is a collection of servers or computers that stores resources and data in a remote data center that can be accessed via the internet. 
A cloud service provider (CSP) is a company that offers cloud computing services. These companies own large data centers in locations around the globe that house millions of servers. Data centers provide technology services, such as storage, and compute at such a large scale that they can sell their services to other companies for a fee. Companies can pay for the storage and services they need and consume them through the CSP’s application programming interface (API) or web console.
CSPs provide three main categories of services:
- **Software as a service (SaaS)** refers to software suites operated by the CSP that a company can use remotely without hosting the software.  
- **Infrastructure as a service** **(IaaS)** refers to the use of virtual computer components offered by the CSP. These include virtual containers and storage that are configured remotely through the CSP’s API or web console. Cloud-compute and storage services can be used to operate existing applications and other technology workloads without significant modifications. Existing applications can be modified to take advantage of the availability, performance, and security features that are unique to cloud provider services. 
- **Platform as a service (PaaS)** refers to tools that application developers can use to design custom applications for their company. Custom applications are designed and accessed in the cloud and used for a company’s specific business needs.
![[Network-img-202510091530 1.png|732x294]]
#### Software-defined networks
CSPs offer networking tools similar to the physical devices that you have learned about in this section of the course. Next, you’ll review  software-defined networking in the cloud. Software-defined networks (SDNs) are made up of virtual network devices and services. Just like CSPs provide virtual computers, many SDNs also provide virtual switches, routers, firewalls, and more. Most modern network hardware devices also support network virtualization and software-defined networking. This means that physical switches and routers use software to perform packet routing. In the case of cloud networking, the SDN tools are hosted on servers located at the CSP’s data center.
### Benefits of cloud computing and software-defined networks
#### Reliability
Reliability in cloud computing is based on how available cloud services and resources are, how secure connections are, and how often the services are effectively running. Cloud computing allows employees and customers to access the resources they need consistently and with minimal interruption.
#### Cost
Traditionally, companies have had to provide their own network infrastructure, at least for internet connections. This meant there could be potentially significant upfront costs for companies. However, because CSPs have such large data centers, they are able to offer virtual devices and services at a fraction of the cost required for companies to install, patch, upgrade, and manage the components and software themselves.
#### Scalability
Another challenge that companies face with traditional computing is scalability. When organizations experience an increase in their business needs, they might be forced to buy more equipment and software to keep up. But what if business decreases shortly after? They might no longer have the business to justify the cost incurred by the upgraded components. CSPs reduce this risk by making it easy to consume services in an elastic utility model as needed. This means that companies only pay for what they need when they need it.
## Network Communication
- Data packet: a basic unit of information that travels from one device to another within a network. 
	- When data is sent from one device to another across a network, it is sent as a packet that contains information about where the packet is going, where it's coming from, and the content of the message.
	- It contains a header that includes the internet protocol address, the IP address, and the media access control, or MAC, address of the destination device. It also includes a protocol number that tells the receiving device what to do with the information in the packet. Then there's the body of the packet, which contains the message that needs to be transmitted to the receiving device. Finally, at the end of the packet, there's a footer, similar to a signature on a letter, the footer signals to the receiving device that the packet is finished.
- Bandwidth: The amount of data a device receives every second
- Speed: The rate at which data packets are received or downloaded
- Packet sniffing: The practice of capturing and inspecting data packets across a network