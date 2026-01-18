## Attacking Internet of Things (IoT) Devices
IoT is an incredibly broad term that can be applied across personal devices, **_industrial control systems (ICS)_**, transportation, and many other businesses and industries. Designing and securing IoT systems – (including **_supervisory control and data acquisition (SCADA)_**, **_Industrial Internet of Things (IIoT)_**, and ICS – involves a lot of complexity. For instance, IoT solutions have challenging integration requirements, and IoT growth is expanding beyond the support capability of traditional IT stakeholders (in terms of scalability and the skills required). Managing and orchestrating IoT systems introduces additional complexity due to disparate hardware and software, the use of legacy technologies, and, often, multiple vendors and integrators. IoT platforms must integrate a wide range of IoT edge devices with varying device constraints and must be integrated to back-end business applications. In addition, no single solution on the market today can be deployed across all IoT scenarios.

The IoT market is extremely large and includes multiple platform offerings from startups as well as very large vendors. In many cases, IoT environments span a range of components that include sensors, gateways, network connectivity, applications, and cloud infrastructure. The unfortunate reality is that most IoT security efforts today focus on only a few elements of the entire system. A secure IoT platform should provide the complete end-to-end infrastructure to build an IoT solution, including the software, management, and security to effectively collect, transform, transport, and deliver data to provide business value. This is, of course, easier said than done.

## Analyzing IoT Protocols
Analyzing IoT protocols is important for tasks such as reconnaissance as well as exploitation. On the other hand, in the IoT world, you will frequently encounter custom, proprietary, or new network protocols. Some of the most common network protocols for IoT implementations include the following:
- Wi-Fi
- Bluetooth and Bluetooth Low Energy (BLE)
- Zigbee
- Z-Wave
- LoraWAN
- Insteon
- Modbus
- Siemens S7comm (S7 Communication)

For instance, **_Bluetooth Low Energy (BLE)_** is used by IoT home devices, medical, industrial, and government equipment. You can analyze protocols such as BLE by using specialized antennas and equipment such as the Ubertooth One ([_https://greatscottgadgets.com/ubertoothone/_](https://greatscottgadgets.com/ubertoothone/)). BLE involves a three-phase process to establish a connection:
- Phase 1. Pairing feature exchange
- Phase 2. Short-term key generation
- Phase 3. Transport-specific key distribution

BLE implements a number of cryptographic functions. It supports AES for encryption and key distribution exchange to share different keys among the BLE-enabled devices. However, many devices that support BLE do not even implement the BLE-layer encryption. In addition, mobile apps cannot control the pairing, which is done at the operating system level. Attackers can scan BLE devices or listen to BLE advertisements and leverage these misconfigurations. Then they can advertise clone/ fake BLE devices and perform on-path (formerly known as man-in-the-middle) attacks.

In some cases, IoT proprietary or custom protocols can be challenging. Even if you can capture network traffic, packet analyzers like Wireshark often can’t identify what you’ve found. Sometimes, you need to write new tools to communicate with IoT devices.

>**TIP** Tools such as GATTacker ([_https://github.com/securing/gattacker_](https://github.com/securing/gattacker)) can be used to perform on-path attacks in BLE implementations.
>BtleJuice ([_https://github.com/DigitalSecurity/BtleJuice_](https://github.com/DigitalSecurity/BtleJuice)) is a framework for performing interception and manipulation of BLE traffic.

## IoT Security Special Considerations
### Fragile Environment
Many IoT devices (including sensors and gateways) have limited compute resources. Because of this lack of resources, some security features, including encryption, may not even be supported in IoT devices.
### Availability Concerns
DoS attacks against IoT systems are a major concern.
### Data Corruption
IoT protocols are often susceptible to input validation vulnerabilities, as well as data corruption issues.
### Data Exfiltration
IoT devices could be manipulated by an attacker and used for sensitive data exfiltration.

## Common IoT Vulnerabilities
### Insecure defaults
Default credentials and insecure default configurations are often concerns with IoT devices. For instance, if you do a search in Shodan.io for IoT devices (or click on the Explore section), you will find hundreds of IoT devices with default credentials and insecure configurations exposed on the Internet.
### Plaintext communication and data leakage
As mentioned earlier, some IoT devices do not provide support for encryption. Even if encryption is supported, many IoT devices fail to implement encrypted communications, and an attacker could easily steal sensitive information. The leakage of sensitive information is always a concern with IoT devices.
### Hard-coded configurations
Often IoT vendors sell their products with hard-coded insecure configurations or credentials (including passwords, tokens, encryption keys, and more).
### Outdated firmware/hardware and the use of insecure or outdated components
Many organizations continue to run outdated software and hardware in their IoT devices. In some cases, some of these devices are never updated! Think about an IoT device controlling different operations on an oil rig platform in the middle of the ocean. In some cases, these devices are never updated, and if you update them, you will have to send a crew to physically perform a software or hardware upgrade. IoT devices often lack a secure update mechanism.

## Data Storage System Vulnerabilities
With the incredibly large number of IoT architectures and platforms available today, choosing which direction to focus on is a major challenge. IoT architectures extend from IoT endpoint devices (things) to intermediary “fog” networks and cloud computing. Gateways and edge nodes are devices such as switches, routers, and computing platforms that act as intermediaries (“the fog layer”) between the endpoints and the higher layers of the IoT system. 
The IoT architectural hierarchy high-level layers are 
1. Cloud Services and Applications
2. Fog Networks
3. Gateways (Fog-Edge Nodes)
4. Endpoints (things)

## Common misconfigurations of IoT devices
Misconfigurations in IoT on-premises and cloud-based solutions can lead to data theft. The following are some of the most common misconfigurations of IoT devices and cloud-based solutions.
### Default/blank username/password
Hardcoded or default credentials are often left in place by administrators and in some cases by software developers, exposing devices or the cloud environment to different attacks.
### Network exposure
Many IoT, ICS, and SCADA systems should never be exposed to the Internet (see https://www.shodan.io/explore/category/industrial-control-systems). For example, programmable logic controllers (PLCs) controlling turbines in a power plant, the lighting at a stadium, and robots in a factory should never be exposed to the Internet. However, you can often see such systems in Shodan scan results.
### Lack of user input sanitization
Input validation vulnerabilities in protocols such as Modbus, S7 Communication, DNP3, and Zigbee could lead to DoS and code execution.
### Underlying software vulnerabilities and injection vulnerabilities
IoT systems can be susceptible to SQL injection and similar vulnerabilities.
### Error messages and debug handling
Many IoT systems include details in error messages and debugging output that can allow an attacker to obtain sensitive information from the system and underlying network.

## Management Interface Vulnerabilities
IoT implementations have suffered from many _management interface vulnerabilities_. For example, the **_Intelligent Platform Management Interface (IPMI)_** is a collection of compute interface specifications (often used by IoT systems) designed to offer management and monitoring capabilities independently of the host system’s CPU, firmware, and operating system. System administrators can use IPMI to enable out-of-band management of computer systems (including IoT systems) and to monitor their operation. For instance, you can use IPMI to manage a system that may be powered off or otherwise unresponsive by using a network connection to the hardware rather than to an operating system or login shell. Many IoT devices have supported IPMI to allow administrators to remotely connect and manage such systems.

An IPMI subsystem includes a main controller, called a baseboard management controller (BMC), and other management controllers, called satellite controllers. The satellite controllers within the same physical device connect to the BMC via the system interface called Intelligent Platform Management Bus/Bridge (IPMB). Similarly, the BMC connects to satellite controllers or another BMC in other remote systems via the IPMB.

The BMC, which has direct access to the system’s motherboard and other hardware, may be leveraged to compromise the system. If you compromise the BMC, it will provide you with the ability to monitor, reboot, and even potentially install implants (or any other software) in the system. Access to the BMC is basically the same as physical access to the underlying system.
