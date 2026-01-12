ICS denotes systems responsible for overseeing and conducting functions that support critical infrastructure, such as water, power, transportation, and manufacturing.

# SCADA (Supervisory Control and Data Acquisition)
SCADA systems are the "command centres" of industrial operations. They act as the bridge between human operators and the machines doing the work. Think of SCADA as the nervous system of a factory—it senses what's happening, processes that information, and sends commands to make things happen.
## Components of a SCADA System
A SCADA system typically consists of four key components:
- Sensors & Actuators: The physical interface. Sensors measure real-world conditions (temperature, weight, position), while actuators perform physical actions (moving motors, opening valves).
- PLCs (Programmable Logic Controllers): The "brains" of the operation. These are ruggedized industrial computers that execute automation logic by reading sensor data and sending commands to actuators in real-time.
- Monitoring Systems (HMI): Visual interfaces like dashboards, alarm panels, and CCTV feeds that allow human operators to observe processes.
- Historians: Specialized databases that record all operational data over time for troubleshooting and auditing.
## Why SCADA Systems Are Targeted
Industrial control systems, such as SCADA, have become increasingly attractive targets for cybercriminals and nation-state actors. Here's why:

- They often run legacy software with known vulnerabilities. Many SCADA systems were installed decades ago and never updated. Security patches that exist for modern software don't exist for these ageing systems.
- Default credentials are commonly left unchanged. Administrators prioritise keeping systems running over changing passwords. In industrial environments, the mentality is often "if it works, don't touch it"—a recipe for security disasters.
- They're designed for reliability, not security. Most SCADA systems were built before cyber security was a significant concern. They were intended for closed networks that were presumed safe. Authentication, encryption, and access controls were afterthoughts at best.
- They control physical processes. Unlike attacking a website or stealing data, compromising SCADA systems has real-world consequences. Attackers can cause blackouts, contaminate water supplies, or—in our case—sabotage Christmas deliveries.
- They're often connected to corporate networks. The myth of "air-gapped" industrial systems is largely fiction. Most SCADA systems connect to business networks for reporting, remote management, and data integration. This connectivity provides attackers with entry points.
- Protocols like Modbus lack authentication. Many industrial protocols were designed for trusted environments. Anyone who can reach the Modbus port (502) can read and write values without proving their identity.
In early 2024, the first ICS/OT malware, FrostyGoop, was discovered. The malware can directly interface with industrial control systems via the Modbus TCP protocol, enabling arbitrary reads and writes to device registers over TCP port 502.

# PLC
A PLC (Programmable Logic Controller) is an industrial computer designed to control machinery and processes in real-world environments. Unlike your laptop or smartphone, PLCs are purpose-built machines engineered for extreme reliability and harsh conditions.

PLCs are designed to:
- **Survive harsh environments** - They operate flawlessly in extreme temperatures, constant vibration, dust, moisture, and electromagnetic interference. A PLC controlling warehouse robotics might endure freezing temperatures in winter storage areas and scorching heat near packaging machinery.
- **Run continuously without failure** - PLCs operate 24/7 for years, sometimes decades, without rebooting. Industrial facilities can't afford downtime for software updates or system restarts. When a PLC starts running, it's expected to keep running indefinitely.
- **Execute control logic in real-time** - PLCs respond to sensor inputs within milliseconds. When a package reaches the end of a conveyor belt, the PLC must instantly activate the robotic arm to catch it. These timing requirements are critical for safety and efficiency.
- **Interface directly with physical hardware** - PLCs connect directly to sensors (measuring temperature, pressure, position, weight) and actuators (motors, valves, switches, robotic arms). They speak the electrical language of industrial machinery.

# Modbus
Modbus is the communication protocol that industrial devices use to talk to each other. Created in 1979 by Modicon (now Schneider Electric), it's one of the oldest and most widely deployed industrial protocols in the world. Its longevity isn't due to sophisticated features—quite the opposite. Modbus succeeded because it's simple, reliable, and works with almost any device.

Think of Modbus as a basic request-response conversation:
- **Client** (your computer): "PLC, what's the current value of register 0?"
- **Server** (the PLC): "Register 0 currently holds the value 1."
This simplicity makes Modbus easy to implement and debug, but it also means security was never a consideration. There's no authentication, no encryption, no authorisation checking. Anyone who can reach the Modbus port can read or write any value. 

## Modbus Data Types
Modbus organises data into four distinct types, each serving a specific purpose in industrial automation:

|Type|Purpose|Values|Example Use Cases|
|---|---|---|---|
|**Coils**|Digital outputs (on/off)|0 or 1|Motor running? Valve open? Alarm active?|
|**Discrete Inputs**|Digital inputs (on/off)|0 or 1|Button pressed? Door closed? Sensor triggered?|
|**Holding Registers**|Analogue outputs (numbers)|0-65535|Temperature setpoint, motor speed, zone selection|
|**Input Registers**|Analogue inputs (numbers)|0-65535|Current temperature, pressure reading, flow rate|

The distinction between inputs and outputs is important. **Coils** and **Holding Registers** are writable—you can change their values to control the system. **Discrete Inputs** and **Input Registers** are read-only—they reflect sensor measurements that you observe but cannot directly modify.

Remember that crumpled note you found earlier? Now it makes complete sense. The maintenance technician was documenting these exact Modbus addresses and their meanings!

## Modbus Addressing
Each data point in Modbus has a unique **address**—think of it like a house number on a street. When you want to read or write a specific value, you reference it by its address number.

**Critical detail:** Modbus addresses start at 0, not 1. This zero-indexing catches many beginners off guard. When documentation mentions "Register 0," it literally means the first register, not the second.

## Modbus TCP vs Serial Modbus
Originally, Modbus operated over serial connections using RS-232 or RS-485 cables. Devices were physically connected in a network, and this physical isolation provided a degree of security—you needed physical access to the wiring to intercept or inject commands.

Modern industrial systems use **Modbus TCP**, which encapsulates the Modbus protocol inside standard TCP/IP network packets. Modbus TCP servers listen on **port 502** by default.

This network connectivity brings enormous benefits—remote monitoring, easier integration with business systems, and centralised management. But it also exposes these historically isolated systems to network-based attacks.

## The Security Problem
Modbus has no built-in security mechanisms:
- **No authentication:** The protocol doesn't verify who's making requests. Any client can connect and issue commands.
- **No encryption:** All communication happens in plaintext. Anyone monitoring network traffic can see exactly what values are being read or written.
- **No authorisation:** There's no concept of permissions. If you can connect, you can read and write anything.
- **No integrity checking:** Beyond basic checksums for transmission errors, there's no cryptographic verification that commands haven't been tampered with.

Modern security solutions exist—VPNs, firewalls, Modbus security gateways—but they're add-ons, not part of the protocol itself. Many industrial facilities haven't implemented these protections, either due to cost concerns, compatibility issues with legacy equipment, or a simple lack of awareness.

## Modbus Reconnaissance
Using `pymodbus` python library.
