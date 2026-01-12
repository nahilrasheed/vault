---
tags:
  - CyberSec
---
## Security Information and Event Management tools (SIEM tools)
A SIEM tool is an application that collects and analyzes log data to monitor critical activities in an organization. SIEM tools collect real-time, or instant, information, and allow security analysts to identify potential breaches as they happen.
 eg: [[Splunk]], Google's Chronicle
 
- A log is a record of events that occur within an organization's systems.  ^a16bc1
- A firewall log is a record of attempted or established connections for incoming traffic from the internet. It also includes outbound requests to the internet from within the network.
- A network log is a record of all computers and devices that enter and leave the network. It also records connections between devices and services on the network.
- A server log is a record of events related to services such as websites, emails, or file shares. It includes actions such as login, password, and username requests.
> Metrics: key technical attributes such as response time, availability, and failure rate, which are used to assess the performance of a software application.
### Benefits of SIEM
- **Access to event data:** SIEM tools provide access to the event and activity data that happens on a network, including real-time activity. Networks can be connected to hundreds of different systems and devices. SIEM tools have the ability to ingest all of this data so that it can be accessed.
- **Monitoring, detecting, and alerting:** SIEM tools continuously monitor systems and networks in real-time. They then analyze the collected data using detection rules to detect malicious activity. If an activity matches the rule, an alert is generated and sent out for security teams to assess.
- **Log storage:** SIEM tools can act as a system for data retention, which can provide access to historical data. Data can be kept or deleted after a period depending on an organization's requirements.
### SIEM process
#### 1. Collect and aggregate data
SIEM tools require data for them to be effectively used. During the first step, the SIEM collects event data / logs from various sources like firewalls, servers, routers, and more. This data contains event details like timestamps, IP addresses, and more. After all of this log data is collected, it gets aggregated in one location. Aggregation refers to the process of consolidating log data into a centralized place. Through collection and aggregation, SIEM tools eliminate the need for manually reviewing and analyzing event data by accessing individual data sources. Instead, all event data is accessible in one location—the SIEM.
Parsing can occur during the first step of the SIEM process when data is collected and aggregated. _Parsing_ maps data according to their fields and their corresponding values.
#### 2. Normalize data
SIEM tools collect data from many different sources. This data must be transformed into a single format so that it can be easily processed by the SIEM. However, each data source is different and data can be formatted in many different ways. For example, a firewall log can be formatted differently than a server log.
Collected event data should go through the process of normalization. Normalization converts data into a standard, structured format that is easily searchable. 
#### 3. Analyze data
After log data has been collected, aggregated, and normalized, the SIEM must do something useful with all of the data to enable security teams to investigate threats. During this final step in the process, SIEM tools analyze the data. Analysis can be done with some type of detection logic such as a set of rules and conditions. SIEM tools then apply these rules to the data, and if any of the log activity matches a rule, alerts are sent out to cybersecurity teams.

**Security orchestration, automation, and response (SOAR)** is a collection of applications, tools, and workflows that uses automation to respond to security events.
### Different types of SIEM tools
- Self hosted
- Cloud
- Hybrid
## Common SIEM tools
- **[[Splunk]]**
- **Chronicle** is Google's cloud-native tool designed to retain, analyze, and search data. Chronicle provides log monitoring, data analysis, and data collection. It is specifically designed to take advantage of cloud computing capabilities including availability, flexibility, and scalability. (Now Google SecOps)
- **Suricata**
	- Suricata is an open-source network analysis and threat detection software.
	- Suricata was developed by the Open Information Security Foundation (OISF).
- AlienVault® OSSIM™
- Elastic
- Exabeam
- IBM QRadar® Security Intelligence Platform
- LogRhythm
- [[Wazuh]]
	
## [[SIEM tools|SIEM Dashboards]]
## Log Injestion
Data is required for SIEM tools to work effectively. SIEM tools must first collect data using log ingestion. Log ingestion is the process of collecting and importing data from log sources into a SIEM tool. Data comes from any source that generates log data, like a server.

In log ingestion, the SIEM creates a copy of the event data it receives and retains it within its own storage. This copy allows the SIEM to analyze and process the data without directly modifying the original source logs. The collection of event data provides a centralized platform for security analysts to analyze the data and respond to incidents. This event data includes authentication attempts, network activity, and more.

## Log forwarders
Log forwarders are software that automate the process of collecting and sending log data.
Manually uploading data may be inefficient and time-consuming because networks can contain thousands of systems and devices. Hence, it's easier to use software that helps collect data.
Some operating systems have native log forwarders. If you are using an operating system that does not have a native log forwarder, you would need to install a third-party log forwarding software on a device. After installing it, you'd configure the software to specify which logs to forward and where to send them.
## Searching
Different SIEM tools use different search methods. 
**Splunk** uses its own query language called Search Processing Language, or SPL for short. SPL has many different search options you can use to optimize search results, so that you can get the data you're looking for.

**Chronicle** uses the YARA-L language to define rules for detection. It's a computer language used to create rules for searching through ingested log data. For example, you can use YARA-L to write a rule to detect specific activities related to the exfiltration of valuable data. Using Chronicle's search field, you can search for fields like hostname, domain, IP, URL, email, username, or file hash.
The default method of search is using UDM search, which stands for Unified Data Model. It searches through normalized data. If you can't find the data you're looking for searching the normalized data, you have the option of searching raw logs. Raw log search searches through the logs which have not been normalized.

- [Splunk’s Search Manual](https://docs.splunk.com/Documentation/Splunk/9.0.1/Search/GetstartedwithSearch) on how to use the Splunk search processing language (SPL)
- [Google Security Operations quickstart guide](https://cloud.google.com/chronicle/docs/review-security-alert) on the different types of searches.
