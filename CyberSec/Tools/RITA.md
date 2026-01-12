Real Intelligence Threat Analytics (RITA) is an open-source framework created by Active Countermeasures. Its core functionality is to detect command and control (C2) communication by analyzing network traffic captures and logs. Its primary features are:

- C2 beacon detection
- DNS tunneling detection
- Long connection detection
- Data exfiltration detection
- Checking threat intel feeds
- Score connections by severity
- Show the number of hosts communicating with a specific external IP
- Shows the datetime when the external host was first seen on the network

The magic behind RITA is its analytics. It correlates several captured fields, including IP addresses, ports, timestamps, and connection durations, among others. Based on the normalized and correlated dataset, RITA runs several analysis modules collecting information like:

- Periodic connection intervals
- Excessive number of DNS queries
- Long FQDN
- Random subdomains
- Volume of data over time over HTTPS, DNS, or non-standard ports
- Self-signed or short-lived certificates
- Known malicious IPs by cross-referencing with public threat intel feeds or blocklists

RITA only accepts network traffic input as **Zeek** logs. 
## Zeek
**Zeek** is an open-source **network security monitoring (NSM)** tool. 
- https://docs.zeek.org/en/master/index.html
Zeek (formerly Bro) is the world's leading platform for network security monitoring. Flexible, open source, and powered by defenders.
Zeek is not a firewall or IPS/IDS; it does not use signatures or specific rules to take an action. It simply observes network traffic via configured SPAN ports (used to copy traffic from one port to another for monitoring), physical network taps, or imported packet captures in the PCAP format. Zeek then analyzes and converts this input into a structured, enriched output. This output can be used in incident detection and response, as well as threat hunting. Out of the box, Zeek covers two of the four types of NSM data: transaction data (summarized records of application-layer transactions) and extracted content data (files or artifacts extracted, such as executables).

>[!tip]
>A SPAN port (sometimes called a mirror port) is a software feature built into a switch or router that creates a copy of selected packets passing through the device and sends them to a designated SPAN port. Using software, the administrator can easily configure or change what data is to be monitored. Since the primary purpose of a switch or router is to forward production packets, SPAN data is given a lower priority on the device. The SPAN also uses a single egress port to aggregate multiple links, so it is easily oversubscribed.

- convert packet captures (PCAPs) into structured logs:
	`zeek readpcap <pcapfile> <outputdirectory>`
	- zeek will convert this pcap to multiple zeek log files based on log types. 
	- like `capture_loss.log dns.log http.log known_services.log notice.log packet_filter.log software.log stats.log x509.log conn.log files.log known_hosts.log loaded_scripts.log ocsp.log reporter.log ssl.log weird.log`
	- know more about different type of log files [here](https://docs.zeek.org/en/master/logs/index.html#).

## Analysis using RITA
Enter the below command for RITA to import the zeek logs. After importing it will parse and analyze the logs.
	`rita import --logs <zeek logs dir> --database <db-name>`
 
 After RITA has parsed and analyzed our data, we can view the results by entering the command 
	 `rita view <db-name>`

After entering the command, we can see a structured terminal window with the results. The terminal window shows three elements: the search bar, the results pane, and a details pane.
![[RITA-1766600448420.png]]
**Search bar**  
To search, we need to enter a forward slash (/). We can then enter our search term and narrow down the results. The search utility supports the use of search fields. When we enter `?` while in search mode, we can see an overview of the search fields, alongside some examples. The image below shows the help for the search utility. To exit the help page, enter `?` again. Enter the escape key ("esc") to exit the search functionality.

![[66c44fd9733427ea1181ad58-1761301233135.png|RITA - Search help]]

**Results pane**  
The results pane includes information for each entry that can quickly help us recognize potential threats. The following columns are included:
- **Severity**: A score calculated based on the results of threat modifiers (discussed below)
- **Source and destination** IP/FQDN
- **Beacon** likelihood
- **Duration** of the connection: Long connections can be indicators of compromise. Most application layer protocols are stateless and close the connection quickly after exchanging data (exceptions are SSH, RDP, and VNC).
- **Subdomains**: Connections to subdomains with the same domain name. If there are many subdomains, it could indicate the use of a C2 beacon or other techniques for data exfiltration.
- **Threat intel**: lists any matches on threat intel feeds

We can see two interesting findings: an FQDN pointing to `sunshine-bizrate-inc-software[.]trycloudflare[.]com` and an IP `91[.]134[.]150[.]150`. Move the keyboard arrows to select the first entry. You should then see detailed information in the right pane.

![[66c44fd9733427ea1181ad58-1761301302504.png|RITA - Details]]

**Details pane**  
Apart from the Source and Destination, we have two information categories: Threat Modifiers and Connection info. Let's have a closer look at these categories:

_Threat Modifiers_  
These are criteria to determine the severity and likelihood of a potential threat. The following modifiers are available:
- **MIME type/URI mismatch:** Flags connections where the MIME type reported in the HTTP header doesn't match the URI. This can indicate an attacker is trying to trick the browser or a security tool.
- **Rare signature:** Points to unusual patterns that attackers might overlook, such as a unique user agent string that is not seen in any other connections on the network.
- **Prevalence:** Analyzes the number of internal hosts communicating with a specific external host. A low percentage of internal hosts communicating with an external one can be suspicious.
- **First Seen:** Checks the date an external host was first observed on the network. A new host on the network is more likely to be a potential threat.
- **Missing host header:** Identifies HTTP connections that are missing the host header, which is often an oversight by attackers or a sign of a misconfigured system.
- **Large amount of outgoing data**: Flags connections that send a very large amount of data out from the network.
- **No direct connections:** Flags connections that don't have any direct connections, which can be a sign of a more complex or hidden command and control communication.

_Connection Info_  
Here, we can find the connections' metadata and basic connection info like:
- Connection count: Shows the number of connections initiated between the source and destination. A very high number can be an indicator of C2 beacon activity.
- Total bytes sent: Displays the total amount of bytes sent from source to destination. If this is a very high number, it could be an indication of data exfiltration.
- Port number - Protocol - Service: If the port number is non-standard, it warrants further investigation. The lack of SSL in the Service info could also be an indicator that warrants further investigation.

