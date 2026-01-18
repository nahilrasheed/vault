A signature specifies detection rules. These rules outline the types of network intrusions you want an IDS to detect. 
For example, a signature can be written to detect and alert on suspicious traffic attempting to connect to a port. Rule language differs depending on different network intrusion detection systems.

NIDS rules consists of three components: an action, a header, and rule options.
- Action
	- Determines the action to take if the rule criteria matches are met. 
	- Actions differ across NIDS rule languages, but some common actions are: alert, pass, or reject.
- Header
	- The header defines the signature's network traffic. These include information such as source and destination IP addresses, source and destination ports, protocols, and traffic direction. If we want to detect an alert on suspicious traffic connecting to a port, we have to first define the source of the suspicious traffic in the header. Suspicious traffic can originate from IP addresses outside the local network. It can also use specific or unusual protocols. We can specify external IP addresses and these protocols in the header.
![[Signature rules-1765219231508.png]]

- Rule Options
	- The rule options lets you customize signatures with additional parameters. There are many different options available to use.
	-  Typically, rule options are separated by semi-colons and enclosed in parentheses.
![[Signature rules-1765219342529.png]]

[[Suricata]]
[[YARA]]
