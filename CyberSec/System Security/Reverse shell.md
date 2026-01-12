A _shell_ is a utility (software) that acts as an interface between a user and the operating system (the kernel and its services). 
For example, in Linux there are several shell environments, such as Bash, ksh, and tcsh. Traditionally, in Windows the shell is the command prompt (command-line interface), which is invoked by cmd.exe. Windows PowerShell is a newer Microsoft shell that combines the old CMD functionality with a new scripting/cmdlet instruction set with built-in system administration functionality. PowerShell cmdlets allow users and administrators to automate complicated tasks with reusable scripts.

## Bind shell
With a bind shell, an attacker opens a port or a listener on the compromised system and waits for a connection. This is done in order to connect to the victim from any system and execute commands and further manipulate the victim.
## Reverse shell
A reverse shell is a vulnerability in which an attacking system has a listener (port open), and the victim initiates a connection back to the attacking system. 

Many tools allow you to create bind and reverse shells from a compromised host. Some of the most popular ones are the Meterpreter module in Metasploit and Netcat. Netcat is one of the best and most versatile tools for pen testers because it is lightweight and very portable.

- [[Netcat]]
- [[Metasploit#Meterpreter|Meterpreter]]
