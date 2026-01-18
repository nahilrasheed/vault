---
tags:
  - CyberSec/tools
---
**_Metasploit_** is by far the most popular exploitation framework in the industry. 
- It was created by a security researcher named H. D. Moore and then sold to Rapid7. 
- There are two versions of Metasploit: a community (free) edition and a professional edition. 
- Metasploit, which is written in Ruby, has a robust architecture. 
- Metasploit is installed in /usr/share/metasploit-framework by default in Kali Linux. All corresponding files, modules, documentation, and scripts are located in that folder.
### Modules
Metasploit has several modules:
- auxiliary
- encoders
- exploits
- nops
- payloads
- post (for post-exploitation)

> [!tip] Usage : 
> You can launch the Metasploit console by using the **msfconsole** command.
> - `msfconsole`
> - `search [service/vuln]`
> - `use [exploit name or no`]
> - `set RHOSTS [ip of victim]`
> - `options` to see current config 
> - `show targets` 
> - `run` or `exploit`
> - to change payloads
> 	- `set payload [name]`
> 

Payload Types:
- Non-Staged
	- Sends exploit shellcode all at once
	- Larger in size and wont always work
	- eg: windows/meterpreter_reverse_tcp
- Staged
	- Sends payload in stages
	- can be less stable
	- eg: windows/meterpreter/reverse_tcp

## Meterpreter
The Meterpreter module of the Metasploit framework can be used to create bind and reverse shells and to perform numerous other post-exploitation tasks.
Meterpreter payload for a bind TCP connection (after exploitation) being set:
	`set payload windows/x64/meterpreter/bind_tcp`
### Common Meterpreter commands
| Meterpreter Command          | Description                                                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `cat`, `cd`, `pwd`, and `ls` | These commands are the same as the ones in Linux or Unix-based systems.                                            |
| `lpwd` and `lcd`             | These commands are used to display and change the local directory (on the attacking system).                       |
| `clearev`                    | This command is used to clear the Application, System, and Security logs on a Windows-based system.                |
| `download`                   | This command is used to download a file from a victim system.                                                      |
| `edit`                       | This command is used to open and edit a file on a victim system using the Vim Linux environment.                   |
| `execute`                    | This command is used to run commands on the victim system.                                                         |
| `getuid`                     | This command is used to display the user logged in on the compromised system.                                      |
| `getsystem`                  |                                                                                                                    |
| `sysinfo`                    |                                                                                                                    |
| `screenshot`                 |                                                                                                                    |
| `hashdump`                   | This command is used to dump the contents of the SAM database in a Windows system.                                 |
| `idletime`                   | This command is used to display the number of seconds that the user at the victim system has been idle.            |
| `ipconfig`                   | This command is used to display the network interface configuration and IP addresses of the victim system.         |
| `migrate`                    | This command is used to migrate to a different process on the victim system.                                       |
| `ps`                         | This command is used to display a list of running processes on the victim system.                                  |
| `resource`                   | This command is used to execute Meterpreter commands listed inside a text file, which can help accelerate actions. |
| `search`                     | This command is used to locate files on the victim system.                                                         |
| `shell`                      | This command is used to go into a standard shell on the victim system.                                             |
| `upload`                     | This command is used to upload a file to the victim system.                                                        |
| `webcam_list`                | This command is used to display all webcams on the victim system.                                                  |
| `webcam_snap`                | This command is used to take a snapshot (picture) using a webcam of the victim system.                             |

## Accelerate the tasks in Metasploit
You can use the PostgreSQL database in Kali to accelerate the tasks in Metasploit and index the underlying components. 
1. You need to start the PostgreSQL service before using the database by using the following command: `service postgresql start`
2. After starting the PostgreSQL service, you need to create and initialize the Metasploit database with the **msfdb init** command.
	Set password.
3. You can search for exploits, auxiliary, and other modules by using the **search** command

---
-  Metasploit Unleashed is a free detailed Metasploit course released by Offensive Security. The course can be accessed at [_https://www.offensive-security.com/metasploit-unleashed_](https://www.offensive-security.com/metasploit-unleashed).
