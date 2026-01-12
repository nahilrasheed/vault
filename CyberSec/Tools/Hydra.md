---
tags:
  - CyberSec/tools
---
Used for Bruteforce attacks
- **_Hydra_** is a tool that is used to guess and crack credentials. 
- Hydra is typically used to interact with a victim server (for example, web server, FTP server, SSH server, file server) and try a list of username/password combinations.

> [!TIP] Basic usage
>```
hydra -l [user | root] -P [wordlist (/usr/share/wordlists/metasploit/unix_passwords.txt)] [uri (ssh://192.168.57.25:22)] -t [no of threads (4)] -V
>```

```
 -l LOGIN or -L FILE login with LOGIN name, or load several logins from FILE
 -p PASS or -P FILE try password PASS, or load several passwords from FILE
 -C FILE    colon separated "login:pass" format, instead of -L/-P options
 -M FILE    list of servers to attack, one entry per line, ':' to specify port
 -t TASKS   run TASKS number of connects in parallel per target (default: 16)
 -U         service module usage details

```

- For example, say you know that an FTP user’s username is omar. You can then try a file that contains a list of passwords against an FTP server (10.1.2.3). To accomplish this, you use the following command: `hydra -l omar -P passwords.txt ftp://10.1.2.3` 

> We can also use metaspoit for bruteforcing ssh

