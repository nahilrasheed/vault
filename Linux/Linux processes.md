##  View Running Processes in Linux
The `ps` command without any options displays information about processes that are bound by the controlling terminal.
Better command : `ps auxf`
- The a flag stands for 'all.' When used with ps, it lists processes from all users on the system.
- The u flag stands for 'user.' It provides detailed information about each process, including the user that owns the process.
- The x flag stands for 'extended.' It lists processes not attached to a terminal, such as system services.
- The f flag do full-format listing

Another tool is `top` which can help you see all of the processes running on your system with live usage statistics.
## Process management
After you press `ctrl+z` it will pause execution of the current process and move it to the background. If you wish to start running it in the background, then type `bg` after pressing `ctrl-z`.
If you wish to have it run in the foreground (and take away your ability to enter new commands into the prompt), type `fg` after pressing `ctrl-z`
If you wish to run it in the background right from the beginning use `&` at the end of your command.

To list all of the suspended processes in the background, you can use two different commands: `ps` and `jobs` (recommended).
`ps` command-list all of the running processes in your system. While the `jobs` command only lists the suspend process suspended using the CTRL+Z shortcut key in your Linux system.

You can additionally run `disown` to detach the now-backgrounded process from the terminal. This lets you close the terminal window without affecting the backgrounded program.

To kill a process use `kill [pid]`. 
	This sends the **TERM** signal to the process. The TERM signal tells the process to please terminate. This allows the program to perform clean-up operations and exit smoothly.
If the program is misbehaving and does not exit when given the TERM signal, you can escalate the signal by passing the `KILL` signal:
	`kill -KILL [pid]`
	 This is a special signal that is not sent to the program. Instead, it is given to the operating system kernel, which shuts down the process. This is used to bypass programs that ignore the signals sent to them.
## Manage Services
- to start a service at startup 
	 `sudo systemctl enable [service] ` 
- start apache http web server
	 `sudo service apache2 start` 
	 to start a apache2 server which will host the location **/var/www/html** 
- python http server
	 `python3 -m http.server 80` 
	 to start a python server which will host everything in the current directory

---
- https://www.digitalocean.com/community/tutorials/how-to-use-ps-kill-and-nice-to-manage-processes-in-linux
- https://iximiuz.com/en/posts/how-to-on-processes/
