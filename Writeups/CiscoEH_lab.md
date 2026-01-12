## Your Employer: Protego Security Solutions
![[image-1.jpg|292x377]]
## Your Client: Pixel Paradise
![[image-3.jpg|296x381]]
## 3.2.6 Lab - Enumeration with nmap
![[image.jpg|493x313]]
A Wireshark capture shows unusual activity on a machine on the 10.6.6.0 DMZ network. You’ve been asked to do some active recon on the machine to determine what services it may be offering and if there are vulnerable applications that could present security issues. The IP address of the suspicious computer is 10.6.6.23. You have access to a Kali Linux system on the 10.6.6.0 network.

``` 
$> ip route
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100 
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100 
10.5.5.0/24 dev br-339414195aeb proto kernel scope link src 10.5.5.1 
10.6.6.0/24 dev br-internal proto kernel scope link src 10.6.6.1 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
192.168.0.0/24 dev br-355ee7945a88 proto kernel scope link src 192.168.0.1 
```

```
$> arp -a
juice-shop.vm (10.6.6.12) at 02:42:0a:06:06:0c [ether] on br-internal
gravemind.vm (10.6.6.23) at 02:42:0a:06:06:17 [ether] on br-internal
metasploitable.vm (172.17.0.2) at 02:42:ac:11:00:02 [ether] on docker0
juice-shop.pc (10.5.5.13) at 02:42:0a:05:05:0d [ether] on br-339414195aeb
gravemind.pc (10.5.5.14) at 02:42:0a:05:05:0e [ether] on br-339414195aeb
metasploitable.pc (192.168.0.10) at 02:42:c0:a8:00:0a [ether] on br-355ee7945a88
```

```
$> nmap -sn 10.6.6.0/24                                                                                                                                                                                                                   
Starting Nmap 7.94 ( https://nmap.org ) at 2025-06-18 16:51 UTC
Nmap scan report for 10.6.6.1
Host is up (0.00043s latency).
Nmap scan report for webgoat.vm (10.6.6.11)
Host is up (0.0022s latency).
Nmap scan report for juice-shop.vm (10.6.6.12)
Host is up (0.0020s latency).
Nmap scan report for dvwa.vm (10.6.6.13)
Host is up (0.00019s latency).
Nmap scan report for mutillidae.vm (10.6.6.14)
Host is up (0.00011s latency).
Nmap scan report for gravemind.vm (10.6.6.23)
Host is up (0.00088s latency).
Nmap scan report for 10.6.6.100
Host is up (0.00015s latency).
Nmap done: 256 IP addresses (7 hosts up) scanned in 16.04 seconds
```

