---
tags:
  - CyberSec/tools
  - CiscoEH
---
Ettercap is used to perform on-path/[[MITM or On-Path Attacks]]. The goal of an on-path attack is to intercept traffic between devices to obtain information that can be used to impersonate the target or to alter data being transmitted. The attacker is situated” between” two communicating hosts. In on-path attacks, the hacker doesn’t need to compromise the target device, but can just sniff traffic passing back and forth between the target and destination. Ettercap is used as an on-path tool, and the attack machine is on the same IP network as the victim.

Four user interfaces are available for the Ettercap tool
```
  -T, --text                  use text only GUI
       -q, --quiet                 do not display packet contents
       -s, --script <CMD>          issue these commands to the GUI
  -C, --curses                use curses GUI
  -D, --daemon                daemonize ettercap (no GUI)
  -G, --gtk                   use GTK+ GUI
```

## Part 1: Launch Ettercap and Explore its Capabilities.
### Step 1: Set up an ARP spoofing attack.

In this attack, you will use ARP spoofing to redirect traffic on the local virtual network to your Kali Linux system at 10.6.6.1. ARP spoofing is often used to impersonate the default gateway router to capture all traffic entering or leaving the local IP network. Because your lab environment uses an internal virtual network, instead of spoofing the default gateway, you will use ARP spoofing to redirect traffic that is destined for a local server with the address 10.6.6.13.

1. Load Kali Linux using the username **kali** and the password **kali**. Open a terminal session from the menu bar at the top of the screen.
2. The target host in this lab is the Linux device at 10.6.6.23. To view the network from the target perspective, and initiate traffic between the target and the server, use SSH to log in to this host. The username is **labuser** and the password is **Cisco123**.

The user of the 10.6.6.23 host is communicating with the server at 10.6.6.13. The on-path attacker at 10.6.6.1 (your Kali VM) will intercept and relay traffic between these hosts.

	ssh -l labuser 10.6.6.23
	labuser@10.6.6.23’s password: **Cisco123**

3. Because you are creating an on-path attack that uses ARP spoofing, you will be monitoring the ARP mappings on the victim host. The attack will cause changes to those mappings.

Use the command **ip neighbor** to view the current ARP cache on the target computer. **Note**: The hostname 3fb0515ea2f7 maybe different for your Kali VM environment.

```
labuser@3fb0515ea2f7:/$ **ip neighbor**
10.6.6.1 dev eth0 llanddr 02:42:17:81:d2:45 REACHABLE (output may vary)
```
you can also use the command **arp -a** with sudo in place of **ip neighbor** to view the current ARP cache throughout this activity.

```
labuser@gravemind:/$ **su -**
Password: **Cisco123**
root@gravemind:/$ **arp -a**
? (10.6.6.1) at 02:42:17:d5:bb:2b:ab [ether] on eth0
```

![[image 1.png|600|500]]
### Step 2: Load Ettercap GUI interface to begin scanning.

1. Open a new terminal session from the menu bar in Kali Linux. Do not close the SSH-terminal that is running the session with 10.6.6.23.
2. Use the **ettercap -h** command to view the help file for the Ettercap application.
3. In this part, you will use a GUI interface to access Ettercap. Start Ettercap GTK+ graphical user interface using the `ettercap -G` command. Most Ettercap functions require root permissions, so use the **sudo** command to obtain the required permissions.
```shell
sudo ettercap -G
```
1. The Ettercap GUI opens in a new window. You are sniffing traffic on an internal, virtual network. The default setup is to scan using interface eth0. Change the sniffing interface to **br-internal**, which is the interface that is configured on the 10.6.6.0/24 virtual network, by changing the value in the **Setup > Primary** **Interface** dropdown.
2. Click the **checkbox** icon at the top right of the Ettercap screen to continue. A message appears at the bottom of the screen indicating that Unified sniffing has started.

## Part 2: Perform the On-Path (MITM) Attack
### Step 1: Select the Target Devices.
1. In the Ettercap GUI window, open the Hosts List window by clicking the Ettercap menu (three dots icon). Select the **Hosts** entry and then **Hosts List**. Click the **Scan for Hosts** icon (magnifying glass) at top left in the menu bar. A list of the hosts that were discovered on the 10.6.6.0/24 network appears in the Host List window.
2. Define the source and destination devices for the attack. To do so, click the IP address **10.6.6.23** in the window to highlight the target user host. Click the **Add to Target 1** button at the bottom of the Host List window. This defines the user’s host as Target 1.
3. Click the IP address of the destination web server at **10.6.6.13** to highlight the line. Click the **Add to Target 2** button at the bottom of the host window.

Any IP/MAC address specified as a Target 1 will have all its traffic diverted through the attacking computer that is running Ettercap. In this lab, the attacking computer is the Kali Linux machine at 10.6.6.1. All other computers on the subnet, other than the targets, will communicate normally.

4. Click the MITM icon on the menu bar (the first circular icon on top right). Select **ARP Poisoning…** from the dropdown menu. Verify that **Sniff remote connections** is selected. Click **OK**.
5. The MITM exploit is started. If sniffing does not start immediately, click the **Start** option (play button) at left in the top menu.

### Step 2: Perform the ARP spoofing attack.

1. Return to the terminal window that is running the SSH session with the target user host at 10.6.6.23. Repeat the ping to 10.6.6.13
`labuser@3fb0515ea2f7:/$ ping -c 5 10.6.6.13`

2. Use the **ip neighbor** command to view the ARP table on 10.6.6.23 again. Note the MAC address listed for 10.6.6.13.
3. Close the Ettercap graphical user interface. Leave the SSH connection to 10.6.6.23 active.

## Part 3: Use [[Wireshark]] to Observe the ARP Spoofing Attack

### Step 1: Select the Target Devices and Perform the MITM attack using the CLI

In this step, you will use the command line interface in Ettercap to perform ARP spoofing and write a .pcap file that can be opened in Wireshark. Refer to the help information for Ettercap to interpret the options used in the commands.

1. Return to the terminal session that is connected via SSH to 10.6.6.23. Ping the IP addresses 10.6.6.11 and 10.6.6.13. 10.6.6.11 is another host on the LAN that we will verify is unaffected by the attack. Then, use the **ip neighbor** command to find the MAC addresses associated with the IP addresses of the two systems.

```
labuser@3fb0515ea2f7:/$ **ping -c 5 10.6.6.11**
labuser@3fb0515ea2f7:/$ **ping -c 5 10.6.6.13**
labuser@3fb0515ea2f7:/$ **ip neighbor**
```

**Note**: To find the MAC of 10.6.6.23, go to the SSH session terminal and enter the **ip address** command. Determine the MAC address of the interface that is addressed on the 10.6.6.0/24 network.

2. The **ettercap -T** command runs Ettercap in text mode, instead of using the GUI interface. The syntax to start Ettercap and specify the targets is: `sudo ettercap -T options -q -i interface --write file name -- mitm arp /target 1// /target 2//.`

| Options and Values | Meaning                                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------- |
| -T                 | user the text only interface                                                                 |
| -q                 | run the command in quiet mode to simplify output                                             |
| -i                 | specify the sniffing/attacking network interface                                             |
| --write            | Write packets to a .pcap file that can be opened in Wireshark. Specify the name for the file |
| --mitm arp         | Conduct the ARP poisoning MITM attack                                                        |
| /target1//         | the IP address of the target user host                                                       |
| /target2//         | the IP address of the target server                                                          |

3. In a terminal window, enter the command as follows to save the pcap file in the current working directory:
 `ettercap -T -q -i br-internal --write mitm-saved.pcap --mitm arp /10.6.6.23// /10.6.6.13//`
When Ettercap starts, you will receive output. 

4. Return to the SSH terminal session to 10.6.6.23. Ping the two IP addresses, 10.6.6.11 and 10.6.6.13, again. Use the **ip neighbor** command to view the associated MAC addresses.
5. Close the SSH terminal session that is connected to 10.6.6.23 and return to the terminal session running Ettercap in text mode. Enter **q** to quit Ettercap.

### Step 2: Open Wireshark to view the Saved PCAP file.

In this step, you will examine the .pcap file that Ettercap created.
1. Review the MAC addresses that you recorded in Step 1c. The MAC address for 10.6.6.23 can be found in the output of the Ettercap text interface in Target Group 1.
2. In the Kali terminal window, start Wireshark with the **mitm-saved.pcap** file that you created with Ettercap.
	`wireshark mitm-saved.pcap`

3. The Ettercap attack computer first broadcasts ARP requests to obtain the actual MAC addresses for the two target hosts, 10.6.6.23 and 10.6.6.11. The attacking machine then begins to send ARP responses to both target hosts using its own MAC for both IP addresses. This causes the two target hosts to address the Ethernet frames to the attacker’s computer, which enables it to collect data as an on-path attacker.
