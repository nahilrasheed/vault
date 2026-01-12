The security of Wi-Fi networks is important because wireless signals often extend beyond the physical boundaries of a facility, making them accessible to outsiders. Since these networks are essentially part of the internal infrastructure, it's crucial to regularly test and verify their security measures. 
Equally important though not specific to Wi-Fi is strong network access control. This ensures that even if someone manages to connect to the wireless network, they won't be able to reach sensitive data or systems.
- [[Wireless Protocols]]
## Rogue Access Points
One of the most simplistic wireless attacks involves an attacker installing a rogue AP in a network to fool users to connect to that AP. Basically, the attacker can use that rogue AP to create a backdoor and obtain access to the network and its systems
## Evil Twin Attacks
In an *evil twin* attack, the attacker creates a rogue access point and configures it exactly the same as the existing corporate network
Typically, the attacker uses DNS spoofing to redirect the victim to a cloned captive portal or a website. When users are logged on to the evil twin, a hacker can easily inject a spoofed DNS record into the DNS cache, changing the DNS record for all users on the fake network. Any user who logs in to the evil twin will be redirected by the spoofed DNS record injected into the cache. An attacker who performs a DNS cache poisoning attack wants to get the DNS cache to accept a spoofed record. Some ways to defend against DNS spoofing are using packet filtering, cryptographic protocols, and spoofing detection features provided by modern wireless implementations.

**TIP** _Captive portals_ are web portals that are typically used in wireless networks in public places such as airports and coffee shops. They are typically used to authenticate users or to simply display terms and conditions that apply to users when they are using the wireless network. The user can simply click Accept to agree to the terms and conditions. In some cases, the user is asked to view an advertisement, provide an email address, or perform some other required action. Attackers can impersonate captive portals to perform social engineering attacks or steal sensitive information from users.

## Disassociation (or Deauthentication) Attacks
An attacker can cause legitimate wireless clients to deauthenticate from legitimate wireless APs or wireless routers to either perform a DoS condition or to make those clients connect to an evil twin. This type of attack is also known as a **_disassociation attack_** because the attacker disassociates (tries to disconnect) the user from the authenticating wireless AP and then carries out another attack to obtain the user’s valid credentials.

A service set identifier (SSID) is the name or identifier associated with an 802.11 wireless local area network (WLAN). SSID names are included in plaintext in many wireless packets and beacons. A wireless client needs to know the SSID in order to associate with a wireless AP. It is possible to configure wireless passive tools like Kismet or KisMAC to listen to and capture SSIDs and any other wireless network traffic. In addition, tools such as _Airmon-ng_ (which is part of the [[Aircrack-ng]] suite) can perform this reconnaissance. The Aircrack-ng suite of tools can be downloaded from [https://www.aircrack-ng.org](https://www.aircrack-ng.org/)

Many corporations and individuals configure their wireless APs to not advertise (broadcast) their SSIDs and to not respond to broadcast probe requests. However, if you sniff on a wireless network long enough, you will eventually catch a client trying to associate with the AP and can then get the SSID. In Example 5-15 you can see the basic service set identifier (BSSID) and the extended basic service set identifier (ESSID) for every available wireless network. Basically, the ESSID identifies the same network as the SSID. You can also see the ENC encryption protocol. The encryption protocols can be Wi-Fi Protected Access (WPA) version 1, WPA version 2 (WPA2), WPA version 3 (WPA3), Wired Equivalent Privacy (WEP), or open (OPN).

The 802.11w standard defines the Management Frame Protection (MFP) feature. MFP protects wireless devices against spoofed management frames from other wireless devices that might otherwise deauthenticate a valid user session. In other words, MFP helps defend against deauthentication attacks. MFP is negotiated between the wireless client (supplicant) and the wireless infrastructure device (AP, wireless router, and so on).

## Preferred Network List Attacks
Operating systems and wireless supplicants (clients), in many cases, maintain a list of trusted or preferred wireless networks. This is also referred to as the _preferred network list (PNL)_. A PNL includes the wireless network SSID, plaintext passwords, or WEP or WPA passwords. Clients use these preferred networks to automatically associate to wireless networks when they are not connected to an AP or a wireless router.

It is possible for attackers to listen to these client requests and impersonate the wireless networks in order to make the clients connect to the attackers’ wireless devices and eavesdrop on their conversation or manipulate their communication.
## Wireless Signal Jamming and Interference
The purpose of **_jamming_** wireless signals or causing wireless network interference is to create a full or partial DoS condition in the wireless network. Such a condition, if successful, is very disruptive. Most modern wireless implementations provide built-in features that can help immediately detect such attacks. In order to jam a Wi-Fi signal or any other type of radio communication, an attacker basically generates random noise on the frequencies that wireless networks use. With the appropriate tools and wireless adapters that support packet injection, an attacker can cause legitimate clients to disconnect from wireless infrastructure devices.
## War Driving
_War driving_ is a method attackers use to find wireless access points wherever they might be. By just driving (or walking) around, an attacker can obtain a significant amount of information over a very short period of time. Another similar attack is _war flying_, which involves using a portable computer or other mobile device to search for wireless networks from an aircraft, such as a drone or another unmanned aerial vehicle (UAV).
> **TIP** A popular site among war drivers is WiGLE ([_https://wigle.net_](https://wigle.net/)). The site allows users to detect Wi-Fi networks and upload information about the networks by using a mobile app.

## Initialization Vector (IV) Attacks and Unsecured Wireless Protocols
An attacker can cause some modification on the initialization vector (IV) of a wireless packet that is encrypted during transmission. The goal of the attacker is to obtain a lot of information about the plaintext of a single packet and generate another encryption key that can then be used to decrypt other packets using the same IV. WEP is susceptible to many different attacks, including IV attacks.

- [[Wifi hacking]]
## Attacks Against WEP
Because WEP is susceptible to many different attacks, it is considered an obsolete wireless protocol. WEP must be avoided, and many wireless network devices no longer support it. WEP keys exist in two sizes: 40-bit (5-byte) and 104-bit (13-byte) keys. In addition, WEP uses a 24-bit IV, which is prepended to the pre-shared key (PSK). When you configure a wireless infrastructure device with WEP, the IVs are sent in plaintext.

WEP has been defeated for decades. WEP uses RC4 in a manner that allows an attacker to crack the PSK with little effort. The problem is related to how WEP uses the IVs in each packet. When WEP uses RC4 to encrypt a packet, it prepends the IV to the secret key before including the key in RC4. Subsequently, an attacker has the first 3 bytes of an allegedly “secret” key used on every packet. In order to recover the PSK, an attacker just needs to collect enough data from the air. An attacker can accelerate this type of attack by just injecting ARP packets (because the length is predictable), which allows the attacker to recover the PSK much faster. After recovering the WEP key, the attacker can use it to access the wireless network.

An attacker can also use the Aircrack-ng set of tools to crack (recover) the WEP PSK.
- [[Aircrack-ng#Cracking WEP PSK|Cracking WEP PSK]]

## Attacks Against WPA
WPA and WPA version 2 (WPA2) are susceptible to different vulnerabilities. WPA version 3 (WPA3) addresses all the vulnerabilities to which WPA and WPA2 are susceptible, and many wireless professionals recommend WPA3 to organizations and individuals.

All versions of WPA support different authentication methods, including PSK. WPA is not susceptible to the IV attacks that affect WEP; however, it is possible to capture the WPA four-way handshake between a client and a wireless infrastructure device and then brute-force the WPA PSK.
![[Wireless Vulnerabilities and Attacks-1751395877097.png]]     ![[Wireless Vulnerabilities and Attacks-1751395898932.png]]

Capturing the WPA Four-Way Handshake and Cracking the PSK
- Step 1. An attacker monitors the Wi-Fi network and finds wireless clients connected to the corp-net SSID.
- Step 2. The attacker sends DeAuth packets to deauthenticate the wireless client.
- Step 3. The attacker captures the WPA four-way handshake and cracks the WPA PSK. (It is possible to use word lists and tools such as Aircrack-ng to perform this attack.)

- [[Aircrack-ng#Cracking WPA PSK|Cracking WPA PSK using Aircrack-ng]]

## KRACK Attacks

Mathy Vanhoef and Frank Piessens, from the University of Leuven, found and disclosed a series of vulnerabilities that affect WPA and WPA2. These vulnerabilities – also referred to as KRACK (which stands for _key reinstallation attack_) – and details about them, are published at [_https://www.krackattacks.com_](https://www.krackattacks.com/).

Exploitation of these vulnerabilities depends on the specific device configuration. Successful exploitation could allow unauthenticated attackers to reinstall a previously used encryption or integrity key (either through the client or the access point, depending on the specific vulnerability). When a previously used key has successfully been reinstalled (by exploiting the disclosed vulnerabilities), an attacker may proceed to capture traffic using the reinstalled key and attempt to decrypt such traffic. In addition, the attacker may attempt to forge or replay previously seen traffic. An attacker can perform these activities by manipulating retransmissions of handshake messages.
**NOTE** For details about KRACK attacks, see [_https://blogs.cisco.com/security/wpa-vulns_](https://blogs.cisco.com/security/wpa-vulns).
Most wireless vendors have provided patches that address the KRACK vulnerabilities, and WPA3 also addresses these vulnerabilities.

## WPA3 Vulnerabilities
No technology or protocol is perfect. Several vulnerabilities in WPA3 have been discovered in recent years. The WPA3 protocol introduced a new handshake called the “dragonfly handshake” that uses Extensible Authentication Protocol (EAP) for authentication. Several vulnerabilities can allow an attacker to perform different side-channel attacks, downgrade attacks, and DoS conditions. Several of these vulnerabilities were found by security researcher Mathy Vanhoef. (For details about these attacks, see https://wpa3.mathyvanhoef.com.)

FragAttacks (which stands for fragmentation and aggregation attacks) is another type of vulnerability that can allow an attacker to exploit WPA3. For details and a demo of FragAttacks, see https://www.fragattacks.com.
## Wi-Fi Protected Setup (WPS) PIN Attacks
Wi-Fi Protected Setup (WPS) is a protocol that simplifies the deployment of wireless networks. It is implemented so that users can simply generate a WPA PSK with little interaction with a wireless device. Typically, a PIN printed on the outside of the wireless device or in the box that came with it is used to provision the wireless device. Most implementations do not care if you incorrectly attempt millions of PIN combinations in a row, which means these devices are susceptible to brute-force attacks.

A tool called Reaver makes WPS attacks very simple and easy to execute. You can download Reaver from https://github.com/t6x/reaver-wps-fork-t6x.

## KARMA Attacks
KARMA (which stands for _karma attacks radio machines automatically_) is an on-path attack that involves creating a rogue AP and allowing an attacker to intercept wireless traffic. A radio machine could be a mobile device, a laptop, or any Wi-Fi-enabled device.

In a KARMA attack scenario, the attacker listens for the probe requests from wireless devices and intercepts them to generate the same SSID for which the device is sending probes. This can be used to attack the PNL.

## Fragmentation Attacks
Wireless fragmentation attacks can be used to acquire 1500 bytes of pseudo-random generation algorithm (PRGA) elements. Wireless fragmentation attacks can be launched against WEP-configured devices. These attacks do not recover the WEP key itself but can use the PRGA to generate packets with tools such as Packetforge-ng (which is part of the Aircrack-ng suite of tools) to perform wireless injection attacks.
-  You can find a paper describing and demonstrating fragmentation attacks at [_http://download.aircrack-ng.org/wiki-files/doc/Fragmentation-Attack-in-Practice.pdf_](http://download.aircrack-ng.org/wiki-files/doc/Fragmentation-Attack-in-Practice.pdf).

## Credential Harvesting
Credential harvesting is an attack that involves obtaining or compromising user credentials. Credential harvesting attacks can be launched using common social engineering attacks such as phishing attacks, and they can be performed by impersonating a wireless AP or a captive portal to convince a user to enter his or her credentials.

Tools such as [[ettercap]] can spoof DNS replies and divert a user visiting a given website to an attacker’s local system. For example, an attacker might spoof a site like Twitter, and when the user visits the website (which looks like the official Twitter website), he or she is prompted to log in, and the attacker captures the user’s credentials. Another tool that enables this type of attack is the Social-Engineer Toolkit (SET).

## Bluejacking and Bluesnarfing
**_Bluejacking_** is an attack that can be performed using Bluetooth with vulnerable devices in range. An attacker sends unsolicited messages to a victim over Bluetooth, including a contact card (vCard) that typically contains a message in the name field. This is done using the Object Exchange (OBEX) protocol. A vCard can contain name, address, telephone numbers, email addresses, and related web URLs. This type of attack has been mostly performed as a form of spam over Bluetooth connections.
>**NOTE** You can find an excellent paper describing Bluejacking at [_http://acadpubl.eu/jsi/2017-116-8/articles/9/72.pdf_](http://acadpubl.eu/jsi/2017-116-8/articles/9/72.pdf).

Another Bluetooth-based attack is Bluesnarfing. **_Bluesnarfing_** attacks are performed to obtain unauthorized access to information from a Bluetooth-enabled device. An attacker can launch Bluesnarfing attacks to access calendars, contact lists, emails and text messages, pictures, or videos from the victim.

Bluesnarfing is considered riskier than Bluejacking because whereas Bluejacking attacks only transmit data to the victim device, Bluesnarfing attacks actually steal information from the victim device.

Bluesnarfing attacks can also be used to obtain the International Mobile Equipment Identity (IMEI) number for a device. Attackers can then divert incoming calls and messages to another device without the user’s knowledge.

Using the Bluesnarfer Tool to Obtain a Device Name
```
$> bluesnarfer -b DE:AD:BE:EF:12:23 -i
device name: omar_phone
```
## Bluetooth Low Energy (BLE) Attacks
Numerous IoT devices use Bluetooth Low Energy (BLE) for communication. BLE communications can be susceptible to on-path attacks, and an attacker could modify the BLE messages between systems that would think that they are communicating with legitimate systems. DoS attacks can also be problematic for BLE implementations. Several research efforts have demonstrated different BLE attacks. For instance, Ohio State University researchers have discovered different fingerprinting attacks that can allow an attacker to reveal design flaws and misconfigurations of BLE devices. Details about this research can be found at [_https://dl.acm.org/doi/pdf/10.1145/3319535.3354240_](https://dl.acm.org/doi/pdf/10.1145/3319535.3354240).

## Radio-Frequency Identification (RFID) Attacks
Radio-frequency identification (RFID) is a technology that uses electromagnetic fields to identify and track tags that hold electronically stored information. There are active and passive RFID tags. Passive tags use energy from RFID readers (via radio waves), and active tags have local power sources and can operate from longer distances. Many organizations use RFID tags to track inventory or in badges used to enter buildings or rooms. RFID tags can even be implanted into animals or people to read specific information that can be stored in the tags.

Low-frequency (LF) RFID tags and devices operate at frequencies between 120kHz and 140kHz, and they exchange information at distances shorter than 3 feet. High-frequency (HF) RFID tags and devices operate at the 13.56MHz frequency and exchange information at distances between 3 and 10 feet. Ultra-high-frequency (UHF) RFID tags and devices operate at frequencies between 860MHz and 960MHz (regional) and exchange information at distances of up to 30 feet.

A few attacks are commonly launched against RFID devices:
- Attackers can silently steal RFID information (such as a badge or a tag) with an RFID reader such as the Proxmark3 ([_https://proxmark.com_](https://proxmark.com/)) by just walking near an individual or a tag.
- Attackers can create and clone an RFID tag (in a process called **_RFID cloning_**). They can then use the cloned RFID tags to enter a building or a specific room.
- Attackers can implant skimmers behind RFID card readers in a building or a room.
- Attackers can use amplified antennas to perform NFC amplification attacks. Attackers can also use amplified antennas to exfiltrate small amounts of data, such as passwords and encryption keys, over relatively long distances.

## 5.2.16 Password Spraying
**_Password spraying_** is a type of credential attack in which an attacker brute-forces logins (that is, attempts to authenticate numerous times) based on a list of usernames with default passwords of common systems or applications. For example, an attacker could try to log in with the word password1 using numerous usernames in a wordlist.

A similar attack is credential stuffing. In this type of attack, the attacker performs automated injection of usernames and passwords that have been exposed in previous breaches. You can learn more about credential stuffing attacks at [_https://owasp.org/www-community/attacks/Credential_stuffing_](https://owasp.org/www-community/attacks/Credential_stuffing).

## 5.2.17 Exploit Chaining
Most sophisticated attacks leverage multiple vulnerabilities to compromise systems. An attacker may “chain” (that is, use multiple) exploits against known or zero-day vulnerabilities to compromise systems, steal, modify, or corrupt data.
