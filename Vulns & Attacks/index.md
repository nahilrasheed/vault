# Vulnerabilities
_Security vulnerabilities_ are any kind of software or hardware defect. 
A program written to take advantage of a known vulnerability is referred to as an _exploit_. 
A cybercriminal can use an exploit against a vulnerability to carry out an _attack_, the goal of which is to gain access to a system, the data it hosts or a specific resource.
### Vulnerability Management
The process of finding and patching vulnerabilities.
1. Identify vulns
2. Consider potential exploits
3. Prepare defences against threats
4. Evaluate those defenses
## Hardware Vulnerabilty
Hardware vulnerabilities are most often the result of hardware design flaws.
eg:
- Rowhammer
- Meltdown
- Spectre

## Software Vulnerability
Software vulnerabilities are usually introduced by errors in the operating system or application code.
### Input Validation and Injection Vulnerabilities
Programs often require data input, but this incoming data could have malicious content, designed to force the program to behave in an unintended way.
- [[Injection Based vulnerabilities]]
	- [[SQLi]]
	- [[XSS - Cross-Site Scripting]]
	- [[CSRF]]
	- [[XXE]]
- [[File Upload Vulnerabilities|File uploads]]
### Access control problems
Access control is the process of controlling who does what and ranges from managing physical access to equipment to dictating who has access to a resource, such as a file, and what they can do with it, such as read or change the file. Many security vulnerabilities are created by the improper use of access controls.
- [[Authentication Based Vulnerabilities]]
- [[Autherization Based Vulnerabilities]]
	- [[IDOR - Insecure direct object reference]]
### Buffer overflow
Buffers are memory areas allocated to an application. A vulnerability occurs when data is written beyond the limits of a buffer. By changing data beyond the boundaries of a buffer, the application can access memory allocated to other processes. This can lead to a system crash or data compromise, or provide escalation of privileges.
### [[Race conditions]]
This vulnerability describes a situation where the output of an event depends on ordered or timed outputs. A race condition becomes a source of vulnerability when the required ordered or timed events do not occur in the correct order or at the proper time.
### Cryptographic & Security Practice Flaws
Systems and sensitive data can be protected through techniques such as authentication, authorization and encryption. Developers should stick to using security techniques and libraries that have already been created, tested and verified and should not attempt to create their own security algorithms. These will only likely introduce new vulnerabilities.
- [[Clickjacking & Cookie Manipulation Attacks]]
- [[Path Traversal]]
- [[LFD, LFI and RFI]]
- [[insecure Coding practises]]
# Attacks
In cybersecurity, an **attack** is any **intentional action** taken by a threat actor to **compromise the confidentiality, integrity, or availability** (CIA triad) of a system, network, application, or data.
> **An attack** is a deliberate attempt to **exploit a vulnerability** in order to **gain unauthorized access**, **cause disruption**, or **steal/damage information**.

## Common Attacks
A computer virus is malicious code written to interfere with computer operations and cause damage to data and software.
Today, viruses are more commonly referred to as malware, which is software designed to harm devices or networks.
- In 1986, the Alvi brothers created the Brain virus, although the intention of the virus was to track illegal copies of medical software and prevent pirated licenses
- In 1988, Robert Morris developed a program to assess the size of the internet. The program crawled the web and installed itself onto other computers to tally the number of computers that were connected to the internet.The program, however, failed to keep track of the computers it had already compromised and continued to re-install itself until the computers ran out of memory and crashed. About 6,000 computers were affected, representing 10% of the internet at the time. This attack cost millions of dollars in damages due to business disruptions and the efforts required to remove the worm.
After the Morris worm, Computer Emergency Response Teams, known as CERTs®, were established to respond to computer security incidents. CERTs still exist today, but their place in the security industry has expanded to include more responsibilities. 

Social engineering is a manipulation technique that exploits human error to gain private information, access, or valuables.
- eg: Loveletter attack.in year 2000, Onel De Guzman created the LoveLetter malware to steal internet login credentials. 

Phishing is the use of digital communications to trick people into revealing sensitive data or deploying malicious software.
- the Equifax breach. In 2017, attackers successfully infiltrated the credit reporting agency, Equifax. This resulted in one of the largest known data breaches of sensitive information. Over 143 million customer records were stolen, and the breach affected approximately 40% of all Americans.
## Attack types
### [[Social Engineering]]
### [[Network Attacks]]
### **Physical attack**
A **physical attack** is a security incident that affects not only digital but also physical environments where the incident is deployed. Some forms of physical attacks are:
- Malicious USB cable  
- Malicious flash drive
- Card cloning and skimming
Physical attacks fall under the asset security domain.
### **Adversarial artificial intelligence**
**Adversarial artificial intelligence** is a technique that manipulates [artificial intelligence and machine learning](https://www.nccoe.nist.gov/ai/adversarial-machine-learning) technology to conduct attacks more efficiently. Adversarial artificial intelligence falls under both the communication and network security and the identity and access management domains.
### **Supply-chain attack**
A **supply-chain attack** targets systems, applications, hardware, and/or software to locate a vulnerability where malware can be deployed. Because every item sold undergoes a process that involves third parties, this means that the security breach can occur at any point in the supply chain. These attacks are costly because they can affect multiple organizations and the individuals who work for them. Supply-chain attacks can fall under several domains, including but not limited to the security and risk management, security architecture and engineering, and security operations domains.
### **Cryptographic attack**
A **cryptographic attack** affects secure forms of communication between a sender and intended recipient. Some forms of cryptographic attacks are: 
- Birthday
- Collision
- Downgrade
Cryptographic attacks fall under the communication and network security domain.
# Malware
## Spyware
Designed to track and spy on you, spyware monitors your online activity and can log every key you press on your keyboard, as well as capture almost any of your data, including sensitive personal information such as your online banking details. Spyware does this by modifying the security settings on your devices.
It often bundles itself with legitimate software or Trojan horses.
## Adware
Adware is often installed with some versions of software and is designed to automatically deliver advertisements to a user, most often on a web browser. You know it when you see it! It’s hard to ignore when you’re faced with constant pop-up ads on your screen.
It is common for adware to come with spyware.
## Backdoor
This type of malware is used to gain unauthorized access by bypassing the normal authentication procedures to access a system. As a result, hackers can gain remote access to resources within an application and issue remote system commands.
A backdoor works in the background and is difficult to detect.
## Ransomware
This malware is designed to hold a computer system or the data it contains captive until a payment is made. Ransomware usually works by encrypting your data so that you can’t access it.
Some versions of ransomware can take advantage of specific system vulnerabilities to lock it down. Ransomware is often spread through phishing emails that encourage you to download a malicious attachment or through a software vulnerability.
## Scareware
This is a type of malware that uses 'scare’ tactics to trick you into taking a specific action. Scareware mainly consists of operating system style windows that pop up to warn you that your system is at risk and needs to run a specific program for it to return to normal operation.
If you agree to execute the specific program, your system will become infected with malware.
## Rootkit
This malware is designed to modify the operating system to create a backdoor, which attackers can then use to access your computer remotely. Most rootkits take advantage of software vulnerabilities to gain access to resources that normally shouldn’t be accessible (privilege escalation) and modify system files.
Rootkits can also modify system forensics and monitoring tools, making them very hard to detect. In most cases, a computer infected by a rootkit has to be wiped and any required software reinstalled.

This kind of malware is often spread by a combination of two components: a dropper and a loader. A **dropper** is a type of malware that comes packed with malicious code which is delivered and installed onto a target system. For example, a dropper is often disguised as a legitimate file, such as a document, an image, or an executable to deceive its target into opening, or dropping it, onto their device. If the user opens the dropper program, its malicious code is executed and it hides itself on the target system.

Multi-staged malware attacks, where multiple packets of malicious code are deployed, commonly use a variation called a loader. A **loader** is a type of malware that downloads strains of malicious code from an external source and installs them onto a target system.
## Virus
A virus is a type of computer program that, when executed, replicates and attaches itself to other executable files, such as a document, by inserting its own code. Most viruses require end-user interaction to initiate activation and can be written to act on a specific date or time.
Viruses can be relatively harmless, such as those that display a funny image. Or they can be destructive, such as those that modify or delete data.
Viruses can also be programmed to mutate in order to avoid detection. Most viruses are spread by USB drives, optical disks, network shares or email.
## Trojan horse
This malware carries out malicious operations by masking its true intent. It might appear legitimate but is, in fact, very dangerous. Trojans exploit your user privileges and are most often found in image files, audio files or games.
Unlike viruses, Trojans do not self-replicate but act as a decoy to sneak malicious software past unsuspecting users.
## Worms
This is a type of malware that replicates itself in order to spread from one computer to another. Unlike a virus, which requires a host program to run, worms can run by themselves. Other than the initial infection of the host, they do not require user participation and can spread very quickly over the network.
Worms share similar patterns: They exploit system vulnerabilities, they have a way to propagate themselves, and they all contain malicious code (payload) to cause damage to computer systems or networks.
Worms are responsible for some of the most devastating attacks on the Internet. In 2001, the Code Red worm had infected over 300,000 servers in just 19 hours.

## [[DoS and DDoS Attacks]]
## On-Path Attacks - [[MITM or On-Path Attacks]]
On-path attackers intercept or modify communications between two devices, such as a web browser and a web server, either to collect information from or to impersonate one of the devices.
This type of attack is also referred to as a man-in-the-middle or man-in-the-mobile attack.

A MitM attack happens when a cybercriminal takes control of a device without the user’s knowledge. With this level of access, an attacker can intercept and capture user information before it is sent to its intended destination. These types of attacks are often used to steal financial information.

There are many types of malware that possess MitM attack capabilities.
A variation of man-in-middle, MitMo is a type of attack used to take control over a user’s mobile device. When infected, the mobile device is instructed to exfiltrate user-sensitive information and send it to the attackers. ZeuS is one example of a malware package with MitMo capabilities. It allows attackers to quietly capture two-step verification SMS messages that are sent to users.
## SEO Poisoning
You’ve probably heard of search engine optimization or SEO which, in simple terms, is about improving an organization’s website so that it gains greater visibility in search engine results.
Search engines such as Google work by presenting a list of web pages to users based on their search query. These web pages are ranked according to the relevancy of their content.
While many legitimate companies specialize in optimizing websites to better position them, attackers take advantage of popular search terms and use SEO to push malicious sites higher up the ranks of search results. This technique is called SEO poisoning.
The most common goal of SEO poisoning is to increase traffic to malicious sites that may host malware or attempt social engineering.

## Wi-Fi Password Cracking
We are able to identify unencrypted passwords by listening in and capturing packets sent on the network. This is called **network sniffing**. If the password is encrypted, they may still be able to reveal it using a password cracking tool.
## [[Password Attacks]]

## Advanced Persistent Threats
Attackers also achieve infiltration through advanced persistent threats (APTs) — a multi-phase, long term, stealthy and advanced operation against a specific target. For these reasons, an individual attacker often lacks the skill set, resources or persistence to perform APTs.
Due to the complexity and the skill level required to carry out such an attack, an APT is usually well-funded and typically targets organizations or nations for business or political reasons.
Its main purpose is to deploy customized malware on one or more of the target’s systems and remain there undetected.