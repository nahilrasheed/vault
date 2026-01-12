---
tags:
  - CiscoEH
  - CyberSec
  - RedTeam
---
A penetration test, colloquially known as a pentest, is an authorized simulated cyberattack on a computer system, performed to evaluate the security of the system. The test is performed to identify weaknesses (or vulnerabilities), including the potential for unauthorized parties to gain access to the system's features and data,as well as strengths, enabling a full risk assessment to be completed.

Penetration testing, commonly known as pen testing, is the act of assessing a computer system, network or organization for security vulnerabilities. A pen test seeks to breach systems, people, processes and code to uncover vulnerabilities which could be exploited. This information is then used to improve the system’s defenses to ensure that it is better able to withstand cyber attacks in the future.

The term **_ethical hacker_** describes a person who acts as an attacker and evaluates the security posture of a computer network for the purpose of minimizing risk. The NIST Computer Security Resource Center (CSRC) defines a _hacker_ as an “unauthorized user who attempts to or gains access to an information system.”

## Different approaches to penetration testing
- Red team tests _simulate attacks_ to identify vulnerabilities in systems, networks, or applications.
- Blue team tests focus on _defense_ _and incident response_ to validate an organization's existing security systems.
- Purple team tests are _collaborative_, focusing on improving the security posture of the organization by combining elements of red and blue team exercises.
## Penetration testing methods
### Unknown-Environment Test (White Box Testing)
In an unknown-environment penetration test, the tester is typically provided only a very limited amount of information. For instance, the tester may be provided only the domain names and IP addresses that are in scope for a particular target. The idea of this type of limitation is to have the tester start out with the perspective that an external attacker might have. Typically, an attacker would first determine a target and then begin to gather information about the target, using public information, and gain more and more information to use in attacks. The tester would not have prior knowledge of the target’s organization and infrastructure. Another aspect of unknown-environment testing is that sometimes the network support personnel of the target may not be given information about exactly when the test is taking place. This allows for a defense exercise to take place as well, and it eliminates the issue of a target preparing for the test and not giving a real-world view of how the security posture really looks.
### Known-Environment Test (White Box Testing)
In a known-environment penetration test, the tester starts out with a significant amount of information about the organization and its infrastructure. The tester would normally be provided things like network diagrams, IP addresses, configurations, and a set of user credentials. If the scope includes an application assessment, the tester might also be provided the source code of the target application. The idea of this type of test is to identify as many security holes as possible. In an unknown-environment test, the scope may be only to identify a path into the organization and stop there. With known-environment testing, the scope is typically much broader and includes internal network configuration auditing and scanning of desktop computers for defects. Time and money are typically deciding factors in the determination of which type of penetration test to complete. If a company has specific concerns about an application, a server, or a segment of the infrastructure, it can provide information about that specific target to decrease the scope and the amount of time spent on the test but still uncover the desired results. With the sophistication and capabilities of adversaries today, it is likely that most networks will be compromised at some point, and a white-box approach is not a bad option.
### Partially Known Environment Test (Grey Box Testing)
A partially known environment penetration test is somewhat of a hybrid approach between unknown- and known-environment tests. With partially known environment testing, the testers may be provided credentials but not full documentation of the network infrastructure. This would allow the testers to still provide results of their testing from the perspective of an external attacker’s point of view. Considering the fact that most compromises start at the client and work their way throughout the network, a good approach would be a scope where the testers start on the inside of the network and have access to a client machine. Then they could pivot throughout the network to determine what the impact of a compromise would be.
## Different types of penetration tests
### Network Infrastructure Tests
Testing of the network infrastructure can mean a few things. For the purposes of this course, we say it is focused on evaluating the security posture of the actual network infrastructure and how it is able to help defend against attacks. This often includes the switches, routers, firewalls, and supporting resources, such as authentication, authorization, and accounting (AAA) servers and IPSs. A penetration test on wireless infrastructure may sometimes be included in the scope of a network infrastructure test. However, additional types of tests beyond a wired network assessment would be performed. For instance, a wireless security tester would attempt to break into a network via the wireless network either by bypassing security mechanisms or breaking the cryptographic methods used to secure the traffic. Testing the wireless infrastructure helps an organization to determine weaknesses in the wireless deployment as well as the exposure. It often includes a detailed heat map of the signal disbursement.
### Application-Based Tests
This type of pen testing focuses on testing for security weaknesses in enterprise applications. These weaknesses can include but are not limited to misconfigurations, input validation issues, injection issues, and logic flaws. Because a web application is typically built on a web server with a back-end database, the testing scope normally includes the database as well. However, it focuses on gaining access to that supporting database through the web application compromise. A great resource that we mention a number of times in this book is the Open Web Application Security Project (OWASP).
### Penetration Testing in the Cloud
Cloud service providers (CSPs) such as Azure, Amazon Web Services (AWS), and Google Cloud Platform (GCP) have no choice but to take their security and compliance responsibilities very seriously. For instance, Amazon created the Shared Responsibility Model to describe the AWS customers’ responsibilities and Amazon’s responsibilities in detail (see https://aws.amazon.com/compliance/shared-responsibility-model).

The responsibility for cloud security depends on the type of cloud model (software as a service [SaaS], platform as a service [PaaS], or infrastructure as a service [IaaS]). For example, with IaaS, the customer (cloud consumer) is responsible for data, applications, runtime, middleware, virtual machines (VMs), containers, and operating systems in VMs. Regardless of the model used, cloud security is the responsibility of both the client and the cloud provider. These details need to be worked out before a cloud computing contract is signed. These contracts vary depending on the security requirements of the client. Considerations include disaster recovery, service-level agreements (SLAs), data integrity, and encryption. For example, is encryption provided end to end or just at the cloud provider? Also, who manages the encryption keys–the CSP or the client?

Overall, you want to ensure that the CSP has the same layers of security (logical, physical, and administrative) in place that you would have for services you control. When performing penetration testing in the cloud, you must understand what you can do and what you cannot do. Most CSPs have detailed guidelines on how to perform security assessments and penetration testing in the cloud. Regardless, there are many potential threats when organizations move to a cloud model. For example, although your data is in the cloud, it must reside in a physical location somewhere. Your cloud provider should agree in writing to provide the level of security required for your customers. As an example, the following link includes the AWS Customer Support Policy for Penetration Testing: https://aws.amazon.com/security/penetration-testing.
## Stages
### Step 1: Planning / Information Gathering
The pen tester gathers as much information as possible about a target system or network, its potential vulnerabilities and exploits to use against it. This involves conducting passive (OSINT) or active reconnaissance (footprinting) and vulnerability research.
### Step 2: Scanning / Enumeration
This stage involves discovering applications and services running on the systems. For example, finding a web server that may be potentially vulnerable.
The pen tester carries out active reconnaissance to probe a target system or network and identify potential weaknesses which, if exploited, could give an attacker access. Active reconnaissance may include:
- port scanning to identify potential access points into a target system
- vulnerability scanning to identify potential exploitable vulnerabilities of a particular target
- establishing an active connection to a target (enumeration) to identify the user account, system account and admin account.
### Step 3: Exploitation / Gaining access
The pen tester will attempt to gain access to a target system and sniff network traffic, using various methods to exploit the system including:
- launching an exploit with a payload onto the system
- breaching physical barriers to assets
- social engineering
- exploiting website vulnerabilities
- exploiting software and hardware vulnerabilities or misconfigurations
- breaching access controls security
- cracking weak encrypted Wi-Fi.
This stage involves leveraging vulnerabilities discovered on a system or application. This stage can involve the use of public exploits or exploiting application logic.
### Step 4: Maintaining access
The pen tester will maintain access to the target to find out what data and systems are vulnerable to exploitation. It is important that they remain undetected, typically using backdoors, Trojan horses, rootkits and other covert channels to hide their presence.
When this infrastructure is in place, the pen tester will then proceed to gather the data that they consider valuable.
#### Privilege Escalation
Once you have successfully exploited a system or application (known as a foothold), this stage is the attempt to expand your access to a system. You can escalate horizontally and vertically, where horizontally is accessing another account of the same permission group (i.e. another user), whereas vertically is that of another permission group (i.e. an administrator).
### Step 5: Post-exploitation
This stage involves a few sub-stages:  
**1.** What other hosts can be targeted (pivoting)
**2.** What additional information can we gather from the host now that we are a privileged user
**3.**  Covering your tracks
**4.** Reporting
### Step 6: Analysis and reporting
The pen tester will provide feedback via a report that recommends updates to products, policies and training to improve an organization’s security.

---
# Planning and scoping a pentest
[[Security Frameworks]]
## [[Legal Concepts]]
## Local Restrictions 
- **Know the Law**: Penetration testing laws vary by country. Violating them—even unintentionally—can lead to legal consequences (e.g., Computer Fraud and Abuse Act, USA). Always confirm local and international laws before testing.
- **Get Written Permission**: Always have **clear, written authorization** from the client. This protects you legally and guides your scope of work (SOW).
- **Identify Pre-engagement Constraints**:
    - Tool and technique restrictions
    - Business/tech limitations
    - Areas/systems off-limits (e.g., live production databases)
    - Limits due to skill sets or known exploits
- **Communicate Clearly**: Discuss any limitations with stakeholders early and throughout the engagement.
- **Respect Privacy Laws**: Be aware of regulations like **GDPR** and **CCPA** that may impact how data can be accessed or handled.
- **Check Corporate Policies**: Clients may have internal rules or regulatory obligations that define how testing must be done. Always ask and document.

## Rules of Engagement
The **rules of engagement document** specifies the conditions under which the security penetration testing engagement will be conducted. You need to document and agree upon these rule of engagement conditions with the client or an appropriate stakeholder.
_Sample Elements of a Rules of Engagement Document_

| **Rule of Engagement Element**                                         | **Example**                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Testing timeline                                                       | Three weeks, as specified in a Gantt chart                                                                                                                                                                                                                                                                                                                                                        |
| Location of the testing                                                | Company’s headquarters in Raleigh, North Carolina                                                                                                                                                                                                                                                                                                                                                 |
| Time window of the testing (times of day)                              | 9:00 a.m. to 5:00 p.m. EST                                                                                                                                                                                                                                                                                                                                                                        |
| Preferred method of communication                                      | Final report and weekly status update meetings                                                                                                                                                                                                                                                                                                                                                    |
| The security controls that could potentially detect or prevent testing | Intrusion prevention systems (IPSs), firewalls, data loss prevention (DLP) systems                                                                                                                                                                                                                                                                                                                |
| IP addresses or networks from which testing will originate             | 10.10.1.0/24, 192.168.66.66, 10.20.15.123                                                                                                                                                                                                                                                                                                                                                         |
| Types of allowed or disallowed tests                                   | Testing only web applications (app1.secretcorp.org and app2.secretcorp.org). No social engineering attacks are allowed. No SQL injection attacks are allowed in the production environment. SQL injection is only allowed in the development and staging environments at:  <br>app1-dev.secretcorp.org  <br>app1-stage.secretcorp.org  <br>app2-dev.secretcorp.org  <br>app2-stage.secretcorp.org |
Gantt charts and work breakdown structures (WBS) can be used as tools to demonstrate and document the timeline.

## Target List and In-Scope Assets
Scoping is one of the most important elements of the pre-engagement tasks with any penetration testing engagement. You not only have to carefully identify and document all systems, applications, and networks that will be tested but also determine any specific requirements and qualifications needed to perform the test. The broader the scope of the penetration testing engagement, the more skills and requirements that will be needed.
Your scope and related documentation must include information about what types of networks will be tested, like the IP address ranges of the devices and assets that the penetration tester is allowed to assess. In addition to IP ranges, you must document any wireless networks or service set identifiers (SSIDs) that you are allowed or not allowed to test.

You may also be hired to perform an assessment of modern applications using different application programming interfaces (APIs).
In this case the client may provide [[API]] Documentation.

Additional resources that may be provided:
- Software development kit (SDK) for specific applications
	An SDK, or devkit, is a collection of software development tools that can be used to interact and deploy a software framework, an operating system, or a hardware platform. SDKs can also help pen testers understand certain specialized applications and hardware platforms within the organization being tested.
- Source code access
	Some organizations may allow you to obtain access to the source code of applications to be tested.
- Examples of application requests
	In most cases, you will be able to reveal context by using web application testing tools such as proxies like the Burp Suite and the OWASP Zed Attack Proxy (ZAP). You will learn more about these tools in Module 6, “Exploiting Application-Based Vulnerabilities,” and Module 10, “Tools and Code Analysis.”
- System and network architectural diagrams
	These documents can be very beneficial for penetration testers, and they can be used to document and define what systems are in scope during the testing.

It is very important to document the physical location where the penetration testing will be done, as well as the Domain Name System (DNS) fully qualified domain names (FQDNs) of the applications and assets that are allowed (including any subdomains). You must also agree and understand if you will be allowed to demonstrate how an external attacker could compromise your systems or how an insider could compromise internal assets. This external vs. internal target identification and scope should be clearly documented.

_Scope creep_ is a project management term that refers to the uncontrolled growth of a project’s scope. It is also often referred to as _kitchen sink syndrome_, _requirement creep_, and _function creep_. Scope creep can put you out of business. Many security firms suffer from scope creep and are unsuccessful because they have no idea how to identify when the problem starts or how to react to it.

## Validating the Scope of Engagement
The first step in validating the scope of an engagement is to _question the client and review contracts_. You must also understand who the target audience is for your penetration testing report. You should understand the subjects, business units, and any other entity that will be assessed by such a penetration testing engagement.

Answering the following questions will help discover different characteristics of your target audience.
- What is the entity’s or individual’s need for the report?
- What is the position of the individual who will be the primary recipient of the report within the organization?
- What is the main purpose and goal of the penetration testing engagement and ultimately the purpose of the report?
- What is the individual’s or business unit’s responsibility and authority to make decisions based on your findings?
- Who will the report be addressed to–for example, the information security manager (ISM), chief information security officer (CISO), chief information officer (CIO), chief technical officer (CTO), technical teams, and so on?
- Who will have access to the report, which may contain sensitive information that should be protected, and whether access will be provided on a need-to-know basis?
You should have proper documentation of answers to the following questions.
- What is the contact information for all relevant stakeholders?
- How will you communicate with the stakeholders?
- How often do you need to interact with the stakeholders?
- Who are the individuals you can contact at any time if an emergency arises?

You should ask for a form of secure bulk data transfer or storage, such as Secure Copy Protocol (SCP) or Secure File Transfer Protocol (SFTP). You should also exchange any Pretty Good Privacy (PGP) keys or Secure/Multipurpose Internet Mail Extensions (S/MIME) keys for encrypted email exchanges.

Questions about budget and return on investment (ROI) may arise from both the client side and the tester sides in penetration testing.
Clients may ask questions like these.
- How do I explain the overall cost of penetration testing to my boss?
- Why do we need penetration testing if we have all these security technical and nontechnical controls in place?
- How do I build in penetration testing as a success factor?
- Can I do it myself?
- How do I calculate the ROI for the penetration testing engagement?
At the same time, the tester needs to answer questions like these.
- How do I account for all items of the penetration testing engagement to avoid going over budget?
- How do I do pricing?
- How can I clearly show ROI to my client?
- The answers to these questions depend on how effective you are at scoping and clearly communicating and understanding all the elements of the penetration testing engagement. Another factor is understanding that penetration testing is a point-in-time assessment.

It is important for both the client and the pen tester to comprehend that penetration testing alone cannot guarantee the overall security of the company. The pen tester also needs to incorporate clear and achievable mitigation strategies for the vulnerabilities found. In addition, an appropriate impact analysis and remediation timelines must be discussed with the respective stakeholders.

## Pre-Engagement Scope and Planning
1. **Review Client Needs**: Start by analyzing the client's initial request to understand their objectives.
2. **Conduct Clarification Meeting**: Meet with the client to refine goals and suggest additional testing aspects they may have missed.
3. **Define Scope**: Clearly outline which systems, applications, and personnel are included or excluded from testing.
4. **Address Compliance**: Identify relevant compliance requirements to be evaluated during the engagement.
5. **Confirm Provided Information**: Determine what access and details the client will share about their network, systems, and facilities.
6. **Establish Rules of Engagement**: Finalize the scope, terms, and conditions to ensure mutual understanding before the engagement begins.
## Create a Pentesting Agreement
A penetration testing agreement is a legally-binding contract between the client or customer, and the penetration tester. The agreement defines all the terms and conditions required for the penetration testing exercise. The agreement will include elements that are mutually agreed upon by both parties. It may contain things, such as the date for the commencement of pentesting, the scope of work, the service-level agreement, the potential pentesting completion date, the project timeline, costs and payment details etc. Also included in the contract will be other terms and conditions as well as pricing details.
Contracts usually do not stipulate the personnel who are conducting the test, but they will include the relevant signatories at the company performing the test. This is usually a member, or members, of the management team. Vulnerabilities are not reported at this time because the test has not yet been conducted.
## Ethics
Hacking is illegal. Ethical hacking is the use of otherwise illegal tools and techniques for legal purposes. It is ethics that differentiate the two.
There are several approaches or perspectives on ethical decision making, including utilitarian ethics, the rights approach, and the common good approach. Other ethical decision models include the fairness or justice approach as well as the virtue approach.
1. Information stored on the computer should be treated as seriously as written or spoken words.
2. Respect the privacy of others.
3. Creation and usage of malware is illegal and must not be practiced.
4. Should not prevent others from accessing public information.
5. Overwhelming other’s system with unwanted information is unethical.
6. Sending inappropriate messages through email or chat is forbidden.
7. Do no harm with a computer.
8. Comply with legal standards.
9. Be trustworthy.
10. Maintain confidentiality.

| scenarios in which an ethical hacker (penetration tester) should demonstrate professionalism and integrity                                                                                                |
| --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| background checks of penetration testing teams                                                                  | Check the credentials and skills of the individuals performing the penetration test.          |
| adherence to the specific scope of engagement                                                                   | Create a list of applications, systems, or networks to be tested.                             |
| Limiting invasiveness based on scope                                                                            | Specify tools and attacks that could be detrimental and disruptive for your client’s systems. |
| Limiting the use of tools used in a particular penetration test                                                 | Specifying the allowed, or disallowed, testing tools.                                         |
| Identification and immediate reporting of criminal activity                                                     | Report evidence of any system or network that was previously compromised.                     |
