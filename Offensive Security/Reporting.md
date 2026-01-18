Upon concluding any penetration test, the transition from execution to reporting hinges entirely on the quality of your documentation. Every action taken during the test, and every result unearthed, contributes to the final report that will be presented to the client. It's imperative that each finding is meticulously recorded, along with the precise methodology used to obtain it. This rigorous approach to **note-keeping** and **documentation management** isn't merely administrative overhead; it's the bedrock upon which you communicate the immense effort invested and the value delivered. Without comprehensive, well-organized data, effectively reporting on your hard work becomes a significant challenge. The immersive nature of penetration testing can often lead to oversight in real-time note-taking, making a conscious commitment to continuous documentation absolutely essential.

Even after the technical execution of a penetration test is complete, the most critical phase delivering a **quality report** awaits. Whether you're an internal team member or a contracted cybersecurity professional, this report is your primary deliverable and directly enables your client to understand and **mitigate** the vulnerabilities you've uncovered.
This final stage encompasses several key activities:
- **Post-Engagement Cleanup:** Begin by thoroughly removing any tools, scripts, or shells that were deployed on the tested systems. This ensures the environment is returned to its original state and maintains the integrity of the client's systems.
- **Report Writing Best Practices:** Crafting an effective report is paramount. This involves adhering to best practices for structure and content, including common report elements like an executive summary, detailed findings, and clear recommendations.
- **Effective Communication:** Finally, proper report handling and communication best practices are essential. This ensures the findings are presented clearly, professionally, and in a way that empowers the client to take decisive action.
## Report Writing
- Recommendations for remediation should be clear to both executives and technical staff
- Report should highlight both non- technical (executive) and technical findings
- A report is typically delivered within a week after the engagement ends
## Debrief
- A debrief walks through your report findings. This can be with technical and non- technical staff present. 
- It gives an opportunity for the client to ask questions and address any concerns before a final report is released.
# Effective Penetration Test Reporting
### Communication as Key
Reports are a form of communication. Just like speaking, effective reports require tailoring language and content to the audience. Be clear and concise for busy people, simplify for less technical readers, and always maintain a respectful, professional tone, avoiding criticism or condescension. This blend of practice and thoughtful consideration makes report writing an art.
### Audience-Centric Reporting
A crucial aspect of reporting is knowing your audience. A report understood only by highly technical staff will miss its mark with non-technical stakeholders like the C-suite. The executive summary is vital here, translating complex technical findings into easily understandable summaries for all technical levels. Remember, your report will likely be passed to various technical teams (IT, InfoSec, Developers), so the detailed sections must provide enough information for them to take action.
### Beyond Automated Outputs
While penetration testing tools often generate impressive reports, resist simply regurgitating their output. Tools can produce false positives or negatives. You must critically review the results, analyze their meaning in the context of the target's business, and determine the actual impact. This in-depth analysis is essential for compiling a prioritized plan to address the findings effectively
## Report Contents
There are many ways you can go about structuring the elements in a report. Most penetration testing consultants start with a template and customize it based on the type of test and the desired deliverable. Keep in mind that there are published standards that you can reference.
**TIP** Take some time to look at the excellent examples of penetration testing reports available at [_https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/pen_testing_reports_](https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/pen_testing_reports). These reports have been provided by various organizations for the purpose of sharing examples of penetration testing reports. A great way to use this resource is to browse through the sample reports and view the report formats. 
A penetration testing report typically contains the following sections (which are not listed in a particular order). Select each for more detail.
**Executive Summary**
A brief high-level summary describes the penetration test scope and major findings.
**Scope Details**
It is important to include a detailed definition of the scope of the network and systems tested as part of the engagement to distinguish between in-scope and out-of-scope systems or segments and identify critical systems that are in or out of scope and explain why they are included in the test as targets.
**Methodology**
A report should provide details on the methodologies used to complete the testing (for example, port scanning, Nmap). You should also include details about the attack narrative. For example, if the environment did not have active services, explain what testing was performed to verify restricted access. Document any issues encountered during testing (for example, interference encountered as a result of active protection systems blocking traffic).
**Findings**
A report should document technical details about whether or how the system under testing and related components may be exploited based on each vulnerability found. It is a good idea to use an industry-accepted risk ratings for each vulnerability, such as the Common Vulnerability Scoring System (CVSS). When it comes to reporting, it can be difficult to determine a relevant method of calculating metrics and measures of the findings uncovered in the testing phases. This information is very important in your presentation to management. You must be able to provide data to show the value in your effort. This is why you should always try to use an industry-standard method for calculating and documenting the risks of the vulnerabilities listed in your report. CVSS has been adopted by many tools, vendors, and organizations. Using an industry standard such as CVSS will increase the value of your report to your client. CVSS, which was developed and is maintained by FIRST.org, provides a method for calculating a score for the seriousness of a threat. The scores are rated from 0 to 10, with 10 being the most severe. CVSS uses three metric groups in determining scores.
- [[CVE, CWE, CVSS]]
**Remediation**
You should provide clear guidance on how to mitigate and remediate each vulnerability. This information will be very useful for the IT technical staff, software developers, and security analysts who are trying to protect the organization (often referred to as the “blue team”).
**Conclusion**
The report must have a good summary of all the findings and recommendations.
**Appendix**
It is important to document any references and include a glossary of terms that the audience of the report may not be familiar with.

## Storage Time for Report and Secure Distribution
The classification of a report’s contents is driven by the organization that the penetration test has been performed on and its policies on classification. In some cases, the contents of a report are considered top secret. However, as a rule of thumb, you should always consider report contents as highly classified and distribute them on a need-to-know basis only. The classification of report contents also determines the method of delivery.
In general, there are two ways to distribute a report: as a hard copy or electronically. Many times, when you perform the readout of the findings from your report, you will be meeting with the stakeholders who requested the penetration test to be performed. This meeting will likely include various people from the organization, including IT, information security, and management. In most cases, they will want to have a hard copy in front of them as you walk through the readout of the findings. This is, of course, possible, but the process should be handled with care.

The following are some examples of how to control the distribution of reports:
- Produce only a **limited number of copies**.
- Define the **distribution list** in the scope of work.
- Label each copy with a **specific ID** or number that is tied to the person it is distributed to.
- Label each copy with the **name of the person** it is distributed to.
- Keep a **log of each hard copy**, including who it was distributed to and the date it was distributed. Table 9-2 shows an example of such a log.
- Ensure that each copy is **physically and formally delivered** to the designated recipient.
- If transferring a report over a network, ensure that the **document is encrypted** and the method of transport is encrypted.
- Ensure that the handling and distribution of an electronic copy of a report are even more restrictive than for a hard copy:  
    - Control distribution on a secure server that is owned by the department that initially requested the penetration test.  
    - Provide only one copy directly to the client or requesting party.  
    - Once the report is delivered to the requesting party, use a documented, secure method of deleting all collected information and any copy of the report from your machine.

## Note Taking
A report is the final outcome of a penetration testing effort. The most accurate and comprehensive way to compile a report is to start collecting and organizing the results while you are still testing. In other words, you need to understand the process of ongoing documentation during testing. As you come across findings that need to be documented, take screenshots of the tools used, the steps, and the output. This will help you piece together exactly the scenario that triggered the finding and illustrate it for the end user. You should include these screenshots as part of the report because including visual proof is the best way for your audience to gain a full picture of and understand the findings. Sometimes it may even be necessary to create a video. In summary, taking screenshots, videos, and lots of notes will help you create a deliverable report.

When it comes to constructing a final penetration testing report, one of the biggest challenges is pulling together all the data and findings collected throughout the testing phases. This is especially true when the penetration test spans a long period of time. Longer test spans often require a lengthier sorting process and use of specialized tools, such as *Dradis*, to find the information you are looking to include in your report.

Dradis is a handy little tool that can ingest the results from many of the penetration testing tools you use and help you produce reports in formats such as CSV, HTML, and PDF. It is very flexible because it includes add-ons and allows you to create your own. If you find yourself in a situation where you need to import from a new tool that is not yet compatible, you can write your own add-on to accomplish this.
**TIP** There are two editions of the Dradis Framework. The Community Edition (CE) is an open-source version that is freely available under the GPLv2 license. The Professional Edition (PE) is a commercial product that includes additional features for managing projects as well as more powerful reporting capabilities. The Community Edition can be found at [_https://github.com/dradis/dradis-ce_](https://github.com/dradis/dradis-ce). Information on the Professional Edition is available at [_https://dradisframework.com_](https://dradisframework.com/) .


## Report Writing Essentials
When I do a penetration test, I find many things: tool outputs, vulnerabilities, and systems not following best practices. Just listing these isn't enough.
**Understand the Real Risk:**
- A tool might say an FTP server is okay, but if I discover it's internet-facing and used for sensitive data (when it shouldn't be), that's a **major concern**.
- I must **analyze** my findings and connect them to the actual environment. This is how I truly understand the **risk** (high, medium, low).
- My report needs to give an **accurate risk rating** and explain the **root cause** of each problem.
**Why a Good Report Matters:**
- **For Clients (Third-Party):** My report is the proof of my work. It's like a home inspection report – the client uses it to fix issues. If my report has **false positives** (things I said were issues but weren't), it wastes their time and money. They won't hire me again.
- **For Internal Teams:** If I report a **vulnerability** (like SQL injection) in an app without properly checking it, and it turns out to be a **false positive**, I cause problems. The developers will waste time trying to fix a non-existent issue. This makes them unhappy and reflects poorly on me.

- [https://github.com/santosomar/public-pentesting-reports](https://github.com/santosomar/public-pentesting-reports)

# Analyzing the Findings and Recommending the Appropriate Remediation Within a Report
## Technical controls
Technical controls make use of technology to reduce vulnerabilities. The following are examples of technical controls that can be recommended as mitigations and remediation of the vulnerabilities found during a pen test.

**System hardening**
System hardening involves applying security best practices, patches, and other configurations to remediate or mitigate the vulnerabilities found in systems and applications. The system hardening process includes closing unnecessary open ports and services, removing unnecessary software, and disabling unused ports.
**User input sanitization and query parameterization**
 The use of input validation (sanitizing user input) best practices is recommended to mitigate and prevent vulnerabilities such as cross-site scripting, cross-site request forgery, SQL injection, command injection, XML external entities, and other vulnerabilities explained in Module 6. OWASP provides several cheat sheets and detailed guidance on how to prevent these vulnerabilities
 - [https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
 - [https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
**Multifactor authentication**
Multifactor authentication (MFA) is authentication that requires two or more factors. Multilayer authentication requires that two or more of the same type of factors be presented. Data classification, regulatory requirements, the impact of unauthorized access, and the likelihood of a threat being exercised should all be considered when you’re deciding on the level of authentication required. The more factors, the more robust the authentication process. In response to password insecurity, many organizations have deployed multifactor authentication options to their users. With multifactor authentication, accounts are protected by something you know (password) and something you have (one-time verification code provided to you). Even gamers have been protecting their accounts using MFA for years.
**TIP** Let’s take a look at this in practice: Jeannette inserts her bank card into an ATM and enters her PIN. What examples of multifactor authentication has she exhibited? An ATM provides a good example of MFA because it requires both “something you have” (your ATM card) and “something you know” (your PIN). Another possible factor in MFA is “something you are,” which can be based on biometrics such as fingerprints, retinal patterns, and hand geometry. Yet another factor is “somewhere you are,” such as authenticating to a specific network in a specific geographic area or boundary using geofencing or GPS.
**Password encryption**
You should always encrypt passwords, tokens, API credentials, and similar authentication data.
**Process-level remediation**
It is important to protect operating system (for example, Linux, Windows, iOS, Android) processes and make sure an attacker has not created or manipulated any processes in the underlying system.
**Patch management**
Patch management is the process of distributing, installing, and applying software updates. A patch management policy lists guidelines for proper management of vulnerabilities and includes phases such as testing, deploying, and documenting the security patches applied to your organization.
**Key rotation**
It is important to have and use a process for retiring an encryption key and replacing it by generating a new cryptographic key. Rotating keys at regular intervals allows you to reduce the attack surface and meet industry standards and compliance.
**Certificate management**
It is important to enroll, generate, manage, and revoke digital certificates in a secure manner.
**Secrets management solution**
You can take advantage of a number of tools and techniques to manage authentication credentials (secrets). These secrets include passwords, API keys, and tokens used in applications, services, and specialized systems. Employing a good secrets management solution enables you to eliminate hard-coded credentials, enforce password best practices (or eliminate passwords with other types of authentication), perform credential use monitoring, and extend secrets management to third parties in a secure manner. Examples of secrets management solutions offered by cloud providers include AWS Secrets Manager ([_https://aws.amazon.com/secrets-manager_](https://aws.amazon.com/secrets-manager)) and Google Cloud Secret Manager ([_https://cloud.google.com/secret-manager_](https://cloud.google.com/secret-manager)).
**Network segmentation**
Segmenting a network may involve using a combination of technologies such as firewalls, VLANs, access control lists in routers, and other techniques. For decades, servers were assigned subnets and VLANs. Sounds pretty simple, right? Well, it introduced a lot of complexities because application segmentation and policies were physically restricted to the boundaries of the VLAN within the same data center (or even in the campus). In virtual environments, the problem became bigger. Today applications can move around between servers to balance loads for performance or high availability upon failures. They can also move between different data centers and even different cloud environments.

Traditional segmentation based on VLANs constrains you to maintain policies related to which application needs to talk to which application (and who can access such applications) in centralized firewalls. This is ineffective because most traffic in data centers is now “east-west” traffic, and a lot of that traffic does not even hit the traditional firewall. In virtual environments, a lot of the traffic does not leave the physical server. You need to apply policies to restrict whether application A needs or does not need to talk to application B or which application should be able to talk to the database. These policies should not be bound by which VLAN or IP subnet the application belongs to and whether it is in the same rack or even in the same data center.

Network traffic should not make multiple trips back and forth between the applications and centralized firewalls to enforce policies between VMs. The ability to enforce network segmentation in those environments is called _microsegmentation_, and microsegmentation is at the VM level or between containers, regardless of a VLAN or a subnet. Microsegmentation solutions need to be application aware. This means that the segmentation process starts and ends with the application itself. Most microsegmentation environments apply a _zero-trust model_ , which dictates that users cannot talk to applications and applications cannot talk to other applications unless a defined set of policies permits them to do so.

## Administrative Controls
**_Administrative controls_** are policies, rules, or training that are designed and implemented to reduce risk and improve safety. The following are examples of administrative controls that may be recommended in your penetration testing report. Select each administrative control for more information.
**Role-based access control (RBAC)**
This type of control bases access permissions on the specific role or function. Administrators grant access rights and permissions to roles. Each user is then associated with a role. There is no provision for assigning rights to a user or group account. For example, say that you have two users: Hannah and Derek. Derek is associated with the role of Engineer and inherits all the permissions assigned to the Engineer role. Derek cannot be assigned any additional permissions. Hannah is associated with the role “Sales” and inherits all the permissions assigned to the Sales role and cannot access Engineer resources. Users can belong to multiple groups. RBAC enables you to control what users can do at both broad and granular levels.
**Secure software development life cycle**
The software development life cycle (SDLC) provides a structured and standardized process for all phases of any system development effort. The act of incorporating security best practices, policies, and technologies to find and remediate vulnerabilities during the SDLC is referred to as the secure software development life cycle (SSDLC). OWASP provides several best practices and guidance on implementing the SSDLC at [_https://owasp.org/www-project-integration-standards/writeups/owasp_in_sdlc_](https://owasp.org/www-project-integration-standards/writeups/owasp_in_sdlc). In addition, the OWASP Software Assurance Maturity Model (SAMM) provides an effective and measurable way for all types of organizations to analyze and improve their software security posture. You can find more details about OWASP’s SAMM at [_https://owaspsamm.org_](https://owaspsamm.org/).
**Minimum password requirements**
Different organizations may have different password complexity requirements (for example, minimum length, the use of uppercase letters, lowercase letters, numeric, and special characters). At the end of the day, the best solution is to use multifactor authentication (as discussed earlier in this module) instead of just simple password authentication.
**Policies and procedures**
A cybersecurity policy is a directive that defines how the organization protects its information assets and information systems, ensures compliance with legal and regulatory requirements, and maintains an environment that supports the guiding principles. The objective of a cybersecurity policy and corresponding program is to protect the organization, its employees, its customers, and its vendors and partners from harm resulting from intentional or accidental damage, misuse, or disclosure of information, as well as to protect the integrity of the information and ensure the availability of information systems. Successful policies establish what must be done and why it must be done–but not how to do it. A good policy must be endorsed, relevant, realistic, attainable, adaptable, enforceable, and inclusive.

## Operational Controls
**_Operational controls_** focus on day-to-day operations and strategies. They are implemented by people instead of machines and ensure that management policies are followed during intermediate-level operations. The following are examples of operational controls that often allow organizations to improve their security operations. Select each operation control for more information.
**Job rotation**
Allowing employees to rotate from one team to another or from one role to a different one allows individuals to learn new skills and get more exposure to other security technologies and practices.
**Time-of-day restrictions**
You might want to restrict access to users based on the time of the day. For example, you may only allow certain users to access specific systems during working hours.
**Mandatory vacations**
Depending on your local labor laws, you may be able to mandate that your employees take vacations during specific times (for example, mandatory holiday shutdown periods).
**User training**
All employees, contractors, interns, and designated third parties must receive security training appropriate to their position throughout their tenure. The training must cover at least compliance requirements, company policies, and handling of standards. A user should have training and provide written acknowledgment of rights and responsibilities prior to being granted access to information and information systems. Organizations will reap significant benefits from training users throughout their tenure.

Security awareness programs, security training, and security education all serve to reinforce the message that security is important. Security awareness programs are designed to remind users of appropriate behaviors. Security education and training teach specific skills and are the basis for decision-making. The National Institute of Standards and Technology (NIST) published Special Publication 800-50, “Building an Information Technology Security Awareness and Training Program,” which succinctly defines why security education and training are so important.

## Physical Controls
**_Physical controls_** use security measures to prevent or deter unauthorized access to sensitive locations or material. The following are examples of physical controls that can be recommended in your penetration testing report. Select each physical control for more information.
**Access control vestibule**
An access control vestibule (formerly known as a mantrap) is a space with typically two sets of interlocking doors, where one door must close before the second door opens.
**Biometric controls**
These controls include fingerprint scanning, retinal scanning, and face recognition, among others.
**Video surveillance**
Cameras may be used to record and monitor activities in the physical premises.

# Importance of Communication
The report is the final deliverable in a penetration test. It communicates all the activities performed during the test as well as the ultimate results in the form of findings and recommendations. The report is, however, not the only form of communication that you will have with a client during a penetration testing engagement. During the testing phases of the engagement, certain situations may arise in which you need to have a plan for communication and escalation.

Poor communication among stakeholders, including your client and your own team, can also contribute to scope creep.

It is extremely important that you understand the _communication path_ and communication channels with your client. You should always have good open lines of communication with your client and the stakeholders that hired you, including the following:
- **Primary contact:** This is the stakeholder who hired you or the main contact identified by the person who hired you.
- **Technical contacts:** You should document any IT staff or security analysts/engineers that you might need to contact for assistance during the testing.
- **Emergency contacts:** You should clearly document who should be contacted in case of an emergency.

## Communication Triggers
It is important that you have _situational awareness_ to properly communicate any significant findings to your client. The following are a few examples of communication triggers:
- **Critical findings:** You should document (as early as in the pre-engagement phase) how critical findings should be communicated and when. Your client might require you to report any critical findings at the time of discovery instead of waiting to inform the client in your final report.
- **Status reports:** Your client may ask you to provide periodic status reports about how the testing is progressing.
- **Indicators of prior compromise:** During a penetration test, you may find that a real (malicious) attacker has likely already compromised the system. You should immediately communicate any indicators of prior compromise and not wait until you deliver the final report.

## Reasons for Communication
You should know the proper ways to _deescalate_ any situation you may encounter with a client. You should also try to _deconflict_ any potentially redundant or irrelevant information from your report and communication with your client. Try to identify and avoid _false positives_ in your report.

You should also report any _criminal activity_ that you may have discovered. For example, you may find that one of the employees may be using corporate assets to attack another company, steal information, or perform some other illegal activity.
>[!TIP]  
>The term _false positive_ is a broad term that describes a situation in which a security device triggers an alarm but there is no malicious activity or actual attack taking place. In other words, false positives are “false alarms”; they are also called “benign triggers”. False positives are problematic because by triggering unjustified alerts, they diminish the value and urgency of real alerts. Having too many false positives to investigate becomes an operational nightmare and is likely to cause you to overlook real security events.
>There are also _false negatives_, which are malicious activities that are not detected by a network security device. 
>A _true positive_ is a successful identification of a security attack or a malicious event. 
>A _true negative_ occurs when an intrusion detection device identifies an activity as acceptable behavior, and the activity is actually acceptable.
## Goal Reprioritization and Presentation of Findings
Depending on the vulnerabilities and weaknesses that you find during a penetration testing engagement, your client may tweak or reprioritize the goal of the testing. Your client may prioritize some systems or applications that may not have been seen as critical. Similarly, your client might ask you to deprioritize some activities in order to focus on some goals that may now present a higher risk.

>[!TIP] The report is the final deliverable for a penetration test. It communicates all the activities performed during the test as well as the ultimate results in the form of findings and recommendations. The report is, however, not the only form of communication that you will have with a client during a penetration testing engagement. During the testing phases of the engagement, certain situations may arise in which you need to have a plan for communication and escalation.

The findings and recommendations section is the meat of a penetration testing report. The information provided here is what will be used to move forward with remediation and mitigation of the issues found in the environment being tested. Whereas earlier sections of the report, such as the executive summary, are purposely not too technical, the findings and recommendations section should provide all the technical details necessary that teams like IT, information security, and development need to use the report to address the issues found in the testing phase.

# Post-Report Delivery Activities
There are several important activities that you must complete after delivering a penetration testing report to a client.
## Post-Engagement Cleanup
Say that you have completed all the testing phases for a penetration test. What you do next is very important to the success of the engagement. Throughout your testing phases, you have likely used many different tools and techniques to gather information, discover vulnerabilities, and perhaps exploit the systems under test. These tools can and most likely will cause residual effects on the systems you have been testing.

Let’s say, for instance, that you have completed a web application penetration test and used an automated web vulnerability scanner in your testing process. This type of tool is meant to discover issues such as input validation and SQL injection. To identify these types of flaws, the automated scanner needs to actually input information into the fields it is testing. The input can be fake data or even malicious scripts. As this information is being input, it will likely make its way into the database that is supporting the web application you are testing. When the testing is complete, that information needs to be cleaned from the database. The best option for this is usually to revert or restore the database to a previous state. This is why it is suggested to test against a staging environment when possible. This is just one example of a cleanup task that needs to be performed at the end of a penetration testing engagement.

Another common example of necessary cleanup is the result of any exploitation of client machines. Say that you are looking to gain shell access to a Windows system that you have found to be vulnerable to a buffer overflow vulnerability that leads to remote code execution. Of course, when you find that this machine is likely vulnerable, you are excited because you know that the Metasploit framework has a module that will allow you to easily exploit the vulnerability and give you a _root shell_ on the system. You run the exploit, but you get an error message that it did not complete, and there may be cleanup necessary. Most of the time, the error message indicates which files you need to clean up. However, it may not, and if it doesn’t, you need to take a look at the specific module code to determine what files you need to clean up. Many tools can leave behind residual files or data that you need to be sure to clean from the target systems after the testing phases of a penetration testing engagement are complete. It is also very important to have the client or system owner validate that your cleanup efforts are sufficient. This is not always easy to accomplish, but providing a comprehensive list of activities performed on any systems under test will help with this.

The following are some examples of the items you will want to be sure to clean from systems:

- **Tester-created credentials**: Remove any user accounts that you created to maintain persistent access or for any other post-exploitation activity.
- **Shells**: Remove shells spawned on exploited systems.
- **Tools**: Remove any tools installed or run from the systems under test.

## Additional Post-Report Delivery Activities
**Client acceptance**
You should have written documentation of your client’s acceptance of your report and related deliverables.
**Lessons learned**
It is important to analyze and present any lessons learned during the penetration testing engagement.
**Follow-up actions/retest**
Your client may ask you to retest different applications or systems after you provide the report. You should follow up and take care of any action items in an agreed appropriate time frame.
**Attestation of findings**
You should provide clear acknowledgement proving that the assessment was performed and reporting your findings.
**Data destruction process**
You need to destroy any client sensitive data as agreed in the pre-engagement activities.

