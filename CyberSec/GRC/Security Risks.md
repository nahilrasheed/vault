---
tags:
  - GCPC
  - CyberSec
  - GRC
  - CiscoEH
---
## [[Threats]] and Risks
A threat is any circumstance or event that can negatively impact assets.
- People are the biggest threat to a company’s security. This is why educating employees about security challenges is essential for minimizing the possibility of a breach.
A risk is anything that can impact the confidentiality, integrity, or availability of an asset.
- A low-risk asset is information that would not harm the organization's reputation or ongoing operations, and would not cause financial damage if compromised. This includes public information such as website content, or published research data.
- A medium-risk asset might include information that's not available to the public and may cause some damage to the organization's finances, reputation, or ongoing operations. For example, the early release of a company's quarterly earnings could impact the value of their stock.
- A high-risk asset is any information protected by regulations or laws, which if compromised, would have a severe negative impact on an organization's finances, ongoing operations, or reputation. This could include leaked assets with SPII, PII, or intellectual property.

- Security posture: refers to an organization's ability to manage its defense of critical assets and data and react to change.
## [[Security Frameworks]]
## NIST’s Risk Management Framework (RMF)
7 steps
1. Prepare
	Activities that are necessary to manage security and privacy risks before a breach occurs
2. Categorize
	Used to develop risk management processes and tasks
3. Select
	Choose, customize, and capture documentation of the controls that protect an organization.
4. Implement
	Implement security and privacy plans for the organization.
5. Assess
	Determine if established controls are implemented correctly.
6. Authorize
	Being accountable for the security and privacy risks that may exist in an organization.
7. Monitor
	Be aware of how systems are operating.
## Vulnerabilities
A **vulnerability** is a weakness that can be exploited by a threat. Therefore, organizations need to regularly inspect for vulnerabilities within their systems. Some vulnerabilities include:
- **ProxyLogon:** A pre-authenticated vulnerability that affects the Microsoft Exchange server. This means a threat actor can complete a user authentication process to deploy malicious code from a remote location.
- **ZeroLogon:** A vulnerability in Microsoft’s Netlogon authentication protocol. An authentication protocol is a way to verify a person's identity. Netlogon is a service that ensures a user’s identity before allowing access to a website's location.
- **Log4Shell:** Allows attackers to run Java code on someone else’s computer or leak sensitive information. It does this by enabling a remote attacker to take control of devices connected to the internet and run malicious code.
- **PetitPotam:** Affects Windows New Technology Local Area Network (LAN) Manager (NTLM). It is a theft technique that allows a LAN-based attacker to initiate an authentication request.
- **Security logging and monitoring failures:** Insufficient logging and monitoring capabilities that result in attackers exploiting vulnerabilities without the organization knowing it
- **Server-side request forgery:** Allows attackers to manipulate a server-side application into accessing and updating backend resources. It can also allow threat actors to steal data.
## Security Controls
**Security controls** are safeguards designed to reduce specific security risks. They are used with security frameworks to establish a strong security posture.
Security controls can be organized into three types: Technical, operational, and managerial. 
1. Technical control types include the many technologies used to protect assets. This includes encryption, authentication systems, and others. 
2. Operational controls relate to maintaining the day-to-day security environment. Generally, people perform these controls like awareness training and incident response. 
3. Managerial controls are centered around how the other two reduce risk. Examples of management controls include policies, standards, and procedures. Typically, organization's security policy outlines the controls needed to achieve their goals. 

- Information privacy is the protection of unauthorized access and distribution of data.
- Security controls should be designed with the principle of least privilege in mind. 
- A data owner is a person who decides who can access, edit, use, or destroy their information.
## OWASP Security principles
- **Minimize attack surface area**: Attack surface refers to all the potential vulnerabilities a threat actor could exploit.
- **Principle of least privilege**: Users have the least amount of access required to perform their everyday tasks.
- **Defense in depth**: Organizations should have varying security controls that mitigate risks and threats.
- **Separation of duties**: Critical actions should rely on multiple people, each of whom follow the principle of least privilege. 
- **Keep security simple**: Avoid unnecessarily complicated solutions. Complexity makes security difficult. 
- **Fix security issues correctly**: When security incidents occur, identify the root cause, contain the impact, identify vulnerabilities, and conduct tests to ensure that remediation is successful.
Additional OWASP security principles
- Fail securely: It means that when a control fails or stops, it should do so by defaulting to its most secure option. 
- Don’t trust services: organization shouldn’t explicitly trust that their partners’ systems are secure.
- Avoid security by obscurity: The security of key systems should not rely on keeping details hidden.

> [[CISSP Domains]]

## Asset Security
Asset management is the process of tracking assets and the risks that affect them. The idea behind this process is simple: you can only protect what you know you have. 
**Asset classification** is the practice of labeling assets based on sensitivity and importance to an organization.
#### Common asset classifications
Asset classification helps organizations implement an effective risk management strategy. It also helps them prioritize security resources, reduce IT costs, and stay in compliance with legal regulations.
- **Restricted** is the highest level. This category is reserved for incredibly sensitive assets,  like need-to-know information.
- **Confidential** refers to assets whose disclosure may lead to a significant negative impact on an organization.
- **Internal-only** describes assets that are available to employees and business partners.
- **Public** is the lowest level of classification. These assets have no negative consequences to the organization if they’re released.

