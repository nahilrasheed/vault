Many organizations are moving to the cloud or deploying hybrid solutions to host their applications. Organizations moving to the cloud are almost always looking to transition from capital expenditure (CapEx) to operating expenditure (OpEx). Most Fortune 500 companies operate in a multicloud environment. It is obvious that cloud computing security is more important today than ever before. Cloud computing security includes many of the same functionalities as traditional IT security, including protecting critical information from theft, data exfiltration, and deletion, as well as privacy.

The National Institute of Standards and Technology (NIST) authored Special Publication (SP) 800-145, “The NIST Definition of Cloud Computing,” to provide a standard set of definitions for the different aspects of cloud computing. The SP 800-145 document also compares the different cloud services and deployment strategies. The advantages of using a cloud-based service include the following:
- Distributed storage
- Scalability
- Resource pooling
- Access from any location
- Measured service
- Automated management

## Characteristics of cloud computing
According to NIST, the essential characteristics of cloud computing include the following:
- On-demand self-service
- Broad network access
- Resource pooling
- Rapid elasticity
- Measured service

## Models of cloud computing
Cloud deployment models include the following:
- Public cloud: Open for public use
- Private cloud: Used just by the client organization on premises or at a dedicated area in a cloud provider
- Community cloud: Shared between several organizations
- Hybrid cloud: Composed of two or more clouds (including on-prem services)

Cloud computing can be broken into the following three basic models:
### Infrastructure as a Service (IaaS)
IaaS is a cloud solution in which you rent infrastructure. You purchase virtual power to execute your software as needed. This is much like running a virtual server on your own equipment, except that you run a virtual server on a virtual disk. IaaS is similar to a utility company model in that you pay for what you use.
### Platform as a Service (PaaS)
PaaS provides everything except applications. Services provided by this model include all phases of the systems development life cycle (SDLC) and can use application programming interfaces (APIs), website portals, or gateway software. These solutions tend to be proprietary, which can cause problems if the customer moves away from the provider’s platform.
### Software as a Service (SaaS)
SaaS is designed to provide a complete packaged solution. The software is rented out to the user. The service is usually provided through some type of front end or web portal. While the end user is free to use the service from anywhere, the company pays a per-use fee.

## Cloud security challenges
All service providers do their best to deliver secure products to their customers. Much of their success depends on preventing breaches and how well they can protect sensitive information. However, since data is stored in the cloud and accessed over the internet, several challenges arise:
- **Misconfiguration** is one of the biggest concerns. Customers of cloud-based services are responsible for configuring their own security environment. Oftentimes, they use out-of-the-box configurations that fail to address their specific security objectives.
- **Cloud-native breaches** are more likely to occur due to misconfigured services.
- **Monitoring access might be difficult** depending on the client and level of service.
- **Meeting regulatory standards** is also a concern, particularly in industries that are required by law to follow specific requirements such as HIPAA, PCI DSS, and GDPR.

# Attacks on Cloud
Many attacks against cloud technologies are possible, and the following are just some of them:
## Credential harvesting
**_Credential harvesting_** is not a new attack type, but the methodologies used by attackers have evolved throughout the years. Credential harvesting (or password harvesting) is the act of gathering and stealing valid usernames, passwords, tokens, PINs, and any other types of credentials through infrastructure breaches. One of the most common ways that attackers perform credential harvesting is by using phishing and spear phishing emails with links that could redirect a user to a bogus site. This “fake site” could be made to look like a legitimate cloud service, such as Gmail, Office 365, or even a social media site such as Twitter, LinkedIn, Instagram, or Facebook. This is why it is so important to use multifactor authentication. However, in some cases, attackers could bypass multifactor authentication by redirecting the user to a malicious site and stealing a session cookie from the user’s browser.

Many cloud services and cloud-hosted applications use single sign-on (SSO), and others use federated authentication. Sometimes cloud-based applications allow you to log in with your Google, Apple, or Facebook credentials. Attackers could redirect users to impersonated websites that may look like legitimate Google, Apple, Facebook, or Twitter login pages. From there, the attacker could steal the victim’s username and password.
- [[Social-Engineer Toolkit (SET)]]
Attackers have been known to harvest cloud service provider credentials once they get into their victims’ systems. Different threat actors have extended their credential harvesting capabilities to target multiple cloud and non-cloud services in victims’ internal networks and systems after the exploitation of other vulnerabilities.

## Privilege escalation
**_Privilege escalation_** is the act of exploiting a bug or design flaw in a software or firmware application to gain access to resources that normally would have been protected from an application or a user. This results in a user gaining additional privileges beyond what the application developer originally intended (for example, a regular user gaining administrative control or a particular user being able to read another user’s email without authorization).

The original developer does not intend for the attacker to gain higher levels of access but probably doesn’t enforce a need-to-know policy properly and/or hasn’t validated the code of the application appropriately. Attackers take advantage of this to gain access to protected areas of operating systems or to applications (for example, reading another user’s email without authorization). Buffer overflows are used on Windows computers to elevate privileges as well. To bypass digital rights management (DRM) on games and music, attackers use a method known as _jailbreaking_, which is another type of privilege escalation, most commonly found on Apple iOS-based mobile devices. Malware also attempts to exploit privilege escalation vulnerabilities, if any exist on the system. Privilege escalation can also be attempted on network devices. Generally, the fix for this is simply to update the device and to check for updates on a regular basis.

The following are a couple different types of privilege escalation:
#### Vertical Privilege Escalation
This type of privilege escalation, also called privilege elevation, occurs when a lower-privileged user accesses functions reserved for higher-privileged users (for example, a standard user accessing functions of an administrator). To protect against this situation, you should update the network device firmware. In the case of an operating system, it should again be updated. The use of some type of access control system – for example, User Account Control (UAC)–is also advisable.
#### Horizontal Privilege Escalation
This type of privilege escalation occurs when a normal user accesses functions or content reserved for other normal users (for example, one user reading another’s email). This can be done through hacking or by a person walking over to someone else’s computer and simply reading their email. Always have your users lock their computer (or log off) when they are not physically at their desk.

## Account takeover
The underlying mechanics and the attacker motive of a cloud account takeover attack are the same as for an account takeover that takes place on premises. In an **_account takeover_**, the threat actor gains access to a user or application account and uses it to then gain access to more accounts and information. There are different ways that an account takeover can happen in the cloud. The impact that an account takeover has in the cloud can also be a bit different from the impact of an on-premises attack. Some of the biggest differences are the organization’s ability to detect a cloud account takeover, find out what was impacted, and determine how to remediate and recover.
There are a number of ways to detect account takeover attacks. Select each for more detail.
### Login location
The location of the user can clue you in to a takeover. For instance, you may not do business in certain geographic locations and countries. You can prevent a user from logging in from IP addresses that reside in those locations. Keep in mind, however, that an attacker can easily use a VPN to bypass this restriction.
### Failed login attempts
It is now fairly easy to detect and block failed login attempts from a user or an attacker.
### Lateral phishing emails
These are phishing emails that originate from an account that has already been compromised by the attacker.
### Malicious OAuth, SAML, or OpenID Connect connections
An attacker could create a fake application that could require read, write, and send permissions for email SaaS offerings such as Office 365 and Gmail. Once the application is granted permission by the user to “connect” and authenticate to these services, the attacker could manipulate it.
### Abnormal file sharing and downloading
You might suspect an account takeover attack if you notice that a particular user is suddenly sharing or downloading a large number of files.

## Metadata service attacks
Traditionally, software developers used hard-coded credentials to access different services, such as databases and shared files on an FTP server. To reduce the exposure of such insecure practices, cloud providers (such as Amazon Web Services) have implemented _metadata services_. When an application requires access to specific assets, it can query the metadata service to get a set of temporary access credentials. This temporary set of credentials can then be used to access services such as AWS Simple Cloud Storage (S3) buckets and other resources. In addition, these metadata services are used to store the user data supplied when launching a new virtual machine (VM) – such as an Amazon Elastic Compute Cloud or AWS EC2 instance – and configure the application during instantiation.

As you can probably already guess, metadata services are some of the most attractive services on AWS for an attacker to access. If you are able to access these resources, at the very least, you will get a set of valid AWS credentials to interface with the API. Software developers often include sensitive information in user startup scripts. These user startup scripts can be accessed through a metadata service and allow AWS EC2 instances (or similar services with other cloud providers) to be launched with certain configurations. Sometimes startup scripts even contain usernames and passwords used to access various services.

By using tools such as nimbostratus ([_https://github.com/andresriancho/nimbostratus_](https://github.com/andresriancho/nimbostratus)), you can find vulnerabilities that could lead to **_metadata service attacks_**.
**TIP** When you are pen testing a web application, look for functionality that fetches page data and returns it to the end user (similar to the way a proxy would). The metadata service doesn’t require any particular parameters. If you access the URL https://x.x.x.x/latest/meta-data/iam/security-credentials/IAM_USER_ROLE_HERE, it will return the AccessKeyID, SecretAccessKey, and Token values you need to authenticate into the account.

## Attacks against misconfigured cloud assets
Attackers can leverage misconfigured cloud assets in a number of ways. Select each for more information.
### Identity and Access Management (IAM) Implementations
IAM solutions are used to administer user and application authentication and authorization. Key IAM features include SSO, multifactor authentication, and user provisioning and life cycle management. If an attacker is able to manipulate a cloud-based IAM solution in an IaaS or PaaS environment, it could be catastrophic for the cloud consumer (that is, the organization developing, deploying, and consuming cloud applications).
### Federation Misconfigurations
Federated authentication (or federated identity) is a method of associating a user’s identity across different identity management systems. For example, every time you access a website, a web application, or a mobile application that allows you to log in or register with your Facebook, Google, or Twitter account, that application is using federated authentication.
Often application developers misconfigure the implementation of the underlying protocols used in a federated identity environment (such as SAML, OAuth, and OpenID). For instance, a SAML assertion–that is, the XML document the identity provider sends to the service provider that contains the user authorization–should contain a unique ID that is accepted only once by the application. If you do not configure your application this way, an attacker could replay a SAML message to create multiple sessions. Attackers could also change the expiration date on an expired SAML message to make it valid again or change the user ID to a different valid user. In some cases, an application could grant default permissions or higher permissions to an unmapped user. Subsequently, if an attacker changes the user ID to an invalid user, the application could be tricked into giving access to the specific resource.
In addition, your application might use security tokens like the JSON Web Token (JWT) and SAML assertions to associate permissions from one platform to another. An attacker could steal such tokens and leverage misconfigured environments to access sensitive data and resources.
### Object Storage
Insecure permission configurations for cloud object storage services, such as Amazon’s AWS S3 buckets, are often the cause of data breaches.
### Containerization Technologies
Attacks against container-based deployments (such as Docker, Rocket, LXC, and containerd) have led to massive data breaches. For instance, you can passively obtain information from Shodan (shodan.io) or run active recon scans to find cloud deployments widely exposing the Docker daemon or Kubernetes elements to the Internet. Often attackers use stolen credentials or known vulnerabilities to compromise cloud-based applications. Similarly, attackers use methods such as typosquatting to create malicious containers and post them in Docker Hub. This attack, which can be considered a supply chain attack, can be very effective. You could, for example, download the base image for NGINX or Apache HTTPd from Docker Hub, and that Docker image might include a backdoor that the attacker can use to manipulate your applications and underlying systems.

## Resource exhaustion and denial-of-service (DoS) attacks
One of the benefits of leveraging cloud services is the distributed and resilient architecture that most leading cloud providers offer. This architecture helps minimize the impact of a DoS or distributed denial-of-service (DDoS) attack compared to what it would be if you were hosting your application on premises in your data center. On the other hand, in recent years, the volume of bits per second (bps), packets per second (pps), and HTTP(s) requests per second (rps) have increased significantly. Often attackers use botnets of numerous compromised laptops and desktop systems and compromise mobile, IoT, and cloud-based systems to launch these attacks. Figure 7-3 illustrates the key metrics used to identify volumetric DDoS attacks.
However, attackers can launch more strategic DoS attacks against applications hosted in the cloud that could lead to _resource exhaustion_. For example, they can leverage a single-packet DoS vulnerability in network equipment used in cloud environments, or they can leverage tools to generate crafted packets to cause an application to crash. For instance, you can search in Exploit Database (exploit-db.com) for exploits that can be used to leverage “denial of service” vulnerabilities, where an attacker could just send a few packets and crash an application or the whole operating system.

Another example of a DoS attack that can affect cloud environments is the **_direct-to-origin_** **_(D2O)_** **_attack_**. In a D2O attack, threat actors are able to reveal the origin network or IP address behind a content delivery network (CDN) or large proxy placed in front of web services in a cloud provider. A D2O attack could allow attackers to bypass different anti-DDoS mitigations.

**NOTE** A CDN is a geographically distributed network of proxies in data centers around the world that offers high availability and performance benefits by distributing web services to end users around the world.

## Cloud malware injection attacks
Cloud deployments are susceptible to malware injection attacks. In a **_cloud malware injection attack_**, the attacker creates a malicious application and injects it into a SaaS, PaaS, or IaaS environment. Once the malware injection is completed, the malware is executed as one of the valid instances running in the cloud infrastructure. Subsequently, the attacker can leverage this foothold to launch additional attacks, such as covert channels, backdoors, eavesdropping, data manipulation, and data theft.

## Side-channel attacks
**_Side-channel attacks_** are often based on information gained from the implementation of the underlying computer system (or cloud environment) instead of a specific weakness in the implemented technology or algorithm. For instance, different elements – such as computing timing information, power consumption, electromagnetic leaks, and even sound – can provide detailed information that can help an attacker compromise a system. The attacker aims to gather information from or influence an application or a system by measuring or exploiting indirect effects of the system or its hardware. Most side-channel attacks are used to exfiltrate credentials, cryptographic keys, and other sensitive information by measuring coincidental hardware emissions.

Side-channel attacks can be used against VMs and in cloud computing environments where a compromised system controlled by the attacker and target share the same physical hardware.

Examples of vulnerabilities that could lead to side-channel attacks are the Spectre and Meltdown vulnerabilities affecting Intel, AMD, and ARM processors. Cloud providers that use Intel CPUs in their virtualized solutions could be affected by these vulnerabilities if they do not apply the appropriate patches. You can find information about Spectre and Meltdown at [_https://spectreattack.com_](https://spectreattack.com/).

- Direct-to-origin attacks

**_Software development kits (SDKs)_** and cloud development kits (CDKs) can provide great insights about cloud-hosted applications, as well as the underlying infrastructure. An SDK is a collection of tools and resources to help with the creation of applications (on premises or in the cloud). SDKs often include compilers, debuggers, and other software frameworks.

CDKs, on the other hand, help software developers and cloud consumers deploy applications in the cloud and use the resources that the cloud provider offers. For example, the AWS Cloud Development Kit (AWS CDK) is an open-source software development framework that cloud consumers and AWS customers use to define cloud application resources using familiar programming languages.

**NOTE** The following site provides detailed information on how to get started with the AWS CDK: [_https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html_](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html).

---
Cloud security is one of the fastest growing subfields of cybersecurity. There are a variety of resources available online to learn more about this specialized topic.
- Omar Santos has included several tools that can be used to scan insecure S3 buckets at my GitHub repository, at [_https://github.com/The-Art-of-Hacking/h4cker/tree/master/cloud_resources_](https://github.com/The-Art-of-Hacking/h4cker/tree/master/cloud_resources).
- [The U.K.’s National Cyber Security Centre](https://www.ncsc.gov.uk/collection/cloud/understanding-cloud-services/cloud-security-shared-responsibility-model) has a detailed guide for choosing, using, and deploying cloud services securely based on the shared responsibility model.
- [The Cloud Security Alliance](https://cloudsecurityalliance.org/)® is an organization dedicated to creating secure cloud environments. They offer access to cloud security-specific research, certification, and products to users with a paid membership.
