---
tags:
  - CiscoEH
  - GRC
  - CyberSec
---
## **Key Technical Elements in Regulations You Should Consider**
Most regulations dictate several key elements, and a penetration tester should pay attention to and verify them during assessment to make sure the organization is compliant. Select each element for more information.
### **Data Isolation**  
Organizations that need to comply with PCI DSS (and other regulations, for that matter) should have a data isolation strategy. Also known as network isolation or network segmentation, the goal is to implement a completely isolated network that includes all systems involved in payment card processing.
### **Password Management**
Most regulations mandate solid password management strategies. For example, organizations must not use vendor-supplied defaults for system passwords and security parameters. This requirement also extends far beyond its title and enters the realm of configuration management. In addition, most of these regulations mandate specific implementation standards, including password length, password complexity, and session timeout, as well as the use of multifactor authentication.
### **Key Management**
This is another important element that is also evaluated and mandated by most regulations. A _key_ is a value that specifies what part of the algorithm to apply and in what order, as well as what variables to input. Much as with authentication passwords, it is critical to use a strong key that cannot be discovered and to protect the key from unauthorized access. Protecting the key is generally referred to as _key management_. NIST SP 800-57: Recommendations for Key Management, Part 1: General (Revision 4) provides general guidance and best practices for the management of cryptographic keying material. Part 2: Best Practices for Key Management Organization provides guidance on policy and security planning requirements for U.S. government agencies. Part 3: Application Specific Key Management Guidance provides guidance when using the cryptographic features of current systems. In the Introduction to Part 1, NIST describes the importance of key management as follows:

The proper management of cryptographic keys is essential to the effective use of cryptography for security. Keys are analogous to the combination of a safe. If a safe combination is known to an adversary, the strongest safe provides no security against penetration. Similarly, poor key management may easily compromise strong algorithms. Ultimately, the security of information protected by cryptography directly depends on the strength of the keys, the effectiveness of mechanisms and protocols associated with keys, and the protection afforded to the keys. All keys need to be protected against modification, and secret and private keys need to be protected against unauthorized disclosure. Key management provides the foundation for the secure generation, storage, distribution, use, and destruction of keys.

Key management policy and standards should include assigned responsibility for key management, the nature of information to be protected, the classes of threats, the cryptographic protection mechanisms to be used, and the protection requirements for the key and associated processes.

**NOTE** The following website includes NIST’s general key management guidance: [_https://csrc.nist.gov/projects/key-management/key-management-guidelines_](https://csrc.nist.gov/projects/key-management/key-management-guidelines).
# Regulations
## **_General Data Protection Regulation (GDPR)_**
GDPR includes strict rules around the processing of data and privacy. One of the GDPR’s main goals is to strengthen and unify data protection for individuals within the European Union (EU), while addressing the export of personal data outside the EU. In short, the primary objective of the GDPR is to give citizens control of their personal data. You can obtain additional information about GDPR at [_https://gdpr-info.eu_](https://gdpr-info.eu/).

## **PCI DSS**
In order to protect cardholders against misuse of their personal information and to minimize payment card channel losses, the major payment card brands (Visa, MasterCard, Discover, and American Express) formed the Payment Card Industry Security Standards Council (PCI SSC) and developed the Payment Card Industry Data Security Standard (PCI DSS). 
The PCI DSS regulation aims to secure the processing of credit card payments and other types of digital payments. 
PCI DSS specifications, documentation, and resources can be accessed at [_https://www.pcisecuritystandards.org_](https://www.pcisecuritystandards.org/).

PCI DSS must be adopted by any organization that transmits, processes, or stores payment card data or that directly or indirectly affects the security of cardholder data. Any organization that leverages a third party to manage cardholder data has the full responsibility of ensuring that this third party is compliant with PCI DSS. The payment card brands can levy fines and penalties against organizations that do not comply with the requirements and/or can revoke their authorization to accept payment cards.

To counter the potential for staggering losses, the payment card brands contractually require that all organizations that store, process, or transmit cardholder data and/or sensitive authentication data comply with PCI DSS. PCI DSS requirements apply to all system components where _account data_ is stored, processed, or transmitted.
Account data consists of cardholder data as well as sensitive authentication data. A system component is any network component, server, or application that is included in, or connected to, the cardholder data environment. The _cardholder data environment_ is defined as the people, processes, and technology that handle cardholder data or sensitive authentication data.

| **Cardholder Data**           | **Sensitive Authentication Data**                      |
| ---------------------------- | ------------------------------------------------------ |
| Primary account number (PAN) | Full magnetic stripe data or equivalent data on a chip |
| Cardholder name              | CAV2/CVC2/CVV2/CID                                     |
| Expiration date              | PINs/PIB blocks                                        |
| Service code                 |                                                        |
The PAN is the defining factor in the applicability of PCI DSS requirements. PCI DSS requirements apply if the PAN is stored, processed, or transmitted. If the PAN is not stored, processed, or transmitted, PCI DSS requirements do not apply. If cardholder name, service code, and/or expiration date are stored, processed, or transmitted with the PAN or are otherwise present in the cardholder data environment, they too must be protected. Per the standards, the PAN must be stored in an unreadable (encrypted) format. Sensitive authentication data may never be stored post-authorization, even if encrypted.

The Luhn algorithm, or Luhn formula, is an industry algorithm used to validate different identification numbers, including credit card numbers, International Mobile Equipment Identity (IMEI) numbers, national provider identifier numbers in the United States, Canadian Social Insurance Numbers, and more. The Luhn algorithm, created by Hans Peter Luhn in 1954, is now in the public domain.
Most credit cards and many government organizations use the Luhn algorithm to validate numbers. The Luhn algorithm is based on the principle of modulo arithmetic and digital roots. It uses modulo-10 mathematics.
## **HIPAA**
The original intent of the Health Insurance Portability and Accountability Act of 1996 (HIPAA) regulation was to simplify and standardize healthcare administrative processes. Administrative simplification called for the transition from paper records and transactions to electronic records and transactions. The U.S. Department of Health and Human Services (HHS) was instructed to develop and publish standards to protect an individual’s electronic health information while permitting appropriate access and use of that information by healthcare providers and other entities. Information about HIPAA can be obtained from [_https://www.cdc.gov/phlp/publications/topic/hipaa.html_](https://www.cdc.gov/phlp/publications/topic/hipaa.html).

On February 20, 2003, the Security Standards for the Protection of Electronic Protected Health Information, known as the HIPAA Security Rule, was published. The Security Rule requires technical and nontechnical safeguards to protect electronic health information. The corresponding HIPAA Security Enforcement Final Rule was issued on February 16, 2006. Since then, the following legislation has modified and expanded the scope and requirements of the Security Rule:
- The 2009 Health Information Technology for Economic and Clinical Health Act (known as the HITECH Act)
- The 2009 Breach Notification Rule
- The 2013 Modifications to the HIPAA Privacy, Security, Enforcement, and Breach Notification Rules under the HITECH Act and the Genetic Information Nondiscrimination Act; Other Modifications to the HIPAA Rules (known as the Omnibus Rule)
HHS has published additional cybersecurity guidance to help healthcare professionals defend against security vulnerabilities, ransomware, and modern cybersecurity threats. See [_https://www.hhs.gov/hipaa/for-professionals/security/guidance/ cybersecurity/index.html_](https://www.hhs.gov/hipaa/for-professionals/security/guidance/).

The HIPAA Security Rule focuses on safeguarding electronic protected health information (ePHI), which is defined as individually identifiable health information (IIHI) that is stored, processed, or transmitted electronically. The HIPAA Security Rule applies to covered entities and business associates. Covered entities include healthcare providers, health plans, healthcare clearinghouses, and certain business associates. Select each covered entity for more information.

## **FedRAMP**
The U.S. federal government uses the Federal Risk and Authorization Management Program (FedRAMP) standard to authorize the use of cloud service offerings. You can obtain information about FedRAMP at [_https://www.fedramp.gov_](https://www.fedramp.gov/).
## **Regulations in the Financial Sector**
The financial sector is responsible for safeguarding customer information and maintaining the critical infrastructure of financial services. 
Examples of regulations applicable to the financial sector:
- Title V, Section 501(b) of the Gramm-Leach-Bliley Act (GLBA) and the corresponding interagency guidelines
- The Federal Financial Institutions Examination Council (FFIEC)
- The Federal Deposit Insurance Corporation (FDIC) Safeguards Act and Financial Institutions Letters (FILs)
- The New York Department of Financial Services Cybersecurity Regulation (NY DFS Cybersecurity Regulation; 23 NYCRR Part 500)
GLBA applies to all financial services organizations, including non-traditional financial institutions such as check-cashing businesses, payday lenders, and technology vendors providing loans to clients. Compliance with some regulations, such as GLBA and NY DFS Cybersecurity Regulation, is mandatory. The regulations mandate financial institutions to undergo periodic penetration testing and vulnerability assessments in their infrastructure. The Federal Trade Commission (FTC) is responsible for enforcing GLBA as it pertains to financial firms not covered by federal banking agencies, the Securities and Exchange Commission (SEC), the Commodity Futures Trading Commission (CFTC), and state insurance authorities.
