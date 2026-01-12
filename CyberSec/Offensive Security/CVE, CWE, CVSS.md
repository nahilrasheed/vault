---
tags:
  - CyberSec
---
## CVE
The Common Vulnerabilities and Exposures (CVE) is a list of publicly known vulnerabilities; each is assigned an ID number, description, and reference.
Common Vulnerabilities and Exposures (CVE) is an effort that reaches across international cybersecurity communities. It was created in 1999 with the idea of consolidating cybersecurity tools and databases. 
A CVE ID is composed of the letters CVE followed by the year of publication and four or more digits in the sequence number portion of the ID (for example, CVE-YYYY-NNNN with four digits in the sequence number, CVE-YYYY-NNNNN with five digits in the sequence number, CVE-YYYY-NNNNNNN with seven digits in the sequence number, and so on). 

CVE Numbering Authority (CNA): An organization that volunteers to analyze and distribute information on eligible CVEs

CVE™ list criteria: 
1. Independent of other issues
2. Recognized as a potential security risk
3. Submitted with supporting evidence
4. Only affect one codebase

- [https://cve.mitre.org](https://cve.mitre.org/)
- [www.cve.org](https://www.cve.org) 
## CWE
Common Weakness Enumeration (CWE), at a high level, is a list of software weaknesses. The purpose of CWE is to create a common language to describe software security weaknesses that are the root causes of given vulnerabilities. CWE provides a common baseline for weakness identification to aid the mitigation process. 
You can obtain additional information about CWE at MITRE’s site: _[https://cwe.mitre.org](https://cwe.mitre.org/)_
## CVSS
Each vulnerability represents a potential risk that threat actors can use to compromise your systems and your network. Each vulnerability carries an associated amount of risk. One of the most widely adopted standards ==for calculating the severity of a given vulnerability== is the Common Vulnerability Scoring System (CVSS), which has three components: base, temporal, and environmental scores. Each component is presented as a score on a scale from 0 to 10.
CVSS is an industry standard maintained by the Forum of Incident Response and Security Teams (FIRST) that is used by many Product Security Incident Response Teams (PSIRTs) to convey information about the severity of vulnerabilities they disclose to their customers. 
In CVSS, a vulnerability is evaluated according to three aspects, with a score assigned to each of them:
### Base group
The base group represents the intrinsic characteristics of a vulnerability that are constant over time and do not depend on a user-specific environment. This is the most important information and the only aspect that’s mandatory to obtain a vulnerability score.
Includes exploitability metrics (for example, attack vector, attack complexity, privileges required, user interaction) and impact metrics (for example, confidentiality impact, integrity impact, availability impact). In addition to these two metrics, a metric called Scope Change (S) is used to convey the impact on other systems that may be impacted by the vulnerability but do not contain the vulnerable code. For instance, if a router is susceptible to a DoS vulnerability and experiences a crash after receiving a crafted packet from the attacker, the scope is changed, since the devices behind the router will also experience the denial-of-service condition.
### Temporal metric group
The temporal group assesses the vulnerability as it changes over time.  
Includes exploit code maturity, remediation level, and report confidence.
### Environmental group
The environmental group represents the characteristics of a vulnerability, taking into account the organizational environment.
Includes modified base metrics, confidentiality, integrity, and availability requirements. 

CVSS includes different metrics and measures that describe the impact of each vulnerability. This risk prioritization can help your customer understand the business impact (business impact analysis) of the vulnerabilities that you found during the penetration testing engagement. You can find full explanations of the CVSS metric groups as well as details on how to calculate scores by accessing the Common Vulnerability Scoring System User Guide at [_https://www.first.org/cvss/user-guide_](https://www.first.org/cvss/user-guide).

The score for the base group is between 0 and 10, where 0 is the least severe and 10 is assigned to highly critical vulnerabilities. For example, a highly critical vulnerability could allow an attacker to remotely compromise a system and get full control. In addition, the score comes in the form of a vector string that identifies each of the components used to make up the score. The formula used to obtain the score takes into account various characteristics of the vulnerability and how the attacker is able to leverage these characteristics.
- FIRST provides additional examples at _[https://www.first.org/cvss/](https://www.first.org/cvss/)_.
- CVSS 3.1 Calculator at [https://www.first.org/cvss/calculator/3.1](https://www.first.org/cvss/calculator/3.1)

The Open Web Application Security Project (OWASP) publishes the Risk Rating Methodology to help with estimating the risk of a vulnerability as it pertains to a business. It is part of the OWASP Testing Guide, at [_https://owasp.org/www-project-web-security-testing-guide_](https://owasp.org/www-project-web-security-testing-guide).