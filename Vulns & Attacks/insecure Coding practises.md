---
tags:
  - CyberSec
  - CiscoEH
---
### Comments in Source Code
Often developers include information in source code that could provide too much information and might be leveraged by an attacker. For example, they might provide details about a system password, API credentials, or other sensitive information that an attacker could find and use.
- CWE-615, “Information Exposure Through Comments,” - [_https://cwe.mitre.org/data/definitions/615.html_](https://cwe.mitre.org/data/definitions/615.html).

### Lack of Error Handling and Overly Verbose Error Handling
Improper error handling is a type of weakness and security malpractice that can provide information to an attacker to help him or her perform additional attacks on the targeted system. Error messages such as error codes, database dumps, and stack traces can provide valuable information to an attacker, such as information about potential flaws in the applications that could be further exploited.

A best practice is to handle error messages according to a well-thought-out scheme that provides a meaningful error message to the user, diagnostic information to developers and support staff, and no useful information to an attacker.
**TIP** OWASP provides detailed examples of improper error handling at [_https://owasp.org/www-community/Improper_Error_Handling_](https://owasp.org/www-community/Improper_Error_Handling). OWASP also provides a cheat sheet that discusses how to find and prevent error handling vulnerabilities; see [_https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html_](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).

### Hard-Coded Credentials
Hard-coded credentials are catastrophic flaws that an attacker can leverage to completely compromise an application or the underlying system. MITRE covers this malpractice (or weakness) in CWE-798. You can obtain detailed information about CWE-798 at [_https://cwe.mitre.org/data/definitions/798.html_](https://cwe.mitre.org/data/definitions/798.html).

### Race Conditions
A _race condition_ occurs when a system or an application attempts to perform two or more operations at the same time. However, due to the nature of such a system or application, the operations must be done in the proper sequence in order to be done correctly. When an attacker exploits such a vulnerability, he or she has a small window of time between when a security control takes effect and when the attack is performed. The attack complexity in race conditions is very high. In other words, race conditions are very difficult to exploit.

**NOTE** Race conditions are also referred to as _time of check to time of use_ (_TOCTOU_) attacks.
An example of a race condition is a security management system pushing a configuration to a security device (such as a firewall or an intrusion prevention system) such that the process rebuilds access control lists and rules from the system. An attacker may have a very small time window in which it could bypass those security controls until they take effect on the managed device.

### Unprotected APIs
Application programming interfaces (APIs) are used everywhere today. A large number of modern applications use APIs to allow other systems to interact with the application. Unfortunately, many APIs lack adequate controls and are difficult to monitor. The breadth and complexity of APIs also make it difficult to automate effective security testing. There are a few methods or technologies behind modern APIs:
- **Simple Object Access Protocol (SOAP):** This standards-based web services access protocol was originally developed by Microsoft and has been used by numerous legacy applications for many years. SOAP exclusively uses XML to provide API services. XML-based specifications are governed by XML Schema Definition (XSD) documents. SOAP was originally created to replace older solutions such as the Distributed Component Object Model (DCOM) and Common Object Request Broker Architecture (CORBA). You can find the latest SOAP specifications at [_https://www.w3.org/TR/soap_](https://www.w3.org/TR/soap).
- **Representational State Transfer (REST):** This API standard is easier to use than SOAP. It uses JSON instead of XML, and it uses standards such as Swagger and the OpenAPI Specification ( [_https://www.openapis.org_](https://www.openapis.org/) ) for ease of documentation and to encourage adoption.
- **GraphQL:** GraphQL is a query language for APIs that provides many developer tools. GraphQL is now used for many mobile applications and online dashboards. Many different languages support GraphQL. You can learn more about GraphQL at [_https://graphql.org/code_](https://graphql.org/code).

>**NOTE** SOAP and REST use the HTTP protocol. However, SOAP is limited to a more strict set of API messaging patterns than REST. As a best practice, you should always use Hypertext Transfer Protocol Secure (HTTPS), which is the secure version of HTTP. HTTPS uses encryption over the Transport Layer Security (TLS) protocol in order to protect sensitive data.

An API often provides a roadmap that describes the underlying implementation of an application. This roadmap can give penetration testers valuable clues about attack vectors they might otherwise overlook. API documentation can provide a great level of detail that can be very valuable to a penetration tester. API documentation can include the following:
- **Swagger (OpenAPI):** Swagger is a modern framework of API documentation and development that is the basis of the OpenAPI Specification (OAS). Additional information about Swagger can be obtained at [_https://swagger.io_](https://swagger.io/). The OAS specification is available at [_https://github.com/OAI/OpenAPI-Specification_](https://github.com/OAI/OpenAPI-Specification).
- **Web Services Description Language (WSDL) documents:** WSDL is an XML-based language that is used to document the functionality of a web service. The WSDL specification can be accessed at [_https://www.w3.org/TR/wsdl20-primer_](https://www.w3.org/TR/wsdl20-primer).
- **Web Application Description Language (WADL) documents:** WADL is an XML-based language for describing web applications. The WADL specification can be obtained from [_https://www.w3.org/Submission/wadl_](https://www.w3.org/Submission/wadl).

When performing pen testing against an API, it is important to collect full requests by using a proxy such as Burp Suite or OWASP ZAP. It is important to make sure that the proxy is able to collect full API requests and not just URLs because REST, SOAP, and other API services use more than just **GET** parameters.

When you are analyzing the collected requests, look for nonstandard parameters and for abnormal HTTP headers. You should also determine whether a URL segment has a repeating pattern across other URLs. These patterns can include a number or an ID, dates, and other valuable information. Inspect the results and look for structured parameter values in JSON, XML, or even nonstandard structures.

You can also use fuzzing to find API vulnerabilities (or vulnerabilities in any application or system). According to OWASP, “Fuzz testing or Fuzzing is an unknown environment/black box software testing technique, which basically consists in finding implementation bugs using malformed/semi-malformed data injection in an automated fashion.”
When testing APIs, you should always analyze the collected requests to optimize fuzzing. After you find potential parameters to fuzz, determine the valid and invalid values that you want to send to the application. Of course, fuzzing should focus on invalid values (for example, sending a **GET** or **PUT** with large values or special characters, Unicode, and so on).

>**NOTE** OWASP has a REST Security Cheat Sheet that provides numerous best practices on how to secure RESTful (REST) APIs. See [_https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html_](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html).

The following are several general best practices and recommendations for securing APIs:
- Secure API services to provide HTTPS endpoints with only a strong version of TLS.
- Validate parameters in the application and sanitize incoming data from API clients.
- Explicitly scan for common attack signatures; injection attacks often betray themselves by following common patterns.
- Use strong authentication and authorization standards.
- Use reputable and standard libraries to create the APIs.
- Segment API implementation and API security into distinct tiers; doing so frees up the API developer to focus completely on the application domain.
- Identify what data should be publicly available and what information is sensitive.
- If possible, have a security expert do the API code verification.
- Make internal API documentation mandatory.
- Avoid discussing company API development (or any other application development) on public forums.

> **NOTE** CWE-227, “API Abuse,” covers unsecured APIs. For detailed information about CWE-227, see [_https://cwe.mitre.org/data/definitions/227.html_](https://cwe.mitre.org/data/definitions/227.html).

### Hidden Elements
Web application parameter tampering attacks can be executed by manipulating parameters exchanged between the web client and the web server in order to modify application data. This could be achieved by manipulating cookies (as discussed earlier in this module) and by abusing hidden form fields.

It might be possible to tamper with the values stored by a web application in hidden form fields. Let’s take a look at an example of a hidden HTML form field. Suppose that the following is part of an e-commerce site selling merchandise to online customers:
`<input type="" id="123" name="price" value="100.00">`
In the hidden field shown in this example, an attacker could potentially edit the **value** information to reduce the price of an item. Not all hidden fields are bad; in some cases, they are useful for the application, and they can even be used to protect against CSRF attacks.

### Lack of Code Signing
_Code signing_ (or _image signing_) involves adding a digital signature to software and applications to verify that the application, operating system, or any software has not been modified since it was signed. Many applications are still not digitally signed today, which means attackers can easily modify and potentially impersonate legitimate applications.

Code signing is similar to the process used for SSL/TLS certificates. A key pair (one public key and one private key) identifies and authenticates the software engineer (developer) and his or her code. This is done by employing trusted certificate authorities (CAs). Developers sign their applications and libraries using their private key. If the software or library is modified after signing, the public key in a system will not be able to verify the authenticity of the developer’s private key signature.
Subresource Integrity (SRI) is a security feature that allows you to provide a hash of a file fetch by a web browser (client). SRI verifies file integrity and ensures that files are delivered without any tampering or manipulation by an attacker.

