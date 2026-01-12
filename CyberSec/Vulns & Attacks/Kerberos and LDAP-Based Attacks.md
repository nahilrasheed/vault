Kerberos is an authentication protocol defined in RFC 4120 that has been used by Windows for a number of years. Kerberos is also used by numerous applications and other operating systems. The Kerberos Consortium’s website provides detailed information about Kerberos at https://www.kerberos.org. 
A Kerberos implementation contains three basic elements:
- Client
- Server
- Key distribution center (KDC), including the authentication server and the ticket-granting server

**Steps in Kerberos Authentication**
- Step 1. The client sends a request to the authentication server within the KDC.
- Step 2. The authentication server sends a session key and a ticket-granting ticket (TGT) that is used to verify the client’s identity.
- Step 3. The client sends the TGT to the ticket-granting server.
- Step 4. The ticket-granting server generates and sends a ticket to the client.
- Step 5. The client presents the ticket to the server.
- Step 6. The server grants access to the client.

[[Active Directory]] uses Lightweight Directory Access Protocol (LDAP) as an access protocol. The Windows LDAP implementation supports Kerberos authentication. LDAP uses an inverted-tree hierarchical structure called the Directory Information Tree (DIT). In LDAP, every entry has a defined position. The Distinguished Name (DN) represents the full path of the entry.

## Kerberos Attacks
### Kerberos golden ticket attack
One of the most common attacks is the Kerberos golden ticket attack. An attacker can manipulate Kerberos tickets based on available hashes by compromising a vulnerable system and obtaining the local user credentials and password hashes. If the system is connected to a domain, the attacker can identify a Kerberos TGT (KRBTGT) password hash to get the golden ticket.

> **TIP** Empire is a popular tool that can be used to perform golden ticket and many other types of attacks. Empire is basically a post-exploitation framework that includes a pure-PowerShell Windows agent and a Python agent. With Empire, you can run PowerShell agents without needing to use powershell.exe. You can download Empire and access demonstrations, presentations, and documentation at [_https://github.com/BC-SECURITY/Empire_](https://github.com/BC-SECURITY/Empire). Empire has a Mimikatz golden_ticket module, which can be used to perform a golden ticket attack. When the Empire Mimikatz golden_ticket module is run against a compromised system, the golden ticket is established for the user using the KRBTGT password hash.
### Kerberos silver ticket attack
A similar attack is the _Kerberos silver ticket attack_. _Silver tickets_ are forged service tickets for a given service on a particular server. The Windows Common Internet File System (CIFS) allows you to access files on a particular server, and the HOST service allows you to execute **schtasks.exe** or Windows Management Instrumentation (WMI) on a given server. In order to create a silver ticket, you need the system account (ending in $), the security identifier (SID) for the domain, the fully qualified domain name, and the given service (for example, CIFS, HOST). You can also use tools such as Empire to get the relevant information from a Mimikatz dump for a compromised system.
### Unconstrained Kerberos delegation.
Another weakness in Kerberos implementations is the use of unconstrained Kerberos delegation. Kerberos delegation is a feature that allows an application to reuse the end-user credentials to access resources hosted on a different server. Typically you should allow Kerberos delegation only if the application server is ultimately trusted; however, allowing it could have negative security consequences if abused, and Kerberos delegation is therefore not enabled by default in Active Directory.

### Kerberoasting
Another attack against Kerberos-based deployments is Kerberoasting. **_Kerberoasting_** is a post-exploitation activity that is used by an attacker to extract service account credential hashes from Active Directory for offline cracking. It is a pervasive attack that exploits a combination of weak encryption implementations and improper password practices. Kerberoasting can be an effective attack because the threat actor can extract service account credential hashes without sending any IP packets to the victim and without having domain admin credentials.
