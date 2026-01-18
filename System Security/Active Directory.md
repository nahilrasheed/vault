Active Directory is a directory service developed by Microsoft for Windows domain networks. 

A **Windows domain** is a group of users and computers under the administration of a given business.

It stores information about network objects such as computers, users, and groups. It provides authentication and authorisation services, and allows administrators to manage network resources centrally.

Advantages:
- **Centralised identity management:** All users across the network can be configured from Active Directory with minimum effort.
- **Managing security policies:** You can configure security policies directly from Active Directory and apply them to users and computers across the network as needed.
## AD Domain Service
The core of any Windows Domain is the **Active Directory Domain Service (AD DS)**. This service acts as a catalogue that holds the information of all of the "objects" that exist on your network.
The associated objects can include:
### **Users**: 
- Individual accounts representing people or services
- Users are one of the most common object types in Active Directory. 
- Users are one of the objects known as **security principals**, meaning that they can be authenticated by the domain and can be assigned privileges over **resources** like files or printers.
- Users can be used to represent two types of entities:
- **People:** users will generally represent persons in your organisation that need to access the network, like employees.
- **Services:** you can also define users to be used by services like IIS or MSSQL. Every single service requires a user to run, but service users are different from regular users as they will only have the privileges needed to run their specific service.
### **Machines**:
- For every computer that joins the Active Directory domain, a machine object will be created. 
- Machines are also considered "security principals" and are assigned an account just as any regular user. This account has somewhat limited rights within the domain itself.
### **Security Groups**: 
- Collections of users or other objects, often with specific permissions.
- Security groups can provide an efficient way to assign access to resources on your network. 
- By using security groups, you can:
- Assign user rights to security groups in Active Directory.
- Assign permissions to security groups for resources.
- Security groups are also considered security principals and, therefore, can have privileges over resources on the network.

Several groups are created by default in a domain that can be used to grant specific privileges to users. As an example, here are some of the most important groups in a domain:

|**Security Group**|**Description**|
|---|---|
|Domain Admins|Users of this group have administrative privileges over the entire domain. By default, they can administer any computer on the domain, including the DCs.|
|Server Operators|Users in this group can administer Domain Controllers. They cannot change any administrative group memberships.|
|Backup Operators|Users in this group are allowed to access any file, ignoring their permissions. They are used to perform backups of data on computers.|
|Account Operators|Users in this group can create or modify other accounts in the domain.|
|Domain Users|Includes all existing user accounts in the domain.|
|Domain Computers|Includes all existing computers in the domain.|
|Domain Controllers|Includes all existing DCs on the domain.|

## AD architecture
The building blocks of an AD architecture include:
### Domains: 
- Logical groupings of network resources such as users, computers, and services. They serve as the main boundary for AD administration and can be identified by their **Domain Component and Domain Controller** name. Everything inside a domain is subject to the same security policies and permissions.
### Organisational Units (OUs): 
- OUs are containers within a domain that help group objects based on departments, locations or functions for easier management. Administrators can apply Group Policy settings to specific OUs, allowing more granular control of security settings or access permissions.
- It is very typical to see the OUs mimic the business' structure, as it allows for efficiently deploying baseline policies that apply to entire departments.
- Default containers created by Windows automatically:
	- **Builtin:** Contains default groups available to any Windows host.
	- **Computers:** Any machine joining the network will be put here by default. You can move them if needed.
	- **Domain Controllers:** Default OU that contains the DCs in your network.
	- **Users:** Default users and groups that apply to a domain-wide context.
	- **Managed Service Accounts:** Holds accounts used by services in your Windows domain.

> [!info] Security Groups vs OUs
>You are probably wondering why we have both groups and OUs. While both are used to classify users and computers, their purposes are entirely different:
>- **OUs** are handy for **applying policies** to users and computers, which include specific configurations that pertain to sets of users depending on their particular role in the enterprise. Remember, a user can only be a member of a single OU at a time, as it wouldn't make sense to try to apply two different sets of policies to a single user.
>- **Security Groups**, on the other hand, are used to **grant permissions over resources**. For example, you will use groups if you want to allow some users to access a shared folder or network printer. A user can be a part of many groups, which is needed to grant access to multiple resources.

### Forest: 
- A collection of one or more domains that share a standard schema, configuration, and global catalogue. The forest is the top-level container in AD.
### Trust Relationships:
- Domains within a forest (and across forests) can establish trust relationships that allow users in one domain to access resources in another, subject to permission.

Combining all these components allows us to establish the **Distinguished Name (DN)** that an object belongs to within the AD. The structure of the name would be as follows:

`DN=CN=John, OU=Management, DC=Bigcompany, DC=thm`

## Core Active Directory Components
Active Directory contains several key components that allow it to provide a wide range of services. Understanding these components will give one a clear picture of how AD supports administrative and security operations.

- **Domain Controllers (DCs):** Domain Controllers are the servers that host Active Directory services. They store the AD database and handle authentication and authorisation requests, such as logging in users or verifying access to resources. Multiple DCs can exist within a domain for redundancy. When changes are made to AD (such as adding users or updating passwords), these changes are replicated across all DCs, ensuring that the directory remains consistent.
- **Global Catalog:** The Global Catalog (GC) is a searchable database within AD that contains a subset of information from all objects in the directory. This allows users and services to locate objects in any domain in the forest, even if those objects reside in different domains.
- **LDAP (Lightweight Directory Access Protocol):** AD uses this protocol to query and modify the directory. The protocol allows for fast searching and retrieving of information about objects such as users, computers, and groups.
- **Kerberos Authentication:** The default authentication protocol used by AD provides secure authentication by using tickets rather than passwords.

## Group Policy
One of Active Directory's most powerful features is **Group Policy**, which allows administrators to enforce policies across the domain. Group Policies can be applied to users and computers to enforce password policies, software deployment, firewall settings, and more.

**Group Policy Objects (GPOs)** are the containers that hold these policies. A GPO can be linked to the entire domain, an OU, or a site, giving the flexibility in applying policies. GPOs are simply a collection of settings that can be applied to OUs. GPOs can contain policies aimed at either users or computers, allowing you to set a baseline on specific machines and identities.

- To configure GPOs, you can use the **Group Policy Management** tool.
-  To configure Group Policies, you first create a GPO under Group Policy Objects and then link it to the OU where you want the policies to apply. 
![[Active Directory-img-202512081118.png]]
- Let's examine the `Default Domain Policy` to see what's inside a GPO. The first tab you'll see when selecting a GPO shows its **scope**, which is where the GPO is linked in the AD. 
- you can also apply **Security Filtering** to GPOs so that they are only applied to specific users/computers under an OU. By default, they will apply to the **Authenticated Users** group, which includes all users/PCs.
- The **Settings** tab includes the actual contents of the GPO and lets us know what specific configurations it applies. As stated before, each GPO has configurations that apply to computers only and configurations that apply to users only. 

eg: 
Ensure all users follow a strict password policy, enforcing minimum password lengths and complexity rules. Here is how it would be done:
1. Using the Run window, open **Group Policy Management** from your server by typing `gpmc.msc`.
2. Right-click your domain and select **"Create a GPO in this domain, and Link it here"**. Name the new GPO **"Password Policy"**.
3. Edit the GPO by navigating to **Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Password Policy**.
4. Configure the following settings:
    - Minimum password length: 12 characters
    - Enforce password history: 10 passwords
    - Maximum password age: 90 days
    - Password must meet complexity requirements: Enabled
5. Click **OK**, then link this GPO to the domain or specific OUs you want to target.

This policy will now be applied across the domain, ensuring all users meet these password requirements.

![[Active Directory-img-202512081118 1.png|Creating and editing GPO settings for Password Policy.]]

### GPO distribution
GPOs are distributed to the network via a network share called SYSVOL, which is stored in the DC. All users in a domain should typically have access to this share over the network to sync their GPOs periodically. The SYSVOL share points by default to the C:\Windows\SYSVOL\sysvol\ directory on each of the DCs in our network.

Once a change has been made to any GPOs, it might take up to 2 hours for computers to catch up. If you want to force any particular computer to sync its GPOs immediately, you can always run the following command on the desired computer: `gpupdate /force`

## Delegation
One of the nice things you can do in AD is to give specific users some control over some OUs. This process is known as **delegation** and allows you to grant users specific privileges to perform advanced tasks on OUs without needing a Domain Administrator to step in.

## Authentication Methods
When using Windows domains, all credentials are stored in the Domain Controllers. Whenever a user tries to authenticate to a service using domain credentials, the service will need to ask the Domain Controller to verify if they are correct. Two protocols can be used for network authentication in windows domains:

- **Kerberos:** Used by any recent version of Windows. This is the default protocol in any recent domain.
- **NetNTLM:** Legacy authentication protocol kept for compatibility purposes.

While NetNTLM should be considered obsolete, most networks will have both protocols enabled.

### Kerberos Authentication

Kerberos authentication is the default authentication protocol for any recent version of Windows. Users who log into a service using Kerberos will be assigned tickets. Think of tickets as proof of a previous authentication. Users with tickets can present them to a service to demonstrate they have already authenticated into the network before and are therefore enabled to use it.

When Kerberos is used for authentication, the following process happens:

1. The user sends their username and a timestamp encrypted using a key derived from their password to the **Key Distribution Center (KDC)**, a service usually installed on the Domain Controller in charge of creating Kerberos tickets on the network.
    
    The KDC will create and send back a **Ticket Granting Ticket (TGT)**, which will allow the user to request additional tickets to access specific services. The need for a ticket to get more tickets may sound a bit weird, but it allows users to request service tickets without passing their credentials every time they want to connect to a service. Along with the TGT, a **Session Key** is given to the user, which they will need to generate the following requests.
    
    Notice the TGT is encrypted using the **krbtgt** account's password hash, and therefore the user can't access its contents. It is essential to know that the encrypted TGT includes a copy of the Session Key as part of its contents, and the KDC has no need to store the Session Key as it can recover a copy by decrypting the TGT if needed.
    
![[Active Directory-img-202512081118 2.png|Kerberos step 1]]

2. When a user wants to connect to a service on the network like a share, website or database, they will use their TGT to ask the KDC for a **Ticket Granting Service (TGS)**. TGS are tickets that allow connection only to the specific service they were created for. To request a TGS, the user will send their username and a timestamp encrypted using the Session Key, along with the TGT and a **Service Principal Name (SPN),** which indicates the service and server name we intend to access.
    
    As a result, the KDC will send us a TGS along with a **Service Session Key**, which we will need to authenticate to the service we want to access. The TGS is encrypted using a key derived from the **Service Owner Hash**. The Service Owner is the user or machine account that the service runs under. The TGS contains a copy of the Service Session Key on its encrypted contents so that the Service Owner can access it by decrypting the TGS.
    

![[Active Directory-img-202512081118 3.png|Kerberos step 2]]

3. The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key.

![[Active Directory-img-202512081118 4.png|Kerberos step 3]]

### NetNTLM Authentication

NetNTLM works using a challenge-response mechanism. The entire process is as follows:

![[Active Directory-img-202512081118 5.png|NetNTLM authentication]]

1. The client sends an authentication request to the server they want to access.
2. The server generates a random number and sends it as a challenge to the client.
3. The client combines their NTLM password hash with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification.
4. The server forwards the challenge and the response to the Domain Controller for verification.
5. The domain controller uses the challenge to recalculate the response and compares it to the original response sent by the client. If they both match, the client is authenticated; otherwise, access is denied. The authentication result is sent back to the server.
6. The server forwards the authentication result to the client.

Note that the user's password (or hash) is never transmitted through the network for security.

**Note:** The described process applies when using a domain account. If a local account is used, the server can verify the response to the challenge itself without requiring interaction with the domain controller since it has the password hash stored locally on its SAM.

## Trees and Forests
When an organization needs to partition its network, perhaps due to legal compliance or the requirement for independent management by separate IT teams—using a single, overly large Active Directory structure becomes cumbersome and prone to errors.

To overcome this, Active Directory allows the integration of multiple domains. If these separate domains share a common, contiguous namespace (e.g., uk.company.local and us.company.local), they can be joined together to form a cohesive unit known as an **Active Directory Tree**. This allows for the network to be logically divided while maintaining a hierarchical relationship.

This partitioned structure gives us better control over who can access what in the domain. The IT people from the UK will have their own DC that manages the UK resources only. For example, a UK user would not be able to manage US users. In that way, the Domain Administrators of each branch will have complete control over their respective DCs, but not other branches' DCs. Policies can also be configured independently for each domain in the tree.

A new security group needs to be introduced when talking about trees and forests. The **Enterprise Admins** group will grant a user administrative privileges over all of an enterprise's domains. Each domain would still have its Domain Admins with administrator privileges over their single domains and the Enterprise Admins who can control everything in the enterprise.  

The domains you manage can also be configured in different namespaces. Suppose your company continues growing and eventually acquires another company. When both companies merge, you will probably have different domain trees for each company, each managed by its own IT department. The union of several trees with different namespaces into the same network is known as a **forest**.
### Trust Relationships
Although organizing domains into trees and forests creates excellent compartmentalization for management and resources, users in one domain often need to access resources in another.

To enable this cross-domain access, domains within trees and forests are connected using **trust relationships.** Simply put, a trust relationship allows you to grant a user from one domain (the trusted domain) permission to access resources on another domain (the trusting domain).

- The most basic configuration is a one-way trust relationship. In a one-way trust, if Domain AAA (the trusting domain) trusts Domain BBB (the trusted domain), then users from BBB can be authorized to access resources located on AAA.
	It is crucial to note that the **direction of a one-way trust is the opposite of the direction of resource access**. If Domain A trusts Domain B, users from B can access A.
- For mutual access, **two-way trust relationships** can be established, allowing users from either domain to be authorized to access resources on the other. By default, when multiple domains are joined together to form an AD Tree or Forest, a **two-way trust relationship is automatically created** between them.
Establishing a trust relationship **does not automatically grant access** to all resources on the trusted domain. It merely creates the **possibility** of cross-domain authorization. The administrator must still explicitly decide which users or groups are actually authorized to access specific resources across the domains.

## Common Active Directory Attacks

Adversaries are always looking for ways to breach and exploit Active Directory environments to destabilise and cause havoc to organisations. Working with Glitch to secure SOC-mas requires us to know common attacks and their mitigation measures.

**Golden Ticket Attack**

A **Golden Ticket** attack allows attackers to exploit the Kerberos protocol and impersonate any account on the AD by forging a Ticket Granting Ticket (TGT). By compromising the **krbtgt** account and using its password hash, the attackers gain complete control over the domain for as long as the forged ticket remains valid. The attack requires four critical pieces of information to be successful:

- Fully Qualified Domain Name (FQDN) of the domain
- SID of the domain
- Username of an account to impersonate
- KRBTGT account password hash

Detection for this type of attack involves monitoring for unusual activity involving the **krbtgt**

- **Event ID 4768**: Look for TGT requests for high-privilege accounts.
- **Event ID 4672**: This logs when special privileges (such as SeTcbPrivilege) are assigned to a user.

**Pass-the-Hash**

This type of attack steals the hash of a password and can be used to authenticate to services without needing the actual password. This is possible because the NTLM protocol allows authentication based on password hashes.

Key ways to mitigate this attack are enforcing strong password policies, conducting regular audits on account privileges, and implementing multi-factor authentication across the domain.

**Kerberoasting**

**Kerberoasting** is an attack targeting Kerberos in which the attacker requests service tickets for accounts with Service Principal Names (SPNs), extracts the tickets and password hashes, and then attempts to crack them offline to retrieve the plaintext password.

Mitigation for this type of attack involves ensuring that service accounts are secured with strong passwords, and therefore, implementing secure policies across the AD would be the defence.

**Pass-the-Ticket**

In a **Pass-the-Ticket** attack, attackers steal Kerberos tickets from a compromised machine and use them to authenticate as the user or service whose ticket was stolen.

This attack can be detected through monitoring for suspicious logins using **Event ID 4768** (TGT request), especially if a user is logging in from unusual locations or devices. Additionally, **Event ID 4624** (successful login) will reveal tickets being used for authentication.

**Malicious GPOs**

Adversaries are known to abuse Group Policy to create persistent, privileged access accounts and distribute and execute malware by setting up policies that mimic software deployment across entire domains. With escalated privileges across the domain, attackers can create GPOs to accomplish goals at scale, including disabling core security software and features such as firewalls, antivirus, security updates, and logging. Additionally, scheduled tasks can be created to execute malicious scripts or exfiltration data from affected devices across the domain.

To mitigate against the exploitation of Group Policy, GPOs need to be regularly audited for unauthorised changes. Strict permissions and procedures for GPO modifications should also be enforced.

**Skeleton Key Attack**

In a **Skeleton Key** attack, attackers install a malware backdoor to log into any account using a master password. The legitimate password for each account would remain unchanged, but attackers can bypass it using the skeleton key password.

## Investigating an Active Directory Breach

**Group Policy**

As previously discussed in this task, Group Policy is a means to distribute configurations and policies to enrolled devices in the domain. For attackers, Group Policy is a lucrative means of spreading malicious scripts to multiple devices.

Reviewing Group Policy Objects (GPOs) is a great investigation step. In this section, we will use PowerShell to audit our GPOs. First, we can use the `Get-GPO` cmdlet to list all GPOs installed on the domain controller.

Listing all GPOs viaPowerShell

```powershell
PS C:\Users\Administrator> Get-GPO -All


DisplayName      : Default Domain Policy
DomainName       : wareville.thm
Owner            : WAREVILLE\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 10/14/2024 12:17:31 PM
ModificationTime : 10/14/2024 12:19:28 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 3, SysVol Version: 3
WmiFilter        :

DisplayName      : Default Domain Controllers Policy
DomainName       : wareville.thm
Owner            : WAREVILLE\Domain Admins
Id               : 6ac1786c-016f-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 10/14/2024 12:17:31 PM
ModificationTime : 10/14/2024 12:17:30 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 1, SysVol Version: 1
WmiFilter        :

DisplayName      : SetWallpaper GPO
DomainName       : wareville.thm
Owner            : WAREVILLE\Domain Admins
Id               : d634d7c1-db7a-4c7a-bf32-efca23d93a56
GpoStatus        : AllSettingsEnabled
Description      : Set the wallpaper of every domain joined machine
CreationTime     : 10/30/2024 9:01:36 AM
ModificationTime : 10/30/2024 9:01:36 AM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        :
```

  

This would allow us to look for out-of-place GPOs. We can export a GPO to an HTML file for further investigation to make it easier to see what configurations the policy enforces. For this example, we will export the "SetWallpaper" GPO.

_Please note that this is a demonstration GPO, and isn't present on the practical machine for today's task._

Exporting SetWallpaperGPO  

```powershell
PS C:\Users\Administrator> Get-GPOReport -Name "SetWallpaper" -ReportType HTML -Path ".\SetWallpaper.html"    
```

  

Then, when opening the HTML file in the browser, we are presented with an overview of things such as:

- When the policy was created and modified.
- What devices or users the GPO applies to.
- The permissions over the GPO.
- The user or computer configurations that it enforces.

![[Active Directory-img-202512081118 6.png|SetWallpaper GPO in a HTML report for easier analysis.]]  

From the screenshot above, we can see that the policy sets the Desktop Wallpaper of devices using the image located in C:\THM.jpg on the domain controller.

Domains are naturally likely to have many GPOs. We can use the same Get-GPO cmdlet, with a bit of _PowerShell-fu_ to list only those GPOs that were recently modified. This is a handy snippet because it highlights policies that were recently modified - perhaps by an attacker.

Listing recently modified GPOs

```powershell
PS C:\Users\Administrator\Desktop> Get-GPO -All | Where-Object { $_.ModificationTime } | Select-Object DisplayName, ModificationTime

DisplayName                                ModificationTime
-----------                                ----------------
Default Domain Policy                      10/14/2024 12:19:28 PM
Default Domain Controllers Policy          10/14/2024 12:17:30 PM
SetWallpaper                               10/31/2024 1:01:04 PM
```

  

## Event Viewer

Windows comes packaged with the Event Viewer. This invaluable repository stores a record of system activity, including security events, service behaviours, and so forth.

For example, within the "Security" tab of Event Viewer, we can see the history of user logins, attempts and logoffs. The screenshot below shows a record of the user "cmnatic" attempting to log into the device.

![[Active Directory-img-202512081118 7.png|Records of a user logging in shown on the Event Viewer.]]  

All categories of events are given an event ID. The table below provides notable event IDs for today's task.

|   |   |
|---|---|
|**Event ID**|**Description**|
|4624|A user account has logged on|
|4625|A user account failed to log on|
|4672|Special privileges (i.e. SeTcbPrivilege) have been assigned to a user|
|4768|A TGT (Kerberos) ticket was requested for a high-privileged account|

  

## User Auditing

User accounts are a valuable and often successful method of attack. You can use Event Viewer IDs to review user events and PowerShell to audit their status. Attack methods such as password spraying will eventually result in user accounts being locked out, depending on the domain controller's lockout policy.

To view all locked accounts, you can use the Search-ADAccount cmdlet, applying some filters to show information such as the last time the user had successfully logged in.

`Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LockedOut, LastLogonDate, DistinguishedName`

  

Additionally, a great way to quickly review the user accounts present on a domain, as well as their group membership, is by using the `Get-ADUser` cmdlet, demonstrated below:

Listing all users and their groups usingPowerShell

```powershell
PS C:\Users\Administrator\Desktop> Get-ADUser -Filter * -Properties MemberOf | Select-Object Name, SamAccountName, @{Name="Groups";Expression={$_.MemberOf}}

Name           SamAccountName Groups
----           -------------- ------
Administrator  Administrator  {CN=Group Policy Creator Owners,CN=Users,DC=wareville,DC=thm, CN=Domain Admins,CN=Users,DC=wareville,DC=thm, CN=Enterprise Admins,CN=Users,DC=wareville,DC=thm, CN=Schema ...
Guest          Guest          CN=Guests,CN=Builtin,DC=wareville,DC=thm
krbtgt         krbtgt         CN=Denied RODC Password Replication Group,CN=Users,DC=wareville,DC=thm
tryhackme      tryhackme      CN=Domain Admins,CN=Users,DC=wareville,DC=thm
DAVID          DAVID
James          James
NewAccount     NewAccount
cmnatic        cmnatic        {CN=Domain Admins,CN=Users,DC=wareville,DC=thm, CN=Remote Desktop Users,CN=Builtin,DC=wareville,DC=thm}
```

  

## Reviewing PowerShell History and Logs

PowerShell, like Bash on Linux, keeps a history of the commands inputted into the session. Reviewing these can be a fantastic way to see recent actions taken by the user account on the machine.

On a Windows Server, this history file  is located at `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

![[Active Directory-img-202512081118 8.png|Location of the PowerShell history file on the system.]]  

You can use the in-built Notepad on Windows or your favourite text editor to review the PowerShell command history.

![[Active Directory-img-202512081118 9.png|Contents of the PowerShell command logs.]]

Additionally, logs are recorded for every PowerShell process executed on a system. These logs are located within the Event Viewer under `Application and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational` or also under `Application and Service Logs -> Windows PowerShell`. The logs have a wealth of information useful for incident response.

![[Active Directory-img-202512081118 10.png|Event Viewer showing PowerShell logs recorded.]]

---
## Resources
- [THM: AD](https://tryhackme.com/module/hacking-active-directory)
- https://tryhackme.com/room/winadbasics

