Access Controls are security controls that manage access，authorization, and accountability of information.
## AAA framework 
- Authentication
- Authorization
- Audit (Accounting)
Authentication is concerned with proving identity, authorization with granting permissions, accounting with maintaining a continuous and robust audit trail via logging.
## Authentication
- The process of verifying that a user is who they claim to be.
- This typically involves requiring a user to provide credentials like a username and password, a multi-factor authentication method, or a biometric scan.
Factors:
1. Knowledge: something the user knows
2. Ownership: something the user possesses
3. Characteristic: something the user is
- [[SSO]]
## Authorization
-  The process of managing what an authenticated user is allowed to access and do on a network.
- Once a user is authenticated, authorization checks their permissions to see which resources, services, or data they can interact with.
Authorization controls are linked to two security principles: Principle of least privilege & separation of duties.
- PoLP, or the Principle of Least Privilege, is the principle that users, systems, and applications are granted only the minimum necessary access rights to perform their authorized functions.
- Separation of duties is the principle that users should not be given levels of authorization that would allow them to misuse a system.
## Accounting
- The process of tracking and logging user activities on the network.
- This involves collecting data on what users do, such as which resources they access, when they access them, and how long they use them. This information is vital for monitoring, auditing, and security analysis.
## IAM
**Identity and access management** (IAM) is a collection of processes and technologies that helps organizations manage digital identities in their environment. Both AAA and IAM systems are designed to authenticate users, determine their access privileges, and track their activities within a system.

Either model used by your organization is more than a single, clearly defined system. They each consist of a collection of security controls that ensure the _right user_ is granted access to the _right resources_ at the _right time_ and for the _right reasons_. Each of those four factors is determined by your organization's policies and processes.

## Access Control Frameworks
### Mandatory Access Control (MAC)
Authorization in this model is based on a strict need-to-know basis. Access to information must be granted manually by a central authority or system administrator. For example, MAC is commonly applied in law enforcement, military, and other government agencies where users must request access through a chain of command. MAC is also known as non-discretionary control because access isn’t given at the discretion of the data owner.
### Discretionary Access Control (DAC)
DAC is typically applied when a data owner decides appropriate levels of access. One example of DAC is when the owner of a Google Drive folder shares editor, viewer, or commentor access with someone else.
### Role-Based Access Control (RBAC)
RBAC is used when authorization is determined by a user's role within an organization. For example, a user in the marketing department may have access to user analytics but not network administration.
### Attribute Based Access Control (ABAC)
A dynamic access control model where permissions are determined by the characteristics of the user, resource, and environment.
Examples of attributes include a user's job title or department, the sensitivity of a file, or the time of day and location of an access attempt.
It offers more fine-grained and flexible control compared to older models like Role-Based Access Control (RBAC). 


---
- [IDPro](https://idpro.org/)© is a professional organization dedicated to sharing essential IAM industry knowledge.