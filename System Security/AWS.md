Amazon Web Services (AWS) is a comprehensive cloud computing platform offered by Amazon. It provides a wide range of services such as computing power, storage, databases, networking, analytics, and more, delivered over the internet on a pay-as-you-go basis.
## AWS CLI
The  AWS  Command  Line  Interface is a unified tool to manage your AWS services.

AWS accounts can be accessed programmatically by using an Access Key ID and a Secret Access Key.

Amazon Security Token Service (STS) allows us to utilise the credentials of a user that we have saved during our AWS CLI configuration. We can use the `get-caller-identity` call to retrieve information about the user we have configured for the AWS CLI : `aws sts get-caller-identity`

## AWS IAM 
Amazon Web Services utilises the Identity and Access Management (IAM) service to manage users and their access to various resources, including the actions that can be performed against those resources. Therefore, it is crucial to ensure that the correct access is assigned to each user according to the requirements. Misconfiguring IAM has led to several high-profile security incidents in the past, giving attackers access to resources they were not supposed to access.
### IAM Users
A user represents a single identity in AWS. Each user has a set of credentials, such as passwords or access keys, that can be used to access resources. Furthermore, permissions can be granted at a user level, defining the level of access a user might have.
### IAM Groups
Multiple users can be combined into a group. This can be done to ease the access management for multiple users. For example, in an organisation employing hundreds of thousands of people, there might be a handful of people who need write access to a certain database. Instead of granting access to each user individually, the admin can grant access to a group and add all users who require write access to that group. When a user no longer needs access, they can be removed from the group.
### IAM Roles
An IAM Role is a temporary identity that can be assumed by a user, as well as by services or external accounts, to get certain permissions. 
### IAM Policies
Access provided to any user, group or role is controlled through IAM policies. A policy is a JSON document that defines the following:
- What action is allowed (Action)
- On which resources (Resource)
- Under which conditions (Condition)
- For whom (Principal)
Policies can be inline or attached. Inline policies are assigned directly in the user (or group/role) profile and hence will be deleted if the identity is deleted. These can be considered as hard-coded policies as they are hard-coded in the identity definitions. Attached policies, also called managed policies, can be considered reusable. An attached policy requires only one change in the policy, and every identity that policy is attached to will inherit that change automatically.

Using aws iam in aws cli:
- enumerating users : `aws iam list-users`
- list user's inline policies : `aws iam list-user-policies --user-name <UserName>`
- list user's attached policies : `aws iam list-attached-user-policies --user-name <UserName>`
- get user's policy details : `aws iam get-user-policy --policy-name <POLICYNAME> --user-name <UserName>` 
- list roles : `aws iam list-roles`
- list role's inline policies : `aws iam list-role-policies --role-name <RoleName>`
- list role's inline policies : `aws iam list-attached-role-policies --role-name <RoleName>`
- get role policy details : `aws iam get-role-policy --role-name <RoleName> --policy-name <POLICYNAME>`

To assume a role we can use AWS STS to obtain the temporary credentials
- `aws sts assume-role --role-arn <RoleARN> --role-session-name <SESSIONNAME>`
This command will ask STS, the service in charge of AWS security tokens, to generate a temporary set of credentials to assume the specified role. The temporary credentials will be referenced by the session-name (you can set any name you want for the session).

The output will provide us the credentials we need to assume this role, specifically the AccessKeyID, SecretAccessKey and SessionToken. To be able to use these, run the following commands in the terminal, replacing with the exact credentials that you received on running the assume-role command.
```bash
user@machine$ export AWS_ACCESS_KEY_ID="ASIAxxxxxxxxxxxx"  
user@machine$ export AWS_SECRET_ACCESS_KEY="abcd1234xxxxxxxxxxxx"  
user@machine$ export AWS_SESSION_TOKEN="FwoGxxxxxx"
```
Once we have done that, we can officially use the permissions granted by the specified role. To check if you have correctly assumed the role, run:  `aws sts get-caller-identity`

## S3
Amazon S3 stands for **Simple Storage Service**. It is an object storage service provided by Amazon Web Services that can store any type of object such as images, documents, logs and backup files in a scalable and reliable way.
Companies often use S3 to store data for various reasons, such as reference images for their website, documents to be shared with clients, or files used by internal services for internal processing. 
Data is stored on buckets, which act as a folder in the cloud where you can store files, applications, backup information or anything you need.

- Listing Contents From a Bucket : `aws s3api list-buckets`
- check out the contents of bucket : `aws s3api list-objects --bucket <bucketname>`
- copy a file from a bucket to our local machine : `aws s3api get-object --bucket <bucketname> --key <cloudfilename> <local_filename>`

---

ARN => Amazon Resource Name