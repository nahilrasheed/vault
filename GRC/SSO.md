**Single sign-on** (SSO) is a technology that combines several different logins into one.
1. **SSO improves the user experience** by eliminating the number of usernames and passwords people have to remember.
2. **Companies can lower costs** by streamlining how they manage connected services.
3. **SSO improves overall security** by reducing the number of access points attackers can target.

## How SSO works

SSO works by automating how trust is established between a user and a service provider. Rather than placing the responsibility on an employee or customer, SSO solutions use trusted third-parties to prove that a user is who they claim to be. This is done through the exchange of encrypted access tokens between the identity provider and the service provider.

Similar to other kinds of digital information, these access tokens are exchanged using specific protocols. SSO implementations commonly rely on two different authentication protocols: LDAP and SAML. LDAP, which stands for Lightweight Directory Access Protocol, is mostly used to transmit information on-premises; SAML, which stands for Security Assertion Markup Language, is mostly used to transmit information off-premises, like in the cloud.

**Note:** LDAP and SAML protocols are often used together.

Here's an example of how SSO can connect a user to multiple applications with one access token:
![[SSO-1764864850878.png]]
## Limitations of SSO

Usernames and passwords alone are not always the most secure way of protecting sensitive information. SSO provides useful benefits, but there’s still the risk associated with using one form of authentication. For example, a lost or stolen password could expose information across multiple services. Thankfully, there’s a solution to this problem.