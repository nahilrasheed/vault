## Encoding vs Encryption vs Hashing vs Obfuscation
## Encoding
Encoding transforms data into another format using a scheme _that is publicly available_ so that it can easily be reversed. It does not require a key as the only thing required to decode it is the algorithm that was used to encode it.
Examples: [ASCII](http://www.asciitable.com/?utm_source=danielmiessler.com&utm_medium=referral&utm_campaign=hashing-vs-encryption-vs-encoding-vs-obfuscation), [unicode](https://danielmiessler.com/study/encoding/#unicode), URL Encoding, [Base64](https://en.wikipedia.org/wiki/Base64?utm_source=danielmiessler.com&utm_medium=referral&utm_campaign=hashing-vs-encryption-vs-encoding-vs-obfuscation)
## Encryption
The purpose of _encryption_ is to transform data in order to keep it secret from others, e.g. sending someone a secret letter that only they should be able to read, or securely sending a password over the Internet. Rather than focusing on usability, the goal is to ensure the data cannot be consumed by anyone other than the intended recipient(s).

Encryption transforms data into another format in such a way that _only specific individual(s)_ can reverse the transformation. It uses a key, which is kept secret, in conjunction with the plaintext and the algorithm, in order to perform the encryption operation. As such, the ciphertext, algorithm, and key are all required to return to the plaintext.

Examples: [AES](https://www.aes.org/?utm_source=danielmiessler.com&utm_medium=referral&utm_campaign=hashing-vs-encryption-vs-encoding-vs-obfuscation), [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)?utm_source=danielmiessler.com&utm_medium=referral&utm_campaign=hashing-vs-encryption-vs-encoding-vs-obfuscation), [RSA](https://www.rsa.com/?utm_source=danielmiessler.com&utm_medium=referral&utm_campaign=hashing-vs-encryption-vs-encoding-vs-obfuscation)
### Types of encryption
There are two main types of encryption:
- **Symmetric encryption** is the use of a single secret key to exchange information. Because it uses one key for encryption and decryption, the sender and receiver must know the secret key to lock or unlock the cipher.
- **Asymmetric encryption** is the use of a public and private key pair for encryption and decryption of data. It uses two separate keys: a public key and a private key. The public key is used to encrypt data, and the private key decrypts it. The private key is only given to users with authorized access.
## Hashing
Hashing serves the purpose of ensuring _integrity_, i.e. making it so that if something is changed you can know that it’s changed. Technically, hashing takes arbitrary input and produce a fixed-length string that has the following attributes:
1. The same input will always produce the same output.
2. Multiple disparate inputs should not produce the same output.
3. It should not be possible to go from the output to the input.
4. Any modification of a given input should result in drastic change to the hash.

Hashing is used in conjunction with authentication to produce strong evidence that a given message has not been modified. This is accomplished by taking a given input, hashing it, and then signing the hash with the sender’s private key.
When the recipient opens the message, they can then validate the signature of the hash with the sender’s public key and then hash the message themselves and compare it to the hash that was signed by the sender. If they match it is an unmodified message, sent by the correct person.

Examples: [SHA-3](https://en.wikipedia.org/wiki/SHA-3), [MD5](https://en.wikipedia.org/wiki/MD5), etc.
## Obfuscation
The purpose of obfuscation is to make something harder to understand, usually for the purposes of making it more difficult to attack or to copy.

One common use is the the obfuscation of source code so that it’s harder to replicate a given product if it is reverse engineered.

It’s important to note that obfuscation is not a strong control (like properly employed encryption) but rather an obstacle. It, like encoding, can often be reversed by using the same technique that obfuscated it. Other times it is simply a manual process that takes time to work through.

Another key thing to realize about obfuscation is that there is a limitation to how obscure the code can become, depending on the content being obscured. If you are obscuring computer code, for example, the limitation is that the result must still be consumable by the computer or else the application will cease to function.

Examples: [JavaScript Obfuscator](https://javascriptobfuscator.com/?utm_source=danielmiessler.com&utm_medium=referral&utm_campaign=hashing-vs-encryption-vs-encoding-vs-obfuscation), [ProGuard](https://www.guardsquare.com/en/products/proguard?utm_source=danielmiessler.com&utm_medium=referral&utm_campaign=hashing-vs-encryption-vs-encoding-vs-obfuscation)

## Public Key Infrastructure (PKI)
Public key infrastructure, or PKI, is an encryption framework that secures the exchange of information online. It's a broad system that makes accessing information fast, easy, and secure.
PKI is a two-step process:
1. The exchange of encrypted information 
	It all starts with the exchange of encrypted information. This involves either asymmetric encryption, symmetric encryption, or both.
2. The establishment of trust using digital certificates between computers and networks.
	A digital certificate is a file that verifies the identity of a public key holder like a website, individual, organization, device, or server.
#### How digital certificates are created
Let's say an online business is about to launch their website, and they want to obtain a digital certificate. When they register their domain, the hosting company sends certain information over to a trusted certificate authority, or CA. The information provided is usually basic things like the company name and the country where its headquarters are located. 
A public key for the site is also provided. The certificate authority then uses this data to verify the company's identity. When it's confirmed, the CA encrypts the data with its own private key. Finally, they create a digital certificate that contains the encrypted company data. It also contains CA's digital signature to prove that it's authentic.

## Encryption algorithms
Many web applications use a combination of symmetric and asymmetric encryption. This is how they balance user experience with safeguarding information. As an analyst, you should be aware of the most widely-used algorithms.
### Symmetric algorithms
- _Triple DES (3DES)_ is known as a block cipher because of the way it converts plaintext into ciphertext in “blocks.” Its origins trace back to the Data Encryption Standard (DES), which was developed in the early 1970s. DES was one of the earliest symmetric encryption algorithms that generated 64-bit keys, although only 56 bits are used for encryption. A **bit** is the smallest unit of data measurement on a computer. As you might imagine, Triple DES generates keys that are three times as long. Triple DES applies the DES algorithm three times, using three different 56-bit keys. This results in an effective key length of 168 bits. Despite the longer keys, many organizations are moving away from using Triple DES due to limitations on the amount of data that can be encrypted. However, Triple DES is likely to remain in use for backwards compatibility purposes.   
- _Advanced Encryption Standard (AES)_ is one of the most secure symmetric algorithms today. AES generates keys that are 128, 192, or 256 bits. Cryptographic keys of this size are considered to be safe from brute force attacks. It’s estimated that brute forcing an AES 128-bit key could take a modern computer billions of years!
### Asymmetric algorithms
- _Rivest Shamir Adleman (RSA)_ is named after its three creators who developed it while at the Massachusetts Institute of Technology (MIT). RSA is one of the first asymmetric encryption algorithms that produces a public and private key pair. Asymmetric algorithms like RSA produce even longer key lengths. In part, this is due to the fact that these functions are creating two keys. RSA key sizes are 1,024, 2,048, or 4,096 bits. RSA is mainly used to protect highly sensitive data.
- _Digital Signature Algorithm (DSA)_ is a standard asymmetric algorithm that was introduced by NIST in the early 1990s. DSA also generates key lengths of 2,048 bits. This algorithm is widely used today as a complement to RSA in public key infrastructure.
### Generating keys
These algorithms must be implemented when an organization chooses one to protect their data. One way this is done is using [[OpenSSL]], which is an open-source command line tool that can be used to generate public and private keys. OpenSSL is commonly used by computers to verify digital certificates that are exchanged as part of public key infrastructure.
## Obscurity is not security
In the world of cryptography, a cipher must be proven to be unbreakable before claiming that it is secure. According to [Kerckhoff’s principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle), cryptography should be designed in such a way that all the details of an algorithm—except for the private key—should be knowable without sacrificing its security. For example, you can access all the details about how AES encryption works online and yet it is still unbreakable.

Occasionally, organizations implement their own, custom encryption algorithms. There have been instances where those secret cryptographic systems have been quickly cracked after being made public.
>[!tip]
>A cryptographic system _should not_ be considered secure if it requires secrecy around how it works.

## Hash Functions
**Hash functions** are algorithms that produce a code that can't be decrypted.

Hash functions have been around since the early days of computing. They were originally created as a way to quickly search for data. Since the beginning, these algorithms have been designed to represent data of any size as small, fixed-size values, or digests. Using a hash table, which is a data structure that's used to store and reference hash values, these small values became a more secure and efficient way for computers to reference data.

One of the earliest hash functions is Message Digest 5, more commonly known as MD5. Professor Ronald Rivest of the Massachusetts Institute of Technology (MIT) developed MD5 in the early 1990s as a way to verify that a file sent over a network matched its source file.
Whether it’s used to convert a single email or the source code of an application, MD5 works by converting data into a 128-bit value. You might recall that a **bit** is the smallest unit of data measurement on a computer. Bits can either be a 0 or 1. In a computer, bits represent user input in a way that computers can interpret. In a hash table, this appears as a string of 32 characters. Altering anything in the source file generates an entirely new hash value.
Generally, the longer the hash value, the more secure it is. It wasn’t long after MD5's creation that security practitioners discovered 128-bit digests resulted in a major vulnerability.
### Hash collisions
One of the flaws in MD5 happens to be a characteristic of all hash functions. Hash algorithms map any input, regardless of its length, into a fixed-size value of letters and numbers. What’s the problem with that? Although there are an infinite amount of possible inputs, there’s only a finite set of available outputs!
MD5 values are limited to 32 characters in length. Due to the limited output size, the algorithm is considered to be vulnerable to **hash collision**, an instance when different inputs produce the same hash value. Because hashes are used for authentication, a hash collision is similar to copying someone’s identity. Attackers can carry out collision attacks to fraudulently impersonate authentic data.
### Next-generation hashing
To avoid the risk of hash collisions, functions that generated longer values were needed. MD5's shortcomings gave way to a new group of functions known as the Secure Hashing Algorithms, or SHAs.
The National Institute of Standards and Technology (NIST) approves each of these algorithms. Numbers besides each SHA function indicate the size of its hash value in bits. Except for SHA-1, which produces a 160-bit digest, these algorithms are considered to be collision-resistant. However, that doesn’t make them invulnerable to other exploits.
Five functions make up the SHA family of algorithms:
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512

