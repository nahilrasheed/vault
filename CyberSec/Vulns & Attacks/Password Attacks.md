Entering a username and password is one of the most popular forms of authenticating to a web site. Therefore, uncovering your password is an easy way for cybercriminals to gain access to your most valuable information.
A **password attack** is an attempt to access password-secured devices, systems, networks, or data.
Password attacks fall under the communication and network security domain. 
- [[Hashcat]]
- [[John the Ripper]]
### Password spraying
This technique attempts to gain access to a system by ‘spraying’ a few commonly used passwords across a large number of accounts.
This technique allows the perpetrator to remain undetected as they avoid frequent account lockouts.
### Dictionary attacks
A hacker systematically tries every word in a dictionary or a list of commonly used words as a password in an attempt to break into a password-protected account.
### Brute-force attacks
The simplest and most commonly used way of gaining access to a password-protected site, brute-force attacks see an attacker using all possible combinations of letters, numbers and symbols in the password space until they get it right.
### Rainbow attacks
Passwords in a computer system are not stored as plain text, but as hashed values (numerical values that uniquely identify data). A rainbow table is a large dictionary of precomputed hashes and the passwords from which they were calculated.
Unlike a brute-force attack that has to calculate each hash, a rainbow attack compares the hash of a password with those stored in the rainbow table. When an attacker finds a match, they identify the password used to create the hash.
[[rainbowcrack|Using Rainbow tables with rainbowcrack]]
### Traffic interception
Plain text or unencrypted passwords can be easily read by other humans and machines by intercepting communications.
If you store a password in clear, readable text, anyone who has access to your account or device, whether authorized or unauthorized, can read it.
### Cracking Times
Carrying out brute-force attacks involves the attacker trying several possible combinations in an attempt to guess the password. These attacks usually involve a word-list file — a text file containing a list of words from a dictionary. A program such as Ophcrack, L0phtCrack, THC Hydra, RainbowCrack or Medusa will then try each word and common combinations until it finds a match.
Because brute-force attacks take time, complex passwords take much longer to guess.
