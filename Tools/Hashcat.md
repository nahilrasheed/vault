---
tags:
  - CyberSec/tools
---
- "World's fastest password cracker"
- used to crack hashes
It allows you to use graphical processing units (GPUs) to accelerate the password-cracking process.
- Hashcat comes with Kali Linux and other penetration testing Linux distributions. You can also download it from [_https://hashcat.net/hashcat_](https://hashcat.net/hashcat).


> [!tip] Basic usage
> ```bash
hashcat -m 0 [hashes] [dictionary]
>```
- -m specifies hash type
	- 0 - md5 
- -a specifies attack mode
	- 0 = Straight
	- 1 = Combination
	- 3 = Brute-force
	- 6 = Hybrid Wordlist + Mask
	- 7 = Hybrid Mask + Wordlist
- -o specifies the output file

eg: `hashcat -m 0 -a 0 -o cracked.txt hashes.txt /usr/share/wordlist/rockyou.txt`