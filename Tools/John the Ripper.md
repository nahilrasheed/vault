---
tags:
  - CyberSec/tools
  - CiscoEH
---
John the Ripper is a free and open-source password-cracking tool. It can crack passwords stored in various formats, including hashes, passwords, and encrypted private keys. It can be used to test passwords' security and recover lost passwords.
 
- It supports different cracking modes and understands many ciphertext formats, including several DES variants, MD5, and Blowfish. John the Ripper does not support AES and SHA-2. John the Ripper can also be used to extract Kerberos AFS and Windows passwords. 
- To list the supported formats, you can use the **john --list=formats** command
- John the Ripper can be downloaded from [_https://www.openwall.com/john_](https://www.openwall.com/john).
 

> [!tip] Usage
> `john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt`

- `--format=[]` specifies the hash format. eg: raw-sha256, raw-md5
- `--wordlist=[]` sets the wordlist that we will use
- `hash1.txt` is the text file containing the hash value we are trying to crack
- `--incremental` to instruct John the Ripper to use only brute force cracking
John the Ripper switches to incremental strategies (brute force) on remaining hashes if there are hashes it cannot crack with its wordlists.

To show your cracked passwords: `john --show [--format=raw-md5] my_pw_hashes.txt`
## Rules
John can start from a long password list and attempt various common derivations from each of the passwords to increase its chances of success. This behaviour can be triggered through the use of **rules**. Various rules come bundled with John the Ripper’s configuration files; one is suited for lengthy wordlists, `--rules=wordlist`.

Adding the option `--rules=wordlist` to your `john` command line generates multiple passwords from each one. For instance, it appends and prepends single digits. It does various common substitutions; for example, `a` can be replaced with `@`, `i` can be replaced with `!`, and `s` can be replaced with `$`. Many more mutations and transformations are part of these rules. You can check all the underlying rules by checking the `[List.Rules:Wordlist]` section in `/etc/john/john.conf`, John’s configuration file.

`john --format=raw-sha256 --rules=wordlist --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt`
## Formatting
To crack the password of other file types, we need to convert the password-protected file into a format that `john` can attack.
John the Ripper jumbo edition comes with the necessary tools. 
The different tools follow the naming style “format2john”. The terminal below shows a few examples.
```bash
/opt/john/1password2john.py /opt/john/ethereum2john.py /opt/john/openssl2john.py /opt/john/7z2john.pl /opt/john/filezilla2john.py /opt/john/padlock2john.py /opt/john/DPAPImk2john.py /opt/john/geli2john.py /opt/john/pcap2john.py /opt/john/adxcsouf2john.py /opt/john/gpg2john /opt/john/pdf2john.pl /opt/john/aem2john.py /opt/john/hccap2john /opt/john/pdf2john.py /opt/john/aix2john.pl /opt/john/hccapx2john.py /opt/john/pem2john.py /opt/john/aix2john.py /opt/john/htdigest2john.py /opt/john/pfx2john.py
```

eg: 
- to crack pdf files : `pdf2john.pl private.pdf > pdf.hash`
- to crack zip files : `zip2john file.zip > ziphash.txt`
---

- You can customize John the Ripper to allow you to build different configurations. The configuration file can be named either john.conf on Unix and Linux-based systems or john.ini on Windows. For additional information about John the Ripper customization and configuration files, see [_https://www.openwall.com/john/doc/CONFIG.shtml_](https://www.openwall.com/john/doc/CONFIG.shtml). The configuration file can include a set of rules, including rules regarding the use of wordlists. The rules syntax can be obtained from [_https://www.openwall.com/john/doc/RULES.shtml_](https://www.openwall.com/john/doc/RULES.shtml).

- John the Ripper also keeps a log in the private john "home directory" for the current user ( **~.john** ).

- There is a GUI version of John the Ripper called Johnny.