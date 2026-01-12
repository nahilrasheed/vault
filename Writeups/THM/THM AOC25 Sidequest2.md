https://tryhackme.com/room/attacks-on-ecrypted-files-aoc2025-asdfghj123

```
ubuntu@tryhackme:~/Desktop/john/run$ ./keepass2john ~/.Passwords.kdbx > ~/hash.txt
ubuntu@tryhackme:~$ cat hash.txt 
.Passwords:$keepass$*4*20*ef636ddf*67108864*19*2*695a889e93e7279803646b988243060740965d661f0627256bc4da2bdd88da43*06c64226005acd9a116702b3248ae4191572df0293ee31ab4f2f7ccffebc2c68*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000695a889e93e7279803646b988243060740965d661f0627256bc4da2bdd88da430710000000958513b5c2c36a02c5e822d6b74ccb420b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c05010000004908000000140000000000000005010000004d08000000000000040000000004010000005004000000020000004201000000532000000006c64226005acd9a116702b3248ae4191572df0293ee31ab4f2f7ccffebc2c6804010000005604000000130000000000040000000d0a0d0a*41b1d7deecfba1baa64171a51f88ecc66e97e20056c6fb245ad13e7ff9b37ff1
```

```
ubuntu@tryhackme:~$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 256/256 AVX2])
Cost 1 (t (rounds)) is 20 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 2 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Failed to use huge pages (not pre-allocated via sysctl? that's fine)
harrypotter      (.Passwords)     
1g 0:00:01:05 DONE (2025-12-16 11:12) 0.01517g/s 1.457p/s 1.457c/s 1.457C/s harrypotter..ihateyou
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

`ubuntu@tryhackme:~$ keepassxc .Passwords.kdbx `

Enter the password in keepass application and select key and go to advanced and in attachements there ill be sq2.png

![[THM AOC25 Sidequest2-1765883626473.png]]