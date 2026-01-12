Creds
mcskidy : AoC2025! 
eddi_knapp : S0mething1Sc0ming

hint from day 1 : Once you have the final flag, use it to unlock the hidden png. Where is it? That's a .secret!


---

root@tbfc-web01:/home/mcskidy/Documents$ cat read-me-please.txt
```
From: mcskidy
To: whoever finds this

I had a short second when no one was watching. I used it.

I've managed to plant a few clues around the account.
If you can get into the user below and look carefully,
those three little "easter eggs" will combine into a passcode
that unlocks a further message that I encrypted in the
/home/eddi_knapp/Documents/ directory.
I didn't want the wrong eyes to see it.

Access the user account:
username: eddi_knapp
password: S0mething1Sc0ming

There are three hidden easter eggs.
They combine to form the passcode to open my encrypted vault.

Clues (one for each egg):

1)
I ride with your session, not with your chest of files.
Open the little bag your shell carries when you arrive.

2)
The tree shows today; the rings remember yesterday.
Read the ledger’s older pages.

3)
When pixels sleep, their tails sometimes whisper plain words.
Listen to the tail.

Find the fragments, join them in order, and use the resulting passcode
to decrypt the message I left. Be careful — I had to be quick,
and I left only enough to get help.
```


---
in ~/.bashrc
export PASSFRAG1="3ast3r"

in eddi_knapp@tbfc-web01:~/.secret_git$ 
git log
git checkout d12875c8b62e089320880b9b7e41d6765818af3d
cat secret_note.txt
PASSFRAG2: -1s-

eddi_knapp@tbfc-web01:~$ cat Pictures/.easter_egg
...
PASSFRAG3: c0M1nG


Passcode: 3ast3r-1s-c0M1nG

---

root@tbfc-web01:/home/eddi_knapp/Documents$  gpg --output mcskidy --decrypt mcskidy_note.txt.gpg

root@tbfc-web01:/home/eddi_knapp/Documents$ cat mcskidy
```
Congrats — you found all fragments and reached this file.

Below is the list that should be live on the site. If you replace the contents of
/home/socmas/2025/wishlist.txt with this exact list (one item per line, no numbering),
the site will recognise it and the takeover glitching will stop. Do it — it will save the site.

Hardware security keys (YubiKey or similar)
Commercial password manager subscriptions (team seats)
Endpoint detection & response (EDR) licenses
Secure remote access appliances (jump boxes)
Cloud workload scanning credits (container/image scanning)
Threat intelligence feed subscription

Secure code review / SAST tool access
Dedicated secure test lab VM pool
Incident response runbook templates and playbooks
Electronic safe drive with encrypted backups

A final note — I don't know exactly where they have me, but there are *lots* of eggs
and I can smell chocolate in the air. Something big is coming.  — McSkidy

---

When the wishlist is corrected, the site will show a block of ciphertext. This ciphertext can be decrypted with the following unlock key:

UNLOCK_KEY: 91J6X7R4FQ9TQPM9JX2Q9X2Z

To decode the ciphertext, use OpenSSL. For instance, if you copied the ciphertext into a file /tmp/website_output.txt you could decode using the following command:

cat > /tmp/website_output.txt
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -in /tmp/website_output.txt -out /tmp/decoded_message.txt -pass pass:'91J6X7R4FQ9TQPM9JX2Q9X2Z'
cat /tmp/decoded_message.txt

Sorry to be so convoluted, I couldn't risk making this easy while King Malhare watches. — McSkidy

```
---

Follow above instructions and visit the webpage to get ciphertext : http://10.48.172.161:8080/

```
U2FsdGVkX1/7xkS74RBSFMhpR9Pv0PZrzOVsIzd38sUGzGsDJOB9FbybAWod5HMsa+WIr5HDprvK6aFNYuOGoZ60qI7axX5Qnn1E6D+BPknRgktrZTbMqfJ7wnwCExyU8ek1RxohYBehaDyUWxSNAkARJtjVJEAOA1kEOUOah11iaPGKxrKRV0kVQKpEVnuZMbf0gv1ih421QvmGucErFhnuX+xv63drOTkYy15s9BVCUfKmjMLniusI0tqs236zv4LGbgrcOfgir+P+gWHc2TVW4CYszVXlAZUg07JlLLx1jkF85TIMjQ3B91MQS+btaH2WGWFyakmqYltz6jB5DOSCA6AMQYsqLlx53ORLxy3FfJhZTl9iwlrgEZjJZjDoXBBMdlMCOjKUZfTbt3pnlHWEaGJD7NoTgywFsIw5cz7hkmAMxAIkNn/5hGd/S7mwVp9h6GmBUYDsgHWpRxvnjh0s5kVD8TYjLzVnvaNFS4FXrQCiVIcp1ETqicXRjE4T0MYdnFD8h7og3ZlAFixM3nYpUYgKnqi2o2zJg7fEZ8c=
```

root@tbfc-web01:~$ openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -in website_output.txt -out decoded_message.txt -pass pass:'91J6X7R4FQ9TQPM9JX2Q9X2Z'

root@tbfc-web01:~$ cat decoded_message.txt
```
Well done — the glitch is fixed. Amazing job going the extra mile and saving the site. Take this flag THM{w3lcome_2_A0c_2025}

NEXT STEP:
If you fancy something a little...spicier....use the FLAG you just obtained as the passphrase to unlock:
/home/eddi_knapp/.secret/dir

That hidden directory has been archived and encrypted with the FLAG.
Inside it you'll find the sidequest key.


```


---

root@tbfc-web01:/home/eddi_knapp/.secret$ gpg --output dir.tar.gz --decrypt dir.tar.gz.gpg
give passphrase and youl get decrypted dir.tar.gz

root@tbfc-web01:/home/eddi_knapp/.secret$ tar xvzf dir.tar.gz
dir/
dir/sq1.png

from local machine:
```
 scp eddi_knapp@10.48.172.161:~/.secret/dir/sq1.png ~/temp
```

![[THM AOC25 Sidequest1-1765654805659.png]]

---

secret key to access https://tryhackme.com/room/sq1-aoc2025-FzPnrt2SAu 
go to http://10.48.145.171:21337/
and enter : now_you_see_me

---

```
nmap 10.48.145.171
Starting Nmap 7.92 ( https://nmap.org ) at 2025-12-13 22:48 +03
Nmap scan report for 10.48.145.171
Host is up (0.14s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
8000/tcp  open     http-alt
8080/tcp  open     http-proxy
9001/tcp  open     tor-orport
32769/tcp filtered filenet-rpc

Nmap done: 1 IP address (1 host up) scanned in 17.42 seconds
```

Also 13400, 13401, 13402, 13403, 13404

---

access the control panel at http://10.48.145.171:8080/

paste in console 
```
document.getElementById('loginWindow').style.display = 'none';
document.getElementById('mapScreen').style.display = 'block';
```

---

Pressing the key on 'Cells/Storage', you get flag1 : THM{h0pp1ing_m4d}
