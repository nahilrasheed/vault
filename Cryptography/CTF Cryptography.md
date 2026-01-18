[[Cryptography]]
## Binary

![[CTF Cryptography-img-202510091530.png]]

Binary basics : https://learn.sparkfun.com/tutorials/binary

Base64 basics : https://levelup.gitconnected.com/an-introduction-to-base64-encoding-716cdccc58ce

## Historical encoding
- Semaphore flag signals
![[CTF Cryptography-img-202510091530.webp]]
- Morse Code
![[CTF Cryptography-img-202510091530 3.webp]]
https://morsecode.world/international/translator.html
- Braille
![[CTF Cryptography-img-202510091530 3 1.webp]]
- Maritime Signal Flags
https://en.wikipedia.org/wiki/International_maritime_signal_flags
![[CTF Cryptography-img-202510091530 2.png]]

## Cipher
Caeser Cipher
Left shift 3 
```bash
cat cipher.txt | tr "d-za-cD-ZA-C" "a-zA-Z"
```
The tr command translates text from one set of characters to another, using a mapping. The first parameter to the tr command represents the input set of characters, and the second represents the output set of characters. Hence, if you provide parameters “abcd” and “pqrs”, and the input string to the tr command is “ac”, the output string will be “pr".

---
- https://www.dcode.fr/cipher-identifier
- https://www.boxentriq.com/code-breaking/caesar-cipher
- https://www.dummies.com/article/home-auto-hobbies/games/puzzles/cryptograms/cryptography-101-basic-solving-techniques-for-substitution-ciphers-195424/
- https://www.boxentriq.com/code-breaking/vigenere-cipher
- https://ctf101.org/cryptography/what-is-xor/