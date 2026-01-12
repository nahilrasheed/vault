---
tags:
  - CyberSec/tools
  - CiscoEH
---
Rainbow crack differs from hash cracking utilities that use brute force algorithms in that it uses rainbow tables to crack password hashes.
You can download RainbowCrack from [_http://project-rainbowcrack.com_](http://project-rainbowcrack.com/).
 
- Rainbow tables are precomputed tables for reversing cryptographic hash functions.  It is possible to use a rainbow table to derive a password by looking at the hashed value.
- Rainbow tables are ordinary files and can be created with RainbowCrack, or they can be downloaded from the internet. Creating a rainbow table can take a considerable amount of time and storage space as they are very large, ranging in size from 20GB to more than a terabyte.
## Usage
1. Create a small simple rainbow table that will crack MD5 passwords of up to 3 characters with only lowercase letters.
	The **rtgen** program is used to generate rainbow tables based on user specified parameters.
	1. Enter the `rtgen -h` command and review the options.
		The example rainbow tables are given at the bottom of the output.
	2. Create a rainbow table by entering:
		`sudo rtgen md5 loweralpha 1 3 0 1000 1000 0`
		This command creates a rainbow table that can crack passwords that are three characters long and only consist of lower-case letters. The application created a fille with 1000 entries. Creating more complex rainbow tables can take significant time and use significant resources.
2. Verify the rainbow table is created. Display the contents of the rainbowcrack directory by entering the command:
	`cd /usr/share/rainbowcrack && ls`
	The newly created rainbow table should be in the directory as an **.rt** file.

### Step 3: Sort the rainbow table.
1. Next, the rainbow table must be sorted. (**Note**: be sure to include the space and the period after **rtsort** as part of the command)
	`sudo rtsort .`
2. Generate a hash for a simple 3-character password which can then be cracked. Enter the command:
	`echo -n 'dog' | md5sum | awk '{print $1}'`
	`06d80eb0c50b49a509b49f2424e8c805`
3. Crack the hash with the rainbow table with RainbowCrack. At the prompt, enter the **rcrack . -h 06d80eb0c50b49a509b492424e8c805** command.
	`rcrack . -h 06d80eb0c50b49a509b492424e8c805`
	Within milliseconds RainbowCrack should crack the hash and reveal the password **dog**.
4. You can also crack hashes contained in a .txt file .
	To crack the hashes in the file, enter the `rcrack . -l ~/my_rainbow_hashes.txt` command at the prompt. The **-l** option tells rcrack to use a hash list file as input.