---
tags:
  - CyberSec
  - CiscoEH
  - NBBC
---
A **_directory traversal_** vulnerability (often referred to as _path traversal_ ) can allow attackers to access files and directories that are stored outside the web root folder.
Directory traversal has many names, including _dot-dot-slash_, _directory climbing_, and _backtracking_.

It is possible to exploit path traversal vulnerabilities by manipulating variables that reference files with the dot-dot-slash ( **../** ) sequence and its variations or by using absolute file paths to access files on the vulnerable system. An attacker can obtain critical and sensitive information when exploiting directory traversal vulnerabilities.

eg: `http://website.com/?page=../../../../../etc/passwd`
The vulnerable application shows the contents of the **/etc/passwd** file to the attacker.

It is possible to use URL encoding, as demonstrated in the following example to exploit directory (path) traversal vulnerabilities:
```
%2e%2e%2f is the same as ../
%2e%2e/ is the same as ../
..%2f is the same as ../
%2e%2e%5c is the same as ..
```
An attacker can also use several other combinations of encoding – for example, operating system-specific path structures such as **/** in Linux or macOS systems and in Windows.

The following are a few best practices for preventing and mitigating directory traversal vulnerabilities:
- Understand how the underlying operating system processes filenames provided by a user or an application.
- Never store sensitive configuration files inside the web root directory.
- Prevent user input when using file system calls.
- Prevent users from supplying all parts of the path. You can do this by surrounding the user input with your path code.
- Perform input validation by only accepting known good input.