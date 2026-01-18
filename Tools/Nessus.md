---
tags:
  - CyberSec/tools
---
- Vulnerabilty Scanner from Tenable 
- has several features that allow you to perform continuous monitoring and compliance analysis. 
- Nessus can be downloaded from [_https://www.tenable.com/downloads/nessus_](https://www.tenable.com/downloads/nessus).

**NOTE** Tenable also has a cloud-based solution called Tenable.io. For information about Tenable.io, see [_https://www.tenable.com/products/tenable-io_](https://www.tenable.com/products/tenable-io).

- to install download nessus file, `dpkg -i [nessus file]`
- to start: `/etc/init.d/nessusd start`
- *You can start Nessus Scanner by typing `/bin/systemctl start nessusd.service`*
- Then go to https://kali:8834/ to configure your scanner
- signup and login

- create a basic scan
	- give name and discription
	- set target ip
	- set scan type in discovery (ports)
	- set scan type in assessment (vulnerabilties)
	- save and launch
