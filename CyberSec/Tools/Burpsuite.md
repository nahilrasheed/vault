---
tags:
  - CyberSec/tools
---
A **_web proxy_** is a piece of software that is typically installed in the attacker’s system to intercept, modify, or delete transactions between a web browser and a web application.

Burp Suite is an integrated platform for performing security testing of web applications. It includes various tools for scanning, fuzzing, intercepting, and analysing web traffic. It is used by security professionals worldwide to find and exploit vulnerabilities in web applications.
- also an network proxy
- to setup
	- Firefox/Preferences/General/Network Proxy/Settings/Manual proxy configuration -> http proxy: 127.0.0.1:8080 / ✅ use this proxy server for all protocols
	- go to https://burp and download the CA certificate and install in firefox.(preferences/privacy and security/Certificates/view/import/select cert )