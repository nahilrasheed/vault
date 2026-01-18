---
tags:
  - CyberSec/tools
---
Veil is a framework that can be used with Metasploit to evade antivirus checks and other security controls. 
You can download Veil from [_https://github.com/Veil-Framework/Veil_](https://github.com/Veil-Framework/Veil) and obtain detailed documentation from [_https://github.com/Veil-Framework/Veil/wiki_](https://github.com/Veil-Framework/Veil/wiki).

## Usage
### **Step 1. Launch Veil**
After using the veil command to launch Veil, the Veil menu is displayed
![[b12baa058a835fcc05da4fa3468f176f7ed2ee17.png]]
### **Step 2. Select Evasion**
To use Veil for evasion, select the first option (number 1). Veil then shows the available payloads and Veil commands.
![[b32e73c419d9ae5ea743ab96185107203b4481d2.png]]
### **Step 3. List the Payloads**
To list the available payloads, use the **list** command, and you see the screen in Figure.
![[f47da85c79e930eed5192999063e7649b8af94b1.png]]
### **Step 4. Install a Payload**
In Figure, the Meterpreter reverse TCP payload is used. After you select the payload, you have to set the local host (LHOST) and then use the **generate** command to generate the payload.
Figure  shows the default Python installer being used to generate the payload. 
**Figure ** - Configuring the LHOST and Generating the Payload_
![[fc735a95e9c0aa1391b88e4c1b86f78966258760.png]]
### **Step 5. Verify Payload File Location**
Once the payload is generated, the screen shown in Figure is displayed. The top portion of Figure lists the locations of the payload executable, the source code, and the Metasploit resource file.
![[516a9b8211cb2b922cc14fc64faff449b608305f.png]]

