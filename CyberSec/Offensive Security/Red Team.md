---
tags:
  - CyberSec
  - RedTeam
---
A _red team_ is a group of cybersecurity experts and penetration testers hired by an organization to mimic a real threat actor by exposing vulnerabilities and risks regarding technology, people, and physical security.

Red teaming is a term borrowed from the military. In military exercises, a group would take the role of a red team to simulate attack techniques to test the reaction capabilities of a defending team, generally known as **blue team**, against known adversary strategies. Translated into the world of cybersecurity, red team engagements consist of emulating a real threat actor's **Tactics, Techniques and Procedures (TTPs)** so that we can measure how well our blue team responds to them and ultimately improve any security controls in place.
### Red Team Engagements
Red team engagements also improve on regular penetration tests by considering several attack surfaces:

- **Technical Infrastructure:** Like in a regular penetration test, a red team will try to uncover technical vulnerabilities, with a much higher emphasis on stealth and evasion.
- **Social Engineering:** Targeting people through phishing campaigns, phone calls or social media to trick them into revealing information that should be private.
- **Physical Intrusion:** Using techniques like lockpicking, RFID cloning, exploiting weaknesses in electronic access control devices to access restricted areas of facilities.

Depending on the resources available, the red team exercise can be run in several ways:

- **Full Engagement:** Simulate an attacker's full workflow, from initial compromise until final goals have been achieved.
- **Assumed Breach:** Start by assuming the attacker has already gained control over some assets, and try to achieve the goals from there. As an example, the red team could receive access to some user's credentials or even a workstation in the internal network.
- **Table-top Exercise:**  An over the table simulation where scenarios are discussed between the red and blue teams to evaluate how they would theoretically respond to certain threats. Ideal for situations where doing live simulations might be complicated.

There are several factors and people involved within a red team engagement. Everyone will have their mindset and methodology to approach the engagement personnel; however, each engagement can be broken into three teams or cells. Below is a brief table illustrating each of the teams and a brief explanation of their responsibilities.

| Team       | Definition                                                                                                                                                                                                                                                                                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Red Cell   | A red cell is the component that makes up the offensive portion of a red team engagement that simulates a given target's strategic and tactical responses.                                                                                                                                                                                                   |
| Blue Cell  | The blue cell is the opposite side of red. It includes all the components defending a target network. The blue cell is typically comprised of blue team members, defenders, internal staff, and an organisation's management.                                                                                                                                |
| White Cell | Serves as referee between red cell activities and blue cell responses during an engagement. Controls the engagement environment/network. Monitors adherence to the ROE. Coordinates activities required to achieve engagement goals. Correlates red cell activities with defensive actions. Ensures the engagement is conducted without bias to either side. |
Roles and responsibilities of members of the red team.

|Role|Purpose|
|---|---|
|Red Team Lead|Plans and organises engagements at a high level—delegates, assistant lead, and operators engagement assignments.|
|Red Team Assistant Lead|Assists the team lead in overseeing engagement operations and operators. Can also assist in writing engagement plans and documentation if needed.|
|Red Team Operator|Executes assignments delegated by team leads. Interpret and analyse engagement plans from team leads.|

### Engagement Structure
A core function of the red team is adversary emulation. While not mandatory, it is commonly used to assess what a real adversary would do in an environment using their tools and methodologies. The red team can use various cyber kill chains to summarize and assess the steps and procedures of an engagement.

The blue team commonly uses cyber kill chains to map behaviors and break down an adversaries movement. The red team can adapt this idea to map adversary TTPs (**T**actics, **T**echniques, and **P**rocedures) to components of an engagement.

Many regulation and standardization bodies have released their cyber kill chain. Each kill chain follows roughly the same structure, with some going more in-depth or defining objectives differently. Below is a small list of standard cyber kill chains.

- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Unified Kill Chain](https://unifiedkillchain.com/)
- [Varonis Cyber Kill Chain](https://www.varonis.com/blog/cyber-kill-chain/)
- [Active Directory Attack Cycle](https://github.com/infosecn1nja/AD-Attack-Defense)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)


The Lockheed Martin kill chain focuses on a perimeter or external breach. Unlike other kill chains, it does not provide an in-depth breakdown of internal movement. You can think of this kill chain as a summary of all behaviors and operations present.

Components of the kill chain are broken down in the table below.

|Technique|	Purpose|	Examples|
| --- | --- |
|Reconnaissance|	Obtain information on the target	|Harvesting emails, OSINT|
|Weaponization|	Combine the objective with an exploit. Commonly results in a deliverable payload.|	Exploit with backdoor, malicious office document|
|Delivery	|How will the weaponized function be delivered to the target|	Email, web, USB|
|Exploitation|	Exploit the target's system to execute code	|MS17-010, Zero-Logon, etc.|
|Installation|	Install malware or other tooling	|Mimikatz, Rubeus, etc.|
|Command & Control	Control |the compromised asset from a remote central controller	|Empire, Cobalt Strike, etc.|
|Actions on Objectives|	Any end objectives: ransomware, data exfiltration, etc.|Conti, LockBit2.0, etc. |
