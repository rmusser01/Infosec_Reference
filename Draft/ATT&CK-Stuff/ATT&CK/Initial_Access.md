# Initial Access

* [MITRE ATT&CK - Initial Access](https://attack.mitre.org/wiki/Initial_Access)
	* The initial access tactic represents the vectors adversaries use to gain an initial foothold within a network.  

-------------------------------
## Drive-by-Compromise
* [Drive-by-Compromise - ATT&CK](https://attack.mitre.org/wiki/Technique/T1189)
	* A drive-by compromise is when an adversary gains access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is targeted for exploitation.  


-------------------------------
## Exploit Public-Facing Application
* [Exploit Public-Facing Application - ATT&CK](https://attack.mitre.org/wiki/Technique/T1190)
	* The use of software, data, or commands to take advantage of a weakness in an Internet-facing computer system or program in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. These applications are often websites, but can include databases (like SQL), standard services (like SMB or SSH), and any other applications with Internet accessible open sockets, such as web servers and related services. Depending on the flaw being exploited this may include Exploitation for Defense Evasion.



-------------------------------
## Hardware Additions
* [Drive-by-Compromise - ATT&CK](https://attack.mitre.org/wiki/Technique/T1200)
	* Computer accessories, computers or networking hardware may be introduced into a system as a vector to gain execution. While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access. Commercial and open source products are leveraged with capabilities such as passive network tapping, man-in-the middle encryption breaking, keystroke injection, kernel memory reading via DMA, adding new wireless access to an existing network, and others. 



-------------------------------
## Replication Through Removable Media
* [Replication Through Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1091)
	* Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.



-------------------------------
## Spearphishing Link
* [Spearphishing Link - ATT&CK](https://attack.mitre.org/wiki/Technique/T1189)
	* Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attachment malicious files to the email itself, to avoid defenses that may inspect email attachments.



-------------------------------
## Spearphishing via Service
* [Drive-by-Compromise - ATT&CK](https://attack.mitre.org/wiki/Technique/T1194)
	* Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels.
	* All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries will create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and software that's running in an environment. The adversary can then send malicious links or attachments through these services.
	* A common example is to build rapport with a target via social media, then send content to a personal webmail service that the target uses on their work computer. This allows an adversary to bypass some email restrictions on the work account, and the target is more likely to open the file since it's something they were expecting. If the payload doesn't work as expected, the adversary can continue normal communications and troubleshoot with the target on how to get it working. 


-------------------------------
## Supply Chain Compromise
* [Supply Chain Compromise - ATT&CK](https://attack.mitre.org/wiki/Technique/T1195)
	* Supply chain compromise is the manipulation of products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise can take place at any stage of the supply chain including: 
		* Manipulation of development tools
		* Manipulation of a development environment
		* Manipulation of source code repositories (public or private)
		* Manipulation of software update/distribution mechanisms
		* Compromised/infected system images (multiple cases of removable media infected at the factory)
		* Replacement of legitimate software with modified versions
		* Sales of modified/counterfeit products to legitimate distributors
		* Shipment interdiction


-------------------------------
## Trusted Relationship
* [Trusted Relationship - ATT&CK](https://attack.mitre.org/wiki/Technique/T1199)
	* Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.
	* Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, Valid Accounts used by the other party for access to internal network systems may be compromised and used. 


-------------------------------
## Valid Accounts
* [Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
	* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access.
	* Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.
	* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.
	* The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise

