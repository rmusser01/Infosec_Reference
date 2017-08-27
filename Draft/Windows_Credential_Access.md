# Windows Credential Access


To Fill
	Cred dumping


## Account Manipulation
-------------------------------
[Account Manipulation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1098)
* Account manipulation may aid adversaries in maintaining access to credentials and certain permission levels within an environment. Manipulation could consist of modifying permissions, adding or changing permission groups, modifying account settings, or modifying how authentication is performed. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. 



## Brute Force
-------------------------------
[Brute Force - ATT&CK](https://attack.mitre.org/wiki/Technique/T1110)
* Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained. 

## Create Account
-------------------------------
[Create Account - ATT&CK](https://attack.mitre.org/wiki/Technique/T1136)
* Adversaries with a sufficient level of access may create a local system or domain account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system. The net user commands can be used to create a local or domain account. 



## Credential Dumping
-------------------------------
[Credential Dumping - ATT&CK](https://attack.mitre.org/wiki/Technique/T1003)
* Credential dumping is the process of obtaining account login and password information from the operating system and software. Credentials can be used to perform Lateral Movement and access restricted information. 

[Mimikatz Against Virtual Machine Memory Part 1 - carnal0wnage](http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html)




## Credentials in Files
-------------------------------
[Credentials in Files](https://attack.mitre.org/wiki/Technique/T1081)
* Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords. 



## Exploitation of Vulnerability
-------------------------------
[Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.



## Input Capture
-------------------------------
[Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception. 



## Network Sniffing
-------------------------------
[Network Sniffing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1040)
* Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. 



## Private Keys
-------------------------------
[Private Keys - ATT&CK](https://attack.mitre.org/wiki/Technique/T1145)
* Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.1 

[Public-key cryptography - Wikipedia](https://en.wikipedia.org/wiki/Public-key_cryptography)

## Two-Factor Authentication Interception
-------------------------------
[Two-Factor Authentication Interception](https://attack.mitre.org/wiki/Technique/T1111)
* Use of two- or multifactor authentication is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. Adversaries may target authentication mechanisms, such as smart cards, to gain access to systems, services, and network resources. 




