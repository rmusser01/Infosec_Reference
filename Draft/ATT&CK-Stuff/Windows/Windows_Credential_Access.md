# Windows Credential Access


To Fill
	Cred dumping
	Brute force/Cracking hashes


## Account Manipulation
-------------------------------
[Account Manipulation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1098)
* Account manipulation may aid adversaries in maintaining access to credentials and certain permission levels within an environment. Manipulation could consist of modifying permissions, adding or changing permission groups, modifying account settings, or modifying how authentication is performed. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. 

[Modify permissions or delete authorized users - technet](https://technet.microsoft.com/en-us/library/cc753706(v=ws.11).aspx)

[Managing User Accounts - msdn](https://msdn.microsoft.com/en-us/library/cc505882.aspx)

[Set, View, Change, or Remove Permissions on Files and Folders - technet](https://technet.microsoft.com/en-us/library/cc754344(v=ws.11).aspx)
* When a file or folder is created, Windows assigns default permissions to that object. 

[Net user - technet](https://technet.microsoft.com/en-us/library/cc771865(v=ws.11).aspx)
* Adds or modifies user accounts, or displays user account information.

[Create admin user from command line - superuser](https://superuser.com/questions/515175/create-admin-user-from-command-line)

[User Rights Assignment - technet](https://technet.microsoft.com/en-us/library/dn221963(v=ws.11).aspx)
* This reference topic for the IT professional provides an overview and links to information about the User Rights Assignment security policy settings user rights that are available in the Windows operating system.





## Brute Force
-------------------------------
[Brute Force - ATT&CK](https://attack.mitre.org/wiki/Technique/T1110)
* Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained. 







## Create Account
-------------------------------
[Create Account - ATT&CK](https://attack.mitre.org/wiki/Technique/T1136)
* Adversaries with a sufficient level of access may create a local system or domain account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system. The net user commands can be used to create a local or domain account. 

[Net user - technet](https://technet.microsoft.com/en-us/library/cc771865(v=ws.11).aspx)
* Adds or modifies user accounts, or displays user account information.





## Credential Dumping
-------------------------------
[Credential Dumping - ATT&CK](https://attack.mitre.org/wiki/Technique/T1003)
* Credential dumping is the process of obtaining account login and password information from the operating system and software. Credentials can be used to perform Lateral Movement and access restricted information. 

[Mimikatz Against Virtual Machine Memory Part 1 - carnal0wnage](http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html)

[CredCrack](https://github.com/gojhonny/CredCrack)
* CredCrack is a fast and stealthy credential harvester. It exfiltrates credentials recusively in memory and in the clear. Upon completion, CredCrack will parse and output the credentials while identifying any domain administrators obtained. CredCrack also comes with the ability to list and enumerate share access and yes, it is threaded! CredCrack has been tested and runs with the tools found natively in Kali Linux. CredCrack solely relies on having PowerSploit's "Invoke-Mimikatz.ps1" under the /var/www directory.









## Credentials in Files
-------------------------------
[Credentials in Files](https://attack.mitre.org/wiki/Technique/T1081)
* Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords. 

[grepwin](https://sourceforge.net/projects/grepwin/)
* grepWin is a simple search and replace tool which can use regular expressions to do its job. This allows to do much more powerful searches and replaces.








## Exploitation of Vulnerability
-------------------------------
[Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.









## Input Capture
-------------------------------
[Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception. 

[Logging Keys with PowerShell: Get-Keystroke](https://obscuresecurity.blogspot.com/2013/06/Get-Keystroke.html)

[How to create a keylogger in PowerShell?](https://www.tarlogic.com/en/blog/how-to-create-keylogger-in-powershell/)

[Get-Keystrokes.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-Keystrokes.ps1)







## Network Sniffing
-------------------------------
[Network Sniffing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1040)
* Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. 

[Packet Sniffing with PowerShell: Getting Started - technet](https://blogs.technet.microsoft.com/heyscriptingguy/2015/10/12/packet-sniffing-with-powershell-getting-started/)

[Network Monitor Automation/Scripting using PowerShell](https://channel9.msdn.com/Blogs/Darryl/Network-Monitor-AutomationScripting-using-PowerShell)
* Will Gregg, Senior Development Consultant, provided an overview of automating the Network Monitor (Netmon) utility using PowerShell at the 2009 Active Directory Windows Protocols Plugfest. In this presentation Will provides an overview of the PowerShell product and then progresses into using PowerShell to automate Netmon to perform a network capture. 

[Capturing network traffic in Windows 7 / Server 2008 R2 - technet](https://blogs.technet.microsoft.com/mrsnrub/2009/09/10/capturing-network-traffic-in-windows-7-server-2008-r2/)

[How to capture Network Traffic on Server without NetMon, Wireshark.. Installation](https://jurelab.wordpress.com/2014/10/11/how-to-capture-network-traffic-on-server-without-netmon-wireshark-installation/)

[No Wireshark? No TCPDump? No Problem! - SANS](https://isc.sans.edu/forums/diary/No+Wireshark+No+TCPDump+No+Problem/19409/)







## Private Keys
-------------------------------
[Private Keys - ATT&CK](https://attack.mitre.org/wiki/Technique/T1145)
* Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.1 

[Public-key cryptography - Wikipedia](https://en.wikipedia.org/wiki/Public-key_cryptography)








## Two-Factor Authentication Interception
-------------------------------
[Two-Factor Authentication Interception](https://attack.mitre.org/wiki/Technique/T1111)
* Use of two- or multifactor authentication is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. Adversaries may target authentication mechanisms, such as smart cards, to gain access to systems, services, and network resources. 

[Disabling Two-Factor SMS Codes to Avoid Interception - Duo](https://duo.com/blog/disabling-two-factor-sms-codes-to-avoid-interception)


