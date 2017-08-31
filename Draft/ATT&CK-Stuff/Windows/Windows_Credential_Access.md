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

[Obtaining Windows Passwords - netsec.ws](https://netsec.ws/?p=314)

[Dumping Windows Credentials - securusglobal2013](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)

[Post-Exploitation in Windows: From Local Admin To Domain Admin (efficiently)](http://pentestmonkey.net/uncategorized/from-local-admin-to-domain-admin)

[CredCrack](https://github.coNetSem/gojhonny/CredCrack)
* CredCrack is a fast and stealthy credential harvester. It exfiltrates credentials recusively in memory and in the clear. Upon completion, CredCrack will parse and output the credentials while identifying any domain administrators obtained. CredCrack also comes with the ability to list and enumerate share access and yes, it is threaded! CredCrack has been tested and runs with the tools found natively in Kali Linux. CredCrack solely relies on having PowerSploit's "Invoke-Mimikatz.ps1" under the /var/www directory.

[mimikatz](https://github.com/gentilkiwi/mimikatz)
* mimikatz is a tool I've made to learn C and make somes experiments with Windows security. It's now well known to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets.

[mimikittenz](https://github.com/putterpanda/mimikittenz)
* mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes.

[Ntdsutil - technet](https://technet.microsoft.com/en-us/library/cc753343.aspx)
* Ntdsutil.exe is a command-line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). You can use the ntdsutil commands to perform database maintenance of AD DS, manage and control single master operations, and remove metadata left behind by domain controllers that were removed from the network without being properly uninstalled. This tool is intended for use by experienced administrators.

[Nirsoft - Password Recovery Utilities](http://nirsoft.net/utils/index.html#password_utils)

[Protected Storage PassView v1.63 - Nirsoft](http://www.nirsoft.net/utils/pspv.html)
*  Protected Storage PassView is a small utility that reveals the passwords stored on your computer by Internet Explorer, Outlook Express and MSN Explorer. The passwords are revealed by reading the information from the Protected Storage. 

[Out-Minidump.ps1 - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)

[ProcDump v9.0 - docs msdn](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
* ProcDump is a command-line utility whose primary purpose is monitoring an application for CPU spikes and generating crash dumps during a spike that an administrator or developer can use to determine the cause of the spike. ProcDump also includes hung window monitoring (using the same definition of a window hang that Windows and Task Manager use), unhandled exception monitoring and can generate dumps based on the values of system performance counters. It also can serve as a general process dump utility that you can embed in other scripts.

[MSCash Algorithm](http://openwall.info/wiki/john/MSCash)
* What happens when you are in front of a Windows machine, which has a domain account and you can't access the domain (due to network outage or domain server shutdown)? Microsoft solved this problem by saving the hash(es) of the last user(s) that logged into the local machine. These hashes are stored in the Windows registry, by default the last 10 hashes.

[MSCash2 Algorithm - openwall.info](http://openwall.info/wiki/john/MSCash2)
* Domain cached credentials (DCC) are cached domain logon information that are stored locally in the Windows registry of Windows operating systems (cf. MSCash Algorithm). With the release of the Windows Vista operating system, Microsoft introduced a new hash algorithm for generating these Domain Cached Credentials. This new algorithm increased the cost of password guessing attacks by several orders of magnitude.

[Windows Gather Credential Cache Dump - rapid7 msf-post module](https://www.rapid7.com/db/modules/post/windows/gather/cachedump)
* This module uses the registry to extract the stored domain hashes that have been cached as a result of a GPO setting. The default setting on Windows is to store the last ten successful logins.

[How to extract Cached and Stored Credentials & LSA secrets](https://www.onlinehashcrack.com/how-to-extract-crack-LSA-cached-credentials.php)

[Dumping Active Directory Password Hashes](https://medium.com/@infosec_stuff/dumping-active-directory-password-hashes-deb9468d1633)

[LSASecretsDump v1.21 - NirSoft](http://www.nirsoft.net/utils/lsa_secrets_dump.html)
* LSASecretsDump is a small console application that extract the LSA secrets from the Registry, decrypt them, and dump them into the console window. The LSA secrets key is located under HKEY_LOCAL_MACHINE\Security\Policy\Secrets and may contain your RAS/VPN passwords, Autologon password, and other system passwords/keys. 

[Cain & Abel](http://www.oxid.it/cain.html)
* Cain & Abel is a password recovery tool for Microsoft Operating Systems. It allows easy recovery of various kind of passwords by sniffing the network, cracking encrypted passwords using Dictionary, Brute-Force and Cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, recovering wireless network keys, revealing password boxes, uncovering cached passwords and analyzing routing protocols. The program does not exploit any software vulnerabilities or bugs that could not be fixed with little effort. It covers some security aspects/weakness present in protocol's standards, authentication methods and caching mechanisms; its main purpose is the simplified recovery of passwords and credentials from various sources, however it also ships some "non standard" utilities for Microsoft Windows users.

[Windows Credentials Editor (WCE) F.A.Q.](http://www.ampliasecurity.com/research/wcefaq.html)

[fgdump - foofus.net](http://foofus.net/goons/fizzgig/fgdump/)

[PWDUMP7](http://www.tarasco.org/security/pwdump_7/)
* We have developed a new password dumper for windows named PWDUMP7. The main difference between pwdump7 and other pwdump tools is that our tool runs by extracting the binary SAM and SYSTEM File from the Filesystem and then the hashes are extracted. For that task Rkdetector NTFS and FAT32 filesystem drivers are used.

[secretsdump.py - impacket](https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py)
* Performs various techniques to dump hashes from the remote machine without executing any agent there. For SAM and LSA Secrets (including cached creds) we try to read as much as we can from the registry and then we save the hives in the target system (%SYSTEMROOT%\\Temp dir) and read the rest of the data from there.

[redsnarf](https://github.com/nccgroup/redsnarf)
* RedSnarf is a pen-testing / red-teaming tool by Ed Williams for retrieving hashes and credentials from Windows workstations, servers and domain controllers using OpSec Safe Techniques.

[creddump7](https://github.com/Neohapsis/creddump7)




## Credentials in Files
-------------------------------
[Credentials in Files](https://attack.mitre.org/wiki/Technique/T1081)
* Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords. 

[grepwin](https://sourceforge.net/projects/grepwin/)
* grepWin is a simple search and replace tool which can use regular expressions to do its job. This allows to do much more powerful searches and replaces.

[LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.






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


