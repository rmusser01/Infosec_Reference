# Credential Access




* [MITRE ATT&CK - Credential Access](https://attack.mitre.org/wiki/Credential_Access)
	* Credential access represents techniques resulting in access to or control over system, domain, or service credentials that are used within an enterprise environment. Adversaries will likely attempt to obtain legitimate credentials from users or administrator accounts (local system administrator or domain users with administrator access) to use within the network. This allows the adversary to assume the identity of the account, with all of that account's permissions on the system and network, and makes it harder for defenders to detect the adversary. With sufficient access within a network, an adversary can create accounts for later use within the environment. 



Gatekeeper exposed
Writing Bad@ass os x malware
Attacking the XNU kernel in el capitan
OS X El Capitan-Sinking the S/h\IP
Memory corruption is for wussies



## Account Manipulation
-------------------------------
* [Account Manipulation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1098)
	* Account manipulation may aid adversaries in maintaining access to credentials and certain permission levels within an environment. Manipulation could consist of modifying permissions, adding or changing permission groups, modifying account settings, or modifying how authentication is performed. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. 

#### Linux
#### OS X
#### Windows
* [Modify permissions or delete authorized users - technet](https://technet.microsoft.com/en-us/library/cc753706(v=ws.11).aspx)
* [Managing User Accounts - msdn](https://msdn.microsoft.com/en-us/library/cc505882.aspx)
* [Set, View, Change, or Remove Permissions on Files and Folders - technet](https://technet.microsoft.com/en-us/library/cc754344(v=ws.11).aspx)
	* When a file or folder is created, Windows assigns default permissions to that object. 
* [Net user - technet](https://technet.microsoft.com/en-us/library/cc771865(v=ws.11).aspx)
	* Adds or modifies user accounts, or displays user account information.
* [Create admin user from command line - superuser](https://superuser.com/questions/515175/create-admin-user-from-command-line)
* [User Rights Assignment - technet](https://technet.microsoft.com/en-us/library/dn221963(v=ws.11).aspx)
	* This reference topic for the IT professional provides an overview and links to information about the User Rights Assignment security policy settings user rights that are available in the Windows operating system.


## Bash History
------------------------------- 
* [Bash History - ATT&CK](https://attack.mitre.org/wiki/Technique/T1139)
	* Bash keeps track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user’s .bash_history file. For each user, this file resides at the same location: ~/.bash_history. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Attackers can abuse this by looking through the file for potential credentials.

#### Linux
* [Command history in Zsh - StackOverflow](https://unix.stackexchange.com/questions/111718/command-history-in-zsh)




## Brute Force
-------------------------------
* [Brute Force - ATT&CK](https://attack.mitre.org/wiki/Technique/T1110)
	* Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained. 
	* Credential Dumping to obtain password hashes may only get an adversary so far when Pass the Hash is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table. Cracking hashes is usually done on adversary-controlled systems outside of the target network.Wikipedia Password cracking 
	* Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.Cylance Cleaver 
	*  A related technique called password spraying uses one password, or a small list of passwords, that matches the complexity policy of the domain and may be a commonly used password. Logins are attempted with that password and many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords.BlackHillsInfosec Password Spraying
* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
* DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain.
* [Simplifying Password Spraying - Spiderlabs](https://www.trustwave.com/Resources/SpiderLabs-Blog/Simplifying-Password-Spraying/)



## Create Account
-------------------------------
* [Create Account - ATT&CK](https://attack.mitre.org/wiki/Technique/T1136)
	* Adversaries with a sufficient level of access may create a local system or domain account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system. The net user commands can be used to create a local or domain account. 
* [Net user - technet](https://technet.microsoft.com/en-us/library/cc771865(v=ws.11).aspx)
	* Adds or modifies user accounts, or displays user account information.





## Credential Dumping
-------------------------------
* [Credential Dumping - ATT&CK](https://attack.mitre.org/wiki/Technique/T1003)
	* Credential dumping is the process of obtaining account login and password information from the operating system and software. Credentials can be used to perform Lateral Movement and access restricted information. 
	* Tools may dump credentials in many different ways: extracting credential hashes for offline cracking, extracting plaintext passwords, and extracting Kerberos tickets, among others. Examples of credential dumpers include pwdump7, Windows Credential Editor, Mimikatz, and gsecdump. These tools are in use by both professional security testers and adversaries. 
	* Plaintext passwords can be obtained using tools such as Mimikatz to extract passwords stored by the Local Security Authority (LSA). If smart cards are used to authenticate to a domain using a personal identification number (PIN), then that PIN is also cached as a result and may be dumped.Github Mimikatz Module sekurlsa 
	*  DCSync is a variation on credential dumping which can be used to acquire sensitive information from a domain controller. The action works by simulating a domain controller replication process from a remote domain controller, which may contain various pieces of information included in Active Directory such as passwords, historical hashes, and current hashes of potentially useful accounts, such as the KRBTGT account NTLM hash. Any members of the Administrators, Domain Admins, Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data.ADSecurity Mimikatz DCSync The hashes can then in turn be used to create a Golden Ticket for use in Pass the Ticket.Harmj0y Mimikatz and DCSync DCSync functionality has been included in the "lsadump" module in Mimikatz.GitHub Mimikatz lsadump Module 

#### Windows
* [Auto-Dumping Domain Credentials using SPNs, PowerShell Remoting, and Mimikatz - NETSPI](https://blog.netspi.com/auto-dumping-domain-credentials-using-spns-powershell-remoting-and-mimikatz/)
* [Mimikatz Against Virtual Machine Memory Part 1 - carnal0wnage](http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html)
* [Obtaining Windows Passwords - netsec.ws](https://netsec.ws/?p=314)
* [Dumping Windows Credentials - securusglobal2013](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)
* [Post-Exploitation in Windows: From Local Admin To Domain Admin (efficiently)](http://pentestmonkey.net/uncategorized/from-local-admin-to-domain-admin)
* [Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
	* The quick lowdown: I wrote a DLL capable of logging the credentials entered at logon for Windows Vista, 7 and future versions which you can download at http://www.leetsys.com/programs/credentialprovider/cp.zip. The credentials are logged to a file located at c:\cplog.txt.  Simply copy the dll to the system32 directory and run the included register.reg script to create the necessary registry settings.
* [Cain & Abel](http://www.oxid.it/cain.html)
* [CredCrack](https://github.coNetSem/gojhonny/CredCrack)
	* CredCrack is a fast and stealthy credential harvester. It exfiltrates credentials recusively in memory and in the clear. Upon completion, CredCrack will parse and output the credentials while identifying any domain administrators obtained. CredCrack also comes with the ability to list and enumerate share access and yes, it is threaded! CredCrack has been tested and runs with the tools found natively in Kali Linux. CredCrack solely relies on having PowerSploit's "Invoke-Mimikatz.ps1" under the /var/www directory.
* [creddump7](https://github.com/Neohapsis/creddump7)	
* [Dumping Active Directory Password Hashes](https://medium.com/@infosec_stuff/dumping-active-directory-password-hashes-deb9468d1633)
* [fgdump - foofus.net](http://foofus.net/goons/fizzgig/fgdump/)
* [How to extract Cached and Stored Credentials & LSA secrets](https://www.onlinehashcrack.com/how-to-extract-crack-LSA-cached-credentials.php)
* [LSASecretsDump v1.21 - NirSoft](http://www.nirsoft.net/utils/lsa_secrets_dump.html)
	* LSASecretsDump is a small console application that extract the LSA secrets from the Registry, decrypt them, and dump them into the console window. The LSA secrets key is located under HKEY_LOCAL_MACHINE\Security\Policy\Secrets and may contain your RAS/VPN passwords, Autologon password, and other system passwords/keys. 
* [mimikatz](https://github.com/gentilkiwi/mimikatz)
	* mimikatz is a tool I've made to learn C and make somes experiments with Windows security. It's now well known to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets.
* [mimikittenz](https://github.com/putterpanda/mimikittenz)
	* mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes.
* [MSCash Algorithm](http://openwall.info/wiki/john/MSCash)
	* What happens when you are in front of a Windows machine, which has a domain account and you can't access the domain (due to network outage or domain server shutdown)? Microsoft solved this problem by saving the hash(es) of the last user(s) that logged into the local machine. These hashes are stored in the Windows registry, by default the last 10 hashes.
* [MSCash2 Algorithm - openwall.info](http://openwall.info/wiki/john/MSCash2)
	* Domain cached credentials (DCC) are cached domain logon information that are stored locally in the Windows registry of Windows operating systems (cf. MSCash Algorithm). With the release of the Windows Vista operating system, Microsoft introduced a new hash algorithm for generating these Domain Cached Credentials. This new algorithm increased the cost of password guessing attacks by several orders of magnitude.
* [Ntdsutil - technet](https://technet.microsoft.com/en-us/library/cc753343.aspx)
	* Ntdsutil.exe is a command-line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). You can use the ntdsutil commands to perform database maintenance of AD DS, manage and control single master operations, and remove metadata left behind by domain controllers that were removed from the network without being properly uninstalled. This tool is intended for use by experienced administrators.
* [Nirsoft - Password Recovery Utilities](http://nirsoft.net/utils/index.html#password_utils)
* [Out-Minidump.ps1 - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)
* [Protected Storage PassView v1.63 - Nirsoft](http://www.nirsoft.net/utils/pspv.html)
	*  Protected Storage PassView is a small utility that reveals the passwords stored on your computer by Internet Explorer, Outlook Express and MSN Explorer. The passwords are revealed by reading the information from the Protected Storage. 
* [ProcDump v9.0 - docs msdn](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
	* ProcDump is a command-line utility whose primary purpose is monitoring an application for CPU spikes and generating crash dumps during a spike that an administrator or developer can use to determine the cause of the spike. ProcDump also includes hung window monitoring (using the same definition of a window hang that Windows and Task Manager use), unhandled exception monitoring and can generate dumps based on the values of system performance counters. It also can serve as a general process dump utility that you can embed in other scripts.
* [PWDUMP7](http://www.tarasco.org/security/pwdump_7/)
	* We have developed a new password dumper for windows named PWDUMP7. The main difference between pwdump7 and other pwdump tools is that our tool runs by extracting the binary SAM and SYSTEM File from the Filesystem and then the hashes are extracted. For that task Rkdetector NTFS and FAT32 filesystem drivers are used.
* [redsnarf](https://github.com/nccgroup/redsnarf)
	* RedSnarf is a pen-testing / red-teaming tool by Ed Williams for retrieving hashes and credentials from Windows workstations, servers and domain controllers using OpSec Safe Techniques.
* [secretsdump.py - impacket](https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py)
	* Performs various techniques to dump hashes from the remote machine without executing any agent there. For SAM and LSA Secrets (including cached creds) we try to read as much as we can from the registry and then we save the hives in the target system (%SYSTEMROOT%\\Temp dir) and read the rest of the data from there.
* [Windows Gather Credential Cache Dump - rapid7 msf-post module](https://www.rapid7.com/db/modules/post/windows/gather/cachedump)
	* This module uses the registry to extract the stored domain hashes that have been cached as a result of a GPO setting. The default setting on Windows is to store the last ten successful logins.
* [Windows Credentials Editor (WCE) F.A.Q.](http://www.ampliasecurity.com/research/wcefaq.html)








## Credentials in Files
-------------------------------
* [Credentials in Files](https://attack.mitre.org/wiki/Technique/T1081)
	* Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords. It is possible to extract passwords from backups or saved virtual machines through Credential Dumping.CG 2014 Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.

#### Windows
* [grepwin](https://sourceforge.net/projects/grepwin/)
	* grepWin is a simple search and replace tool which can use regular expressions to do its job. This allows to do much more powerful searches and replaces.
* [LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
	* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.

#### Linux
* [How do I find all files containing specific text on Linux? - StackOverflow](https://stackoverflow.com/questions/16956810/how-do-i-find-all-files-containing-specific-text-on-linux)
* [Find Files in Linux, Using the Command Line - Linode](https://www.linode.com/docs/tools-reference/tools/find-files-in-linux-using-the-command-line)






## Exploitation of Vulnerability
-------------------------------
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
	* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.

#### Linux
* [Triple-Fetch-Kernel-Creds](https://github.com/coffeebreakerz/Tripple-Fetch-Kernel-Creds)
	* Attempt to steal kernelcredentials from launchd + task_t pointer (Based on: CVE-2017-7047)

#### Windows




## Input Capture
-------------------------------
* [Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
	* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.
	* Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes,Adventures of a Keystroke but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider.Wrightson 2012 
	* Keylogging is likely to be used to acquire credentials for new access opportunities when Credential Dumping efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises. 
	*  Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the initial compromise by exploitation of the externally facing web service.Volexity Virtual Private Keylogging 

#### Linux
* [logkeys - a GNU/Linux keylogger](https://github.com/kernc/logkeys)
	* logkeys is a linux keylogger. It is no more advanced than other available linux keyloggers, notably lkl and uberkey, but is a bit newer, more up to date, it doesn't unreliably repeat keys and it shouldn't crash your X. All in all, it just seems to work. It relies on event interface of the Linux input subsystem. Once completely set, it logs all common character and function keys, while also being fully aware of Shift and AltGr key modifiers.
* [Using xkeyscan to Parse an X-Based Linux Keylogger](http://porterhau5.com/blog/xkeyscan-parse-linux-keylogger/)
	* Leverage native X-based tools for real-time keylogging with xkeyscan, a Python script that translates X keycodes into legible keystrokes.
* [keysniffer: trace pressed keys in debugfs](http://tuxdiary.com/2015/10/14/keysniffer/)
* [SKeylogger](https://github.com/gsingh93/simple-key-logger)
	* SKeylogger is a simple keylogger. I had previously been using a few other open source keyloggers, but they stopped working when I upgraded my operating system. I tried to look through the code of those keyloggers, but it was undocumented, messy, and complex. I decided to make my own highly documented and very simple keylogger.
* [The Linux Security Circus: On GUI isolation](https://theinvisiblethings.blogspot.com/2011/04/linux-security-circus-on-gui-isolation.html)

#### OS X
* [OSX-Keylogger](https://github.com/CounterfeitLlama/OSX-Keylogger)
* [Swift-Keylogger](https://github.com/SkrewEverything/Swift-Keylogger)
	* Keylogger for mac written in Swift using HID
* [Mac OS X Keylogger](https://github.com/caseyscarborough/keylogger)
	* This repository holds the code for a simple and easy to use keylogger for Mac OS X. It is not meant to be malicious, and is written as a proof of concept. There is not a lot of information on keyloggers or implementing them on Mac OS X, and most of the ones I've seen do not work as indicated. This project aims to be a simple implementation on how it can be accomplished on OS X.

#### Windows
* [Logging Keys with PowerShell: Get-Keystroke](https://obscuresecurity.blogspot.com/2013/06/Get-Keystroke.html)
* [How to create a keylogger in PowerShell?](https://www.tarlogic.com/en/blog/how-to-create-keylogger-in-powershell/)
* [Get-Keystrokes.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-Keystrokes.ps1)
* [Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))
* [The Adventures of a KeyStroke: An in-depth look into Keyloggers on Windows](http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf)
* [Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)



------------------------------- 
## Input Prompt
* [Input Prompt - ATT&CK](https://attack.mitre.org/wiki/Technique/T1141)
	* When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task. Adversaries can mimic this functionality to prompt users for credentials with a normal-looking prompt. This type of prompt can be accomplished with AppleScript: 
	* `set thePassword to the text returned of (display dialog "AdobeUpdater needs permission to check for updates. Please authenticate." default answer "")`
	* Adversaries can prompt a user for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.OSX Malware Exploits MacKeeper

#### OS X
* [osascript: for local phishing - fuzzyknop](http://fuzzynop.blogspot.com/2014/10/osascript-for-local-phishing.html)
* [FiveOnceInYourLife](https://github.com/fuzzynop/FiveOnceInYourLife)
* [osascript - macphish](https://github.com/cldrn/macphish/wiki/Osascript)
* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
	* A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.


------------------------------- 
## Keychain 
* [Keychain - ATT&CK](https://attack.mitre.org/wiki/Technique/T1142)
	* Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes, certificates, and Kerberos. Keychain files are located in ~/Library/Keychains/,/Library/Keychains/, and /Network/Library/Keychains/.Wikipedia keychain The security command-line utility, which is built into macOS by default, provides a useful way to manage these credentials. To manage their credentials, users have to use additional credentials to access their keychain. If an adversary knows the credentials for the login keychain, then they can get access to all the other credentials stored in this vault.External to DA, the OS X Way By default, the passphrase for the keychain is the user’s logon credentials.

#### OS X
* [Keychain for Mac: Keychain Access overview](https://support.apple.com/kb/PH20093?locale=en_US)
* [Is there a quick and easy way to dump the contents of a MacOS X keychain? - StackOverflow](https://stackoverflow.com/questions/717095/is-there-a-quick-and-easy-way-to-dump-the-contents-of-a-macos-x-keychain)
* [How to dump the content of keychain from the shell? - askdifferent](https://apple.stackexchange.com/questions/184897/how-to-dump-the-content-of-keychain-from-the-shell)
* [Breaking into the OS X keychain - 2012](http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain)
* [chainbreaker](https://github.com/n0fate/chainbreaker)
	* chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner. Master Key candidates can be extracted from volafox or volatility keychaindump module.
* [Examining Mac OS X User & System Keychains - Digital Forensics Today blog](http://encase-forensic-blog.guidancesoftware.com/2013/07/examining-mac-os-x-user-system-keychains.html)
* [Dumping cleartext passwords from the OS X keychain](http://x3ro.de/retrieving-passwords-from-keychain.html)
* [Keychain Analysis with Mac OS X Memory Forensics](https://forensic.n0fate.com/wp-content/uploads/2012/07/Keychain-Analysis-with-Mac-OS-X-Memory-Forensics.pdf)




## Network Sniffing
-------------------------------
* [Network Sniffing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1040)
	* Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. User credentials may be sent over an insecure, unencrypted protocol that can be captured and obtained through network packet analysis. An adversary may place a network interface into promiscuous mode, using a utility to capture traffic in transit over the network or use span ports to capture a larger amount of data. In addition, Address Resolution Protocol (ARP) and Domain Name Service (DNS) poisoning can be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

#### Linux
* [Manpage for TCPDump](http://www.tcpdump.org/tcpdump_man.html)
* [A tcpdump Tutorial and Primer with Examples - Daniel Messler](https://danielmiessler.com/study/tcpdump/)
* [net-creds](https://github.com/DanMcInerney/net-creds)
	* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification.
* [tcpflow](https://github.com/simsong/tcpflow)
	* tcpflow is a program that captures data transmitted as part of TCP connections (flows), and stores the data in a way that is convenient for protocol analysis and debugging. Each TCP flow is stored in its own file. Thus, the typical TCP flow will be stored in two files, one for each direction. tcpflow can also process stored 'tcpdump' packet flows.

#### OS X
* [OS X Yosemite Has A Secret Packet Sniffer](https://jacobsalmela.com/2014/11/23/os-x-yosemite-secret-packet-sniffer/)
* [Capture a packet trace using Terminal on your Mac - support.apple](https://support.apple.com/en-us/HT202013)


#### Windows
* [Packet Sniffing with PowerShell: Getting Started - technet](https://blogs.technet.microsoft.com/heyscriptingguy/2015/10/12/packet-sniffing-with-powershell-getting-started/)
* [Network Monitor Automation/Scripting using PowerShell](https://channel9.msdn.com/Blogs/Darryl/Network-Monitor-AutomationScripting-using-PowerShell)
	* Will Gregg, Senior Development Consultant, provided an overview of automating the Network Monitor (Netmon) utility using PowerShell at the 2009 Active Directory Windows Protocols Plugfest. In this presentation Will provides an overview of the PowerShell product and then progresses into using PowerShell to automate Netmon to perform a network capture. 
* [Capturing network traffic in Windows 7 / Server 2008 R2 - technet](https://blogs.technet.microsoft.com/mrsnrub/2009/09/10/capturing-network-traffic-in-windows-7-server-2008-r2/)
* [How to capture Network Traffic on Server without NetMon, Wireshark.. Installation](https://jurelab.wordpress.com/2014/10/11/how-to-capture-network-traffic-on-server-without-netmon-wireshark-installation/)
* [No Wireshark? No TCPDump? No Problem! - SANS](https://isc.sans.edu/forums/diary/No+Wireshark+No+TCPDump+No+Problem/19409/)







## Private Keys
-------------------------------
Private Keys
* [Private Keys - ATT&CK](https://attack.mitre.org/wiki/Technique/T1145)
	* Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.Wikipedia Public Key Crypto 
	* Adversaries may gather private keys from compromised systems for use in authenticating to Remote Services like SSH or for use in decrypting other collected files such as email. Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, pfx, .cer, .p7b, .asc. Adversaries may also look in common key directories, such as ~/.ssh for SSH keys on `*nix-based systems` or `C:\Users\(username)\.ssh\` on Windows. 
	* Private keys should require a password or passphrase for operation, so an adversary may also use Input Capture for keylogging or attempt to Brute Force the passphrase off-line. 
	*  Adversary tools have been discovered that search compromised systems for file extensions relating to cryptographic keys and certificates.Kaspersky CaretoPalo Alto Prince of Persia
* [Public-key cryptography - Wikipedia](https://en.wikipedia.org/wiki/Public-key_cryptography)
* [What is a Pem file and how does it differ from other OpenSSL Generated Key File Formats? - StackOverflow](https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file)





------------------------------- 
## Securityd Memory (OS X)
* [Securityd Memory - ATT&CK](https://attack.mitre.org/wiki/Technique/T1167)
	* In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple’s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords.OS X KeychainExternal to DA, the OS X Way Apple’s securityd utility takes the user’s logon password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a set of keys and algorithms to encrypt the user’s password, but once the master key is found, an attacker need only iterate over the other values to unlock the final password.OS X Keychain If an adversary can obtain root access (allowing them to read securityd’s memory), then they can scan through memory to find the correct sequence of keys in relatively few tries to decrypt the user’s logon keychain. This provides the adversary with all the plaintext passwords for users, WiFi, mail, browsers, certificates, secure notes, etc.OS X KeychainOSX Keydnap malware





## Two-Factor Authentication Interception
-------------------------------
* [Two-Factor Authentication Interception](https://attack.mitre.org/wiki/Technique/T1111)
	* Use of two- or multifactor authentication is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. Adversaries may target authentication mechanisms, such as smart cards, to gain access to systems, services, and network resources. 
	* If a smart card is used for two-factor authentication (2FA), then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token.Mandiant M Trends 2011 
	* Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors.Operation Emmental 
	* Other hardware tokens, such as RSA SecurID, require the adversary to have access to the physical device or the seed and algorithm in addition to the corresponding credentials. 

* [Disabling Two-Factor SMS Codes to Avoid Interception - Duo](https://duo.com/blog/disabling-two-factor-sms-codes-to-avoid-interception)


