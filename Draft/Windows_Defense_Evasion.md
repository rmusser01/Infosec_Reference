# Defense Evasion


To Do:
	Add AV Avoidance, bypassing App whitelisting to Binary padding section
	Component Firmware
	De/Obfuscation




## Access Token Manipulation
-------------------------------
[Access Token Manipulation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1134)

[LogonUser function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx)
* The LogonUser function attempts to log a user on to the local computer. The local computer is the computer from which LogonUser was called. You cannot use LogonUser to log on to a remote computer. You specify the user with a user name and domain and authenticate the user with a plaintext password. If the function succeeds, you receive a handle to a token that represents the logged-on user. You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.

[Token Manipulation - Pentestlab](https://pentestlab.blog/2017/04/03/token-manipulation/)

[Fun with Incognito](https://www.offensive-security.com/metasploit-unleashed/fun-incognito/)

[Windows Access Tokens and Alternate Credentials -cobaltstrike](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)

[Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
* [RottenPotato tool](https://github.com/foxglovesec/RottenPotato)

[PowerShell and Token Impersonation](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)

[Account Hunting for Invoke-TokenManipulation](https://www.trustedsec.com/2015/01/account-hunting-invoke-tokenmanipulation/)



## Binary Padding
-------------------------------
[Binary Padding - ATT&CK](https://attack.mitre.org/wiki/Technique/T1009)
* Some security tools inspect files with static signatures to determine if they are known malicious. Adversaries may add data to files to increase the size beyond what security tools are capable of handling or to change the file hash to avoid hash-based blacklists. 



## Bypass User Account Control
-------------------------------
[Bypass User Account Control - ATT&CK](https://attack.mitre.org/wiki/Technique/T1088)

[User Account Control and WMI - MSDN](https://msdn.microsoft.com/en-us/library/aa826699(v=vs.85).aspx)

[Lesson 2: Understanding User Account Control (UAC) - MSDN](https://msdn.microsoft.com/en-us/library/cc505883.aspx)

[Bypassing Windows User Account Control (UAC) and ways of mitigation](https://www.greyhathacker.net/?p=796)

[UACMe](https://github.com/hfiref0x/UACME)
* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
* 41 different Methods

[Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
* Bypass-UAC provides a framework to perform UAC bypasses based on auto elevating IFileOperation COM object method calls. This is not a new technique, traditionally, this is accomplished by injecting a DLL into "explorer.exe". This is not desirable because injecting into explorer may trigger security alerts and working with unmanaged DLL's makes for an inflexible work-flow.

[UAC Bypasses - Powershell Empire](https://www.powershellempire.com/?page_id=380)

[UAC Bypass – Event Viewer - Pentestlab](https://pentestlab.blog/2017/05/02/uac-bypass-event-viewer/)

[UAC Bypass – Fodhelper - Pentesterlab](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/)

[Bypass UAC Using DLL Hijacking - nullbyte](https://null-byte.wonderhowto.com/how-to/bypass-uac-using-dll-hijacking-0168600/)

[“Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking - enigma0x3](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)

[Bypassing UAC using App Paths - enigma0x3](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/)

[“Fileless” UAC Bypass using sdclt.exe - enigma0x3](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)

[Research on CMSTP.exe](https://msitpros.com/?p=3960)
* Methods to bypass UAC and load a DLL over webdav 



## Code Signing
-------------------------------

[Introduction to Code Signing - MSDN](https://msdn.microsoft.com/en-us/library/ms537361(v=vs.85).aspx)

[Practical Windows Code and Driver Signing](http://www.davidegrayson.com/signing/)

[Bypassing Application Whitelisting - CERT](https://insights.sei.cmu.edu/cert/2016/06/bypassing-application-whitelisting.html)

[ApplicationWhitelistBypassTechniques - subTee](https://github.com/subTee/ApplicationWhitelistBypassTechniques)
* A Catalog of Application Whitelisting Bypass Techniques
* [ApplicationWhitelistBypassTechniques/TheList.txt - subTee](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)

[Babushka Dolls or How To Bypass Application Whitelisting and Constrained Powershell](https://improsec.com/blog//babushka-dolls-or-how-to-bypass-application-whitelisting-and-constrained-powershell)

[How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)



## Component Firmware
-------------------------------



## Component Object Model Hijacking
-------------------------------
[Component Object Model Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1122)

[The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)

[COM Object hijacking: the discreet way of persistence](https://www.gdatasoftware.com/blog/2014/10/23941-com-object-hijacking-the-discreet-way-of-persistence)



## DLL Injection
-------------------------------
[DLL Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1055)

[DLL injection - Wikipedia](https://en.wikipedia.org/wiki/DLL_injection)

[Inject All the Things - Shutup and Hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
* Writeup of 7 different injection techniques
* [Code - Github](https://github.com/fdiskyou/injectAllTheThings)



## DLL Search Order Hijacking
-------------------------------
[DLL Search Order Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1038)

[Dynamic-Link Library Search Order](https://msdn.microsoft.com/en-US/library/ms682586)



## DLL Side-Loading
-------------------------------
[DLL Side-Loading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1073)

[Manifests - MSDN](https://msdn.microsoft.com/en-us/library/aa375365)

[DLL Side-Loading: Another Blind-Spot for Anti-Virus - FireEye](https://www.fireeye.com/blog/threat-research/2014/04/dll-side-loading-another-blind-spot-for-anti-virus.html)
* [DLL SIDE-LOADING:  A Thorn in the Side of  the Anti-Virus Industry - pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)

[DLL Side Loading - veramine detections](https://github.com/veramine/Detections/wiki/DLL-Side-Loading)

[Secure loading of libraries to prevent DLL preloading attacks - MSDN](https://support.microsoft.com/en-us/help/2389418/secure-loading-of-libraries-to-prevent-dll-preloading-attacks)



## Deobfuscate/Decode File or Information
-------------------------------
[Deobfuscate/Decode Files or Information - ATT&CK](https://attack.mitre.org/wiki/Technique/T1140)

[Obfuscation - Wikipedia](https://en.wikipedia.org/wiki/Obfuscation_(software))



## Disabling Security Tools
-------------------------------
[Disabling Security Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1089)
* Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting. 



## Exploitatin of Vulnerability
-------------------------------
[Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)## Exploitation of Vulnerability



## File Deletion
-------------------------------
[File Deletion - ATT&CK](https://attack.mitre.org/wiki/Technique/T1107)
* Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process. 



## File System Logical Offsets
-------------------------------
[File System Logical Offsets - ATT&CK](https://attack.mitre.org/wiki/Technique/T1006)
* Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools. Utilities, such as NinjaCopy, exist to perform these actions in PowerShell.

[FDump - Dumping File Sectors Directly from Disk using Logical Offsets](https://www.codeproject.com/Articles/32169/FDump-Dumping-File-Sectors-Directly-from-Disk-usin)

[Invoke-NinjaCopy.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)



## Hidden Files and Directories
-------------------------------
[Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
* Users can mark specific files as hidden by using the attrib.exe binary. Simply do attrib +h filename to mark a file or folder as hidden. Similarly, the “+s” marks a file as a system file and the “+r” flag marks the file as read only. Like most windows binaries, the attrib.exe binary provides the ability to apply these changes recursively “/S”. 

[ What is a Hidden File? ](https://www.lifewire.com/what-is-a-hidden-file-2625898)



## Indicator Blocking
-------------------------------
[Indicator Blocking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1054)
* An adversary may attempt to block indicators or events from leaving the host machine. In the case of network-based reporting of indicators, an adversary may block traffic associated with reporting to prevent central analysis. This may be accomplished by many means, such as stopping a local process or creating a host-based firewall rule to block traffic to a specific server. 



## Indicator Removal from Tools
-------------------------------
[Indicator Removal from Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1066)
* If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems. A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use Software Packing or otherwise modify the file so it has a different signature, and then re-use the malware. 


## Indicator Removal on Host
-------------------------------
[Indicator Removal on Host - ATT&CK](https://attack.mitre.org/wiki/Technique/T1070)
* Adversaries may delete or alter generated event files on a host system, including potentially captured files such as quarantined malware. This may compromise the integrity of the security solution, causing events to go unreported, or make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred. 




## Install Root Certificate
-------------------------------
[Install Root Certificate - ATT&CK](https://attack.mitre.org/wiki/Technique/T1130)
* 

[Root certificate - Wikipedia](https://en.wikipedia.org/wiki/Root_certificate)

[HTTP Public Key Pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)


## InstallUtil
-------------------------------


## Masquerading
-------------------------------




## Modify Registry
-------------------------------



## NTFS Extended Attributes
-------------------------------



## Network Share Connection Removal
-------------------------------




## Obfuscated Files or Information
-------------------------------



## Process Hollowing
-------------------------------



## Redundant Access 
-------------------------------



## Regsvcs/Regasm
-------------------------------




## Regsvr32
-------------------------------




## Rootkit
-------------------------------



## Rundll32
-------------------------------



## Scripting
-------------------------------



## Software Packing
-------------------------------



## Timestomp
-------------------------------




## Trusted Developer Utilites
------------------------------



## Valid Accounts
-------------------------------
[Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)






