# Defense Evasion



## Access Token Manipulation
-------------------------------
Access Token Manipulation
* [Access Token Manipulation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1134)
* [LogonUser function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx)
	* The LogonUser function attempts to log a user on to the local computer. The local computer is the computer from which LogonUser was called. You cannot use LogonUser to log on to a remote computer. You specify the user with a user name and domain and authenticate the user with a plaintext password. If the function succeeds, you receive a handle to a token that represents the logged-on user. You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.
* [Token Manipulation - Pentestlab](https://pentestlab.blog/2017/04/03/token-manipulation/)
* [Fun with Incognito](https://www.offensive-security.com/metasploit-unleashed/fun-incognito/)
* [Windows Access Tokens and Alternate Credentials -cobaltstrike](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
* [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
	* [RottenPotato tool](https://github.com/foxglovesec/RottenPotato)
* [PowerShell and Token Impersonation](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)
* [Account Hunting for Invoke-TokenManipulation](https://www.trustedsec.com/2015/01/account-hunting-invoke-tokenmanipulation/)



## Binary Padding
-------------------------------
[Binary Padding - ATT&CK](https://attack.mitre.org/wiki/Technique/T1009)
* Some security tools inspect files with static signatures to determine if they are known malicious. Adversaries may add data to files to increase the size beyond what security tools are capable of handling or to change the file hash to avoid hash-based blacklists. 






## Bypass User Account Control
-------------------------------
Bypass User Account Control
* [Bypass User Account Control - ATT&CK](https://attack.mitre.org/wiki/Technique/T1088)
* [User Account Control and WMI - MSDN](https://msdn.microsoft.com/en-us/library/aa826699(v=vs.85).aspx)
* [Lesson 2: Understanding User Account Control (UAC) - MSDN](https://msdn.microsoft.com/en-us/library/cc505883.aspx)
* [Bypassing Windows User Account Control (UAC) and ways of mitigation](https://www.greyhathacker.net/?p=796)
* [UACMe](https://github.com/hfiref0x/UACME)
	* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
	* 41 different Methods
* [Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
	* Bypass-UAC provides a framework to perform UAC bypasses based on auto elevating IFileOperation COM object method calls. This is not a new technique, traditionally, this is accomplished by injecting a DLL into "explorer.exe". This is not desirable because injecting into explorer may trigger security alerts and working with unmanaged DLL's makes for an inflexible work-flow.
* [UAC Bypasses - Powershell Empire](https://www.powershellempire.com/?page_id=380)
* [UAC Bypass – Event Viewer - Pentestlab](https://pentestlab.blog/2017/05/02/uac-bypass-event-viewer/)
* [UAC Bypass – Fodhelper - Pentesterlab](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/)
* [Bypass UAC Using DLL Hijacking - nullbyte](https://null-byte.wonderhowto.com/how-to/bypass-uac-using-dll-hijacking-0168600/)
* [“Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking - enigma0x3](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
* [Bypassing UAC using App Paths - enigma0x3](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/)
* [“Fileless” UAC Bypass using sdclt.exe - enigma0x3](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)
* [Research on CMSTP.exe](https://msitpros.com/?p=3960)
	* Methods to bypass UAC and load a DLL over webdav 



## Code Signing
-------------------------------
Code Signing
* [Introduction to Code Signing - MSDN](https://msdn.microsoft.com/en-us/library/ms537361(v=vs.85).aspx)
* [Practical Windows Code and Driver Signing](http://www.davidegrayson.com/signing/)
* [Bypassing Application Whitelisting - CERT](https://insights.sei.cmu.edu/cert/2016/06/bypassing-application-whitelisting.html)
* [ApplicationWhitelistBypassTechniques - subTee](https://github.com/subTee/ApplicationWhitelistBypassTechniques)
	* A Catalog of Application Whitelisting Bypass Techniques
	* [ApplicationWhitelistBypassTechniques/TheList.txt - subTee](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)
* [Babushka Dolls or How To Bypass Application Whitelisting and Constrained Powershell](https://improsec.com/blog//babushka-dolls-or-how-to-bypass-application-whitelisting-and-constrained-powershell)
* [How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)



## Component Firmware
-------------------------------
Component Firmware
* [Component Firmware - ATT&CK](https://attack.mitre.org/wiki/Technique/T1109)
	* Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to System Firmware but conducted upon other system components that may not have the same capability or level of integrity checking. Malicious device firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks. 
* [HD Hacking - SpritesMods](http://spritesmods.com/?art=hddhack)


## Component Object Model Hijacking
-------------------------------
Component Object Model Hijacking
* [Component Object Model Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1122)
* [The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)
* [COM Object hijacking: the discreet way of persistence](https://www.gdatasoftware.com/blog/2014/10/23941-com-object-hijacking-the-discreet-way-of-persistence)



## DLL Injection
-------------------------------
DLL Injection
* [DLL Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1055)
* [DLL injection - Wikipedia](https://en.wikipedia.org/wiki/DLL_injection)
* [Inject All the Things - Shutup and Hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
	* Writeup of 7 different injection techniques
	* [Code - Github](https://github.com/fdiskyou/injectAllTheThings)



## DLL Search Order Hijacking
-------------------------------
DLL Search Order Hijacking
* [DLL Search Order Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1038)
* [Dynamic-Link Library Search Order](https://msdn.microsoft.com/en-US/library/ms682586)







## DLL Side-Loading
-------------------------------
DLL Side Loading
* [DLL Side-Loading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1073)
* [Manifests - MSDN](https://msdn.microsoft.com/en-us/library/aa375365)
* [DLL Side-Loading: Another Blind-Spot for Anti-Virus - FireEye](https://www.fireeye.com/blog/threat-research/2014/04/dll-side-loading-another-blind-spot-for-anti-virus.html)
* [DLL Side-Loading: A Thorn in the Side of  the Anti-Virus Industry - pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)
* [DLL Side Loading - veramine detections](https://github.com/veramine/Detections/wiki/DLL-Side-Loading)
* [Secure loading of libraries to prevent DLL preloading attacks - MSDN](https://support.microsoft.com/en-us/help/2389418/secure-loading-of-libraries-to-prevent-dll-preloading-attacks)



## Deobfuscate/Decode File or Information
-------------------------------
Deobfuscate/Decode File or Information
* [Deobfuscate/Decode Files or Information - ATT&CK](https://attack.mitre.org/wiki/Technique/T1140)
* [Obfuscation - Wikipedia](https://en.wikipedia.org/wiki/Obfuscation_(software))






## Disabling Security Tools
-------------------------------
Disabling Security Tools
* [Disabling Security Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1089)
	* Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting. 
* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
	* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.





## Exploitation of Vulnerability
-------------------------------
Exploitation of Vulnerability
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068) 





## File Deletion
-------------------------------
File Deletion
* [File Deletion - ATT&CK](https://attack.mitre.org/wiki/Technique/T1107)
	* Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process. 
* [del - ss64](https://ss64.com/nt/del.html)
* [Del - msdn](https://technet.microsoft.com/en-us/library/cc771049(v=ws.11).aspx)



## File System Logical Offsets
-------------------------------
File System Logical Offsets
* [File System Logical Offsets - ATT&CK](https://attack.mitre.org/wiki/Technique/T1006)
	* Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools. Utilities, such as NinjaCopy, exist to perform these actions in PowerShell.
* [FDump - Dumping File Sectors Directly from Disk using Logical Offsets](https://www.codeproject.com/Articles/32169/FDump-Dumping-File-Sectors-Directly-from-Disk-usin)
* [Invoke-NinjaCopy.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)



## Hidden Files and Directories
-------------------------------
Hidden Files and Directories
* [Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
	* Users can mark specific files as hidden by using the attrib.exe binary. Simply do attrib +h filename to mark a file or folder as hidden. Similarly, the “+s” marks a file as a system file and the “+r” flag marks the file as read only. Like most windows binaries, the attrib.exe binary provides the ability to apply these changes recursively “/S”. 
* [What is a Hidden File?](https://www.lifewire.com/what-is-a-hidden-file-2625898)



## Indicator Blocking
-------------------------------
Indicator Blocking
* [Indicator Blocking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1054)
	* An adversary may attempt to block indicators or events from leaving the host machine. In the case of network-based reporting of indicators, an adversary may block traffic associated with reporting to prevent central analysis. This may be accomplished by many means, such as stopping a local process or creating a host-based firewall rule to block traffic to a specific server. 



## Indicator Removal from Tools
-------------------------------
Indicator Removal from Tools
* [Indicator Removal from Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1066)
	* If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems. A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use Software Packing or otherwise modify the file so it has a different signature, and then re-use the malware. 





## Indicator Removal on Host
-------------------------------
Indicator Removal on Host
* [Indicator Removal on Host - ATT&CK](https://attack.mitre.org/wiki/Technique/T1070)
	* Adversaries may delete or alter generated event files on a host system, including potentially captured files such as quarantined malware. This may compromise the integrity of the security solution, causing events to go unreported, or make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred. 
* [Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)






## Install Root Certificate
-------------------------------
Install Root Certificate
* [Install Root Certificate - ATT&CK](https://attack.mitre.org/wiki/Technique/T1130)
	* 
* [Root certificate - Wikipedia](https://en.wikipedia.org/wiki/Root_certificate)
* [HTTP Public Key Pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)
* [Manage Trusted Root Certificates - msdn](https://technet.microsoft.com/en-us/library/cc754841(v=ws.11).aspx)
* [Installing a root certificate - msdn](https://msdn.microsoft.com/en-us/library/cc750534.aspx)





## InstallUtil
-------------------------------
InstallUtil
* [InstallUtil - ATT&CK](https://attack.mitre.org/wiki/Technique/T1118)
	* InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries.1 InstallUtil is located in the .NET directory on a Windows system: C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe.InstallUtil.exe is digitally signed by Microsoft. 
* [Installutil.exe (Installer Tool) - MSDN](https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool)
	* [AllTheThings](https://github.com/subTee/AllTheThings)
	* Includes 5 Known Application Whitelisting/ Application Control Bypass Techniques in One File. (First one is InstallUtil)



## Masquerading (Trusted Name/Path Execution Abuse)
-------------------------------
Masquerading (Trusted Name/Path Execution Abuse)
* [Masquerading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1036)
	* Masquerading occurs when an executable, legitimate or malicious, is placed in a commonly trusted location (such as C:\Windows\System32) or named with a common name (such as "explorer.exe" or "svchost.exe") to bypass tools that trust executables by relying on file name or path. An adversary may even use a renamed copy of a legitimate utility, such as rundll32.exe. Masquerading also may be done to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate. 
* [Metasploit Module - Windows Service Trusted Path Privilege Escalation](https://www.rapid7.com/db/modules/exploit/windows/local/trusted_service_path)
* [Unquoted Service Path - pentestlab.blog](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
* [Practical Guide to exploiting the unquoted service path vulnerability in Windows - trustfoundry](https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/)


## Modify Registry
-------------------------------
Modify Registry
* [Modify Registry - ATT&CK](https://attack.mitre.org/wiki/Technique/T1112)
* [Reg - MSDN](https://technet.microsoft.com/en-us/library/cc732643.aspx)
* [Enable the Remote Registry Service - MSDN](https://technet.microsoft.com/en-us/library/cc754820.aspx)



## NTFS Extended Attributes & Alternate Data Streams
-------------------------------
NTFS Extended Attributes & Alternate Data Streams
* [NTFS Extended Attributes - ATT&CK](https://attack.mitre.org/wiki/Technique/T1096)
	* Data or executables may be stored in New Technology File System (NTFS) partition metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus. The NTFS format has a feature called Extended Attributes (EA), which allows data to be stored as an attribute of a file or folder.
* [File Streams - MSDN](https://msdn.microsoft.com/en-us/library/aa364404)
* [Extracting ZeroAccess from NTFS Extended Attributes](http://journeyintoir.blogspot.com/2012/12/extracting-zeroaccess-from-ntfs.html)
* [EaTools](https://github.com/jschicht/EaTools)
	* Analysis and manipulation of extended attribute ($EA) on NTFS


#### Alternate Data Streams
Alternate Data Streams
* [Alternate Data Streams in NTFS - technet](https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs/)
* [Introduction to ADS – Alternate Data Streams](https://hshrzd.wordpress.com/2016/03/19/introduction-to-ads-alternate-data-streams/)
* [Exploring Alternate Data Streams - Rootkit Analytics](http://www.rootkitanalytics.com/userland/Exploring-Alternate-Data-Streams.php)
* [How To Use NTFS Alternate Data Streams - MS](https://support.microsoft.com/en-us/help/105763/how-to-use-ntfs-alternate-data-streams)
* [Practical Guide to Alternative Data Streams in NTFS - IronGeek](https://www.irongeek.com/i.php?page=security/altds)
* [Streams v1.6 - SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/streams)
	* Streams will examine the files and directories (note that directories can also have alternate data streams) you specify and inform you of the name and sizes of any named streams it encounters within those files. Streams makes use of an undocumented native function for retrieving file stream information.
* [Using Alternate Data Streams to Persist on a Compromised Machine - enigma0x3](https://enigma0x3.net/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/)
* [Computer Associates, Alternate Data Streams, and why you should be concerned. And what you might be able to do about it. - 2007](http://www.2kevin.net/datastreams.html)



## Network Share Connection Removal
-------------------------------
Network Share Connection Removal
* [Network Share Connection Removal - ATT&CK](https://attack.mitre.org/wiki/Technique/T1126)
	* Windows shared drive and Windows Admin Shares connections can be removed when no longer needed. Net is an example utility that can be used to remove network share connections with the net use \\system\share /delete command. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. 
* [Net use - technet](https://technet.microsoft.com/en-us/bb490717.aspx)



## Obfuscated Files or Information
-------------------------------
Obfuscated Files or Information
* [Obfuscated Files or Information - ATT&CK](https://attack.mitre.org/wiki/Technique/T1027)
	* Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system. 



## Process Hollowing
-------------------------------
Process Hollowing
* [Process Hollowing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1093)
	* Process hollowing occurs when a process is created in a suspended state and the process's memory is replaced with the code of a second program so that the second program runs instead of the original program. Windows and process monitoring tools believe the original process is running, whereas the actual program running is different. Process hollowing may be used similarly to DLL Injection to evade defenses and detection analysis of malicious process execution by launching adversary-controlled code under the context of a legitimate process. 
* [Process Hollowing - John Leitch - PDF](http://www.autosectools.com/process-hollowing.pdf)
	* [Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
	* Great explanation of Process Hollowing (a Technique often used in Malware) 



## Redundant Access 
-------------------------------
Redundant Access
* [Redundant Access - ATT&CK](https://attack.mitre.org/wiki/Technique/T1108)
	* Adversaries may use more than one remote access tool with varying command and control protocols as a hedge against detection. If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to Valid Accounts to use External Remote Services such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.





## Regsvcs/Regasm
-------------------------------
Regsvcs/Regasm
* [Regsvcs/Regasm - ATT&CK](https://attack.mitre.org/wiki/Technique/T1121)
	* Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: [ComRegisterFunction] or [ComUnregisterFunction] respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute
* [Regsvcs.exe (.NET Services Installation Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool)
* [Regasm.exe (Assembly Registration Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool)





## Regsvr32
-------------------------------
Regsvr32
* [Regsvr32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1117)
	* Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary. Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed.2 This variation of the technique has been used in campaigns targeting governments.
* [How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages](https://support.microsoft.com/en-us/help/249873/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages)
* [How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)
* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files) - subTee](http://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html)
* [Practical use of JavaScript and COM Scriptlets for Penetration Testing](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)



## Rootkit
-------------------------------
Rootkit
* [Rootkit - ATT&CK](https://attack.mitre.org/wiki/Technique/T1014)
	* Rootkits are programs that hide the existence of malware by intercepting and modifying operating system API calls that supply system information. Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a Hypervisor, Master Boot Record, or the System Firmware.



## Rundll32
-------------------------------
Rundll32
* [Rundll32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1085)
	* The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations. 
* [Rundll32 - technet](https://technet.microsoft.com/en-us/library/ee649171(v=ws.11).aspx)
* [AppLocker Bypass – Rundll32 - pentesterlab](https://pentestlab.blog/tag/rundll32/)
 	


## Scripting
-------------------------------
Scripting
* [Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
	* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts. 
* Batch Scripting
	* [Batch script - docs.ms](https://docs.microsoft.com/en-us/vsts/build-release/tasks/utility/batch-script)
	* [Using Batch files](https://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/batch.mspx?mfr=true)
	* [Batch file - Wikipedia](https://en.wikipedia.org/wiki/Batch_file)
	* [Batch Script Tutorial - TutorialsPoint](https://www.tutorialspoint.com/batch_script/)
	* [Windows Batch Scripting - WikiBooks](https://en.wikibooks.org/wiki/Windows_Batch_Scripting)
	* [Guide to Windows Batch Scripting - 10 Part series](https://steve-jansen.github.io/guides/windows-batch-scripting/)
* PowerShell Scripting
	* [PowerShell Core](https://github.com/PowerShell/PowerShell)
		* Welcome to the PowerShell GitHub Community! PowerShell Core is a cross-platform (Windows, Linux, and macOS) automation and configuration tool/framework that works well with your existing tools and is optimized for dealing with structured data (e.g. JSON, CSV, XML, etc.), REST APIs, and object models. It includes a command-line shell, an associated scripting language and a framework for processing cmdlets.
	* [Getting Started with Windows PowerShell - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/getting-started-with-windows-powershell?view=powershell-5.1)
	* [Learning PowerShell](https://github.com/PowerShell/PowerShell/tree/master/docs/learning-powershell)





## Software Packing
-------------------------------
Software Packing
* [Software Packing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1045)
	* Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. 
* [Executable compression - Wikipedia](https://en.wikipedia.org/wiki/Executable_compression)
* [UPX](https://upx.github.io/)
* [Basic Packers: Easy As Pie ](https://www.trustwave.com/Resources/SpiderLabs-Blog/Basic-Packers--Easy-As-Pie/)




## Timestomp
-------------------------------
Timestomp
* [Timestomp - ATT&CK](https://attack.mitre.org/wiki/Technique/T1099)
	* Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools. Timestomping may be used along with file name Masquerading to hide malware and tools.



## Trusted Developer Utilites
------------------------------
Trusted Developer Utilities
* [Trusted Developer Utilities - ATT&CK](https://attack.mitre.org/wiki/Technique/T1127)
	* There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application whitelisting defensive solutions. 

### MSBuild

* MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It takes XML formatted project files that define requirements for building various platforms and configurations. Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into the XML project file.2 MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application whitelisting defenses that are configured to allow MSBuild.exe execution.
* [MSBuild - MSDN](https://msdn.microsoft.com/library/dd393574.aspx)
* [MSBuild Inline Tasks - msdn](https://msdn.microsoft.com/library/dd722601.aspx)
* [MSBuild Inline Tasks - docs ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks)
* [AppLocker Bypass – MSBuild - pentestlab](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)

### DNX
* The .NET Execution Environment (DNX), dnx.exe, is a software development kit packaged with Visual Studio Enterprise. It was retired in favor of .NET Core CLI in 2016.4 DNX is not present on standard builds of Windows and may only be present on developer workstations using older versions of .NET Core and ASP.NET Core 1.0. The dnx.exe executable is signed by Microsoft. An adversary can use dnx.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for DNX. 
* [Migrating from DNX to .NET Core CLI (project.json) - docs ms](https://docs.microsoft.com/en-us/dotnet/core/migration/from-dnx)
* [Bypassing Application Whitelisting By Using dnx.exe - enigma0x3](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)



### RCSI
* The rcsi.exe utility is a non-interactive command-line interface for C# that is similar to csi.exe. It was provided within an early version of the Roslyn .NET Compiler Platform but has since been deprecated for an integrated solution. The rcsi.exe binary is signed by Microsoft. C# .csx script files can be written and executed with rcsi.exe at the command-line. An adversary can use rcsi.exe to proxy execution of arbitrary code to bypass application whitelisting policies that do not account for execution of rcsi.exe.
* [Introducing the Microsoft “Roslyn” CTP](https://blogs.msdn.microsoft.com/visualstudio/2011/10/19/introducing-the-microsoft-roslyn-ctp/)
* [Bypassing Application Whitelisting By Using rcsi.exe - enigma0x3](https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/)


### WinDbg/CDB
* WinDbg is a Microsoft Windows kernel and user-mode debugging utility. The Microsoft Console Debugger (CDB) cdb.exe is also user-mode debugger. Both utilities are included in Windows software development kits and can be used as standalone tools. They are commonly used in software development and reverse engineering and may not be found on typical Windows systems. Both WinDbg.exe and cdb.exe binaries are signed by Microsoft. An adversary can use WinDbg.exe and cdb.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for execution of those utilities. It is likely possible to use other debuggers for similar purposes, such as the kernel-mode debugger kd.exe, which is also signed by Microsoft. 
* [Debugging Tools for Windows (WinDbg, KD, CDB, NTSD) -docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/index)
* [Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner - exploitmonday](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)



## Valid Accounts
-------------------------------
Valid Accounts
* [Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
	* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence. Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful. The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.
* [Attractive Accounts for Credential Theft - docs ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/attractive-accounts-for-credential-theft)



