# Defense Evasion


[MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/wiki/Defense_Evasion)
* Defense evasion consists of techniques an adversary may use to evade detection or avoid other defenses. Sometimes these actions are the same as or variations of techniques in other categories that have the added benefit of subverting a particular defense or mitigation. Defense evasion may be considered a set of attributes the adversary applies to all other phases of the operation. 




-------------------------------
## Access Token Manipulation
* [Access Token Manipulation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1134)
	* Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token. For example, Microsoft promotes the use of access tokens as a security best practice. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas. Microsoft runas 
	* Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection. An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level.Pentestlab Token Manipulation 
	* Adversaries can also create spoofed access tokens if they know the credentials of a user. Any standard user can use the runas command, and the Windows API functions, to do this; it does not require access to an administrator account. 
	* Lastly, an adversary can use a spoofed token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system. 
	* Metasploit’s Meterpreter payload allows arbitrary token stealing and uses token stealing to escalate privileges. Metasploit access token The Cobalt Strike beacon payload allows arbitrary token stealing and can also create tokens. Cobalt Strike Access Token

#### Windows
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


-------------------------------
## Binary Padding
* [Binary Padding - ATT&CK](https://attack.mitre.org/wiki/Technique/T1009)
	* Some security tools inspect files with static signatures to determine if they are known malicious. Adversaries may add data to files to increase the size beyond what security tools are capable of handling or to change the file hash to avoid hash-based blacklists.




-------------------------------
## Bypass User Account Control
* [Bypass User Account Control](https://attack.mitre.org/wiki/Technique/T1088)
	* Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.TechNet How UAC Works 
	* If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs are allowed to elevate privileges or execute some elevated COM objects without prompting the user through the UAC notification box.TechNet Inside UACMSDN COM Elevation An example of this is use of rundll32.exe to load a specifically crafted DLL which loads an auto-elevated COM object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.Davidson Windows Adversaries can use these techniques to elevate privileges to administrator if the target process is unprotected. 
	* Many methods have been discovered to bypass UAC. The Github readme page for UACMe contains an extensive list of methodsGithub UACMe that have been discovered and implemented within UACMe, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:
		* `eventvwr.exe` can auto-elevate and execute a specified binary or script.enigma0x3 Fileless UAC BypassFortinet Fareit
	* Another bypass is possible through some Lateral Movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on lateral systems and default to high integrity.SANS UAC Bypass

#### Windows
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


------------------------------- 
## Clear Command History
* [Clear Command History - ATT&CK](https://attack.mitre.org/wiki/Technique/T1146)
	* macOS and Linux both keep track of the commands users type in their terminal so that users can easily remember what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable HISTFILE. When a user logs off a system, this information is flushed to a file in the user's home directory called ~/.bash_history. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as unset HISTFILE, export HISTFILESIZE=0, history -c, rm ~/.bash_history.

#### Linux/OS X
* [Clear Command History - ATT&CK](https://attack.mitre.org/wiki/Technique/T1146)
	* macOS and Linux both keep track of the commands users type in their terminal so that users can easily remember what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable HISTFILE. When a user logs off a system, this information is flushed to a file in the user's home directory called ~/.bash_history. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as unset HISTFILE, export HISTFILESIZE=0, history -c, rm ~/.bash_history. 
	* Location of bash history file on linux: ```~/.bash_history```
* [How to clear bash history completely? - StackOverflow](https://askubuntu.com/questions/191999/how-to-clear-bash-history-completely)
* [How To Delete / Clear Linux Comand Line History With Examples](https://linoxide.com/how-tos/how-to-delete-history-linux/)




-------------------------------
## Code Signing
* [Code Signing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1116)
	* Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with.Wikipedia Code Signing However, adversaries are known to use code signing certificates to masquerade malware and tools as legitimate binariesJanicab. The certificates used during an operation may be created, forged, or stolen by the adversary.Securelist Digital CertificatesSymantec Digital Certificates 
	* Code signing to verify software on first run can be used on modern Windows and MacOS/OS X systems. It is not used on Linux due to the decentralized nature of the platform.Wikipedia Code Signing 
	*  Code signing certificates may be used to bypass security policies that require signed code to execute on a system.

#### Linux

#### OS X
* [macOS Code Signing In Depth - dev.apple](https://developer.apple.com/library/content/technotes/tn2206/_index.html)
* [High Sierra's 'Secure Kernel Extension Loading' is Broken](https://objective-see.com/blog/blog_0x21.html)

#### Windows
* [Introduction to Code Signing - MSDN](https://msdn.microsoft.com/en-us/library/ms537361(v=vs.85).aspx)
* [Practical Windows Code and Driver Signing](http://www.davidegrayson.com/signing/)
* [Bypassing Application Whitelisting - CERT](https://insights.sei.cmu.edu/cert/2016/06/bypassing-application-whitelisting.html)
* [ApplicationWhitelistBypassTechniques - subTee](https://github.com/subTee/ApplicationWhitelistBypassTechniques)
	* A Catalog of Application Whitelisting Bypass Techniques
	* [ApplicationWhitelistBypassTechniques/TheList.txt - subTee](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)
* [Babushka Dolls or How To Bypass Application Whitelisting and Constrained Powershell](https://improsec.com/blog//babushka-dolls-or-how-to-bypass-application-whitelisting-and-constrained-powershell)
* [How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)


-------------------------------
## Component Firmware
* [Component Firmware - ATT&CK](https://attack.mitre.org/wiki/Technique/T1109)
	* Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to System Firmware but conducted upon other system components that may not have the same capability or level of integrity checking. Malicious device firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.
* [HD Hacking - SpritesMods](http://spritesmods.com/?art=hddhack)

-------------------------------
## Component Object Model Hijacking
* [Component Object Model Hijacking](https://attack.mitre.org/wiki/Defense_Evasion)
	* The Microsoft Component Object Model (COM) is a system within Windows to enable interaction between software components through the operating system.Microsoft Component Object Model Adversaries can use this system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Windows Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead.GDATA COM Hijacking An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

#### Windows
Component Object Model Hijacking
* [Component Object Model Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1122)
* [The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)
* [COM Object hijacking: the discreet way of persistence](https://www.gdatasoftware.com/blog/2014/10/23941-com-object-hijacking-the-discreet-way-of-persistence)




-------------------------------
## DLL Injection
* [DLL Injection - ATT&CK](https://attack.mitre.org/wiki/Defense_Evasion)
	* DLL injection is used to run code in the context of another process by causing the other process to load and execute code. Running code in the context of another process provides adversaries many benefits, such as access to the process's memory and permissions. It also allows adversaries to mask their actions under a legitimate process. A more sophisticated kind of DLL injection, reflective DLL injection, loads code without calling the normal Windows API calls, potentially bypassing DLL load monitoring. Numerous methods of DLL injection exist on Windows, including modifying the Registry, creating remote threads, Windows hooking APIs, and DLL pre-loading.CodeProject Inject CodeWikipedia DLL Injection

#### Windows
* [DLL Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1055)
* [DLL injection - Wikipedia](https://en.wikipedia.org/wiki/DLL_injection)
* [Inject All the Things - Shutup and Hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
	* Writeup of 7 different injection techniques
	* [Code - Github](https://github.com/fdiskyou/injectAllTheThings)


-------------------------------
## DLL Search Order Hijacking
* [DLL Search Order Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1038)
	* Windows systems use a common method to look for required DLLs to load into a program.Microsoft DLL Search Adversaries may take advantage of the Windows DLL search order and programs that ambiguously specify DLLs to gain privilege escalation and persistence. 
	* Adversaries may perform DLL preloading, also called binary planting attacks,OWASP Binary Planting by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program. Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL.Microsoft 2269637 Adversaries may use this behavior to cause the program to load a malicious DLL. 
	* Adversaries may also directly modify the way a program loads DLLs by replacing an existing DLL or modifying a .manifest or .local redirection file, directory, or junction to cause the program to load a different DLL to maintain persistence or privilege escalation.Microsoft DLL RedirectionMicrosoft ManifestsMandiant Search Order 
	* If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. 
	*  Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.

#### Windows
* [DLL Search Order Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1038)
* [Dynamic-Link Library Search Order](https://msdn.microsoft.com/en-US/library/ms682586)






-------------------------------
## DLL Side-Loading
* [DLL Side Loading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1073)
	* Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifestsMSDN Manifests are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable to side-loading to load a malicious DLL.Stewart 2014 Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

#### Windows
* [DLL Side-Loading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1073)
* [Manifests - MSDN](https://msdn.microsoft.com/en-us/library/aa375365)
* [DLL Side-Loading: Another Blind-Spot for Anti-Virus - FireEye](https://www.fireeye.com/blog/threat-research/2014/04/dll-side-loading-another-blind-spot-for-anti-virus.html)
* [DLL Side-Loading: A Thorn in the Side of  the Anti-Virus Industry - pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)
* [DLL Side Loading - veramine detections](https://github.com/veramine/Detections/wiki/DLL-Side-Loading)
* [Secure loading of libraries to prevent DLL preloading attacks - MSDN](https://support.microsoft.com/en-us/help/2389418/secure-loading-of-libraries-to-prevent-dll-preloading-attacks)


-------------------------------
## Deobfuscate/Decode File or Information
* [Deobfuscate/Decode Files or Information - ATT&CK](https://attack.mitre.org/wiki/Technique/T1140)
	* Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware, Scripting, PowerShell, or by using utilities present on the system. One such example is use of certutil to decode a remote access tool portable executable file that has been hidden inside a certificate file.Malwarebytes Targeted Attack against Saudi Arabia
* [Obfuscation - Wikipedia](https://en.wikipedia.org/wiki/Obfuscation_(software))





-------------------------------
## Disabling Security Tools
* [Disabling Security Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1089)
	* Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting. 

#### Windows
* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
	* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.




-------------------------------
## Exploitation of Vulnerability
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068) 
	* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.Technet MS14-068ADSecurity Detecting Forged Tickets


----------------
## Extra Window Memory Injection
* [Extra Window Memory Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1181)
	* Before creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data).1 Registration of new windows classes can include a request for up to 40 bytes of extra window memory (EWM) to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value.23
	* Although small, the EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process’s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process’s EWM.
	* Execution granted through EWM injection may take place in the address space of a separate live process. Similar to Process Injection, this may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as WriteProcessMemory and CreateRemoteThread.4 More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process

#### Windows
* [PowerLoader Injection – Something truly amazing - malwaretech](https://www.malwaretech.com/2013/08/powerloader-injection-something-truly.html)



-------------------------------
## File Deletion
* [File Deletion - ATT&CK](https://attack.mitre.org/wiki/Technique/T1107)
	* Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process. 

#### Linux
* [rm(1) - Linux man page](https://linux.die.net/man/1/rm)
* [Linux / UNIX: Delete a file - nixcraft](https://www.google.com/search?q=linux+clear+history&ie=utf-8&oe=utf-8)

#### Windows
* [del - ss64](https://ss64.com/nt/del.html)
* [Del - msdn](https://technet.microsoft.com/en-us/library/cc771049(v=ws.11).aspx)





-------------------------------
## File System Logical Offsets
* [File System Logical Offsets - ATT&CK](https://attack.mitre.org/wiki/Technique/T1006)
* Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools.Hakobyan 2009 Utilities, such as NinjaCopy, exist to perform these actions in PowerShell.Github PowerSploit Ninjacopy

#### Windows
* [File System Logical Offsets - ATT&CK](https://attack.mitre.org/wiki/Technique/T1006)
	* Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools. Utilities, such as NinjaCopy, exist to perform these actions in PowerShell.
* [FDump - Dumping File Sectors Directly from Disk using Logical Offsets](https://www.codeproject.com/Articles/32169/FDump-Dumping-File-Sectors-Directly-from-Disk-usin)
* [Invoke-NinjaCopy.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)


----------------------------- 
## Gatekeeper Bypass (OS X)
* [Gatekeeper Bypass- ATT&CK](https://attack.mitre.org/wiki/Technique/T1144)
	* In macOS and OS X, when applications or programs are downloaded from the internet, there is a special attribute set on the file called com.apple.quarantine. This attribute is read by Apple's Gatekeeper defense program at execution time and provides a prompt to the user to allow or deny execution.
	* Apps loaded onto the system from USB flash drive, optical disk, external hard drive, or even from a drive shared over the local network won’t set this flag. Additionally, other utilities or events like drive-by downloads don’t necessarily set it either. This completely bypasses the built-in Gatekeeper check1. The presence of the quarantine flag can be checked by the xattr command `xattr /path/to/MyApp.app for com.apple.quarantine`. Similarly, given sudo access or elevated permission, this attribute can be removed with xattr as well, sudo xattr -r -d com.apple.quarantine /path/to/MyApp.app.
	* In typical operation, a file will be downloaded from the internet and given a quarantine flag before being saved to disk. When the user tries to open the file or application, macOS’s gatekeeper will step in and check for the presence of this flag. If it exists, then macOS will then prompt the user to confirmation that they want to run the program and will even provide the url where the application came from. However, this is all based on the file being downloaded from a quarantine-savvy application . 
* [OS X: About Gatekeeper](https://support.apple.com/en-us/HT202491)
* [Last-minute paper: Exposing Gatekeeper - Patrick Wardle](https://www.virusbulletin.com/conference/vb2015/abstracts/exposing-gatekeeper)
* ['Untranslocating' an App >apple broke some of my apps - let's show how to fix them!](https://objective-see.com/blog/blog_0x15.html)
* [OS X Gatekeeper Bypass Vulnerability - Amplia Security2015](http://www.ampliasecurity.com/advisories/os-x-gatekeeper-bypass-vulnerability.html)



-------------------------------
## Hidden Files and Directories
* [Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
	* To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS). 

#### Linux 
* MITRE
	* Users can mark specific files as hidden simply by putting a “.” as the first character in the file or folder name Sofacy Komplex TrojanAntiquated Mac Malware. Files and folder that start with a period, ‘.’, are by default hidden from being viewed in the Finder application and standard command-line utilities like “ls”. Users must specifically change settings to have these files viewable. For command line usages, there is typically a flag to see all files (including hidden ones). To view these files in the Finder Application, the following command must be executed: defaults write com.apple.finder AppleShowAllFiles YES, and then relaunch the Finder Application. 
* [Hide files in Linux without using the dot - SuperUser](https://superuser.com/questions/359784/hide-files-in-linux-without-using-the-dot)

#### OS X
* MITRE
	* Files on macOS can be marked with the UF_HIDDEN flag which prevents them from being seen in Finder.app, but still allows them to be seen in Terminal.appWireLurker. Many applications create these hidden files and folders to store information so that it doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder that’s hidden and contains the user’s known hosts and keys. 
	*  Adversaries can use this to their advantage to hide files and folders anywhere on the system for persistence and evading a typical user or system analysis that does not incorporate investigation of hidden files.
* Files and Folders with a `.` in front of them will remain hidden by default; Can use `Shift+CMD+.` to enable/disable.
* [chflags - SS64](https://ss64.com/osx/chflags.html)

#### Windows
* Users can mark specific files as hidden by using the attrib.exe binary. Simply do attrib +h filename to mark a file or folder as hidden. Similarly, the “+s” marks a file as a system file and the “+r” flag marks the file as read only. Like most windows binaries, the attrib.exe binary provides the ability to apply these changes recursively “/S”. 
* [What is a Hidden File?](https://www.lifewire.com/what-is-a-hidden-file-2625898)






------------------------------- 
## Hidden Users (OS X)
* [Hidden Users - ATT&CK](https://attack.mitre.org/wiki/Technique/T1147)
	* Every user account in macOS has a userID associated with it. When creating a user, you can specify the userID for that account. There is a property value in /Library/Preferences/com.apple.loginwindow called Hide500Users that prevents users with userIDs 500 and lower from appearing at the login screen. By using the Create Account technique with a userID under 500 and enabling this property (setting it to Yes), an adversary can hide their user accounts much more easily: sudo dscl . -create /Users/username UniqueID 401. 
* [Hide a user account in macOS - support.apple](https://support.apple.com/en-us/HT203998)
* [How to add hidden user - StackOverflow](https://apple.stackexchange.com/questions/174433/how-to-add-hidden-user)
* `sudo dscl . create /Users/USERNAME IsHidden 1`





------------------------------- 
## Hidden Window
* [Hidden Window - ATT&CK](https://attack.mitre.org/wiki/Technique/T1143)
	* The configurations for how applications run on macOS and OS X are listed in property list (plist) files. One of the tags in these files can be apple.awt.UIElement, which allows for Java applications to prevent the application's icon from appearing in the Dock. A common use for this is when applications run in the system tray, but don't also want to show up in the Dock. However, adversaries can abuse this feature and hide their running window.


------------------------------- 
## HISTCONTROL (Linux)
* [HISTCONTROL - ATT&CK](https://attack.mitre.org/wiki/Technique/T1148)
	* The HISTCONTROL environment variable keeps track of what should be saved by the history command and eventually into the ~/.bash_history file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to "ignorespace". HISTCONTROL can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history. HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected. Adversaries can use this to operate without leaving traces by simply prepending a space to all of their terminal commands. 
* [15 Examples To Master Linux Command Line History](http://www.thegeekstuff.com/2008/08/15-examples-to-master-linux-command-line-history/)


---------------------------
## Image File Execution Options Injection
* [Image File Execution Options Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1183)
	* Image File Execution Options (IFEO) enable a developer to attach a debugger to an application. When a process is created, any executable file present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., `“C:\dbg\ntsd.exe -g notepad.exe”)`.
	* IFEOs can be set directly via the Registry or in Global Flags via the Gflags tool.2 IFEOs are represented as Debugger Values in the Registry under `*HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options/<executable> and HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable>` where `<executable>` is the binary on which the debugger is attached.
	* Similar to Process Injection, this value can be abused to obtain persistence and privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. Installing IFEO mechanisms may also provide Persistence via continuous invocation.
	* Malware may also use IFEO for Defense Evasion by registering invalid debuggers that redirect and effectively disable various system and security applications.

#### Windows
* [Image File Execution Options (IFEO) - blogs.msdn](https://blogs.msdn.microsoft.com/mithuns/2010/03/24/image-file-execution-options-ifeo/)





-------------------------------
## Indicator Blocking
* [Indicator Blocking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1054)
	* An adversary may attempt to block indicators or events from leaving the host machine. In the case of network-based reporting of indicators, an adversary may block traffic associated with reporting to prevent central analysis. This may be accomplished by many means, such as stopping a local process or creating a host-based firewall rule to block traffic to a specific server. 


-------------------------------
## Indicator Removal from Tools
* [Indicator Removal from Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1066)
	* If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems. A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use Software Packing or otherwise modify the file so it has a different signature, and then re-use the malware. 




-------------------------------
## Indicator Removal on Host
* [Indicator Removal on Host - ATT&CK](https://attack.mitre.org/wiki/Technique/T1070)
	* Adversaries may delete or alter generated event files on a host system, including potentially captured files such as quarantined malware. This may compromise the integrity of the security solution, causing events to go unreported, or make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred.

#### Windows
* [Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)





-------------------------------
## Install Root Certificate
* [Install Root Certifcate](https://attack.mitre.org/wiki/Technique/T1130)
	* Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate.Wikipedia Root Certificate Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website. 
	* Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system. Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials.Operation Emmental 
	*  Atypical root certificates have also been pre-installed on systems by the manufacturer or in the software supply chain and were used in conjunction with malware/adware to provide a man-in-the-middle capability for intercepting information transmitted over secure TLS/SSL communications.Kaspersky Superfish

#### Linux
* [How do I install a root certificate? - StackOverflow](https://askubuntu.com/questions/73287/how-do-i-install-a-root-certificate)

#### OS X

#### Windows
* [Install Root Certificate - ATT&CK](https://attack.mitre.org/wiki/Technique/T1130)
* [Root certificate - Wikipedia](https://en.wikipedia.org/wiki/Root_certificate)
* [HTTP Public Key Pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)
* [Manage Trusted Root Certificates - msdn](https://technet.microsoft.com/en-us/library/cc754841(v=ws.11).aspx)
* [Installing a root certificate - msdn](https://msdn.microsoft.com/en-us/library/cc750534.aspx)





-------------------------------
## InstallUtil
* [InstallUtil - ATT&CK](https://attack.mitre.org/wiki/Technique/T1118)
	* InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries.MSDN InstallUtil InstallUtil is located in the .NET directory on a Windows system: C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe.InstallUtil.exe is digitally signed by Microsoft. Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil may also be used to bypass process whitelisting through use of attributes within the binary that execute the class decorated with the attribute [System.ComponentModel.RunInstaller(true)].

#### Windows
* [InstallUtil - ATT&CK](https://attack.mitre.org/wiki/Technique/T1118)
	* InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries.1 InstallUtil is located in the .NET directory on a Windows system: C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe.InstallUtil.exe is digitally signed by Microsoft. 
* [Installutil.exe (Installer Tool) - MSDN](https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool)
	* [AllTheThings](https://github.com/subTee/AllTheThings)
	* Includes 5 Known Application Whitelisting/ Application Control Bypass Techniques in One File. (First one is InstallUtil)



------------------------------- 
## LC_MAIN Hijacking
#### OS X
* [LC_MAIN Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1149)
	* As of OS X 10.8, mach-O binaries introduced a new header called LC_MAIN that points to the binary’s entry point for execution. Previously, there were two headers to achieve this same effect: LC_THREAD and LC_UNIXTHREAD. The entry point for a binary can be hijacked so that initial execution flows to a malicious addition (either another section or a code cave) and then goes back to the initial entry point so that the victim doesn’t know anything was different 2. By modifying a binary in this way, application whitelisting can be bypassed because the file name or application path is still the same. 
* [Methods Of Malware Persistence On Mac OS X](https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf)


------------------------------- 
## Launchctl
* [Launchctl - ATT&CK](https://attack.mitre.org/wiki/Technique/T1152)
	* Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made Sofacy Komplex Trojan. Running a command from launchctl is as simple as `launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg"`. Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges. Adversaries can abuse this functionality to execute code or even bypass whitelisting if launchctl is an allowed process.

#### OS X
* [launchd tutorial](http://www.launchd.info/)
* [Creating Launch Daemons and Agents - developer.apple](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)





-------------------------------
## Masquerading (Trusted Name/Path Execution Abuse)
* [Masquerading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1036)
	* Masquerading occurs when an executable, legitimate or malicious, is placed in a commonly trusted location (such as C:\Windows\System32) or named with a common name (such as "explorer.exe" or "svchost.exe") to bypass tools that trust executables by relying on file name or path. An adversary may even use a renamed copy of a legitimate utility, such as rundll32.exe. Masquerading also may be done to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate. 

#### Linux
* Think Shell Scripts that call out to services/items; Cron Jobs; 

#### OS X 
* [Platypus](http://www.sveinbjorn.org/platypus)
	* Platypus is a Mac OS X developer tool that creates native Mac applications from interpreted scripts such as shell scripts or Perl, Ruby and Python programs. This is done by wrapping the script in an application bundle along with a native executable binary that runs the script.

#### Windows
* [Metasploit Module - Windows Service Trusted Path Privilege Escalation](https://www.rapid7.com/db/modules/exploit/windows/local/trusted_service_path)
* [Unquoted Service Path - pentestlab.blog](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
* [Practical Guide to exploiting the unquoted service path vulnerability in Windows - trustfoundry](https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/)




-------------------------------
## Modify Registry
* [Modify Registry - ATT&CK](https://attack.mitre.org/wiki/Technique/T1112)
	* Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in Persistence and Execution. 
	* Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility Reg may be used for local or remote Registry modification.Microsoft Reg Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API (see examples). 
	*  The Registry of a remote system may be modified to aid in execution of files as part of Lateral Movement. It requires the remote Registry service to be running on the target system.Microsoft Remote Often Valid Accounts are required, along with access to the remote system's Windows Admin Shares for RPC communication.

#### Windows
* [Modify Registry - ATT&CK](https://attack.mitre.org/wiki/Technique/T1112)
* [Reg - MSDN](https://technet.microsoft.com/en-us/library/cc732643.aspx)
* [Enable the Remote Registry Service - MSDN](https://technet.microsoft.com/en-us/library/cc754820.aspx)




-------------------------------
## NTFS Extended Attributes & Alternate Data Streams
* [NTFS Extended Attributes - ATT&CK](https://attack.mitre.org/wiki/Technique/T1096)
	* Data or executables may be stored in New Technology File System (NTFS) partition metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus.Journey into IR ZeroAccess NTFS EA The NTFS format has a feature called Extended Attributes (EA), which allows data to be stored as an attribute of a file or folder.Microsoft File Streams


#### Windows
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





-------------------------------
## Network Share Connection Removal
* [Network Share Connection Removal - ATT&CK](https://attack.mitre.org/wiki/Technique/T1126)
	* Windows shared drive and Windows Admin Shares connections can be removed when no longer needed. Net is an example utility that can be used to remove network share connections with the `net use \\system\share /delete` command. Use Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation.

#### Windows
* [Network Share Connection Removal - ATT&CK](https://attack.mitre.org/wiki/Technique/T1126)
	* Windows shared drive and Windows Admin Shares connections can be removed when no longer needed. Net is an example utility that can be used to remove network share connections with the net use \\system\share /delete command. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. 
* [Net use - technet](https://technet.microsoft.com/en-us/bb490717.aspx)






-------------------------------
## Obfuscated Files or Information
* [Obfuscated Files or Information - ATT&CK](https://attack.mitre.org/wiki/Technique/T1027)
	* Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system.






------------------------------- 
## Plist Modification
* [Plist Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1150)
	* Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UT-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as /Library/Preferences (which execute with elevated privileges) and `~/Library/Preferences` (which execute with a user's privileges). Adversaries can modify these plist files to point to their own code, can use them to execute their code in the context of another user, bypass whitelisting procedures, or even use them as a persistence mechanismSofacy Komplex Trojan.

#### OS X



-------------------------------
## Process Hollowing
* [Process Hollowing](https://attack.mitre.org/wiki/Technique/T1093)
	* Process hollowing occurs when a process is created in a suspended state and the process's memory is replaced with the code of a second program so that the second program runs instead of the original program. Windows and process monitoring tools believe the original process is running, whereas the actual program running is different.Leitch Hollowing Process hollowing may be used similarly to DLL Injection to evade defenses and detection analysis of malicious process execution by launching adversary-controlled code under the context of a legitimate process.

#### Windows
* [Process Hollowing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1093)
	* Process hollowing occurs when a process is created in a suspended state and the process's memory is replaced with the code of a second program so that the second program runs instead of the original program. Windows and process monitoring tools believe the original process is running, whereas the actual program running is different. Process hollowing may be used similarly to DLL Injection to evade defenses and detection analysis of malicious process execution by launching adversary-controlled code under the context of a legitimate process. 
* [Process Hollowing - John Leitch - PDF](http://www.autosectools.com/process-hollowing.pdf)
	* [Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
	* Great explanation of Process Hollowing (a Technique often used in Malware) 



-------------------------------
## Process Injection
* [Process Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1055)
	* Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. 


#### Linux & OS X
* Implementations for Linux and OS X/macOS systems include:
	* LD_PRELOAD, LD_LIBRARY_PATH (Linux), DYLD_INSERT_LIBRARIES (Mac OS X) environment variables, or the dlfcn application programming interface (API) can be used to dynamically load a library (shared object) in a process which can be used to intercept API calls from the running process.
	* Ptrace system calls can be used to attach to a running process and modify it in runtime.
	* /proc/[pid]/mem provides access to the memory of the process and can be used to read/write arbitrary data to it. This technique is very rare due to its complexity.
	* VDSO hijacking performs runtime injection on ELF binaries by manipulating code stubs mapped in from the linux-vdso.so shared object.
* Malware commonly utilizes process injection to access system resources through which Persistence and other environment modifications can be made. More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel.
 

#### Windows
There are multiple approaches to injecting code into a live process. Windows implementations include:
	* Dynamic-link library (DLL) injection involves writing the path to a malicious DLL inside a process then invoking execution by creating a remote thread.
	* Portable executable injection involves writing malicious code directly into the process (without a file on disk) then invoking execution with either additional code or by creating a remote thread. The displacement of the injected code introduces the additional requirement for functionality to remap memory references. Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue.
	* Thread execution hijacking involves injecting malicious code or the path to a DLL into a thread of a process. Similar to Process Hollowing, the thread must first be suspended.
	* Asynchronous Procedure Call (APC) injection involves attaching malicious code to the APC Queue3 of a process's thread. Queued APC functions are executed when the thread enters an alterable state. AtomBombing  is a variation that utilizes APCs to invoke malicious code previously written to the global atom table.
	* Thread Local Storage (TLS) callback injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point.


-------------------------------
## Redundant Access 
* [Redundant Access - ATT&CK](https://attack.mitre.org/wiki/Technique/T1108)
	* Adversaries may use more than one remote access tool with varying command and control protocols as a hedge against detection. If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to Valid Accounts to use External Remote Services such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.




-------------------------------
## Regsvcs/Regasm
* [Regsvcs/Regasm - ATT&CK](https://attack.mitre.org/wiki/Technique/T1121)
	* Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft.MSDN RegsvcsMSDN Regasm Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: `[ComRegisterFunction]` or `[ComUnregisterFunction]` respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute.

#### Windows
* [Regsvcs/Regasm - ATT&CK](https://attack.mitre.org/wiki/Technique/T1121)
	* Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: [ComRegisterFunction] or [ComUnregisterFunction] respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute
* [Regsvcs.exe (.NET Services Installation Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool)
* [Regasm.exe (Assembly Registration Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool)





-------------------------------
## Regsvr32
* [Regsvr32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1117)
	* Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries.Microsoft Regsvr32 
	* Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary. 
	* Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed.SubTee Regsvr32 Whitelisting Bypass This variation of the technique has been used in campaigns targeting governments.FireEye Regsvr32 Targeting Mongolian Gov

#### Windows
* [How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages](https://support.microsoft.com/en-us/help/249873/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages)
* [How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)
* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files) - subTee](http://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html)
* [Practical use of JavaScript and COM Scriptlets for Penetration Testing](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)


-------------------------------
## Rootkit
* [Rootkit - ATT&CK](https://attack.mitre.org/wiki/Technique/T1014)
	* Rootkits are programs that hide the existence of malware by intercepting and modifying operating system API calls that supply system information. Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a Hypervisor, Master Boot Record, or the System Firmware.Wikipedia Rootkit Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.

#### Linux

#### OS X

#### Windows



------------------------------
## Rundll32
* [Rundll32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1085)
	* The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations. 

#### Windows
* [Rundll32 - technet](https://technet.microsoft.com/en-us/library/ee649171(v=ws.11).aspx)
* [AppLocker Bypass – Rundll32 - pentesterlab](https://pentestlab.blog/tag/rundll32/)
 	

-------------------------------
## Scripting
* [Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
	* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts. 

#### Linux
* [BASH Programming - Introduction HOW-TO - tldp](http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html)
* [Advanced Bash-Scripting Guide - tldp](http://tldp.org/LDP/abs/html/)
* [Bash Shell Scripting - Wikibooks](https://en.wikibooks.org/wiki/Bash_Shell_Scripting)

#### OS X
* [Introduction to AppleScript Language Guide](https://developer.apple.com/library/content/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html)
* [osascript - SS64](https://ss64.com/osx/osascript.html)

#### Windows
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




-------------------------------
## Software Packing
* [Software Packing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1045)
	* Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. 
* [Executable compression - Wikipedia](https://en.wikipedia.org/wiki/Executable_compression)
* [UPX](https://upx.github.io/)
* [Basic Packers: Easy As Pie ](https://www.trustwave.com/Resources/SpiderLabs-Blog/Basic-Packers--Easy-As-Pie/)



------------------------------- 
## Spaces after Filename 
* [Spaces after Filename - ATT&CK](https://attack.mitre.org/wiki/Technique/T1151)
	* Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system. For example, if there is a Mach-O executable file called evil.bin, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to evil.txt, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to "evil.txt " (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed.

#### Linux



-------------------------------
## Timestomp
* [Timestomp - ATT&CK](https://attack.mitre.org/wiki/Technique/T1099)
	* Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools. Timestomping may be used along with file name Masquerading to hide malware and tools.

#### Linux
* [Bash - Timestomping Linux Files](http://64bit.ca/code/bash-timestomping-linux-files/)
* [Timestomp - Forensics Wiki](http://www.forensicswiki.org/wiki/Timestomp)
* [Linux Timestamps, Oh boy!](https://articles.forensicfocus.com/2015/08/25/linux-timestamps-oh-boy/)

#### OS X

#### Windows



------------------------------
## Trusted Developer Utilites
* [Trusted Developer Utilities - ATT&CK](https://attack.mitre.org/wiki/Technique/T1127)
	* There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application whitelisting defensive solutions. 

#### Windows
### MSBuild
* MITRE
	* MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It takes XML formatted project files that define requirements for building various platforms and configurations. Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into the XML project file.2 MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application whitelisting defenses that are configured to allow MSBuild.exe execution.
* [MSBuild - MSDN](https://msdn.microsoft.com/library/dd393574.aspx)
* [MSBuild Inline Tasks - msdn](https://msdn.microsoft.com/library/dd722601.aspx)
* [MSBuild Inline Tasks - docs ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks)
* [AppLocker Bypass – MSBuild - pentestlab](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)

### DNX
* MITRE
	* The .NET Execution Environment (DNX), dnx.exe, is a software development kit packaged with Visual Studio Enterprise. It was retired in favor of .NET Core CLI in 2016.4 DNX is not present on standard builds of Windows and may only be present on developer workstations using older versions of .NET Core and ASP.NET Core 1.0. The dnx.exe executable is signed by Microsoft. An adversary can use dnx.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for DNX. 
* [Migrating from DNX to .NET Core CLI (project.json) - docs ms](https://docs.microsoft.com/en-us/dotnet/core/migration/from-dnx)
* [Bypassing Application Whitelisting By Using dnx.exe - enigma0x3](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)



### RCSI
* MITRE
	* The rcsi.exe utility is a non-interactive command-line interface for C# that is similar to csi.exe. It was provided within an early version of the Roslyn .NET Compiler Platform but has since been deprecated for an integrated solution. The rcsi.exe binary is signed by Microsoft. C# .csx script files can be written and executed with rcsi.exe at the command-line. An adversary can use rcsi.exe to proxy execution of arbitrary code to bypass application whitelisting policies that do not account for execution of rcsi.exe.
* [Introducing the Microsoft “Roslyn” CTP](https://blogs.msdn.microsoft.com/visualstudio/2011/10/19/introducing-the-microsoft-roslyn-ctp/)
* [Bypassing Application Whitelisting By Using rcsi.exe - enigma0x3](https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/)


### WinDbg/CDB
* MITRE
	* WinDbg is a Microsoft Windows kernel and user-mode debugging utility. The Microsoft Console Debugger (CDB) cdb.exe is also user-mode debugger. Both utilities are included in Windows software development kits and can be used as standalone tools. They are commonly used in software development and reverse engineering and may not be found on typical Windows systems. Both WinDbg.exe and cdb.exe binaries are signed by Microsoft. An adversary can use WinDbg.exe and cdb.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for execution of those utilities. It is likely possible to use other debuggers for similar purposes, such as the kernel-mode debugger kd.exe, which is also signed by Microsoft. 
* [Debugging Tools for Windows (WinDbg, KD, CDB, NTSD) -docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/index)
* [Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner - exploitmonday](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)


--------------------
## Valid Accounts
* [Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
	* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence. Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful. The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.
	
#### Linux
* ```cat /etc/passwd```
* ```cat /etc/shadow```


#### OS X
* [osascript - SS64](https://ss64.com/osx/osascript.html)
also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.
	* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.
	* The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.
* `dscl . list /Users`

#### Windows
* [Attractive Accounts for Credential Theft - docs ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/attractive-accounts-for-credential-theft)