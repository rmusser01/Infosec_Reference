# Privlege Escalation

[MITRE ATT&CK - Privilege Escalation](https://attack.mitre.org/wiki/Privilege_Escalation)

-------------------------------
## Access Token Manipulation
* [Access Token Manipulation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1134)
	* Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token. For example, Microsoft promotes the use of access tokens as a security best practice. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas. Microsoft runas 
	* Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection. An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level.Pentestlab Token Manipulation 
	* Adversaries can also create spoofed access tokens if they know the credentials of a user. Any standard user can use the runas command, and the Windows API functions, to do this; it does not require access to an administrator account. 
	* Lastly, an adversary can use a spoofed token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system. 
	*  Metasploit’s Meterpreter payload allows arbitrary token stealing and uses token stealing to escalate privileges. Metasploit access token The Cobalt Strike beacon payload allows arbitrary token stealing and can also create tokens. Cobalt Strike Access Token

#### Windows
* [LogonUser function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx)
	* The LogonUser function attempts to log a user on to the local computer. The local computer is the computer from which LogonUser was called. You cannot use LogonUser to log on to a remote computer. You specify the user with a user name and domain and authenticate the user with a plaintext password. If the function succeeds, you receive a handle to a token that represents the logged-on user. You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.
* [Token Manipulation - Pentestlab](https://pentestlab.blog/2017/04/03/token-manipulation/)
* [Fun with Incognito](https://www.offensive-security.com/metasploit-unleashed/fun-incognito/)
* [Windows Access Tokens and Alternate Credentials -cobaltstrike](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
* [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
	* [RottenPotato tool](https://github.com/foxglovesec/RottenPotato)
* [PowerShell and Token Impersonation](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)
* [Account Hunting for Invoke-TokenManipulation](https://www.trustedsec.com/2015/01/account-hunting-invoke-tokenmanipulation/)
* [Abusing Token Privileges For LPE - drone/breenmachine](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)





-------------------------------
## Accessibility Features
* [Accessibility Features - ATT&CK](https://attack.mitre.org/wiki/Technique/T1015)
	* Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.
	* Two common accessibility programs are C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times and C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen.FireEye Hikit Rootkit
	* Depending on the version of Windows, an adversary may take advantage of these features in different ways because of code integrity enhancements. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in %systemdir%\, and it must be protected by Windows File or Resource Protection (WFP/WRP).DEFCON2016 Sticky Keys The debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced. Examples for both methods:
	* For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., C:\Windows\System32\utilman.exe) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over Remote Desktop Protocol will cause the replaced file to be executed with SYSTEM privileges.Tilbury 2014
	* For the debugger method on Windows Vista and later as well as Windows Server 2008 and later, for example, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for the accessibility program (e.g., "utilman.exe"). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with RDP will cause the "debugger" program to be executed with SYSTEM privileges.Tilbury 2014
	* Other accessibility features exist that may also be leveraged in a similar fashion:DEFCON2016 Sticky Keys
	* ```
	    On-Screen Keyboard: C:\Windows\System32\osk.exe
	    Magnifier: C:\Windows\System32\Magnify.exe
	    Narrator: C:\Windows\System32\Narrator.exe
	    Display Switcher: C:\Windows\System32\DisplaySwitch.exe
	    App Switcher: C:\Windows\System32\AtBroker.exe
	```

#### Windows
* [Sticky Keys to the Kingdom](https://www.slideshare.net/DennisMaldonado5/sticky-keys-to-the-kingdom)
* [Walk through of making such a backdoor by crowdstrike](https://www.crowdstrike.com/blog/crowdresponse-windows-sticky-keys/)
* [Privilege Escalation via "Sticky" Keys](http://carnal0wnage.attackresearch.com/2012/04/privilege-escalation-via-sticky-keys.html)



-------------------------------
## AppInit DLLs
* [AppInit DLLs - ATT&CK](https://attack.mitre.org/wiki/Technique/T1103)
	* DLLs that are specified in the AppInit_DLLs value in the Registry key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program. This value can be abused to obtain persistence by causing a DLL to be loaded into most processes on the computer.AppInit Registry The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled.AppInit Secure Boot

#### Windows
* [Working with the AppInit_DLLs registry value](https://support.microsoft.com/en-us/help/197571/working-with-the-appinit-dlls-registry-value)
	* (All the DLLs that are specified in this value are loaded by each Microsoft Windows-based application that is running in the current log on session.)
* [LoadDLLViaAppInit - Didier Stevens](https://blog.didierstevens.com/2009/12/23/loaddllviaappinit/)
	* Selectively Load DLLs with AppInit 
* [AppInit DLLs and Secure Boot](https://msdn.microsoft.com/en-us/library/dn280412)






-------------------------------
## Application Shimming
* [Application Shimming - ATT&CK](https://attack.mitre.org/wiki/Technique/T1138)
	* The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow compatibility of programs as Windows updates and changes its code. For example, application shimming feature that allows programs that were created for Windows XP to work with Windows 10. Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses API hooking to redirect the code as necessary in order to communicate with the OS. A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in: 
		* `%WINDIR%\AppPatch\sysmain.sdb`
    	* `hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb`
    * Custom databases are stored in: 
    	* `%WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom`
    	* `hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom`
    *  To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to Bypass User Account Control (UAC) (RedirectEXE), inject DLLs into processes (InjectDll), and intercept memory addresses (GetProcAddress). Utilizing these shims, an adversary can perform several malicious acts, such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc.

#### Windows
* [Understanding Shims](https://technet.microsoft.com/en-us/library/dd837644(v=ws.10).aspx)
* [Secrets of the Application Compatilibity Database (SDB) – Part 1](http://www.alex-ionescu.com/?p=39)
* [Secrets of the Application Compatilibity Database (SDB) – Part 2](http://www.alex-ionescu.com/?p=40)
* [Secrets of the Application Compatilibity Database (SDB) – Part 3](http://www.alex-ionescu.com/?p=41)
* [Secrets of the Application Compatilibity Database (SDB) – Part 4](http://www.alex-ionescu.com/?p=43)
* [Malicious Application Compatibility Shims](https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims-wp.pdf)
* [Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)
* [Windows 0wn3d By Default - Mark Baggett - Derbycon 2013](http://www.irongeek.com/i.php?page=videos/derbycon3/4206-windows-0wn3d-by-default-mark-baggett)
	* Description: “In this talk we will discuss API Hooking, Process Execution Redirection, Hiding Registry keys and hiding directories on the hard drive. We must be talking about rootkits, right? Well yes, but not in the way you think. The Windows family of operating systems has all of these capabilities built right in! Using nothing but tools and techniques distributed and documented by Microsoft we can implement all of these rootkit functions. During this exciting talk I will present new attacks against Windows operating system that provide rootkit like functionality with built-in OS tools. In session, we’ll demonstrate how to leverage the Microsoft Application Compatibility Toolkit to help hide an attacker’s presence on your system. The Application Compatibility Toolkit allows you to create application shims that intercept and redirect calls from applications to the operating system. This native rootkit like capability is intended to make the Windows operating system compatible with very old or poorly written applications. Do DEP, ASLR, UAC, and Windows Resource Protection, File system ACLS and other modern OS security measures get it your way? No problem. Turn them off! Do you want to hide files and registry keys and from the user? The Application Compatibility toolkit allows you to create a virtual world for any application and hide resources from view. If someone inspects the registry with regedit they will see exactly what the attacker wants them to see and not what the OS sees when it launches programs. Did they patch your target so your exploit doesn’t work? Guess what, making applications backwards compatible is what this tool is intended to do. Make your favorite applications “old exploit compatible” insuring you can re-exploit the target with this awesome untapped resource. Everything you need to subvert windows applications is built right into the windows kernel. Come learn how to use the application compatibility toolkit to tap this great resource.”
* [Shackles, Shims, and Shivs - Understanding Bypass Techniques](http://www.irongeek.com/i.php?page=videos/derbycon6/535-shackles-shims-and-shivs-understanding-bypass-techniques-mirovengi)



-------------------------------
## Bypass User Account Control
* [Bypass User Account Control - ATT&CK](https://attack.mitre.org/wiki/Technique/T1088)
	* Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.TechNet How UAC Works 
	* If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs are allowed to elevate privileges or execute some elevated COM objects without prompting the user through the UAC notification box.TechNet Inside UACMSDN COM Elevation An example of this is use of rundll32.exe to load a specifically crafted DLL which loads an auto-elevated COM object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.Davidson Windows Adversaries can use these techniques to elevate privileges to administrator if the target process is unprotected. 
	* Many methods have been discovered to bypass UAC. The Github readme page for UACMe contains an extensive list of methodsGithub UACMe that have been discovered and implemented within UACMe, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as: 
		* `eventvwr.exe` can auto-elevate and execute a specified binary or script.enigma0x3 Fileless UAC BypassFortinet Fareit
	* Another bypass is possible through some Lateral Movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on lateral systems and default to high integrity.SANS UAC Bypass


#### Windows
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
## DLL Injection
* [DLL Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1055)
	* DLL injection is used to run code in the context of another process by causing the other process to load and execute code. Running code in the context of another process provides adversaries many benefits, such as access to the process's memory and permissions. It also allows adversaries to mask their actions under a legitimate process. A more sophisticated kind of DLL injection, reflective DLL injection, loads code without calling the normal Windows API calls, potentially bypassing DLL load monitoring. Numerous methods of DLL injection exist on Windows, including modifying the Registry, creating remote threads, Windows hooking APIs, and DLL pre-loading.CodeProject Inject CodeWikipedia DLL Injection

#### Windows
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
* [Dynamic-Link Library Search Order](https://msdn.microsoft.com/en-US/library/ms682586)




## Dylib Hijacking
---------------
* [Dylib Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1157)
	* macOS and OS X use a common method to look for required dynamic libraries (dylib) to load into a program based on search paths. Adversaries can take advantage of ambiguous paths to plant dylibs to gain privilege escalation or persistence. 
	* A common method is to see what dylibs an application uses, then plant a malicious version with the same name higher up in the search path. This typically results in the dylib being in the same folder as the application itselfWriting Bad Malware for OSXMalware Persistence on OS X. 
	* If the program is configured to run at a higher privilege level than the current user, then when the dylib is loaded into the application, the dylib will also run at that elevated level. This can be used by adversaries as a privilege escalation technique.	

#### OS X
* [Dylib Hijacking on OS X](https://www.virusbtn.com/pdf/magazine/2015/vb201503-dylib-hijacking.pdf)





-------------------------------
## Exploitation of Vulnerability
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
	* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.Technet MS14-068ADSecurity Detecting Forged Tickets

#### Linux
* [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
	* Shell script to check for simple privilege escalation vectors on Unix systems. Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases).
* [LinEnum](https://github.com/rebootuser/LinEnum)
	* Scripted Local Linux Enumeration & Privilege Escalation Checks
* [linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)
	* linux-exploit-suggester.sh was inspired by the excellent Linux_Exploit_Suggester script by PenturaLabs. The issue with Pentura's script however is that it isn't up to date anymore (the script was last updated in early 2014) so it lacks some recent Linux kernel exploits. linux-exploit-suggester.sh on the other hand also contains all the latest (as of early 2017) publicly known Linux kernel exploits. It is also capable to identify possible privilege escalation vectors via installed userspace packages and comes with some additional minor features that makes finding right exploit more time efficient.
* [cve-check-tool - Intel](https://github.com/clearlinux/cve-check-tool)
	* Original Automated CVE Checking Tool
* [Linux Kernel Exploitation - xairy github](https://github.com/xairy/linux-kernel-exploitation)
* [Vuls: Vulnerability Scanner](https://github.com/future-architect/vuls)
	* Vulnerability scanner for Linux/FreeBSD, agentless, written in golang.
* [cvechecker](https://github.com/sjvermeu/cvechecker)
	* The goal of cvechecker is to report about possible vulnerabilities on your system, by scanning a list of installed software and matching results with the CVE database. This is not a bullet-proof method and you will have many false positives (ie: vulnerability is fixed with a revision-release, but the tool isn't able to detect the revision itself), yet it is still better than nothing, especially if you are running a distribution with little security coverage.
* [kernel-exploits - xairy](https://github.com/xairy/kernel-exploits)
	* A bunch of proof-of-concept exploits for the Linux kernel

#### OS X
* [physmem](https://github.com/bazad/physmem)
	* physmem is a physical memory inspection tool and local privilege escalation targeting macOS up through 10.12.1. It exploits either CVE-2016-1825 or CVE-2016-7617 depending on the deployment target. These two vulnerabilities are nearly identical, and exploitation can be done exactly the same. They were patched in OS X El Capitan 10.11.5 and macOS Sierra 10.12.2, respectively.
* [macOS High Sierra 10.13.1 insecure cron system](https://m4.rkw.io/blog/macos-high-sierra-10131-insecure-cron-system.html)
	* Easy root
* [Exploiting appliances presentation v1.1](https://www.slideshare.net/NCC_Group/exploiting-appliances-presentation-v11vidsremoved)
* [async_wake](https://github.com/benjibobs/async_wake)
	* async_wake - iOS 11.1.2 kernel exploit and PoC local kernel debugger by @i41nbeer
* [IOHIDeous](https://siguza.github.io/IOHIDeous/)
* [OS X El Capitan - Sinking the S\H/IP - Stefan Esser - Syscan360 - 2016](https://www.syscan360.org/slides/2016_SG_Stefan_Esser_OS_X_El_Capitan_Sinking_The_SHIP.pdf)
* [ZeroNights / Syscan360 2016] Abusing the Mac Recovery & OS Update Process](https://speakerdeck.com/patrickwardle/syscan360-2016-abusing-the-mac-recovery-and-os-update-process)
	* Did you know that Macs contain a secondary OS that sits hidden besides OS X? This talk will initially dive into technical details of the Recovery OS, before showing that while on (newer) native hardware Apple verifies this OS, in virtualized environments this may not be the case. Due to this 'flaw' we'll describe how an attacker can infect a virtualized OS X instance with malware that is able to survive a full OS X restore. Though limited to virtual instances, such malware can also abuse this process install itself into SIP'd locations making disinfection far more difficult. It's also worth noting that this attack likely would succeed on older versions of non-virtualized OS X as well.


#### Windows
* [Windows Exploit Suggester](https://github.com/AJMartel/Windows-Exploit-Suggester)



-------------------------------
## File System Permissions Weakness
* [File System Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1044)
	* Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. 
	* Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence. 
	* Services
		* Manipulation of Windows service binaries is one variation of this technique. Adversaries may replace a legitimate service executable with their own executable to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService). Once the service is started, either directly by the user (if appropriate access is available) or through some other means, such as a system restart if the service starts on bootup, the replaced executable will run instead of the original service executable. 
	* Executable Installers
		*  Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the %TEMP% directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL Search Order Hijacking. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors.Mozilla Firefox Installer DLL HijackSeclists Kanthak 7zip Installer 

#### Windows
* [Executable installers are vulnerable^WEVIL (case 7): 7z.exe allows remote code execution with escalation of privilege](http://seclists.org/fulldisclosure/2015/Dec/34)




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
## Launch Daemon
* [Launch Daemon - ATT&CK](https://attack.mitre.org/wiki/Technique/T1160)
	* Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in /System/Library/LaunchDaemons and /Library/LaunchDaemonsAppleDocs Launch Agent Daemons. These LaunchDaemons have property list files which point to the executables that will be launchedMethods of Mac Malware Persistence. 
	* Adversaries may install a new launch daemon that can be configured to execute at startup by using launchd or launchctl to load a plist into the appropriate directoriesOSX Malware Detection. The daemon name may be disguised by using a name from a related operating system or benign software WireLurker. Launch Daemons may be created with administrator privileges, but are executed under root privileges, so an adversary may also use a service to escalate privileges from administrator to root. 
	*  The plist file permissions must be root:wheel, but the script or program that it points to has no such requirement. So, it is possible for poor configurations to allow an adversary to modify a current Launch Daemon’s executable and gain persistence or Privilege Escalation.

#### OS X






-------------------------------
## Local Port Monitor
* [Local Port Monitor - ATT&CK](https://attack.mitre.org/wiki/Technique/T1013)
	* A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup.AddMonitor This DLL can be located in C:\Windows\System32 and will be loaded by the print spooler service, spoolsv.exe, on boot.Bloxham Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors.Bloxham` The spoolsv.exe process also runs under SYSTEM level permissions. Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM. 

#### Windows
* [AddMonitor function](https://msdn.microsoft.com/en-us/library/dd183341)









-------------------------------
## New Service
* [New Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1050)
	* When operating systems boot up, they can start programs or applications called services that perform background system functions.TechNet Services A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry. Adversaries may install a new service that can be configured to execute at startup by using utilities to interact with services or by directly modifying the Registry. The service name may be disguised by using a name from a related operating system or benign software with Masquerading. Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through Service Execution. 

#### Windows
* [Services](https://technet.microsoft.com/en-us/library/cc772408.aspx)





-------------------------------
### Path Interception
* [Path Interception - ATT&CK](https://attack.mitre.org/wiki/Technique/T1034)
	* Path interception occurs when an executable is placed in a specific path so that it is executed by an application instead of the intended target. One example of this was the use of a copy of cmd in the current working directory of a vulnerable application that loads a CMD or BAT file with the CreateProcess function.TechNet MS14-019 
	* There are multiple distinct weaknesses or misconfigurations that adversaries may take advantage of when performing path interception: unquoted paths, path environment variable misconfigurations, and search order hijacking. The first vulnerability deals with full program paths, while the second and third occur when program paths are not specified. These techniques can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process. 


#### Unqouted Paths
Unquoted Paths
* Service paths (stored in Windows Registry keys)2 and shortcut paths are vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\safe path with space\program.exe"). An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program. 
* [CurrentControlSet\Services Subkey Entries](https://support.microsoft.com/en-us/help/103000/currentcontrolset-services-subkey-entries)
	* This article contains registry entries for the CurrentControlSet\Services subkeys. There are no subgroups.
* [Unquoted Service Paths - commonexploits](https://www.commonexploits.com/unquoted-service-paths/)
* [PrivEsc: Unquoted Service Path - gracefulsecurity](https://www.gracefulsecurity.com/privesc-unquoted-service-path/)
* [Practical Guide to exploiting the unquoted service path vulnerability in Windows - TrustFoundry](https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/)
* [Help eliminate unquoted path vulnerabilities](https://isc.sans.edu/diary/Help+eliminate+unquoted+path+vulnerabilities/14464)



#### PATH Environment Variable Misconfiguration
PATH Environment Variable Misconfiguration
* The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory, %SystemRoot%\system32 (e.g., C:\Windows\system32), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or Python), which will be executed when that command is executed from a script or command-line. 
* For example, if C:\example path precedes C:\Windows\system32 is in the PATH environment variable, a program that is named net.exe and placed in C:\example path will be called instead of the Windows system "net" when "net" is executed from the command-line. 
* [The $env:PATH Less Traveled: Subverting Trust with 3rd-Party Applications - obscuresec](http://obscuresecurity.blogspot.com/2014/02/the-envpath-less-traveled-subverting.html)


#### Search Order Hijacking
Search Order Hijacking
* Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. The search order differs depending on the method that is used to execute the program. However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.
* For example, "example.exe" runs "cmd.exe" with the command-line argument net user. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net user will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT. 
* [WinExec function](https://msdn.microsoft.com/en-us/library/ms687393)
* [Launching Apps from NT cmd shell](https://technet.microsoft.com/en-us/library/cc723564.aspx#XSLTsection127121120120)
* [CreateProcess function](https://msdn.microsoft.com/en-us/library/ms682425)
* [Environment Property](https://msdn.microsoft.com/en-us/library/fd7hxfdd.aspx)







------------------------------- 
## Plist Modification
* [Plist Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1150)
	* Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UT-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as /Library/Preferences (which execute with elevated privileges) and ~/Library/Preferences (which execute with a user's privileges). Adversaries can modify these plist files to point to their own code, can use them to execute their code in the context of another user, bypass whitelisting procedures, or even use them as a persistence mechanismSofacy Komplex Trojan.




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
## Scheduled Tasks
* [Scheduled Tasks - ATT&CK](https://attack.mitre.org/wiki/Technique/T1053)
	* Utilities such as at and schtasks, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. The account used to create the task must be in the Administrators group on the local system. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on.TechNet Task Scheduler Security An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.

#### Windows
* [Schedule a Task - MSDN](https://technet.microsoft.com/en-us/library/cc748993(v=ws.11).aspx)
* [Schtasks.exe - MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/bb736357(v=vs.85).aspx)
	* Enables an administrator to create, delete, query, change, run, and end scheduled tasks on a local or remote computer. Running Schtasks.exe without arguments displays the status and next run time for each registered task.
* [At - MSDN](https://technet.microsoft.com/en-us/library/bb490866.aspx)
	* Schedules commands and programs to run on a computer at a specified time and date. You can use at only when the Schedule service is running. Used without parameters, at lists scheduled commands.
* [How To Use the AT Com------------------------------- 
## Plist Modification
[Plist Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1150)
* Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UT-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as /Library/Preferences (which execute with elevated privileges) and ~/Library/Preferences (which execute with a user's privileges). Adversaries can modify these plist files to point to their own code, can use them to execute their code in the context of another user, bypass whitelisting procedures, or even use them as a persistence mechanism.mand to Schedule Tasks - MS](https://support.microsoft.com/en-us/help/313565/how-to-use-the-at-command-to-schedule-tasks)





-------------------------------
## Service Registry Permissions Weakness
* [Service Registry Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1058)
	* Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through Access Control Lists and permissions.MSDN Registry Key Security If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then adversaries can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

#### Windows
* [Registry Key Security and Access Rights - MSDN](https://msdn.microsoft.com/library/windows/desktop/ms724878.aspx)





## Setuid and Setgid
------------------------------- 
* [Setuid and Setgid - ATT&CK](https://attack.mitre.org/wiki/Technique/T1166)
	* When the setuid or setgid bits are set on Linux or macOS for an application, this means that the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. There are instances where programs need to be executed in an elevated context to function properly, but the user running them doesn’t need the elevated privileges. Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications. These bits are indicated with an "s" instead of an "x" when viewing a file's attributes via `ls -l`. The chmod program can set these bits with via bitmasking, chmod 4777 [file] or via shorthand naming, chmod u+s [file]. An adversary can take advantage of this to either do a shell escape or exploit a vulnerability in an application with the setsuid or setgid bits to get code running in a different user’s context. 
* [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)

#### Linux
* [SETGID(2) - man7.org](http://man7.org/linux/man-pages/man2/setgid.2.html)
* [Special File Permissions (setuid, setgid and Sticky Bit)](https://docs.oracle.com/cd/E19683-01/806-4078/secfiles-69/index.html)
* [Exploiting SUID Executables](https://www.pentestpartners.com/security-blog/exploiting-suid-executables/)

#### OS X




## SID-History Injection
* [SID-History Injection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1178)
	* The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens.1 An account can hold additional SIDs in the SID-History Active Directory attribute2, allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).
	* Adversaries may use this mechanism for privilege escalation. With Domain Administrator (or equivalent) rights, harvested or well-known SID values3 may be inserted into SID-History to enable impersonation of arbitrary users/groups such as Enterprise Administrators. This manipulation may result in elevated access to local resources and/or access to otherwise inaccessible domains via lateral movement techniques such as Remote Services, Windows Admin Shares, or Windows Remote Management. 

#### Windows
* [Security Identifiers - msdn.ms](https://msdn.microsoft.com/library/windows/desktop/aa379571.aspx)
* [SID-History attribute - msdn.ms](https://msdn.microsoft.com/library/ms679833.aspx)
* [Well-known security identifiers in Windows operating systems](https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems)

------------------------------- 
## Startup Items
* [Startup Items - ATT&CK](https://attack.mitre.org/wiki/Technique/T1165)
	* Per Apple’s documentation, startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup itemsStartup Items. This is technically a deprecated version (superseded by Launch Daemons), and thus the appropriate folder, /Library/StartupItems isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), StartupParameters.plist, reside in the top-level directory. An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanismMethods of Mac Malware Persistence. Additionally, since StartupItems run during the bootup phase of macOS, they will run as root. If an adversary is able to modify an existing Startup Item, then they will be able to Privilege Escalate as well. 

#### OS X




------------------------------- 
## Sudo
* [Sudo - ATT&CK](https://attack.mitre.org/wiki/Technique/T1169)
	* The sudoers file, `/etc/sudoers`, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the idea of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like `user1 ALL=(ALL) NOPASSWD: ALLOSX.Dok Malware`. Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges. You must have elevated privileges to edit this file though. 

#### Linux
* [sudo(8) - Linux man page](https://linux.die.net/man/8/sudo)
* [Sudo Main Page](https://www.sudo.ws/)
* [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)






---------------------
## Valid Accounts
* [Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
	* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence. 
	* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful. 
	*  The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.TechNet Credential Theft

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


-------------------------------
## Web Shell
* [Web Shell - ATT&CK](https://attack.mitre.org/wiki/Technique/T1100)
	* A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. 
* [public-shell](https://github.com/BDLeet/public-shell)
	* Some Public Shell
* [php-webshells](https://github.com/JohnTroony/php-webshells)
	* Common php webshells. Do not host the file(s) on your server!
* [PHP-Backdoors](https://github.com/bartblaze/PHP-backdoors)
	* A collection of PHP backdoors. For educational or testing purposes only.


