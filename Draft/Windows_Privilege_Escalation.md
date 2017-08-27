# Windows Privlege Escalatio

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

[Abusing Token Privileges For LPE - drone/breenmachine](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)



## Accessibility Features
-------------------------------
[Accessibility Features - ATT&CK](https://attack.mitre.org/wiki/Technique/T1015)

* Replace the windows accessibilty applications with desired binary to be ran instead. Sticky-Keys backdoor. 
* Debugger trick -

[Sticky Keys to the Kingdom](https://www.slideshare.net/DennisMaldonado5/sticky-keys-to-the-kingdom)

[Walk through of making such a backdoor by crowdstrike](https://www.crowdstrike.com/blog/crowdresponse-windows-sticky-keys/)

[Privilege Escalation via "Sticky" Keys](http://carnal0wnage.attackresearch.com/2012/04/privilege-escalation-via-sticky-keys.html)



## AppInit DLLs
-------------------------------
[AppInit DLLs - ATT&CK](https://attack.mitre.org/wiki/Technique/T1103)


[Working with the AppInit_DLLs registry value](https://support.microsoft.com/en-us/help/197571/working-with-the-appinit-dlls-registry-value)
* (All the DLLs that are specified in this value are loaded by each Microsoft Windows-based application that is running in the current log on session.)

[LoadDLLViaAppInit - Didier Stevens](https://blog.didierstevens.com/2009/12/23/loaddllviaappinit/)
* Selectively Load DLLs with AppInit 

[AppInit DLLs and Secure Boot](https://msdn.microsoft.com/en-us/library/dn280412)



## Application Shimming
-------------------------------
[Application Shimming - ATT&CK](https://attack.mitre.org/wiki/Technique/T1138)

[Understanding Shims](https://technet.microsoft.com/en-us/library/dd837644(v=ws.10).aspx)

[Secrets of the Application Compatilibity Database (SDB) – Part 1](http://www.alex-ionescu.com/?p=39)

[Secrets of the Application Compatilibity Database (SDB) – Part 2](http://www.alex-ionescu.com/?p=40)

[Secrets of the Application Compatilibity Database (SDB) – Part 3](http://www.alex-ionescu.com/?p=41)

[Secrets of the Application Compatilibity Database (SDB) – Part 4](http://www.alex-ionescu.com/?p=43)

[Malicious Application Compatibility Shims](https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims-wp.pdf)

[Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)

[Windows 0wn3d By Default - Mark Baggett - Derbycon 2013](http://www.irongeek.com/i.php?page=videos/derbycon3/4206-windows-0wn3d-by-default-mark-baggett)
* Description: “In this talk we will discuss API Hooking, Process Execution Redirection, Hiding Registry keys and hiding directories on the hard drive. We must be talking about rootkits, right? Well yes, but not in the way you think. The Windows family of operating systems has all of these capabilities built right in! Using nothing but tools and techniques distributed and documented by Microsoft we can implement all of these rootkit functions. During this exciting talk I will present new attacks against Windows operating system that provide rootkit like functionality with built-in OS tools. In session, we’ll demonstrate how to leverage the Microsoft Application Compatibility Toolkit to help hide an attacker’s presence on your system. The Application Compatibility Toolkit allows you to create application shims that intercept and redirect calls from applications to the operating system. This native rootkit like capability is intended to make the Windows operating system compatible with very old or poorly written applications. Do DEP, ASLR, UAC, and Windows Resource Protection, File system ACLS and other modern OS security measures get it your way? No problem. Turn them off! Do you want to hide files and registry keys and from the user? The Application Compatibility toolkit allows you to create a virtual world for any application and hide resources from view. If someone inspects the registry with regedit they will see exactly what the attacker wants them to see and not what the OS sees when it launches programs. Did they patch your target so your exploit doesn’t work? Guess what, making applications backwards compatible is what this tool is intended to do. Make your favorite applications “old exploit compatible” insuring you can re-exploit the target with this awesome untapped resource. Everything you need to subvert windows applications is built right into the windows kernel. Come learn how to use the application compatibility toolkit to tap this great resource.”



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




## Exploitatoin of Vulnerability
-------------------------------
[Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)



## File System Permissions Weakness
-------------------------------
[File System Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1044)
* Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. 

[Executable installers are vulnerable^WEVIL (case 7): 7z*.exe allows remote code execution with escalation of privilege](http://seclists.org/fulldisclosure/2015/Dec/34)



## Local Port Monitor
-------------------------------
[Local Port Monitor - ATT&CK](https://attack.mitre.org/wiki/Technique/T1013)
* A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:\Windows\System32 and will be loaded by the print spooler service, spoolsv.exe, on boot. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. The spoolsv.exe process also runs under SYSTEM level permissions. 

[AddMonitor function](https://msdn.microsoft.com/en-us/library/dd183341)



## New Service
-------------------------------
[New Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1050)
* When operating systems boot up, they can start programs or applications called services that perform background system functions. A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry. Adversaries may install a new service that can be configured to execute at startup by using utilities to interact with services or by directly modifying the Registry. The service name may be disguised by using a name from a related operating system or benign software with Masquerading. Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through Service Execution. 

[Services](https://technet.microsoft.com/en-us/library/cc772408.aspx)




#### Unqouted Paths
* Service paths (stored in Windows Registry keys)2 and shortcut paths are vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\safe path with space\program.exe"). An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program. 

[CurrentControlSet\Services Subkey Entries](https://support.microsoft.com/en-us/help/103000/currentcontrolset-services-subkey-entries)
* This article contains registry entries for the CurrentControlSet\Services subkeys. There are no subgroups.

[Unquoted Service Paths - commonexploits](https://www.commonexploits.com/unquoted-service-paths/)

[PrivEsc: Unquoted Service Path - gracefulsecurity](https://www.gracefulsecurity.com/privesc-unquoted-service-path/)

[Practical Guide to exploiting the unquoted service path vulnerability in Windows - TrustFoundry](https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/)

[Help eliminate unquoted path vulnerabilities](https://isc.sans.edu/diary/Help+eliminate+unquoted+path+vulnerabilities/14464)

#### PATH Environment Variable Misconfiguration
* The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory, %SystemRoot%\system32 (e.g., C:\Windows\system32), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or Python), which will be executed when that command is executed from a script or command-line. 
* For example, if C:\example path precedes C:\Windows\system32 is in the PATH environment variable, a program that is named net.exe and placed in C:\example path will be called instead of the Windows system "net" when "net" is executed from the command-line. 

[The $env:PATH Less Traveled: Subverting Trust with 3rd-Party Applications - obscuresec](http://obscuresecurity.blogspot.com/2014/02/the-envpath-less-traveled-subverting.html)

#### Search Order Hijacking

Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. The search order differs depending on the method that is used to execute the program. However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.
* For example, "example.exe" runs "cmd.exe" with the command-line argument net user. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net user will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT. 

[WinExec function](https://msdn.microsoft.com/en-us/library/ms687393)

[Launching Apps from NT cmd shell](https://technet.microsoft.com/en-us/library/cc723564.aspx#XSLTsection127121120120)

[CreateProcess function](https://msdn.microsoft.com/en-us/library/ms682425)

[Environment Property](https://msdn.microsoft.com/en-us/library/fd7hxfdd.aspx)



## Scheduled Tasks
-------------------------------
[Scheduled Tasks - ATT&CK](https://attack.mitre.org/wiki/Technique/T1053)
* Utilities such as at and schtasks, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. The account used to create the task must be in the Administrators group on the local system. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on.

[Schedule a Task - MSDN](https://technet.microsoft.com/en-us/library/cc748993(v=ws.11).aspx)

[Schtasks.exe - MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/bb736357(v=vs.85).aspx)
* Enables an administrator to create, delete, query, change, run, and end scheduled tasks on a local or remote computer. Running Schtasks.exe without arguments displays the status and next run time for each registered task.

[At - MSDN](https://technet.microsoft.com/en-us/library/bb490866.aspx)
* Schedules commands and programs to run on a computer at a specified time and date. You can use at only when the Schedule service is running. Used without parameters, at lists scheduled commands.

[How To Use the AT Command to Schedule Tasks - MS](https://support.microsoft.com/en-us/help/313565/how-to-use-the-at-command-to-schedule-tasks)



## Service Registry Permissions Weakness
-------------------------------
[Service Registry Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1058)
* Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through Access Control Lists and permissions.
* If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then adversaries can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService). 

[Registry Key Security and Access Rights - MSDN](https://msdn.microsoft.com/library/windows/desktop/ms724878.aspx)



## Valid Accounts
-------------------------------
[Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)



## Web Shell
-------------------------------
[Web Shell - ATT&CK](https://attack.mitre.org/wiki/Technique/T1100)
* A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. 

[public-shell](https://github.com/BDLeet/public-shell)
* Some Public Shell

[php-webshells](https://github.com/JohnTroony/php-webshells)
* Common php webshells. Do not host the file(s) on your server!

[PHP-Backdoors](https://github.com/bartblaze/PHP-backdoors)
* A collection of PHP backdoors. For educational or testing purposes only.


