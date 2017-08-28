Unfilled:
	External Remote Services
	Hypervisor
	System Firmware
	Valid Accounts
	Web Shells



# Windows Persistence

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


## Authentication Package
-------------------------------
[Authentication Package - ATT&CK](https://attack.mitre.org/wiki/Technique/T1131)
* Adversaries can use the autostart mechanism provided by LSA Authentication Packages for persistence by placing a reference to a binary in the Windows Registry location HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ with the key value of "Authentication Packages"=<target binary>. The binary will then be executed by the system when the authentication packages are loaded. (from https://attack.mitre.org/wiki/Technique/T1131#scite-b8a6357c4704477b91b769fd0bcd0fc8)

[Authentication Packages](https://msdn.microsoft.com/library/windows/desktop/aa374733.aspx)
* Authentication packages are contained in dynamic-link libraries. The Local Security Authority (LSA) loads authentication packages by using configuration information stored in the registry. Loaded at OS start.



## Bootkit
-------------------------------
[Bootkit - ATT&CK](https://attack.mitre.org/wiki/Technique/T1067)
* A bootkit is a malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR).

* Not going to list much here. If you're doing this, you don't need this.


## Change Default File Association
-------------------------------
[Change Default File Association - ATT&CK](https://attack.mitre.org/wiki/Technique/T1042)
* When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access.

[Change which programs Windows 7 uses by default](https://support.microsoft.com/en-us/help/18539/windows-7-change-default-programs)

* Win 7,8,10: Open Control Panel > Control Panel Home > Default Programs > Set Associations


## Component Firmware
-------------------------------
[Component Firmware - ATT&CK](https://attack.mitre.org/wiki/Technique/T1109)



## Component Object Model Hijacking
-------------------------------
[Component Object Model Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1122)

[The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)

[COM Object hijacking: the discreet way of persistence](https://www.gdatasoftware.com/blog/2014/10/23941-com-object-hijacking-the-discreet-way-of-persistence)



## DLL Search Order Hijacking
-------------------------------
[DLL Search Order Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1038)

[Dynamic-Link Library Search Order](https://msdn.microsoft.com/en-US/library/ms682586)



## External Remote Services
-------------------------------
[External Remote Services - ATT&CK](https://attack.mitre.org/wiki/Technique/T1133)

* VPN/RDP/Citrix Hijacking



## File System Permissions Weakness
-------------------------------
[File System Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1044)
* Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. 

[Executable installers are vulnerable^WEVIL (case 7): 7z*.exe allows remote code execution with escalation of privilege](http://seclists.org/fulldisclosure/2015/Dec/34)



## Hidden Files and Directories
-------------------------------
[Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
* Users can mark specific files as hidden by using the attrib.exe binary. Simply do attrib +h filename to mark a file or folder as hidden. Similarly, the “+s” marks a file as a system file and the “+r” flag marks the file as read only. Like most windows binaries, the attrib.exe binary provides the ability to apply these changes recursively “/S”. 

[ What is a Hidden File? ](https://www.lifewire.com/what-is-a-hidden-file-2625898)



## Hypervisor
-------------------------------
[Hypervisor - ATT&CK](https://attack.mitre.org/wiki/Technique/T1062)

[An Introduction to Hardware-Assisted Virtual Machine (HVM) - pdf](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.90.8832&rep=rep1&type=pdf)



## Local Port Monitor
-------------------------------
[Local Port Monitor - ATT&CK](https://attack.mitre.org/wiki/Technique/T1013)
* A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:\Windows\System32 and will be loaded by the print spooler service, spoolsv.exe, on boot. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. The spoolsv.exe process also runs under SYSTEM level permissions. 

[AddMonitor function](https://msdn.microsoft.com/en-us/library/dd183341)



## Logon Scripts
-------------------------------
[Logon Scripts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1037)
* Windows allows logon scripts to be run whenever a specific user or group of users log into a system.

[Introduction Logon Scripts - With VBScript](http://www.computerperformance.co.uk/Logon/logon_scripts.htm)

[Login Scripts - Creating and Using Login Scripts](http://loginscripts.com/)



## Modify Existing Service
-------------------------------
[Modify Existing Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1031)
* Windows service configuration information, including the file path to the service's executable, is stored in the Registry. Service configurations can be modified using utilities such as sc.exe and Reg.  Adversaries can modify an existing service to persist malware on a system by using system utilities or by using custom tools to interact with the Windows API. Use of existing services is a type of Masquerading that may make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used. 

[Install a Persistant Backdoor in Windows Using Netcat ](https://null-byte.wonderhowto.com/how-to/install-persistant-backdoor-windows-using-netcat-0162348/)



## Netsh Helper DLL
-------------------------------
[Netsh Helper DLL - ATT&CK](https://attack.mitre.org/wiki/Technique/T1128)
* Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM\SOFTWARE\Microsoft\Netsh. Adversaries can use netsh.exe with helper DLLs to proxy execution of arbitrary code in a persistent manner when netsh.exe is executed automatically with another Persistence technique or if other persistent software is present on the system that executes netsh.exe as part of its normal functionality. Examples include some VPN software that invoke netsh.exe.

[Using Netsh](https://technet.microsoft.com/library/bb490939.aspx)

[Netshell - Matthew Demaske](https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html)



## New Service
-------------------------------
[New Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1050)
* When operating systems boot up, they can start programs or applications called services that perform background system functions. A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry. Adversaries may install a new service that can be configured to execute at startup by using utilities to interact with services or by directly modifying the Registry. The service name may be disguised by using a name from a related operating system or benign software with Masquerading. Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through Service Execution. 

[Services](https://technet.microsoft.com/en-us/library/cc772408.aspx)



## Office Application Startup
-------------------------------
[Office Application Startup - ATT&CK](https://attack.mitre.org/wiki/Technique/T1137)
* Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started. 

[Change the Normal template (Normal.dotm)](https://support.office.com/en-us/article/Change-the-Normal-template-Normal-dotm-06de294b-d216-47f6-ab77-ccb5166f98ea?ui=en-US&rs=en-US&ad=US)
* The Normal.dotm template opens whenever you start Microsoft Word, and it includes default styles and customizations that determine the basic look of a document.

[Getting Started with VBA in Office](https://msdn.microsoft.com/en-us/vba/office-shared-vba/articles/getting-started-with-vba-in-office)

[Maintaining Access with Normal.dotm - enigma0x3](https://enigma0x3.net/2014/01/23/maintaining-access-with-normal-dotm/comment-page-1/)

[Beyond good ol’ Run key, Part 62 - Hexacorn](http://www.hexacorn.com/blog/2017/04/19/beyond-good-ol-run-key-part-62/)
* Takeaway: Dropping any macro sheet inside the XLSTART folder and opening it from there will not show the macro warning

[Add or remove add-ins](https://support.office.com/en-us/article/Add-or-remove-add-ins-0af570c4-5cf3-4fa9-9b88-403625a0b460?ui=en-US&rs=en-US&ad=US)
* Add-ins provide optional commands and features for Microsoft Excel. By default, add-ins are not immediately available in Excel, so you must first install and (in some cases) activate these add-ins so that you can use them.



## Path Interception
-------------------------------
[Path Interception - ATT&CK](https://attack.mitre.org/wiki/Technique/T1034)
* Path interception occurs when an executable is placed in a specific path so that it is executed by an application instead of the intended target.
* There are multiple distinct weaknesses or misconfigurations that adversaries may take advantage of when performing path interception: unquoted paths, path environment variable misconfigurations, and search order hijacking. The first vulnerability deals with full program paths, while the second and third occur when program paths are not specified. These techniques can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process. 

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



## Redundant Access
-------------------------------
* Don't just use one backdoor. Use multiple avenues of exfil. Plan ahead and exepct observation/discovery. Prepare backup solutions ready to go in case SHTF.



## Registry Run Key/ Start Folder
-------------------------------
[Registry Run Keys / Start Folder - ATT&CK](https://attack.mitre.org/wiki/Technique/T1060)
* Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. The program will be executed under the context of the user and will have the account's associated permissions level. 

[Run and RunOnce Registry Keys - MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376977(v=vs.85).aspx)
* Run and RunOnce registry keys cause programs to run each time that a user logs on.

[Beyond good ol’ Run key – All parts](http://www.hexacorn.com/blog/2017/01/28/beyond-good-ol-run-key-all-parts/)
* Here are the links to all the ‘Beyond good ol’ Run key’ posts so far. 



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





## Security Support Provider
-------------------------------
[Security Support Provider - ATT&CK](https://attack.mitre.org/wiki/Technique/T1101)
* Windows Security Support Provider (SSP) DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages and HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called. 

[Analysis of Malicious Security Support Provider DLLs](http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html)

[Security Support Provider Interface - Wikipedia](https://en.wikipedia.org/wiki/Security_Support_Provider_Interface)

[The Security Support Provider Interface - MSDN](https://msdn.microsoft.com/en-us/library/bb742535.aspx)



## Service Registry Permissions Weakness
-------------------------------
[Service Registry Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1058)
* Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through Access Control Lists and permissions.
* If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then adversaries can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService). 

[Registry Key Security and Access Rights - MSDN](https://msdn.microsoft.com/library/windows/desktop/ms724878.aspx)


## Shortcut Modification
-------------------------------
[Shortcut Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1023)
* Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program. 

[How to create shortcuts for apps, files, folders and web pages in Windows](http://www.digitalcitizen.life/how-create-shortcuts)



## System Firmware
-------------------------------
[System Firmware - ATT&CK](https://attack.mitre.org/wiki/Technique/T1019)
* The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.
* System firmware like BIOS and (U)EFI underly the functionality of a computer and may be modified by an adversary to perform or assist in malicious activity. Capabilities exist to overwrite the system firmware, which may give sophisticated adversaries a means to install malicious firmware updates as a means of persistence on a system that may be difficult to detect. 


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



## Windows Management Instrumentation(WMI) Event Subscription
-------------------------------
[Windows Management Instrumentation Event Subscription - ATT&CK](https://attack.mitre.org/wiki/Technique/T1084)
* Windows Management Instrumentation (WMI) can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may attempt to evade detection of this technique by compiling WMI scripts. Examples of events that may be subscribed to are the wall clock time or the computer's uptime.

[Windows Management  Instrumentation (WMI)  Offense, Defense, and Forensics](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)

[A Novel WMI Persistence Implementation - SecureWorks](https://www.secureworks.com/blog/wmi-persistence)

[PowerShell and Events: Permanent WMI Event Subscriptions](https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/)

[Receiving a WMI Event](https://msdn.microsoft.com/en-us/library/aa393013(v=vs.85).aspx)

[Example_WMI_Detection_EventLogAlert.ps1](https://gist.github.com/mattifestation/aff0cb8bf66c7f6ef44a)
* An example of how to use permanent WMI event subscriptions to log a malicious action to the event log

[Yeabests.cc: A fileless infection using WMI to hijack your Browser](https://www.bleepingcomputer.com/news/security/yeabests-cc-a-fileless-infection-using-wmi-to-hijack-your-browser/)

[Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)

[List all WMI Permanent Event Subscriptions](https://gallery.technet.microsoft.com/scriptcenter/List-all-WMI-Permanent-73e04ab4)

[Use PowerShell to Create a Permanent WMI Event to Launch a VBScript](https://gallery.technet.microsoft.com/scriptcenter/List-all-WMI-Permanent-73e04ab4)



## Winlogon Helper DLL
-------------------------------
[Winlogon Helper DLL - ATT&CK](https://attack.mitre.org/wiki/Technique/T1004)
* Winlogon is a part of some Windows versions that performs actions at logon. In Windows systems prior to Windows Vista, a Registry key can be modified that causes Winlogon to load a DLL on startup. Adversaries may take advantage of this feature to load adversarial code at startup for persistence. 
* Winlogon is a part of Windows that performs logon actions. In Windows systems prior to Windows Vista, a registry key can be modified that causes Winlogon to load a DLL on startup. Adversaries may take advantage of this feature to load adversarial code at startup.

