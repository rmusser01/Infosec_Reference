# Persistence


[MITRE ATT&CK - Persistence](https://attack.mitre.org/wiki/Persistence)
* Persistence is any access, action, or configuration change to a system that gives an adversary a persistent presence on that system. Adversaries will often need to maintain access to systems through interruptions such as system restarts, loss of credentials, or other failures that would require a remote access tool to restart or alternate backdoor for them to regain access. 


-------------------------------
## .bash_profile and .bashrc
* [.bash_profile and .bashrc - ATT&CK](https://attack.mitre.org/wiki/Technique/T1156)
	* `~/.bash_profile` and `~/.bashrc` are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly. `~/.bash_profile` is executed for login shells and `~/.bashrc` is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), `~/.bash_profile` is executed before the initial command prompt is returned to the user. After that, every time a new shell is opened, `~/.bashrc` is executed. This allows users more fine grained control over when they want certain commands executed.
	* Mac's Terminal.app is a little different in that it runs a login shell by default each time a new terminal window is opened, thus calling ~/.bash_profile each time instead of ~/.bashrc.
	* These files are meant to be written to by the local user to configure their own environment; however, adversaries can also insert code into these files to gain persistence each time a user logs in or opens a new shell.

#### Linux
#### OS X







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
## AppCert DLLs
* [AppCert DLLs - ATT&CK](https://attack.mitre.org/wiki/Technique/T1182)
	* Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager are loaded into every process that calls the ubiquitously used application programming interface (API) functions:1
	* CreateProcess
	* CreateProcessAsUser
	* CreateProcessWithLoginW
	* CreateProcessWithTokenW
	* WinExec
		* Similar to Process Injection, this value can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. 


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
## Authentication Package
* [Authentication Package - ATT&CK](https://attack.mitre.org/wiki/Technique/T1131)
	* Windows Authentication Package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.MSDN Authentication Packages Adversaries can use the autostart mechanism provided by LSA Authentication Packages for persistence by placing a reference to a binary in the Windows Registry location HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ with the key value of "Authentication Packages"=<target binary>. The binary will then be executed by the system when the authentication packages are loaded.

#### Windows
* [Authentication Packages](https://msdn.microsoft.com/library/windows/desktop/aa374733.aspx)
	* Authentication packages are contained in dynamic-link libraries. The Local Security Authority (LSA) loads authentication packages by using configuration information stored in the registry. Loaded at OS start.






-------------------------------
## Bootkit
* [Bootkit - ATT&CK](https://attack.mitre.org/wiki/Technique/T1067)
	* A bootkit is a malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR).
	* Adversaries may use bootkits to persist on systems at a layer below the operating system, which may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly. 
	* Master Boot Record
		* The MBR is the section of disk that is first loaded after completing hardware initialization by the BIOS. It is the location of the boot loader. An adversary who has raw access to the boot drive may overwrite this area, diverting execution during startup from the normal boot loader to adversary code.Lau 2011 
	* Volume Boot Record
		*  The MBR passes control of the boot process to the VBR. Similar to the case of MBR, an adversary who has raw access to the boot drive may overwrite the VBR to divert execution during startup to adversary code.



-------------------------------
## Change Default File Association
* [Change Default File Association - ATT&CK](https://attack.mitre.org/wiki/Technique/T1042)
	* When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access.Microsoft Change Default ProgramsMicrosoft File Handlers Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

#### Windows
* [Change which programs Windows 7 uses by default](https://support.microsoft.com/en-us/help/18539/windows-7-change-default-programs)
	* Win 7,8,10: Open Control Panel > Control Panel Home > Default Programs > Set Associations




-------------------------------
## Component Firmware
* [Component Firmware - ATT&CK](https://attack.mitre.org/wiki/Technique/T1109)
	* Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to System Firmware but conducted upon other system components that may not have the same capability or level of integrity checking. Malicious device firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.
* [HD Hacking - SpritesMods](http://spritesmods.com/?art=hddhack)






-------------------------------
## Component Object Model Hijacking
* [Component Object Model Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1122)
	* The Microsoft Component Object Model (COM) is a system within Windows to enable interaction between software components through the operating system.Microsoft Component Object Model Adversaries can use this system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Windows Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead.GDATA COM Hijacking An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

#### Windows
* [The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)
* [COM Object hijacking: the discreet way of persistence](https://www.gdatasoftware.com/blog/2014/10/23941-com-object-hijacking-the-discreet-way-of-persistence)
* [Userland Persistence with Scheduled Tasks and COM Handler Hijacking](https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
* [Windows Operating System Archaeology](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology)
	* Given at BSides Nashville 2017. The modern Windows Operating System carries with it an incredible amount of legacy code. The Component Object Model (COM) has left a lasting impact on Windows. This technology is far from dead as it continues to be the foundation for many aspects of the Windows Operating System. You can find hundreds of COM Classes defined by CLSID (COM Class Identifiers). Do you know what they do? This talk seeks to expose tactics long forgotten by the modern defender. We seek to bring to light artifacts in the Windows OS that can be used for persistence. We will present novel tactics for persistence using only the registry and COM objects.







-------------------------------
## Cron Job
* [Cron Job - ATT&CK](https://attack.mitre.org/wiki/Technique/T1168)
	* System-wide cron jobs are installed by modifying /etc/crontab while per-user cron jobs are installed using crontab with specifically formatted crontab files 1. This works on Mac and Linux systems.
	* Both methods allow for commands or scripts to be executed at specific, periodic intervals in the background without user interaction. An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence234, to conduct Execution as part of Lateral Movement, to gain root privileges, or to run a process under the context of a specific account. 

#### Linux
* [Intro to Cron - unixgeeks](http://www.unixgeeks.org/security/newbie/unix/cron-1.html)
* [Scheduling Tasks with Cron Jobs - tutsplus](https://code.tutsplus.com/tutorials/scheduling-tasks-with-cron-jobs--net-8800)

#### OS X
* Per Apple’s developer documentation, there are two supported methods for creating periodic background jobs: launchd and cron1. 
	* Launchd 
		* Each Launchd job is described by a different configuration property list (plist) file similar to Launch Daemons or Launch Agents, except there is an additional key called StartCalendarInterval with a dictionary of time values. This only works on macOS and OS X. 
	* cron
		* System-wide cron jobs are installed by modifying /etc/crontab while per-user cron jobs are installed using crontab with specifically formatted crontab files. This works on Mac and Linux systems.
	* Both methods allow for commands or scripts to be executed at specific, periodic intervals in the background without user interaction. An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence234, to conduct Execution as part of Lateral Movement, to gain root privileges, or to run a process under the context of a specific account. 






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
## External Remote Services
* [External Remote Services - ATT&CK](https://attack.mitre.org/wiki/Technique/T1133)
	* Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Adversaries may use remote services to access and persist within a network.Volexity Virtual Private Keylogging Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network. Access to remote services may be used as part of Redundant Access during an operation.
* VPN/RDP/Citrix Hijacking







-------------------------------
## File System Permissions Weakness
* [File System Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1044)
	* Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.
	* Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence. 
	* Services
		* Manipulation of Windows service binaries is one variation of this technique. Adversaries may replace a legitimate service executable with their own executable to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService). Once the service is started, either directly by the user (if appropriate access is available) or through some other means, such as a system restart if the service starts on bootup, the replaced executable will run instead of the original service executable. 
	* Executable Installers
		*  Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the %TEMP% directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL Search Order Hijacking. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors.Mozilla Firefox Installer DLL HijackSeclists Kanthak 7zip Installer

#### Linux
#### OS X
#### Windows
* [Executable installers are vulnerable^WEVIL (case 7): 7z.exe allows remote code execution with escalation of privilege](http://seclists.org/fulldisclosure/2015/Dec/34)
* [Hide files using SSDT hooking](http://blog.sevagas.com/?Hide-files-using-SSDT-hooking)



-------------------------------
## Hidden Files and Directories
* [Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
	* To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS). 
	* 
* [ What is a Hidden File? ](https://www.lifewire.com/what-is-a-hidden-file-2625898)

#### Linux
* Users can mark specific files as hidden simply by putting a “.” as the first character in the file or folder name Sofacy Komplex TrojanAntiquated Mac Malware. Files and folder that start with a period, ‘.’, are by default hidden from being viewed in the Finder application and standard command-line utilities like “ls”. Users must specifically change settings to have these files viewable. For command line usages, there is typically a flag to see all files (including hidden ones). To view these files in the Finder Application, the following command must be executed: defaults write com.apple.finder AppleShowAllFiles YES, and then relaunch the Finder Application. 
* [Hidden File Definition - LinuxInfoProject](http://www.linfo.org/hidden_file.html)

#### OS X
* Files on macOS can be marked with the UF_HIDDEN flag which prevents them from being seen in Finder.app, but still allows them to be seen in Terminal.appWireLurker. Many applications create these hidden files and folders to store information so that it doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder that’s hidden and contains the user’s known hosts and keys. 
*  Adversaries can use this to their advantage to hide files and folders anywhere on the system for persistence and evading a typical user or system analysis that does not incorporate investigation of hidden files.

#### Windows
* Users can mark specific files as hidden by using the attrib.exe binary. Simply do attrib +h filename to mark a file or folder as hidden. Similarly, the “+s” marks a file as a system file and the “+r” flag marks the file as read only. Like most windows binaries, the attrib.exe binary provides the ability to apply these changes recursively “/S”. 


-------------------------------
## Hypervisor
* [Hypervisor - ATT&CK](https://attack.mitre.org/wiki/Technique/T1062)
	* A type-1 hypervisor is a software layer that sits between the guest operating systems and system's hardware.Wikipedia Hypervisor It presents a virtual running environment to an operating system. An example of a common hypervisor is Xen.Wikipedia Xen A type-1 hypervisor operates at a level below the operating system and could be designed with Rootkit functionality to hide its existence from the guest operating system.Myers 2007 A malicious hypervisor of this nature could be used to persist on systems through interruption.
* [An Introduction to Hardware-Assisted Virtual Machine (HVM) - pdf](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.90.8832&rep=rep1&type=pdf)



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
## LC_LOAD_DYLIB Addition
* [LC_LOAD_DYLIB Addition - ATT&CK](https://attack.mitre.org/wiki/Technique/T1161)
	* Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long adjustments are made to the rest of the fields and dependenciesWriting Bad Malware for OSX. There are tools available to perform these changes. Any changes will invalidate digital signatures on binaries because the binary is being modified. Adversaries can remediate this issue by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load timeMalware Persistence on OS X.

#### OS X






-------------------------------
## Launch Agent
* [Launch Agent - ATT&CK](https://attack.mitre.org/wiki/Technique/T1159)
	* Per Apple’s developer documentation, when a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (plist) files found in /System/Library/LaunchAgents, /Library/LaunchAgents, and $HOME/Library/LaunchAgentsAppleDocs Launch Agent DaemonsOSX Keydnap malwareAntiquated Mac Malware. These launch agents have property list files which point to the executables that will be launchedOSX.Dok Malware. Adversaries may install a new launch agent that can be configured to execute at login by using launchd or launchctl to load a plist into the appropriate directories Sofacy Komplex Trojan Methods of Mac Malware Persistence. The agent name may be disguised by using a name from a related operating system or benign software. Launch Agents are created with user level privileges and are executed with the privileges of the user when they log inOSX Malware DetectionOceanLotus for OS X. They can be set up to execute when a specific user logs in (in the specific user’s directory structure) or when any user logs in (which requires administrator privileges). 

#### OS X










-------------------------------
## Launch Daemon
* [Launch Daemon - ATT&CK](https://attack.mitre.org/wiki/Technique/T1160)
	* Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in /System/Library/LaunchDaemons and /Library/LaunchDaemonsAppleDocs Launch Agent Daemons. These LaunchDaemons have property list files which point to the executables that will be launchedMethods of Mac Malware Persistence. 
	* Adversaries may install a new launch daemon that can be configured to execute at startup by using launchd or launchctl to load a plist into the appropriate directoriesOSX Malware Detection. The daemon name may be disguised by using a name from a related operating system or benign software WireLurker. Launch Daemons may be created with administrator privileges, but are executed under root privileges, so an adversary may also use a service to escalate privileges from administrator to root. 
	* The plist file permissions must be root:wheel, but the script or program that it points to has no such requirement. So, it is possible for poor configurations to allow an adversary to modify a current Launch Daemon’s executable and gain persistence or Privilege Escalation.

#### OS X


-------------------------------
## Launchctl
* [Launchctl - ATT&CK](https://attack.mitre.org/wiki/Technique/T1152)
	* Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made Sofacy Komplex Trojan. Running a command from launchctl is as simple as `launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg"`. Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges. Adversaries can abuse this functionality to execute code or even bypass whitelisting if launchctl is an allowed process. 





-------------------------------
## Local Port Monitor
* [Local Port Monitor - ATT&CK](https://attack.mitre.org/wiki/Technique/T1013)
	* A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup.AddMonitor This DLL can be located in C:\Windows\System32 and will be loaded by the print spooler service, spoolsv.exe, on boot.Bloxham Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors.Bloxham The spoolsv.exe process also runs under SYSTEM level permissions. Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM. 

#### Windows
* [AddMonitor function](https://msdn.microsoft.com/en-us/library/dd183341)




-------------------------------
## Login Item
* [Login Item - ATT&CK](https://attack.mitre.org/wiki/Technique/T1162)
	* MacOS provides the option to list specific applications to run when a user logs in. These applications run under the logged in user's context, and will be started every time the user logs in. Login items installed using the Service Management Framework are not visible in the System Preferences and can only be removed by the application that created themAdding Login Items. Users have direct control over login items installed using a shared file list which are also visible in System PreferencesAdding Login Items. These login items are stored in the user's `~/Library/Preferences/` directory in a plist file called `com.apple.loginitems.plist`. Some of these applications can open visible dialogs to the user, but they don’t all have to since there is an option to ‘Hide’ the window. If an adversary can register their own login item or modified an existing one, then they can use it to execute their code for a persistence mechanism each time the user logs inMalware Persistence on OS XOSX.Dok Malware. 





-------------------------------
## Logon Scripts
* [Logon Scripts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1037)

#### OS X
[Mac OS X: Creating a login hook - apple](https://support.apple.com/de-at/HT2420)

#### Windows
* [Logon Scripts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1037)
	* Windows allows logon scripts to be run whenever a specific user or group of users log into a system.TechNet Logon Scripts The scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server.
	* If adversaries can access these scripts, they may insert additional code into the logon script to execute their tools when a user logs in. This code can allow them to maintain persistence on a single system, if it is a local script, or to move laterally within a network, if the script is stored on a central server and pushed to many systems. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 
* [Introduction Logon Scripts - With VBScript](http://www.computerperformance.co.uk/Logon/logon_scripts.htm)
* [Login Scripts - Creating and Using Login Scripts](http://loginscripts.com/)





-------------------------------
## Modify Existing Service
* [Modify Existing Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1031)
	* Windows service configuration information, including the file path to the service's executable, is stored in the Registry. Service configurations can be modified using utilities such as sc.exe and Reg. Adversaries can modify an existing service to persist malware on a system by using system utilities or by using custom tools to interact with the Windows API. Use of existing services is a type of Masquerading that may make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used. 

#### Linux
#### OS X
#### Windows
* [Install a Persistant Backdoor in Windows Using Netcat ](https://null-byte.wonderhowto.com/how-to/install-persistant-backdoor-windows-using-netcat-0162348/)
* [Script Task](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task)
	* Persistence Via MSSQL




-------------------------------
### Netsh Helper DLL
Netsh Helper DLL
* [Netsh Helper DLL - ATT&CK](https://attack.mitre.org/wiki/Technique/T1128)
	* Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility.TechNet Netsh The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM\SOFTWARE\Microsoft\Netsh. 
	* Adversaries can use netsh.exe with helper DLLs to proxy execution of arbitrary code in a persistent manner when netsh.exe is executed automatically with another Persistence technique or if other persistent software is present on the system that executes netsh.exe as part of its normal functionality. Examples include some VPN software that invoke netsh.exe.Demaske Netsh Persistence 

#### Windows 
* [Using Netsh](https://technet.microsoft.com/library/bb490939.aspx)
* [Netshell - Matthew Demaske](https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html)
* [NetshHelperBeacon - DLL to load from Windows NetShell. Will pop calc and execute shellcode.](https://github.com/outflanknl/NetshHelperBeacon)





## New Service
-------------------------------
* [New Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1050)
	* When operating systems boot up, they can start programs or applications called services that perform background system functions.TechNet Services A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry. Adversaries may install a new service that can be configured to execute at startup by using utilities to interact with services or by directly modifying the Registry. The service name may be disguised by using a name from a related operating system or benign software with Masquerading. Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through Service Execution. 

#### Windows
* [Services](https://technet.microsoft.com/en-us/library/cc772408.aspx)







-------------------------------
## Office Application Startup
* [Office Application Startup - ATT&CK](https://attack.mitre.org/wiki/Technique/T1137)
	* Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started. 
	* Office template Macros
		* Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts.Microsoft Change Normal Template 
		* Office Visual Basic for Applications (VBA) macrosMSDN VBA in Office can inserted into the base templated and used to execute code when the respective Office application starts in order to obtain persistence. Examples for both Word and Excel have been discovered and published. By default, Word has a Normal.dotm template created that can be modified to include a malicious macro. Excel does not have a template file created by default, but one can be added that will automatically be loaded.enigma0x3 normal.dotmHexacorn Office Template Macros 
		* Word Normal.dotm location: `C:\Users\(username)\AppData\Roaming\Microsoft\Templates\Normal.dotm` 
		* Excel Personal.xlsb location: `C:\Users\(username)\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB`
		* An adversary may need to enable macros to execute unrestricted depending on the system or enterprise security policy on use of macros. 
	* Office Test
		* A Registry location was found that when a DLL reference was placed within it the corresponding DLL pointed to by the binary path would be executed every time an Office application is startedHexacorn Office Test 
		* `HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf` 
	* Add-ins
		* Office add-ins can be used to add functionality to Office programs.Microsoft Office Add-ins 
		*  Add-ins can also be used to obtain persistence because they can be set to execute code when an Office application starts. There are different types of add-ins that can be used by the various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), and Visual Studio Tools for Office (VSTO) add-ins.MRWLabs Office Persistence Add-ins

#### Windows 
* [Change the Normal template (Normal.dotm)](https://support.office.com/en-us/article/Change-the-Normal-template-Normal-dotm-06de294b-d216-47f6-ab77-ccb5166f98ea?ui=en-US&rs=en-US&ad=US)
	* The Normal.dotm template opens whenever you start Microsoft Word, and it includes default styles and customizations that determine the basic look of a document.
* [Getting Started with VBA in Office](https://msdn.microsoft.com/en-us/vba/office-shared-vba/articles/getting-started-with-vba-in-office)
* [Maintaining Access with Normal.dotm - enigma0x3](https://enigma0x3.net/2014/01/23/maintaining-access-with-normal-dotm/comment-page-1/)
* [Beyond good ol’ Run key, Part 62 - Hexacorn](http://www.hexacorn.com/blog/2017/04/19/beyond-good-ol-run-key-part-62/)
	* Takeaway: Dropping any macro sheet inside the XLSTART folder and opening it from there will not show the macro warning
* [Add or remove add-ins](https://support.office.com/en-us/article/Add-or-remove-add-ins-0af570c4-5cf3-4fa9-9b88-403625a0b460?ui=en-US&rs=en-US&ad=US)
	* Add-ins provide optional commands and features for Microsoft Excel. By default, add-ins are not immediately available in Excel, so you must first install and (in some cases) activate these add-ins so that you can use them.


-------------------------------
## Path Interception
* [Path Interception - ATT&CK](https://attack.mitre.org/wiki/Technique/T1034)
	* Path interception occurs when an executable is placed in a specific path so that it is executed by an application instead of the intended target. One example of this was the use of a copy of cmd in the current working directory of a vulnerable application that loads a CMD or BAT file with the CreateProcess function.TechNet MS14-019 
	* There are multiple distinct weaknesses or misconfigurations that adversaries may take advantage of when performing path interception: unquoted paths, path environment variable misconfigurations, and search order hijacking. The first vulnerability deals with full program paths, while the second and third occur when program paths are not specified. These techniques can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process.  

#### Unqouted Paths
* Service paths (stored in Windows Registry keys)Microsoft Subkey and shortcut paths are vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\safe path with space\program.exe").Baggett 2012 An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program.  
* [CurrentControlSet\Services Subkey Entries](https://support.microsoft.com/en-us/help/103000/currentcontrolset-services-subkey-entries)
	* This article contains registry entries for the CurrentControlSet\Services subkeys. There are no subgroups.
* [Unquoted Service Paths - commonexploits](https://www.commonexploits.com/unquoted-service-paths/)
* [PrivEsc: Unquoted Service Path - gracefulsecurity](https://www.gracefulsecurity.com/privesc-unquoted-service-path/)
* [Practical Guide to exploiting the unquoted service path vulnerability in Windows - TrustFoundry](https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/)
* [Help eliminate unquoted path vulnerabilities](https://isc.sans.edu/diary/Help+eliminate+unquoted+path+vulnerabilities/14464)

#### PATH Environment Variable Misconfiguration
* The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory, %SystemRoot%\system32 (e.g., C:\Windows\system32), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or Python), which will be executed when that command is executed from a script or command-line.  
* For example, if `C:\example` path precedes `C:\Windows\system32` is in the PATH environment variable, a program that is named `net.exe` and placed in `C:\example` path will be called instead of the Windows system "`net`" when "`net`" is executed from the command-line. 
* [The $env:PATH Less Traveled: Subverting Trust with 3rd-Party Applications - obscuresec](http://obscuresecurity.blogspot.com/2014/02/the-envpath-less-traveled-subverting.html)




#### Search Order Hijacking
* Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. The search order differs depending on the method that is used to execute the program.Microsoft CreateProcessHill NT ShellMicrosoft WinExec However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory. 
* For example, "example.exe" runs "cmd.exe" with the command-line argument net user. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net user will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT.MSDN Environment Property  
* [WinExec function](https://msdn.microsoft.com/en-us/library/ms687393)
* [Launching Apps from NT cmd shell](https://technet.microsoft.com/en-us/library/cc723564.aspx#XSLTsection127121120120)
* [CreateProcess function](https://msdn.microsoft.com/en-us/library/ms682425)
* [Environment Property](https://msdn.microsoft.com/en-us/library/fd7hxfdd.aspx)



-------------------------------
## Plist Modification
[Plist Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1150)
	* Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UT-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as /Library/Preferences (which execute with elevated privileges) and ~/Library/Preferences (which execute with a user's privileges). Adversaries can modify these plist files to point to their own code, can use them to execute their code in the context of another user, bypass whitelisting procedures, or even use them as a persistence mechanismSofacy Komplex Trojan.

#### OS X




-------------------------------
## Rc.common
* [Rc.common - ATT&CK](https://attack.mitre.org/wiki/Technique/T1163)
	* During the boot process, macOS and Linux both execute source /etc/rc.common, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings, and is thus recommended to include in the start of Startup Item ScriptsStartup Items. In macOS and OS X, this is now a deprecated technique in favor of launch agents and launch daemons, but is currently still used. Adversaries can use the rc.common file as a way to hide code for persistence that will execute on each reboot as the root userMethods of Mac Malware Persistence. 

#### Linux
* [An introduction to services, runlevels, and rc.d scripts - linux.com](https://www.linux.com/news/introduction-services-runlevels-and-rcd-scripts)

#### OS X
* During the boot process, macOS and Linux both execute source /etc/rc.common, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings, and is thus recommended to include in the start of Startup Item Scripts. In macOS and OS X, this is now a deprecated technique in favor of launch agents and launch daemons, but is currently still used.







-------------------------------
## Re-opened Applications
* [Re-opened Applications - ATT&CK](https://attack.mitre.org/wiki/Technique/T1164)
	* Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened when a user reboots their machine. While this is usually done via a Graphical User Interface (GUI) on an app-by-app basis, there are property list files (plist) that contain this information as well located at `~/Library/Preferences/com.apple.loginwindow.plist` and `~/Library/Preferences/ByHost/com.apple.loginwindow.*.plist`. An adversary can modify one of these files directly to include a link to their malicious executable to provide a persistence mechanism each time the user reboots their machineMethods of Mac Malware Persistence.

#### OS X


-------------------------------
## Redundant Access
* [Redundant Access - ATT&CK](https://attack.mitre.org/wiki/Technique/T1108)
	* Adversaries may use more than one remote access tool with varying command and control protocols as a hedge against detection. If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to Valid Accounts to use External Remote Services such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.Mandiant APT1 Use of a Web Shell is one such way to maintain access to a network through an externally accessible Web server.
* Don't just use one backdoor. Use multiple avenues of exfil. Plan ahead and exepct observation/discovery. Prepare backup solutions ready to go in case SHTF.




-------------------------------
## Registry Run Key/ Start Folder
* [Registry Run Keys / Start Folder - ATT&CK](https://attack.mitre.org/wiki/Technique/T1060)
	* Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.Microsoft Run Key The program will be executed under the context of the user and will have the account's associated permissions level. Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs. 

#### Windows
* [Run and RunOnce Registry Keys - MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376977(v=vs.85).aspx)
	* Run and RunOnce registry keys cause programs to run each time that a user logs on.
* [Beyond good ol’ Run key – All parts](http://www.hexacorn.com/blog/2017/01/28/beyond-good-ol-run-key-all-parts/)
	* Here are the links to all the ‘Beyond good ol’ Run key’ posts so far. 









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
* [How To Use the AT Command to Schedule Tasks - MS](https://support.microsoft.com/en-us/help/313565/how-to-use-the-at-command-to-schedule-tasks)







-------------------------------
## Security Support Provider
* [Security Support Provider - ATT&CK](https://attack.mitre.org/wiki/Technique/T1101)
	* Windows Security Support Provider (SSP) DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` and `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.

#### Windows
* [Analysis of Malicious Security Support Provider DLLs](http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html)
* [Security Support Provider Interface - Wikipedia](https://en.wikipedia.org/wiki/Security_Support_Provider_Interface)
* [The Security Support Provider Interface - MSDN](https://msdn.microsoft.com/en-us/library/bb742535.aspx)



-------------------------------
## Service Registry Permissions Weakness
* [Service Registry Permissions Weakness - ATT&CK](https://attack.mitre.org/wiki/Technique/T1058)
	* Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through Access Control Lists and permissions.MSDN Registry Key Security If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then adversaries can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

#### Windows 
* [Registry Key Security and Access Rights - MSDN](https://msdn.microsoft.com/library/windows/desktop/ms724878.aspx)





-------------------------------
## Shortcut Modification
* [Shortcut Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1023)
	* Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.

#### Linux
#### OS X
#### Windows
* [How to create shortcuts for apps, files, folders and web pages in Windows](http://www.digitalcitizen.life/how-create-shortcuts)
* [tricky.lnk](https://github.com/xillwillx/tricky.lnk)
	* Creates a .lnk file with unicode chars that reverse the file extension and adds a .txt to the end to make it appear as a textfile. Payload is a powershell webdl and execute
* [pylnker](https://github.com/HarmJ0y/pylnker)
	* This is a Python port of lnk-parse-1.0, a tool to parse Windows .lnk files.
* [python_lnk_maker](https://github.com/carnal0wnage/python_lnk_maker)
	* Make Windows LNK file with python (pylnk)
* [LNKUp](https://github.com/Plazmaz/LNKUp)
	* This tool will allow you to generate LNK payloads. Upon rendering or being run, they will exfiltrate data.
* [liblnk](https://github.com/libyal/liblnk)
	* Library and tools to access the Windows Shortcut File (LNK) format
* [lnk-parse](https://github.com/lcorbasson/lnk-parse)
	* MS Windows LNK file parser




-------------------------------
## Startup Items
* [Startup Items - ATT&CK](https://attack.mitre.org/wiki/Technique/T1165)
	* Per Apple’s documentation, startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup itemsStartup Items. This is technically a deprecated version (superseded by Launch Daemons), and thus the appropriate folder, /Library/StartupItems isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), StartupParameters.plist, reside in the top-level directory. An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanismMethods of Mac Malware Persistence. Additionally, since StartupItems run during the bootup phase of macOS, they will run as root. If an adversary is able to modify an existing Startup Item, then they will be able to Privilege Escalate as well.





-------------------------------
## System Firmware
* [System Firmware - ATT&CK](https://attack.mitre.org/wiki/Technique/T1019)
	* The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.Wikipedia BIOSWikipedia UEFIAbout UEFI System firmware like BIOS and (U)EFI underly the functionality of a computer and may be modified by an adversary to perform or assist in malicious activity. Capabilities exist to overwrite the system firmware, which may give sophisticated adversaries a means to install malicious firmware updates as a means of persistence on a system that may be difficult to detect.






-------------------------------
## Trap
* [Trap - ATT&CK](https://attack.mitre.org/wiki/Technique/T1154)
	* The `trap` command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received. 

#### Linux
* [Traps - tldp](http://tldp.org/LDP/Bash-Beginners-Guide/html/sect_12_02.html)
* [Shell Scripting Tutorial - Trap](https://www.shellscript.sh/trap.html)
* [Unix / Linux - Signals and Traps - TutorialsPoint](https://www.tutorialspoint.com/unix/unix-signals-traps.htm)

#### OS X






-------------------------------
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
	* A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (see, for example, China Chopper Web shell client).Lee 2013 Web shells may serve as Redundant Access or as a persistence mechanism in case an adversary's primary access methods are detected and removed.

#### General
* [public-shell](https://github.com/BDLeet/public-shell)
	* Some Public Shell
* [php-webshells](https://github.com/JohnTroony/php-webshells)
	* Common php webshells. Do not host the file(s) on your server!
* [PHP-Backdoors](https://github.com/bartblaze/PHP-backdoors)
	* A collection of PHP backdoors. For educational or testing purposes only.
* [Weevely](https://github.com/epinna/weevely3)
	* Weevely is a command line web shell dynamically extended over the network at runtime, designed for remote server administration and penetration testing.


-------------------------------
## Windows Management Instrumentation(WMI) Event Subscription
* [Windows Management Instrumentation Event Subscription - ATT&CK](https://attack.mitre.org/wiki/Technique/T1084)
	* Windows Management Instrumentation (WMI) can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may attempt to evade detection of this technique by compiling WMI scripts.Dell WMI Persistence Examples of events that may be subscribed to are the wall clock time or the computer's uptime.Kazanciyan 2014 Several threat groups have reportedly used this technique to maintain persistence.Mandiant M-Trends 2015

#### Windows
* [Windows Management  Instrumentation (WMI)  Offense, Defense, and Forensics](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)
* [A Novel WMI Persistence Implementation - SecureWorks](https://www.secureworks.com/blog/wmi-persistence)
* [PowerShell and Events: Permanent WMI Event Subscriptions](https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/)
* [Receiving a WMI Event](https://msdn.microsoft.com/en-us/library/aa393013(v=vs.85).aspx)
* [Example_WMI_Detection_EventLogAlert.ps1](https://gist.github.com/mattifestation/aff0cb8bf66c7f6ef44a)
	* An example of how to use permanent WMI event subscriptions to log a malicious action to the event log
* [Yeabests.cc: A fileless infection using WMI to hijack your Browser](https://www.bleepingcomputer.com/news/security/yeabests-cc-a-fileless-infection-using-wmi-to-hijack-your-browser/)
* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)
* [List all WMI Permanent Event Subscriptions](https://gallery.technet.microsoft.com/scriptcenter/List-all-WMI-Permanent-73e04ab4)
* [Use PowerShell to Create a Permanent WMI Event to Launch a VBScript](https://gallery.technet.microsoft.com/scriptcenter/List-all-WMI-Permanent-73e04ab4)






-------------------------------
## Winlogon Helper DLL
* [Winlogon Helper DLL - ATT&CK](https://attack.mitre.org/wiki/Technique/T1004)
	* Winlogon is a part of some Windows versions that performs actions at logon. In Windows systems prior to Windows Vista, a Registry key can be modified that causes Winlogon to load a DLL on startup. Adversaries may take advantage of this feature to load adversarial code at startup for persistence.

