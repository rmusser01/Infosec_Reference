#  Execution


[MITRE ATT&CK - Execution](https://attack.mitre.org/wiki/execution)
* The execution tactic represents techniques that result in execution of adversary-controlled code on a local or remote system. This tactic is often used in conjunction with lateral movement to expand access to remote systems on a network. 



## AppleScript
------------------------------- 
* [AppleScript - ATT&CK](https://attack.mitre.org/wiki/Technique/T1155)
	* macOS and OS X applications send AppleEvent messages to each other for interprocess communications (IPC). These messages can be easily scripted with AppleScript for local or remote IPC. Osascript executes AppleScript and any other Open Scripting Architecture (OSA) language scripts. A list of OSA languages installed on a system can be found by using the `osalang` program. 
	* AppleEvent messages can be sent independently or as part of a script. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely. 
	*  Adversaries can use this to interact with open SSH connection, move to remote machines, and even present users with fake dialog boxes. These events cannot start applications remotely (they can start them locally though), but can interact with applications if they're already running remotely. Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via python Macro Malware Targets Macs. Scripts can be run from the command lie via `osascript /path/to/script` or `osascript -e "script here"`.

#### OS X
* [osascript - SS64](https://ss64.com/osx/osascript.html)
* [AppleScript - Wikipedia](https://en.wikipedia.org/wiki/AppleScript)
* [Introduction to AppleScript Language Guide - developer.apple](https://developer.apple.com/library/content/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html)
 




## Application Shimming
-------------------------------
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




## Command-Line Interface
-------------------------------
* [Command-Line Interface - ATT&CK](https://attack.mitre.org/wiki/Technique/T1059)
	* Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms.Wikipedia Command-Line Interface One example command-line interface on Windows systems is cmd, which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. Scheduled Task). Adversaries may use command-line interfaces to interact with systems and execute other software during the course of an operation.

#### Linux
* [Linuxcommand.org](http://linuxcommand.org/lc3_learning_the_shell.php)
* [Learn the Bash Command Line](https://ryanstutorials.net/linuxtutorial/)

#### OS X

#### Windows



## Execution through API
-------------------------------
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




## Execution through Module Load
-------------------------------
* [Execution through Module Load - ATT&CK](https://attack.mitre.org/wiki/Technique/T1129)
	* The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess(), LoadLibrary(), etc. of the Win32 API.Wikipedia Windows Library Files
	* The module loader can load DLLs: 
		* via specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;
		* via EXPORT forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);
		* via an NTFS junction or symlink program.exe.local with the fully-qualified or relative pathname of a directory containing the DLLs specified in the IMPORT directory or forwarded EXPORTs;
		* via `<file name="filename.extension" loadFrom="fully-qualified or relative pathname">` in an embedded or external "application manifest". The file name refers to an entry in the IMPORT directory or a forwarded EXPORT.
	* Adversaries can use this functionality as a way to execute arbitrary code on a system.





## Graphical User Interface
-------------------------------
* [Graphical User Interface - ATT&CK](https://attack.mitre.org/wiki/Technique/T1061)
	* Cause a binary or script to execute based on interacting with the file through a graphical user interface (GUI) or in an interactive remote session such as Remote Desktop Protocol.




## InstallUtil
-------------------------------
* [InstallUtil - ATT&CK](https://attack.mitre.org/wiki/Technique/T1118)
	* InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. InstallUtil is located in the .NET directory on a Windows system: `C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe`. InstallUtil.exe is digitally signed by Microsoft. Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil may also be used to bypass process whitelisting through use of attributes within the binary that execute the class decorated with the attribute [System.ComponentModel.RunInstaller(true)].

#### Windows
* [Installutil.exe (Installer Tool) - MSDN](https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool)
* [AllTheThings](https://github.com/subTee/AllTheThings)
	* Includes 5 Known Application Whitelisting/ Application Control Bypass Techniques in One File. (First one is InstallUtil)






## Launchctl
------------------------------- 
* [Launchctl - ATT&CK](https://attack.mitre.org/wiki/Technique/T1152)
	* Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made Sofacy Komplex Trojan. Running a command from launchctl is as simple as `launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg"`. Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges. Adversaries can abuse this functionality to execute code or even bypass whitelisting if launchctl is an allowed process.



## Powershell
-------------------------------
* [PowerShell](https://attack.mitre.org/wiki/Technique/T1086)
	* PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.TechNet PowerShell Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 
	* PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk. 
	* Administrator permissions are required to use PowerShell to connect to remote systems. 
	*  A number of PowerShell-based offensive testing tools are available, including Empire,Github PowerShell Empire PowerSploit,Powersploit and PSAttack.Github PSAttack


#### Windows
* [PowerShell - ms docs](https://docs.microsoft.com/en-us/powershell/scripting/powershell-scripting?view=powershell-5.1)
* [Powershell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
* [Microsoft Powershell - msdn](https://msdn.microsoft.com/en-us/powershell/mt173057.aspx)





## Process Hollowing
-------------------------------
* [Process Hollowing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1093)
	* Process hollowing occurs when a process is created in a suspended state and the process's memory is replaced with the code of a second program so that the second program runs instead of the original program. Windows and process monitoring tools believe the original process is running, whereas the actual program running is different. Hollowing Process hollowing may be used similarly to DLL Injection to evade defenses and detection analysis of malicious process execution by launching adversary-controlled code under the context of a legitimate process.

#### Windows
* [Process Hollowing - John Leitch - PDF](http://www.autosectools.com/process-hollowing.pdf)
* [Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
	* Great explanation of Process Hollowing







## Regsvcs/Regasm
-------------------------------
* [Regsvcs/Regasm - ATT&CK](https://attack.mitre.org/wiki/Technique/T1121)
	* Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft.MSDN RegsvcsMSDN Regasm Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: `[ComRegisterFunction]` or `[ComUnregisterFunction]` respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute.SubTee GitHub All The Things Application Whitelisting Bypass

#### Windows
* [Regsvcs.exe (.NET Services Installation Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool)
* [Regasm.exe (Assembly Registration Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool)








## Regsvr32
-------------------------------
* [Regsvr32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1117)
	* Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries.Microsoft Regsvr32 
	* Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary. 
	*  Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed.SubTee Regsvr32 Whitelisting Bypass This variation of the technique has been used in campaigns targeting governments.FireEye Regsvr32 Targeting Mongolian Gov

#### Windows
* [How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages](https://support.microsoft.com/en-us/help/249873/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages)
* [How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)
* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files) - subTee](http://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html)
* [Practical use of JavaScript and COM Scriptlets for Penetration Testing](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)







## Rundll32
-------------------------------
* [Rundll32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1085)
	* The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

#### Windows
* [Rundll32 - technet](https://technet.microsoft.com/en-us/library/ee649171(v=ws.11).aspx)
* [AppLocker Bypass – Rundll32 - pentesterlab](https://pentestlab.blog/tag/rundll32/)




## Scheduled Tasks
-------------------------------
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







## Scripting
-------------------------------
* [Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
	* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts. Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. MetasploitMetasploit, VeilVeil, and PowerSploitPowersploit are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell.Alperovitch 2014

#### OS X
* [Shell Script Basics - developer.apple](https://developer.apple.com/library/content/documentation/OpenSource/Conceptual/ShellScripting/shell_scripts/shell_scripts.html)









## Service Execution
-------------------------------
* [Service Execution - ATT&CK](https://attack.mitre.org/wiki/Technique/T1035)
	* Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by either creating a new service or modifying an existing service. This technique is the execution used in conjunction with New Service and Modify Existing Service during service persistence or privilege escalation.

#### Linux
#### OS X
#### Windows
* [Net.exe reference.](http://windowsitpro.com/windows/netexe-reference)
* [PSExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
* [xCmd an Alternative to PsExec](https://ashwinrayaprolu.wordpress.com/2011/04/12/xcmd-an-alternative-to-psexec/)




## Source
------------------------------- 
* [Source - ATT&CK](https://attack.mitre.org/wiki/Technique/T1153)
	* The source command loads functions into the current shell or executes files in the current context. This built-in command can be run in two different ways `source /path/to/filename [arguments]` or . `/path/to/filename [arguments]`. Take note of the space after the ".". Without a space, a new shell is created that runs the program instead of running the program within the current context. This is often used to make certain features or functions available to a shell or to update a specific shell's environment. Adversaries can abuse this functionality to execute programs. The file executed with this technique does not need to be marked executable beforehand.

#### Linux
* [Sourcing a File - tldp](http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x237.html)
* [Source command - bash.cyberciti](https://bash.cyberciti.biz/guide/Source_command)



 
## Spaces after Filename 
-------------------------------
* [Spaces after Filename - ATT&CK](https://attack.mitre.org/wiki/Technique/T1151)
	* Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system. For example, if there is a Mach-O executable file called evil.bin, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to evil.txt, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to "evil.txt " (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed.








## Third-Party Software
-------------------------------
Third-Party Software
* [Third-Party Software - ATT&CK](https://attack.mitre.org/wiki/Technique/T1072)
	* Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.). If an adversary gains access to these systems, then they may be able to execute code. 
	* Adversaries may gain access to and use third-party application deployment systems installed within an enterprise network. Access to a network-wide or enterprise-wide software deployment system enables an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints. 
	*  The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment.





## Trap
-------------------------------
* [Trap - ATT&CK](https://attack.mitre.org/wiki/Technique/T1154)
	* The `trap` command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format `trap` 'command list' signals where "command list" will be executed when "signals" are received.

#### Linux
* [Traps - tldp](http://tldp.org/LDP/Bash-Beginners-Guide/html/sect_12_02.html)
* [Shell Scripting Tutorial - Trap](https://www.shellscript.sh/trap.html)
* [Unix / Linux - Signals and Traps - TutorialsPoint](https://www.tutorialspoint.com/unix/unix-signals-traps.htm)











## Trusted Developer Utilites
------------------------------
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





## Windows Management Instrumentation
-------------------------------
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










## Windows Remote Management
-------------------------------
* [Windows Remote Management - ATT&CK](https://attack.mitre.org/wiki/Technique/T1028)
	* Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).Microsoft WinRM It may be called with the winrm command or by any number of programs such as PowerShell.Jacobsen 2014

#### Windows
* [An Introduction to WinRM Basics - technet](https://blogs.technet.microsoft.com/askperf/2010/09/24/an-introduction-to-winrm-basics/)
* [Windows Remote Management - msdn](https://msdn.microsoft.com/en-us/library/aa384426)
* [Using Credentials to Own Windows Boxes - Part 3 (WMI and WinRM)](http://hackingandsecurity.blogspot.com/2016/08/using-credentials-to-own-windows-boxes_99.html)







