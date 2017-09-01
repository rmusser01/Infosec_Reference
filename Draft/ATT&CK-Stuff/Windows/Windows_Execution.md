# Windows Execution



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




## Command-Line Interface
-------------------------------
[Command-Line Interface - ATT&CK](https://attack.mitre.org/wiki/Technique/T1059)
* Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms.1 One example command-line interface on Windows systems is cmd, which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. Scheduled Task). 



## Execution through API
-------------------------------
[Execution through API - ATT&CK](https://attack.mitre.org/wiki/Technique/T1106)
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

[Application Verifier Provider](https://skanthak.homepage.t-online.de/verifier.html)

[CreateProcess function - msdn](https://msdn.microsoft.com/en-us/library/ms682425)



## Execution through Module Load
-------------------------------
[Execution through Module Load - ATT&CK](https://attack.mitre.org/wiki/Technique/T1129)
* The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess(), LoadLibrary(), etc. of the Win32 API.


## Graphical User Interface
-------------------------------
[Graphical User Interface - ATT&CK](https://attack.mitre.org/wiki/Technique/T1061)
* Cause a binary or script to execute based on interacting with the file through a graphical user interface (GUI) or in an interactive remote session such as Remote Desktop Protocol. 



## InstallUtil
-------------------------------
[InstallUtil - ATT&CK](https://attack.mitre.org/wiki/Technique/T1118)
* InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries.1 InstallUtil is located in the .NET directory on a Windows system: C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe.InstallUtil.exe is digitally signed by Microsoft. 

[Installutil.exe (Installer Tool) - MSDN](https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool)
* [AllTheThings](https://github.com/subTee/AllTheThings)
* Includes 5 Known Application Whitelisting/ Application Control Bypass Techniques in One File. (First one is InstallUtil)



## Powershell
-------------------------------
[PowerShell](https://attack.mitre.org/wiki/Technique/T1086)
* PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.1 Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 

[PowerShell - ms docs](https://docs.microsoft.com/en-us/powershell/scripting/powershell-scripting?view=powershell-5.1)

[Powershell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)

[Microsoft Powershell - msdn](https://msdn.microsoft.com/en-us/powershell/mt173057.aspx)



## Process Hollowing
-------------------------------
[Process Hollowing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1093)
* Process hollowing occurs when a process is created in a suspended state and the process's memory is replaced with the code of a second program so that the second program runs instead of the original program. Windows and process monitoring tools believe the original process is running, whereas the actual program running is different. Process hollowing may be used similarly to DLL Injection to evade defenses and detection analysis of malicious process execution by launching adversary-controlled code under the context of a legitimate process. 

[Process Hollowing - John Leitch - PDF](http://www.autosectools.com/process-hollowing.pdf)
* [Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
* Great explanation of Process Hollowing (a Technique often used in Malware) 



## Regsvcs/Regasm
-------------------------------
[Regsvcs/Regasm - ATT&CK](https://attack.mitre.org/wiki/Technique/T1121)
* Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: [ComRegisterFunction] or [ComUnregisterFunction] respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute

[Regsvcs.exe (.NET Services Installation Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool)

[Regasm.exe (Assembly Registration Tool) - msdn](https://docs.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool)



## Regsvr32
-------------------------------
[Regsvr32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1117)
* Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary. Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed.2 This variation of the technique has been used in campaigns targeting governments.

[How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages](https://support.microsoft.com/en-us/help/249873/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages)

[How to Evade Application Whitelisting Using REGSVR32 - BHIS](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)

[Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files) - subTee](http://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html)

[Practical use of JavaScript and COM Scriptlets for Penetration Testing](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)



## Rundll32
-------------------------------
[Rundll32 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1085)
* The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations. 

[Rundll32 - technet](https://technet.microsoft.com/en-us/library/ee649171(v=ws.11).aspx)

[AppLocker Bypass – Rundll32 - pentesterlab](https://pentestlab.blog/tag/rundll32/)



## Scripting
-------------------------------
[Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts. 



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



## Service Execution
-------------------------------
[Service Execution - ATT&CK](https://attack.mitre.org/wiki/Technique/T1035)
* Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by either creating a new service or modifying an existing service. This technique is the execution used in conjunction with New Service and Modify Existing Service during service persistence or privilege escalation. 

[Net.exe reference.](http://windowsitpro.com/windows/netexe-reference)

[PSExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

[xCmd an Alternative to PsExec](https://ashwinrayaprolu.wordpress.com/2011/04/12/xcmd-an-alternative-to-psexec/)



## Third-Party Software
-------------------------------
[Third-Party Software - ATT&CK](https://attack.mitre.org/wiki/Technique/T1072)



## Trusted Developer Utilites
------------------------------
[Trusted Developer Utilities - ATT&CK](https://attack.mitre.org/wiki/Technique/T1127)
* There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application whitelisting defensive solutions. 

* #### MSBuild
* MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It takes XML formatted project files that define requirements for building various platforms and configurations. Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into the XML project file.2 MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application whitelisting defenses that are configured to allow MSBuild.exe execution.

[MSBuild - MSDN](https://msdn.microsoft.com/library/dd393574.aspx)

[MSBuild Inline Tasks - msdn](https://msdn.microsoft.com/library/dd722601.aspx)

[MSBuild Inline Tasks - docs ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks)

[AppLocker Bypass – MSBuild - pentestlab](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)



* #### DNX
* The .NET Execution Environment (DNX), dnx.exe, is a software development kit packaged with Visual Studio Enterprise. It was retired in favor of .NET Core CLI in 2016.4 DNX is not present on standard builds of Windows and may only be present on developer workstations using older versions of .NET Core and ASP.NET Core 1.0. The dnx.exe executable is signed by Microsoft. An adversary can use dnx.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for DNX. 

[Migrating from DNX to .NET Core CLI (project.json) - docs ms](https://docs.microsoft.com/en-us/dotnet/core/migration/from-dnx)

[Bypassing Application Whitelisting By Using dnx.exe - enigma0x3](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)



* #### RCSI
* The rcsi.exe utility is a non-interactive command-line interface for C# that is similar to csi.exe. It was provided within an early version of the Roslyn .NET Compiler Platform but has since been deprecated for an integrated solution. The rcsi.exe binary is signed by Microsoft. C# .csx script files can be written and executed with rcsi.exe at the command-line. An adversary can use rcsi.exe to proxy execution of arbitrary code to bypass application whitelisting policies that do not account for execution of rcsi.exe.

[Introducing the Microsoft “Roslyn” CTP](https://blogs.msdn.microsoft.com/visualstudio/2011/10/19/introducing-the-microsoft-roslyn-ctp/)

[Bypassing Application Whitelisting By Using rcsi.exe - enigma0x3](https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/)



* #### WinDbg/CDB
* WinDbg is a Microsoft Windows kernel and user-mode debugging utility. The Microsoft Console Debugger (CDB) cdb.exe is also user-mode debugger. Both utilities are included in Windows software development kits and can be used as standalone tools. They are commonly used in software development and reverse engineering and may not be found on typical Windows systems. Both WinDbg.exe and cdb.exe binaries are signed by Microsoft. An adversary can use WinDbg.exe and cdb.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for execution of those utilities. It is likely possible to use other debuggers for similar purposes, such as the kernel-mode debugger kd.exe, which is also signed by Microsoft. 

[Debugging Tools for Windows (WinDbg, KD, CDB, NTSD) -docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/index)

[Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner - exploitmonday](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)



## Windows Management Instrumentation
-------------------------------
[Windows Management Instrumentation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1047)
* Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB)1 and Remote Procedure Call Service (RPCS)2 for remote access. RPCS operates over port 135.3 


[Windows Management Instrumentation - msdn](https://msdn.microsoft.com/en-us/library/aa394582.aspx)

[Windows Management  Instrumentation (WMI) Offense, Defense, and Forensics](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)

[WMI_Backdoor](https://github.com/mattifestation/WMI_Backdoor)
* A PoC WMI backdoor presented at Black Hat 2015

[Abusing Windows Management Instrumentation (WMI) to Build a persistent, Asynchronous and Fileless Backdoor](http://www.securitynewspaper.com/2015/10/10/abusing-windows-management-instrumentation-wmi-to-build-a-persistent-asynchronous-and-fileless-backdoor/)

[Introduction to WMI Basics with PowerShell Part 1 (What it is and exploring it with a GUI)](https://www.darkoperator.com/blog/2013/1/31/introduction-to-wmi-basics-with-powershell-part-1-what-it-is.html)

[Creating a WMI Script - msdn](https://msdn.microsoft.com/en-us/library/aa389763(v=vs.85).aspx)

[Learn About Scripting for Windows Management Instrumentation (WMI) - technet](https://technet.microsoft.com/en-us/scriptcenter/dd742341.aspx)

[WMI Persistence using wmic.exe - exploit-monday](http://www.exploit-monday.com/2016/08/wmi-persistence-using-wmic.html)

[WMI_persistence_template.ps1](https://gist.github.com/mattifestation/e55843eef6c263608206)
* Fileless WMI persistence payload template (CommandlineEventConsumer, __IntervalTimerInstruction trigger, w/ registry payload storage)

[Playing with MOF files on Windows, for fun & profit](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)

[Managed Object Format (MOF)](https://msdn.microsoft.com/en-us/library/aa823192(VS.85).aspx)



## Windows Remote Management
-------------------------------
[Windows Remote Management - ATT&CK](https://attack.mitre.org/wiki/Technique/T1028)
* Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the winrm command or by any number of programs such as PowerShell. 

[An Introduction to WinRM Basics - technet](https://blogs.technet.microsoft.com/askperf/2010/09/24/an-introduction-to-winrm-basics/)

[Windows Remote Management - msdn](https://msdn.microsoft.com/en-us/library/aa384426)

[Using Credentials to Own Windows Boxes - Part 3 (WMI and WinRM)](http://hackingandsecurity.blogspot.com/2016/08/using-credentials-to-own-windows-boxes_99.html)







