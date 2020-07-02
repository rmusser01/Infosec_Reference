# Privilege Escalation & Post-Exploitation

----------------------------------------------------------------------
## Table of Contents
- [Privilege Escalation](#privesc)
	- [Hardware-based Privilege Escalation](#hardware)
	- [Linux Privilege Escalation](#linpriv)
	- [CSharp Things](#csharp-stuff) 
	- [Powershell Things](#powershell-stuff) 
- [Post-Exploitation](#postex)
	- [General Post Exploitation Tactics](#postex-general)
	- [Linux Post Exploitation](#linpost)
		- [Execution](#linexec)
		- [Persistence](#linpersist)
		- [Privilege Escalation](#linprivesc)
		- [Defense Evasion](#lindefe)
		- [Credential Access](#lincredac)
		- [Discovery](#lindisco)
		- [Lateral Movement](#linlat)
		- [Collection](#lincollect)
	- [OS X Post Exploitation](#osxpost)
		- [Educational](#osxedu)
		- [AppleScript](#osxa)
		- [Execution](#osxexecute)
		- [Persistence](#osxpersist)
		- [Privilege Escalation](#osxprivesc)
		- [Defense Evasion](#osxdefev)
		- [Credential Access](#osxcredac)
		- [Discovery](#osxdisco)
		- [Lateral Movement](#osxlat)
		- [Collection](#osxcollect)
	- [Windows Post Exploitation](#winpost)
		- [101](#win101)
		- [Living_off_The_Land](#lolbins)
		- [Execution](#winexec)
		- [Persistence](#winpersist)
		- [Privilege Escalation](#winprivesc)
		- [Defense Evasion](#windefev)
		- [Credential Access](#wincredac)
		- [Discovery](#windisco)
		- [Lateral Movement](#winlater)
		- [Collection](#collection)
		- [Windows Technologies](#wintech)
		- [Application Shims](#winappshims)
		- [Code Signing](#wincodesign)
		- [Windows Technologies](#wintech)
			- [ClickOnce](#clickonce)
			- [DPAPI](#dpapi)
			- [ETW](#etw)
			- [Logging](#winlog)
			- [PowerShell Desired State](#winpsc)
			- [Windows Communication Facility](#wcf)
			- [Windows Notification Facility](#wnf)
			- [Windows Scripting Host](#wsh)
- [Active Directory](#active-directory)
	- [Attacking AD 101](#adatk101)
	- [Active Directory Technologies](#ADtech)
		- [ADFS](#adfs)
		- [AdminSD](#adminsd)
		- [Advanced Threat Analytics](#ata)
		- [Advanced Threat Protection](#atp)
		- [DACLs](#dacl)
		- [DNS](#dns)
		- [Domain Trusts](#domain-trusts)
		- [Forests](#forests)
		- [Group Policy](#grouppolicy)
		- [Kerberos](#kerberos)
		- [LDAP](#ldap)
		- [Local Admin Password Solution](#laps)
		- [Lync](#lync)
		- [MS-SQL](#mssql)
		- [NTLM](#ntlm)
		- [Read-Only Domain Controllers](#rodc)
		- [Red Forest](#redforest)
		- [Service Principal Names](#spn)
		- [System Center Configuration Manager](#sccm)
		- [Domain Trusts](#trusts)
		- [WSUS](#wsus)
	- [Attacking AD](#adattack)
		- [Hunting Users](#huntingusers)
		- [DCShadow](#dcshadow)
		- [DCSync](#dcsync)
		- [Kerberos Delegation](#)
			- [Constrained](#constrained)
			- [Un-Constrained](#unconstrained)
		- [Kebreroasting](#kerberoasting)
		- [Pass-the-`*`](#pth)
		- [Shadow Admin](#shadowadmin)
		- [Skeleton Key](#skeleton)
		- [AD Vulnerabilities(CVEs)](#advulns)
		- [Defense Evasion](#addefev)
		- [Collection](#adcollect)
		- [Credential Access](#adcred)
		- [Persistence](#adpersist)
		- [Privilege Escalation](#adprivesc)
		- [Reconnaissance](#adrecon)
- [Pivoting](#pivot)
- [Avoiding/Bypassing Anti-Virus/Whitelisting/Sandboxes/etc](#av)	
- [Payloads](#payloads)




------------------------------------------------------------------------------------------------------------------------
## <a name="privesc"></a>Privilege Escalation 

---------------
### <a name="hardware">Hardware-based Privilege Escalation</a>
* **Writeups**
	* [Windows DMA Attacks : Gaining SYSTEM shells using a generic patch](https://sysdream.com/news/lab/2017-12-22-windows-dma-attacks-gaining-system-shells-using-a-generic-patch/)
	* [Where there's a JTAG, there's a way: Obtaining full system access via USB](https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Where-theres-a-JTAG-theres-a-way.pdf)
	* [Snagging creds from locked machines - mubix](https://malicious.link/post/2016/snagging-creds-from-locked-machines/)
	* [Bash Bunny QuickCreds – Grab Creds from Locked Machines](https://www.doyler.net/security-not-included/bash-bunny-quickcreds)
	* [PoisonTap](https://github.com/samyk/poisontap)
		* Exploits locked/password protected computers over USB, drops persistent WebSocket-based backdoor, exposes internal router, and siphons cookies using Raspberry Pi Zero & Node.js.
	* **Rowhammer**
		* [Exploiting the DRAM rowhammer bug to gain kernel privileges](https://googleprojectzero.blogspot.com/2015/03/exploiting-dram-rowhammer-bug-to-gain.html)
		* [Row hammer - Wikipedia](https://en.wikipedia.org/wiki/Row_hammer)
		* [Another Flip in the Wall of Rowhammer Defenses](https://arxiv.org/abs/1710.00551)
		* [rowhammer.js](https://github.com/IAIK/rowhammerjs)
			* Rowhammer.js - A Remote Software-Induced Fault Attack in JavaScript
		* [Rowhammer.js: A Remote Software-Induced Fault Attack in JavaScript](https://link.springer.com/chapter/10.1007/978-3-319-40667-1_15)
		* [Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors](https://www.ece.cmu.edu/~safari/pubs/kim-isca14.pdf)
			* Abstract. Memory isolation is a key property of a reliable and secure computing system — an access to one memory ad- dress should not have unintended side e ects on data stored in other addresses. However, as DRAM process technology scales down to smaller dimensions, it becomes more diffcult to prevent DRAM cells from electrically interacting with each other. In this paper, we expose the vulnerability of commodity DRAM chips to disturbance errors. By reading from the same address in DRAM, we show that it is possible to corrupt data in nearby addresses. More specifically, activating the same row in DRAM corrupts data in nearby rows. We demonstrate this phenomenon on Intel and AMD systems using a malicious program that generates many DRAM accesses. We induce errors in most DRAM modules (110 out of 129) from three major DRAM manufacturers. From this we conclude that many deployed systems are likely to be at risk. We identify the root cause of disturbance errors as the repeated toggling of a DRAM row’s wordline, which stresses inter-cell coupling e ects that accelerate charge leakage from nearby rows. We provide an extensive characterization study of disturbance errors and their behavior using an FPGA-based testing plat- form. Among our key findings, we show that (i) it takes as few as 139K accesses to induce an error and (ii) up to one in every 1.7K cells is susceptible to errors. After examining var- ious potential ways of addressing the problem, we propose a low-overhead solution to prevent the errors.
* **Tools**
	* [Inception](https://github.com/carmaa/inception)
		* Inception is a physical memory manipulation and hacking tool exploiting PCI-based DMA. The tool can attack over FireWire, Thunderbolt, ExpressCard, PC Card and any other PCI/PCIe HW interfaces.
	* [PCILeech](https://github.com/ufrisk/pcileech)
		* PCILeech uses PCIe hardware devices to read and write from the target system memory. This is achieved by using DMA over PCIe. No drivers are needed on the target system.
	* [physmem](https://github.com/bazad/physmem)
		* physmem is a physical memory inspection tool and local privilege escalation targeting macOS up through 10.12.1. It exploits either CVE-2016-1825 or CVE-2016-7617 depending on the deployment target. These two vulnerabilities are nearly identical, and exploitation can be done exactly the same. They were patched in OS X El Capitan 10.11.5 and macOS Sierra 10.12.2, respectively.
	* [rowhammer-test](https://github.com/google/rowhammer-test)
		* Program for testing for the DRAM "rowhammer" problem
	* [Tools for "Another Flip in the Wall"](https://github.com/IAIK/flipfloyd)



---------------
### <a name="csharp-stuff">C# Stuff</a>
* **101**
	* [GhostPack](https://github.com/GhostPack)
	* [Interesting DFIR traces of .NET CLR Usage Logs - ](https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html)
* **Educational**
	* [A Lesson in .NET Framework Versions - Rastamouse](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)
	* [The 68 things the CLR does before executing a single line of your code - mattwarren.org](https://web.archive.org/web/20170614215931/http://mattwarren.org:80/2017/02/07/The-68-things-the-CLR-does-before-executing-a-single-line-of-your-code/)
	* [An Introduction to Microsoft .NET Remoting Framework - docs.ms](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/ms973864(v=msdn.10))
	* [OffensiveCSharp-matterpreter](https://github.com/matterpreter/OffensiveCSharp)
		* This is a collection of C# tooling and POCs I've created for use on operations. Each project is designed to use no external libraries. Open each project's .SLN in Visual Studio and compile as "Release".
		* SharpBox is a C# tool for compressing, encrypting, and exfiltrating data to Dropbox using the Dropbox API.
	* [Hijacking .NET to Defend PowerShell - Amanda Rosseau](https://arxiv.org/pdf/1709.07508.pdf)
		* Abstract—With the rise of attacks using PowerShell in the recent months, there has not been a comprehensive solution for monitoring or prevention. Microsoft recently released the AMSI solution for PowerShell v5, however this can also be bypassed. This paper focuses on repurposing various stealthy runtime .NET hijacking techniques implemented for PowerShell attacks for defensive monitoring of PowerShell. It begins with a brief introduction to .NET and PowerShell, followed by a deeper explanation of various attacker techniques, which is explained from the perspective of the defender, including assembly modification, class and method injection, compiler profiling, and C based function hooking. Of the four attacker techniques that are repurposed for defensive real-time monitoring of PowerShell execution, intermediate language binary modification, JIT hooking, and machine code manipulation provide the best results for stealthy run-time interfaces for PowerShell scripting analysis
* **Credentials** 
	* [Dumping Process Memory with Custom C# Code - 3xplo1tcod3r](https://3xpl01tc0d3r.blogspot.com/2019/07/dumping-process-memory-with-custom-c-sharp.html)
	* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
		* SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
	* [SharpDump](https://github.com/GhostPack/SharpDump)
		* SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
	* [SharpLocker](https://github.com/Pickfordmatt/SharpLocker)
		* SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike. It is written in C# to allow for direct execution via memory injection using techniques such as execute-assembly found in Cobalt Strike or others, this method prevents the executable from ever touching disk. It is NOT intended to be compilled and run locally on a device.
	* [SharpClipboard](https://github.com/slyd0g/SharpClipboard)
		* C# Clipboard Monitor
		* [Blogpost](https://grumpy-sec.blogspot.com/2018/12/i-csharp-your-clipboard-contents.html)
	* [ADFSpoof](https://github.com/fireeye/ADFSpoof)
		* A python tool to forge AD FS security tokens. - Meant to be used with ADFSDump
	* [ADFSDump](https://github.com/fireeye/ADFSDump)
		* ADFSDump is a tool that will read information from Active Directory and from the AD FS Configuration Database that is needed to generate forged security tokens. This information can then be fed into ADFSpoof to generate those tokens. - Meant to be used with ADFSpoof
	* [SharpDomainSpray](https://github.com/HunnicCyber/SharpDomainSpray)
		* SharpDomainSpray is a very simple password spraying tool written in .NET. It takes a password then finds users in the domain and attempts to authenticate to the domain with that given password.
	* [SafetyKatz](https://github.com/GhostPack/SafetyKatz)
		* SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subtee's .NET PE Loader.
	* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
		* Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
	* [InveighZero](https://github.com/Kevin-Robertson/InveighZero)
		* Windows C# LLMNR/mDNS/NBNS/DNS spoofer/man-in-the-middle tool		
	* [RdpThief](https://github.com/0x09AL/RdpThief)
		* RdpThief by itself is a standalone DLL that when injected in the mstsc.exe process, will perform API hooking, extract the clear-text credentials and save them to a file.
		* [Blogpost](https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/)
	* [ATPMiniDump](https://github.com/b4rtik/ATPMiniDump)
		* Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft.
	* [SprayAD](https://github.com/outflanknl/Spray-AD)
		* This tool can help Red and Blue teams to audit Active Directory useraccounts for weak, well known or easy guessable passwords and can help Blue teams to assess whether these events are properly logged and acted upon. When this tool is executed, it generates event IDs 4771 (Kerberos pre-authentication failed) instead of 4625 (logon failure). This event is not audited by default on domain controllers and therefore this tool might help evading detection while password spraying.
	* [Rubeus](https://github.com/GhostPack/Rubeus)
		* Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpy's Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUX's MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.https://www.slideshare.net/aj0612/a-study-on-net-framework-for-red-team-part-i
* **Collection**
	* [Sharp-Profit](https://github.com/Z3R0th-13/Sharp-Profit)
		* "Sharp-Profit is a C# version of my Profit script. This version can be utilized with Cobalt Strike's execute-assembly function. Seeing as how most people are moving away from PowerShell I figured this would be a good learning opportunity. This is my first program made in C#, so I’m sure the flow isn’t the greatest. Let me know any improvements that could be made or additional functionality!"
	* [FirePwd.Net](https://github.com/gourk/FirePwd.Net)
		* FirePwd.Net is an open source tool wrote in C# to decrypt Mozilla stored password.
	* [SharpWeb](https://github.com/djhohnstein/SharpWeb)
		* SharpWeb is a .NET 2.0 CLR compliant project that can retrieve saved logins from Google Chrome, Firefox, Internet Explorer and Microsoft Edge. In the future, this project will be expanded upon to retrieve Cookies and History items from these browsers.
    * [SharpCloud](https://github.com/chrismaddalena/SharpCloud)
        * SharpCloud is a simple C# utility for checking for the existence of credential files related to Amazon Web Services, Microsoft Azure, and Google Compute.
    * [WireTap](https://github.com/djhohnstein/WireTap)
		* .NET 4.0 Project to interact with video, audio and keyboard hardware.
* **Discovery**
	* [Seatbelt](https://github.com/GhostPack/Seatbelt)
		* Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
	* [SharpView](https://github.com/tevora-threat/SharpView)
	* [HastySeries](https://github.com/obscuritylabs/HastySeries)
		* A C# toolset to support offensive operators to triage, asses and make intelligent able decisions. Provided operators access to toolsets that can be integrated into other projects and workflow throughout a Red Team, Pentest or host investigation. We built this toolset over a period of a few days, hence the tool prefix of "Hasty".
	* [reconerator](https://github.com/stufus/reconerator)
		* This is a custom .NET assembly which will perform a number of situational awareness activities.
	* [SharpSniper](https://github.com/HunnicCyber/SharpSniper)
		* Often a Red Team engagement is more than just achieving Domain Admin. Some clients will want to see if specific users in the domain can be compromised, for example the CEO. SharpSniper is a simple tool to find the IP address of these users so that you can target their box. It requires that you have privileges to read logs on Domain Controllers. First it queries and makes a list of Domain contollers, then search for Log-on events on any of the DCs for the user you are looking for and then reads the most recent DHCP allocated logon IP address.
	* [SharpWitness](https://github.com/rasta-mouse/SharpWitness)
		* SharpWitness is my attempt at cobbling together a C# version of EyeWitness by Christopher Truncer. It still barely functions right now, but will hopefully become more useful once I put some dev time into it.	
	* [SharpPrinter](https://github.com/rvrsh3ll/SharpPrinter)
		* Printer is a modified and console version of ListNetworks
	* [SharpSearch](https://github.com/djhohnstein/SharpSearch)
		* Search files for extensions as well as text within.
	* [SharpFruit](https://github.com/rvrsh3ll/SharpFruit)
		* A C# penetration testing tool to discover low-haning web fruit via web requests.
	* [Recon-AD](https://github.com/outflanknl/Recon-AD)
		* As a proof of concept, we[OutflankNL] developed an C/C++ Active Directory reconnaissance tool based on ADSI and reflective DLLs which can be used within Cobalt Strike. The tool is called “Recon-AD” and at this moment consist of seven Reflective DLLs and a corresponding aggressor script. This tool should help you moving away from PowerShell and .NET when enumerating Active Directory and help you stay under the radar from the latest monitoring and defense technologies being applied within modern environments.
* **Execution**
	* [RunDLL32 your .NET (AKA DLL exports from .NET) - Adam Chester](https://blog.xpnsec.com/rundll32-your-dotnet/)
		* In this post I wanted to look at a technique which is by no means new to .NET developers, but may prove useful to redteamers crafting their tools... exporting .NET static methods within a DLL... AKA using RunDLL32 to launch your .NET assembly.
	* [Staying # & Bringing Covert Injection Tradecraft to .NET - The Wover, Ruben Boonen(BlueHat IL 2020)](https://www.youtube.com/watch?v=FuxpMXTgV9s&feature=share)
		* As .NET has taken over as the preferred platform for development on Windows, many attackers have chosen to take advantage of its features for post-exploitation tradecraft. Legitimate APIs can be leveraged for nearly every imaginable task, managed code can be loaded and executed from memory with extraordinary ease, and scalable monitoring for suspicious usage of .NET APIs is a problem yet to be solved. However, offensive .NET tools are still hindered by a fundamental weakness: the inability to leverage unmanaged code (such as the Win32/NT APIs) safe from observation by EDR. Managed code must eventually invoke unmanaged code in order to interface with the operating system. It is here that the attacker may be caught in the hooks of any system keen on watching for fundamentally malicious behavior. To expose the depth of tradecraft still unexplored in .NET and highlight the fragility of many existing detections, we will detail the tools we have built for evading these hooks.  All of our efforts have been integrated into SharpSploit, a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers. Over the past few months we have added numerous new tools and techniques for loading and executing unmanaged code safely from .NET. Unmanaged APIs may be safely accessed and modules loaded either from memory or from disk in the new DInvoke API, a dynamic replacement for .NET's PInvoke API. It also includes manual mapping, a generic syscall wrapper, a new technique we call Module Overloading, and more. Additionally, we have added a modular process injection API that allows tool developers to build their own injection technique. Simply select an allocation and injection primitive, pass in any options, and execute the result with your preferred payload. This exposes all possible design decisions to the user, and allows for easy adaptation when existing tools fail.  In our talk we will focus on explaining the fundamental tradecraft behind these new developments, the challenges and requirements associated with them, and how they can be adapted to suit your needs. Additionally, we will discuss how SharpSploit can be combined with other open-source projects to be integrated into a red team's tooling. As much as possible, we will also discuss how to counter and detect the techniques that we have developed. Finally, we will explain the community-focused development of these projects and how you too can contribute to advance open-source .NET tradecraft
	* [CSExec](https://github.com/malcomvetter/CSExec)
		* This is an example for how to implement psexec (from SysInternals Suite) functionality, but in open source C#. This does not implement all of the psexec functionality, but it does implement the equivalent functionality to running: psexec -s \\target-host cmd.exe
	* [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
		* SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
	* [SharpCradle](https://github.com/anthemtotheego/SharpCradle)
		* SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.	
	* [ManagedWindows](https://github.com/zodiacon/ManagedWindows)
		* Managed wrappers around the Windows API and some Native API
	* [DotNet Core: A Vector For AWL Bypass & Defense Evasion - bohops](https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/)
	* [TikiService](https://rastamouse.me/2019/08/tikiservice/)
		* TikiService is a new .NET Service Binary that allows you to run a TikiTorch payload via the Service Control Manager (à la PsExec). This blog post provides a brief overview and usage examples.
	* [Create a Trimmed Self-Contained Single Executable in .NET Core 3.0 - talkingdotnet.com](https://www.talkingdotnet.com/create-trimmed-self-contained-executable-in-net-core-3-0/)
	* [SharpExcel4-DCOM](https://github.com/rvrsh3ll/SharpExcel4-DCOM)
		* Port of Invoke-Excel4DCOM
	* [Running a .NET Assembly in Memory with Meterpreter - Thomas Hendrickson](https://www.praetorian.com/blog/running-a-net-assembly-in-memory-with-meterpreter)
	* [Reflection in the .NET Framework - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/reflection)
	* [PowerAvails](https://github.com/homjxi0e/PowerAvails)
		* PowerAvails Powershell .NET Operating system
	* [Offensive P/Invoke: Leveraging the Win32 API from Managed Code - Matt Hand](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d)
	* [Using Parameters With InstallUtil - ip3lee](https://diaryofadeveloper.wordpress.com/2012/04/26/using-paramters-with-installutil/)
	* [Shellcode: Loading .NET Assemblies From Memory - modexp](https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/)
	* [OffensiveDLR](https://github.com/byt3bl33d3r/OffensiveDLR)
		* Toolbox containing research notes & PoC code for weaponizing .NET's DLR
	* [MemorySharp](https://github.com/ZenLulz/MemorySharp)
		* MemorySharp is a C# based memory editing library targeting Windows applications, offering various functions to extract and inject data and codes into remote processes to allow interoperability.
	* [Running a .NET Assembly in Memory with Meterpreter - Thomas Hendrickson](https://www.praetorian.com/blog/running-a-net-assembly-in-memory-with-meterpreter)
	* [RunShellcode](https://github.com/zerosum0x0/RunShellcode)
		* Simple GUI program when you just want to run some shellcode.
	* [ManagedInjection](https://github.com/malcomvetter/ManagedInjection)
		* A proof of concept for dynamically loading .net assemblies at runtime with only a minimal convention pre-knowledge
	* [SharpAttack](https://github.com/jaredhaight/SharpAttack)
		* SharpAttack is a console for certain things I use often during security assessments. It leverages .NET and the Windows API to perform its work. It contains commands for domain enumeration, code execution, and other fun things.
	* [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
		* ﻿This file is part of DotNetToJScript - A tool to generate a JScript which bootstraps an arbitrary .NET Assembly and class.
	* [SharpNado - Teaching an old dog evil tricks using .NET Remoting or WCF to host smarter and dynamic payloads - redxorblue](http://blog.redxorblue.com/2018/12/sharpnado-teaching-old-dog-evil-tricks.html)
		* SharpNado is proof of concept tool that demonstrates how one could use .Net Remoting or Windows Communication Foundation (WCF) to host smarter and dynamic .NET payloads.  SharpNado is not meant to be a full functioning, robust, payload delivery system nor is it anything groundbreaking. It's merely something to get the creative juices flowing on how one could use these technologies or others to create dynamic and hopefully smarter payloads. I have provided a few simple examples of how this could be used to either dynamically execute base64 assemblies in memory or dynamically compile source code and execute it in memory.  This, however, could be expanded upon to include different kinds of stagers, payloads, protocols, etc.
* **Lateral Movement**
	* [SharpExec - Lateral Movement With Your Favorite .NET Bling - RedXORBlue](http://blog.redxorblue.com/2019/04/sharpexec-lateral-movement-with-your.html)
		* [SharpExec - Github](https://github.com/anthemtotheego/SharpExec)
	* [Lateral movement via MSSQL: a tale of CLR and socket reuse - Juan Manuel Fernandez, Pablo Martínez](https://www.blackarrow.net/mssqlproxy-pivoting-clr/)
		* Recently, our Red Team had to deal with a restricted scenario, where all traffic from the DMZ to the main network was blocked, except for connections to specific services like databases and some web applications. In this article, we will explain how we overcame the situation, covering the technical details. We also introduce [mssqlproxy](https://github.com/blackarrowsec/mssqlproxy), a tool for turning a Microsoft SQL Server into a socks proxy.
	* [SharpCOM](https://github.com/rvrsh3ll/SharpCOM)
		* SharpCOM is a c# port of Invoke-DCOM
	* [SharpRPD](https://github.com/0xthirteen/SharpRDP)
		* Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
		* [Revisiting Remote Desktop Lateral Movement - Steven F](https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3)
	* [SharpMove](https://github.com/0xthirteen/SharpMove)
		* .NET Project for performing Authenticated Remote Execution
	* [SCShell](https://github.com/Mr-Un1k0d3r/SCShell)	
		* Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
	* [SharpWMI](https://github.com/GhostPack/SharpWMI)
		* SharpWMI is a C# implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods.
	* [SharpDoor](https://github.com/infosecn1nja/SharpDoor)
		* SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file, for opsec considerations SharpDoor still using cmd.exe to run sc services to impersonating as trustedinstaller in the future will be avoiding cmd.exe usage, currently only support for Windows 10.
* **Persistence**
	* [SharpStay](https://github.com/0xthirteen/SharpStay)
		* .NET project for installing Persistence
	* [Task Scheduler](https://github.com/dahall/taskscheduler)
		* Provides a .NET wrapper for the Windows Task Scheduler. It aggregates the multiple versions, provides an editor and allows for localization.
* **PrivEsc**
	* [SharpExchangePriv](https://github.com/panagioto/SharpExchangePriv)
		* A C# implementation of PrivExchange by `@_dirkjan`. Kudos to @g0ldenGunSec, as I relied on his code.
	* [SharpUp](https://github.com/GhostPack/SharpUp)
		* SharpUp is a C# port of various PowerUp functionality. Currently, only the most common checks have been ported; no weaponization functions have yet been implemented.
	* [Watson](https://github.com/rasta-mouse/Watson)
		* Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
* **Other**
	* [bytecode-api](https://github.com/bytecode77/bytecode-api)
		* C# library with common classes, extensions and additional features in addition to the .NET Framework. BytecodeApi implements lots of extensions and classes for general purpose use. In addition, specific classes implement more complex logic for both general app development as well as for WPF apps. Especially, boilerplate code that is known to be part of any Core DLL in a C# project is likely to be already here. In fact, I use this library in many of my own projects. For this reason, each class and method has been reviewed numerous times. BytecodeApi is highly consistent, particularly in terms of structure, naming conventions, patterns, etc. The entire code style resembles the patterns used in the .NET Framework itself. You will find it intuitive to understand.
	* [OutlookToolbox](https://github.com/ThunderGunExpress/OutlookToolbox)
		* OutlookToolbox is a C# DLL that uses COM to do stuff with Outlook. Also included is a Cobalt Strike aggressor script that uses Outlooktoolbox.dll to give it a graphical and control interface.
		* [Blogpost](https://ijustwannared.team/2017/10/28/outlooktoolbox/)
	* [Using C# for post-PowerShell attacks - John Bergbom(2018)](https://www.forcepoint.com/blog/x-labs/using-c-post-powershell-attacks)
	* [SharpBox](https://github.com/P1CKLES/SharpBox)











---------------
### <a name="powershell-stuff">Powershell Things</a>
* **101**
* **Educational**
	* [Get-Help: An Intro to PowerShell and How to Use it for Evil - Jared Haight](https://www.psattack.com/presentations/get-help-an-intro-to-powershell-and-how-to-use-it-for-evil/)
	* [Brosec](https://github.com/gabemarshall/Brosec)
		* Brosec is a terminal based reference utility designed to help us infosec bros and broettes with usefuPowershelll (yet sometimes complex) payloads and commands that are often used during work as infosec practitioners. An example of one of Brosec's most popular use cases is the ability to generate on the fly reverse shells (python, perl, powershell, etc) that get copied to the clipboard.
	* [Introducing PowerShell into your Arsenal with PS>Attack - Jared Haight](http://www.irongeek.com/i.php?page=videos/derbycon6/119-introducing-powershell-into-your-arsenal-with-psattack-jared-haight)
		* [Introducing PS Attack, a portable PowerShell attack toolkit - Jared Haight](https://www.youtube.com/watch?v=lFCtPdUPdHw)
	* [PowerShell Secrets and Tactics Ben0xA ](https://www.youtube.com/watch?v=mPPv6_adTyg)
	* [Egress Testing using PowerShell](http://www.labofapenetrationtester.com/2014/04/egress-testing-using-powershell.html)
    * [Defensive Coding Strategies for a High-Security Environment - Matt Graeber - PowerShell Conference EU 2017](https://www.youtube.com/watch?reload=9&v=O1lglnNTM18)
        * How sure are you that your PowerShell code is prepared to handle anything that a user might throw at it? What if the user was an attacker attempting to circumvent security controls by exploiting a vulnerability in your script? This may sound unrealistic but this is a legitimate concern of the PowerShell team when including PowerShell code in the operating system. In a high-security environment where strict AppLocker or Device Guard rules are deployed, PowerShell exposes a large attack surface that can be used to circumvent security controls. While constrained language mode goes a long way in preventing malicious PowerShell code from executing, attackers will seek out vulnerabilities in trusted signed code in order to circumvent security controls. This talk will cover numerous different ways in which attackers can influence the execution of your code in unanticipated ways. A thorough discussion of mitigations against such attacks will then follow.
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Client Side attacks using Powershell](http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html)
	* [Accessing the Windows API in PowerShell via internal .NET methods and reflection](http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html)
		* It is possible to invoke Windows API function calls via internal .NET native method wrappers in PowerShell without requiring P/Invoke or C# compilation. How is this useful for an attacker? You can call any Windows API function (exported or non-exported) entirely in memory. For those familiar with Metasploit internals, think of this as an analogue to railgun.
	* [PSReflect](https://github.com/mattifestation/PSReflect)
		* Easily define in-memory enums, structs, and Win32 functions in PowerShell
* **Command and Control**
	* [Empire](https://github.com/EmpireProject/Empire)
		* Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent. It is the merge of the previous PowerShell Empire and Python EmPyre projects. The framework offers cryptologically-secure communications and a flexible architecture. On the PowerShell side, Empire implements the ability to run PowerShell agents without needing powershell.exe, rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz, and adaptable communications to evade network detection, all wrapped up in a usability-focused framework. PowerShell Empire premiered at BSidesLV in 2015 and Python EmPyre premeiered at HackMiami 2016.
	* [Koadic](https://github.com/zerosum0x0/koadic)
		* Koadic, or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript), with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.
	* [Babadook](https://github.com/jseidl/Babadook)
		* Connection-less Powershell Persistent and Resilient Backdoor
* **Bypass X**
	* **General**
		* [nps_payload](https://github.com/trustedsec/nps_payload)
			* This script will generate payloads for basic intrusion detection avoidance. It utilizes publicly demonstrated techniques from several different sources.
	* **AMSI**
		* See Avoiding AV section
    * **Constrained-Language Mode**
		* **Articles/Blogposts/Writeups**
			* [PowerShell Constrained Language Mode - devblogs.ms](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
			* [Exploiting PowerShell Code Injection Vulnerabilities to Bypass Constrained Language Mode](http://www.exploit-monday.com/2017/08/exploiting-powershell-code-injection.html?m=1)
			* [AppLocker CLM Bypass via COM - MDSec](https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/)
			* [Powershell CLM Bypass Using Runspaces - Shaksham Jaiswal](https://www.secjuice.com/powershell-constrainted-language-mode-bypass-using-runspaces/)
				* [CLMBypassBlogpost](https://github.com/MinatoTW/CLMBypassBlogpost)
			* [A Comparison of Shell and Scripting Language Security - PowerShell Team](https://devblogs.microsoft.com/powershell/a-comparison-of-shell-and-scripting-language-security/)
		* **Tools**
			* [DotNetToJScript Constrained/Restricted LanguageMode Breakout](https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout/blob/master/README.md)
				* This repository is based on a post by [@xpn](https://twitter.com/_xpn_), [more details available here.](https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/) Xpn's post outlines a bug of sorts where ConstrainedLanguage, when enforced through AppLocker does not prevent COM invocation. Because of this it is possible to define a custom COM object in the registry and force PowerShell to load a Dll. On load it is possible to change the LanguageMode to FullLanguage and break out of the restricted shell. This repo is a variation on this technique where a DotNetToJScript scriptlet is used to directly stage a .Net assembly into the PowerShell process.
			* [PoSH_Bypass](https://github.com/davehardy20/PoSHBypass)
				* PoSHBypass is a payload and console proof of concept that allows an attatcker or for that matter a legitimate user to bypass PowerShell's 'Constrianed Language Mode, AMSI and ScriptBlock and Module logging'. The bulk of this concept is the combination of 3 separate pieces of research, I've stuck these 3 elements together as my first attempt at non 'Hello World!' C# project.
			* [PSByPassCLM](https://github.com/padovah4ck/PSByPassCLM)
				* Bypass for PowerShell Constrained Language Mode
			* [powershellveryless](https://github.com/decoder-it/powershellveryless)
				* Constrained Language Mode + AMSI bypass all in one(Currently Blocked without modification)
	* **Execution Policy**
		* [15 Ways to Bypass the PowerShell Execution Policy - NetSPI](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
		* [Bat Armor](https://github.com/klsecservices/bat-armor)
			* Bypass PowerShell execution policy by encoding ps script into bat file.
	* **Logging**
		* [About Eventlogs(PowerShell) - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1)
		* [Script Tracing and Logging - docs.ms](https://docs.microsoft.com/en-us/powershell/wmf/whats-new/script-logging)
* **Frameworks**
	* Empire -> See rt.md
	* Powersploit
	* **Nishang**
		* [Nishang](https://github.com/samratashok/nishang)
			* Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
		* [Hacking In Windows Using Nishang With Windows PowerShell, Like A Boss! - serenity-networks.com](https://serenity-networks.com/hacking-in-windows-using-nishang-with-windows-powershell/)
* **Dumping/Grabbing Creds**
	* [Out-Minidump.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)
		* Generates a full-memory minidump of a process.
	* [PShell Script: Extract All GPO Set Passwords From Domain](http://www.nathanv.com/2012/07/04/pshell-script-extract-all-gpo-set-passwords-from-domain/)
		* This script parses the domain’s Policies folder looking for Group.xml files.  These files contain either a username change, password setting, or both.  This gives you the raw data for local accounts and/or passwords enforced using Group Policy Preferences.  Microsoft chose to use a static AES key for encrypting this password.  How awesome is that!
	* [mimikittenz](https://github.com/putterpanda/mimikittenz/)
		* A post-exploitation powershell tool for extracting juicy info from memory.
	* [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
		* Inveigh is a PowerShell LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system.
	* [PowerMemory](https://github.com/giMini/PowerMemory)
		* Exploit the credentials present in files and memory. PowerMemory levers Microsoft signed binaries to hack Microsoft operating systems.
	* [Dump-Clear-Text-Password-after-KB2871997-installed](https://github.com/3gstudent/Dump-Clear-Password-after-KB2871997-installed)
		* Auto start Wdigest Auth,Lock Screen,Detect User Logon and get clear password.
	* [SessionGopher](https://github.com/fireeye/SessionGopher)
		* SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It has WMI functionality built in so it can be run remotely. Its best use case is to identify systems that may connect to Unix systems, jump boxes, or point-of-sale terminals. SessionGopher works by querying the HKEY_USERS hive for all users who have logged onto a domain-joined box at some point. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. It automatically extracts and decrypts WinSCP, FileZilla, and SuperPuTTY saved passwords. When run in Thorough mode, it also searches all drives for PuTTY private key files (.ppk) and extracts all relevant private key information, including the key itself, as well as for Remote Desktop (.rdp) and RSA (.sdtid) files.
	* [Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump)
		* PowerShell script to dump Windows credentials from the Credential Manager. Invoke-WCMDump enumerates Windows credentials in the Credential Manager and then extracts available information about each one. Passwords are retrieved for "Generic" type credentials, but can not be retrived by the same method for "Domain" type credentials. Credentials are only returned for the current user. Does not require admin privileges!
	* [MimiDbg](https://github.com/giMini/mimiDbg)
		* PowerShell oneliner to retrieve wdigest passwords from the memory
	* [mimikittenz](https://github.com/putterpanda/mimikittenz/)
		* mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes.
* **Grabbing Useful files**
	* [BrowserGatherer](https://github.com/sekirkity/BrowserGather)
		* Fileless Extraction of Sensitive Browser Information with PowerShell
	* [SessionGopher](https://github.com/fireeye/SessionGopher)
		* SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.
	* [CC_Checker](https://github.com/NetSPI/PS_CC_Checker)
		* CC_Checker cracks credit card hashes with PowerShell.
	* [BrowserGather](https://github.com/sekirkity/BrowserGather)
		* Fileless Extraction of Sensitive Browser Information with PowerShell. This project will include various cmdlets for extracting credential, history, and cookie/session data from the top 3 most popular web browsers (Chrome, Firefox, and IE). The goal is to perform this extraction entirely in-memory, without touching the disk of the victim. Currently Chrome credential and cookie extraction is supported. 
* **Lateral Movement**
	* [Invoke-CommandAs](https://github.com/mkellerman/Invoke-CommandAs)
       * Invoke Command as System/User on Local/Remote computer using ScheduleTask.
* **Malicious X (Document/Macro/whatever) Generation**
	* [​psWar.py](https://gist.github.com/HarmJ0y/aecabdc30f4c4ef1fad3)
	* Code that quickly generates a deployable .war for a PowerShell one-liner
* **Obfuscation**
	* [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
		* Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
		* [Presentation](https://www.youtube.com/watch?v=P1lkflnWb0I)
		* [Invoke-Obfuscation: PowerShell obFUsk8tion Techniques & How To (Try To) D""e`Tec`T 'Th'+'em'](http://www.irongeek.com/i.php?page=videos/derbycon6/121-invoke-obfuscation-powershell-obfusk8tion-techniques-how-to-try-to-detect-them-daniel-bohannon)
		* [PyFuscation](https://github.com/CBHue/PyFuscation)
	* Obfuscate powershell scripts by replacing Function names, Variables and Parameters.
	* [Pulling Back the Curtains on EncodedCommand PowerShell Attacks](https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/)
	* [Invoke-CradleCrafter: Moar PowerShell obFUsk8tion by Daniel Bohannon](https://www.youtube.com/watch?feature=youtu.be&v=Nn9yJjFGXU0&app=desktop)
	* [Invoke-CradleCrafter v1.1](https://github.com/danielbohannon/Invoke-CradleCrafter)
	* [invoke-Confusion .NET attacker of Powershell Remotely - homjxl0e]
	* [PowerAvails](https://github.com/homjxi0e/PowerAvails)
	* [PowerShell Obfuscation using SecureString - ](https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring)
		* TL;DR - PowerShell has built-in functionality to save sensitive plaintext data to an encrypted object called `SecureString`. Malicious actors have exploited this functionality as a means to obfuscate PowerShell commands. This blog post discusses `SecureString`, examples seen in the wild, and [presents a tool](https://wietze.github.io/powershell-securestring-decoder/) that helps analyse SecureString obfuscated commands.
	* [pOWershell obFUsCation - N1CFURY](https://n1cfury.com/ps-obfuscation/)
* **Powershell without Powershell**
	* **Articles/Blogposts/Writeups**
		* [Empire without PowerShell.exe](https://bneg.io/2017/07/26/empire-without-powershell-exe/)
		* [Powershell without Powershell to bypass app whitelist](https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/)
		* [We don’t need powershell.exe - decoder.cloud](https://decoder.cloud/2017/11/02/we-dont-need-powershell-exe/)
			* [Part 2](https://decoder.cloud/2017/11/08/we-dont-need-powershell-exe-part-2/)
			* [Part 3](https://decoder.cloud/2017/11/17/we-dont-need-powershell-exe-part-3/)
		* [PowerShell: In-Memory Injection Using CertUtil.exe](https://www.coalfire.com/The-Coalfire-Blog/May-2018/PowerShell-In-Memory-Injection-Using-CertUtil-exe)
		* [Run PowerShell without Powershell.exe — Best tools & techniques - Bank Security](https://medium.com/@Bank_Security/how-to-running-powershell-commands-without-powershell-exe-a6a19595f628)
	* **Talks & Presentations**
	* **Tools**
		* [PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell)
			* PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. You can also execute raw shellcode using the same approach.
		* [NoPowerShell](https://github.com/bitsadmin/nopowershell)
			* NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No `System.Management.Automation.dll` is used; only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: `rundll32 NoPowerShell.dll,main`.
		* [p0wnedShell](https://github.com/Cn33liz/p0wnedShell)
			* p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET).	
		* [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell/tree/master)
		* [nps - Not PowerShell](https://github.com/Ben0xA/nps)
			* Execute powershell without powershell.exe
		* [PSShell](https://github.com/fdiskyou/PSShell)
			* PSShell is an application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET). It doesn't need to be "installed" so it's very portable.
		* [PowerShdll](https://github.com/p3nt4/PowerShdll)
			* Run PowerShell with rundll32. Bypass software restrictions.
		* [PowerOPS: PowerShell for Offensive Operations](https://labs.portcullis.co.uk/blog/powerops-powershell-for-offensive-operations/)
		* [PowerOPS Github page](https://github.com/fdiskyou/PowerOPS)
			* PowerOPS is an application written in C# that does not rely on powershell.exe but runs PowerShell commands and functions within a powershell runspace environment (.NET). It intends to include multiple offensive PowerShell modules to make the process of Post Exploitation easier.
		* [PowerLine](https://github.com/fullmetalcache/powerline)
			* [Presentation](https://www.youtube.com/watch?v=HiAtkLa8FOc)
			* Running into environments where the use of PowerShell is being monitored or is just flat-out disabled? Have you tried out the fantastic PowerOps framework but are wishing you could use something similar via Meterpreter, Empire, or other C2 channels? Look no further! In this talk, Brian Fehrman talks about his new PowerLine framework. He overviews the tool, walks you through how to use it, shows you how you can add additional PowerShell scripts with little effort, and demonstrates just how powerful (all pun intended) this little program can be!
* **Priv Esc / Post Ex Scripts**
	* [PowerUp](https://github.com/HarmJ0y/PowerUp) 
		* PowerUp is a powershell tool to assist with local privilege escalation on Windows systems. It contains several methods to identify and abuse vulnerable services, as well as DLL hijacking opportunities, vulnerable registry settings, and escalation opportunities.
	* [Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/README.md)
		* PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.
	* [JSRat-Py](https://github.com/Hood3dRob1n/JSRat-Py) 
		* implementation of JSRat.ps1 in Python so you can now run the attack server from any OS instead of being limited to a Windows OS with Powershell enabled
	* [ps1-toolkit](https://github.com/vysec/ps1-toolkit)
		* This is a set of PowerShell scripts that are used by many penetration testers released by multiple leading professionals. This is simply a collection of scripts that are prepared and obfuscated to reduce level of detectability and to slow down incident response from understanding the actions performed by an attacker.
* **Recon**
	* [Invoke-ProcessScan](https://github.com/vysec/Invoke-ProcessScan)
		* Gives context to a system. Uses EQGRP shadow broker leaked list to give some descriptions to processes.
	* [Powersploit-PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
		* PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net \*" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.
	* [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
		* AD PowerShell Recon Scripts
	* [PowEnum](https://github.com/whitehat-zero/PowEnum)
		* PowEnum executes common PowerSploit Powerview functions and combines the output into a spreadsheet for easy analysis. All network traffic is only sent to the DC(s). PowEnum also leverages PowerSploit Get-GPPPassword and Harmj0y's ASREPRoast.
* **Signatures**
	* [DigitalSignature-Hijack.ps1](https://gist.github.com/netbiosX/fe5b13b4cc59f9a944fe40944920d07c)
		* [Hijack Digital Signatures – PowerShell Script - pentestlab](https://pentestlab.blog/2017/11/08/hijack-digital-signatures-powershell-script/)
	* [PoCSubjectInterfacePackage](https://github.com/mattifestation/PoCSubjectInterfacePackage)
		* A proof-of-concept subject interface package (SIP) used to demonstrate digital signature subversion attacks.
* **Miscellaneous Useful Things** 
	* [Invoke-DCOM.ps1](https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1)
	* [PowerShell and Token Impersonation](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)
	* [Harness](https://github.com/Rich5/Harness)
		* Harness is remote access payload with the ability to provide a remote interactive PowerShell interface from a Windows system to virtually any TCP socket. The primary goal of the Harness Project is to provide a remote interface with the same capabilities and overall feel of the native PowerShell executable bundled with the Windows OS.
	* [DPAPI Primer for Pentesters - webstersprodigy](https://webstersprodigy.net/2013/04/05/dpapi-primer-for-pentesters/)
	* [PowerHub](https://github.com/AdrianVollmer/PowerHub)
		* Webserver frontend for powersploit with functionality and niceness.
	* [Invoke-VNC](https://github.com/artkond/Invoke-Vnc)
		* Powershell VNC injector
	* [Invoke-BSOD](https://github.com/peewpw/Invoke-BSOD)
		* A PowerShell script to induce a Blue Screen of Death (BSOD) without admin privileges. Also enumerates Windows crash dump settings. This is a standalone script, it does not depend on any other files.
	* [Invoke-SocksProxy](https://github.com/p3nt4/Invoke-SocksProxy)
		* Creates a Socks proxy using powershell.
	* [OffensivePowerShellTasking](https://github.com/leechristensen/OffensivePowerShellTasking)
		* Run multiple PowerShell scripts concurrently in different app domains. Solves the offensive security problem of running multiple PowerShell scripts concurrently without spawning powershell.exe and without the scripts causing problems with each other (usually due to PInvoke'd functions).
	* [PowerShell-Suite](https://github.com/FuzzySecurity/PowerShell-Suite/)
		* There are great tools and resources online to accomplish most any task in PowerShell, sometimes however, there is a need to script together a util for a specific purpose or to bridge an ontological gap. This is a collection of PowerShell utilities I put together either for fun or because I had a narrow application in mind. - b33f
	* [Powershell-SSHTools](https://github.com/fridgehead/Powershell-SSHTools)
		* A bunch of useful SSH tools for powershell
	* **Utilities**
		* [7Zip4Powershell](https://github.com/thoemmi/7Zip4Powershell) 
			* Powershell module for creating and extracting 7-Zip archives
	* **Servers**
		* [Dirty Powershell Webserver](http://obscuresecurity.blogspot.com/2014/05/dirty-powershell-webserver.html)
		* [Pode](https://github.com/Badgerati/Pode)
			* Pode is a PowerShell framework that runs HTTP/TCP listeners on a specific port, allowing you to host REST APIs, Web Pages and SMTP/TCP servers via PowerShell. It also allows you to render dynamic HTML using PSHTML files.




-------------------
## Post-Exploitation<a name="postex"></a>

-------------------
### <a name="postex-general"></a>General Post Exploitation
* **Tactics**
	* [Adversarial Post Ex - Lessons from the Pros](https://www.slideshare.net/sixdub/adversarial-post-ex-lessons-from-the-pros)
	* [Meta-Post Exploitation - Using Old, Lost, Forgotten Knowledge](https://www.blackhat.com/presentations/bh-usa-08/Smith_Ames/BH_US_08_Smith_Ames_Meta-Post_Exploitation.pdf)
	* [Operating in the Shadows - Carlos Perez - DerbyCon(2015)](https://www.youtube.com/watch?v=NXTr4bomAxk)
	* [RTLO-attack](https://github.com/ctrlaltdev/RTLO-attack)
		* This is a really simple example on how to create a file with a unicode right to left ove rride character used to disguise the real extention of the file.  In this example I disguise my .sh file as a .jpg file.
	* [Blog](https://ctrlalt.dev/RTLO)
	* [IPFuscator](https://github.com/vysec/IPFuscator)
		* IPFuscation is a technique that allows for IP addresses to be represented in hexadecimal or decimal instead of the decimal encoding we are used to. IPFuscator allows us to easily convert to these alternative formats that are interpreted in the same way.
		* [Blogpost](https://vincentyiu.co.uk/ipfuscation/)
	* [Cuteit](https://github.com/D4Vinci/Cuteit)
		* A simple python tool to help you to social engineer, bypass whitelisting firewalls, potentially break regex rules for command line logging looking for IP addresses and obfuscate cleartext strings to C2 locations within the payload.
* **Egress Testing**
	* [Egress Testing using PowerShell](http://www.labofapenetrationtester.com/2014/04/egress-testing-using-powershell.html)
	* [Egress Buster Reverse Shell](https://www.trustedsec.com/files/egress_buster_revshell.zip)
		* Egress Buster Reverse Shell – Brute force egress ports until one if found and execute a reverse shell(from trustedsec)
	* [Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess)
		* Egress-Assess is a tool used to test egress data detection capabilities
* **Execution**
	* [Shellpaste](https://github.com/andrew-morris/shellpaste)
		* Tiny snippet of code that pulls ASCII shellcode from pastebin and executes it. The purpose of this is to have a minimal amount of benign code so AV doesn't freak out, then it pulls down the evil stuff. People have been doing this kind of stuff for years so I take no credit for the concept. That being said, this code (or similar code) works surprisingly often during pentests when conventional malware fails.
* **File Transfer**
	* **Platform-Neutral**
		* [Updog](https://github.com/sc0tfree/updog)
			* Updog is a replacement for Python's SimpleHTTPServer. It allows uploading and downloading via HTTP/S, can set ad hoc SSL certificates and use http basic auth.
		* [File transfer skills in the red team post penetration test - xax007](https://www.exploit-db.com/docs/english/46515-file-transfer-skills-in-the-red-team-post-penetration-test.pdf)
		* [(Almost) All The Ways to File Transfer - PenTest-Duck](https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65)
		* [ffsend](https://github.com/timvisee/ffsend)
			* Easily and securely share files and directories from the command line through a safe, private and encrypted link using a single simple command. Files are shared using the Send service and may be up to 1GB (2.5GB authenticated). Others are able to download these files with this tool, or through their web browser.
	* **Linux**
	* **Mac OS**
	* **Windows**
		* [WMI & PowerShell: An Introduction to Copying Files - FortyNorthSecurity](https://fortynorthsecurity.com/blog/wmi/)
* **Persistence**
	* [List of low-level attacks/persistence techniques.  HIGHLY RECOMMENDED!](http://timeglider.com/timeline/5ca2daa6078caaf4)
	* [How to Remotely Control Your PC (Even When it Crashes)](https://www.howtogeek.com/56538/how-to-remotely-control-your-pc-even-when-it-crashes/)
	* **Backdooring X**
		* [Introduction to Manual Backdooring - abatchy17](http://www.abatchy.com/2017/05/introduction-to-manual-backdooring_24.html)
		* [Backdooring PE-File (with ASLR) - hansesecure.de](https://hansesecure.de/2018/06/backdooring-pe-file-with-aslr/?lang=en)
			* Simple codecave
		* [An Introduction to Backdooring Operating Systems for Fun and trolling - Defcon22](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20video%20and%20slides/DEF%20CON%2022%20Hacking%20Conference%20Presentation%20By%20Nemus%20-%20An%20Introduction%20to%20Back%20Dooring%20Operating%20Systems%20for%20Fun%20and%20Trolling%20-%20Video%20and%20Slides.m4v)
	* **Building a backdoored Binary**
		* [Pybuild](https://www.trustedsec.com/files/pybuild.zip)
			* PyBuild is a tool for automating the pyinstaller method for compiling python code into an executable. This works on Windows, Linux, and OSX (pe and elf formats)(From trustedsec)
	* **PYTHONPATH**
		* [I'm In Your $PYTHONPATH, Backdooring Your Python Programs](http://www.ikotler.org/InYourPythonPath.pdf)
		* [Pyekaboo](https://github.com/SafeBreach-Labs/pyekaboo)
			* Pyekaboo is a proof-of-concept program that is able to to hijack/hook/proxy Python module(s) thanks to $PYTHONPATH variable. It's like "DLL Search Order Hijacking" for Python.
* **Defense Evasion**
* **Credential Access**
	* **Keyloggers**
		* [HeraKeylogger](https://github.com/UndeadSec/HeraKeylogger)
			* Chrome Keylogger Extension
		* [Meltdown PoC for Reading Google Chrome Passwords](https://github.com/RealJTG/Meltdown)
* **Discovery**
	* **Packet Sniffing**
		* See Network_Attacks.md
	* **Finding your external IP:**
		* Curl any of the following addresses: `ident.me, ifconfig.me or whatsmyip.akamai.com`
		* [Determine Public IP from CLI](http://askubuntu.com/questions/95910/command-for-determining-my-public-ip)
	* **Virtual Machine Detection(VM Dection)**
		* [How to determine Linux guest VM virtualization technology](https://www.cyberciti.biz/faq/linux-determine-virtualization-technology-command/)
		* **Virtualbox**
			* [VirtualBox Detection Via WQL Queries](http://waleedassar.blogspot.com/)
			* [Bypassing VirtualBox Process Hardening on Windows](https://googleprojectzero.blogspot.com/2017/08/bypassing-virtualbox-process-hardening.html)
			* [VBoxHardenedLoader](https://github.com/hfiref0x/VBoxHardenedLoader)
				* VirtualBox VM detection mitigation loader
* **Lateral Movement**
	* **Browser Pivoting**
		* [Browser Pivot for Chrome - ijustwannaredteam](https://ijustwannared.team/2019/03/11/browser-pivot-for-chrome/)
			* Today’s post is about Browser Pivoting with Chrome. For anyone unaware of Browser Pivoting, it’s a technique which essentially leverages an exploited system to gain access to the browser’s authenticated sessions. This is not a new technique, in fact, Raphael Mudge wrote about it in 2013. Detailed in the linked post, the Browser Pivot module for Cobalt Strike targets IE only, and as far as I know, cannot be used against Chrome. In this post we’re trying to achieve a similar result while taking a different approach – stealing the target’s Chrome profile in real time. Just a FYI, if you have the option to use Cobalt Strike’s Browser Pivot module instead, do so, it’s much cleaner.
		* [Pass the Cookie and Pivot to the Clouds - wunderwuzzi](https://wunderwuzzi23.github.io/blog/passthecookie.html)
			* An adversary can pivot from a compromised host to Web Applications and Internet Services by stealing authentication cookies from browsers and related processes. At the same time this technique bypasses most multi-factor authentication protocols.
* **Collection**
	* **Tools**
		* [LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
			* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
		* [DumpsterDiver](https://github.com/securing/DumpsterDiver)
			* DumpsterDiver is a tool used to analyze big volumes of various file types in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. Additionally, it allows creating a simple search rules with basic conditions (e.g. reports only csv file including at least 10 email addresses). The main idea of this tool is to detect any potential secret leaks. You can watch it in action in the [demo video](https://vimeo.com/272944858) or [read about all its features in this article.](https://medium.com/@rzepsky/hunting-for-secrets-with-the-dumpsterdiver-93d38a9cd4c1)
		* [SharpCloud](https://github.com/chrismaddalena/SharpCloud)
			* SharpCloud is a simple C# utility for checking for the existence of credential files related to Amazon Web Services, Microsoft Azure, and Google Compute.
		* [Packet sniffing with powershell](https://blogs.technet.microsoft.com/heyscriptingguy/2015/10/12/packet-sniffing-with-powershell-getting-started/)
* **Miscellaneous**
	* **Redis**
		* [Redis post-exploitation - Pavel Toporkov(ZeroNights18)](https://www.youtube.com/watch?v=Jmv-0PnoJ6c&feature=share)
			* We will overview the techniques of redis post-exploitation and present new ones. In the course of the talk, you will also find out what to do if a pentester or adversary has obtained access to redis.
* **Unsorted**
	* [portia](https://github.com/SpiderLabs/portia)
		* Portia aims to automate a number of techniques commonly performed on internal network penetration tests after a low privileged account has been compromised.
	* [JVM Post-Exploitation One-Liners](https://gist.github.com/frohoff/a976928e3c1dc7c359f8)
	* [Oneliner-izer](https://github.com/csvoss/onelinerizer)
		* Convert any Python file into a single line of code which has the same functionality.










--------------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="linpost">Post-Exploitation Linux</a>
* **101**
	* [More on Using Bash's Built-in /dev/tcp File (TCP/IP)](http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip)
	* [Bash Brace Expansion Cleverness - Jon Oberhide](https://jon.oberheide.org/blog/2008/09/04/bash-brace-expansion-cleverness/)
	* [Basic Linux Privilege Escalation - g0tmi1k](http://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
		* Not so much a script as a resource, g0tmi1k’s blog post here has led to so many privilege escalations on Linux system’s it’s not funny. Would definitely recommend trying out everything on this post for enumerating systems.
* **Execution**<a name="linexec"></a>
	* **General Articles/Blogposts/Writeups**
		* [needle - Linux x86 run-time process manipulation(paper)](http://hick.org/code/skape/papers/needle.txt)	
	* **Tools**
		* [GTFOBins](https://gtfobins.github.io/#)
			* GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. The project collects legitimate functions of Unix binaries that can be abused to break out of restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks. 
		* [GTFOPlus](https://github.com/yuudev/gtfoplus)
	    	* GTFOPlus is a helper script that relies on the GTFOBins repo to identify standard Linux binaries that could assist with privilege escalation.
		* [fireELF](https://github.com/rek7/fireELF)
			* fireELF is a opensource fileless linux malware framework thats crossplatform and allows users to easily create and manage payloads. By default is comes with 'memfd_create' which is a new way to run linux elf executables completely from memory, without having the binary touch the harddrive.
		* [Orc](https://github.com/zMarch/Orc)
			* Orc is a post-exploitation framework for Linux written in Bash
		* [msf-elf-in-memory-execution](https://github.com/fbkcs/msf-elf-in-memory-execution)
			* Post module for Metasploit to execute ELF in memory
	* **CLI**
		* **Articles/Blogposts/Writeups**
	* **Exploitation for Client Execution**
		* **Articles/Blogposts/Writeups**
	* **GUI**
		* **Articles/Blogposts/Writeups**	
	* **Local Job Scheduling**
		* **Articles/Blogposts/Writeups**	
	* **Scripting**
		* **Articles/Blogposts/Writeups**	
	* **Source**
		* **Articles/Blogposts/Writeups**	
	* **Space after Filename**
		* **Articles/Blogposts/Writeups**	
	* **Third-Party Software**
		* **Articles/Blogposts/Writeups**	
	* **Trap**
		* **Articles/Blogposts/Writeups**	
	* **User Execution**
		* **Articles/Blogposts/Writeups**	
			* [Introducing tmpnix - an alternative to static binaries for post exploitation - shiftordie.de](https://shiftordie.de/blog/2019/02/05/introducing-tmpnix-an-alternative-to-static-binaries-for-post-exploitation/)
			* [A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux - muppetlabs](http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html)
			* [In-Memory-Only ELF Execution (Without tmpfs) - Stuart](https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html)
			* [No one expect command execution!](http://0x90909090.blogspot.fr/2015/07/no-one-expect-command-execution.html)
				* Command execution through native utilities
* **Persistence**<a name="linpersist"></a>
	* **.bash_profile and .bashrc**
	* **Bootkit**
	* **Browser Extensions**
	* **Create Account**
	* **Hidden Files and Directories**
	* **Kernel Modules and Extensions**
	* **Local Job Scheduling**
		* **Cron**
		* **Systemd**
	* **Port Knocking**
	* **Redundant Access**
	* **Server Software Component**
	* **Setuid and Setgid**
	* **Supply-Chain**
		* [Debinject](https://github.com/UndeadSec/Debinject)
			* Inject malicious code into .debs
	* **Systemd Service**
	* **Trap**
	* **Vaid Accounts**
	* **Web Shell**
* **Privilege Escalation**<a name="linprivesc"></a>
	* **101**
		* [Basic Linux Privilege Escalation - g0tm1lk](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
		* [Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
		* [AllTheThings - Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#checklists)
	* **Articles/Blogposts/Writeups**
		* [How I did not get a shell - NCCGroup](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/how-i-did-not-get-a-shell/)
		* [Linux: VMA use-after-free via buggy vmacache_flush_all() fastpath - projectzero](https://bugs.chromium.org/p/project-zero/issues/detail?id=1664)
		* [Attack and Defend: Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
		* [Privilege Escalation - ]
	* **Exploits**
		* **Docker**
		* **Dirty COW**
			* [DirtyCow.ninja](https://dirtycow.ninja/)
		* **Huge Dirty COW**
			* [“Huge Dirty COW” (CVE-2017–1000405) The incomplete Dirty COW patch - Eylon Ben Yaakov](https://medium.com/bindecy/huge-dirty-cow-cve-2017-1000405-110eca132de0)
			* [HugeDirtyCow PoC](https://github.com/bindecy/HugeDirtyCowPOC)
				* A POC for the Huge Dirty Cow vulnerability (CVE-2017-1000405)
		* **dirty_sock**
		* [dirty_sock - Linux privilege escalation exploit via snapd (CVE-2019-7304)](https://github.com/initstring/dirty_sock)
			* In January 2019, current versions of Ubuntu Linux were found to be vulnerable to local privilege escalation due to a bug in the snapd API. This repository contains the original exploit POC, which is being made available for research and education. For a detailed walkthrough of the vulnerability and the exploit, please refer to the blog posting here.
			* [Linux Privilege Escalation via snapd (dirty_sock exploit)](https://initblog.com/2019/dirty-sock/)
		* **Kernel-based**
		* **Miscellaneous Software**
			* [Vim/Neovim Arbitrary Code Execution via Modelines - CVE-2019-12735](https://github.com/numirias/security/blob/master/doc/2019-06-04_ace-vim-neovim.md)
				* Vim before 8.1.1365 and Neovim before 0.3.6 are vulnerable to arbitrary code execution via modelines by opening a specially crafted text file.
			* [[0day] [exploit] Compromising a Linux desktop using... 6502 processor opcodes on the NES?! - scarybeastsecurity](https://scarybeastsecurity.blogspot.com/2016/11/0day-exploit-compromising-linux-desktop.html)
				*  A vulnerability and a separate logic error exist in the gstreamer 0.10.x player for NSF music files. Combined, they allow for very reliable exploitation and the bypass of 64-bit ASLR, DEP, etc. The reliability is provided by the presence of a turing complete “scripting” inside a music player. NSF files are music files from the Nintendo Entertainment System. Curious? Read on...
			* [systemd (systemd-tmpfiles) < 236 - 'fs.protected_hardlinks=0' Local Privilege Escalation](https://www.exploit-db.com/exploits/43935/)
	* **Techniques**
		* **Container-based**
			* [Using the docker command to root the host (totally not a security issue)](http://reventlov.com/advisories/using-the-docker-command-to-root-the-host)
				* It is possible to do a few more things more with docker besides working with containers, such as creating a root shell on the host, overwriting system configuration files, reading restricted stuff, etc.
			* [Linux Privilege Escalation via LXD & Hijacked UNIX Socket Credentials - Chris Moberly](https://shenaniganslabs.io/2019/05/21/LXD-LPE.html)
		* **Capabilities**
			* [An Interesting Privilege Escalation vector (getcap/setcap) - nxnjz](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)
			* [Linux Privilege Escalation using Capabilities - Raj Chandel](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)
		* **Cron jobs**
			* [Linux Privilege Escalation by Exploiting Cronjobs - Raj Chandel](https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/)
			* [Linux Privilege Escalation by Exploiting Cronjobs - ArmourInfoSec](https://www.armourinfosec.com/linux-privilege-escalation-by-exploiting-cronjobs/)
			* [Day 40: Privilege Escalation (Linux) by Modifying Shadow File for the Easy Win - int0x33](https://medium.com/@int0x33/day-40-privilege-escalation-linux-by-modifying-shadow-file-for-the-easy-win-aff61c1c14ed)
		 * **Exploitation for Privilege Escalation**
		* **GTFOBins**
		* **NFS**
			* [Linux Privilege Escalation using weak NFS permissions - Haider Mahmood](https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/)
			* [Linux Privilege Escalation using Misconfigured NFS - Raj Chandel](https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/)
			* [NFS weak permissions(Linux Privilege Escalation) - Touhid Shaikh](https://touhidshaikh.com/blog/?p=788)
			* [NFS, no_root_squash and SUID - Basic NFS Security - fullyautolinux](https://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html)
			* [A tale of a lesser known NFS privesc - gquere](https://www.errno.fr/nfs_privesc)
			* [NFS - myexperiments.io](https://myexperiments.io/linux-privilege-escalation.html#vii-network-file-system)
		* **PATH**
			* [Abusing users with '.' in their PATH: - gimboyd](http://www.dankalia.com/tutor/01005/0100501004.htm)
		 * **Process Injection**
		 	* **Shared Libraries**
		 * **Setuid and Setgid**
			* [SUID - myexperiments.io](https://myexperiments.io/linux-privilege-escalation.html#vi-file-permission)
			* [SUID Executables - NetbiosX](https://pentestlab.blog/category/privilege-escalation/)
			* **Tools**
				* [SUID3NUM](https://github.com/Anon-Exploiter/SUID3NUM)
					* A standalone python script which utilizes python's built-in modules to find SUID bins, separate default bins from custom bins, cross-match those with bins in GTFO Bin's repository & auto-exploit those, all with colors! ( ͡ʘ ͜ʖ ͡ʘ)
		 * **Sudo**
			* [Dangerous Sudoers Entries – Series, 5 parts](https://blog.compass-security.com/2012/10/dangerous-sudoer-entries-part-1-command-execution/)
			* [sudo - myexperiments.io](https://myexperiments.io/linux-privilege-escalation.html#v-sudo)
		 * **Sudo Caching**
		 * **Valid Accounts**
		 * **Web Shell**
		* **Wildcards**
			* [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)
			* [wildpwn](https://github.com/localh0t/wildpwn)
		* **Writable Files**
			* [uptux](https://github.com/initstring/uptux)
				* Linux privilege escalation checks (systemd, dbus, socket fun, etc)
	* **Solaris**
		* [uid=0 is deprecated: A trick unix-privesc-check doesn’t yet know - TMB](https://labs.portcullis.co.uk/blog/uid0-is-deprecated-a-trick-unix-privesc-check-doesnt-yet-know/)
		* [dtappgather-poc.sh](https://github.com/HackerFantastic/Public/blob/master/exploits/dtappgather-poc.sh)
			* Exploit PoC reverse engineered from EXTREMEPARR which provides local root on Solaris 7 - 11 (x86 & SPARC). Uses a environment variable of setuid binary dtappgather to manipulate file permissions and create a user owned directory anywhere on the system (as root). Can then add a shared object to locale folder and run setuid binaries with an untrusted library file.
	* **Talks/Videos**
		* [Chw00t: Breaking Unixes’ Chroot Solutions](https://www.youtube.com/watch?v=1A7yJxh-fyc)
	* **Tools**
		* [LinEnum](http://www.rebootuser.com/?p=1758)
			* This tool is great at running through a heap of things you should check on a Linux system in the post exploit process. This include file permissions, cron jobs if visible, weak credentials etc. The first thing I run on a newly compromised system.
		* [Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)
			* Linux Exploit Suggester; based on operating system release number.  This program run without arguments will perform a 'uname -r' to grab the Linux Operating Systems release version, and return a suggestive list of possible exploits. Nothing fancy, so a patched/back-ported patch may fool this script.  Additionally possible to provide '-k' flag to manually enter the Kernel Version/Operating System Release Version.
		* [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
			* Linux privilege escalation auditing tool
		* [LinuxPrivChecker](http://www.securitysift.com/download/linuxprivchecker.py)
			* This is a great tool for once again checking a lot of standard things like file permissions etc. The real gem of this script is the recommended privilege escalation exploits given at the conclusion of the sc
			* [Github](https://github.com/oschoudhury/linuxprivchecker)
		* [Unix Privilege Escalation Checker](https://code.google.com/p/unix-privesc-check/)
			* Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases). It is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed). It can run either as a normal user or as root (obviously it does a better job when running as root because it can read more files).
		* [EvilAbigail](https://github.com/GDSSecurity/EvilAbigail/blob/master/README.md)
			* Initrd encrypted root fs attack
		* [kernelpop](https://github.com/spencerdodd/kernelpop)
			* kernel privilege escalation enumeration and exploitation framework
* **Defense Evasion**<a name="lindefe"></a>
	* **Binary Padding**
	* **Clear Command History**
	* **Compile After Delivery**
	* **Connection Proxy**
	* **Disabling Security Tools**
	* **Execution Guardrails**
	* **Exploitation for Defense Evasion**
	* **File and Directory Permissions Modification**
	* **File Deletion**
	* **Hidden Files and Directories**
	* **HISTCONTROL**
	* **Indicator Removal from Tools**
	* **Indicator Removal on Host**
	* **Install Root Certificate**
	* **Masquerading**
	* **Obfuscated Files or Information**
	* **Port Knocking**
	* **Process Injection**
	* **Redundant Access**
	* **Rootkit**
	* **Scripting**
	* **Space after Filename**
	* **Timestomp**
	* **Valid Accounts**
	* **Web Service**
* **Credential Access**<a name="lincredac"></a>
	* **Bash History**
		* **Articles/Blogposts**
		* **Tools**
	* **Brute Force**
		* **Articles/Blogposts**
		* **Tools**
	* **Credential Dumping**
		* **Articles/Blogposts**
			* [Where 2 Worlds Collide: Bringing Mimikatz et al to UNIX - Tim(-Wadha) Brown](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Wadhwa-Brown-Where-2-Worlds-Collide-Bringing-Mimikatz-et-al-to-UNIX.pdf)
			    * What this talk is about: Why a domain joined UNIX box matters to Enterprise Admins; How AD based trust relationships on UNIX boxes are abused; How UNIX admins can help mitigate the worst side effects;
			* [Kerberos Credential Thiever (GNU/Linux) - Ronan Loftus, Arne Zismer](https://www.delaat.net/rp/2016-2017/p97/report.pdf)
				* Kerberos is an authentication protocol that aims to reduce the amount of sensitive data that needs to be sent across a network with lots of network resources that require authentication.  This reduces the risk of having authentication data stolen by an attacker.  Network Attached Storage devices, big data processing applications like Hadoop, databases and web servers commonly run on GNU/Linux machines that are integrated in a Kerberos system.  Due to the sensitivity of the data these services deal with, their security is of great importance.  There has been done a lot of research about sniffing and replaying Kerberos  credentials  from  the  network.   However,  little  work  has  been  done  on  stealing  credentials from Kerberos clients on GNU/Linux.  We therefore investigate the feasibility of extracting and reusing Kerberos credentials from GNU/Linux machines.  In this research we show that all the credentials can be extracted, independently of how they are stored on the client.  We also show how these credentials can be reused to impersonate the compromised client.  In order to improve the security of Kerberos, we also propose mitigations to these attacks.
			* [Exfiltrating credentials via PAM backdoors & DNS requests - x-c3ll](https://x-c3ll.github.io/posts/PAM-backdoor-DNS/)
		* **Tools**
			* [linikatz](https://github.com/portcullislabs/linikatz)
			* [mimipenguin](https://github.com/huntergregal/mimipenguin)
				* A tool to dump the login password from the current linux user
			* [3snake](https://github.com/blendin/3snake)
				* Targeting rooted servers, reads memory from sshd and sudo system calls that handle password based authentication. Doesn't write any memory to the traced processes. Spawns a new process for every sshd and sudo command that is run. Listens for the proc event using netlink sockets to get candidate processes to trace. When it receives an sshd or sudo process ptrace is attached and traces read and write system calls, extracting strings related to password based authentication.
			* [Tickey](https://github.com/TarlogicSecurity/tickey)
				* Tool to extract Kerberos tickets from Linux kernel keys. [Paper](https://www.delaat.net/rp/2016-2017/p97/report.pdf)	
	* **Credentials from Web Browsers**
		* **Articles/Blogposts**
		* **Tools**
	* **Credentials in Files**
		* **Articles/Blogposts**
			* [Digging passwords in Linux swap](http://blog.sevagas.com/?Digging-passwords-in-Linux-swap)
		* **Tools**
			* [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
				* KeyTabExtract is a little utility to help extract valuable information from 502 type .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script will extract information such as the realm, Service Principal, Encryption Type and NTLM Hash.
			* [swap_digger](https://github.com/sevagas/swap_digger)
				* swap_digger is a bash script used to automate Linux swap analysis for post-exploitation or forensics purpose. It automates swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, HTTP basic authentication, WiFi SSID and keys, etc.
	* **Exploitation for Credential Access**
		* **Articles/Blogposts**
			* [Triple-Fetch-Kernel-Creds](https://github.com/coffeebreakerz/Tripple-Fetch-Kernel-Creds)
				* Attempt to steal kernelcredentials from launchd + task_t pointer (Based on: CVE-2017-7047)
		* **Tools**
	* **Input Capture**
		* **Articles/Blogposts**
		* **Tools**
			* [SudoHulk](https://github.com/hc0d3r/sudohulk)
				* This tool change sudo command, hooking the execve syscall using ptrace, tested under bash and zsh
	* **Network Sniffing**
		* **Articles/Blogposts**
		* **Tools**
	* **Private Keys**
		* **Articles/Blogposts**
		* **Tools**	
	* **Steal Web Session Cookie**
		* **Articles/Blogposts**
		* **Tools**
	* **Two-Factor Authentication Interception**
		* **Articles/Blogposts**
		* **Tools**
* **Discovery**<a name="lindisco"></a>
	* **Articles/Blogposts/Writeups**
	* **Account Discovery**
	* **Browser Bookmark Discovery**
	* **File and Directory Discovery**
	* **Network Service Scanning**
		* **Articles/Blogposts/Writeups**
			* [Finding DNS servers provided by DHCP using network manager on Linux -ilostmynotes.blogspot ](https://ilostmynotes.blogspot.com/2019/03/finding-dns-servers-provided-by-dhcp.html)
		* **Tools**
			* [Baboossh](https://github.com/cybiere/baboossh)
				* BabooSSH allows you, from a simple SSH connection to a compromised host, to quickly gather info on other SSH endpoints to pivot and compromise them.
	* **Network Sniffing**
	* **Password Policy Discovery**
	* **Permission Groups Discovery**
	* **Process Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**		
			* [pspy](https://github.com/DominicBreuker/pspy)
				* pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute.  The tool gathers the info from procfs scans. Inotify watchers placed on selected parts of the file system trigger these scans to catch short-lived processes.
	* **Remote System Discovery**
		* [nullinux](https://github.com/m8r0wn/nullinux)
			* nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. If no username and password are provided, nullinux will attempt to connect to the target using an SMB null session. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation.This program assumes Python 2.7, and the smbclient package is installed on the machine. Run the setup.sh script to check if these packages are installed.
	* **Software Discovery**
	* **System Information Discovery**
		* [LinEnum](https://github.com/rebootuser/LinEnum)
	* **System Network Configuration Discovery**
 	* **System Network Connections Discovery**
 	* **System Owner/User Discovery**
* **Lateral Movement**<a name="linlate"></a>
	* **Application Deployment Software**
	* **Exploitation of Remote Services**
	* **Internal Spearphishing**
	* **Port Forwarding & Proxies**
		* [PortPush](https://github.com/itsKindred/PortPush)
			* PortPush is a small Bash utility used for pivoting into internal networks upon compromising a public-facing host.
	* **Remote File Copy**
	* **Remote Services**
		* **RDP**
			* [The RDP Through SSH Encyclopedia - Carrie Roberts](https://www.blackhillsinfosec.com/the-rdp-through-ssh-encyclopedia/)
				* I have needed to remind myself how to set up RDP access through an SSH connection so many times that I’ve decided to document it here for future reference. I hope it proves useful to you as well. I do “adversary simulation” for work and so I present this information using terms like “attacker” and “target” but this info is also useful for performing system administration tasks.
		* **SSH**
			* [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
			* [SSH manpage](https://linux.die.net/man/1/ssh)
			* [SSH Essentials: Working with SSH Servers, Clients, and Keys - Justin Ellingwood](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys)
			* [An SSH tunnel via multiple hops - stackoverflow](https://superuser.com/questions/96489/an-ssh-tunnel-via-multiple-hops)
	* **SSH Hijacking**
 	* **Third-party Software**
* **Collection**<a name="lincollect"></a>
	* **Audio Capture**
	* **Automated Collection**
	* **Clipboard Data**
	* **Data from Information Repositories**
	* **Data from Local System**
		* **Tools**
			* [swap_digger](https://github.com/sevagas/swap_digger)
				* swap_digger is a bash script used to automate Linux swap analysis for post-exploitation or forensics purpose. It automates swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, HTTP basic authentication, WiFi SSID and keys, etc.
	* **Data from Network Shared Drive**
	* **Data from Removable Media**
	* **Data Staged**
	* **Input Capture**
	* **Screen Capture**














----------------------
### <a name="osxpost"></a>Post-Exploitation OS X
* **Educational**<a name="osxedu"></a>
	* **Articles/Blogposts/Writeups**
		* [The ‘app’ you can’t trash: how SIP is broken in High Sierra](https://eclecticlight.co/2018/01/02/the-app-you-cant-trash-how-sip-is-broken-in-high-sierra/)
		* [I can be Apple, and so can you - A Public Disclosure of Issues Around Third Party Code Signing Checks - Josh Pitts](https://www.okta.com/security-blog/2018/06/issues-around-third-party-apple-code-signing-checks/)
	* **Talks/Presentations/Videos**
		* [The Mouse is Mightier than the Sword - Patrick Wardle](https://speakerdeck.com/patrickwardle/the-mouse-is-mightier-than-the-sword)
			* In this talk we'll discuss a vulnerability (CVE-2017-7150) found in all recent versions of macOS that allowed unprivileged code to interact with any UI component including 'protected' security dialogues. Armed with the bug, it was trivial to programmatically bypass Apple's touted 'User-Approved Kext' security feature, dump all passwords from the keychain, bypass 3rd-party security tools, and much more! And as Apple's patch was incomplete (surprise surprise) we'll drop an 0day that (still) allows unprivileged code to post synthetic events and bypass various security mechanisms on a fully patched macOS box!
		* [Fire & Ice; Making and Breaking macOS firewalls - Patrick Wardle(Rootcon12)](https://www.youtube.com/watch?v=zmIt9ags3Cg)
			* [Slides](https://speakerdeck.com/patrickwardle/fire-and-ice-making-and-breaking-macos-firewalls)
		* [When Macs Come Under ATT&CK - Richie Cyrus(Derbycon2018)](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-01-when-macs-come-under-attck-richie-cyrus)
			* Macs are becoming commonplace in corporate environments as a alternative to Windows systems. Developers, security teams, and executives alike favor the ease of use and full administrative control Macs provide. However, their systems are often joined to an active directory domain and ripe for attackers to leverage for initial access and lateral movement. Mac malware is evolving as Mac computers continue to grow in popularity. As a result, there is a need for proactive detection of attacks targeting MacOS systems in a enterprise environment. Despite advancements in MacOS security tooling for a single user/endpoint, little is known and discussed regarding detection at a enterprise level. This talk will discuss common tactics, techniques and procedures used by attackers on MacOS systems, as well as methods to detect adversary activity. We will take a look at known malware, mapping the techniques utilized to the MITRE ATT&CK framework. Attendees will leave equipped to begin hunting for evil lurking within their MacOS fleet.
		* [Harnessing Weapons of Mac Destruction - Patrick Wardle](https://speakerdeck.com/patrickwardle/harnessing-weapons-of-mac-destruction)
		* [Herding cattle in the desert: How malware actors have adjusted to new security enhancements in Mojave - Omer Zohar](https://www.youtube.com/watch?v=ZztuWe6sv18&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=3)
		    * [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Zohar.pdf)
    		* In this talk, we’ll deep dive into recent security changes in MacOS Mojave & Safari and examine how these updates impacted actors of highly distributed malware in terms of number of infections, and more importantly - monetization. We’ll take a look at malware actors currently infecting machines in the wild (Bundlore and Genio to name a few) - and investigate how their tactics evolved after the update: From vectors of infection that bypass Gatekeeper, getting around the new TCC dialogs, hijacking search in a SIP protected Safari, to persistency and reinfection mechanisms that ultimately turn these ‘annoying PUPs’ into a fully fledged backdoored botnet. 
		* [Never Before Had Stierlitz Been So Close To Failure (Sergei Shevchenko(OBTS v2.0)](https://www.youtube.com/watch?v=0zL0RWjzFFU&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=16)
	    	* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Shevchenko.pdf)
			* In this research, we'll dive into the installer's Mach-O binary to demonstrate how it piggy-backs on 'non-lazy' Objective-C classes, the way it dynamically unpacks its code section in memory and decrypts its config. An in-depth analysis will reveal the structure of its engine and a full scope of its hidden backdoor capabilities, anti-debugging, VM evasion techniques and other interesting tricks that are so typical to the Windows malware scene but aren’t commonly found in the unwanted apps that claim to be clean, particularly on the Mac platform. This talk reveals practical hands-on tricks used in Mach-O binary analysis under a Hackintosh VM guest, using LLDB debugger and IDA Pro disassembler, along with a very interesting marker found during such analysis. Curious to learn what that marker was? Willing to see how far the Mac-specific techniques evolved in relation to Windows malware? 
		* [An 0day in macOS - Patrick Wardle(OBTSv2.0)](https://www.youtube.com/watch?v=yWyxJla6xPo&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=18)
		    * [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Wardle.pdf)
		    * Let's talk about a powerful 0day in macOS Mojave.
* **Execution**<a name="osxexecute"></a>
	* **General**
		* [Weaponizing a Lazarus Group Implant - Patrick Wardle(2020)](https://objective-see.com/blog/blog_0x54.html)
			* repurposing a 1st-stage loader, to execute custom 'fileless' payloads
	* **AppleScript**<a name="osxa"></a>
		* **101**
			* [AppleScript Language Guide - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html#//apple_ref/doc/uid/TP40000983-CH208-SW1)
			* [AppleScript Fundamentals - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/conceptual/ASLR_fundamentals.html)
				* Section from the Language Guide
			* [AppleScript - William R. Cook(2006)](https://www.cs.utexas.edu/users/wcook/Drafts/2006/ashopl.pdf)
			* [Scripting with AppleScript - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptX/Concepts/work_with_as.html#//apple_ref/doc/uid/TP40001568)
				* The following is a brief introduction to AppleScript scripts, tools for working with them, and information on using AppleScript scripts together with other scripting systems. For related documents, see the learning paths in Getting Started with AppleScript.
			* [AppleScript: The Definitive Guide, 2nd Edition - Matt Neuburg](http://books.gigatux.nl/mirror/applescriptdefinitiveguide/toc.html)
		* **Articles/Blogposts/Writeups**
			* [macOS Red Team: Spoofing Privileged Helpers (and Others) to Gain Root - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-spoofing-privileged-helpers-and-others-to-gain-root/)
			* [macOS Red Team: Calling Apple APIs Without Building Binaries - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/)
			* [Launch Scripts from Webpage Links - macosxautomation.com](https://www.macosxautomation.com/applescript/linktrigger/)
			* [Using NSAppleScript - appscript.sourceforge](http://appscript.sourceforge.net/nsapplescript.html)
			* [hello, applescript 2: user in, user out - philastokes(applehelpwriter.com)](https://applehelpwriter.com/2018/09/03/hello-applescript-2-user-in-user-out/)
			* [hello, applescript 3: (don’t?) tell me to run - philastokes(appplehelpwriter)](https://applehelpwriter.com/2018/09/14/hello-applescript-3-dont-tell-me-to-run/)
		* **Tools**
	* **Command-Line Interface**
		* **Articles/Blogposts/Writeups**
			* [ShellOut](https://github.com/JohnSundell/ShellOut)
				* Easily run shell commands from a Swift script or command line tool
		* **Tools**
	* **Exploitation for Client Execution**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Graphical User Interface**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Launchctl**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Local Job Scheduling**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Javascript for Automation(JXA)**
		* [Orchard](https://github.com/its-a-feature/Orchard)
			* Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web.
		* **Talks/Presentations/Videos**
			* [Bash-ing Brittle Indicators: Red Teaming macOS without Bash or Python - Cody Thomas(Objective by the Sea v2.0)](https://www.youtube.com/watch?v=E-QEsGsq3uI&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=17)
			    * [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf)
		    	*  In this talk, I'll go into the research, development, and usage of a new kind of agent based on JavaScript for Automation (JXA) and how it can be used in modern red teaming operations. This agent is incorporated into a broader open source project designed for collaborative red teaming I created called Apfell. I will discuss TTPs for doing reconnaissance, persistence, injection, and some keylogging all without using a shell command or spawning another scripting language. I will go into details of how JXA can be used to create an agent complete with encrypted key exchange for secure communications, domain fronting C2, and modular design to load or change key functionality on the fly. I will also cover the defensive considerations of these TTPs and how Apple is starting to secure these capabilities going forward. 
	* **Scripting**
		* **Articles/Blogposts/Writeups**
		* **Tools**	* **Source**
	* **Space after Filename**
		* **Articles/Blogposts/Writeups**
		* **Tools**	* **Third-party Software**
	* **Trap**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **User Execution**
		* **Articles/Blogposts/Writeups**
			* [Native Mac OS X Application / Mach-O Backdoors for Pentesters](https://lockboxx.blogspot.com/2014/11/native-mac-os-x-application-mach-o.html)
		* **Tools**
			* [HappyMac](https://github.com/laffra/happymac)
				* A Python Mac app to suspend background processes 
			* [Platypus](https://github.com/sveinbjornt/Platypus)
				* Platypus is a developer tool that creates native Mac applications from command line scripts such as shell scripts or Python, Perl, Ruby, Tcl, JavaScript and PHP programs. This is done by wrapping the script in an application bundle along with a slim app binary that runs the script.
	* **URL Schemes/Routing**
		* **Articles/Blogposts/Writeups**
			* [URL Routing on macOS - Florian Schliep](https://medium.com/@floschliep/url-routing-on-macos-c53a06f0a984)
			* [Remote Mac Exploitation Via Custom URL Schemes - Patrick Wardle(2018)](https://objective-see.com/blog/blog_0x38.html)
		* **Tools**
	* **Tools**
		* [Mouse](https://github.com/entynetproject/mouse)
			* Mouse Framework is an iOS and macOS post-exploitation framework that gives you  a command line session with extra functionality between you and a target machine  using only a simple Mouse Payload. Mouse gives you the power and convenience of  uploading and downloading files, tab completion, taking pictures, location tracking,  shell command execution, escalating privileges, password retrieval, and much more.
		* [Appfell](https://github.com/its-a-feature/Apfell)
			* A collaborative, multi-platform, red teaming framework
		* [MacShell Post Exploitation Tool - Cedric Owens](https://medium.com/red-teaming-with-a-blue-team-mentaility/macshell-post-exploitation-tool-41696be9d826)
		* [MacShell](https://github.com/cedowens/MacShell)
			* MacShell is a macOS post exploitation tool written in python using encrypted sockets. I wrote this tool as a way for defenders and offensive security researchers to more easily understand the inner workings of python-based post exploitation tools on macOS.
		* [MacShellSwift](https://github.com/cedowens/MacShellSwift/tree/master/MacShellSwift)
			* MacShellSwift is a proof of concept MacOS post exploitation tool written in Swift using encrypted sockets. I rewrote a prior tool of mine MacShell (one of my repos) and changed the client to Swift intstead of python. This tool consists of two parts: a server script and a client binary. I wrote this tool to help blue teamers proactively guage detections against macOS post exploitation methods that use macOS internal calls. Red teams can also find this of use for getting ideas around using Swift for macOS post exploitation.
		* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
			* An evil RAT (Remote Administration Tool) for macOS / OS X.
		* [Parasite](https://github.com/ParasiteTeam/documentation)
			* Parasite is a powerful code insertion platform for OS X. It enables developers to easily create extensions which change the original behavior of functions. For users Parasite provides an easy way to install these extensions and tweak their OS.
		* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
			* An evil RAT (Remote Administration Tool) for macOS / OS X.
* **Persistence**<a name="osxpersist"></a>
	* **General**
		* **Articles/Blogposts/Writeups**
			* [Methods Of Malware Persistence On Mac OS X](https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf)
			* [How Malware Persists on macOS - Phil Stokes](https://www.sentinelone.com/blog/how-malware-persists-on-macos/)
			* [What's the easiest way to have a script run at boot time in OS X? - Stack Overflow](https://superuser.com/questions/245713/whats-the-easiest-way-to-have-a-script-run-at-boot-time-in-os-x)
	* **Presentations/Talks/Videos**
		* [Userland Persistence On Mac Os X "It Just Works"  -  Shmoocon 2015](http://www.securitytube.net/video/12428?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed:%20SecurityTube%20%28SecurityTube.Net%29)
			* Got root on OSX? Do you want to persist between reboots and have access whenever you need it? You do not need plists, new binaries, scripts, or other easily noticeable techniques. Kext programming and kernel patching can be troublesome! Leverage already running daemon processes to guarantee your access.  As the presentation will show, if given userland administrative access (read: root), how easy it is to persist between reboots without plists, non-native binaries, scripting, and kexts or kernel patching using the Backdoor Factory.
	* **.bash_profile and .bashrc**
	* **Browser Extensions**
	* **Create Account**
	* **Dylib Hijacking**
	* **Emond**
	* **Folder Actions**
		* [Folder Actions for Persistence on macOS - Cody Thomas](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
	* **Hidden Files and Directories**
	* **Kernel Modules and Extensions**
	* **Launch Agent**
	* **Launch Daemon**
	* **Launchctl**
	* **LC_LOAD_DYLIB Addition**
	* **Local Job Scheduling**
	* **Login Item**
		* [Adding Login Items - developer.apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLoginItems.html)
		* [Open items automatically when you log in on Mac - developer.apple](https://support.apple.com/en-gb/guide/mac-help/mh15189/mac)
	* **Logon Scripts**
	* **Mail.app**
		* [Using email for persistence on OS X - n00py](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
	* **Plist Modification**
	* **Port Knocking**
	* **Rc.common**
	* **Re-opened Applications**
	* **Redundant Access**
	* **Setuid and Setgid**
	* **Startup Items**
	* **Trap**
	* **Valid Accounts**
	* **Web Shell**
	* **Xcode**
		* [Running and disguising programs through XCode shims on OS X](https://randomtechnicalstuff.blogspot.com.au/2016/05/os-x-and-xcode-doing-it-apple-way.html)
	* **Tools**
		* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
			* A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.
		* [p0st-ex](https://github.com/n00py/pOSt-eX)
			* Post-exploitation scripts for OosxpostS X persistence and privesc
* **Privilege Escalation**<a name="osxprivesc"></a>
	* **General**
		* **Articles/Blogposts/Writeups**
			* [Hidden backdoor API to root privileges in Apple OS X](https://truesecdev.wordpress.com/2015/04/09/hidden-backdoor-api-to-root-privileges-in-apple-os-x/)
				* The Admin framework in Apple OS X contains a hidden backdoor API to root privileges. It’s been there for several years (at least since 2011), I found it in October 2014 and it can be exploited to escalate privileges to root from any user account in the system. The intention was probably to serve the “System Preferences” app and systemsetup (command-line tool), but any user process can use the same functionality. Apple has now released OS X 10.10.3 where the issue is resolved. OS X 10.9.x and older remain vulnerable, since Apple decided not to patch these versions. We recommend that all users upgrade to 10.10.3.
				* Works on 10.7 -> 10.10.2
		* **Presentations/Talks/Videos**
			* [Hacking Exposed: Hacking Macs - RSA Keynote, George Kurtz and Dmitri Alperovitch, Part 1 "Delivery"(2019)](https://www.youtube.com/watch?v=DMT_vYVoM4k&feature=emb_title)
				* CrowdStrike Co-founders, CEO George Kurtz and CTO Dmitri Alperovitch, and Falcon OverWatch Senior Engineer Jaron Bradley demonstrate a “Delivery” stage attack against a MacOS system. This demo is from their RSA 2019 keynote address titled, “Hacking Exposed: Hacking Macs.”
			* [Hacking Macs from RSA- George Kurtz and Dmitri Alperovitch, Part 2 "Privilege Escalation"](https://www.youtube.com/watch?v=Dh-XMkYOdE8&feature=emb_title)
				* CrowdStrike Co-founders, CEO George Kurtz and CTO Dmitri Alperovitch, and Falcon OverWatch Senior Engineer Jaron Bradley demonstrate a “Privilege Escalation” stage attack against a MacOS system. This demo is from their RSA 2019 keynote address titled, “Hacking Exposed: Hacking Macs.”
	* **Dylib Hijacking**
		* **Talks/Presentations/Videos**
			* [Gaining Root with Harmless AppStore Apps - Csaba Fitzi](https://www.youtube.com/watch?v=sOtcM-dryF4&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=8)
	    		* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Fitzl.pdf)
			    * This talk is about my journey from trying to find dylib hijacking vulnerability in a particular application to finding a privilege escalation vulnerability in macOS. During the talk I will try to show the research process, how did I moved from one finding to the next and I will also show many of the failures / dead ends I had during the exploit development.First I will briefly cover what is a dylib hijacking, and what is the current state of various application regarding this type of vulnerability. We will see how hard is to exploit these in many cases due to the fact that root access is required. Second I will cover two seemingly harmless bugs affecting the installation process of AppStore apps, and we will see how can we chain these together in order to gain root privileges - for this we will utilise a completely benign app from the macOS App Store. Part of this I will cover how can we submit apps to the store, and what are the difficulties with that process.In the last part I will cover how we can infect and include our malicious file in an App installer without breaking the App’s signature.
	* **Elevated Execution with Prompt**
		* **Articles/Blogposts/Writeups**
			* [Elevating Privileges Safely - developer.apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/AccessControl.html)
			* [macOS Red Team: Spoofing Privileged Helpers (and Others) to Gain Root - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-spoofing-privileged-helpers-and-others-to-gain-root/)
			* [Privilege escalation on OS X – without exploits - n00py.io](https://www.n00py.io/2016/10/privilege-escalation-on-os-x-without-exploits/)
	* **Emond**
	* **Exploitation for Privilege Escalation**
		* [CVE-2019-8805 - A macOS Catalina privilege escalation - Scott Knight](https://knight.sc/reverse%20engineering/2019/10/31/macos-catalina-privilege-escalation.html)
		* [Sniffing Authentication References on macOS - Patrick Wardle(2018)](https://objective-see.com/blog/blog_0x55.html)
			* details of a privilege-escalation vulnerability (CVE-2017-7170)
			* `The Ugly: for last ~13 years (OSX 10.4+) anybody could locally sniff 'auth tokens' then replay to stealthy & reliably elevate to r00t 🍎🤒☠️ The Bad: reported to Apple -they silently patched it (10.13.1) 🤬 The Good: when confronted they finally assigned CVE + updated docs 😋 [pic.twitter.com/RlNBT1DBvK](pic.twitter.com/RlNBT1DBvK)`
		* [Mac OS X local privilege escalation (IOBluetoothFamily)](http://randomthoughts.greyhats.it/2014/10/osx-local-privilege-escalation.html)
		* [How to gain root with CVE-2018-4193 in < 10s - Eloi Benoist-Vanderbeken](https://www.synacktiv.com/ressources/OffensiveCon_2019_macOS_how_to_gain_root_with_CVE-2018-4193_in_10s.pdf)
		* [CVE-2018-4193](https://github.com/Synacktiv-contrib/CVE-2018-4193)
			* exploit for CVE-2018-4193
		* **Rootpipe**	
			* [Rootpipe Reborn (Part I) - codecolorist](https://medium.com/0xcc/rootpipe-reborn-part-i-cve-2019-8513-timemachine-root-command-injection-47e056b3cb43)
    			* CVE-2019-8513 TimeMachine root command injection
			* [Rootpipe Reborn (Part II) - codecolorist](https://medium.com/0xcc/rootpipe-reborn-part-ii-e5a1ffff6afe)
	    		* CVE-2019-8565 Feedback Assistant race condition leads to root LPE
			* [Stick That In Your (root)Pipe & Smoke It - Patrick Wardle(Defcon23)](https://www.slideshare.net/Synack/stick-that-in-your-rootpipe-smoke-it)
				* [Talk](https://www.youtube.com/watch?v=pbpaUuGLS5g)
	* **Launch Daemon**
	* **Permissions Misconfiguration**
		* **Articles/Blogposts/Writeups**
			* [Exploiting directory permissions on macOS - theevilbit](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
				*  In the following post I will first go over the permission model of the macOS filesystem, with focus on the POSIX part, discuss some of the non trivial cases it can produce, and also give a brief overview how it is extended. I won’t cover every single detail of the permission model, as it would be a topic in itself, but rather what I found interesting from the exploitation perspective. Then I will cover how to find these bugs, and finally I will go through in detail all of the bugs I found. Some of these are very interesting as we will see, as exploitation of them involves “writing” to files owned by root, while we are not root, which is not trivial, and can be very tricky.
		* **Talks/Presentations/Videos**
			* [Root Canal - Samuel Keeley(OBTSv2.0)](https://www.youtube.com/watch?v=sFxz3akCNsg&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=11)
	    		* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Keeley.pdf)
   			 	* Apple released System Integrity Protection/rootless with OS X El Capitan almost four years ago.The root account is still there, and many common pieces of software open the Mac up to simple root escalations - including common macOS management tools. How can we detect these vulnerabilities across our Mac fleets? What can root still be abused for in 2019?	
	* **Plist Modification**
	* **Privileged File Operations**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
			* [Job(s) Bless Us!Privileged Operations on macOS - Julia Vaschenko(OBTSv3.0)](https://objectivebythesea.com/v3/talks/OBTS_v3_jVashchenko.pdf)
	* **Process Injection**
		* **Articles/Blogposts/Writeups**
			* [Privilege Escalation on OS X below 10.0](https://bugs.chromium.org/p/project-zero/issues/detail?id=121)
				* CVE-2014-8835
		* **Tools**
			* [osxinj](https://github.com/scen/osxinj)
				* Another dylib injector. Uses a bootstrapping module since mach_inject doesn't fully emulate library loading and crashes when loading complex modules.
	* **Setuid and Setgid**
	* **Startup Items**
	* **Sudo**
	* **Sudo Caching**
		* [tty_tickets option now on by default for macOS Sierra’s sudo tool - rtrouton](https://derflounder.wordpress.com/2016/09/21/tty_tickets-option-now-on-by-default-for-macos-sierras-sudo-tool/)
		* [Privilege escalation on OS X – without exploits - n00py.io](https://www.n00py.io/2016/10/privilege-escalation-on-os-x-without-exploits/)
	* **Valid Accounts**
	* **Web Shell**
	* **SIP Bypass**
		* [abusing the local upgrade process to bypass SIP - Objective-see](https://objective-see.com/blog/blog_0x14.html)
	* **Exploits**
		* [Why `<blank>` Gets You Root- Patrick Wardle(2017)](https://objective-see.com/blog/blog_0x24.html)
			*  In case you haven't heard the news, there is a massive security flaw which affects the latest version of macOS (High Sierra). The bug allows anybody to log into the root account with a blank, or password of their choosing. Yikes! 
		* [macOS 10.13.x SIP bypass (kernel privilege escalation)](https://github.com/ChiChou/sploits/tree/master/ModJack)
			* "Works only on High Sierra, and requires root privilege. It can be chained with my previous local root exploits."
			* [Slides](https://conference.hitb.org/hitbsecconf2019ams/materials/D2T2%20-%20ModJack%20-%20Hijacking%20the%20MacOS%20Kernel%20-%20Zhi%20Zhou.pdf)
		* [IOHIDeous(2017)](https://siguza.github.io/IOHIDeous/)
			* [Code](https://github.com/Siguza/IOHIDeous/)
			* A macOS kernel exploit based on an IOHIDFamily 0day.
	* **Talks/Presentations/Videos**
		* [Death By 1000 Installers on macOS and it's all broken! - Patrick Wardle(Defcon25)](https://www.youtube.com/watch?v=mBwXkqJ4Z6c)
		    * [Slides](https://speakerdeck.com/patrickwardle/defcon-2017-death-by-1000-installers-its-all-broken)
		* [Attacking OSX for fun and profit tool set limiations frustration and table flipping Dan Tentler - ShowMeCon](https://www.youtube.com/watch?v=9T_2KYox9Us)
			* 'I was approached by Fusion to be part of their 'Real Future' documentary - specifically, and I quote, to 'see how badly I could fuck his life up, while having control of his laptop'. They wanted me to approach this scenario from how a typical attacker wou'
	* **Tools**
		* [BigPhish](https://github.com/Psychotrope37/bigphish)
			* This issue has been resolved by Apple in MacOS Sierra by enabling tty_tickets by default. NOTE: All other MacOS operation system (El Capitan, Yosemite, Mavericks etc...) still remain vulnerable to this exploit.
* **Defense Evasion**<a name="osxdefev"></a>
	* **101**
		* [App security overview - support.apple](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/1/web/1)
		* [Protecting against malware - support.apple](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/1/web/1)
		* [Gatekeeper and runtime protection - support.apple](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/1/web/1)
	* **Application Whitelisting**<a name="whitelist"></a>
		* **Articles/Blogposts/Writeups**
				* [Bypassing Google's Santa Application Whitelisting on macOS (Part 1 of 2) - Adam Crosser](https://www.praetorian.com/blog/bypassing-google-santa-application-whitelisting-on-macos-part-1)
				* [Bypassing Google's Santa Application Whitelisting on macOS (Part 2 of 2) - Adam Crosser](https://www.praetorian.com/blog/bypassing-google-santa-application-whitelisting-on-macos-part-2)
	* **Endpoint Security**<a name="esf"></a>
		* **101**
			* [EndpointSecurity - developer.apple](https://developer.apple.com/documentation/endpointsecurity)
				* Endpoint Security is a C API for monitoring system events for potentially malicious activity. Your client, which you can write in any language supporting native calls, registers with Endpoint Security to authorize pending events, or receive notifications of events that have already occurred. These events include process executions, mounting file systems, forking processes, and raising signals. Develop your system extension with Endpoint Security and package it in an app that uses the SystemExtensions framework to install and upgrade the extension on the user’s Mac.
		* **Articles/Blogposts/Writeups**
	* **Gatekeeper**<a name="gatekeeper"></a>
		* **101**
			* [Gatekeeper - Wikipedia](https://en.wikipedia.org/wiki/Gatekeeper_(macOS))
			* [Gatekeeper Bypass - ATT&CK](https://attack.mitre.org/techniques/T1144/)
			* [Safely open apps on your Mac - support.apple](https://support.apple.com/en-us/HT202491)
    			* 'macOS includes a technology called Gatekeeper, that's designed to ensure that only trusted software runs on your Mac.'
			* [Launch Service Keys - `LSFileQuarantineEnabled`](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html#//apple_ref/doc/uid/TP40009250-SW10)
			* [macOS Code Signing In Depth - developer.apple](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
		* **Articles/Blogposts/Writeups**
			* [GateKeeper - Bypass or not bypass? - theevilbit(2019)](https://theevilbit.github.io/posts/gatekeeper_bypass_or_not_bypass/)
			* [How WindTail and Other Malware Bypass macOS Gatekeeper Settings - Phil Stokes](https://www.sentinelone.com/blog/how-malware-bypass-macos-gatekeeper/)
			* [MacOS X GateKeeper Bypass - Filippo Cavallarin(2019)](https://www.fcvl.net/vulnerabilities/macosx-gatekeeper-bypass)
	* **System Integrity Protection(SIP)**<a name="sip"></a>
		* **101**
			* [System Integrity Protection - Wikipedia](https://en.wikipedia.org/wiki/System_Integrity_Protection)
			* [About System Integrity Protection on your Mac - support.apple.com](https://support.apple.com/en-us/HT204899)
			* [Configuring System Integrity Protection - developer.apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html#//apple_ref/doc/uid/TP40016462-CH5-SW1)
		* **Articles/Blogposts/Writeups**
			* [Bypassing Apple's System Integrity Protection - Patrick Wardle](https://objective-see.com/blog/blog_0x14.html)
				* abusing the local upgrade process to bypass SIP]
		* **Talks/Presentations/Videos**
			* [Bad Things in Small Packages - Jaron Bradley](https://www.youtube.com/watch?v=5nOxznrOK48&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=5)
    			* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Bradley.pdf)
   				* This talk will primarily focus on the work that went into discovering CVE-2019-8561. The vulnerability exists within PackageKit that could lead to privilege escalation, signature bypassing, and ultimately the bypassing of Apple's System Integrity Protection (SIP). This vulnerability was patched in macOS 10.14.4, but the details behind this exploit have not been documented anywhere prior to this conference! 
	* **XProtect**<a name="xprotect"></a>
		* **101**
			* [XProtect Explained: How Your Mac’s Built-in Anti-malware Software Works - Chris Hoffman(2015)](https://www.howtogeek.com/217043/xprotect-explained-how-your-macs-built-in-anti-malware-works/)
			* [How the “antimalware” XProtect for MacOS works and why it detects poorly and badly - ElevenPaths(2019)](https://business.blogthinkbig.com/antimalware-xprotect-macos/)
		* **Articles/Blogposts/Writeups**
			* [How To Bypass XProtect on Catalina - Phil Stokes](https://www.sentinelone.com/blog/macos-malware-researchers-how-to-bypass-xprotect-on-catalina/)
			* [XProtect](https://github.com/knightsc/XProtect)
				* This repo contains historical releases of the XProtect configuration data.
* **Credential Access**<a name="osxcredac"></a>
	* **Cracking Password Hashes**
		* **Articles/Blogposts/Writeups**
			* [How to extract hashes and crack Mac OS X Passwords - onlinehashcrack.com](https://www.onlinehashcrack.com/how-to-extract-hashes-crack-mac-osx-passwords.php)
			* [How to Hack a Mac Password Without Changing It - Tokyoneon](https://null-byte.wonderhowto.com/how-to/hacking-macos-hack-mac-password-without-changing-0189001/)
			* [Mac OSX Password Cracking - mcontino(2017)](http://hackersvanguard.com/mac-osx-password-cracking/)
			* [What type of hash are a Mac's password stored in? - AskDifferent](https://apple.stackexchange.com/questions/220729/what-type-of-hash-are-a-macs-password-stored-in)
				* Check the first answer
			* [Cracking Mac OS Lion Passwords - frameloss.org(2011)](https://www.frameloss.org/2011/09/05/cracking-macos-lion-passwords/)
		* **Tools**	
			* [DaveGrohl 3.01 alpha](https://github.com/octomagon/davegrohl)
				* A Password Cracker for OS X
	* **Bash History**
		* **Articles/Blogposts/Writeups**
	* **Brute Force**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Credential Dumping**
		* **Articles/Blogposts/Writeups**
			* [Getting What You’re Entitled To: A Journey Into MacOS Stored Credentials - MDSec(2020)](https://www.mdsec.co.uk/2020/02/getting-what-youre-entitled-to-a-journey-in-to-macos-stored-credentials/)
				* In this blog post we will explore how an operator can gain access to credentials stored within MacOS third party apps by abusing surrogate applications for code injection, including a case study of Microsoft Remote Desktop and Google Drive.
			* [Bypassing MacOS Privacy Controls - Adam Chester(2020)](https://blog.xpnsec.com/bypassing-macos-privacy-controls/)
		* **Talks/Presentations/Videos**
		* **Tools**
	* **Credentials from Web Browsers**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**		
		* **Tools**
	* **Credentials in Files**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**		
		* **Tools**
	* **Exploitation for Credential Access**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**		
		* **Tools**
	* **Input Capture**
		* **Articles/Blogposts/Writeups**
			* [How to Dump 1Password, KeePassX & LastPass Passwords in Plaintext - Tokyoneon](https://null-byte.wonderhowto.com/how-to/hacking-macos-dump-1password-keepassx-lastpass-passwords-plaintext-0198550/)
		* **Talks/Presentations/Videos**
		* **Tools**
			* [kcap](https://github.com/scriptjunkie/kcap)
				* This program simply uses screen captures and programmatically generated key and mouse events to locally and graphically man-in-the-middle an OS X password prompt to escalate privileges.
	* **Input Prompt**
		* **Articles/Blogposts/Writeups**
			* [osascript: for local phishing - fuzzynop](https://fuzzynop.blogspot.com/2014/10/osascript-for-local-phishing.html)
		* **Talks/Presentations/Videos**		
		* **Tools**
			* [Empire propmt.py](https://github.com/BC-SECURITY/Empire/blob/master/lib/modules/python/collection/osx/prompt.py)
			* [FiveOnceinYourlife](https://github.com/fuzzynop/FiveOnceInYourLife)
				* Local osx dialog box phishing using osascript. Easier than keylogging on osx. Simply ask for the passwords you want.
	* **Keychain**
		* **Articles/Blogposts/Writeups**
			* [Keychain Services - developer.apple.com](https://developer.apple.com/documentation/security/keychain_services)
			* [Security Flaw in OS X displays all keychain passwords in plain text - Brenton Henry(2016)](https://medium.com/@brentonhenry/security-flaw-in-os-x-displays-all-keychain-passwords-in-plain-text-a530b246e960)
	    		* There is a method in OS X that will allow any user to export your keychain, without sudo privileges or any system dialogs, to a text file, with the username and passwords displayed in plain text. As of this writing(2016), this method works in at least 10.10 and 10.11.5, and presumably at the least all iterations in between.
		* **Talks/Presentations/Videos**
			* [OBTS v2.0 "KeySteal: A Vulnerability in Apple's Keychain" (Linus Henze)](https://www.youtube.com/watch?v=wPd6rMk8-gg&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=9)
    			* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Henze.pdf)
    			* What do your iCloud, Slack, MS Office, etc. credentials have in common? Correct, they're all stored inside your Mac's Keychain. While the Keychain is great because it prevents all those annoying password prompts from disturbing you, the ultimate question is: Is it really safe? Does it prevent malicious Apps from stealing all my passwords?In this talk I will try to answer those questions, showing you how the Keychain works and how it can be exploited by showing you the full details of my KeySteal exploit for the first time. The complete exploit code will be available online after the talk.
		* **Tools**
			* [Mac OS X Keychain Forensic Tool](https://github.com/n0fate/chainbreaker)
				* The chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner. Master Key candidates can be extracted from volafox or volatility keychaindump module. Supports: Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra. This branch contains a quick patch for chainbreaker to dump non-exportable keys on High Sierra, see README-keydump.txt for more details.
			* [KeySteal](https://github.com/LinusHenze/Keysteal)
				* KeySteal is a macOS <= 10.14.3 Keychain exploit that allows you to access passwords inside the Keychain without a user prompt. The vulnerability has been assigned CVE-2019-8526 number.
			* [OSX Key Chain Dumper](https://github.com/lancerushing/osx-keychain-dumper)
				* 'Scripts to dump the values out of OSX Keychain. Tested on OS X El Capitan ver 10.11.6'
			* [keychaindump(2015)](https://github.com/x43x61x69/Keychain-Dump)
				* Keychaindump is a proof-of-concept tool for reading OS X keychain passwords as root. It hunts for unlocked keychain master keys located in the memory space of the securityd process, and uses them to decrypt keychain files.
			* [osx-hash-dumper](https://github.com/cedowens/osx-hash-dumper)
				* Bash script to dump OSX user hashes in crackable format. Author: Cedric Owens
			* [retrieve-osxhash.py](https://github.com/highmeh/pentest_scripts/blob/master/retrieve-osxhash.py)
	* **Network Sniffing**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**		
		* **Tools**	
	* **Private Keys**
		* **Articles/Blogposts/Writeups**
	* **Securityd Memory**
		* **Articles/Blogposts/Writeups**			
		* **Tools**
	* **Steal Web Session Cookie**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Two-Factor Authentication Interception**
		* **Articles/Blogposts/Writeups**
		* **Tools**
* **Discovery**<a name="osxdisco"></a>
    * [forgetmenot](https://github.com/eavalenzuela/forgetmenot)
        * local looting script in python
	* [APOLLO - Apple Pattern of Life Lazy Output'er](https://github.com/mac4n6/APOLLO)
		* APOLLO stands for Apple Pattern of Life Lazy Output’er. I wanted to create this tool to be able to easily correlate multiple databases with hundreds of thousands of records into a timeline that would make the analyst (me, mostly) be able to tell what has happened on the device. iOS (and MacOS) have these absolutely fantastic databases that I’ve been using for years with my own personal collection of SQL queries to do what I need to get done. This is also a way for me to share my own research and queries with the community. Many of these queries have taken hours, even days to research and compile into something useful. My goal with this script is to put the analysis function the SQL query itself. Each query will output a different part of the puzzle. The script itself just compiles the data into a CSV or SQLite database for viewing and filtering. While this database/spreadsheet can get very large, it is still more efficient that running queries on multiple databases and compiling the data into a timeline manually.
	* **Account Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Application Window Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Browser Bookmark Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **File and Directory Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Network Service Scanning**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Network Share Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Network Sniffing**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Password Policy Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Peripheral Device Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Permission Groups Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Process Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Remote System Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Security Software Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Software Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **System Information Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **System Network Configuration Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **System Network Connections Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **System Owner/User Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Virtualization/Sandbox Evasion**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
* **Lateral Movement**<a name="osxlat"></a>
	* **AppleScript**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Application Deployment Software**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Exploitation of Remote Services**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Internal Spearphishing**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Logon Scripts**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Remote File Copy**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Remote Services**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **SSH Hijacking**
		* **Articles/Blogposts/Writeups**
			* [Interacting with MacOS terminal windows for lateral movement - Steve Borosh](https://medium.com/rvrsh3ll/interacting-with-macos-terminal-windows-for-lateral-movement-ec8710413e29)
		* **Tools**	
	* **Third-party Software**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
* **Collection**<a name="osxcollect"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Breaking macOS Mojave Beta: does apple adequately protect the webcam and mic? ...no - Patrick Wardle(2018)](https://objective-see.com/blog/blog_0x2F.html)
	* **Tools**
	* **Audio Capture**
	* **Automated Collection**
	* **Clipboard Data**
	* **Data from Information Repositories**
	* **Data from Local System**
		* [PICT - Post-Infection Collection Toolkit](https://github.com/thomasareed/pict)
			* This set of scripts is designed to collect a variety of data from an endpoint thought to be infected, to facilitate the incident response process. This data should not be considered to be a full forensic data collection, but does capture a lot of useful forensic information.
		* [PICT-Swift (Post Infection Collection Toolkit)](https://github.com/cedowens/PICT-Swift/tree/master/pict-Swift)
			* This is a Swift (and slightly modified) version of Thomas Reed's PICT (Post Infection Collection Toolkit: https://github.com/thomasareed/pict). Thomas Reed is the brains behind the awesome PICT concept. I just simply wrote a Swift version of it and added an additional collector.
		* [macOS-browserhist-parser](https://github.com/cedowens/macOS-browserhist-parser)
			* Swift code to parse the quarantine history database, Chrome history database, Safari history database, and Firefox history database on macOS.
	* **Data from Network Shared Drive**
	* **Data from Removable Media**
	* **Data Staged**
	* **Input Capture**
	* **Screen Capture**
	* **Video Capture**
* **MacOS Red Teaming Blogpost Series by Action Dan**
	* [MacOS Red Teaming 201: Introduction - Action Dan](https://lockboxx.blogspot.com/2019/03/macos-red-teaming-201-introduction.html)
	* [MacOS Red Teaming 202: Profiles - Action Dan](https://lockboxx.blogspot.com/2019/03/macos-red-teaming-202-profiles.html)
	* [MacOS Red Teaming 203: MDM (Mobile Device Managment - Action Dan)](https://lockboxx.blogspot.com/2019/04/macos-red-teaming-203-mdm-mobile-device.html)
	* [MacOS Red Teaming 204: Munki Business - Action Dan](https://lockboxx.blogspot.com/2019/04/macos-red-teaming-204-munki-business.html)
	* [MacOS Red Teaming 205: TCC (Transparency, Consent, and Control - Action Dan)](https://lockboxx.blogspot.com/2019/04/macos-red-teaming-205-tcc-transparency.html)
	* [MacOS Red Teaming 206: ARD (Apple Remote Desktop Protocol - Action Dan)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
	* [MacOS Red Teaming 207: Remote Apple Events (RAE) - Action Dan](https://lockboxx.blogspot.com/2019/08/macos-red-teaming-207-remote-apple.html)
	* [MacOS Red Teaming 208: macOS ATT&CK Techniques - Action Dan](https://lockboxx.blogspot.com/2019/09/macos-red-teaming-208-macos-att.html)
	* [MacOS Red Teaming 209: macOS Frameworks for Command and Control - Action Dan](https://lockboxx.blogspot.com/2019/09/macos-red-teaming-209-macos-frameworks.html)
	* [MacOS Red Teaming 210: Abusing Pkgs for Privilege Escalation - Action Dan](https://lockboxx.blogspot.com/2019/10/macos-red-teaming-210-abusing-pkgs-for.html)
	* [MacOS Red Teaming 211: Dylib Hijacking - Action Dan](https://lockboxx.blogspot.com/2019/10/macos-red-teaming-211-dylib-hijacking.html)
* **Technologies**
	* [macOS Code Signing In Depth](https://developer.apple.com/library/content/technotes/tn2206/_index.html)






------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="winpost">Post-Exploitation Windows</a>
* **101**<a name="win101"></a>
	* [Windows CMD Reference - ms](https://www.microsoft.com/en-us/download/details.aspx?id=56846)
* **Living_off_The_Land**<a name="lolbins"></a>
	* **101**
		* [Living Off The Land: A Minimalist's Guide To Windows Post Exploitation Christopher(Derbycon3)](https://www.youtube.com/watch?v=j-r6UonEkUw)
		* [LOLBins - Living Off The Land Binaries & Scripts & Libraries](https://github.com/LOLBAS-Project/LOLBAS)
			* "Living off the land" was coined by Matt Graeber - @mattifestation <3
			* The term LOLBins came from a twitter discussion on what to call these binaries. It was first proposed by Philip Goh - @MathCasualty here: https://twitter.com/MathCasualty/status/969174982579273728
			* The term LOLScripts came from Jimmy - @bohops: https://twitter.com/bohops/status/984828803120881665
			* [Installers – Interactive Lolbins - Hexacorn](http://www.hexacorn.com/blog/2019/04/18/installers-interactive-lolbins/)
	* **Articles/Blogposts/Writeups**
		* [Installers – Interactive Lolbins, Part 2 - Hexacorn](http://www.hexacorn.com/blog/2019/04/19/installers-interactive-lolbins-part-2/)
		* [Bring your own lolbas? - Hexacorn](http://www.hexacorn.com/blog/2019/07/05/bring-your-own-lolbas/)
		* [Reusigned Binaries - Hexacorn](http://www.hexacorn.com/blog/category/living-off-the-land/reusigned-binaries/)
		* [Reusigned Binaries – Living off the signed land - Hexacorn](http://www.hexacorn.com/blog/2017/11/10/reusigned-binaries-living-off-the-signed-land/)
		* [Hack Microsoft Using Microsoft Signed Binaries - Pierre-Alexandre Braeken](https://www.blackhat.com/docs/asia-17/materials/asia-17-Braeken-Hack-Microsoft-Using-Microsoft-Signed-Binaries-wp.pdf)
		* [Microsoft Applications and Blocklist - FortyNorth Security](https://www.fortynorthsecurity.com/how-to-bypass-wdac-with-dbgsrv-exe/)
		* [Unsanitized file validation leads to Malicious payload download via Office binaries. - Reegun J](https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191)
		* [Background Intelligent Transfer Protocol - TH Team](https://medium.com/@threathuntingteam/background-intelligent-transfer-protocol-ab81cd900aa7)	
		* [Stay positive Lolbins… not! - Hexacorn](http://www.hexacorn.com/blog/2020/02/05/stay-positive-lolbins-not/)
		* [Living Off the Land - liberty-shell](https://liberty-shell.com/sec/2018/10/20/living-off-the-land/)
	* **Talks/Presentations/Videos**
		* [Covert Attack Mystery Box: A few novel techniques for exploiting Microsoft "features" - Mike Felch and Beau Bullock (WWHF2018)](https://www.youtube.com/watch?v=XFk-b0aT6cs)
			* Over the last few months we’ve been doing a bit of research around various Microsoft “features”, and have mined a few interesting nuggets that you might find useful if you’re trying to be covert on your red team engagements. This talk will be “mystery surprise box” style as we’ll be weaponizing some things for the first time. There will be demos and new tools presented during the talk. So, if you want to win at hide-n-seek with the blue team, come get your covert attack mystery box!
	* **In-the-Spirit-Of**
		* [BADministration](https://github.com/ThunderGunExpress/BADministration)
			* BADministration is a tool which interfaces with management or administration applications from an offensive standpoint. It attempts to provide offsec personnel a tool with the ability to identify and leverage these non-technical vulnerabilities. As always: use for good, promote security, and fight application propagation.
	* **Not really**
		* [Windows Store Apps Can Compromise PC Security - Russell Smith](https://www.petri.com/windows-store-apps-can-compromise-pc-security)
* **Execution**<a name="winexec"></a>
	* **Articles/Blogposts/Writeups**
		* [cmd.exe running any file no matter what extension - Hexacorn](http://www.hexacorn.com/blog/2019/04/21/cmd-exe-running-any-file-no-matter-what-extension/)
		* [Post-Exploitation on Windows using ActiveX Controls](http://uninformed.org/?v=all&a=3&t=sumry)
			*  When exploiting software vulnerabilities it is sometimes impossible to build direct communication channels between a target machine and an attacker's machine due to restrictive outbound filters that may be in place on the target machine's network. Bypassing these filters involves creating a post-exploitation payload that is capable of masquerading as normal user traffic from within the context of a trusted process. One method of accomplishing this is to create a payload that enables ActiveX controls by modifying Internet Explorer's zone restrictions. With ActiveX controls enabled, the payload can then launch a hidden instance of Internet Explorer that is pointed at a URL with an embedded ActiveX control. The end result is the ability for an attacker to run custom code in the form of a DLL on a target machine by using a trusted process that uses one or more trusted communication protocols, such as HTTP or DNS.
		* [Penetration Testing: Stopping an Unstoppable Windows Service - Scott Sutherland](https://blog.netspi.com/penetration-testing-stopping-an-unstoppable-windows-service/)
		* [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT)
			* Remote Command Execution as SYSTEM on Windows IoT Core; The method is exploiting the Sirep Test Service that’s built in and running on the official images offered at Microsoft’s site. This service is the client part of the HLK setup one may build in order to perform driver/hardware tests on the IoT device. It serves the Sirep/WPCon/TShell protocol. We broke down the Sirep/WPCon protocol and demonstrated how this protocol exposes a remote command interface for attackers, that include RAT abilities such as get/put arbitrary files on arbitrary locations and obtain system information. Based on the findings we have extracted from this research about the service and protocol, we built a simple python tool that allows exploiting them using the different supported commands. We called it SirepRAT. It features an easy and intuitive user interface for sending commands to a Windows IoT Core target. It works on any cable-connected device running Windows IoT Core with an official Microsoft image.
			* [Whitepaper](https://github.com/SafeBreach-Labs/SirepRAT/blob/master/docs/SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_White_Paper.pdf)
			* [Slides](https://github.com/SafeBreach-Labs/SirepRAT/blob/master/docs/SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_Slides.pdf)
	* **CMSTP**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Command-Line Interface**
		* **Articles/Blogposts/Writeups**
			* [DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and Detection Techniques - Daniel Bohannon](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)
		* **Tools**
			* [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
				* Cmd.exe Command Obfuscation Generator & Detection Test Harness

	* **Compiled HTML File**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Component Object Model and Distributed COM**
		* **Articles/Blogposts/Writeups**
			* [Forcing Iexplore.exe to Load a Malicious DLL via COM Abuse - ired.team](https://ired.team/offensive-security/code-execution/forcing-iexplore.exe-to-load-a-malicious-dll-via-com-abuse)
		* **Tools**
	* **Control Panel Items**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Dynamic Data Exchange**
		* **Articles/Blogposts/Writeups**
			* [DDE Downloaders, Excel Abuse, and a PowerShell Backdoor - rinseandREpeat analysis](https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html)
		* **Tools**
	* **Excel**
		* **Articles/Blogposts/Writeups**
			* [Welcome to the Excel Software Development Kit - docs.ms](https://docs.microsoft.com/en-us/office/client-developer/excel/welcome-to-the-excel-software-development-kit)
			* [DLL Execution via Excel.Application RegisterXLL() method - Ryan Hanson](https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52)
			* [ExcelDllLoader](https://github.com/3gstudent/ExcelDllLoader)
			* [Use Excel.Application object's RegisterXLL() method to load dll - 3gstudent](https://translate.google.com/translate?sl=auto&tl=en&u=https%3A%2F%2F3gstudent.github.io%2F3gstudent.github.io%2FUse-Excel.Application-object%27s-RegisterXLL%28%29-method-to-load-dll%2F)
		* **Tools**
			* [Hello World XLL](https://github.com/edparcell/HelloWorldXll)
				* This is a simple XLL, showing how to create an XLL from scratch.
			* [xllpoc](https://github.com/moohax/xllpoc)
				* A small project that aggregates community knowledge for Excel XLL execution, via xlAutoOpen() or PROCESS_ATTACH.
	* **Execution through API**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Execution through Module Load**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Exploitation for Client Execution**
		* **Articles/Blogposts/Writeups**
			* [CVE-2019-0726 - MWRLabs](https://labs.mwrinfosecurity.com/advisories/windows-dhcp-client/)
				* DHCP client rce
		* **Tools**
	* **Graphical User Interface**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **InstallUtil**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **LSASS Driver**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Mshta**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **PowerShell**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Regsvcs/Regasm**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Regsvr32**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Rundll32**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Scheduled Task**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Scripting**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Service Execution**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Signed Binary Proxy Execution**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Signed Script Proxy Execution**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Third-party Software**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Trusted Developer Utilities**
		* **Articles/Blogposts/Writeups**
			* [MSBuild - docs.ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild?view=vs-2015)
			* [MSBuild Inline Tasks - docs.ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks?view=vs-2015)
			* [Understanding the Project File(MSBuild) - docs.ms](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/deployment/web-deployment-in-the-enterprise/understanding-the-project-file)
			* [Doing More With MSBuild - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-MSBuild-To-Do-More/)
			* [Aggressive MSBuild - Bypass Detection - fortynorthsecurity](https://fortynorthsecurity.com/blog/aggressive-msbuild-bypass-detection/)
		* **Tools**
	* **User Execution**
		* **Articles/Blogposts/Writeups**
			* [ClickOnce Security and Deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2015)
			* [ClickOnce (Twice or Thrice): A Technique for Social Engineering and (Un)trusted Command Execution - bohops](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)

		* **Tools**
	* **Windows Management Instrumentation**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Windows Remote Management**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **XSL Script Processing**
		* **Articles/Blogposts/Writeups**
		* **Tools**
* **Persistence**<a name="winpersist"></a>
	* **Accessibility Features**
	* **Account Manipulation**
	* **AppCert DLLs**
	* **AppInit DLLs**
	* **Application Shimming**
	* **Authentication Package**
	* **BITS Jobs**
	* **Bootkit**
	* **Browser Extensions**
	* **Change Default File Association**
	* **Component Firmware**
	* **Component Object Model Hijacking**
	* **Create Account**
	* **DLL Search Order Hijacking**
	* **External Remote Services**
	* **File System Permissions Weakness**
	* **Hidden Files and Directories**
	* **Hooking**
	* **Hypervisor**
	* **Image File Execution Options Injection**
	* **Logon Scripts**
	* **LSASS Driver**
	* **Modify Existing Service**
	* **Netsh Helper DLL**
	* **New Service**
	* **Office Application Startup**
	* **Path Interception**
	* **Port Monitors**
	* **PowerShell Profile**
	* **Redundant Access**
	* **Registry Run Keys / Startup Folder**
	* **Scheduled Task**
	* **Screensaver**
	* **Security Support Provider**
	* **Server Software Component**
	* **Service Registry Permissions Weakness**
	* **Shortcut Modification**
	* **SIP and Trust Provider Hijacking**
	* **System Firmware**
	* **Time Providers**
	* **Valid Accounts**
	* **Web Shell**
	* **Windows Management Instrumentation Event Subscription**
	* **Winlogon Helper DLL**	
	* **101**
		* [Windows Userland Persistence Fundamentals - b33f](http://www.fuzzysecurity.com/tutorials/19.html)
	* **Articles/Blogposts/Writeups**
		* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence - bohops](https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/)
		* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence (Part 2) - bohops](https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/)
	    * [Userland Persistence with Scheduled Tasks and COM Handler Hijacking - enigma0x3](https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
		* [Quiet in the Windows: Dropping Network Connections - Eviatar Gerzi](https://medium.com/@eviatargerzi/quiet-in-the-windows-dropping-network-connections-a5181b874116)
		* [Pentester’s Windows NTFS Tricks Collection - Rene Freingruber](https://sec-consult.com/en/blog/2018/06/pentesters-windows-ntfs-tricks-collection/)
		* [RID Hijacking: Maintaining access on Windows machines - r4wd3r](https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html)
		* [Hiding Registry keys with PSReflect - Brian Reitz](https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353)
		* [Evading Autoruns Kyle Hanslovan Chris Bisnett - DerbyCon 7](https://www.youtube.com/watch?v=AEmuhCwFL5I&app=desktop)
		* [RE: Evading Autoruns PoCs on Windows 10 - Kyle Hanslovan](https://medium.com/@KyleHanslovan/re-evading-autoruns-pocs-on-windows-10-dd810d7e8a3f)
		* [Hiding Files by Exploiting Spaces in Windows Paths](http://blakhal0.blogspot.com/2012/08/hiding-files-by-exploiting-spaces-in.html)
		* [Stealing passwords every time they change - carnal0wnage](http://carnal0wnage.attackresearch.com/2013/09/stealing-passwords-every-time-they.html)
		* [Activation Contexts — A Love Story - Philip Tsukerman](https://medium.com/philip-tsukerman/activation-contexts-a-love-story-5f57f82bccd)
			* TL;DR — Windows loads a version of the Microsoft.Windows.SystemCompatible assembly manifest into every process. Tampering with it lets you inject DLL side-loading opportunities into every process, and to perform COM hijacking without touching the registry. Unfortunately, the manifest could be replaced by another version, possibly killing your persistence by surprise.
	* **Talks/Presentations/Videos**
		* [Evading Autoruns - Kyle Hanslovan, Chris Bisnet(Derbycon2017)](https://www.youtube.com/watch?v=AEmuhCwFL5I&feature=youtu.be)
			* When it comes to offense, maintaining access to your endpoints is key. For defenders, it's equally important to discover these footholds within your network. During this talk, Kyle and Chris will expose several semi-public and private techniques used to evade the most common persistence enumeration tools. Their techniques will explore ways to re-invent the run key, unconventionally abuse search order, and exploit trusted applications. To complement their technical explanations, each bypass will include a live demo and recommendations for detection.
		* [Materials](https://github.com/huntresslabs/evading-autoruns)
		* [Here to stay: Gaining persistency by Abusing Advanced Authentication Mechanisms - Marina Simakov, Igal Gofman](https://www.youtube.com/watch?v=JvormRcth9w)
			* [Slides](https://paper.seebug.org/papers/Security%20Conf/Defcon/2017/DEFCON-25-Marina-Simakov-and-Igal-Gofman-Here-to-stay-Gaining-persistence-by-abusing-auth-mechanisms.pdf)
	* **Tools**
		* [Invisible Persistence](https://github.com/ewhitehats/InvisiblePersistence)
			* [Code](https://github.com/ewhitehats/InvisiblePersistence/tree/master/InvisibleKeys)
			* [Paper](https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf)
		* [Evading Autoruns - DerbyCon 7.0](https://github.com/huntresslabs/evading-autoruns)
		* [RID Hijacking: Maintaining Access on Windows Machines](https://github.com/r4wd3r/RID-Hijacking)
			* The RID Hijacking hook, applicable to all Windows versions, allows setting desired privileges to an existent account in a stealthy manner by modifying some security attributes of an user. By only using OS resources, it is possible to replace the RID of an user right before the primary access token is created, allowing to spoof the privileges of the hijacked RID owner.
			* [Presentation - Derbycon 8](https://github.com/r4wd3r/RID-Hijacking/blob/master/slides/derbycon-8.0/RID_HIJACKING_DERBYCON_2018.pdf)
			* [Blogpost](https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html)
		* [DropNet](https://github.com/g3rzi/DropNet)
			* A tool that can be used to close network connections automatically with a given parameters
	* **Active Directory**
		* [Sneaky Active Directory Persistence Tricks - adsecurity.org](https://adsecurity.org/?p=1929)
		* [Obtaining and Detecting Domain Persistence - Grant Bugher(DEF CON 23)](https://www.youtube.com/watch?v=gajEuuC2-Dk)
			* When a Windows domain is compromised, an attacker has several options to create backdoors, obscure his tracks, and make his access difficult to detect and remove. In this talk, I discuss ways that an attacker who has obtained domain administrator privileges can extend, persist, and maintain control, as well as how a forensic examiner or incident responder could detect these activities and root out an attacker.
		* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most - Asaf Hect](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
		* [Thousand ways to backdoor a Windows domain (forest)](http://jumpespjump.blogspot.com/2015/03/thousand-ways-to-backdoor-windows.html)
		* [Remote Hash Extraction On Demand Via Host Security Descriptor Modification - Will Harmjoy](https://posts.specterops.io/remote-hash-extraction-on-demand-via-host-security-descriptor-modification-2cf505ec5c40)
			* Tl;dr if you gain “administrative” access to a remote machine, you can modify a few host security descriptors and have a security principal/trustee of your choice generate Silver Tickets indefinitely, as well as remotely retrieve local hashes and domain cached credentials.
	* **AppDomain**
		* [Use AppDomainManager to maintain persistence](https://3gstudent.github.io/3gstudent.github.io/Use-AppDomainManager-to-maintain-persistence/)
	* **AppInit.dlls**
		* [AppInit_DLLs in Windows 7 and Windows Server 2008 R2 - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2)
		* [AppInit DLLs and Secure Boot - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dlls/secure-boot-and-appinit-dlls)
			* Starting in Windows 8, the AppInit_DLLs infrastructure is disabled when secure boot is enabled.
		* [Alternative psexec: no wmi, services or mof needed - Diablohorn](https://diablohorn.com/2013/10/19/alternative-psexec-no-wmi-services-or-mof-needed/)
			* [Poc](https://github.com/DiabloHorn/DiabloHorn/tree/master/remote_appinitdlls)
	* **Application Plugins**
		* [Backdooring Plugins - Averagejoe](https://www.gironsec.com/blog/2018/03/backdooring-plugins/)
	* **APPX/UWP**
		* [Persistence using Universal Windows Platform apps (APPX) - oddvarmoe](https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/)
			* Persistence can be achieved with Appx/UWP apps using the debugger options. This technique will not be visible by Autoruns.
	* **Alternate Data Streams**
		* **Articles/Blogposts/Writeups**
			* [Putting data in Alternate data streams and how to execute it - oddvar.moe](https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/)
				* [Part 2](https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/)
			* [Kurt Seifried Security Advisory 003 (KSSA-003)](https://seifried.org/security/advisories/kssa-003.html)
			* [NTFS Alternate Data Streams for pentesters (part 1)](https://labs.portcullis.co.uk/blog/ntfs-alternate-data-streams-for-pentesters-part-1/)
			* [Using Alternate Data Streams to Persist on a Compromised Machine](https://enigma0x3.wordpress.com/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/)
			* [Using Alternate Data Streams to Persist on a Compromised Machine - enigma0x3](https://enigma0x3.net/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/)
			* [NTFS Alternate Data Streams - darknessgate.com](http://www.darknessgate.com/security-tutorials/date-hiding/ntfs-alternate-data-streams/)
		* **Talks & Presentations**
		* **Tools**
			* [Exe_ADS_Methods.txt - api0cradle](https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f)
				* Execute from Alternate Streams
			* [Get-ADS](https://github.com/p0shkatz/Get-ADS)
				* Powershell script to search for alternate data streams
			* [Evading Autoruns](https://github.com/huntresslabs/evading-autoruns)
				* When it comes to offense, maintaining access to your endpoints is key. For defenders, it's equally important to discover these footholds within your network. During this talk, Kyle and Chris will expose several semi-public and private techniques used to evade the most common persistence enumeration tools. Their techniques will explore ways to re-invent the run key, unconventionally abuse search order, and exploit trusted applications. To complement their technical explanations, each bypass will include a live demo and recommendations for detection.
				* [Talk](https://www.youtube.com/watch?v=AEmuhCwFL5I&feature=youtu.be)	
			* [Alternate-Data-Streams with PowerShell](https://github.com/davehardy20/Alternate-Data-Streams)
				* I literally stumbled upon this whilst reading up on the parameters for the Get-Content and Set-Content cmdlets for another piece of research. The parameter that got my interest is -Stream which allows the user the ability to read and write NTFS alternate data streams. If we create a file with the following commands: `$file = "$env:TEMP\test.txt" \ Set-Content -Path $file -Value 'Alternate Data Stream Test File'`. To read the file content, we use the following: `Get-Content -Path $file` ; Which will return: `Alternate Data Stream Test File`
			* [Get-ADS](https://github.com/p0shkatz/Get-ADS)
				* Powershell script to search for alternate data streams This script searches recursively through a specified file system for alternate data streams (ADS). The script can search local and UNC paths speciffied by the $path paramenter. All readable files will have the stream attrubute inspected ignoring the default DATA and FAVICON (image file on URL files) streams. The script use Boe Prox's amazing Get-RunspaceData function and other code to multithread the search. The default number of threads is the number of logical cores plus one. This can be adjusted by specifiying the $threads parameter. Use with caution as runspaces can easily chomp resources (CPU and RAM). Once the number of file system objects (files and folders) is determined, they are split into equal groups of objects divided by the number of threads. Then each thread has a subset of the total objects to inspect for ADS.
	* **bitsadmin**
		* [Temporal Persistence with bitsadmin and schtasks](http://0xthem.blogspot.com/2014/03/t-emporal-persistence-with-and-schtasks.html)
		/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
	* **COM**
		* [COM Object hijacking: the discreet way of persistence](https://blog.gdatasoftware.com/blog/article/com-object-hijacking-the-discreet-way-of-persistence.html)
		* [Userland Persistence with Scheduled Tasks and COM Handler Hijacking](https://enigma0x3.net/2016/05/25)
		* [How To Hunt: Detecting Persistence & Evasion With The COM - Blake Strom](https://www.endgame.com/blog/technical-blog/how-hunt-detecting-persistence-evasion-com)
		* [Persistence: “the continued or prolonged existence of something”: Part 2 – COM Hijacking - MDSec](https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-2-com-hijacking/)
		* [Use COM Object hijacking to maintain persistence——Hijack CAccPropServicesClass and MMDeviceEnumerator - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-CAccPropServicesClass-and-MMDeviceEnumerator/)
		* [Use COM Object hijacking to maintain persistence——Hijack explorer.exe - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-explorer.exe/)
		* [Activation Contexts — A Love Story - Philip Tsukerman(2019)](https://medium.com/philip-tsukerman/activation-contexts-a-love-story-5f57f82bccd)
			* TL;DR — Windows loads a version of the Microsoft.Windows.SystemCompatible assembly manifest into every process. Tampering with it lets you inject DLL side-loading opportunities into every process, and to perform COM hijacking without touching the registry. Unfortunately, the manifest could be replaced by another version, possibly killing your persistence by surprise.
	* **Directory Services Restore Mode**
		* [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
		* [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)
	* **Drivers**
		* [Windows Firewall Hook Enumeration](https://www.nccgroup.com/en/blog/2015/01/windows-firewall-hook-enumeration/)
			* We’re going to look in detail at Microsoft Windows Firewall Hook drivers from Windows 2000, XP and 2003. This functionality was leveraged by the Derusbi family of malicious code to implement port-knocking like functionality. We’re going to discuss the problem we faced, the required reverse engineering to understand how these hooks could be identified and finally how the enumeration tool was developed.
	* **Event Log**
		* [Windows Event Log Driven Back Doors](http://blakhal0.blogspot.com/2015/03/windows-event-log-driven-back-doors.html)
	* **File Handling/Execution**
		* [Persistence using GLOBALFLAGS in image file execution options – hidden from autoruns.exe - Oddvar Moe](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)
		* [Registering an Application to a URI Scheme - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa767914(v=vs.85)?redirectedfrom=MSDN)
	* **LAPS**
		* [Mise en place d'une Backdoor LAPS via modification de l'attribut SearchFlags avec DCShadow - Gregory Lucand](https://adds-security.blogspot.com/2018/08/mise-en-place-dune-backdoor-laps-via.html)
		* [Adding a Backdoor to AD in 400 Milliseconds - David Rowe](https://www.secframe.com/blog/persistence-in-400-milliseconds)
		* [LAPS - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/域渗透-利用SYSVOL还原组策略中保存的密码/)
		* [LAPS - liuhaihua](http://www.liuhaihua.cn/archives/179102.html)
	* **Library Files**
		* [Abusing Windows Library Files for Persistence - F-Secure](https://blog.f-secure.com/abusing-windows-library-files-for-persistence/)
	* **Golden(Silver) Ticket**
		* [Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)
		* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)
		* [Silver & Golden Tickets - hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/)
		* [Mimikatz 2.0 - Golden Ticket Walkthrough - Ben Lincoln](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html)
	* **IIS**
		* [IIS Raid – Backdooring IIS Using Native Modules - MDSec](https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/)
	* **msdtc**
		* [Use msdtc to maintain persistence - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-msdtc-to-maintain-persistence/)
	* **MS Office**
		* [Persistence: “the continued or prolonged existence of something” - Dominic Chell](https://medium.com/@dmchell/persistence-the-continued-or-prolonged-existence-of-something-e29ea63e5c9a)
		* [Add-In Opportunities for Office Persistence - William Knowles](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
		* [One Template To Rule 'Em All - Kostas Lintovois](https://labs.f-secure.com/archive/one-template-to-rule-em-all/)
			* Introduction of wePWNize
		* [Persisting with Microsoft Office: Abusing Extensibility Options - William Knowles](https://labs.mwrinfosecurity.com/assets/BlogFiles/WilliamKnowles-MWR-44con-PersistingWithMicrosoftOffice.pdf)
		* [Use Office to maintain persistence - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/)
		* [Office Persistence on x64 operating system - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Office-Persistence-on-x64-operating-system/)
	* **.NET**
		* [Common Language Runtime Hook for Persistence - Paul Laine](https://www.contextis.com/en/blog/common-language-runtime-hook-for-persistence)
			* This blog post explains how it is possible to execute arbitrary code and maintain access to a Microsoft Windows system by leveraging the Common Language Runtime application domain manager.
		* [CLR-Persistence](https://github.com/3gstudent/CLR-Injection)
			* Use CLR to inject all the .NET apps
		* [Using CLR to maintain Persistence](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-maintain-persistence/)
		* [Common Language Runtime Hook for Persistence - Paul Laine](https://www.contextis.com/en/blog/common-language-runtime-hook-for-persistence#When:10:30:00Z)
		* [SharPersist: Windows Persistence Toolkit in C# - Brett Hawkins](https://www.fireeye.com/blog/threat-research/2019/09/sharpersist-windows-persistence-toolkit.html)
		* [SharPersist](https://github.com/fireeye/SharPersist)
			* Windows persistence toolkit written in C#
	* **Netsh Helper DLL**
		* [Persistence – Netsh Helper DLL - NetbiosX](https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/)
	* **Password Filter DLL**
		* **101**
			* [Password Filters - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secmgmt/password-filters)
				* Password filters provide a way for you to implement password policy and change notification.
			* [AD Password Filters - ldapwiki](https://ldapwiki.com/wiki/AD%20Password%20Filters)
			* [Installing and Registering a Password Filter DLL - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secmgmt/installing-and-registering-a-password-filter-dll)
				* You can use the Windows password filter to filter domain or local account passwords. To use the password filter for domain accounts, install and register the DLL on each domain controller in the domain.
			* [Installing and Registering a Password Filter DLL - msdn.ms](https://msdn.microsoft.com/library/windows/desktop/ms721766.aspx)
			* [PSAM_PASSWORD_NOTIFICATION_ROUTINE callback function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nc-ntsecapi-psam_password_notification_routine)
				* The PasswordChangeNotify function is implemented by a password filter DLL. It notifies the DLL that a password was changed.
		* **Articles/Blogposts/Writeups**
			* [Capture password change at active directory controller - StackOverflow(2013)](https://stackoverflow.com/questions/15582444/capture-password-change-at-active-directory-controller)
			* [How a Windows Password Filters Works - NFront(2014)](https://www.slideshare.net/nFrontSecurity/how-do-password-filters-work)
			* [Stealing passwords every time they change - carnal0wnage(2013)](http://carnal0wnage.attackresearch.com/2013/09/stealing-passwords-every-time-they.html)
			* [Intercepting Password Changes With Function Hooking - clymb3r(2013)](https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/)
			* [T1174: Password Filter - @spottheplanet](https://ired.team/offensive-security/credential-access-and-credential-dumping/t1174-password-filter-dll)
			* [Throwing it out the Windows: Exfiltrating Active Directory credentials through DNS - Leanne Dutil](https://www.gosecure.net/blog/2018/07/10/exfiltrating-active-directory-credentials-through-dns/)
				* This post will detail the password filter implant project we developed recently. Our password filter is used to exfiltrate Active Directory credentials through DNS. This text will discuss the technicalities of the project as well as my personal experience developing it.
			* [Dump-Clear-Text-Password-after-KB2871997-installed - 3gstudent](https://github.com/3gstudent/Dump-Clear-Password-after-KB2871997-installed)
			* [Domain Penetration-Hook PasswordChangeNotify – Three Good Students](http://www.vuln.cn/6812)
		* **Talks/Presentations/Videos**
		* **Tools**
			* [DLLPasswordFilterImplant](https://github.com/GoSecure/DLLPasswordFilterImplant)
				* DLLPasswordFilterImplant is a custom password filter DLL that allows the capture of a user's credentials. Each password change event on a domain will trigger the registered DLL in order to exfiltrate the username and new password value prior successfully changing it in the Active Directory (AD).
			* [OpenPasswordFilter](https://github.com/jephthai/OpenPasswordFilter)
				* OpenPasswordFilter is an open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords.
			* [PasswordStealing](https://github.com/gtworek/PSBits/tree/master/PasswordStealing)
				* Password stealing DLL I have written about 1999, some time before Active Directory was announced. And of course it still works. First, it was written in 32-bit Delphi (pardon my language) and when it stopped working as everything changed into 64-bit - in (so much simpler when it comes to Win32 API) C, as I did not have 64-bit Delphi. The original implementation was a bit more complex, including broadcasting the changed password over the network etc. but now it works as a demonstration of an idea, so let's keep it as simple as possible. It works everywhere - on local machines for local accounts and on DCs for domain accounts.
	* **PowerShell**
		* [Using and Abusing Aliases with PowerShell - notoriousrebel.space](https://notoriousrebel.space/2019-11-24-using-and-abusing-aliases-with-powershell/)
			* Shimming Aliases with PowerShell
		* [Remapper](https://github.com/NotoriousRebel/Remapper)
			* PowerShell script that will shim aliases throughout PowerShell sessions through the use of PowerShell profiles.
		* [p0shkiller(2016)](https://github.com/Cn33liz/p0shKiller)
			* Proof of Concept exploit to bypass Microsoft latest AntiMalware Scan Interface technology within PowerShell5 on Windows 10. With this exploit/patch applied, you can take control over powershells program flow by using DLL Hijacking and UAC Bypasstechniques. Every time powershell is started, a local admin named BadAss with password FacePalm01 will be added to the system (when run by an non elevated administrator account) and a reverse (SYSTEM) https meterpreter session (default 192.168.1.120) will be started every hour using a scheduled task.
	* **Protocol Handlers**
		* [Exploiting custom protocol handlers in Windows - Andrey Polkovnychenko](https://www.vdoo.com/blog/exploiting-custom-protocol-handlers-in-windows)
			* In this article we would like to present the mechanism for custom protocol handling in Windows, and how it can be exploited using a simple command injection vulnerability.
	* **Registry**
		* [Windows Registry Attacks: Knowledge Is the Best Defense](https://www.redcanary.com/blog/windows-registry-attacks-threat-detection/)
		* [Windows Registry Persistence, Part 1: Introduction, Attack Phases and Windows Services](http://blog.cylance.com/windows-registry-persistence-part-1-introduction-attack-phases-and-windows-services)
		* [Windows Registry Persistence, Part 2: The Run Keys and Search-Order](http://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order)
		* [List of autorun keys / malware persistence Windows registry entries](https://www.peerlyst.com/posts/list-of-autorun-keys-malware-persistence-windows-registry-entries-benjamin-infosec)
		* [How to Evade Detection: Hiding in the Registry - David Lu](https://www.tripwire.com/state-of-security/mitre-framework/evade-detection-hiding-registry/)
		* [Persistence – Registry Run Keys - NetbiosX](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/)
		* [InvisiblePersistence](https://github.com/ewhitehats/InvisiblePersistence)
			* Persisting in the Windows registry "invisibly". Whitepaper and POC
	* **SC/Scheduled Tasks**
		* [Sc](https://technet.microsoft.com/en-us/library/cc754599.aspx)
			* Communicates with the Service Controller and installed services. The SC.exe program provides capabilities similar to those provided in Services in the Control Panel.
		* [schtasks](https://technet.microsoft.com/en-us/library/cc725744.aspx)
		* [Script Task](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task)
			* Persistence Via MSSQL
	* **Security Support Provider**
		* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760)
	* **SeEnableDelegationPrivilege**
		* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
		* [SeEnableDelegationPrivilege Active Directory Backdoor](https://www.youtube.com/watch?v=OiqaO9RHskU)
	* **ScreenSaver**
		* [Persistence – Screensaver - NetbiosX](https://pentestlab.blog/2019/10/09/persistence-screensaver/)
	* **Services**
		* [Stealthier persistence using new services purposely vulnerable to path interception - Christophe Tafani-Dereeper](https://blog.christophetd.fr/stealthier-persistence-using-new-services-purposely-vulnerable-to-path-interception/)
		* [Persistence – New Service - NetbiosX](https://pentestlab.blog/2019/10/07/persistence-new-service/)
	* **Shims**
		* [Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)
		* [Shimming for Post Exploitation(blog)](http://www.sdb.tools/)
		* [Demystifying Shims – or – Using the App Compat Toolkit to make your old stuff work with your new stuff](https://web.archive.org/web/20170910104808/https://blogs.technet.microsoft.com/askperf/2011/06/17/demystifying-shims-or-using-the-app-compat-toolkit-to-make-your-old-stuff-work-with-your-new-stuff/)
		* [Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)
		* [Shim Database Talks](http://sdb.tools/talks.html)
		* [Using Application Compatibility Shims](https://web.archive.org/web/20170815050734/http://subt0x10.blogspot.com/2017/05/using-application-compatibility-shims.html)
		* [Persistence via Shims - liberty-shell](https://liberty-shell.com/sec/2020/02/25/shim-persistence/)
	* **Shortcuts**
		* [Persistence – Shortcut Modification - NetbiosX](https://pentestlab.blog/2019/10/08/persistence-shortcut-modification/)
	* **SID History**
		* [Sneaky Active Directory Persistence #14: SID History](https://adsecurity.org/?p=1772)
	* **SQL Server**
		* [Maintaining Persistence via SQL Server – Part 1: Startup Stored Procedures - NETSPI](https://blog.netspi.com/sql-server-persistence-part-1-startup-stored-procedures/)
		* [Script Task - doc.ms](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task?redirectedfrom=MSDN&view=sql-server-2017)
	* **Startup**
		* [Windows Startup Application Database](http://www.pacs-portal.co.uk/startup_content.php)
		* [SYSTEM Context Persistence in GPO Startup Scripts](https://cybersyndicates.com/2016/01/system-context-persistence-in-gpo-startup/)
	* **WaitFor**
		* [Persistence – WaitFor - NetbiosX](https://pentestlab.blog/2020/02/04/persistence-waitfor/)
	* **Windows Instrumentation Management**
		* [WMIC - Take Command-line Control over WMI - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742610(v=technet.10))
		* [WMIC - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/wmic)
		* [Abusing Windows Management  Instrumentation (WMI) to Build a Persistent,  Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
		* [Abusing Windows Management Instrumentation (WMI) - Matthew Graeber(BH USA 2015)](https://www.youtube.com/watch?v=0SjMgnGwpq8)
			* Imagine a technology that is built into every Windows operating system going back to Windows 95, runs as System, executes arbitrary code, persists across reboots, and does not drop a single file to disk. Such a thing does exist and it's called Windows Management Instrumentation (WMI). With increased scrutiny from anti-virus and 'next-gen' host endpoints, advanced red teams and attackers already know that the introduction of binaries into a high-security environment is subject to increased scrutiny. WMI enables an attacker practicing a minimalist methodology to blend into their target environment without dropping a single utility to disk. WMI is also unlike other persistence techniques in that rather than executing a payload at a predetermined time, WMI conditionally executes code asynchronously in response to operating system events. This talk will introduce WMI and demonstrate its offensive uses. We will cover what WMI is, how attackers are currently using it in the wild, how to build a full-featured backdoor, and how to detect and prevent these attacks from occurring.
	* **WPAD**
		* [WPAD Persistence](http://room362.com/post/2016/wpad-persistence/)
	* **Miscellaneous**
		* [backdoorme](https://github.com/Kkevsterrr/backdoorme)
			* Tools like metasploit are great for exploiting computers, but what happens after you've gained access to a computer? Backdoorme answers that question by unleashing a slew of backdoors to establish persistence over long periods of time. Once an SSH connection has been established with the target, Backdoorme's strengths can come to fruition. Unfortunately, Backdoorme is not a tool to gain root access - only keep that access once it has been gained.
		* [Windows Program Automatic Startup Locations(2004) BleepingComputer](https://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)
* **Privilege Escalation**<a name="winprivesc"></a>
	* **101**
		* [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
		* [Windows Privilege Escalation Methods for Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
		* [Common Windows Privilege Escalation Vectors](https://toshellandback.com/2015/11/24/ms-priv-esc/)
		* [Windows Privilege Escalation Cheat Sheet/Tricks](http://it-ovid.blogspot.fr/2012/02/windows-privilege-escalation.html)
		* [Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
		* [Hunting for Privilege Escalation in Windows Environment - Heirhabarov](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)
		* [Elevating your Windows Privileges Like a Boss! - Jake Williams(WWHF2019)](https://www.youtube.com/watch?v=SHdM197sbIE)
			* Local privilege escalation on Windows is becoming increasingly difficult. Gone are the days when you could just easily exploit the Windows kernel. Multiple controls (KASLR, DEP, SMEP, etc.) have made kernel mode exploitation of the bugs that are discovered much more difficult. In this talk, we'll discuss multiple opportunities for privilege escalation including using COM objects, DLL side loading, and various privileges assigned to user accounts. Bring a Windows 10 VM. We'll have instructions available for recreating the scenarios demonstrated in the talk.
	* **General**
		* [Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege - James Forshaw](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html)
		* [Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read - James Forshaw](https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html)
		* [PrivescCheck](https://github.com/itm4n/PrivescCheck)
			* This script aims to enumerate common Windows security misconfigurations which can be leveraged for privilege escalation and gather various information which might be useful for exploitation and/or post-exploitation.
	* **Specific Techniques**
		* **Always Install Elevated**
			* [AlwaysInstallElevated - docs.ms](https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated)
			* [Always Install Elevated - NetbiosX](https://pentestlab.blog/2017/02/28/always-install-elevated/)
			* [Get-RegistryAlwaysInstallElevated - PowerSploit](https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAlwaysInstallElevated/)
		* **DLL Stuff** <a name="dll"></a>
			* [Creating a Windows DLL with Visual Basic](http://www.windowsdevcenter.com/pub/a/windows/2005/04/26/create_dll.html)
			* [Calling DLL Functions from Visual Basic Applications - msdn](https://msdn.microsoft.com/en-us/library/dt232c9t.aspx)
			* **DLL Hijacking**
				* [Dynamic-Link Library Search Order - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/Dlls/dynamic-link-library-search-order)
				* [Dynamic-Link Library Hijacking](https://www.exploit-db.com/docs/31687.pdf)
				* [Crash Course in DLL Hijacking](https://blog.fortinet.com/2015/12/10/a-crash-course-in-dll-hijacking)
				* [VB.NET Tutorial - Create a DLL / Class Library](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)
				* [Windows 10 - Task Scheduler service - Privilege Escalation/Persistence through DLL planting - remoteawesomethoughts.blogspot](https://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html)
				* [DLL Hijacking via URL files - InsertScript](https://insert-script.blogspot.com/2018/05/dll-hijacking-via-url-files.html)
			* **DLL Injection**
				* [DLL Injection and Hooking](http://securityxploded.com/dll-injection-and-hooking.php)
				* [Windows DLL Injection Basics](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html)
				* [Crash Course in DLL Hijacking](https://blog.fortinet.com/2015/12/10/a-crash-course-in-dll-hijacking)
				* [Windows DLL Injection Basics - OpenSecurityTraining](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html)
				* [An Improved Reflective DLL Injection Technique - Dan Staples](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html)
				* [Reflective DLL Injection with PowerShell - clymb3r](https://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/)	
				* [Delivering custom payloads with Metasploit using DLL injection - blog.cobalstrike](https://blog.cobaltstrike.com/2012/09/17/delivering-custom-payloads-with-metasploit-using-dll-injection/)
				* [Understanding how DLL Hijacking works - Astr0baby](https://astr0baby.wordpress.com/2018/09/08/understanding-how-dll-hijacking-works/)
				* [DLL Injection - NetbiosX](https://pentestlab.blog/2017/04/04/dll-injection/)
			* **DLL Tools**
				* [rattler](https://github.com/sensepost/rattler)
					* Rattler is a tool that automates the identification of DLL's which can be used for DLL preloading attacks.
				* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings)
					* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
				* [Pazuzu](https://github.com/BorjaMerino/Pazuzu)
					* Pazuzu is a Python script that allows you to embed a binary within a precompiled DLL which uses reflective DLL injection. The goal is that you can run your own binary directly from memory. This can be useful in various scenarios.	
				* [Bleak](https://github.com/Akaion/Bleak)
					* A Windows native DLL injection library written in C# that supports several methods of injection.
				* [Reflective DLL injection using SetThreadContext() and NtContinue(https://zerosum0x0.blogspot.com/2017/07/threadcontinue-reflective-injection.html)
					* [Code](https://github.com/zerosum0x0/ThreadContinue)
		* **Exploits/Missing Patches**
			* [Windows Kernel Exploits - NetbiosX](https://pentestlab.blog/2017/04/24/windows-kernel-exploits/)
			* [kernel-exploits - SecWiki](https://github.com/SecWiki/windows-kernel-exploits)
			* **MS17-010 (Eternal Blue)**
			* **CVE-2018-8140**
				* [Want to Break Into a Locked Windows 10 Device? Ask Cortana (CVE-2018-8140) - Cedric Cochin, Steve Povolny](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/want-to-break-into-a-locked-windows-10-device-ask-cortana-cve-2018-8140/)
			* **CVE-2019-0841**
				* [AppX Deployment Service Local Privilege Escalation - CVE-2019-0841 BYPASS #2 - sandboxescaper](https://www.exploit-db.com/exploits/46976)
			* **CVE-2019-1064**
				* [CVE-2019-1064 AppXSVC Local Privilege Escalation - RhythmStick](https://www.rythmstick.net/posts/cve-2019-1064/)
			* **CVE-2019-1069**
				* [Exploiting the Windows Task Scheduler Through CVE-2019-1069 - Simon Zuckerbraun](https://www.thezdi.com/blog/2019/6/11/exploiting-the-windows-task-scheduler-through-cve-2019-1069)
			* **CVE-2019–1082**
				* [More Than a Penetration Test (Microsoft Windows CVE-2019–1082) - Michal Bazyli](https://medium.com/@bazyli.michal/more-than-a-penetration-test-cve-2019-1082-647ba2e59034)
			* **CVE-2020-0618**
				* [CVE-2020-0618: RCE in SQL Server Reporting Services (SSRS) - MDSec](https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/)
			* **CVE-2020-0787**
				* [BitsArbitraryFileMove](https://github.com/itm4n/BitsArbitraryFileMove)
			* **CVE-2020-0796**
				* [CVE-2020-0796](https://github.com/danigargu/CVE-2020-0796)
					* Windows SMBv3 LPE Exploit
			* **Miscellaneous**
				* [CVE-2019-1405 and CVE-2019-1322 – Elevation to SYSTEM via the UPnP Device Host Service and the Update Orchestrator Service - Phillip Langlois and Edward Torkington](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/)
					* This blog post discusses two vulnerabilities discovered by NCC Group consultants during research undertaken on privilege elevation via COM local services. The first of these vulnerabilities (CVE-2019-1405) is a logic error in a COM service and allows local unprivileged users to execute arbitrary commands as a LOCAL SERVICE user. The second vulnerability (CVE-2019-1322) is a simple service misconfiguration that allows any user in the local SERVICE group to reconfigure a service that executes as SYSTEM (this vulnerability was independently also discovered by other researchers). When combined, these vulnerabilities allow an unprivileged local user to execute arbitrary commands as the SYSTEM user on a default installation of Windows 10.
				* [Thanksgiving Treat: Easy-As-Pie Windows 7 Secure Desktop Escalation Of Privilege - Simon Zuckerbraun](https://www.zerodayinitiative.com/blog/2019/11/19/thanksgiving-treat-easy-as-pie-windows-7-secure-desktop-escalation-of-privilege)
		* **Group Policy (Preferences)**
			* [Get-GPPermission - docs.ms](https://docs.microsoft.com/en-us/powershell/module/grouppolicy/get-gppermission?view=win10-ps)
			* [Exploiting Windows 2008 Group Policy Preferences](http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html)
			* [Decrypting Windows 2008 GPP user passwords using Gpprefdecrypt.py](https://web.archive.org/web/20160408235812/http://www.leonteale.co.uk/decrypting-windows-2008-gpp-user-passwords-using-gpprefdecrypt-py/)
			* [Group Policy Preferences and Getting Your Domain 0wned - Carnal0wnage](http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html)
			* [Compromise Networks Through Group Policy Preferences - securestate.com(archive.org)](https://web.archive.org/web/20150108083024/http://blog.securestate.com/how-to-pwn-systems-through-group-policy-preferences/)
			* [Group Policy Preferences - NetbiosX](https://pentestlab.blog/2017/03/20/group-policy-preferences/)
		* **Intel SYSRET**
			* [Windows Kernel Intel x64 SYSRET Vulnerability + Code Signing Bypass Bonus](https://repret.wordpress.com/2012/08/25/windows-kernel-intel-x64-sysret-vulnerability-code-signing-bypass-bonus/)
			* [Windows Kernel Intel x64 SYSRET Vulnerability Exploit + Kernel Code Signing Bypass Bonus](https://github.com/shjalayeri/sysret)
		* **LAPS Misconfiguration**
			* [Taking over Windows Workstations thanks to LAPS and PXE - Rémi ESCOURROU](https://www.securityinsider-wavestone.com/2020/01/taking-over-windows-workstations-pxe-laps.html)
				* In this article we will examine how the combination of two good security solutions with no apparent connection to each other can lead to the takeover of all workstations in a Windows environment. The main advantage of this technique is that it is exploitable in black box, i.e. without any prior knowledge of the target.
			* [Who Can See LAPS Passwords? - David Rowe](https://www.secframe.com/blog/when-can-you-see-a-laps-password)
		* **Local Phishing**
			* [Ask and ye shall receive - Impersonating everyday applications for profit - FoxIT](https://www.fox-it.com/en/insights/blogs/blog/phishing-ask-and-ye-shall-receive/)
			* [Phishing for Credentials: If you want it, just ask! - enigma0x3](http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
			* [Invoke-CredentialPhisher](https://github.com/fox-it/Invoke-CredentialPhisher)
				* The first one is a powershell script to send toast notifications on behalf on an (installed) application or the computer itself. The user will be asked to supply credentials once they click on the notification toast. The second one is a Cobalt Strike module to launch the phishing attack on connected beacons.
			* [Phishing Windows Credentials - NetbiosX](https://pentestlab.blog/2020/03/02/phishing-windows-credentials/)
		* **Logic**
			* [Introduction to Logical Privilege Escalation on Windows - James Forshaw](https://conference.hitb.org/hitbsecconf2017ams/materials/D2T3%20-%20James%20Forshaw%20-%20Introduction%20to%20Logical%20Privilege%20Escalation%20on%20Windows.pdf)
			* [Windows Logical EoP Workbook](https://docs.google.com/document/d/1qujIzDmFrcFCBeIgMjWDZTLNMCAHChAnKDkHdWYEomM/edit)	
			* [Abusing Token Privileges For EoP](https://github.com/hatRiot/token-priv)
				* This repository contains all code and a Phrack-style paper on research into abusing token privileges for escalation of privilege. Please feel free to ping us with questions, ideas, insults, or bugs.				
		* **Named Pipes**
			* [Discovering and Exploiting Named Pipe Security Flaws for Fun and Profit - Blake Watts(2002)](http://www.blakewatts.com/namedpipepaper.html)
			* [Named Pipe Filename Local Privilege Escalation - Securiteam(2003)](https://securiteam.com/windowsntfocus/5bp012kaki/)
			* [Windows Named Pipes & Impersonation - decoder.cloud(2019)](https://decoder.cloud/2019/03/06/windows-named-pipes-impersonation/)
			* [Windows NamedPipes 101 + Privilege Escalation - @spottheplanet](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
			* [Part I: The Fundamentals of Windows Named Pipes - Robert Hawes](https://versprite.com/blog/security-research/microsoft-windows-pipes-intro/)
			* [Part II: Analysis of a Vulnerable Microsoft Windows Named Pipe Application - Robert Hawes](https://versprite.com/blog/security-research/vulnerable-named-pipe-application/)
		* **Privileged File Operation Abuse**
			* [An introduction to privileged file operation abuse on Windows - @Claviollotte](https://offsec.provadys.com/intro-to-file-operation-abuse-on-Windows.html)
				* TL;DR This is a (bit long) introduction on how to abuse file operations performed by privileged processes on Windows for local privilege escalation (user to admin/system), and a presentation of available techniques, tools and procedures to exploit these types of bugs.
		* **NTLM-related**
			* Search "NTLM" in the 'Network_Attacks.md' page.
			* **Articles/Blogposts/Writeups**
				* [Practical Usage of NTLM Hashes - ropnop](https://blog.ropnop.com/practical-usage-of-ntlm-hashes/)
				* [Abusing Unsafe Defaults in Active Directory Domain Services: A Real-World Case Study - Louis Dion-Marcil](https://www.gosecure.net/blog/2019/02/20/abusing-unsafe-defaults-in-active-directory/)
			* **NTLM Reflection**
				* [Windows: DCOM DCE/RPC Local NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=325&redir=1)
				* [Windows: Local WebDAV NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=222&redir=1)
				* [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
					* Earlier this week, Microsoft issued patches for CVE-2019-1040, which is a vulnerability that allows for bypassing of NTLM relay mitigations. The vulnerability was discovered by Marina Simakov and Yaron Zinar (as well as several others credited in the Microsoft advisory), and they published a technical write-up about the vulnerability here. The short version is that this vulnerability allows for bypassing of the Message Integrity Code in NTLM authentication. The impact of this however, is quite big if combined with the Printer Bug discovered by Lee Christensen and some of my own research that builds forth on the Kerberos research of Elad Shamir. Using a combination of these vulnerabilities, it is possible to relay SMB authentication to LDAP. This allows for Remote code execution as SYSTEM on any unpatched Windows server or workstation (even those that are in different Active Directory forests), and for instant escalation to Domain Admin via any unpatched Exchange server (unless Exchange permissions were reduced in the domain). The most important takeaway of this post is that you should apply the June 2019 patches as soon as possible.
					* [CVE-2019-1040 scanner](https://github.com/fox-it/cve-2019-1040-scanner)
						* Checks for CVE-2019-1040 vulnerability over SMB. The script will establish a connection to the target host(s) and send an invalid NTLM authentication. If this is accepted, the host is vulnerable to CVE-2019-1040 and you can execute the MIC Remove attack with ntlmrelayx. Note that this does not generate failed login attempts as the login information itself is valid, it is just the NTLM message integrity code that is absent, which is why the authentication is refused without increasing the badpwdcount.
			* **NTLM Relay**
				* [NTLM Relay - Pixis](https://en.hackndo.com/ntlm-relay/)
				* [Playing with Relayed Credentials - @agsolino](https://www.secureauth.com/blog/playing-relayed-credentials)
				* [Server Message Block: SMB Relay Attack (Attack That Always Works) - CQURE Academy](https://cqureacademy.com/blog/penetration-testing/smb-relay-attack)
				* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes) - byt3bl33d3r](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
				* [An SMB Relay Race – How To Exploit LLMNR and SMB Message Signing for Fun and Profit - Jordan Drysdale](https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/)
				* [Effective NTLM / SMB Relaying - mubix](https://malicious.link/post/2014/effective-ntlm-smb-relaying/)
				* [SMB Relay with Snarf - Jeff Dimmock](https://bluescreenofjeff.com/2016-02-19-smb-relay-with-snarfjs-making-the-most-of-your-mitm/)
				* [Responder with NTLM relay and Empire - chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/execution/responder-with-ntlm-relay-and-empire.html)
			* **Hot Potato**
				* [Hot Potato](https://foxglovesecurity.com/2016/01/16/hot-potato/)
					* Hot Potato (aka: Potato) takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.
				* [Hot Potato](https://pentestlab.blog/2017/04/13/hot-potato/)
				* [SmashedPotato](https://github.com/Cn33liz/SmashedPotato)
			* **Ghost Potato**
				* [Ghost Potato - shenaniganslabs.io(2019)](https://shenaniganslabs.io/2019/11/12/Ghost-Potato.html)
					* Halloween has come and gone, and yet NTLM reflection is back from the dead to haunt MSRC once again. This post describes a deceptively simple bug that has existed in Windows for 15 years. NTLM reflection is still possible through a highly reliable timing attack. The attack works by abusing the logic responsible for its mitigation, a widely speculated challenge cache. Attackers can purge this cache by deliberately failing an authentication attempt and doing so removes all challenge entries older than 5 minutes. 
			* **Tools**
				* [Snarf](https://github.com/purpleteam/snarf)
					* Snarf man-in-the-middle / relay suite
				* [eternalrelayx.py — Non-Admin NTLM Relaying & ETERNALBLUE Exploitation - Kory Findley](https://medium.com/@technicalsyn/eternalrelayx-py-non-admin-ntlm-relaying-eternalblue-exploitation-dab9e2b97337)
					* In this post, we will cover how to perform the EternalRelay attack, an attack technique which reuses non-Admin SMB connections during an NTLM Relay attack to launch ETERNALBLUE against hosts running affected versions of the Windows operating system. This attack provides an attacker with the potential to achieve remote code execution in the privilege context of SYSTEM against vulnerable Windows hosts without the need for local Administrator privileges or credentials.
				* [Responder](https://github.com/lgandx/Responder)
					* Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
		* **Registry Paths/Permissions**
			* [Insecure Registry Permissions - NetbiosX](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
			* [RegSLScan](https://github.com/Dankirk/RegSLScan)
				* A tool for scanning registery key permissions. Find where non-admins can create symbolic links.
		* **Services**
			* [The power of backup operators - decoder.cloud](https://decoder.cloud/2018/02/12/the-power-of-backup-operatos/)
				* [Associated Code](https://github.com/decoder-it/BadBackupOperator)
			* [Unquoted Service Path - NetbiosX](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
		* **Stored Creds/Passwords on disk**
			* [Stored Credentials - NetbiosX](https://pentestlab.blog/2017/04/19/stored-credentials/)
		* **Tokens**
			* **Articles/Blogposts/Writeups**
				* [Abusing Token Privileges For LPE - drone/breenmachine](https://raw.githubusercontent.com/hatRiot/token-priv/master/abusing_token_eop_1.0.txt)
				* [Post-Exploitation with “Incognito”. - Ignacio Sorribas](http://hardsec.net/post-exploitation-with-incognito/?lang=en)
				* [The Art of Becoming TrustedInstaller](https://tyranidslair.blogspot.co.uk/2017/08/the-art-of-becoming-trustedinstaller.html)
					* There's many ways of getting the TI token other than these 3 techniques. For example as Vincent Yiu pointed out on Twitter if you've got easy access to a system token, say using Metasploit's getsystem command you can impersonate system and then open the TI token, it's just IMO less easy :-). If you get a system token with SeTcbPrivilege you can also call LogonUserExExW or LsaLogonUser where you can specify an set of additional groups to apply to a service token. Finally if you get a system token with SeCreateTokenPrivilege (say from LSASS.exe if it's not running PPL) you can craft an arbitrary token using the NtCreateToken system call.
				* [c:\whoami /priv - [show me your privileges and I will lead you to SYSTEM] - Andrea Pierini](https://github.com/decoder-it/whoami-priv-Hackinparis2019/blob/master/whoamiprivParis_Split.pdf)
				* [Windows: DCOM DCE/RPC Local NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=325&redir=1)
				* [Account Hunting for Invoke-TokenManipulation - TrustedSec](https://www.trustedsec.com/2015/01/account-hunting-invoke-tokenmanipulation/)
				* [Tokenvator: A Tool to Elevate Privilege using Windows Tokens - Alexander Polce Leary](https://blog.netspi.com/tokenvator-a-tool-to-elevate-privilege-using-windows-tokens/)
				* [Tokenvator: Release 2 - Alexander Leary](https://blog.netspi.com/tokenvator-release-2/)
				* [Abusing SeLoadDriverPrivilege for privilege escalation - TarLogic](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
				* [The power of backup operators - decoder.cloud](https://decoder.cloud/2018/02/12/the-power-of-backup-operatos/)
				* [Token Manipulation](https://pentestlab.blog/2017/04/03/token-manipulation/)
			* **Talks & Presentations**
				* [Social Engineering The Windows Kernel: Finding And Exploiting Token Handling Vulnerabilities - James Forshaw - BHUSA2015](https://www.youtube.com/watch?v=QRpfvmMbDMg)
					* [Slides](https://www.slideshare.net/Shakacon/social-engineering-the-windows-kernel-by-james-forshaw)
					* One successful technique in social engineering is pretending to be someone or something you're not and hoping the security guard who's forgotten their reading glasses doesn't look too closely at your fake ID. Of course there's no hyperopic guard in the Windows OS, but we do have an ID card, the Access Token which proves our identity to the system and let's us access secured resources. The Windows kernel provides simple capabilities to identify fake Access Tokens, but sometimes the kernel or other kernel-mode drivers are too busy to use them correctly. If a fake token isn't spotted during a privileged operation local elevation of privilege or information disclosure vulnerabilities can be the result. This could allow an attacker to break out of an application sandbox, elevate to administrator privileges, or even compromise the kernel itself. This presentation is about finding and then exploiting the incorrect handling of tokens in the Windows kernel as well as first and third party drivers. Examples of serious vulnerabilities, such as CVE-2015-0002 and CVE-2015-0062 will be presented. It will provide clear exploitable patterns so that you can do your own security reviews for these issues. Finally, I'll discuss some of the ways of exploiting these types of vulnerabilities to elevate local privileges.
			* **Tools**
				* [Tokenvator](https://github.com/0xbadjuju/Tokenvator)
					* A tool to alter privilege with Windows Tokens
				* [token_manipulation](https://github.com/G-E-N-E-S-I-S/token_manipulation)
					* Bypass User Account Control by manipulating tokens (can bypass AlwaysNotify)
			* **Potatoes**				
				* [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM - @breenmachine](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
				* [Rotten Potato Privilege Escalation from Service Accounts to SYSTEM - Stephen Breen Chris Mallz - Derbycon6](https://www.youtube.com/watch?v=8Wjs__mWOKI)
				* [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)
					* New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.
				* [The lonely potato - decoder.cloud(2017)](https://decoder.cloud/2017/12/23/the-lonely-potato/)
				* [No more rotten/juicy potato? - decoder.cloud(2018)](https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/)
					* Rotten potato inadvertently patched on Win10 1809
				* [Potatoes and tokens - decoder.cloud(2018)](https://decoder.cloud/2018/01/13/potato-and-tokens/)
				* [Juicy Potato (abusing the golden privileges) - Andrea Pierini, Giuseppe Trotta(2018)](https://decoder.cloud/2018/08/10/juicy-potato/)
					* [Github)](https://github.com/decoder-it/juicy-potato)	
		* **PentestLab Windows PrivEsc Writeup List**
			* [Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)
			* [Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
			* [Intel SYSRET](https://pentestlab.blog/2017/06/14/intel-sysret/)
			* [Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/)
		**Obtaining System Privileges**
			* [The “SYSTEM” challenge](https://decoder.cloud/2017/02/21/the-system-challenge/)
			* Writeup of achieving system from limited user privs.
			* [All roads lead to SYSTEM](https://labs.mwrinfosecurity.com/system/assets/760/original/Windows_Services_-_All_roads_lead_to_SYSTEM.pdf)
			* [Alternative methods of becoming SYSTEM - XPN](https://blog.xpnsec.com/becoming-system/)
			* [admin to SYSTEM win7 with remote.exe - carnal0wnage](http://carnal0wnage.attackresearch.com/2013/07/admin-to-system-win7-with-remoteexe.html)
			* [Getting a CMD prompt as SYSTEM in Windows Vista and Windows Server 2008 - blogs.technet](https://blogs.technet.microsoft.com/askds/2008/10/22/getting-a-cmd-prompt-as-system-in-windows-vista-and-windows-server-2008/)
			* [Another way to get to a system shell – Assistive Technology -oddvar.moe](https://oddvar.moe/2018/07/23/another-way-to-get-to-a-system-shell/)
				* `Manipulate HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\magnifier – StartExe to run other binary when pressing WinKey and plus to zoom.`
    			* `Can load binary from Webdav and also start webbrowser and browse to desired link`
    			* `Runs command as system during UAC prompt and logon screen`
	* **Talks/Videos**
		* [Hacking windows through the Windows API; delves into windows api, how it can break itself](http://www.irongeek.com/i.php?page=videos/derbycon4/t122-getting-windows-to-play-with-itself-a-pen-testers-guide-to-windows-api-abuse-brady-bloxham)
		* [Sedating the Watchdog Abusing Security Products to Bypass Windows Protections - Tomer Bit - BSidesSF](https://www.youtube.com/watch?v=7RKHux8QJfU)
		* [Black hat talk on Windows Privilege Escalation](http://www.slideshare.net/riyazwalikar/windows-privilege-escalation)
		* [Level Up! - Practical Windows Privilege Escalation](https://www.slideshare.net/jakx_/level-up-practical-windows-privilege-escalation)
		* [Extreme Privelege Escalataion on Windows8 UEFI Systems](https://www.youtube.com/watch?v=UJp_rMwdyyI)
			* [Slides](https://www.blackhat.com/docs/us-14/materials/us-14-Kallenberg-Extreme-Privilege-Escalation-On-Windows8-UEFI-Systems.pdf)
			* Summary by stormehh from reddit: “In this whitepaper (and accompanying Defcon/Blackhat presentations), the authors demonstrate vulnerabilities in the UEFI "Runtime Service" interface accessible by a privileged userland process on Windows 8. This paper steps through the exploitation process in great detail and demonstrates the ability to obtain code execution in SMM and maintain persistence by means of overwriting SPI flash”
		* [The Travelling Pentester: Diaries of the Shortest Path to Compromise](https://www.slideshare.net/harmj0y/the-travelling-pentester-diaries-of-the-shortest-path-to-compromise)
		* [Windows Privilege Escalation -  Riyaz Walikar](https://www.slideshare.net/riyazwalikar/windows-privilege-escalation)
		* [Privilege Escalation FTW - MalwareJake(WWHF2018)](https://www.youtube.com/watch?v=yXe4X-AIbps)
			* Often you don't land in a penetration test with full admin rights. How can you fix that? In most networks it's easier than you might think. In this session, Jake will discuss and demonstrate various privilege escalation techniques that are possible primarily due to misconfigurations. Practically every network has one or more misconfigurations that let you easily escalate from random Joe to total pro. We'll examine some common issues present in both Windows and Linux to you can level up for your next penetration test.
		* [Abusing privileged file operations on Windows - Clement Lavoillotte(Troopers19)](https://www.youtube.com/watch?v=xQKtdMO5FuE&list=PL1eoQr97VfJnvOWo_Jxk2qUrFyB-BJh4Y&index=6)
	* **Tools**
		* [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) 
			* [Blogpost]https://blog.gdssecurity.com/labs/2014/7/11/introducing-windows-exploit-suggester.html 
			* This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins. 
		* [PowerUp](https://n0where.net/windows-local-privilege-escalation-powerup/)
			* Windows Privilege Escalation through Powershell
		* [ElevateKit](https://github.com/rsmudge/ElevateKit)
			* The Elevate Kit demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload.
		* [BeRoot](https://github.com/AlessandroZ/BeRoot)
			* BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege. 
		* [Pompem](https://github.com/rfunix/Pompem)
			* Pompem is an open source tool, designed to automate the search for Exploits and Vulnerability in the most important databases. Developed in Python, has a system of advanced search, that help the work of pentesters and ethical hackers. In the current version, it performs searches in PacketStorm security, CXSecurity, ZeroDay, Vulners, National Vulnerability Database, WPScan Vulnerability Database
		* [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
			* As a part of ensuring that they've created a secure environment Windows administrators often need to know what kind of accesses specific users or groups have to resources including files, directories, Registry keys, global objects and Windows services. AccessChk quickly answers these questions with an intuitive interface and output.
		* [AutoDane at BSides Cape Town](https://sensepost.com/blog/2015/autodane-at-bsides-cape-town/)
		* [Auto DANE](https://github.com/sensepost/autoDANE)
			* Auto DANE attempts to automate the process of exploiting, pivoting and escalating privileges on windows domains.
		* [lonelypotato](https://github.com/decoder-it/lonelypotato)
			* Modified version of RottenPotatoNG C++ 
			* [Blogpost](https://decoder.cloud/2017/12/23/the-lonely-potato/)
		* [psgetsystem](https://github.com/decoder-it/psgetsystem)
			* getsystem via parent process using ps1 & embeded c#
		* [Sherlock](https://github.com/rasta-mouse/Sherlock)
			* PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.
		* [Robber](https://github.com/MojtabaTajik/Robber)
			* Robber is open source tool for finding executables prone to DLL hijacking 
    	* [WinPrivCheck.bat](https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
		* [JAWS - Just Another Windows (Enum) Script](https://github.com/411Hall/JAWS)
			* JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7.
		* [Windows Exploit Suggester - Next Generation (WES-NG)](https://github.com/bitsadmin/wesng)
			* WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported.
		* [Powerless](https://github.com/M4ximuss/Powerless)
			* "A Windows privilege escalation (enumeration) script designed with OSCP labs (i.e. legacy Windows machines without Powershell) in mind. The script represents a conglomeration of various privilege escalation checks, gathered from various sources, all done via native Windows binaries present in almost every version of Windows." - It's a batch file
	* **Writeups**
		* **To-be-sorted**
			* [Analyzing local privilege escalations in win32k](http://uninformed.org/?v=all&a=45&t=sumry)
				* This paper analyzes three vulnerabilities that were found in win32k.sys that allow kernel-mode code execution. The win32k.sys driver is a major component of the GUI subsystem in the Windows operating system. These vulnerabilities have been reported by the author and patched in MS08-025. The first vulnerability is a kernel pool overflow with an old communication mechanism called the Dynamic Data Exchange (DDE) protocol. The second vulnerability involves improper use of the ProbeForWrite function within string management functions. The third vulnerability concerns how win32k handles system menu functions. Their discovery and exploitation are covered. 
			* [Windows-Privilege-Escalation - frizb](https://github.com/frizb/Windows-Privilege-Escalation)
				* Windows Privilege Escalation Techniques and Scripts
			* [Some forum posts on Win Priv Esc](https://forums.hak5.org/index.php?/topic/26709-windows-7-now-secure/)
			* [Post Exploitation Using netNTLM Downgrade attacks - Fishnet/Archive.org](https://web.archive.org/web/20131023064257/http://www.fishnetsecurity.com/6labs/blog/post-exploitation-using-netntlm-downgrade-attacks)
			* [Old Privilege Escalation Techniques](https://web.archive.org/web/20150712205115/http://obscuresecurity.blogspot.com/2011/11/old-privilege-escalation-techniques.html)
			* [Windows 7 ‘Startup Repair’ Authentication Bypass](https://hackingandsecurity.blogspot.nl/2016/03/windows-7-startup-repair-authentication.html)
			* [Windows Privilege Escalation Guide - sploitspren(2018)](https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
				* Nice methodology/walk through of Windows PrivEsc methods and tactics
			* [Windows Privilege Escalation Methods for Pentesters - pentest.blog](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
			* [Linux Vulnerabilities Windows Exploits: Escalating Privileges with WSL - BlueHat IL 2018 - Saar Amar](http://www.bluehatil.com/files/Linux%20Vulnerabilities%2C%20Windows%20Exploits%20-%20Escalating%20Privileges%20with%20WSL.PDF)
				* [Slides](http://www.bluehatil.com/files/Linux%20Vulnerabilities%2C%20Windows%20Exploits%20-%20Escalating%20Privileges%20with%20WSL.PDF)
			* [CVE-2018-0952: Privilege Escalation Vulnerability in Windows Standard Collector Service - Ryan Hanson](https://www.atredis.com/blog/cve-2018-0952-privilege-escalation-vulnerability-in-windows-standard-collector-service)
			* [Windows 10 Privilege Escalation using Fodhelper - hackercool](https://web.archive.org/web/20180903225606/https://hackercool.com/2017/08/windows-10-privilege-escalation-using-fodhelper/)
			* [Local privilege escalation via the Windows I/O Manager: a variant finding collaboration - swiat](https://msrc-blog.microsoft.com/2019/03/14/local-privilege-escalation-via-the-windows-i-o-manager-a-variant-finding-collaboration/)
			* [Abusing SeLoadDriverPrivilege for privilege escalation - Oscar Mallo](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
			* [Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege - James Forshaw](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html)
			* [Give Me Back My Privileges! Please? - itm4n](https://itm4n.github.io/localservice-privileges/)
				* I want to tell you the story of a service account which lost all its powers (a.k.a. privileges). Windows world is getting increasingly ruthless and when the system considers you are not worthy, this is what happens. Fortunately for our service account, all is not lost, there’s still hope. In this merciless world, you can always turn to the old sages to find some comfort and support. Among them, the Task Scheduler might be willing to help and restore what was lost, provided that you ask kindly…
			* [CVE-2020-0668 - A Trivial Privilege Escalation Bug in Windows Service Tracing - itm4n](https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/)
				* "In this post, I’ll discuss an arbitrary file move vulnerability I found in Windows Service Tracing. From my testing, it affected all versions of Windows from Vista to 10 but it’s probably even older because this feature was already present in XP."
			* [Issue 1554: Windows: Desktop Bridge Virtual Registry CVE-2018-0880 Incomplete Fix EoP - Project0](https://bugs.chromium.org/p/project-zero/issues/detail?id=1554)
			* [Waves Maxx Audio DLL Side-Loading LPE via Windows Registry - Robert Hawes](https://versprite.com/blog/security-research/windows-registry/)
		* **ALPC**
			* [Original](https://github.com/SandboxEscaper/randomrepo)
			* [zeroday-powershell](https://github.com/OneLogicalMyth/zeroday-powershell)
				* A PowerShell example of the Windows zero day priv esc
		* **Anti-Virus Software**
			* [#AVGater: Getting Local Admin by Abusing the Anti-Virus Quarantine](https://bogner.sh/2017/11/avgater-getting-local-admin-by-abusing-the-anti-virus-quarantine/)
			* [CVE-2018-8955: Bitdefender GravityZone Arbitrary Code Execution - Kyriakos Economou](https://labs.nettitude.com/blog/cve-2018-8955-bitdefender-gravityzone-arbitrary-code-execution/)

			* [COModo: From Sandbox to SYSTEM (CVE-2019–3969) - David Wells](https://medium.com/tenable-techblog/comodo-from-sandbox-to-system-cve-2019-3969-b6a34cc85e67)
			* [Reading Physical Memory using Carbon Black's Endpoint driver - Bill Demirkapi](https://d4stiny.github.io/Reading-Physical-Memory-using-Carbon-Black/)
			* [SEPM-EoP](https://github.com/DimopoulosElias/SEPM-EoP)
			* [Exploiting STOPzilla AntiMalware Arbitrary Write Vulnerability using SeCreateTokenPrivilege - Parvez](http://www.greyhathacker.net/?p=1025)
			* [Analysis and Exploitation of an ESET Vulnerability - Tavid Ormandy(2015)](https://googleprojectzero.blogspot.com/2015/06/analysis-and-exploitation-of-eset.html)
			* [Compromised by Endpoint Protection - codewhitesec.blogspot](https://codewhitesec.blogspot.com/2015/07/symantec-endpoint-protection.html)
			    * Symantec Endpoint Protection vulns
		    * [Escalating Privileges with CylancePROTECT - Ryan Hanson](https://www.atredis.com/blog/cylance-privilege-escalation-vulnerability)
			* [Avira Optimizer Local Privilege Escalation - Enigma0x3](https://enigma0x3.net/2019/08/29/avira-optimizer-local-privilege-escalation/)
		* **Other**
			* [One more Steam Windows Client Local Privilege Escalation 0day - Vasily Kravets](https://amonitoring.ru/article/onemore_steam_eop_0day/)
			* [Local Privilege Escalation on Dell machines running Windows - Bill Demirkapi](https://d4stiny.github.io/Local-Privilege-Escalation-on-most-Dell-computers/)
				* This blog post will cover my research into a Local Privilege Escalation vulnerability in Dell SupportAssist. Dell SupportAssist is advertised to “proactively check the health of your system’s hardware and software”. Unfortunately, Dell SupportAsssist comes pre-installed on most of all new Dell machines running Windows. If you’re on Windows, never heard of this software, and have a Dell machine - chances are you have it installed.
			* [CVE-2019-9730: LPE in Synaptics Sound Device Driver - @Jackon_T](http://jackson-t.ca/synaptics-cxutilsvc-lpe.html)
				* CVE details for a COM-based local privilege elevation with a brief write-up on discovery to root.
			* [Technical Advisory: Intel Driver Support & Assistance – Local Privilege Escalation - NCCGroup](https://www.nccgroup.trust/uk/our-research/technical-advisory-intel-driver-support-and-assistance-local-privilege-escalation/)
			* [Elastic Boundaries – Elevating Privileges by Environment Variables Expansion - Yoam Gottesman](https://blog.ensilo.com/elastic-boundaries-elevating-privileges-by-environment-variables-expansion)
	* **Exploits**
		* [CVE-2017-8759](https://github.com/bhdresh/CVE-2017-8759)
			* Exploit toolkit CVE-2017-8759 - v1.0 is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft .NET Framework RCE. It could generate a malicious RTF file and deliver metasploit / meterpreter / other payload to victim without any complex configuration.
		* [Win10-LPE](https://github.com/3ndG4me/Win10-LPE)
			* The Windows 10 LPE exploit written by SandboxEscaper. This includes the source code for the original exploit, a precompiled DLL injector binary included with the original source, and a powershell script to find potentially vulnerable libraries to overwrite for the exploit.
		* [Component Services Volatile Environment LPE - bytecode77](https://github.com/bytecode77/component-services-privilege-escalation)
		* [CVE-2018-0952-SystemCollector](https://github.com/atredispartners/CVE-2018-0952-SystemCollector)
			* PoC for Privilege Escalation in Windows 10 Diagnostics Hub Standard Collector Service
		* [CVE-2018-8420](https://github.com/idkwim/CVE-2018-8420)
		* [CVE-2018-8440 - PowerShell PoC](https://github.com/OneLogicalMyth/zeroday-powershell)
		* [Remote Code Execution — Gaining Domain Admin due to a typo: CVE-2018-9022 - Daniel C](https://medium.com/@DanielC7/remote-code-execution-gaining-domain-admin-privileges-due-to-a-typo-dbf8773df767)
			* A short time ago as part of a red team engagement I found and successfully exploited a remote code execution vulnerability that resulted in us quickly gaining high privilege access to the customers internal network. So far nothing sounds too out of the ordinary, however interestingly the root cause of this vulnerability was due to a two character typo.		
		* [Another Local Privilege Escalation Vulnerability Using Process Creation Impersonation - Wayne Chin Yick Low](https://www.fortinet.com/blog/threat-research/another-local-privilege-escalation-lpe-vulnerability.html)
		* [XIGNCODE3 xhunter1.sys LPE - x86.re](https://x86.re/blog/xigncode3-xhunter1.sys-lpe/)
		* [Display Languages Volatile Environment LPE - bytecode77](https://github.com/bytecode77/display-languages-privilege-escalation)
		* [Performance Monitor Volatile Environment LPE](https://github.com/bytecode77/performance-monitor-privilege-escalation)
		* [Enter Product Key Volatile Environment LPE](https://github.com/bytecode77/enter-product-key-privilege-escalation)
		* [Sysprep Volatile Environment LPE(2017)](https://github.com/bytecode77/sysprep-privilege-escalation)
		* [Remote Assistance Volatile Environment LPE](https://github.com/bytecode77/remote-assistance-privilege-escalation)
		* [Display Languages Volatile Environment LPE](https://github.com/bytecode77/display-languages-privilege-escalation)
		* [CVE-2017-12478 - Unitrends 9.x api_storage exploit](http://blog.redactedsec.net/exploits/2018/01/29/UEB9.html)
		* [CVE-2020-0668](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668)
			* Use CVE-2020-0668 to perform an arbitrary privileged file move operation.
		* [CVE-2019-8372: Local Privilege Elevation in LG Kernel Driver - Jackson_T](http://jackson-t.ca/lg-driver-lpe.html)
			* TL;DR: CVE for driver-based LPE with an in-depth tutorial on discovery to root and details on two new tools.
		* [CVE-2020-0787 - Windows BITS - An EoP Bug Hidden in an Undocumented RPC Function - itm4n](https://itm4n.github.io/cve-2020-0787-windows-bits-eop/)
			* This post is about an arbitrary file move vulnerability I found in the Background Intelligent Transfer Service. This is yet another example of a privileged file operation abuse in Windows 10. There is nothing really new but the bug itself is quite interesting because it was hidden in an undocumented function. Therefore, I will explain how I found it and I will also share some insights about the reverse engineering process I went through in order to identify the logic flaw.
	* **Just-Enough-Administration(JEA)**
		* [Get $pwnd: Attacking Battle Hardened Windows Server - Lee Holmes - Defcon25](https://www.youtube.com/watch?v=ahxMOAAani8)
        	* Windows Server has introduced major advances in remote management hardening in recent years through PowerShell Just Enough Administration ("JEA"). When set up correctly, hardened JEA endpoints can provide a formidable barrier for attackers: whitelisted commands, with no administrative access to the underlying operating system. In this presentation, watch as we show how to systematically destroy these hardened endpoints by exploiting insecure coding practices and administrative complexity. 
	* **Microsoft**
		* [From Hyper-V Admin to SYSTEM - decoder.cloud](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/)
		* [Windows Credential Theft: RDP & Internet Explorer 11](https://vdalabs.com/2019/09/25/windows-credential-theft-rdp-internet-explorer-11/)
			* NTLM Hashes/relay through RDP files/IE11 XXE explained
    * **MSSQL**
		* [PowerUpSQL - 2018 Blackhat USA Arsenal](https://www.youtube.com/watch?reload=9&v=UX_tBJQtqW0&feature=youtu.be)
        	* This is the presentation we provided at the 2018 Blackhat USA Arsenal to introduce PowerUpSQL. PowerUpSQL includes functions that support SQL Server discovery, weak configuration auditing, privilege escalation on scale, and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server. This should be interesting to red, blue, and purple teams interested in automating day to day tasks involving SQL Server.
	* **VirtualMachines**
		* [InviZzzible](https://github.com/CheckPointSW/InviZzzible)
			* InviZzzible is a tool for assessment of your virtual environments in an easy and reliable way. It contains the most recent and up to date detection and evasion techniques as well as fixes for them. Also, you can add and expand existing techniques yourself even without modifying the source code.
	* **VMWare**
		* [VMware Escape Exploit](https://github.com/unamer/vmware_escape)
			* VMware Escape Exploit before VMware WorkStation 12.5.5	
		* [A bunch of Red Pills: VMware Escapes - Marco Grassi, Azureyang, Jackyxty](https://keenlab.tencent.com/en/2018/04/23/A-bunch-of-Red-Pills-VMware-Escapes/)
		* [VMware Exploitation](https://github.com/xairy/vmware-exploitation)
			* A bunch of links related to VMware escape exploits
* **Defense Evasion**<a name="windefev"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
	* **AMSI**<a name="amsi"></a>
		* **101**
			* [AMSI Bypass - Paul Laine](https://www.contextis.com/en/blog/amsi-bypass)
			* [Exploring PowerShell AMSI and Logging Evasion - Adam Chester](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
			* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - Blogpost](http://www.labofapenetrationtester.com/2016/09/amsi.html)
			* [AMSI: How Windows 10 Plans to Stop Script-Based Attaacks and How Well It Does It - BH US16](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
		* **AMSI Internals**
			* [The Rise and Fall of AMSI - Tal Liberman(BHAsia 2018)](https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf)
			* [IAmsiStream interface sample - MS Github](https://github.com/Microsoft/Windows-classic-samples/tree/master/Samples/AmsiStream)
				* Demonstrates how to use the Antimalware Scan Interface to scan a stream.
			* [Antimalware Scan Interface (AMSI) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
			* [Developer audience, and sample code - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/dev-audience)
			* [Antimalware Scan Interface (AMSI) functions - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-functions)
			* [MS Office file format sorcery - Stan Hegt, Pieter Ceelen(Troopers19)](https://www.youtube.com/watch?v=iXvvQ5XML7g)
				* [Slides](https://github.com/outflanknl/Presentations/raw/master/Troopers19_MS_Office_file_format_sorcery.pdf)
				* A deep dive into file formats used in MS Office and how we can leverage these for offensive purposes. We will show how to fully weaponize ‘p-code’ across all MS Office versions in order to create malicious documents without using VBA code, successfully bypassing antivirus and other defensive measures. In this talk Stan and Pieter will do a deep dive into the file formats used in MS Office, demonstrating many features that can be used offensively. They will present attacks that apply to both the legacy formats (OLE streams) and the newer XML based documents. Specific focus is around the internal representation of VBA macros and pseudo code (p-code, execodes) and how these can be weaponized. We will detail the inner logic of Word and Excel regarding VBA and p-code, and release scripts and tools for creating malicious Office documents that bypass anti-virus, YARA rules, AMSI for VBA and various MS Office document analyzers.
		* **Bypass Blogposts**
			* [Antimalware Scan Interface (AMSI) — A Red Team Analysis on Evasion - iwantmore.pizza](https://iwantmore.pizza/posts/amsi.html)
			* [How Red Teams Bypass AMSI and WLDP for .NET Dynamic Code - modexp](https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/)
			* [Bypassing Amsi using PowerShell 5 DLL Hijacking - cn33liz](https://cn33liz.blogspot.com/2016/05/bypassing-amsi-using-powershell-5-dll.html)
			* [Alternative AMSI bypass - Benoit Sevens](https://medium.com/@benoit.sevens/alternative-amsi-bypass-554dc61d70b1)
			* [AMSI Bypass With a Null Character - satoshi's note](http://standa-note.blogspot.com/2018/02/amsi-bypass-with-null-character.html)
			* [Disabling AMSI in JScript with One Simple Trick - James Forshaw](https://tyranidslair.blogspot.com/2018/06/disabling-amsi-in-jscript-with-one.html)
			* [AMSI Bypass: Patching Technique - Avi Gimpel & Zeev Ben Porat](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/)
			* [AMSI Bypass Redux - Avi Gimpel](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/)
			* [Bypassing AMSI via COM Server Hijacking - Enigma0x3](https://enigma0x3.net/2017/07/19/bypassing-amsi-via-com-server-hijacking/)
				*  This post will highlight a way to bypass AMSI by hijacking the AMSI COM server, analyze how Microsoft fixed it in build #16232 and then how to bypass that fix. This issue was reported to Microsoft on May 3rd, and has been fixed as a Defense in Depth patch in build #16232.
			* [Sneaking Past Device Guard - Philip Tsukerman](https://conference.hitb.org/hitbsecconf2019ams/materials/D2T1%20-%20Sneaking%20Past%20Device%20Guard%20-%20Philip%20Tsukerman.pdf)
			* [Red Team TTPs Part 1: AMSI Evasion - 0xDarkVortex.dev](https://0xdarkvortex.dev/index.php/2019/07/17/red-team-ttps-part-1-amsi-evasion/)
			* RastaMouse AmsiScanBuffer Bypass Series
				* [Part 1](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/)
				* [Part 2](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-2/)
				* [Part 3](https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/)
				* [Part 4](https://rastamouse.me/2018/12/amsiscanbuffer-bypass-part-4/)
			* [How to bypass AMSI and execute ANY malicious Powershell code - zc00l](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
			* [Weaponizing AMSI bypass with PowerShell - @0xB455](http://ha.cker.info/weaponizing-amsi-bypass-with-powershell/)
			* [How to Bypass AMSI with an Unconventional Powershell Cradle - Mohammed Danish](https://medium.com/@gamer.skullie/bypassing-amsi-with-an-unconventional-powershell-cradle-6bd15a17d8b9)
			* [Bypassing AMSI via COM Server Hijacking - Matt Nelson](https://posts.specterops.io/bypassing-amsi-via-com-server-hijacking-b8a3354d1aff)
			* fixed as a Defense in Depth patch in build #16232.
			* [Adventures in the Wonderful World of AMSI. - byte_st0rm](https://medium.com/@byte_St0rm/adventures-in-the-wonderful-world-of-amsi-25d235eb749c)
			* [How to bypass AMSI and execute ANY malicious Powershell code - zc00l](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
			* [Understanding and Bypassing AMSI - Tom Carver(2020)](https://x64sec.sh/understanding-and-bypassing-amsi/)
		* **Bypass Talks**
			* [Antimalware Scan Interface (AMSI) - Dave Kennedy(WWHF2018)](https://www.youtube.com/watch?v=wBK1fTg6xuU)
				* This talk will dive into the Antimalware Scan Interface (AMSI) as well as other alternatives in the “NextGen” series of preventative measures and show how trivial it is to write code that doesn’t get snagged.  The security market is focusing on open source data collection sources and security researchers as the main method to write signatures to detect attacks, much like what we saw in the 90s with traditional anti-virus tech. Not much has changed, let’s dive into the reality in security and how little these protective measures really do in the grand scheme of things. We’ll also be covering solid practices in defending against attacks, and what we should be focusing on.
			* [PSAmsi An offensive PowerShell module for interacting with the Anti Malware Scan Interface in Windows - Ryan Cobb(Derbycon7)](https://www.youtube.com/watch?v=rEFyalXfQWk)
			* [The Rise and Fall of AMSI - Tal Liberman(BH Asia18)]https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf)
			* [Red Team TTPs Part 1: AMSI Evasion - paranoidninja](https://0xdarkvortex.dev/index.php/2019/07/17/red-team-ttps-part-1-amsi-evasion/)
			* [AMSI: How Windows 10 Plans To Stop Script Based Attacks And How Well It Does It - Nikhil Mittal(BHUSA16)](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
			* [Goodbye Obfuscation, Hello Invisi-Shell: Hiding Your Powershell Script in Plain Sight - Omer Yair(Derbycon2018)](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-15-goodbye-obfuscation-hello-invisi-shell-hiding-your-powershell-script-in-plain-sight-omer-yair)
				* “The very concept of objective truth is fading out of the world. Lies will pass into history.” George Orwell. Objective truth is essential for security. Logs, notifications and saved data must reflect the actual events for security tools, forensic teams and IT managers to perform their job correctly. Powershell is a prime example of the constant cat and mouse game hackers and security personnel play every day to either reveal or hide the “objective truth” of a running script. Powershell’s auto logging, obfuscation techniques, AMSI and more are all participants of the same game playing by the same rules. We don’t like rules, so we broke them. As a result, Babel-Shellfish and Invisi-Shelltwo new tools that both expose and disguise powershell scripts were born. Babel-Shellfish reveals the inner hidden code of any obfuscated script while Invisi-Shell offers a new method of hiding malicious scripts, even from the Powershell process running it. Join us as we present a new way to think about scripts.
		* **Bypass Tools**
			* [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)
			* [AmsiScanBufferBypass](https://github.com/rasta-mouse/AmsiScanBufferBypass)
				* Circumvent AMSI by patching AmsiScanBuffer
			* [CorruptCLRGlobal.ps1](https://gist.github.com/mattifestation/ef0132ba4ae3cc136914da32a88106b9)
				* A PoC function to corrupt the g_amsiContext global variable in clr.dll in .NET Framework Early Access build 3694 Raw
			* [AMSI Bypass Code Snippet Examples](https://github.com/SecureThisShit/Amsi-Bypass-Powershell#Using-Cornelis-de-Plaas-DLL-hijack-method)
				* "This repo contains some Amsi Bypass methods i found on different Blog Posts."
			* [PSAmsi](https://github.com/cobbr/PSAmsi)
				* PSAmsi is a tool for auditing and defeating AMSI signatures. It's best utilized in a test environment to quickly create payloads you know will not be detected by a particular AntiMalware Provider, although it can be useful in certain situations outside of a test environment. When using outside of a test environment, be sure to understand how PSAmsi works, as it can generate AMSI alerts.
			* [powershellveryless](https://github.com/decoder-it/powershellveryless)
				* Constrained Language Mode + AMSI bypass all in one
			* [AmsiBypass](https://github.com/0xb455/AmsiBypass/)
				* C# PoC implementation for bypassing AMSI via in memory patching
			* [NoAmci](https://github.com/med0x2e/NoAmci)
				* A PoC for using DInvoke to patch AMSI.dll in order to bypass AMSI detections triggered when loading .NET tradecraft via Assembly.Load(). .Net tradecraft can be compressed, encoded (encrypted if required) in order to keep the assembly size less than 1MB, then embedded as a resource to be loaded after patching amsi.dll memory.
		* **VBA Specific**
			* **101**	
				* [Office VBA + AMSI: Parting the veil on malicious macros - MS Security Team](https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/)
			* **Blogposts**
				* [Dynamic Microsoft Office 365 AMSI In Memory Bypass Using VBA - Richard Davy, Gary Nield](https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/)
				* [The Document that Eluded AppLocker and AMSI - ZLAB-YOROI](https://blog.yoroi.company/research/the-document-that-eluded-applocker-and-amsi/)
				* [Office 365 AMSI Bypass (fixed) - Ring0x00](https://idafchev.github.io/research/2019/03/23/office365_amsi_bypass.html)
			* **Talks & Presentations**
				* [Bypassing AMSI for VBA - Pieter Ceelen](https://outflank.nl/blog/2019/04/17/bypassing-amsi-for-vba/)
					* This blog is a writeup of the various AMSI weaknesses presented at [the Troopers talk ‘MS Office File Format Sorcery‘](https://github.com/outflanknl/Presentations/raw/master/Troopers19_MS_Office_file_format_sorcery.pdf) and [the Blackhat Asia presentation ‘Office in Wonderland’](https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Hegt-MS-Office-in-Wonderland.pdf).
	* **Application Whitelisting**<a name="appwhitelist"></a>
		* **101**
			* [Whitelist Evasion revisited](https://khr0x40sh.wordpress.com/2015/05/27/whitelist-evasion-revisited/)
			* [Shackles, Shims, and Shivs - Understanding Bypass Techniques](http://www.irongeek.com/i.php?page=videos/derbycon6/535-shackles-shims-and-shivs-understanding-bypass-techniques-mirovengi)
			* [$@|sh – Or: Getting a shell environment from Runtime.exec](https://codewhitesec.blogspot.ro/2015/03/sh-or-getting-shell-environment-from.html)
			* [WSH Injection: A Case Study - enigma0x3](https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/)
		* **Articles/Blogposts/Writeups**
			* [Escaping the Microsoft Office Sandbox: a faulty regex, allows malicious code to escape and persist - Adam Chester](https://objective-see.com/blog/blog_0x35.html)
			* [Microsoft Applications and Blocklist - FortyNorthSecurity](https://www.fortynorthsecurity.com/how-to-bypass-wdac-with-dbgsrv-exe/)
			* [Technical Advisory: Bypassing Workflows Protection Mechanisms - Remote Code Execution on SharePoint - Soroush Dalilil](https://www.nccgroup.trust/uk/our-research/technical-advisory-bypassing-workflows-protection-mechanisms-remote-code-execution-on-sharepoint/)
			* [Bypassing Application Whitelisting with BGInfo - Oddvar Moe](https://msitpros.com/?p=3831)
			* [Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner - exploit-monday.com](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)
			* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files)](https://web.archive.org/web/20160424110035/http://subt0x10.blogspot.com:80/2016/04/bypass-application-whitelisting-script.html)
			* [How to Evade Application Whitelisting Using REGSVR32 - Joff Thyer](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)
			* [Bypassing Application Whitelisting with runscripthelper.exe - Matt Graeber](https://posts.specterops.io/bypassing-application-whitelisting-with-runscripthelper-exe-1906923658fc)
			* [Using Application Compatibility Shims - subTee](https://web.archive.org/web/20170815050734/http://subt0x10.blogspot.com/2017/05/using-application-compatibility-shims.html)
			* [Consider Application Whitelisting with Device Guard - subTee](https://web.archive.org/web/20170517232357/http://subt0x10.blogspot.com:80/2017/04/consider-application-whitelisting-with.html)
			* [Bypassing Application Whitelisting using MSBuild.exe - Device Guard Example and Mitigations - subTee](https://web.archive.org/web/20170714075746/http://subt0x10.blogspot.com:80/2017/04/bypassing-application-whitelisting.html)
			* [Setting Up A Homestead In the Enterprise with JavaScript - subTee](https://web.archive.org/web/20160908140124/https://subt0x10.blogspot.in/2016/04/setting-up-homestead-in-enterprise-with.html)
			* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files)](http://subt0x10.blogspot.sg/2017/04/bypass-application-whitelisting-script.html)
			* [Application Whitelist Bypass Techniques](https://web.archive.org/web/20170430065331/https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)
				* A Catalog of Application Whitelisting Bypass Techniques - SubTee
			* [Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)
			* [BinariesThatDoesOtherStuff.txt - api0cradle](https://gist.github.com/api0cradle/8cdc53e2a80de079709d28a2d96458c2)
			* [VBA RunPE - Breaking Out of Highly Constrained Desktop Environments - Part 1/2 - itm4n](https://itm4n.github.io/vba-runpe-part1/)
				* [Part 2](https://itm4n.github.io/vba-runpe-part2/)	
		* **Talks & Presentations**
			* [Fantastic Red-Team Attacks and How to Find Them - Casey Smith, Ross Wolf(BHUSA 2019)](https://www.blackhat.com/us-19/briefings/schedule/index.html#fantastic-red-team-attacks-and-how-to-find-them-16540)
				* This talk summarizes prevalent and ongoing gaps across organizations uncovered by testing their defenses against a broad spectrum of attacks via Atomic Red Team. Many of these adversary behaviors are not atomic, but span multiple events in an event stream that may be arbitrarily and inconsistently separated in time by nuisance events.
				* [Slides](https://i.blackhat.com/USA-19/Thursday/us-19-Smith-Fantastic-Red-Team-Attacks-And-How-To-Find-Them.pdf)
		* **Talks**
			* [Modern Evasion Techniques Jason Lang - Derbycon7](https://www.youtube.com/watch?v=xcA2riLyHtQ&index=6&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
			* [Whitelisting Evasion - subTee - Shmoocon 2015](https://www.youtube.com/watch?v=85M1Rw6mh4U)
		* **Tools**
			* [MS Signed mimikatz in just 3 steps](https://github.com/secretsquirrel/SigThief)
			* [GreatSCT](https://github.com/GreatSCT/GreatSCT)
				* The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
			* [RunMe.c](https://gist.github.com/hugsy/e5c4ce99cd7821744f95)
				* Trick to run arbitrary command when code execution policy is enforced (i.e. AppLocker or equivalent). Works on Win98 (lol) and up - tested on 7/8
			* [Window Signed Binary](https://github.com/vysec/Windows-SignedBinary)
			* [VBA-RunPE](https://github.com/itm4n/VBA-RunPE)
				* A VBA implementation of the RunPE technique or how to bypass application whitelisting.
		* **Applocker**
			* **101**
				* [Ultimate AppLocker ByPass List](https://github.com/api0cradle/UltimateAppLockerByPassList)
					* "The goal of this repository is to document the most common and known techniques to bypass AppLocker. Since AppLocker can be configured in different ways I maintain a verified list of bypasses (that works against the default AppLocker rules) and a list with possible bypass technique (depending on configuration) or claimed to be a bypass by someone. I also have a list of generic bypass techniques as well as a legacy list of methods to execute through DLLs."
			* **Articles/Blogposts/Writeups**
				* [AppLocker Bypass Checklist - netbiosX](https://github.com/netbiosX/Checklists/blob/master/AppLocker.md)
				* [AppLocker Case study: How insecure is it really? Part 1 oddvar.moe](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-1/)
				* AppLocker Case study: How insecure is it really? Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
				* [AppLocker Bypass – Weak Path Rules](https://pentestlab.blog/2017/05/22/applocker-bypass-weak-path-rules/)
				* [Applocker Bypass via Registry Key Manipulation](https://www.contextis.com/resources/blog/applocker-bypass-registry-key-manipulation/)
				* [Bypassing AppLocker Custom Rules - 0x09AL Security Blog](https://0x09al.github.io/security/applocker/bypass/custom/rules/windows/2018/09/13/applocker-custom-rules-bypass.html)
				* [AppLocker Bypass – CMSTP - netbiosX](https://pentestlab.blog/2018/05/10/applocker-bypass-cmstp/)
				* [Bypassing AppLocker Custom Rules](https://0x09al.github.io/security/applocker/bypass/custom/rules/windows/2018/09/13/applocker-custom-rules-bypass.html)
				* [A small discovery about AppLocker - oddvar.moe](https://oddvar.moe/2019/05/29/a-small-discovery-about-applocker/)
					* 'While I was prepping for a session a while back I made a a little special discovery about AppLocker. Turns out that the files that AppLocker uses under C:\Windows\System32\AppLocker can be used in many cases to bypass a Default AppLocker ruleset.'
				* [Applocker Bypass via Registry Key Manipulation - Francesco Mifsud](https://www.contextis.com/en/blog/applocker-bypass-via-registry-key-manipulation)
				* [Bypassing AppLocker Custom Rules - 0x09AL](https://0x09al.github.io/security/applocker/bypass/custom/rules/windows/2018/09/13/applocker-custom-rules-bypass.html)
				* [myAPPLockerBypassSummary](https://github.com/0xVIC/myAPPLockerBypassSummary)
					* Simple APPLocker bypass summary based on the extensive work of @api0cradle
			* **Tools**
				* [Backdoor-Minimalist.sct](https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302)
					* Applocker bypass
	* **Defender**<a name="defender"></a>
		* **Articles/Blogposts/Writeups**
 			* [Untangling the “Windows Defender” Naming Mess - Lenny Zeltser](https://blog.minerva-labs.com/untangling-the-windows-defender-naming-mess)
 			* [Bypass Windows Defender Attack Surface Reduction - Emeric Nasi](https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf)
			* [Documenting and Attacking a Windows Defender Application Control Feature the Hard Way — A Case Study in Security Research Methodology - Matt Graeber](https://posts.specterops.io/documenting-and-attacking-a-windows-defender-application-control-feature-the-hard-way-a-case-73dd1e11be3a)
			* [Bypassing AV (Windows Defender) … the tedious way. - CB Hue](https://www.cyberguider.com/bypassing-windows-defender-the-tedious-way/)
			* [Dear Windows Defender, please tell me where I can drop my malicious code. - Simone Aonzo](https://medium.com/@simone.aonzo/dear-windows-defender-please-tell-me-where-i-can-drop-my-malicious-code-9c4f50f417a1)
				* 'The Get-MpPreference cmdlet exposes the field ExclusionPath without administrator privilege.'
			* [Hiding Metasploit Shellcode to Evade Windows Defender - Rapid7](https://blog.rapid7.com/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/)
		* **Talks/Presentations/Videos**
			* [Reverse Engineering Windows Defender’s JavaScript Engine - Alexei Bulazel(REcon Brussels18)](https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Reverse-Engineering-Windows-Defender-s-JavaScript-Engine.pdf)
				* [Defcon Videos](https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/Alexei%20Bulazel/Alexei-Bulazel-Reverse-Engineering-Windows-Defender-Demo-Videos/)
				* [Blackhat2018 Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf)
				* [Tools](https://github.com/0xAlexei/WindowsDefenderTools)
		* **Tools**
	 		* [Windows Defender Emulator Tools](https://github.com/0xAlexei/WindowsDefenderTools)
				* Tools for instrumenting Windows Defender's mpengine.dll
				* [Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf)
				* [Video](https://www.youtube.com/watch?v=xbu0ARqmZDc)
			* [ExpandDefenderSig.ps1](https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866)
				* Decompresses Windows Defender AV signatures for exploration purposes
	* **Microsoft ATA & ATP**<a name="msatap"></a>
			* [Red Team Techniques for Evading, Bypassing, and Disabling MS Advanced Threat Protection and Advanced Threat Analytics](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
			* [Red Team Revenge - Attacking Microsoft ATA](https://www.slideshare.net/nikhil_mittal/red-team-revenge-attacking-microsoft-ata)
			* [Evading Microsoft ATA for Active Directory Domination](https://www.slideshare.net/nikhil_mittal/evading-microsoft-ata-for-active-directory-domination)
			* [Week of Evading Microsoft ATA - Announcement and Day 1 - Nikhil Mittal(Aug 2017)](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day1.html)
			* [Week of Evading Microsoft ATA - Day 2 - Overpass-the-hash and Golden Ticket - Nikhil Mittal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day2.html)
			* [Week of Evading Microsoft ATA - Day 3 - Constrained Delegation, Attacks across trusts, DCSync and DNSAdmins - Nikhil Mittal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day3.html)
			* [Week of Evading Microsoft ATA - Day 4 - Silver ticket, Kerberoast and SQL Servers - Nikhil Mittal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day4.html)
			* [Week of Evading Microsoft ATA - Day 5 - Attacking ATA, Closing thoughts and Microsoft's response - Nikhil MIttal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day5.html)
			* [Evading Microsoft ATA for Active Directory Domination - Nikhil Mittal(BH USA17)](https://www.youtube.com/watch?v=bHkv63-1GBY)
				* [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Mittal-Evading-MicrosoftATA-for-ActiveDirectory-Domination.pdf)
				* [BruCON 0x09 Talk](https://www.youtube.com/watch?v=5gu4r-IDDwU)
			* [Microsoft Advanced Threat Analytics – My best practices - Oddvar Moe](https://msitpros.com/?p=3509)
			* [Evading WinDefender ATP credential-theft: kernel version - B4rtik](https://b4rtik.github.io/posts/evading-windefender-atp-credential-theft-kernel-version/)
		* **Tools**
			* [DefenderCheck](https://github.com/matterpreter/DefenderCheck)
				* Takes a binary as input and splits it until it pinpoints that exact byte that Microsoft Defender will flag on, and then prints those offending bytes to the screen.
	* **DeviceGuard Bypass**<a name="deviceguard"></a>
		* **Articles/Blogposts/Talks/Writeups**
			* [Defeating Device Guard: A look into CVE-2017-0007](https://enigma0x3.net/2017/04/03/defeating-device-guard-a-look-into-cve-2017-0007/)
			* [Consider Application Whitelisting with Device Guard](https://web.archive.org/web/20170517232357/http://subt0x10.blogspot.com:80/2017/04/consider-application-whitelisting-with.html)
			* [Bypassing Application Whitelisting using MSBuild.exe - Device guard Example and Mitigations](https://web.archive.org/web/20170714075746/http://subt0x10.blogspot.com:80/2017/04/bypassing-application-whitelisting.html)
			* [Defeating Device Guard: A look into CVE-2017–0007 - Matt Nelson](https://posts.specterops.io/defeating-device-guard-a-look-into-cve-2017-0007-25c77c155767)
			* [UMCI vs Internet Explorer: Exploring CVE-2017–8625 - Matt Nelson](https://posts.specterops.io/umci-vs-internet-explorer-exploring-cve-2017-8625-3946536c6442)
			* [Windows: LUAFV NtSetCachedSigningLevel Device Guard Bypass - Google](https://www.exploit-db.com/exploits/46716)
		* **Talks/Presentations/Videos**
			* [Sneaking Past Device Guard - Philip Tsukerman(Troopers19)](https://www.youtube.com/watch?v=VJqr_UIwB_M&list=PL1eoQr97VfJlV65VBem99gRd6r4ih9GQE&index=6)
		* **Tools**
			* [DeviceGuard Bypasses - James Forshaw](https://github.com/tyranid/DeviceGuardBypasses)
				* This solution contains some of my UMCI/Device Guard bypasses. They're are designed to allow you to analyze a system, such as Windows 10 S which comes pre-configured with a restrictive UMCI policy.
			* [Window 10 Device Guard Bypass](https://github.com/tyranid/DeviceGuardBypasses)
	* **PowerShell Script Block Logging**
		* **Articles/Blogposts/Writeups**
			* [A Critique of Logging Capabilities in PowerShell v6](http://www.labofapenetrationtester.com/2018/01/powershell6.html)
				* Introduces 'PowerShell Upgrade Attack'
			* [Some PowerShell Logging Observations - mrt-f.com](https://mrt-f.com/blog/2018/powershellLogging/)
			* [Bypass for PowerShell ScriptBlock Warning Logging of Suspicious Commands - cobbr.io(2017)](https://cobbr.io/ScriptBlock-Warning-Event-Logging-Bypass.html)
			* [PowerShell ScriptBlock Logging Bypass - cobbr.io(2017)](https://cobbr.io/ScriptBlock-Logging-Bypass.html)
			* [Exploring PowerShell AMSI and Logging Evasion - Adam Chester(2018)](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
		* **Talks/Presentations/Videos**
		* **Tools**
	* **PowerShell Constrained Language Mode**
		* **Articles/Blogposts/Writeups**
			* [A Critique of Logging Capabilities in PowerShell v6](http://www.labofapenetrationtester.com/2018/01/powershell6.html)
				* Introduces 'PowerShell Upgrade Attack'
		* **Talks/Presentations/Videos**
		* **Tools**
	* **Sysmon**
		* **Articles/Blogposts/Writeups**
			* [Subverting Sysmon materials](https://github.com/mattifestation/BHUSA2018_Sysmon)
		* **Talks/Presentations/Videos**
		* **Tools**
			* [Shhmon - Neuter Sysmon by unloading its driver](https://github.com/matterpreter/Shhmon)
			* [Sysmon configuration bypass finder](https://github.com/mkorman90/sysmon-config-bypass-finder)
				* Detect possible sysmon logging bypasses given a specific configuration
	* **Windows User Account Control(UAC)**
		* **101**
			* [User Account Control - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/user-account-control)
			* [User Account Control Step-by-Step Guide - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc709691(v=ws.10))
			* User Account Control - Steven Sinofsky(blogs.msdn)](https://blogs.msdn.microsoft.com/e7/2008/10/08/user-account-control/)
			* [Inside Windows Vista User Account Control - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc138019(v=msdn.10)?redirectedfrom=MSDN)
			* [Inside Windows 7 User Account Control - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/dd822916(v=msdn.10)?redirectedfrom=MSDN)
		* **Articles/Blogposts/Writeups**
			* [Anatomy of UAC Attacks - b33f](https://www.fuzzysecurity.com/tutorials/27.html)
			* [Farewell to the Token Stealing UAC Bypass - tyranidslair.blogspot](https://tyranidslair.blogspot.com/2018/10/farewell-to-token-stealing-uac-bypass.html)
			* [Testing UAC on Windows 10 - Ernesto Fernandez](https://www.researchgate.net/publication/319454675_Testing_UAC_on_Windows_10)
				* User Account Control (UAC) is a mechanism implemented in Windows systems from Vista to prevent malicious software from executing with administrative privileges without user consent. However, this mechanism does not provide a secure solution to that problem, since can be easily bypassed in some ways, something we will show by means of different methods such as DLL hijacking, token impersonation or COM interface elevation, also we will show a new method which we have developed based on a previous one. Moreover, this new Proof of Concept has been ported to the Metasploit Framework as a new module, which indeed is the only UAC bypass module that works in the latest Windows 10 build version.
			* [Reading Your Way Around UAC (Part 1)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-1.html)
				* [Reading Your Way Around UAC (Part 2)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-2.html)
				* [Reading Your Way Around UAC (Part 3)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-3.html)
			* [Testing User Account Control (UAC) on  Windows 10 - Ernesto Fernández Provecho](https://www.researchgate.net/publication/319454675_Testing_UAC_on_Windows_10)
		* **Bypasses**
			* [Bypassing Windows User Account Control (UAC) and ways of mitigation](https://www.greyhathacker.net/?p=796)
			* [Bypassing User Account Control (UAC) using TpmInit.exe - uacmeltdown.blogspot](https://uacmeltdown.blogspot.com/)
			* [UAC Bypass in System Reset Binary via DLL Hijacking - activecyber.us](https://www.activecyber.us/activelabs/uac-bypass-in-system-reset-binary-via-dll-hijacking)
			* [Bypassing UAC using App Paths - Matt Nelson](https://posts.specterops.io/bypassing-uac-using-app-paths-9249d8cbe9c9)
			* [Bypassing UAC on Windows 10 using Disk Cleanup](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/)
			* [Research on CMSTP.exe](https://msitpros.com/?p=3960)
				* Methods to bypass UAC and load a DLL over webdav 
			* [Bypassing UAC using App Paths](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/)
			* [“Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
			* [Fileless UAC Bypass using sdclt](https://posts.specterops.io/fileless-uac-bypass-using-sdclt-exe-3e9f9ad4e2b3)
			* [Eventvwr File-less UAC Bypass CNA](https://www.mdsec.co.uk/2016/12/cna-eventvwr-uac-bypass/)
			* [How to bypass UAC in newer Windows versions - zcool(Oct2018)](https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html)
			* [Fileless UAC Bypass in Windows Store Binary - activecyber.us](https://www.activecyber.us/activelabs/windows-uac-bypass)
			* [Fileless_UAC_bypass_WSReset](https://github.com/sailay1996/Fileless_UAC_bypass_WSReset)
		* **Talks & Presentations**
			* [Not a Security Boundary: Bypassing User Account Control - Matt Nelson(Derbycon7)](https://www.youtube.com/watch?v=c8LgqtATAnE&index=21&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
		* **Tools**
			* [UACME](https://github.com/hfiref0x/UACME)
				* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
			* [DccwBypassUAC](https://github.com/L3cr0f/DccwBypassUAC)
				* This exploit abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. It supports "x86" and "x64" architectures. Moreover, it has been successfully tested on Windows 8.1 9600, Windows 10 14393, Windows 10 15031 and Windows 10 15062.
			* [Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
				* Bypass-UAC provides a framework to perform UAC bypasses based on auto elevating IFileOperation COM object method calls. This is not a new technique, traditionally, this is accomplished by injecting a DLL into "explorer.exe". This is not desirable because injecting into explorer may trigger security alerts and working with unmanaged DLL's makes for an inflexible work-flow. To get around this, Bypass-UAC implements a function which rewrites PowerShell's PEB to give it the appearance of "explorer.exe". This provides the same effect because COM objects exclusively rely on Windows's Process Status API (PSAPI) which reads the process PEB.
			* [Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
* **Credential Access**<a name="wincredac"></a>
	* **101**
		* [An Overview of KB2871997 - msrc-blog.ms](https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/)
			* Increasing complexity of retrieving clear-text creds
		* [Cached and Stored Credentials Technical Overview - docs.ms(2016)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11))
	* **Articles/Blogposts/Writeups**
		* [Cached and Stored Credentials - ldapwiki](https://ldapwiki.com/wiki/Cached%20and%20Stored%20Credentials)
		* [Hunting for Credentials  Dumping in Windows  Environment - Teymur Kheirhabarov - ZeroNights](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
		* [Dumping user passwords in plaintext on Windows 8.1 and Server 2012](http://www.labofapenetrationtester.com/2015/05/dumping-passwords-in-plain-on-windows-8-1.html)	
		* [Dump Windows password hashes efficiently - Part 1](http://www.bernardodamele.blogspot.com/2011/12/dump-windows-password-hashes.html)
		* [Dumping Windows Credentials](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)
		* [Dumping Clear-Text Credentials - NetbiosX](https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/)
		* [Dumping user passwords in plaintext on Windows 8.1 and Server 2012 - labofapenetrationtester](http://www.labofapenetrationtester.com/2015/05/dumping-passwords-in-plain-on-windows-8-1.html)
		* [Dumping passwords in a VMware .vmem file - Remko Weijnen](https://www.remkoweijnen.nl/blog/2013/11/25/dumping-passwords-in-a-vmware-vmem-file/)
		* [Password Managers: Under the Hood of Secrets Management - ISE](https://www.securityevaluators.com/casestudies/password-manager-hacking/)
				* Password managers allow the storage and retrieval of sensitive information from an encrypted database. Users rely on them to provide better security guarantees against trivial exfiltration than alternative ways of storing passwords, such as an unsecured flat text file. In this paper we propose security guarantees password managers should offer and examine the underlying workings of five popular password managers targeting the Windows 10 platform: 1Password 7, 1Password 4, Dashlane, KeePass, and LastPass. We anticipated that password managers would employ basic security best practices, such as scrubbing secrets from memory when they are not in use and sanitization of memory once a password manager was logged out and placed into a locked state. However, we found that in all password managers we examined, trivial secrets extraction was possible from a locked password manager, including the master password in some cases, exposing up to 60 million users that use the password managers in this study to secrets retrieval from an assumed secure locked state.
		* [How to retrieve user’s passwords from a Windows memory dump using Volatility - Andrea Fortuna](https://www.andreafortuna.org/2017/11/15/how-to-retrieve-users-passwords-from-a-windows-memory-dump-using-volatility/)
		* [The True Story of Windows 10 and the DMA-protection - Sami Laiho](http://blog.win-fu.com/2017/02/the-true-story-of-windows-10-and-dma.html)
			*  This blog post will tell you if / how Windows 10 protects against DMA (Direct Memory Access) bases attacks used against BitLocker and other encryption mechanisms by stealing the encryption key from the memory of a running computer. The story might be long(ish) but rest assured you want to read it through.
		* [Intercepting Password Changes With Function Hooking - clymb3r](https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/)
		* [Dump-Clear-Text-Password-after-KB2871997-installed - 3gstudent](https://github.com/3gstudent/Dump-Clear-Password-after-KB2871997-installed))
	* **Active Directory Environment**
		* **Articles/Blogposts/Writeups**
			* [Dumping Domain Password Hashes - pentestlab.blog](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
			* [How Attackers Dump Active Directory Database Credentials - adsecurity.org](https://adsecurity.org/?p=2398)
			* [Compromising Plain Text Passwords In Active Directory](https://blog.stealthbits.com/compromising-plain-text-passwords-in-active-directory)
			* [Safely Dumping Domain Hashes, with Meterpreter - Rapid7](https://blog.rapid7.com/2015/07/01/safely-dumping-domain-hashes-with-meterpreter/)
			* [Active Directory Domain Services Database Mounting Tool (Snapshot Viewer or Snapshot Browser) Step-by-Step Guide](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753609(v=ws.10))
				* This guide shows how you can use an improved version of Ntdsutil and a new Active Directory® database mounting tool in Windows Server® 2008 to create and view snapshots of data that is stored in Active Directory Domain Services (AD DS) or Active Directory Lightweight Directory Services (AD LDS), without restarting the domain controller or AD LDS server. A snapshot is a shadow copy—created by the Volume Shadow Copy Service (VSS)—of the volumes that contain the Active Directory database and log files.
	* **AWS**
		* **Articles/Blogposts/Writeups**
			* [CloudCopy — Stealing hashes from Domain Controllers in the Cloud - Tanner Barnes](https://medium.com/@_StaticFlow_/cloudcopy-stealing-hashes-from-domain-controllers-in-the-cloud-c55747f0913)
	* **Azure**
		* **Articles/Blogposts/Writeups**
			* [PowerShell, Azure, and Password Hashes in 4 steps - FortyNorth Security](https://www.fortynorthsecurity.com/powershell-azure-and-password-haswinposthes-in-4-steps/)
				* this blog post will walk you through the process of obtaining hashes from a domain controller within Azure using PowerShell.
	* **CredSSP**
		* [Credential theft without admin or touching LSASS with Kekeo by abusing CredSSP / TSPKG (RDP SSO) - Clement Notin](https://clement.notin.org/blog/2019/07/03/credential-theft-without-admin-or-touching-lsass-with-kekeo-by-abusing-credssp-tspkg-rdp-sso/)
	* **Dumping Credential Manager**
		* [Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump)
			* PowerShell Script to Dump Windows Credentials from the Credential Manager
	* **Dumping NTDS.dit**
		* **Articles/Blogposts/Writeups**
			* [How Attackers Pull the Active Directory Database (NTDS.dit) from a Domain Controller](https://adsecurity.org/?p=451)
			* [Extracting Password Hashes From The Ntds.dit File](https://blog.stealthbits.com/extracting-password-hashes-from-the-ntds-dit-file/)
			* [Obtaining NTDS.Dit Using In-Built Windows Commands - Cyberis(2014)](https://www.cyberis.co.uk/2014/02/obtaining-ntdsdit-using-in-built.html)
			* [Volume Shadow Copy NTDS.dit Domain Hashes Remotely - Part 1  - mubix](https://malicious.link/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/)
			* [Getting Hashes from NTDS.dit File - swordshield.com](https://www.swordshield.com/blog/getting-hashes-from-ntds-dit-file/)
			* [Extracting Hashes and Domain Info From ntds.dit - ropnop](https://blog.ropnop.com/extracting-hashes-and-domain-info-from-ntds-dit/)
			* [Practice ntds.dit File Part 2: Extracting Hashes - Didier Stevens](https://blog.didierstevens.com/2016/07/13/practice-ntds-dit-file-part-2-extracting-hashes/)
		* **Tools**
			* [adXtract](https://github.com/LordNem/adXtract)
			* [DIT Snapshot Viewer](https://github.com/yosqueoy/ditsnap)
				* DIT Snapshot Viewer is an inspection tool for Active Directory database, ntds.dit. This tool connects to ESE (Extensible Storage Engine) and reads tables/records including hidden objects by low level C API. The tool can extract ntds.dit file without stopping lsass.exe. When Active Directory Service is running, lsass.exe locks the file and does not allow to access to it. The snapshot wizard copies ntds.dit using VSS (Volume Shadow Copy Service) even if the file is exclusively locked. As copying ntds.dit may cause data inconsistency in ESE DB, the wizard automatically runs esentutil /repair command to fix the inconsistency.
			* [NTDSXtract - Active Directory Forensics Framework](http://www.ntdsxtract.com/)
				* This framework was developed by the author in order to provide the community with a solution to extract forensically important information from the main database of Microsoft Active Directory (NTDS.DIT).
			* [NTDSDumpEx](https://github.com/zcgonvh/NTDSDumpEx)
				* NTDS.dit offline dumper with non-elevated
			* [NTDS-Extraction-Tools](https://github.com/robemmerson/NTDS-Extractions-Tools)
				* Automated scripts that use an older version of libesedb (2014-04-06) to extract large NTDS.dit files
	* **Internal Monologue**
	    * [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue/)
	        * In secure environments, where Mimikatz should not be executed, an adversary can perform an Internal Monologue Attack, in which they invoke a local procedure call to the NTLM authentication package (MSV1_0) from a user-mode application through SSPI to calculate a NetNTLM response in the context of the logged on user, after performing an extended NetNTLM downgrade.
	* **Local Phishing**
		* **Articles/Blogposts/Writeups**
			* [Post exploitation trick - Phish users for creds on domains, from their own box](https://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
		* **Tools**
			* [Pickl3](https://github.com/hlldz/pickl3)
				* Pickl3 is Windows active user credential phishing tool. You can execute the Pickl3 and phish the target user credential. 
	* **Logon**
		* [Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
			* The quick lowdown: I wrote a DLL capable of logging the credentials entered at logon for Windows Vista, 7 and future versions which you can download at http://www.leetsys.com/programs/credentialprovider/cp.zip. The credentials are logged to a file located at c:\cplog.txt. Simply copy the dll to the system32 directory and run the included register.reg script to create the necessary registry settings.
	* **Keylogger**
		* [How to create a keylogger in PowerShell? - Juan Manuel Fernandez](https://www.tarlogic.com/en/blog/how-to-create-keylogger-in-powershell/)
		* [Puffadder](https://github.com/xp4xbox/Puffader/blob/master/readme.md)
			* Puffader is an opensource, hidden and undetectable keylogger for windows written in Python 2.7 which can also capture screenshots, mouse window clicks and clipboard data.
		* [You Can Type, but You Can’t Hide: A Stealthy GPU-based Keylogger](http://www.cs.columbia.edu/~mikepo/papers/gpukeylogger.eurosec13.pdf) 
			* Keyloggers are a prominent class of malware that harvests sensitive data by recording any typed in information. Key- logger implementations strive to hide their presence using rootkit-like techniques to evade detection by antivirus and other system protections. In this paper, we present a new approach for implementing a stealthy keylogger: we explore the possibility of leveraging the graphics card as an alterna- tive environment for hosting the operation of a keylogger. The key idea behind our approach is to monitor the system’s keyboard buffer directly from the GPU via DMA, without any hooks or modifications in the kernel’s code and data structures besides the page table. The evaluation of our pro- totype implementation shows that a GPU-based keylogger can effectively record all user keystrokes, store them in the memory space of the GPU, and even analyze the recorded data in-place, with negligible runtime overhead.
	* **Local Files**
		* **Articles/Blogposts/Writeups**
			* [Extracting SSH Private Keys from Windows 10 ssh-agent - ropnop](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)
			* [Stored passwords found all over the place after installing Windows in company networks :( - Win-Fu Official Blog](http://blog.win-fu.com/2017/08/stored-passwords-found-all-over-place.html)
		* **Tools**
			* [windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)
				* PoC code to extract private keys from Windows 10's built in ssh-agent service
	* **Local Security Authority Subsystem Service(LSASS&LSA)**
		* **101**
			* [Local Security Authority Subsystem Service - Wikipedia](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)
			* [Local Security Authority SubSystem Service - ldapwiki](https://ldapwiki.com/wiki/Local%20Security%20Authority%20Subsystem%20Service)
			* [Security Subsystem Architecture - 2012](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN)
			* [LSA Authentication - docs.ms(2018)](https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication?redirectedfrom=MSDN)
		* **Articles/Blogposts/Writeups**
			* [Dumping Lsass.exe to Disk Without Mimikatz and Extracting Credentials - @spotheplanet](https://ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
			* [Some ways to dump LSASS.exe - Mark Mo](https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf)
			* [Extract credentials from lsass remotely - hackndo](https://en.hackndo.com/remote-lsass-dump-passwords/)
		* **Tools**
			* [Dumpert](https://github.com/outflanknl/Dumpert)
				* Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike, while not touching disk and evading AV/EDR monitored user-mode API calls.
		* [MiniDumpWriteDump via COM+ Services DLL - modexp](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/)
		* [AndrewSpecial](https://github.com/hoangprod/AndrewSpecial)
			* AndrewSpecial, dumping lsass' memory stealthily and bypassing "Cilence" since 2019.
		* [PhysMem2Profit](https://github.com/FSecureLABS/physmem2profit)
			* Physmem2profit can be used to create a minidump of a target host's LSASS process by analysing physical memory remotely. The intention of this research is to propose an alternative approach to credential theft and create a modular framework that can be extended to support other drivers that can access physical memory. Physmem2profit generates a minidump (.dmp) of LSASS that can be further analyzed with Mimikatz. The tool does not require Cobalt Strike but should work fine over beacon with a SOCKS proxy.
			* [Blogpost](https://labs.f-secure.com/blog/rethinking-credential-theft/)
		* [lsassy](https://github.com/hackndo/lsassy)
			* Python library to remotely extract credentials on a set of hosts
			* [Blogpost](https://en.hackndo.com/remote-lsass-dump-passwords/)
	* **Mimikatz/Similar**
		* **Official**
			* ["Mimikatz" - Benjamin Delpy(NoSuchCon#2)](https://www.youtube.com/watch?v=j2m7x1deVRk)
				* [Slides](http://www.nosuchcon.org/talks/2014/D2_02_Benjamin_Delpy_Mimikatz.pdf)
			* [mimikatz](https://github.com/gentilkiwi/mimikatz)
			* [Mimikatz Scheduled tasks Creds](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-scheduled-tasks-credentials)
			* [module ~ dpapi - mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)
		* **Using**
			* [Unofficial Guide to Mimikatz](https://adsecurity.org/?page_id=1821)
			* [Mimikatz Overview, Defenses and Detection](https://www.sans.org/reading-room/whitepapers/detection/mimikatz-overview-defenses-detection-36780)
			* [Mimikatz Logs and Netcat](http://blackpentesters.blogspot.com/2013/12/mimikatz-logs-and-netcat.html?m=1)
			* [Dumping a Domains worth of passwords using mimikatz](http://carnal0wnage.attackresearch.com/2013/10/dumping-domains-worth-of-passwords-with.html)
			* [Mass mimikatz - hacklikeapornstar](https://www.hacklikeapornstar.com/mass-mimikatz/)
			* [Reading DPAPI Encrypted Secrets with Mimikatz and C++ -ired.team](https://ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++)
			* [How to add a Module in Mimikatz?](https://web.archive.org/web/20180326112104/https://littlesecurityprince.com/security/2018/03/18/ModuleMimikatz.html)
			* [howto ~ scheduled tasks credentials - Benjamin Delpy(2017)](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-scheduled-tasks-credentials)
				* There are somes ways to get scheduled tasks passwords
			* [howto ~ credential manager saved credentials - Benjamin Delpy(2017)](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)
			* [mimikatz offline addendum - francesco picasso](http://blog.digital-forensics.it/2014/03/mimikatz-offline-addendum_28.html)
		* **How-it-Works**
			* [mimikatz: deep dive on lsadump::lsa /patch and /inject - Dimitrios Slamaris](https://blog.3or.de/mimikatz-deep-dive-on-lsadumplsa-patch-and-inject.html)
			* [Walk-through Mimikatz sekurlsa module - ](https://jetsecurity.github.io/post/mimikatz/walk-through_sekurlsa/)
				* So in this post, I propose you to follow the steps I used in an attempt to understand the sekurlsa::tspkg command and reproduce its operations with WinDbg on a LSASS dump from a Windows 7 SP1 64-bits machine. We will find the secrets in the dump, and then decrypt them.
			* [Exploring Mimikatz - Part 1 - WDigest - Adam Chester](https://blog.xpnsec.com/exploring-mimikatz-part-1/)
		* **Defense**
			* [Preventing Mimikatz Attacks - Panagiotis Gkatziroulis](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)
		* **Other**
			* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)
			* [Windows Credential Guard & Mimikatz - nviso](https://blog.nviso.be/2018/01/09/windows-credential-guard-mimikatz/)
			* [Auto-Dumping Domain Credentials using SPNs, PowerShell Remoting, and Mimikatz - Scott Sutherland](https://blog.netspi.com/auto-dumping-domain-credentials-using-spns-powershell-remoting-and-mimikatz/)
			* [Mimikatz 2.0 - Brute-Forcing Service Account Passwords ](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Brute-Forcing_Service_Account_Passwords.html)
				* If everything about that ticket-generation operation is valid except for the NTLM hash, then accessing the web application will result in a failure. However, this will not cause a failed logon to appear in the Windows® event log. It will also not increment the count of failed logon attempts for the service account. Therefore, the result is an ability to perform brute-force (or, more realistically, dictionary-based) password checks for such a service account, without locking it out or generating suspicious event log entries. 
			* **Golden Tickets**
				* [mimikatz - golden ticket](http://rycon.hu/papers/goldenticket.html)
				* [Mimikatz 2.0 - Golden Ticket Walkthrough - Ben Lincoln](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html)
			* **Skeleton Key**
				* [Active Directory Domain Controller Skeleton Key Malware & Mimikatz - ADSecurity](https://adsecurity.org/?p=1255)
			* **DCSync**
				* [Mimikatz DCSync Usage, Exploitation, and Detection - Sean Metcalf](https://adsecurity.org/?p=1729)
			* [Mimikatz and DCSync and ExtraSids, Oh My - harmj0y](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)
			* [Active Directory Attack - DCSync - c0d3xpl0it](https://www.c0d3xpl0it.com/2018/06/active-directory-attack-dcsync.html)
		* **DCShadow**
			* [DCShadow - Minimal permissions, Active Directory Deception, Shadowception and more - Nikhil Mittal](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)
			* [DCShadow](https://www.dcshadow.com/)
				* DCShadow is a new feature in mimikatz located in the lsadump module. It simulates the behavior of a Domain Controller (using protocols like RPC used only by DC) to inject its own data, bypassing most of the common security controls and including your SIEM. It shares some similarities with the DCSync attack (already present in the lsadump module of mimikatz).
			* [Active Directory: What can make your million dollar SIEM go blind? - Vincent Le Toux, Benjamin Delpy](https://www.dropbox.com/s/baypdb6glmvp0j9/Buehat%20IL%20v2.3.pdf)
		* **pypykatz**
			* [pypykatz](https://github.com/skelsec/pypykatz)
				* Mimikatz implementation in pure Python
			* [pypykatz_server](https://github.com/skelsec/pypykatz_server)
	* **Password Filter DLL**
		* [Credential Access – Password Filter DLL - NetbiosX](https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/)
	* **RDP**
		* [Vol de session RDP - Gentil Kiwi](http://blog.gentilkiwi.com/securite/vol-de-session-rdp)
		* [Passwordless RDP Session Hijacking Feature All Windows versions - Alexander Korznikov](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)
	* **Volume Shadow Copy Service**
		* [Shadow Copy - Wikipedia](https://en.wikipedia.org/wiki/Shadow_Copy)
		* [Manage Volume Shadow Copy Service from the Vssadmin Command-Line - technet.ms](https://technet.microsoft.com/en-us/library/dd348398.aspx)
		* [vssadmin - ss64](https://ss64.com/nt/vssadmin.html)
		* [vssown.vbs](https://github.com/lanmaster53/ptscripts/blob/master/windows/vssown.vbs)
		* [Using Shadow Copies to Steal the SAM - dcortesi.com](http://www.dcortesi.com/blog/2005/03/22/using-shadow-copies-to-steal-the-sam/)
	* **WDigest**
		* [Dumping WDigest Creds with Meterpreter Mimikatz/Kiwi in Windows 8.1 - TrustedSec](https://www.trustedsec.com/2015/04/dumping-wdigest-creds-with-meterpreter-mimikatzkiwi-in-windows-8-1/)
	* **Web Browsers**
		* [SharpCookieMonster](https://github.com/m0rv4i/SharpCookieMonster)
			* Extracts cookies from Chrome.
			* [Blogpost](https://jmpesp.me/sharpcookiemonster/)
	* **Tools**
		* [credgrap_ie_edge](https://github.com/HanseSecure/credgrap_ie_edge)
			* Extract stored credentials from Internet Explorer and Edge
		* [quarkspwdump](https://github.com/quarkslab/quarkspwdump)
			* Dump various types of Windows credentials without injecting in any process.
		* [SessionGopher](https://github.com/fireeye/SessionGopher)
			* SessionGopher is a PowerShell tool that uses ff to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.
		* [CredCrack](https://github.com/gojhonny/CredCrack)
			* CredCrack is a fast and stealthy credential harvester. It exfiltrates credentials recusively in memory and in the clear. Upon completion, CredCrack will parse and output the credentials while identifying any domain administrators obtained. CredCrack also comes with the ability to list and enumerate share access and yes, it is threaded! CredCrack has been tested and runs with the tools found natively in Kali Linux. CredCrack solely relies on having PowerSploit's "Invoke-Mimikatz.ps1" under the /var/www directory.
		* [pysecdump](https://github.com/pentestmonkey/pysecdump)
			* pysecdump is a python tool to extract various credentials and secrets from running Windows systems. It currently extracts:
			* LM and NT hashes (SYSKEY protected); Cached domain passwords; LSA secrets; Secrets from Credential Manager (only some)
		* [Remote-Desktop-Caching-](https://github.com/Viralmaniar/Remote-Desktop-Caching-)
			* This tool allows one to recover old RDP (mstsc) session information in the form of broken PNG files. These PNG files allows Red Team member to extract juicy information such as LAPS passwords or any sensitive information on the screen. Blue Team member can reconstruct PNG files to see what an attacker did on a compromised host. It is extremely useful for a forensics team to extract timestamps after an attack on a host to collect evidences and perform further analysis.
* **Discovery**<a name="windisco"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Windows Driver and Service enumeration with Python](https://cybersyndicates.com/2015/09/windows-driver-and-service-enumeration-with-python/)
		* [Red Team Play-book - Initial Enumeration - HunnicCyber](https://blog.hunniccyber.com/red-team-play-book-initial-enumeration/)
		* [Finding Hidden Treasure on Owned Boxes: Post-Exploitation Enumeration with wmiServSessEnum - RedXORBlue](http://blog.redxorblue.com/2019/08/finding-hidden-treasure-on-owned-boxes.html)
			* TLDR: We can use WMI queries to enumerate accounts configured to run any service on a box (even non-started / disabled), as well as perform live session enumeration.  Info on running the tool is in the bottom section.
		* [Detecting Hypervisor Presence On Windows 10 - Daax Rynd](https://revers.engineering/detecting-hypervisor-presence-on-windows-10/)
		* [Offensive Event Parsing – Bringing Home Trophies - sixdub](https://www.sixdub.net/?p=315)
		* [Push it, Push it Real Good - harmj0y](http://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
		* [Low Privilege Active Directory Enumeration from a non-Domain Joined Host - matt](https://www.attackdebris.com/?p=470)
		* [Capture a Network Trace without installing anything (& capture a network trace of a reboot) - Chad Duffey(blogs.mdsn)](https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/)
		* [PowerQuinsta - harmj0y](http://www.harmj0y.net/blog/powershell/powerquinsta/)
		* [Compliance search – a pentesters dream - Oddvar Moe](https://msitpros.com/?p=3678)
		* [Remotely Enumerate Anti-Virus Configurations - FortyNorthSecurity](https://fortynorthsecurity.com/blog/remotely-enumerate-anti-virus-configurations/)
		* [Get-MpPreference - docs.ms](https://docs.microsoft.com/en-us/powershell/module/defender/get-mppreference?view=win10-ps)
		* [Script to Create an Overview and Full Report of all Group Objects in a Domain - Jeremy Saunders](http://www.jhouseconsulting.com/2015/01/02/script-to-create-an-overview-and-full-report-of-all-group-objects-in-a-domain-1455)
	* **Talks/Presentations/Videos**
		* [Post Exploitation: Striking Gold with Covert Recon - Derek Rook(WWHF19)](https://www.youtube.com/watch?v=04H1s9z0JDo)
			* You're on a covert penetration test focusing on the client's monitoring and alerting capabilities. You've just established a foothold, maybe even elevated to admin, but now what? You want to know more about the internal network but careless packet slinging will get you caught. Join me on a mining expedition where you can't swing your pick axe without striking gold. We'll be mining logs, pilfering connection statistics, and claim jumping process network connections. Without leaving the comfort of your beachhead, you'll be shouting "Eureka!" in no time.
	* **Tools**
	    * [PyStat](https://github.com/roothaxor/PyStat)
	        * Advanced Netstat For Windows
	    * [pspy](https://github.com/DominicBreuker/pspy)
	        * pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. Great for enumeration of Linux systems in CTFs. Also great to demonstrate your colleagues why passing secrets as arguments on the command line is a bad idea. The tool gathers it's info from procfs scans. Inotify watchers placed on selected parts of the file system trigger these scans to catch short-lived processes.
	    * [forgetmenot](https://github.com/eavalenzuela/forgetmenot)
	        * local looting script in python
		* [SharpPrinter](https://github.com/rvrsh3ll/SharpPrinter)
			* SharpPrinter is a modified and console version of ListNetworks. As an example, one could execute SharpPrinter.exe through Cobalt Strike's Beacon "execute-assembly" module.
		* [wmiServSessEnum](https://github.com/G0ldenGunSec/wmiServSessEnum)
			* multithreaded .net tool that uses WMI queries to enumerate active user sessions and accounts configured to run services (even those that are stopped and disabled) on remote systems
		* [MemScan](https://github.com/checkymander/MemScan)
			* Quick Proof of Concept for reading a processes memory and searching for a specific string.
		* [RidRelay](https://github.com/skorov/ridrelay)
			* Enumerate usernames on a domain where you have no creds by using SMB Relay with low priv.
		* [Eavesarp](https://github.com/arch4ngel/eavesarp)
			* A reconnaissance tool that analyzes ARP requests to identify hosts that are likely communicating with one another, which is useful in those dreaded situations where LLMNR/NBNS aren't in use for name resolution.
			* [Blogpost](https://blackhillsinfosec.com/analyzing-arp-to-discover-exploit-stale-network-address-configurations/)
		* [NetRipper](https://github.com/NytroRST/NetRipper)
			* NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.
* **Lateral Movement**<a name="winlater"></a>
	* **Application Deployment Software**
	* **Component Object Model and Distributed COM**
	* **Exploitation of Remote Services**
	* **Internal Spearphishing**
	* **Logon Scripts**
	* **Pass the Hash**
	* **Pass the Ticket**
	* **Remote Desktop Protocol**
	* **Remote File Copy**
	* **Remote Services**
	* **Replication Through Removable Media**
	* **Shared Webroot**
	* **Taint Shared Content**
	* **Third-party Software**
	* **Windows Admin Shares**
	* **Windows Remote Management**

	* **Some Readings**
		* [Using Credentials to Own Windows Boxes - Part 1 (from Kali) - ropnop](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
		* [Authenticated Remote Code Execution Methods in Windows](https://www.scriptjunkie.us/2013/02/authenticated-remote-code-execution-methods-in-windows/)
		* [The Industrial Revolution of Lateral Movement - Tal Be'ery, Tal Maor(BH USA17)](https://www.blackhat.com/docs/us-17/thursday/us-17-Beery-The-Industrial-Revolution-Of-Lateral-Movement.pdf)
		* [Lateral Movement and Persistence: tactics vs techniques - hexacorn](http://www.hexacorn.com/blog/2018/10/05/lateral-movement-and-persistence-tactics-vs-techniques/)
		 * [Offensive Lateral Movement - Hausec](https://hausec.com/2019/08/12/offensive-lateral-movement/)
	* **AppInit.dlls**
		* [AppInit DLLs and Secure Boot - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dlls/secure-boot-and-appinit-dlls)
		* [AppInit_DLLs in Windows 7 and Windows Server 2008 R2 - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2)
		* [Alternative psexec: no wmi, services or mof needed - Diablohorn](https://diablohorn.com/2013/10/19/alternative-psexec-no-wmi-services-or-mof-needed/)
			* [Poc](https://github.com/DiabloHorn/DiabloHorn/tree/master/remote_appinitdlls)
	* **DCOM**
		* [Lateral movement using excel application and dcom](https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)
		* [New lateral movement techniques abuse DCOM technology - Philip Tsukerman](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
		* [Lateral Movement Using Outlook’s CreateObject Method and DotNetToJScript - Matt Nelson](https://posts.specterops.io/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript-a88a81df27eb)
		* [Lateral Movement with PowerPoint and DCOM - Attactics](https://attactics.org/2018/02/dcom-lateral-movement-powerpoint/)
	* **Desired State Configuration**
		* [Lateral Movement via Desired State Configuration(DSC) - Matt Graeber](https://twitter.com/mattifestation/status/970440419485007872?s=19)
	* **Excel**
		* [Excel4.0 Macros - Now With Twice The Bits! - Philip Tsukerman](https://www.cybereason.com/blog/excel4.0-macros-now-with-twice-the-bits)
		* [Excel4-DCOM](https://github.com/outflanknl/Excel4-DCOM)
			* PowerShell and Cobalt Strike scripts for lateral movement using Excel 4.0 / XLM macros via DCOM (direct shellcode injection in Excel.exe)
		* [Invoke-ExShellcode.ps1 - Philts](https://gist.github.com/Philts/f7c85995c5198e845c70cc51cd4e7e2a)
			* Lateral movement and shellcode injection via Excel 4.0 macros
	* **NTLM Relay**
		* [Skip Cracking Responder Hashes and Relay Them - Richard de la Cruz](https://threat.tevora.com/quick-tip-skip-cracking-responder-hashes-and-replay-them/)		
	* **Pass-The-Hash**
		* **Articles/Blogposts/Writeups**
			* [*Puff* *Puff* PSExec - Jonathan Renard](https://www.toshellandback.com/2017/02/11/psexec/)
			* [PsExec and the Nasty Things It Can Do](http://www.windowsecurity.com/articles-tutorials/misc_network_security/PsExec-Nasty-Things-It-Can-Do.html)
				* An overview of what PsExec is and what its capabilities are from an administrative standpoint.
			* [Pass-the-Hash is Dead: Long Live Pass-the-Hash - harmj0y](http://www.harmj0y.net/blog/penetesting/pass-the-hash-is-dead-long-live-pass-the-hash/)
			* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - harmj0y](http://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
			* [Still Passing the Hash 15 Years Later: Using Keys to the Kingdom to Access Data - BH 2012](https://www.youtube.com/watch?v=O7WRojkYR00)
			* [Still Passing the Hash 15 Years Later](http://passing-the-hash.blogspot.com/)
			* [The Evolution of Protected Processes Part 1: Pass-the-Hash Mitigations in Windows 8.1](http://www.alex-ionescu.com/?p=97)
			* [Et tu Kerberos - Christopher Campbell](https://www.youtube.com/watch?v=RIRQQCM4wz8)
				* For over a decade we have been told that Kerberos is the answer to Microsoft’s authentication woes and now we know that isn’t the case. The problems with LM and NTLM are widely known- but the problems with Kerberos have only recently surfaced. In this talk we will look back at previous failures in order to look forward. We will take a look at what recent problems in Kerberos mean to your enterprise and ways you could possibly mitigate them. Attacks such as Spoofed-PAC- Pass-the-Hash- Golden Ticket- Pass-the-Ticket and Over-Pass-the-Ticket will be explained. Unfortunately- we don’t really know what is next – only that what we have now is broken.
			* [Battle Of SKM And IUM How Windows 10 Rewrites OS Architecture - Alex Ionescu - BHUSA2015](https://www.youtube.com/watch?v=LqaWIn4y26E&index=15&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7)
				* [Slides](http://www.alex-ionescu.com/blackhat2015.pdf)
			* [Psexec: The Ultimate Guide - Adam Bertram](https://adamtheautomator.com/psexec-ultimate-guide/)
			* [Pass the Hash with Kerberos - mubix](https://malicious.link/post/2018/pass-the-hash-with-kerberos/)
				* This blog post may be of limited use, most of the time, when you have an NTLM hash, you also have the tools to use it. But, if you find yourself in a situation where you don’t have the tools and do happen to have kerberos tools, you can pass the hash with it.
		* **Tools**
			* [smbexec](https://github.com/pentestgeek/smbexec)
				* A rapid psexec style attack with samba tools
				* [Blogpost that inspired it](http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html)
			* [pth-toolkit I.e Portable pass the hash toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
				* A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
	* **Port-Forwarding & Proxies**
		* [Port Forwarding in Windows - WindowsOSHub](http://woshub.com/port-forwarding-in-windows/)
		* [WinPortPush](https://github.com/itsKindred/winPortPush)
			* win PortPush is a small PowerShell utility used for pivoting into internal networks upon compromising a Windows public-facing host.
	* **RDP**
		* [RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation - Kevin Beaumont])(https://doublepulsar.com/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
		* [RDPInception - MDsec](https://www.mdsec.co.uk/2017/06/rdpinception/)
		* [The RDP Through SSH Encyclopedia - Carrie Roberts](https://www.blackhillsinfosec.com/the-rdp-through-ssh-encyclopedia/)
			* I have needed to remind myself how to set up RDP access through an SSH connection so many times that I’ve decided to document it here for future reference. I hope it proves useful to you as well. I do “adversary simulation” for work and so I present this information using terms like “attacker” and “target” but this info is also useful for performing system administration tasks.
		* [Remote Desktop tunneling tips & tricks - Maurizio Agazzini](https://techblog.mediaservice.net/2019/10/remote-desktop-tunneling-tips-tricks/)
		* [Jumping Network Segregation with RDP - Rastamouse](https://rastamouse.me/2017/08/jumping-network-segregation-with-rdp/)
	* **SCM**
		* [Lateral Movement — SCM and DLL Hijacking Primer - Dwight Hohnstein](https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992)
	* **SMB**
	* **URL**
		* [Lateral movement using URL Protocol - Matt harr0ey](https://medium.com/@mattharr0ey/lateral-movement-using-url-protocol-e6f7d2d6cf2e)
	* **WinRM**
		* [PowerShell Remoting from Linux to Windows - William Martin](https://blog.quickbreach.io/ps-remote-from-linux-to-windows/)
		* [Lateral Movement – WinRM - pentestlab.blog](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)
	* **WMI**
		* [WMI Shell Tool](https://github.com/secabstraction/Create-WMIshell)
			* The WMI shell tool that we have developed allows us to execute commands and get their output using only the WMI infrastructure, without any help from other services, like the SMB server. With the wmi-shell tool we can execute commands, upload files and recover Windows passwords remotely using only the WMI service available on port 135.
		* [WMIcmd](https://github.com/nccgroup/WMIcmd)
			* A command shell wrapper using only WMI for Microsoft Windows
		* [No Win32_Process Needed – Expanding the WMI Lateral Movement Arsenal - Philip Tsukerman](https://www.cybereason.com/blog/no-win32-process-needed-expanding-the-wmi-lateral-movement-arsenal?hs_preview=UbvcDFUZ-5764480077)
	* **Password Spraying**
		* **Linux**
			* [Raining shells on Linux environments with Hwacha](https://www.n00py.io/2017/12/raining-shells-on-linux-environments-with-hwacha/)
			* [Hwacha](https://github.com/n00py/Hwacha)
				* Hwacha is a tool to quickly execute payloads on `*`Nix based systems. Easily collect artifacts or execute shellcode on an entire subnet of systems for which credentials are obtained.
		* **Windows**
			* [Use PowerShell to Get Account Lockout and Password Policy](https://blogs.technet.microsoft.com/heyscriptingguy/2014/01/09/use-powershell-to-get-account-lockout-and-password-policy/)
			* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
				* DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain.
			* [DomainPasswordSpray](https://github.com/mdavis332/DomainPasswordSpray)
				* DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. It will automatically generate a userlist from the domain which excludes accounts that are expired, disabled locked out, or within 1 lockout attempt.
			* [NTLM - Open-source script from root9B for manipulating NTLM authentication](https://github.com/root9b/NTLM)
				* This script tests a single hash or file of hashes against an ntlmv2 challenge/response e.g. from auxiliary/server/capture/smb The idea is that you can identify re-used passwords between accounts that you do have the hash for and accounts that you do not have the hash for, offline and without cracking the password hashes. This saves you from trying your hashes against other accounts live, which triggers lockouts and alerts.
			* [CredNinja](https://github.com/Raikia/CredNinja)
				* A multithreaded tool designed to identify if credentials are valid, invalid, or local admin valid credentials within a network at-scale via SMB, plus now with a user hunter.
			* [passpr3y](https://github.com/depthsecurity/passpr3y/blob/master/passpr3y.py)
				* This is a fire-and-forget long-running password spraying tool. You hand it a list of usernames and passwords and walk away. It will perform a horizontal login attack while keeping in mind lockout times, erroneous responses, etc... Set it up on your attack box at the beginning of an assessment and check back for creds gradually over time. Output is intended to be easy to read through and grep. Focus is on simplicity.
	* **(Ab)Using 'Legitimate' Applications already installed**
		* [How I Hacked Into Your Corporate Network Using Your Own Antivirus Agent - Angelo Ruwantha](https://pentestmag.com/how-i-hacked-into-your-corporate-network-using-your-own-anti-virus-agent/)
			* Code exec through admin access to eset admin console
		* [Abusing Common Cluster Configuration for Lateral Movement](https://www.lares.com/abusing-common-cluster-configuration-privileged-lateral-movement/)
			* Tech sites have published articles that walk a Windows Systems Administrator through the process of adding a machine account to the Local Administrators group on another machine. These accounts end in a $ (dollar sign) and look like SERVER$ in Active Directory. While this may be useful for simplifying the installation of clusters such as Lync, Exchange, or SQL Server, it’s not always the best idea. Servers that are set up in this way weaken the overall security posture of the cluster, and ultimately the organization, by allowing a single vulnerability or misconfiguration on one server the ability to move laterally without having to escalate privileges or compromise additional credentials. Using SQL Server as the example, any user who has READ permissions to a database essentially has SYSTEM-level permissions on a remote server. We’ll walk through that path below.
	* **Tools**
		* [PoisonHandler](https://github.com/Mr-Un1k0d3r/PoisonHandler)
			* This technique is registering a protocol handler remotely and invoke it to execute arbitrary code on the remote host. The idea is to simply invoke start handler:// to execute commands and evade detection.
* **Collection**<a name="wincollect"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Digging Up the Past: Windows Registry Forensics Revisited - David Via](https://www.fireeye.com/blog/threat-research/2019/01/digging-up-the-past-windows-registry-forensics-revisited.html)
		* [Pillage Exchange - Digby](https://warroom.securestate.com/pillage-exchange/)
		* [Pillaging .pst Files - Digby](https://warroom.securestate.com/pillaging-pst-files/)
		* [File Server Triage on Red Team Engagements - harmj0y](http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/)
		* [No one expect command execution!](http://0x90909090.blogspot.fr/2015/07/no-one-expect-command-execution.html)
		* Decrypting IIS Passwords to Break Out of the DMZ	
			* [Decrypting IIS Passwords to Break Out of the DMZ: Part 1 ](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/)
			* [Decrypting IIS Passwords to Break Out of the DMZ: Part 2](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/)
		* [Recovering Plaintext Domain Credentials from WPA2 Enterprise on a Compromised Host - zc00l(2018)](https://0x00-0x00.github.io/research/2018/11/06/Recovering-Plaintext-Domain-Credentials-From-WPA2-Enterprise-on-a-compromised-host.html)
	* **CC**
		* [SearchForCC](https://github.com/eelsivart/SearchForCC)
			* A collection of open source/common tools/scripts to perform a system memory dump and/or process memory dump on Windows-based PoS systems and search for unencrypted credit card track data.
	* **Code Storage**
		* [dvcs-ripper](https://github.com/kost/dvcs-ripper)
			* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even when directory browsing is turned off.
		* [cred_scanner](https://github.com/disruptops/cred_scanner)
			* A simple command line tool for finding AWS credentials in files. Optimized for use with Jenkins and other CI systems.
	* **KeePass**
		* [KeeFarce](https://github.com/denandz/KeeFarce)
			* Extracts passwords from a KeePass 2.x database, directly from memory.
		* [KeeThief](https://github.com/HarmJ0y/KeeThief)
			* Methods for attacking KeePass 2.X databases, including extracting of encryption key material from memory.
	* **Outlook**
		* [Pillaging .pst Files](https://warroom.securestate.com/pillaging-pst-files/)
	* **PCAP/Live Interface**
		* [net-creds](https://github.com/DanMcInerney/net-creds)
			* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification.
		* [PCredz](https://github.com/lgandx/PCredz)
			* This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
	* **Skype**
		* [skype log viewer](https://github.com/lordgreggreg/skype-log-viewer)
			* Download and View Skype History Without Skype This program allows you to view all of your skype chat logs and then easily export them as text files. It correctly organizes them by conversation, and makes sure that group conversations do not get jumbled with one on one chats.





---------------------------
#### Windows Technologies<a name="wintech"></a>
* **Application Shims**<a name="winappshim"></a>
	* [Windows - Application Shims](https://technet.microsoft.com/en-us/library/dd837644%28v=ws.10%29.aspx)
* **Code Signing**
	* **Articles/Blogposts/Writeups**
		* [Code Signing Certificate Cloning Attacks and Defenses - Matt Graeber](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
		* [MetaTwin – Borrowing Microsoft Metadata and Digital Signatures to “Hide” Binaries - Joe Vest](https://web.archive.org/web/20190303110249/http://threatexpress.com/2017/10/metatwin-borrowing-microsoft-metadata-and-digital-signatures-to-hide-binaries/)
		* [Borrowing Microsoft Code Signing Certificates - lopi](https://blog.conscioushacker.io/index.php/2017/09/27/borrowing-microsoft-code-signing-certificates/)
		* [Application of Authenticode Signatures to Unsigned Code - mattifestation](http://www.exploit-monday.com/2017/08/application-of-authenticode-signatures.html)
		* [Subverting Trust in Windows - Matt Graeber](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
		* [Masquerading as a Windows System Binary Using Digital Signatures - Stuart Morgan](https://labs.mwrinfosecurity.com/archive/masquerading-as-a-windows-system-binary-using-digital-signatures/)
		* [Hijack Digital Signatures – PowerShell Script - pentestlab.blog](https://pentestlab.blog/2017/11/08/hijack-digital-signatures-powershell-script/)
	* **Talks/Videos**
		* [Hi, My Name is "CN=Microsoft Windows, O=Microsoft Corporation… - Matt Graeber(BlueHat IL 2018)](https://www.youtube.com/watch?v=I3jCGBzMmzw)
			* [Slides](http://www.bluehatil.com/files/Matt%20Graeber%20BlueHat%20IL%202018.pdf)
		* [Subverting Sysmon - Application of a Formalized Security Product Evasion Method - Matt Graeber, Lee Christensen(BHUSA18)](https://i.blackhat.com/us-18/Wed-August-8/us-18-Graeber-Subverting-Sysmon-Application-Of-A-Formalized-Security-Product-Evasion-Methodology.pdf)
	* **Tools**
		* [certerator](https://github.com/stufus/certerator)
			* This is the code relating to a project to simplify the act of creating a CA, signing a binary with the CA and then installing the CA on the target machine. It investigates the extent to which this can be achieved without the benefit of a GUI and shows how this can be modified to generate valid EV certificates which are trusted by Windows. It is intended for penetration testers who are looking to install an implant binary which looks as legitimate as possible. None of these techniques are new, but it is hoped that this tool and project will make them easier and more accessible.
* **ClickOnce Applications**<a name="clickonce"></a>
	* [ClickOnce - Wikipedia](https://en.wikipedia.org/wiki/ClickOnce)
	* [ClickOnce security and deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2019)
	* [ClickOnce Deployment for Windows Forms - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/winforms/clickonce-deployment-for-windows-forms)
	* [ClickOnce Applications in Enterprise Environments - Remko Weijnen](https://www.remkoweijnen.nl/blog/2013/08/05/clickonce-applications-in-enterprise-environments/)
		* ClickOnce is a Microsoft technology that enables an end user to install an application from the web without administrative permissions.
	* [Eight Evil Things Microsoft Never Showed You in the ClickOnce Demos (and What You Can Do About Some of Them) - Chris Williams](https://www.codemag.com/Article/0902031/Eight-Evil-Things-Microsoft-Never-Showed-You-in-the-ClickOnce-Demos-and-What-You-Can-Do-About-Some-of-Them)
* **DPAPI** <a name="dpapi"></a>
	* **101**
		* [CNG DPAPI - docs.ms](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-dpapi)
		* [Data Protection API - Wikipedia](https://en.wikipedia.org/wiki/Data_Protection_API)
		* [DPAPI Secrets. Security analysis and data recovery in DPAPI - Passcape](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28)
		* [Windows Data Protection - docs.ms(WinXP)](https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)
		* [module ~ dpapi - mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)
	* **Articles/Blogposts/Writeups** 
		* [DPAPI Primer for Pentesters - WebstersProdigy](https://webstersprodigy.net/2013/04/05/dpapi-primer-for-pentesters/)
		* [Grab the Windows secrets! - decoder.cloud](https://decoder.cloud/2017/02/11/grab-the-windows-secrets/)
		* [DPAPI exploitation during pentest and password cracking - Jean-Christophe Delaunay](https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf)
		* [Happy DPAPI! - ZenaForensics](http://blog.digital-forensics.it/2015/01/happy-dpapi.html)
		* [ReVaulting! Decryption and opportunities - Reality Net System Solutions](https://www.slideshare.net/realitynet/revaulting-decryption-and-opportunities)
		* [Windows ReVaulting - digital-forensics.it](http://blog.digital-forensics.it/2016/01/windows-revaulting.html)
		* [TBAL: an (accidental?) DPAPI Backdoor for local users - vztekoverflow](https://vztekoverflow.com/2018/07/31/tbal-dpapi-backdoor/)
		* [Operational Guidance for Offensive User DPAPI Abuse - harmj0y](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/)
		* [Offensive Encrypted Data Storage (DPAPI edition) - harmj0y](https://www.harmj0y.net/blog/redteaming/offensive-encrypted-data-storage-dpapi-edition/)
		* [A Case Study in Attacking KeePass - harmj0y](https://www.harmj0y.net/blog/redteaming/a-case-study-in-attacking-keepass/)
		* [Reading DPAPI Encrypted Secrets with Mimikatz and C++ -ired.team](https://ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++)
		* [Retrieving DPAPI Backup Keys from Active Directory - Michael Grafnetter](https://www.dsinternals.com/en/retrieving-dpapi-backup-keys-from-active-directory/)
	* **Talks & Presentations**
		* [The BlackBox of DPAPI: The Gift That Keeps on Giving - Bart Inglot](https://github.com/comaeio/OPCDE/blob/master/2017/The%20Blackbox%20of%20DPAPI%20the%20gift%20that%20keeps%20on%20giving%20-%20Bartosz%20Inglot/The%20Blackbox%20of%20DPAPI%20-%20Bart%20Inglot.pdf)
		* [DPAPI and DPAPI-NG: Decryption Toolkit - Paula Januskiewicz](https://www.slideshare.net/paulajanuszkiewicz/black-hat-europe-2017-dpapi-and-dpaping-decryption-toolkit)
			* [Tools/Blogpost](https://cqureacademy.com/blog/windows-internals/black-hat-europe-2017)
		* [Protecting browsers’ secrets in a domain environment - Itai Grady](https://www.slideshare.net/ItaiGrady/protecting-browsers-secrets-in-adomainenvironment)
			* All popular browsers allow users to store sensitive data such as credentials for online and cloud services (such as social networks, email providers, and banking) and forms data (e.g. Credit card number, address, phone number) In Windows environment, most browsers (and many other applications) choose to protect these secrets by using Window Data Protection API (DPAPI), which provides an easy method to encrypt and decrypt secret data. Lately, Mimikatz, a popular pentest/hacking tool, was updated to include a functionality that allows highly-privileged attackers to decrypt all of DPAPI secrets. In this talk, I will analyze the Mimikatz Anti-DPAPI attack targeting the Domain Controller (DC) which puts all DPAPI secrets in peril and show how it can be defeated with network monitoring.
		* [Decrypting DPAPI data - Jean-Michel Picod, Elie Bursztein](https://elie.net/static/files/reversing-dpapi-and-stealing-windows-secrets-offline/reversing-dpapi-and-stealing-windows-secrets-offline-slides.pdf)
		* [give me the password and I'll rule the world: dpapi, what else? - Francesco Picasso](https://digital-forensics.sans.org/summit-archives/dfirprague14/Give_Me_the_Password_and_Ill_Rule_the_World_Francesco_Picasso.pdf)
		* [DPAPI exploitation during pentest and password cracking - Jean-Christophe Delaunay](https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf)
		* [ReVaulting! Decryption and opportunities - Francesco Picasso](https://www.slideshare.net/realitynet/revaulting-decryption-and-opportunities)
			* Windows credentials manager stores users’ credentials in special folders called vaults. Being able to access such credentials could be truly useful during a digital investigation for example, to gain access to other protected systems. Moreover, if data is in the cloud, there is the need to have the proper tokens to access it. This presentation will describe vaults’ internals and how they can be decrypted; the related Python Open Source code will be made publicly available. During the session, credentials and vaults coming from Windows 7, Windows 8.1 and Windows 10 will be decrypted, focusing on particular cases of interest. Finally, the presentation will address the challenges coming from Windows Phone, such as getting system-users’ passwords and obtaining users’ ActiveSync tokens.
	* **Tools**
		* [dpapick](https://bitbucket.org/jmichel/dpapick/src/default/)
			* DPAPIck is a forensic toolkit, written in Python and designed to easily deal with Microsoft DPAPI blob decryption in an offline and cross-platform way.
		* [Windows DPAPI Lab](https://github.com/dfirfpi/dpapilab)
			* My own DPAPI laboratory. Here I put some ongoing works that involve Windows DPAPI (Data Protection API). It's a lab, so something could not work: please see "How to Use".
		* [The LaZagne Project](https://github.com/AlessandroZ/LaZagneForensic)
			* LaZagne uses an internal Windows function called CryptUnprotectData to decrypt user passwords. This API should be called on the victim user session, otherwise, it does not work. If the computer has not been started (when the analysis is realized on an offline mounted disk), or if we do not want to drop a binary on the remote host, no passwords can be retrieved. LaZagneForensic has been created to avoid this problem. This work has been mainly inspired by the awesome work done by Jean-Michel Picod and Elie Bursztein for DPAPICK and Francesco Picasso for Windows DPAPI laboratory.
		* [DataProtectionDecryptor v1.06 - Nirsoft](https://www.nirsoft.net/utils/dpapi_data_decryptor.html)
* **ETW**<a name="etw"></a>
	* **101**
		* [Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
		* [About Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
		* [Using Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/using-event-tracing)
	* **Articles/Blogposts/Writeups**
		* [SilkETW: Because Free Telemetry is … Free! - Ruben Boonnen](https://www.fireeye.com/blog/threat-research/2019/03/silketw-because-free-telemetry-is-free.html)
			* [Slides](https://github.com/FuzzySecurity/BH-Arsenal-2019/blob/master/Ruben%20Boonen%20-%20BHArsenal_SilkETW_v0.2.pdf)
		* [Tampering with Windows Event Tracing: Background, Offense, and Defense - Palantir](https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
		* [Getting started with Event Tracing for Windows in C# - Alex Khanin](https://medium.com/@alexkhanin/getting-started-with-event-tracing-for-windows-in-c-8d866e8ab5f2)
		* [ETW Event Tracing for Windows and ETL Files - Nicole Ibrahim](https://www.hecfblog.com/2018/06/etw-event-tracing-for-windows-and-etl.html)
	* **Talks/Videos**
		* [Production tracing with Event Tracing for Windows (ETW) - Doug Cook](https://channel9.msdn.com/Events/Build/2017/P4099)
		* [ETW - Monitor Anything, Anytime, Anywhere - Dina Goldshtein(NDC Oslo 2017)](https://www.youtube.com/watch?v=ZNdpLM4uIpw)
			* You’ll learn how to diagnose incredibly complex issues in production systems such as excessive garbage collection pauses, slow startup due to JIT and disk accesses, and even sluggishness during the Windows boot process. We will also explore some ways to automate ETW collection and analysis to build self-diagnosing applications that identify high CPU issues, resource leaks, and concurrency problems and produce alerts and reports. In the course of the talk we will use innovative performance tools that haven’t been applied to ETW before — flame graphs for visualising call stacks and a command-line interface for dynamic, scriptable ETW tracing. ETW is truly a window into everything happening on your system, and it doesn’t require expensive licenses, invasive tools, or modifying your code in any way. It is a critical, first-stop skill on your way to mastering application performance and diagnostics.
	* **Tools**
		* [SilkETW & SilkService](https://github.com/fireeye/SilkETW)
			* SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection. While both projects have obvious defensive (and offensive) applications they should primarily be considered as research tools. For easy consumption, output data is serialized to JSON. The JSON data can either be written to file and analyzed locally using PowerShell, stored in the Windows eventlog or shipped off to 3rd party infrastructure such as Elasticsearch.
* **Fibers**<a name="fibers"></a>
	* **101**
		* [Fibers - docs.ms](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers)
	* **Articles/Blogposts/Writeups**
* **LNK Files**<a name="LNK"></a>
	* [Suspected Sapphire Mushroom (APT-C-12) malicious LNK files - @mattnotmax](https://bitofhex.com/2020/02/10/sapphire-mushroom-lnk-files/)
	* [The Missing LNK — Correlating User Search LNK files - Ashley Frazer](https://www.fireeye.com/blog/threat-research/2020/02/the-missing-lnk-correlating-user-search-lnk-files.html)
	* [Analyzing the Windows LNK file attack method - 0xd3xt3r](https://dexters-lab.net/2019/02/16/analyzing-the-windows-lnk-file-attack-method/)
* **Logging**<a name="winlog"></a>
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
			* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
		* [GENE: Go Evtx sigNature Engine](https://github.com/0xrawsec/gene)
			* The idea behind this project is to provide an efficient and standard way to look into Windows Event Logs (a.k.a EVTX files). For those who are familiar with Yara, it can be seen as a Yara engine but to look for information into Windows Events.
			* [Documentation](https://rawsec.lu/doc/gene/1.6/)
* **Named Pipes**
	* [Named Pipe - Wikipedia](https://en.wikipedia.org/wiki/Named_pipe)
	* [Named Pipes - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
	* [Named Pipe Security and Access Rights - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
	* [Named Pipe client](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-client)
* **PowerShell Desired State Configuration**<a name="winpsc"></a>
	* **Documentation**
		* [Windows PowerShell Desired State Configuration Overview - docs.ms](https://docs.microsoft.com/en-us/powershell/dsc/overview)
	* [DSCompromised: A Windows DSC Attack Framework - Matt Hastings, Ryan Kazanciyan - BH Asia16](https://www.blackhat.com/docs/asia-16/materials/asia-16-Kazanciyan-DSCompromised-A-Windows-DSC-Attack-Framework.pdf)
	* [DSCompromised](https://github.com/matthastings/DSCompromised)
		* PowerShell framework for managing and infecting systems via Windows Desired State Configuration (DSC) DSC is a built-in feature in Windows Management Framework 4.0 (PowerShell v4) and is installed natively on Windows operating systems beginning with Server 2012 R2 and Windows 8.1.
* **Windows Communication Foundation**<a name="wcf"></a>
	* **101**
		* [What Is Windows Communication Foundation - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/wcf/whats-wcf)
		* [Best Practices for Security in WCF - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/best-practices-for-security-in-wcf)
	* **Articles/Blogposts/Writeups**
		* [Windows Communication Foundation(WCF) FAQ: Part I - Shivprasd(C#Corner)](https://www.c-sharpcorner.com/UploadFile/shivprasadk/windows-communication-foundationwcf-faq-part-i/)
		* [Abusing Insecure Windows Communication Foundation (WCF) Endpoints - Fabius Watson](https://versprite.com/blog/security-research/abusing-insecure-wcf-endpoints/)
		* [Exploitation of Remote WCF Vulnerabilities - Versprite](https://versprite.com/blog/security-research/exploitation-of-remote-services/)
		* [Abusing WCF Endpoints for Fun and Profit](https://downloads.immunityinc.com/infiltrate2019-slidepacks/christopher-anastasio-abusing-insecure-wcf-endpoints-for-profit-and-fun/abusing_wcf_endpoints.pdf)
		* [Finding and Exploiting .NET Remoting over HTTP using Deserialisation - Sorush Dalili](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/)
	* **Talks/Presentations/Videos**
* **Windows Notification Facility**<a name="wnf"></a>
	* [Playing with the Windows Notification Facility (WNF) - Gwaby](https://blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf.html)
* **Windows Scripting Host**<a name="wsh"></a>
	* **101**
		* [Windows Scripting Host - Wikipedia](https://en.wikipedia.org/wiki/Windows_Script_Host)
		* [Windows Script Host - docs.ms](https://web.archive.org/web/20190212190548/https://docs.microsoft.com/en-us/previous-versions//9bbdkx3k(v=vs.85))
			* The following sections provide information about Windows Script Host along with a reference section that documents the object model.
		* [wscript - docs.ms](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wscript)
			* Windows Script Host provides an environment in which users can execute scripts in a variety of languages that use a variety of object models to perform tasks.
		* [Scripting - docs.ms](https://docs.microsoft.com/en-us/previous-versions/ms950396(v=msdn.10))
			* Windows Script is a comprehensive scripting infrastructure for the Microsoft® Windows® platform. Windows Script provides two script engines, Visual Basic® Scripting Edition and Microsoft JScript®, which can be embedded into Windows Applications. It also provides an extensive array of supporting technologies that makes it easier for script users to script Windows applications.
	* **Articles/Blogposts/Writeups**
		* [Is VBScript or VBA Dead/Dying? - isvbscriptdead.com](https://isvbscriptdead.com)
		* [WSH - Windows Script Host - Rob Van der Woude](https://www.robvanderwoude.com/wsh.php)
		* [Windows Script Host (jscript): how do i download a binary file? - StackOverflow](https://stackoverflow.com/questions/4164400/windows-script-host-jscript-how-do-i-download-a-binary-file)
		* [WSH - Windows Script Host - renenyffenegger.ch](https://renenyffenegger.ch/notes/development/languages/WSH/index)
* **Malicious Butler**
	* [The Remote Malicious Butler Did It! - Tal Be'ery, Chaim Hoch(BHUSA 2015)](https://www.youtube.com/watch?v=xujWesUS1ZQ)
		* An Evil Maid attack is a security exploit that targets a computing device that has been left unattended. An evil maid attack is characterized by the attacker's ability to physically access the target multiple times without the owner's knowledge. On BlackHat Europe 2015, Ian Haken in his talk "Bypassing Local Windows Authentication to Defeat Full Disk Encryption" had demonstrated a smart Evil Maid attack which allows the attacker to bypass Bitlocker disk encryption in an enterprise's domain environment. The attacker can do so by connecting the unattended computer into a rogue Domain Controller and abusing a client side authentication vulnerability. As a result, Microsoft had released a patch to fix this vulnerability and mitigate the attack. While being a clever attack, the physical access requirement for the attack seems to be prohibitive and would prevent it from being used on most APT campaigns. As a result, defenders might not correctly prioritize the importance of patching it. In our talk, we reveal the "Remote Malicious Butler" attack, which shows how attackers can perform such an attack, remotely, to take a complete control over the remote computer. We will dive into the technical details of the attack including the rogue Domain Controller, the client-side vulnerability and the Kerberos authentication protocol network traffic that ties them. We would explore some other attack avenues, all leveraging on the rogue Domain Controller concept. We would conclude with the analysis of some practical generic detection and prevention methods against rogue Domain Controllers.
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Beery-The-Remote-Malicious-Butler-Did-It.pdf)












---------------------------------------------------------------------------------------------------------------------------------
### <a name="active-directory"></a>Active Directory
* **101**
	* [What is Active Directory Domain Services and how does it work?](https://serverfault.com/questions/402580/what-is-active-directory-domain-services-and-how-does-it-work#)
	* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them - Sean Metcalf](https://adsecurity.org/?p=1684)
	* [What is Active Directory Red Forest Design? - social.technet.ms](https://social.technet.microsoft.com/wiki/contents/articles/37509.what-is-active-directory-red-forest-design.aspx)
	* [Presentations by Sean Metcalf(ADSecurity.org)](https://adsecurity.org/?page_id=1352)
	* **Articles/Blogposts/Writeups**
		* [Beyond Domain Admins – Domain Controller & AD Administration - ADSecurity.org](https://adsecurity.org/?p=3700)
			* This post provides information on how Active Directory is typically administered and the associated roles & rights.
		* [Setting up Samba as a Domain Member](https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member)
	* **Talks/Videos**
		* [Beyond the MCSE: Active Directory for the Security Professional - Sean Metcalf(BHUSA 2016)](https://www.youtube.com/watch?v=2w1cesS7pGY)
			* Active Directory (AD) is leveraged by 95% of the Fortune 1000 companies for its directory, authentication, and management capabilities. This means tSMBhat both Red and Blue teams need to have a better understanding of Active Directory, it's security, how it's attacked, and how best to align defenses. This presentation covers key Active Directory components which are critical for security professionals to know in order to defend AD. Properly securing the enterprise means identifying and leveraging appropriate defensive technologies. The provided information is immediately useful and actionable in order to help organizations better secure their enterprise resources against attackers. Highlighted are areas attackers go after including some recently patched vulnerabilities and the exploited weaknesses. This includes the critical Kerberos vulnerability (MS14-068), Group Policy Man-in-the-Middle (MS15-011 & MS15-014) and how they take advantages of AD communication.
	* **Attacking101**<a name="adatk101"></a>
		* **Articles/Blogposts/Writeups**
			* [Active Directory Security Workshop: A Red and Blue Guide to Popular AD Attacks - `@_theViVi`(AfricaHackon2019)](https://thevivi.net/wp-content/uploads/2019/08/theVIVI-AD-Security-Workshop_AfricaHackon2019.pdf)
			* [Active Directory Kill Chain Attack & Defense - infosecn1nja](https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md)
				* This document was designed to be a useful, informational asset for those looking to understand the specific tactics, techniques, and procedures (TTPs) attackers are leveraging to compromise active directory and guidance to mitigation, detection, and prevention. And understand Active Directory Kill Chain Attack and Modern Post Exploitation Adversary Tradecraft Activity.
			* [Penetration Testing Active Directory, Part I - Hausec](https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/)
				* [Part II](https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/)
			* [Active Directory Attacks - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
			* [Pen Testing Active Directory Series - Andy Green](https://blog.varonis.com/binge-read-pen-testing-active-directory-series/)
		* **Talks/Videos**
			* [Offensive Active Directory with Powershell - harmj0y(Troopers2016)](https://www.youtube.com/watch?v=cXWtu-qalSs)
			* [Abusing Active Directory in Post-Exploitation - Carlos Perez(Derbycon4)](https://www.irongeek.com/i.php?page=videos/derbycon4/t105-abusing-active-directory-in-post-exploitation-carlos-perez)
				* Windows APIs are often a blackbox with poor documentation, taking input and spewing output with little visibility on what actually happens in the background. By reverse engineering (and abusing) some of these seemingly benign APIs, we can effectively manipulate Windows into performing stealthy custom attacks using previously unknown persistent and injection techniques. In this talk, we’ll get Windows to play with itself nonstop while revealing 0day persistence, previously unknown DLL injection techniques, and Windows API tips and tricks. To top it all off, a custom HTTP beaconing backdoor will be released leveraging the newly released persistence and injection techniques. So much Windows abuse, so little time.
			* [Beyond the MCSE: Red Teaming Active Directory - Sean Metcalf](https://www.youtube.com/watch?v=tEfwmReo1Hk)
			* [Red vs Blue: Modern Active Directory Attacks & Defense - Sean Metcalf(Defcon23)](https://www.youtube.com/watch?v=rknpKIxT7NM)
			* [Red Vs. Blue: Modern Active Directory Attacks, Detection, And Protection - Sean Metcalf(BHUSA15)](https://www.youtube.com/watch?v=b6GUXerE9Ac)
				* Kerberos "Golden Tickets" were unveiled by Alva "Skip" Duckwall & Benjamin Delpy in 2014 during their Black Hat USA presentation. Around this time, Active Directory (AD) admins all over the world felt a great disturbance in the Force. Golden Tickets are the ultimate method for persistent, forever AD admin rights to a network since they are valid Kerberos tickets and can't be detected, right? The news is filled with reports of breached companies and government agencies with little detail on the attack vectors and mitigation. This briefing discusses in detail the latest attack methods for gaining and maintaining administrative access in Active Directory. Also covered are traditional defensive security measures that work (and ones that don't) as well as the mitigation strategies that can keep your company's name off the front page. Prepare to go beyond "Pass-the-Hash" and down the rabbit hole. This talk explores the latest Active Directory attack vectors and describes how Golden Ticket usage can be detected. When forged Kerberos tickets are used in AD, there are some interesting artifacts that can be identified. Yes, despite what you may have read on the internet, there are ways to detect Golden & Silver Ticket usage!
* **Active Directory Attributes & Technologies**<a name="ADtech"></a>
	* **Active Directory Service Interaces**
		* **101**
			* [Active Directory Service Interfaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)
		* **Articles/Blogposts/Writeups**
		* **Talks/Videos**
		* **Tools**
			* [AdsiPS](https://github.com/lazywinadmin/AdsiPS)
				* PowerShell module to interact with Active Directory using ADSI and the `System.DirectoryServices` namespace (.NET Framework).
	* **AD Permissions/Rights**
		* **101**
			* [Extended Rights Reference - docs.ms](https://docs.microsoft.com/en-us/previous-versions/tn-archive/ff405676(v=msdn.10))
				* This page lists all the extended rights available for delegation in Active Directory. These rights have been categorized according to the object (such as the user account object) that the right applies to; each listing includes the extended right name, a brief description, and the object GUID required when writing a script to delegate that right.
	* **Groups**
		* **101**
			* [Active Directory Security Groups - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11))
	* **Account Logon History**
		* [Get All AD Users Logon History with their Logged on Computers (with IPs)& OUs](https://gallery.technet.microsoft.com/scriptcenter/Get-All-AD-Users-Logon-9e721a89)
			* This script will list the AD users logon information with their logged on computers by inspecting the Kerberos TGT Request Events(EventID 4768) from domain controllers. Not Only User account Name is fetched, but also users OU path and Computer Accounts are retrieved. You can also list the history of last logged on users. In Environment where Exchange Servers are used, the exchange servers authentication request for users will also be logged since it also uses EventID (4768) to for TGT Request. You can also export the result to CSV file format. Powershell version 3.0 is needed to use the script.
	* **ADFS**<a name="adfs"></a>
		* [118 Attacking ADFS Endpoints with PowerShell Karl Fosaaen](https://www.youtube.com/watch?v=oTyLdAUjw30)
		* [Using PowerShell to Identify Federated Domains](https://blog.netspi.com/using-powershell-identify-federated-domains/)
		* [LyncSniper: A tool for penetration testing Skype for Business and Lync deployments](https://github.com/mdsecresearch/LyncSniper)
		* [Sniffing and replaying ADFS claims with Fiddler! - Paula Januszkiewicz](https://cqureacademy.com/blog/replaying-adfs-claims-with-fiddler)
		* [Attacking ADFS Endpoints with PowerShell](http://www.irongeek.com/i.php?page=videos/derbycon6/118-attacking-adfs-endpoints-with-powershell-karl-fosaaen)
	* **AdminSDHolder**<a name="adminsd"></a>
		* [Reference Material | Understanding Privileged Accounts and the AdminSDHolder - Specopssoft.com](https://specopssoft.com/support-docs/specops-password-reset/reference-material/understanding-privileged-accounts-and-the-adminsdholder/)
		* [Five common questions about AdminSdHolder and SDProp - blogs.technet](https://blogs.technet.microsoft.com/askds/2009/05/07/five-common-questions-about-adminsdholder-and-sdprop/)
		* [Sneaky Active Directory Persistence #15: Leverage AdminSDHolder & SDProp to (Re)Gain Domain Admin Rights](https://adsecurity.org/?p=1906)
		* [Persistence Using Adminsdholder And Sdprop](https://blog.stealthbits.com/persistence-using-adminsdholder-and-sdprop/)
		* [AdminSDHolder, Protected Groups and SDPROP - John Policelli - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)#id0250006)
	* **ATA**<a name="ATA"></a>
		* [ATA Suspicious Activity Playbook - technet.ms](https://gallery.technet.microsoft.com/ATA-Playbook-ef0a8e38)
	* **(Discretionary)Access Control Lists**<a name="dacl">
		* **Articles/Blogposts/Writeups**
			* [Here Be Dragons The Unexplored Land of Active Directory ACLs - Andy Robbins, Will Schroeder, Rohan(Derbycon7)](https://www.youtube.com/watch?v=bHuetBOeOOQ)
			* [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
			* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
			* [The Unintended Risks of Trusting Active Directory](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)
			* [Exploiting Weak Active Directory Permissions With Powersploit](https://blog.stealthbits.com/exploiting-weak-active-directory-permissions-with-powersploit/)
			* [Abusing Active Directory Permissions with PowerView](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
			* [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
			* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
			* [Active Directory Access Control List – Attacks and Defense](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Active-Directory-Access-Control-List-8211-Attacks-and-Defense/ba-p/250315)
			* [Abusing Active Directory ACLs/ACEs - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
			* [Escalating privileges with ACLs in Active Directory - Rindert Kramer and Dirk-jan Mollema(Fox-IT)](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
			    * During internal penetration tests, it happens quite often that we manage to obtain Domain Administrative access within a few hours. Contributing to this are insufficient system hardening and the use of insecure Active Directory defaults. In such scenarios publicly available tools help in finding and exploiting these issues and often result in obtaining domain administrative privileges. This blogpost describes a scenario where our standard attack methods did not work and where we had to dig deeper in order to gain high privileges in the domain. We describe more advanced privilege escalation attacks using Access Control Lists and introduce a new tool called Invoke-Aclpwn and an extension to ntlmrelayx that automate the steps for this advanced attack.
			* [Viewing Service ACLs - rohnspowershellblog(2013)](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/)
			* [Modifying Service ACLs - rohnspowershellblog(2014)](https://rohnspowershellblog.wordpress.com/2013/04/13/modifying-service-acls/)
				* In my [last post](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/), I showed an early version of a function to get the Discretionary Access Control List (DACL) of a Windows service. In this post, I’m going to show a newer version of that function, along with a function to change the DACL, and a helper function to create Access Control Entries (ACEs). The source code is quite a bit longer, so I’m not going to walk through each bit of code. What I will do is give a brief overview of each of the three functions, along with some examples of how to use them. I’ll also mention where I plan to take the functions in the future. I’ll include the source code of the functions as they currently stand at the end of the post. Included in the source code is comment based help for each of the three functions.
			* [AD Privilege Escalation Exploit: The Overlooked ACL - David Rowe](https://www.secframe.com/blog/ad-privilege-escalation-the-overlooked-acl)
		* **Talks & Presentations**
			* [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
			* [Invoke-ACLpwn](https://github.com/fox-it/Invoke-ACLPwn)
    			* Invoke-ACLpwn is a tool that automates the discovery and pwnage of ACLs in Active Directory that are unsafe configured.
		* **Tools**
			* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
				* A collection of tools to enumerate and analyse Windows DACLs
			* [DAMP - The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.](https://github.com/HarmJ0y/DAMP)
				* This project contains several files that implement host-based security descriptor "backdoors" that facilitate the abuse of various remotely accessible services for arbitrary trustees/security principals. tl;dr - this grants users/groups (local, domain, or 'well-known' like 'Everyone') of an attacker's choosing the ability to perform specific administrative actions on a modified host without needing membership in the local administrators group. Note: to implement these backdoors, you need the right to change the security descriptor information for the targeted service, which in stock configurations nearly always means membership in the local administrators group.
	* **DNS**<a name="dns"></a>
		* **Articles/Blogposts/Writeups**
			* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
			* [From DNSAdmins to Domain Admin, When DNSAdmins is More than Just DNS Administration](https://adsecurity.org/?p=4064)
			* [AD Zone Transfers as a user - mubix](http://carnal0wnage.attackresearch.com/2013/10/ad-zone-transfers-as-user.html)
			* [Feature, not bug: DNSAdmin to DC compromise in one line - Shay Ber](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
			* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
				* Zone transfers are a classical way of performing reconnaissance in networks (or even from the internet). They require an insecurely configured DNS server that allows anonymous users to transfer all records and gather information about host in the network. What not many people know however is that if Active Directory integrated DNS is used, any user can query all the DNS records by default. This blog introduces a tool to do this and describes a method to do this even for records normal users don’t have read rights for.
			* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - Kevin Robertson](https://blog.netspi.com/exploiting-adidns/)
			* [Compiling a DLL using MingGW - mubix](https://malicious.link/post/2020/compiling-a-dll-using-mingw/)
				* Compiling a DLL using MingGW to pull of the DNSAdmins attack
			* [Feature, not bug: DNSAdmin to DC compromise in one line - Shay Ber(2017)](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
			* [Abusing DNSAdmins privilege for escalation in Active Directory - Nikil Mittal(2017)](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
		* **Tools**
			* [DnsCache](https://github.com/malcomvetter/DnsCache)
				* This is a reference example for how to call the Windows API to enumerate cached DNS records in the Windows resolver. Proof of concept or pattern only.
			* [adidnsdump](https://github.com/dirkjanm/adidnsdump)
				* By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones, similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
				* [Blogpost](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
	* **Domain Trusts**<a name="domain-trusts"></a>
		* [Domain Trusts: Why You Should Care](http://www.harmj0y.net/blog/redteaming/domain-trusts-why-you-should-care/)
		* [Trusts You Might Have Missed](http://www.harmj0y.net/blog/redteaming/trusts-you-might-have-missed/)
		* [A Guide to Attacking Domain Trusts - harmj0y](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
		* [Domain Trusts: We’re Not Done Yet - harmj0y](http://www.harmj0y.net/blog/redteaming/domain-trusts-were-not-done-yet/)
		* [The Trustpocalypse - harmj0y](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
		* [Subverting Trust in Windows - Matt Graeber](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
		* [A Guide to Attacking Domain Trusts - harmj0y](https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944)
		* [Trust Direction: An Enabler for Active Directory Enumeration and Trust Exploitation - BOHOPS](https://bohops.com/2017/12/02/trust-direction-an-enabler-for-active-directory-enumeration-and-trust-exploitation/)
	* **Forests**<a name="forests"></a>
		* [How Domain and Forest Trusts Work - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10))
		* [How NOT to use the PAM trust - Leveraging Shadow Principals for Cross Forest Attacks - Nikhil Mittal](http://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)
	* **Groups**
		* [A Pentester’s Guide to Group Scoping - harmj0y](http://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)
	* **Group Policy**<a name="grouppolicy"></a>
		* **101**
			* [Group Policy - Wikipedia](https://en.wikipedia.org/wiki/Group_Policy)
			* [Group Policy Overview - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v%3Dws.11))
			* [Group Policy Architecture - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-architecture)
		* **Articles/Blogposts/Writeups**
			* [Abusing GPO Permissions - harmj0y](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
			* [Sneaky Active Directory Persistence #17: Group Policy](https://adsecurity.org/?p=2716)
			* [A Red Teamer’s Guide to GPOs and OUs](https://wald0.com/?p=179)
			* [File templates for GPO Abuse](https://github.com/rasta-mouse/GPO-Abuse)
			* [GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
			* [Local Group Enumeration - harmj0y](http://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
			* [Where My Admins At? (GPO Edition) - harmj0y](http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/)
			* [Bypassing Group Policy Proxy Settings Using The Windows Registry - Scriptmonkey](http://blog.scriptmonkey.eu/bypassing-group-policy-using-the-windows-registry/)
		* **Talks & Presentations**
			* [Get-GPTrashFire - Mike Loss(BSides Canberra2018)](https://www.youtube.com/watch?v=JfyiWspXpQo)
				* Identifying and Abusing Vulnerable Configurations in MS AD Group Policy
				* [Slides](https://github.com/l0ss/Get-GPTrashfire)
		 **Tools**
			* [Grouper](https://github.com/l0ss/Grouper)
				* Grouper is a slightly wobbly PowerShell module designed for pentesters and redteamers (although probably also useful for sysadmins) which sifts through the (usually very noisy) XML output from the Get-GPOReport cmdlet (part of Microsoft's Group Policy module) and identifies all the settings defined in Group Policy Objects (GPOs) that might prove useful to someone trying to do something fun/evil.
			* [Grouper2](https://github.com/l0ss/Grouper2)
				* Grouper2 is a tool for pentesters to help find security-related misconfigurations in Active Directory Group Policy. It might also be useful for other people doing other stuff, but it is explicitly NOT meant to be an audit tool. If you want to check your policy configs against some particular standard, you probably want Microsoft's Security and Compliance Toolkit, not Grouper or Grouper2.
			* [SharpGPO-RemoteAccessPolicies](https://github.com/mwrlabs/SharpGPO-RemoteAccessPolicies)
				* A C# tool for enumerating remote access policies through group policy.
			* [Get-GPTrashFire](https://github.com/l0ss/Get-GPTrashfire/blob/master/Get-GPTrashFire.pdf)
				* Identifiying and Abusing Vulnerable Configuraitons in MS AD Group Policy
			* [SharpGPOAbuse](https://github.com/mwrlabs/SharpGPOAbuse)
				* SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO. [Blogpost](https://labs.mwrinfosecurity.com/tools/sharpgpoabuse)
			* [GetVulnerableGPO](https://github.com/gpoguy/GetVulnerableGPO)
    			* PowerShell script to find 'vulnerable' security-related GPOs that should be hardended
			* [Policy Plus](https://github.com/Fleex255/PolicyPlus)
				* Local Group Policy Editor plus more, for all Windows editions.
	* **Kerberos**<a name="kerberos"></a>
		* **101**
			* [Kerberos (I): How does Kerberos work? – Theory - Eloy Perez](https://www.tarlogic.com/en/blog/how-kerberos-works/)
			* [Kerberos (II): How to attack Kerberos? - Eloy Perez](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
				* In this article about Kerberos, a few attacks against the protocol will be shown. In order to refresh the concepts behind the following attacks, it is recommended to check the [first part](https://www.tarlogic.com/en/blog/how-kerberos-works/) of this series which covers Kerberos theory.		* [Kerberos Attacks Questions - social.technet.ms](https://social.technet.microsoft.com/Forums/en-US/d8e19263-e4f9-49d5-b940-026b0769420a/kerberos-attacks-questions)
			* [Explain like I’m 5: Kerberos - Lynn Roots](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
			* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall, Benjamin Delpy(BHUSA 2015)](https://www.youtube.com/watch?v=lJQn06QLwEw)
				* Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions.
		* **Articles/Writeups**
			* [How To Attack Kerberos 101 - m0chan](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
			* [Kerberos, Active Directory’s Secret Decoder Ring - Sean Metcalf](https://adsecurity.org/?p=227)
			* [Credential cache - MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html)
			* [Kerberos Authentication problems – Service Principal Name (SPN) issues – Part 1 - blogs.technet](https://blogs.technet.microsoft.com/askds/2008/05/29/kerberos-authentication-problems-service-principal-name-spn-issues-part-1/)
			* [Security Focus: Analysing 'Account is sensitive and cannot be delegated' for Privileged Accounts - Ian Fann(2015)](https://blogs.technet.microsoft.com/poshchap/2015/05/01/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts/)
			* [Delegating like a boss: Abusing Kerberos Delegation in Active Directory - Kevin Murphy](https://www.guidepointsecurity.com/2019/09/04/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)
			    * I wanted to write a post that could serve as a (relatively) quick reference for how to abuse the various types of Kerberos delegation that you may find in an Active Directory environment during a penetration test or red team engagement.
		* **Talks & Presentations**
			* [Attacking Microsoft Kerberos: Kicking the Guard Dog of Hades](https://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin)
				* Kerberos- besides having three heads and guarding the gates of hell- protects services on Microsoft Windows Domains. Its use is increasing due to the growing number of attacks targeting NTLM authentication. Attacking Kerberos to access Windows resources represents the next generation of attacks on Windows authentication.In this talk Tim will discuss his research on new attacks against Kerberos- including a way to attack the credentials of a remote service without sending traffic to the service as well as rewriting tickets to access systems.He will also examine potential countermeasures against Kerberos attacks with suggestions for mitigating the most common weaknesses in Windows Kerberos deployments.
			* [Et tu - Kerberos?](https://www.irongeek.com/i.php?page=videos/derbycon4/t109-et-tu-kerberos-christopher-campbell)
				* For over a decade we have been told that Kerberos is the answer to Microsoft’s authentication woes and now we know that isn’t the case. The problems with LM and NTLM are widely known- but the problems with Kerberos have only recently surfaced. In this talk we will look back at previous failures in order to look forward. We will take a look at what recent problems in Kerberos mean to your enterprise and ways you could possibly mitigate them. Attacks such as Spoofed-PAC- Pass-the-Hash- Golden Ticket- Pass-the-Ticket and Over-Pass-the-Ticket will be explained. Unfortunately- we don’t really know what is next – only that what we have now is broken.
			* [Attacking Kerberos: Kicking the Guard Dog of Hades](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf)
			* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws - Exumbraops.com](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
			* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall and Benjamin Delpy(BHUSA 2014)](https://www.youtube.com/watch?v=lJQn06QLwEw)
				* "Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions. Prepare to have all your assumptions about Kerberos challenged!"
				* [Slides](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It-wp.pdf)
			* [Return From The Underworld - The Future Of Red Team Kerberos - Jim Shaver & Mitchell Hennigan](https://www.irongeek.com/i.php?page=videos/derbycon7/t107-return-from-the-underworld-the-future-of-red-team-kerberos-jim-shaver-mitchell-hennigan)
			* [You (dis)liked mimikatz? Wait for kekeo - Benjamin Delpy(BlueHat IL 2019)](https://www.youtube.com/watch?v=sROKCsXdVDg&feature=youtu.be)
		* **Tools**
			* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws - Geoffrey Janja](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
				* [Slides](https://static1.squarespace.com/static/557377e6e4b0976301e02e0f/t/574a0008f85082d3b6ba88a8/1464467468683/Layer1+2016+-+Janjua+-+Kerberos+Party+Tricks+-+Weaponizing+Kerberos+Protocol+Flaws.pdf)
			* [kekeo](https://github.com/gentilkiwi/kekeo)
				* A little toolbox to play with Microsoft Kerberos in C
			* [PyKEK](https://github.com/bidord/pykek)
				* PyKEK (Python Kerberos Exploitation Kit), a python library to manipulate KRB5-related data. (Still in development)
			* [Kerberom](https://github.com/Fist0urs/kerberom)
				* Kerberom is a tool aimed to retrieve ARC4-HMAC'ed encrypted Tickets Granting Service (TGS) of accounts having a Service Principal Name (SPN) within an Active Directory
			* [Kerbrute - ropnop](https://github.com/ropnop/kerbrute)
				* A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication
			* [kerbrute - Tarlogic](https://github.com/TarlogicSecurity/kerbrute)
				* An script to perform kerberos bruteforcing by using the Impacket library.		
	* **LDAP**<a name="ldap"></a>
		* **Articles/Writeups**
			* [LDAP Swiss Army Knife - Moritz Bechler](https://www.exploit-db.com/docs/english/46986-ldap-swiss-army-knife.pdf)
			* [Fun with LDAP and Kerberos: Attacking AD from non-Windows machines - Ronnie Flathers(TR19)](https://www.youtube.com/watch?v=2Xfd962QfPs)
				* [Slides](https://speakerdeck.com/ropnop/fun-with-ldap-and-kerberos-troopers-19)
			* [Faster Domain Escalation using LDAP - Scott Sutherland](https://blog.netspi.com/faster-domain-escalation-using-ldap/)
			* [LDAP Injection Cheat Sheet, Attack Examples & Protection - Checkmarx](https://www.checkmarx.com/knowledge/knowledgebase/LDAP)
		* **Talks & Presentations**
			* [Fun with LDAP and Kerberos: Attacking AD from non-Windows machines - Ronnie Flathers(Troopers19)](https://www.youtube.com/watch?v=2Xfd962QfPs)
				* [Slides](https://speakerdeck.com/ropnop/fun-with-ldap-and-kerberos-troopers-19)
				* You don’t need Windows to talk to Windows. This talk will explain and walk through various techniques to (ab)use LDAP and Kerberos from non-Windows machines to perform reconnaissance, gain footholds, and maintain persistence, with an emphasis on explaining how the attacks and protocols work. This talk will walk through some lesser known tools and techniques for doing reconnaissance and enumeration in AD environments, as well as gaining an initial foothold, and using credentials in different, stealthier ways (i.e. Kerberos). While tools like Bloodhound, CrackMapExec and Deathstar have made footholds and paths to DA very easy and automated, this talk will instead discuss how tools like this work “under-the-hood” and will stress living off the land with default tools and manual recon and exploitation. After discussing some of the technologies and protocols that make up Active Directory Domain Services, I’ll explain how to interact with these using Linux tools and Python. You don’t need a Windows foothold to talk Windows - everything will be done straight from Linux using DNS, LDAP, Heimdal Kerberos, Samba and Python Impacket.
		* **Tools**
			* [LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump)
				* In an Active Directory domain, a lot of interesting information can be retrieved via LDAP by any authenticated user (or machine). This makes LDAP an interesting protocol for gathering information in the recon phase of a pentest of an internal network. A problem is that data from LDAP often is not available in an easy to read format. ldapdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via LDAP and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files.
			* [windapsearch](https://github.com/ropnop/windapsearch)
				* windapsearch is a Python script to help enumerate users, groups and computers from a Windows domain through LDAP queries. By default, Windows Domain Controllers support basic LDAP operations through port 389/tcp. With any valid domain account (regardless of privileges), it is possible to perform LDAP queries against a domain controller for any AD related information. You can always use a tool like ldapsearch to perform custom LDAP queries against a Domain Controller. I found myself running different LDAP commands over and over again, and it was difficult to memorize all the custom LDAP queries. So this tool was born to help automate some of the most useful LDAP queries a pentester would want to perform in an AD environment.
	* **LAPS**<a name="laps"></a>
		* **101**
			* [Local Administrator Password Solution - docs.ms](https://docs.microsoft.com/en-us/previous-versions/mt227395(v=msdn.10)?redirectedfrom=MSDN)
		* **Articles/Blogposts/Writeups**
			* [Running LAPS with PowerView - harmj0y](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
			* [RastaMouse LAPS Part 1 & 2](https://rastamouse.me/tags/laps/)
			* [Mise en place d'une Backdoor LAPS via modification de l'attribut SearchFlags avec DCShadow - Gregory Lucand](https://adds-security.blogspot.com/2018/08/mise-en-place-dune-backdoor-laps-via.html)
			* [Malicious use of Microsoft LAPS - akijos](https://akijosberryblog.wordpress.com/2019/01/01/malicious-use-of-microsoft-laps/)
			* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon - adsecurity.org](https://adsecurity.org/?p=3164)
			* [Running LAPS Around Cleartext Passwords - Karl Fosaaen](https://blog.netspi.com/running-laps-around-cleartext-passwords/)
		* **Tools**
			* [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
				* Tool to audit and attack LAPS environments
	* **Lync**<a name="lync"></a>
		* [LyncSniper](https://github.com/mdsecresearch/LyncSniper)
			* A tool for penetration testing Skype for Business and Lync deployments
			* [Blogpost/Writeup](https://www.mdsec.co.uk/2017/04/penetration-testing-skype-for-business-exploiting-the-missing-lync/)
		* [LyncSmash](https://github.com/nyxgeek/lyncsmash)
			* a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
			* [Talk](https://www.youtube.com/watch?v=v0NTaCFk6VI)
			* [Slides](https://github.com/nyxgeek/lyncsmash/blob/master/DerbyCon%20Files/TheWeakestLync.pdf)
	* **MachineAccountQuota**
		* [MS-DS-Machine-Account-Quota attribute - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)
			* The number of computer accounts that a user is allowed to create in a domain.
		* [MachineAccountQuota is USEFUL Sometimes: Exploiting One of Active Directory’s Oddest Settings - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)
		* [MachineAccountQuota Transitive Quota: 110 Accounts and Beyond - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-transitive-quota/)
		* [PowerMAD](https://github.com/Kevin-Robertson/Powermad)
			* PowerShell MachineAccountQuota and DNS exploit tools
			* [Blogpost](https://blog.netspi.com/exploiting-adidns/)
	* **MS SQL Server**<a name="mssql"></a>
			* [Hacking SQL Server on Scale with PowerShell - Secure360 2017](https://www.slideshare.net/nullbind/2017-secure360-hacking-sql-server-on-scale-with-powershell)
			* [Using SQL Server for attacking a Forest Trust](http://www.labofapenetrationtester.com/2017/03/using-sql-server-for-attacking-forest-trust.html)
			* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki)
				* [2018 Blackhat USA Arsenal Presentation](https://www.youtube.com/watch?reload=9&v=UX_tBJQtqW0&feature=youtu.be)
			* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server! - Annti Rantasaari(2013)](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
	* **NTLM**<a name="ntlm"></a>
		* [Pwning with Responder – A Pentester’s Guide](https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/)
		* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes)](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
		* [Relaying credentials everywhere with ntlmrelayx](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/)
	* **Read-Only Domain Controllers**<a name="rodc"></a>
		* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)
	* **Red Forest**<a name="redforest"></a>
		* [Attack and defend Microsoft Enhanced Security Administrative](https://download.ernw-insight.de/troopers/tr18/slides/TR18_AD_Attack-and-Defend-Microsoft-Enhanced-Security.pdf)
	* **Service Principal Names**<a name="spn"></a>
		* **101**
			* [Service Principal Names - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)
			* [Service Principal Names - docs.ms(older documentation)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961723(v=technet.10))
			* [Register a Service Principal Name for Kerberos Connections - docs.ms](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-2017)
		* **Articles/Blogposts/Writeups**
			* [Active Directory Pentest Recon Part 1: SPN Scanning aka Mining Kerberos Service Principal Names - Sean Metcalf](https://adsecurity.org/?p=230)
			* [SPN Discovery - pentestlab.blog](https://pentestlab.blog/2018/06/04/spn-discovery/)
			* [Service Principal Name (SPN) - hackndo](https://en.hackndo.com/service-principal-name-spn/)
	* **System Center Configuration Manager**<a name="sccm"></a>
	    * [Targeted Workstation Compromise with SCCM - enigma0x3](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/)
	        * [LM Hash and NT Hash - AD Shot Gyan](http://www.adshotgyan.com/2012/02/lm-hash-and-nt-hash.html)
		* [Using SCCM to violate best practices - cr0n1c](https://cr0n1c.wordpress.com/2016/01/27/using-sccm-to-violate-best-practices/)
	* **Trusts**<a name="trusts"></a>
		* **101**
		* **Articles/Blogposts/Writeups** 
			* [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
			* [It's All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)
			* [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work)
			* [The Forest Is Under Control. Taking over the entire Active Directory forest](https://hackmag.com/security/ad-forest/)
			* [Not A Security Bou* **Read-Only Domain Controllers**
			* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)
			* Not a Security Boundary: Breaking Forest Trusts](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)
			* [Pentesting Active Directory Forests](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
			* [Active Directory forest trusts part 1 - How does SID filtering work? - Dirk-jan Mollema](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
			* [The Trustpocalypse](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
		* **WSUS**<a name="wsus"></a>
			* [WSUSPect - Compromising the Windows Enterprise via Windows Update - Paul Stone, Alex Chapman - BHUS15](https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf)
				* [Blogpost](https://www.contextis.com/en/resources/white-papers/wsuspect-compromising-the-windows-enterprise-via-windows-update))
				* [Slides](https://www.contextis.com/media/downloads/WSUSuspect_Presentation.pdf)
			* [WSuspect Proxy](https://github.com/ctxis/wsuspect-proxy)
				* WSUSpect Proxy - a tool for MITM'ing insecure WSUS connections
			* [WSUSpendu](https://github.com/AlsidOfficial/WSUSpendu)
				* Implement WSUSpendu attack
* **Attack(s/ing)**<a name="adattack"></a>a
	* **Hunting Users**<a name="huntingusers"></a>
		* **Articles/Blogposts/Writeups**
			* [Derivative Local Admin - sixdub](http://www.sixdub.net/?p=591)
			* [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths)
				* Control paths in Active Directory are an aggregation of "control relations" between entities of the domain (users, computers, groups, GPO, containers, etc.) which can be visualized as graphs (such as above) and whose purpose is to answer questions like "Who can get 'Domain Admins' privileges ?" or "What resources can a user control ?" and even "Who can read the CEO's emails ?".
			* [5 Ways to Find Systems Running Domain Admin Processes - Scott Sutherland](https://blog.netspi.com/5-ways-to-find-systems-running-domain-admin-processes/)
			* [Attack Methods for Gaining Domain Admin Rights in Active Directory](https://adsecurity.org/?p"active=2362)
			* [Nodal Analysis of Domain Trusts – Maximizing the Win!](http://www.sixdub.net/?p=285)
			* [Derivative Local Admin - sixdub](https://web.archive.org/web/20170606071124/https://www.sixdub.net/?p=591)
			* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
			* [How Attackers Dump Active Directory Database Credentials](https://adsecurity.org/?p=2398)
			* [“I Hunt Sys Admins”](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)
			* [Gaining Domain Admin from Outside Active Directory - markitzeroday](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
		* **Talks/Videos**
			* [I Hunt Sys Admins - Will Schroeder/@harmj0y(Shmoocon 2015)](https://www.youtube.com/watch?v=yhuXbkY3s0E)
			* [I Hunt Sysadmins 2.0 - slides](http://www.slideshare.net/harmj0y/i-hunt-sys-admins-20)
				* It covers various ways to hunt for users in Windows domains, including using PowerView.
			* [Requiem For An Admin, Walter Legowski (@SadProcessor) - BSides Amsterdam 2017](https://www.youtube.com/watch?v=uMg18TvLAcE&index=3&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
				* Orchestrating BloodHound and Empire for Automated AD Post-Exploitation. Lateral Movement and Privilege Escalation are two of the main steps in the Active Directory attacker kill- chain. Applying the 'assume breach' mentality, more and more companies are asking for red-teaming type of assessments, and security researcher have therefor developed a wide range of open-source tools to assist them during these engagements. Out of these, two have quickly gained a solid reputation: PowerShell Empire and BloodHound (Both by @Harmj0y & ex-ATD Crew). In this Session, I will be presenting DogStrike, a new tool (PowerShell Modules) made to interface Empire & BloodHound, allowing penetration testers to merge their Empire infrastructure into the bloodhound graph database. Doing so allows the operator to request a bloodhound path that is 'Agent Aware', and makes it possible to automate the entire kill chain, from initial foothold to DA - or any desired part of an attacker's routine. Presentation will be demo-driven. Code for the module will be made public after the presentation. Automation of Active Directory post-exploitation is going to happen sooner than you might think. (Other tools are being released with the same goal). Is it a good thing? Is it a bad thing? If I do not run out of time, I would like to finish the presentation by opening the discussion with the audience and see what the consequences of automated post- exploitation could mean, from the red, the blue or any other point of view... : DeathStar by @Byt3Bl33d3r | GoFetch by @TalTheMaor.
		* **Tools**
			* [Check-LocalAdminHash](https://github.com/dafthack/Check-LocalAdminHash)
				* Check-LocalAdminHash is a PowerShell tool that attempts to authenticate to multiple hosts over either WMI or SMB using a password hash to determine if the provided credential is a local administrator. It's useful if you obtain a password hash for a user and want to see where they are local admin on a network.
				* [Blogpost](https://www.blackhillsinfosec.com/check-localadminhash-exfiltrating-all-powershell-history/)
			* [hunter](https://github.com/fdiskyou/hunter)
				* (l)user hunter using WinAPI calls only
			* [icebreaker](https://github.com/DanMcInerney/icebreaker)
				* Automates network attacks against Active Directory to deliver you piping hot plaintext credentials when you're inside the network but outside of the Active Directory environment. Performs 5 different network attacks for plaintext credentials as well as hashes. Autocracks hashes found with JohnTheRipper and the top 10 million most common passwords.
			* [Invoke-HostRecon](https://github.com/dafthack/HostRecon)
				* This function runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.
			* [DeathStar](https://github.com/byt3bl33d3r/DeathStar)
				* DeathStar is a Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory  environments using a variety of techinques.
			* [ANGRYPUPPY](https://github.com/vysec/ANGRYPUPPY)
				* Bloodhound Attack Path Execution for Cobalt Strike
			* [GoFetch](https://github.com/GoFetchAD/GoFetch)
				* GoFetch is a tool to automatically exercise an attack plan generated by the BloodHound application.  GoFetch first loads a path of local admin users and computers generated by BloodHound and converts it to its own attack plan format. Once the attack plan is ready, GoFetch advances towards the destination according to plan step by step, by successively applying remote code execution techniques and compromising credentials with Mimikatz.
			* [DogWhisperer - BloodHound Cypher Cheat Sheet (v2)](https://github.com/SadProcessor/Cheats/blob/master/DogWhispererV2.md)
			* [DomainTrustExplorer](https://github.com/sixdub/DomainTrustExplorer)
				* Python script for analyis of the "Trust.csv" file generated by Veil PowerView. Provides graph based analysis and output.
	* **DCShadow**<a name="dcshadow"></a>
		* [DCShadow](https://www.dcshadow.com/)
			* DCShadow is a new feature in mimikatz located in the lsadump module. It simulates the behavior of a Domain Controller (using protocols like RPC used only by DC) to inject its own data, bypassing most of the common security controls and including your SIEM. It shares some similarities with the DCSync attack (already present in the lsadump module of mimikatz).
		* [DCShadow explained: A technical deep dive into the latest AD attack technique - Luc Delsalle](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)
		* [What is DCShadow? - Stealthbits](https://attack.stealthbits.com/how-dcshadow-persistence-attack-works)
		* [DCShadow: Attacking Active Directory with Rogue DCs - Jeff Warren](https://blog.stealthbits.com/dcshadow-attacking-active-directory-with-rogue-dcs/)
		* [Silently turn off Active Directory Auditing using DCShadow - Nikhil Mittal](http://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html)
		* [Creating Persistence With Dcshadow](https://blog.stealthbits.com/creating-persistence-with-dcshadow/)
	* **DCSync Attack**<a name="dcsync"></a>
		* [What is DCSync? An Introduction - Lee Berg](https://blog.stealthbits.com/what-is-dcsync/)
		* [DCSync - Yojimbo Security](https://yojimbosecurity.ninja/dcsync/)
		* [[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)
		* [Abusing Active Directory Permissions with PowerView - harmj0y](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
		* [DCSync: Dump Password Hashes from Domain Controller - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
		* [Mimikatz DCSync Usage, Exploitation, and Detection - Sean Metcalf](https://adsecurity.org/?p=1729)
		* [Mimikatz and DCSync and ExtraSids, Oh My - harmj0y](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)
		* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)
		* [Extracting User Password Data with Mimikatz DCSync - Jeff Warren](https://blog.stealthbits.com/extracting-user-password-data-with-mimikatz-dcsync/)
	* **Constrained-Delegation**<a name="constrained"></a>
		* **Articles/Blogposts/Writeups**
			* [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
			* [From Kekeo to Rubeus](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
			* [S4U2Pwnage](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
			* [Kerberos Delegation, Spns And More...](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
			* [A Case Study in Wagging the Dog: Computer Takeover - harmj0y](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/)
			* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory - Elad Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
				* Back in March 2018, I embarked on an arguably pointless crusade to prove that the TrustedToAuthForDelegation attribute was meaningless, and that “protocol transition” can be achieved without it. I believed that security wise, once constrained delegation was enabled (msDS-AllowedToDelegateTo was not null), it did not matter whether it was configured to use “Kerberos only” or “any authentication protocol”.  I started the journey with Benjamin Delpy’s (@gentilkiwi) help modifying Kekeo to support a certain attack that involved invoking S4U2Proxy with a silver ticket without a PAC, and we had partial success, but the final TGS turned out to be unusable. Ever since then, I kept coming back to it, trying to solve the problem with different approaches but did not have much success. Until I finally accepted defeat, and ironically then the solution came up, along with several other interesting abuse cases and new attack techniques.
			* [Kerberos Delegation, SPNs and More... - Alberto Solino(2017)](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
				* In this blog post, I will cover some findings (and still remaining open questions) around the Kerberos Constrained Delegation feature in Windows as well as Service Principal Name (SPN) filtering that might be useful when considering using/testing this technology.
			* [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation - Dirk-jan Mollema](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
				* After my in-depth post last month about unconstrained delegation, this post will discuss a different type of Kerberos delegation: resource-based constrained delegation. The content in this post is based on Elad Shamir’s Kerberos research and combined with my own NTLM research to present an attack that can get code execution as SYSTEM on any Windows computer in Active Directory without any credentials, if you are in the same network segment. This is another example of insecure Active Directory default abuse, and not any kind of new exploit.
			* [Kerberos Resource-Based Constrained Delegation: When an Image Change Leads to a Privilege Escalation - Daniel López Jiménez and Simone Salucci](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/august/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)
		* **Talks & Presentations**
			* [Delegate to the Top Abusing Kerberos for Arbitrary Impersonations and RCE - Matan Hart(BHASIA 17)](https://www.youtube.com/watch?v=orkFcTqClIE)
	* **Unconstrained Delegation**<a name="unconstrained"></a>
		* **Articles/Blogposts/Writeups**
			* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain)](https://adsecurity.org/?p=1667)
			* [Unconstrained Delegation Permissions](https://blog.stealthbits.com/unconstrained-delegation-permissions/)
			* [Trust? Years to earn, seconds to break](https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/)
			* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
			* [Getting Domain Admin with Kerberos Unconstrained Delegation - Nikhil Mittal](http://www.labofapenetrationtester.com/2016/02/getting-domain-admin-with-kerberos-unconstrained-delegation.html)
			* [Domain Controller Print Server + Unconstrained Kerberos Delegation = Pwned Active Directory Forest - adsecurity.org](https://adsecurity.org/?p=4056)
			* [[MS-RPRN]: Print System Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)
			* [[MS-RPRN]: Print System Remote Protocol - msdn.ms](https://msdn.microsoft.com/en-us/library/cc244528.aspx)
		* **Talks & Presentations**
			* [The Unintended Risks of Trusting Active Directory - Lee Christensen, Will Schroeder, Matt Nel(Derbycon 2018)](https://www.youtube.com/watch?v=-bcWZQCLk_4)
			    * Your crown jewels are locked in a database, the system is patched, utilizes modern endpoint security software, and permissions are carefully controlled and locked down. Once this system is joined to Active Directory, however, does that static trust model remain the same? Or has the number of attack paths to your data increased by an order of magnitude? We’ve spent the last year exploring the access control model of Active Directory and recently broadened our focus to include security descriptor misconfigurations/backdoor opportunities at the host level. We soon realized that the post-exploitation “attack surface” of Windows hosts spans well beyond what we originally realized, and that host misconfigurations can sometimes have a profound effect on the security of every other host in the forest. This talk will explore a number of lesser-known Active Directory and host-based permission settings that can be abused in concert for remote access, privilege escalation, or persistence. We will show how targeted host modifications (or existing misconfigurations) can facilitate complex Active Directory attack chains with far-reaching effects on other systems and services in the forest, and can allow new AD attack paths to be built without modifying Active Directory itself.
			    * [Slides](https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory)
		* **Tools**
			* [SpoolSample -> NetNTLMv1 -> NTLM -> Silver Ticket](https://github.com/NotMedic/NetNTLMtoSilverTicket)
				* This technique has been alluded to by others, but I haven't seen anything cohesive out there. Below we'll walk through the steps of obtaining NetNTLMv1 Challenge/Response authentication, cracking those to NTLM Hashes, and using that NTLM Hash to sign a Kerberos Silver ticket. This will work on networks where "LAN Manager authentication level" is set to 2 or less. This is a fairly common scenario in older, larger Windows deployments. It should not work on Windows 10 / Server 2016 or newer.
			* [SpoolerScanner](https://github.com/vletoux/SpoolerScanner)
				* Check if the spooler (MS-RPRN) is remotely available with powershell/c#
			* [SpoolSample](https://github.com/leechristensen/SpoolSample)
			    * PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. This is possible via other protocols as well.
	* **Kerberoast(ing)**<a name="kerberoasting"></a>
		* **Articles/Blogposts/Writueps**
			* [Kerberoasting - Part 1 - mubix](https://room362.com/post/2016/kerberoast-pt1/)
			* [Kerberoasting - Part 2 - mubix](https://room362.com/post/2016/kerberoast-pt2/)
			* [Kerberoasting - Part 3 - mubix](https://room362.com/post/2016/kerberoast-pt3/)
			* [Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain - adsecurity.org](https://adsecurity.org/?p=2293)
			* [Kerberoasting Without Mimikatz - Will Schroeder](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
			* [Mimikatz 2.0 - Brute-Forcing Service Account Passwords ](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Brute-Forcing_Service_Account_Passwords.html)
				* If everything about that ticket-generation operation is valid except for the NTLM hash, then accessing the web application will result in a failure. However, this will not cause a failed logon to appear in the Windows® event log. It will also not increment the count of failed logon attempts for the service account. Therefore, the result is an ability to perform brute-force (or, more realistically, dictionary-based) password checks for such a service account, without locking it out or generating suspicious event log entries. 
			* [kerberos, kerberoast and golden tickets - leonjza](https://leonjza.github.io/blog/2016/01/09/kerberos-kerberoast-and-golden-tickets/)
			* [Extracting Service Account Passwords with Kerberoasting - Jeff Warren](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
			* [Cracking Service Account Passwords with Kerberoasting](https://www.cyberark.com/blog/cracking-service-account-passwords-kerberoasting/)
			* [Targeted Kerberoasting - harmj0y](http://www.harmj0y.net/blog/activedirectory/targeted-kerberoasting/)
			* [Kerberoast PW list for cracking passwords with complexity requirements](https://gist.github.com/edermi/f8b143b11dc020b854178d3809cf91b5)
			* [kerberos, kerberoast and golden tickets - leonzja](https://leonjza.github.io/blog/2016/01/09/kerberos-kerberoast-and-golden-tickets/)
			* [Kerberoast - pentestlab.blog](https://pentestlab.blog/2018/06/12/kerberoast/)
			* [A Toast to Kerberoast - Derek Banks](https://www.blackhillsinfosec.com/a-toast-to-kerberoast/)
			* [Kerberoasting, exploiting unpatched systems – a day in the life of a Red Teamer - Chetan Nayak](http://niiconsulting.com/checkmate/2018/05/kerberoasting-exploiting-unpatched-systems-a-day-in-the-life-of-a-red-teamer/)
			* [Discovering Service Accounts Without Using Privileges - Jeff Warren](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
			* [Kerberoasting - Pixis](https://en.hackndo.com/kerberoasting/)
			* [Kerberoasting and SharpRoast output parsing! - grumpy-sec](https://grumpy-sec.blogspot.com/2018/08/kerberoasting-and-sharproast-output.html)
		* **Talks & Presentations**
			* [Attacking Kerberos: Kicking the Guard Dog of Hades - Tim Medin](https://www.youtube.com/watch?v=HHJWfG9b0-E)
				* Kerberos, besides having three heads and guarding the gates of hell, protects services on Microsoft Windows Domains. Its use is increasing due to the growing number of attacks targeting NTLM authentication. Attacking Kerberos to access Windows resources represents the next generation of attacks on Windows authentication.In this talk Tim will discuss his research on new attacks against Kerberos- including a way to attack the credentials of a remote service without sending traffic to the service as well as rewriting tickets to access systems.He will also examine potential countermeasures against Kerberos attacks with suggestions for mitigating the most common weaknesses in Windows Kerberos deployments.
			* [Demo of kerberoasting on EvilCorp Derbycon6](https://adsecurity.org/wp-content/uploads/2016/09/DerbyCon6-2016-AttackingEvilCorp-Anatomy-of-a-Corporate-Hack-Demo-4-kerberoast.mp4)
			* [Attacking EvilCorp Anatomy of a Corporate Hack - Sean Metcalf, Will Schroeder](https://www.youtube.com/watch?v=nJSMJyRNvlM&feature=youtu.be&t=16)
				* [Slides](https://adsecurity.org/wp-content/uploads/2016/09/DerbyCon6-2016-AttackingEvilCorp-Anatomy-of-a-Corporate-Hack-Presented.pdf)
			* [Kerberos & Attacks 101 - Tim Medin(SANS Webcast)](https://www.youtube.com/watch?v=LmbP-XD1SC8)
			    * Want to understand how Kerberos works? Would you like to understand modern Kerberos attacks? If so, then join Tim Medin as he walks you through how to attack Kerberos with ticket attacks and Kerberoasting. Well cover the basics of Kerberos authentication and then show you how the trust model can be exploited for persistence, pivoting, and privilege escalation.
			* [Kerberoasting Revisited - Will Schroeder(Derbycon2019)](https://www.youtube.com/watch?v=yrMGRhyoyGs)
				* Kerberoasting has become the red team'?'s best friend over the past several years, with various tools being built to support this technique. However, by failing to understand a fundamental detail concerning account encryption support, we haven'?'t understood the entire picture. This talk will revisit our favorite TTP, bringing a deeper understanding to how the attack works, what we?ve been missing, and what new tooling and approaches to kerberoasting exist.
		* **Tools**
			* [kerberoast](https://github.com/nidem/kerberoast)
				* Kerberoast is a series of tools for attacking MS Kerberos implementations.
			* [tgscrack](https://github.com/leechristensen/tgscrack)
			   	* Kerberos TGS_REP cracker written in Golang
		* **AS-REP**
			* [Roasting AS-REPs - harmj0y](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
				* tl;dr – if you can enumerate any accounts in a Windows domain that don’t require Kerberos preauthentication, you can now easily request a piece of encrypted information for said accounts and efficiently crack the material offline, revealing the user’s password.
	* **Pass-the-`*`**<a name="pth"></a>
		* **101**
		* **Cache**
			* [Tweet by Benjamin Delpy(2014)](https://twitter.com/gentilkiwi/status/536489791735750656?lang=en&source=post_page---------------------------)
			* [Pass-the-Cache to Domain Compromise - Jamie Shaw](https://medium.com/@jamie.shaw/pass-the-cache-to-domain-compromise-320b6e2ff7da)
				* This post is going to go over a very quick domain compromise by abusing cached Kerberos tickets discovered on a Linux-based jump-box within a Windows domain environment. In essence, we were able to steal cached credentials from a Linux host and use them on a Window-based system to escalate our privileges to domain administrator level.
		* **Hash**
			* For this kind of attack and related ones, check out the Network Attacks page, under Pass-the-Hash.
			* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - harmj0y](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
			* [Windows Credential Guard & Mimikatz - nviso](https://blog.nviso.be/2018/01/09/windows-credential-guard-mimikatz/)
			* [Wendel's Small Hacking Tricks - The Annoying NT_STATUS_INVALID_WORKSTATION](https://www.trustwave.com/Resources/SpiderLabs-Blog/Wendel-s-Small-Hacking-Tricks---The-Annoying-NT_STATUS_INVALID_WORKSTATION-/)
			* [Passing the hash with native RDP client (mstsc.exe)](https://michael-eder.net/post/2018/native_rdp_pass_the_hash/)
				* TL;DR: If the remote server allows Restricted Admin login, it is possible to login via RDP by passing the hash using the native 	Windows RDP client mstsc.exe. (You’ll need mimikatz or something else to inject the hash into the process)
			* [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)
				* Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB services are accessed through .NET TCPClient connections. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
			* [Pass-The-Hash with RDP in 2019 - shellz.club](https://shellz.club/pass-the-hash-with-rdp-in-2019/)
			* [Pass the Hash - hackndo](https://en.hackndo.com/pass-the-hash/)
			* [Pass-the-Hash Web Style - SANS](https://pen-testing.sans.org/blog/2013/04/05/pass-the-hash-web-style)
		* **Over-Pass-the-Hash**
			* [Overpass-the-hash - Benjamin Delpy](http://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
			* [AD Security – Overpass-the-Hash Scenario - Eli Shlomo](https://www.eshlomo.us/ad-security-overpass-the-hash-scenario/)
		* **Ticket**
			* [How To Pass the Ticket Through SSH Tunnels](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
			* [Pass-the-ticket - ldapwiki](http://ldapwiki.com/wiki/Pass-the-ticket)
			* [Silver & Golden Tickets - hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/)
			* **Silver**
				* [Sneaky Active Directory Persistence #16: Computer Accounts & Domain Controller Silver Tickets - adsecurity](https://adsecurity.org/?p=2753)
				* [Impersonating Service Accounts with Silver Tickets - stealthbits](https://blog.stealthbits.com/impersonating-service-accounts-with-silver-tickets)
				* [Mimikatz 2.0 - Silver Ticket Walkthrough](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Silver_Ticket_Walkthrough.html)
				* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
			* **Golden**
				* [mimikatz - golden ticket](http://rycon.hu/papers/goldenticket.html)
				* [Golden Ticket - ldapwiki](http://ldapwiki.com/wiki/Golden%20Ticket)
				* [Advanced Targeted Attack. PoC Golden Ticket Attack - BSides Tampa 17](https://www.irongeek.com/i.php?page=videos/bsidestampa2017/102-advanced-targeted-attack-andy-thompson)
				* [Complete Domain Compromise with Golden Tickets - stealthbits](https://blog.stealthbits.com/complete-domain-compromise-with-golden-tickets/)
				* [Pass-the-(Golden)-Ticket with WMIC](https://blog.cobaltstrike.com/2015/01/07/pass-the-golden-ticket-with-wmic/)
				* [Kerberos Golden Tickets are Now More Golden - ADSecurity.org](https://adsecurity.org/?p=1640)
				* [Mimikatz 2.0 - Golden Ticket Walkthrough - Ben Lincoln](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html)
	* **Shadow Admins(ACLs)**<a name="shadowadmin"></a>
		* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most - Asaf Hecht](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
		* [ACLight](https://github.com/cyberark/ACLight)
			* ACLight is a tool for discovering privileged accounts through advanced ACLs analysis (objects’ ACLs - Access Lists, aka DACL\ACEs). It includes the discovery of Shadow Admins in the scanned network.
	* **(NTLM)SMB Relay**
		* See `Network_Attacks.md`
		* [Redirect to SMB - Cylance SPEAR](https://blog.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf)
	* **Skeleton Key**<a name="skeleton"></a>
		* [Active Directory Domain Controller Skeleton Key Malware & Mimikatz - ADSecurity](https://adsecurity.org/?p=1255)
		* [Skeleton Key Malware Analysis - SecureWorks](https://www.secureworks.com/research/skeleton-key-malware-analysis)
		* [Unlocking All The Doors To Active Directory With The Skeleton Key Attack](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)
		* [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
		* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)
	* **Specific Vulnerabilities**"<a name="advulns"></a>
		* **MS14-068**
			* **About**
				* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege](https://adsecurity.org/?p=525)
				* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege - adsecurity.org](https://adsecurity.org/?p=525)
				* [Kerberos Vulnerability in MS14-068 (KB3011780) Explained - adsecurity.org](https://adsecurity.org/?p=541)
				* [Detecting MS14-068 Kerberos Exploit Packets on the Wire aka How the PyKEK Exploit Works - adsecurity.org](https://adsecurity.org/?p=763)
				* [Exploiting MS14-068 Vulnerable Domain Controllers Successfully with the Python Kerberos Exploitation Kit (PyKEK) - adsecurity.org](https://adsecurity.org/?p=676)
				* [Digging into MS14-068, Exploitation and Defence - Ben Campbell, Jon Cave](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
			* **Exploiting**
				* [Digging into MS14-068, Exploitation and Defence](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
				* [From MS14-068 to Full Compromise - Stepy by Step - David Kennedy](https://www.trustedsec.com/2014/12/ms14-068-full-compromise-step-step/)
				* [Microsoft Security Bulletin MS14-068 - Critical - docs.ms](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068)
				* [Exploiting MS14-068 with PyKEK and Kali - Zach Grace](https://zachgrace.com/posts/exploiting-ms14-068/)
				* [Exploiting MS14-068 Vulnerable Domain Controllers Successfully with the Python Kerberos Exploitation Kit (PyKEK) - adsecurity.org](https://adsecurity.org/?p=676)
		* **MS15-011**
			* [Practically Exploiting MS15-014 and MS15-011 - MWR](https://labs.mwrinfosecurity.com/blog/practically-exploiting-ms15-014-and-ms15-011/)
			* [MS15-011 - Microsoft Windows Group Policy real exploitation via a SMB MiTM attack - coresecurity](https://www.coresecurity.com/blog/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack)
* **WIP**
	* **Defense Evasion**<a name="addefev"></a>
		* [Evading Microsoft ATA for Active Directory Domination - Nikhil Mittal](https://www.youtube.com/watch?v=bHkv63-1GBY)
			* Microsoft Advanced Threat Analytics (ATA) is a defense platform which reads information from multiple sources like traffic for certain protocols to the Domain Controller, Windows Event Logs and SIEM events. The information thus collected is used to detect Reconnaissance, Credentials replay, Lateral movement, Persistence attacks etc. Well known attacks like Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Golden Ticket, Directory services replication, Brute-force, Skeleton key etc. can be detected using ATA. 
		* [Red Team Techniques for Evading, Bypassing & Disabling MS - Chris Thompson]
			* Windows Defender Advanced Threat Protection is now available for all Blue Teams to utilize within Windows 10 Enterprise and Server 2012/16, which includes detection of post breach tools, tactics and techniques commonly used by Red Teams, as well as behavior analytics. 
			* [Slides](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
	* **Collection**<a name="adcollect"></a>
		* [Accessing Internal Fileshares through Exchange ActiveSync - Adam Rutherford and David Chismon](https://labs.mwrinfosecurity.com/blog/accessing-internal-fileshares-through-exchange-activesync)
	* **Credential Access**<a name="adcred"></a>
		* **Articles/Blogposts/Writeups**
			* [Remotely dump "Active Directory Domain Controller" machine user database using web shell - Indishell](http://www.mannulinux.org/2018/12/remotely-dump-active-directory-domain.html)
			* [Auto-Dumping Domain Credentials using SPNs, PowerShell Remoting, and Mimikatz - Scott Sutherland](https://blog.netspi.com/auto-dumping-domain-credentials-using-spns-powershell-remoting-and-mimikatz/)
			* [How Attackers Dump Active Directory Database Credentials - adsecurity.org](https://adsecurity.org/?p=2398)
			* [Places of Interest in Stealing NetNTLM Hashes - osandamalith.com](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
			* [Multi-Factor Mixup: Who Were You Again? - Okta](https://www.okta.com/security-blog/2018/08/multi-factor-authentication-microsoft-adfs-vulnerability/)
				* A weakness in the Microsoft ADFS protocol for integration with MFA products allows a second factor for one account to be used for second-factor authentication to all other accounts in an organization.
			* [Playing with Relayed Credentials - SecureAuth](https://www.secureauth.com/blog/playing-relayed-credentials)
			* [When Everyone's Dog is Named Fluffy: Abusing the Brand New Security Questions in Windows 10 to Gain Domain-Wide Persistence - Magal Baz, Tom Sela](https://www.blackhat.com/eu-18/briefings/schedule/index.html#when-everyone39s-dog-is-named-fluffy-abusing-the-brand-new-security-questions-in-windows-10-to-gain-domain-wide-persistence-12863)
				* [Slides](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Baz-When-Everyones-Dog-Is-Named-Fluffy.pdf)
			* [Active Directory Enumeration with PowerShell - Haboob](https://www.exploit-db.com/docs/english/46990-active-directory-enumeration-with-powershell.pdf)
				* Nowadays, most of the environments are using Active Directory to manage their networks and resources. And over the past years, the attackers have been focused to abuse and attack the Active Directory environments using different techniques and methodologies. So in this research paper, we are going to use the power of the PowerShell to enumerate the resources of the Active Directory, like enumerating the domains, users, groups, ACL, GPOs, domain trusts also hunting the users and the domain admins. With this valuable information, we can increase our attack surface to abuse the AD like Privilege escalation, lateral movements and persistence and so on.
			* [Cached Credentials: Important Facts That You Cannot Miss - CQURE](https://cqureacademy.com/blog/windows-internals/cached-credentials-important-facts)
			* [Protect derived domain credentials with Windows Defender Credential Guard - docs.ms](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
			* [KB2871997 and Wdigest - Part 1 - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/kfalde/kb2871997-and-wdigest-part-1)
			* [Clearing cached/saved Windows credentials - University of Waterloo](https://uwaterloo.teamdynamix.com/TDClient/1804/Portal/KB/ArticleDet?ID=69756)
			* [Cached domain logon information - support.ms](https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information)
			* [Interactive logon: Number of previous logons to cache (in case domain controller is not available) - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available)
			* [Interactive logon: Number of previous logons to cache (in case domain controller is not available - UltimateWindowsSecurity](https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=ILNumPrev)
			* [Using Domain Controller Account Passwords To HashDump Domains - Mubix](https://room362.blogspot.com/2015/09/using-domain-controller-account.html)
		* **Presentations/Talks/Videos**
		* **Tools**
			* [DomainPasswordTest](https://github.com/rvazarkar/DomainPasswordTest)
				* Tests AD passwords while respecting Bad Password Count
			* [serviceFu](https://github.com/securifera/serviceFu)
				* Automates credential skimming from service accounts in Windows Registry using Mimikatz lsadump::secrets. The use case for this tool is when you have administrative rights across certain computers in a domain but do not have any clear-text credentials. ServiceFu will remotely connect to target computers, check if any credentialed services are present, download the system and security registry hive, and decrypt clear-text credentials for the domain service account.
			* [Credential Assessment: Mapping Privilege Escalation at Scale - Matt Weeks(Hack.lu 2016)](https://www.youtube.com/watch?v=tXx6RB0raEY)
				* In countless intrusions from large retail giants to oil companies, attackers have progressed from initial access to complete network compromise. In the aftermath, much ink is spilt and products are sold on how the attackers first obtained access and how the malware they used could or could not have been detected, while little attention is given to the credentials they found that turned their access on a single-system into thousands more. This process, while critical for offensive operations, is often complex, involving many links in the escalation chain composed of obtaining credentials on system A that grant access to system B and credentials later used on system B that grant further access, etc. We’ll show how to identify and combat such credential exposure at scale with the framework we developed. We comprehensively identify exposed credentials and automatically construct the compromise chains to identify maximal access and privileges gained, useful for either offensive or defensive purposes.
	* **Persistence**<a name="adpersist"></a>
		* [The Active Directory Botnet - Ty Miller, Paul Kalinin(BHUSA 17)](https://www.blackhat.com/docs/us-17/wednesday/us-17-Miller-The-Active-Directory-Botnet.pdf)
		* [Command and Control Using Active Directory - harmj0y](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
		* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP) - adsecurity.org](https://adsecurity.org/?p=1760)
	* **Privilege Escalation**<a name="adprivesc"></a>
		* **ACEs/ACLs/DACLs**
			* [DACL Permissions Overwrite Privilege Escalation (CVE-2019-0841) - Nabeel Ahmed](https://krbtgt.pw/dacl-permissions-overwrite-privilege-escalation-cve-2019-0841/)
				* This vulnerability allows low privileged users to hijack file that are owned by NT AUTHORITY\SYSTEM by overwriting permissions on the targeted file. Successful exploitation results in "Full Control" permissions for the low privileged user.
			* [Microsoft Exchange – ACL - NetbiosX](https://pentestlab.blog/2019/09/12/microsoft-exchange-acl/)
		* **Aiming for DA**
			* [Post-Exploitation in Windows: From Local Admin To Domain Admin (efficiently) - pentestmonkey](http://pentestmonkey.net/uncategorized/from-local-admin-to-domain-admin))
			* [Scenario-based pen-testing: From zero to domain admin with no missing patches required - Georgia Weidman](https://www.computerworld.com/article/2843632/scenario-based-pen-testing-from-zero-to-domain-admin-with-no-missing-patches-required.html)
			* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
			* [Attack Methods for Gaining Domain Admin Rights in Active Directory - adsecurity](https://adsecurity.org/?p=2362)
			* [Gaining Domain Admin from Outside Active Directory - markitzeroday.com](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
		* **Group Policy**
			* [How to own any windows network with group policy hijacking attacks](https://labs.mwrinfosecurity.com/blog/2015/04/02/how-to-own-any-windows-network-with-group-policy-hijacking-attacks/)
		* **One-offs**
			* [Gone to the Dogs - Elad Shamir](https://shenaniganslabs.io/2019/08/08/Lock-Screen-LPE.html)
				* Win10 PrivEsc Domain Joined
			* [CVE-2018-8340: Multi-Factor Mixup: Who Were You Again? - Andrew Lee](https://www.okta.com/security-blog/2018/08/multi-factor-authentication-microsoft-adfs-vulnerability)
				* A weakness in the Microsoft ADFS protocol for integration with MFA products allows a second factor for one account to be used for second-factor authentication to all other accounts in an organization.
	* [MS CVE-2018-8340](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8340)
		* **Tools**
			* [ADAPE-Script](https://github.com/hausec/ADAPE-Script)
			    * Active Directory Assessment and Privilege Escalation Script
	* **Reconaissance**<a name="adrecon"></a>
		* **Articles/Blogposts/Presentations/Talks/Writeups**
			* [Active Directory Firewall Ports – Let’s Try To Make This Simple - Ace Fekay(2011)](https://blogs.msmvps.com/acefekay/2011/11/01/active-directory-firewall-ports-let-s-try-to-make-this-simple/)
			* [Automating the Empire with the Death Star: getting Domain Admin with a push of a button](https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html)
			* [Active Directory Pentest Recon Part 1: SPN Scanning aka Mining Kerberos Service Principal Names](https://adsecurity.org/?p=230)
			* [Active Directory Recon Without Admin Rights - adsecurity](https://adsecurity.org/?p=2535)
			* [Using ActiveDirectory module for Domain Enumeration from PowerShell Constrained Language Mode - Nikhil Mittal](http://www.labofapenetrationtester.com/2018/10/domain-enumeration-from-PowerShell-CLM.html)
			* [Kerberos Domain Username Enumeration - matt](https://www.attackdebris.com/?p=311)
			* [adcli info - Fedora documentation](https://fedoraproject.org/wiki/QA:Testcase_adcli_info)
			* [adcli info forest - Fedora documentation](https://fedoraproject.org/wiki/QA:Testcase_adcli_info_forest)
			* [AD Zone Transfers as a user - mubix](https://malicious.link/post/2013/ad-zone-transfers-as-a-user/)
			* [Gathering AD Data with the Active Directory PowerShell Module - ADSecurity.com](https://adsecurity.org/?p=3719)
			* [Enumerating remote access policies through GPO - William Knowles, Jon Cave](https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/)
		* **Tools**
			* **BloodHound**
				* **101**
					* [Introducing BloodHound](https://wald0.com/?p=68)
					* [Bloodhound 2.2 - A Tool for Many Tradecrafts - Andy Gill](https://blog.zsec.uk/bloodhound-101/)
				* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
					* BloodHound is a single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a PowerShell ingestor. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.
				* **Articles/Blogposts/Writeups**
					* [BloodHound and the Adversary Resilience Model](https://docs.google.com/presentation/d/14tHNBCavg-HfM7aoeEbGnyhVQusfwOjOyQE1_wXVs9o/mobilepresent#slide=id.g35f391192_00)
					* [Introducing the Adversary Resilience Methodology — Part One - Andy Robbins](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
					* [Introducing the Adversary Resilience Methodology — Part Two - Andy Robbins](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
				* **Historical Posts**
					* [Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win. - JohnLaTwC](https://github.com/JohnLaTwC/Shared/blob/master/Defenders%20think%20in%20lists.%20Attackers%20think%20in%20graphs.%20As%20long%20as%20this%20is%20true%2C%20attackers%20win.md)
					* [Automated Derivative Administrator Search - wald0](https://wald0.com/?p=14)
					* [BloodHound 1.3 – The ACL Attack Path Update - wald0](https://wald0.com/?p=112)	
					* [BloodHound 1.4: The Object Properties Update - CptJesus](https://blog.cptjesus.com/posts/bloodhoundobjectproperties)
					* [SharpHound: Target Selection and API Usage](https://blog.cptjesus.com/posts/sharphoundtargeting)	
					* [BloodHound 1.5: The Container Update](https://blog.cptjesus.com/posts/bloodhound15)
					* [A Red Teamer’s Guide to GPOs and OUs - wald0](https://wald0.com/?p=179)
					* [BloodHound 2.0 - CptJesus](https://blog.cptjesus.com/posts/bloodhound20)
					* [BloodHound 2.1: The Fix Broken Stuff Update - Rohan Vazarkar](https://posts.specterops.io/bloodhound-2-1-the-fix-broken-stuff-update-4d28ff732b1)
				* **Using**
					* [BloodHound: Intro to Cypher - CptJesus](https://blog.cptjesus.com/posts/introtocypher)
					* [The Dog Whisperer's Handbook: A Hacker's Guide to the BloodHound Galaxy - @SadProcessor](https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf)
						* [Blogpost](https://insinuator.net/2018/11/the-dog-whisperers-handbook/)
					* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
					* [Lay of the Land with BloodHound](http://threat.tevora.com/lay-of-the-land-with-bloodhound/)
					* [Bloodhound walkthrough. A Tool for Many Tradecrafts - Andy Gill](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)
						* A walkthrough on how to set up and use BloodHound
					* [BloodHound From Red to Blue - Mathieu Saulnier(BSides Charm2019)](https://www.youtube.com/watch?v=UWY772iIq_Y)
					* [BloodHound Tips and Tricks - Riccardo Ancarani](https://blog.riccardoancarani.it/bloodhound-tips-and-tricks/)
				* **Neo4j**
					* [Neo4j Cypher Refcard 3.5](https://neo4j.com/docs/cypher-refcard/current/)
				* **Extending Functionality**
					* [Visualizing BloodHound Data with PowerBI — Part 1 - Andy Robbins](https://posts.specterops.io/visualizing-bloodhound-data-with-powerbi-part-1-ba8ea4908422)
					* [Visualizing BloodHound Data with PowerBI — Part 2 - Andy Robbins](https://posts.specterops.io/visualizing-bloodhound-data-with-powerbi-part-2-3e1c521fb7ae)
					* [Extending BloodHound: Track and Visualize Your Compromise](https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise/)
						* Customizing BloodHound's UI and taking advantage of Custom Queries to document a compromise, find collateral spread of 	owned nodes, and visualize deltas in privilege gains.
					* [Extending BloodHound Part 1 - GPOs and User Right Assignment - Riccardo Ancarani](https://riccardoancarani.github.io/2020-02-06-extending-bloodhound-pt1/)
					* [Cypheroth](https://github.com/seajaysec/cypheroth)
						* Automated, extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets.
				* **Ingestors**
					* [BloodHound.py](https://github.com/fox-it/BloodHound.py)
						* A Python based ingestor for BloodHound
				* **API**
					* [CypherDog](https://github.com/SadProcessor/CypherDog)
						* PowerShell Cmdlets to interact with BloodHound Data via Neo4j REST API
			* **Domain Reconaissance**
				* [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
				* [PywerView](https://github.com/the-useless-one/pywerview)
					* A (partial) Python rewriting of PowerSploit's PowerView.
				* [The PowerView PowerUsage Series #1 - harmjoy](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-1/)
					* [Part #2](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-2/)
					* [Part #3](https://posts.specterops.io/the-powerview-powerusage-series-3-f46089b3cc43)
					* [Part #4](https://posts.specterops.io/the-powerview-powerusage-series-4-e8d408c15c95)
					* [Part #5](https://posts.specterops.io/the-powerview-powerusage-series-5-7ca3ebb23927)
				* [goddi](https://github.com/NetSPI/goddi)
					* goddi (go dump domain info) dumps Active Directory domain information
				* [ADRecon](https://github.com/adrecon/ADRecon)
					* ADRecon is a tool which extracts and combines various artefacts (as highlighted below) out of an AD environment. The information can be presented in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis and provide a holistic picture of the current state of the target AD environment. The tool is useful to various classes of security professionals like auditors, DFIR, students, administrators, etc. It can also be an invaluable post-exploitation tool for a penetration tester. It can be run from any workstation that is connected to the environment, even hosts that are not domain members. Furthermore, the tool can be executed in the context of a non-privileged (i.e. standard domain user) account. Fine Grained Password Policy, LAPS and BitLocker may require Privileged user accounts. The tool will use Microsoft Remote Server Administration Tools (RSAT) if available, otherwise it will communicate with the Domain Controller using LDAP.
				* [AdEnumerator](https://github.com/chango77747/AdEnumerator)
					* Active Directory enumeration from non-domain system. Powershell script
				* [Orchard](https://github.com/its-a-feature/Orchard)
					* Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS' JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web.
				* [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
					* AD PowerShell Recon Scripts
				* [ADCollector](https://github.com/dev-2null/ADCollector)
					* A lightweight tool that enumerates the Active Directory environment to identify possible attack vectors
				* [AdsiPS](https://github.com/lazywinadmin/AdsiPS)
					* PowerShell module to interact with Active Directory using ADSI and the `System.DirectoryServices` namespace (.NET Framework).
				* [jackdaw](https://github.com/skelsec/jackdaw)
					* Jackdaw is here to collect all information in your domain, store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
			* **Local Machine**
				* [HostEnum](https://github.com/threatexpress/red-team-scripts)
					* A PowerShell v2.0 compatible script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain, it can also perform limited domain enumeration with the -Domain switch. However, domain enumeration is significantly limited with the intention that PowerView or BoodHound could also be used.
			* **Passwords**
				* [NtdsAudit](https://github.com/Dionach/NtdsAudit)
					* NtdsAudit is an application to assist in auditing Active Directory databases. It provides some useful statistics relating to accounts and passwords. It can also be used to dump password hashes for later cracking.
			* **Service Principal Name(SPN) Scanning**
				* [Service Principal Names - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/AD/service-principal-names)
				* [SPNs - adsecurity.org](https://adsecurity.org/?page_id=183)
					* This page is a comprehensive reference (as comprehensive as possible) for Active Directory Service Principal Names (SPNs). As I discover more SPNs, they will be added.
				* [Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe - social.technet.ms.com)](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx)
				* [SPN Discovery - pentestlab.blog](https://pentestlab.blog/2018/06/04/spn-discovery/)
				* [Discovering Service Accounts Without Using Privileges - Jeff Warren](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
		* **Miscellaneous Tools**
			* [ActiveReign](https://github.com/m8r0wn/ActiveReign)
				* A Network Enumeration and Attack Toolset
			* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
				* A swiss army knife for pentesting networks
			* [Windows Vault Password Dumper](http://www.oxid.it/downloads/vaultdump.txt)
				* The following code shows how to use native undocumented functions of Windows Vault API to enumerate and extract credentials stored by Microsoft Windows Vault. The code has been successfully tested on Windows7 and Windows8 operating systems.
			* [knit_brute.sh](https://gist.github.com/ropnop/8711392d5e1d9a0ba533705f7f4f455f)
				* A quick tool to bruteforce an AD user's password by requesting TGTs from the Domain Controller with 'kinit'
			* [BTA](https://bitbucket.org/iwseclabs/bta)
				* BTA is an open-source Active Directory security a5udit framework.
			* [WinPwn](https://github.com/SecureThisShit/WinPwn)
			    * Automation for internal Windows Penetrationtest / AD-Security
			* [Check-LocalAdminHash & Exfiltrating All PowerShell History - Beau Bullock](https://www.blackhillsinfosec.com/check-localadminhash-exfiltrating-all-powershell-history/)
				* Check-LocalAdminHash is a new PowerShell script that can check a password hash against multiple hosts to determine if it’s a valid administrative credential. It also has the ability to exfiltrate all PowerShell PSReadline console history files from every profile on every system that the credential provided is an administrator of.
			* [Check-LocalAdminHash](https://github.com/dafthack/Check-LocalAdminHash)
				* Check-LocalAdminHash is a PowerShell tool that attempts to authenticate to multiple hosts over either WMI or SMB using a password hash to determine if the provided credential is a local administrator. It's useful if you obtain a password hash for a user and want to see where they are local admin on a network. It is essentially a Frankenstein of two of my favorite tools along with some of my own code. It utilizes Kevin Robertson's (@kevin_robertson) Invoke-TheHash project for the credential checking portion. Additionally, the script utilizes modules from PowerView by Will Schroeder (@harmj0y) and Matt Graeber (@mattifestation) to enumerate domain computers to find targets for testing admin access against.
			* [Wireless_Query](https://github.com/gobiasinfosec/Wireless_Query)
				* Query Active Directory for Workstations and then Pull their Wireless Network Passwords. This tool is designed to pull a list of machines from AD and then use psexec to pull their wireless network passwords. This should be run with either a DOMAIN or WORKSTATION Admin account.
			* [Find AD users with empty password using PowerShell](https://4sysops.com/archives/find-ad-users-with-empty-password-passwd_notreqd-flag-using-powershell/)
			* [ACLight](https://github.com/cyberark/ACLight)
				* The tool queries the Active Directory (AD) for its objects' ACLs and then filters and analyzes the sensitive permissions of each one. The result is a list of domain privileged accounts in the network (from the advanced ACLs perspective of the AD). You can run the scan with just any regular user (could be non-privileged user) and it automatically scans all the domains of the scanned network forest.
			* [zBang](https://github.com/cyberark/zBang)
				* zBang is a special risk assessment tool that detects potential privileged account threats in the scanned network.
				* [Blogpost](https://www.cyberark.com/threat-research-blog/the-big-zbang-theory-a-new-open-source-tool/)



















-------------
### <a name="email"></a>Email/Microsoft Exchange
* **Look at the phishing page**
	* [Link to the Phishing page - Markdown](./Phishing.md)
	* [Link to the Phishing page - HTML](./Phishing.html)
* **Articles/Blogposts/Writeups**
	* [Microsoft Exchange – Password Spraying - pentestlab.blog](https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/)
	* [Microsoft Exchange – Domain Escalation - pentestlab.blog](https://pentestlab.blog/2019/09/04/microsoft-exchange-domain-escalation/)
	* [Microsoft Exchange – Mailbox Post Compromise - NetbiosX](https://pentestlab.blog/2019/09/11/microsoft-exchange-mailbox-post-compromise/)
* **Privilege Escalation (ab)using**
	* [Abusing Exchange: One API call away from Domain Admin - dirkjanm.io](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
	* [Red Teaming Made Easy with Exchange Privilege Escalation and PowerPriv - RedXORBlue](http://blog.redxorblue.com/2019/01/red-teaming-made-easy-with-exchange.html)
* **Tools**
	* [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
		* This repository provides a few techniques and scripts regarding the impact of Microsoft Exchange deployment on Active Directory security. This is a side project of [AD-Control-Paths](https://github.com/ANSSI-FR/AD-control-paths), an AD permissions auditing project to which I recently added some Exchange-related modules.
	* [Abusing Exchange: One API call away from Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
	* [Exploiting PrivExchange - chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
		* expansion and demo of how to use the PrivExchange exploit
	* [MailSniper](https://github.com/dafthack/MailSniper)
		* MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an Exchange administrator to search the mailboxes of every user in a domain. MailSniper also includes additional modules for password spraying, enumerating users/domains, gathering the Global Address List from OWA and EWS, and checking mailbox permissions for every Exchange user at an organization.
	* [PowerPriv](https://github.com/G0ldenGunSec/PowerPriv)
		* A powershell implementation of PrivExchange by `@_dirkjan` (original code found here: https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py) Useful for environments on which you cannot run python-based applications, have user credentials, or do not want to drop files to disk. Will cause the target exchange server system account to attempt to authenticate to a system of your choice.
	* [exchange_hunter2](https://github.com/aslarchergore/exchange_hunter2)
		* This script uses a valid credential, a DC IP and Hostname to log into the DC over LDAP and query the LDAP server for the wherabouts of the Microsoft Exchange servers in the environment.







---------------------
### <a name="Pivoting">Pivoting</a>
* **Pivoting** <a name="pivot"></a>
	* **Articles/Writeups**
		* [A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/#corporate-http-proxy-as-a-way-out)
		* [Pivoting into a network using PLINK and FPipe](http://exploit.co.il/hacking/pivoting-into-a-network-using-plink-and-fpipe/)
		* [Pillage the Village Redux w/ Ed Skoudis & John Strand - SANS](https://www.youtube.com/watch?v=n2nptntIsn4)
		* [Browser Pivot for Chrome - cplsec](https://ijustwannared.team/2019/03/11/browser-pivot-for-chrome/)
		* [Browser Pivoting (Get past two-factor auth) - blog.cobalstrike](https://blog.cobaltstrike.com/2013/09/26/browser-pivoting-get-past-two-factor-auth/)
		* [Windows Domains, Pivot & Profit - Fuzzynop](http://www.fuzzysecurity.com/tutorials/25.html)
    		* Hola! In this write-up we will be looking at different ways to move laterally when compromising a Windows domain. This post is by no means exhaustive but it should cover some of the more basic techniques and thought processes.
		* **Bash**
			* [More on Using Bash's Built-in /dev/tcp File (TCP/IP)](http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip)
		* **Metasploit**
			* [Portfwd - Pivot from within meterpreter](http://www.offensive-security.com/metasploit-unleashed/Portfwd)
			* [Reverse SSL backdoor with socat and metasploit (and proxies)](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)
		* **SSH**
			* [Pivoting Ssh Reverse Tunnel Gateway](http://blog.oneiroi.co.uk/linux/pivoting-ssh-reverse-tunnel-gateway/)
			* [SSH Gymnastics and Tunneling with ProxyChains](http://magikh0e.ihtb.org/pubPapers/ssh_gymnastics_tunneling.html)
			* [SSH Cheat Sheet - pentestmonkey](http://pentestmonkey.net/cheat-sheet/ssh-cheat-sheet)
			* [proxychains-ng](https://github.com/rofl0r/proxychains-ng)
				* proxychains ng (new generation) - a preloader which hooks calls to sockets in dynamically linked programs and redirects it through one or more socks/http proxies. continuation of the unmaintained proxychains project. the sf.net page is currently not updated, use releases from github release page instead.
			* [Using sshuttle in daily work - Huiming Teo](http://teohm.com/blog/using-sshuttle-in-daily-work/)
		* **VPN**
			* [How VPN Pivoting Works (with Source Code) - cs](https://blog.cobaltstrike.com/2014/10/14/how-vpn-pivoting-works-with-source-code/)
			* [Universal TUN/TAP device driver. - kernel.org](https://www.kernel.org/pub/linux/kernel/people/marcelo/linux-2.4/Documentation/networking/tuntap.txt)
			* [Tun/Tap interface tutorial - backreference](http://backreference.org/2010/03/26/tuntap-interface-tutorial/)
			* [Responder and Layer 2 Pivots - cplsec](https://ijustwannared.team/2017/05/27/responder-and-layer-2-pivots/)
			* [simpletun](https://github.com/gregnietsky/simpletun)
				* Example program for tap driver VPN
		* **WMIC**
			* [The Grammar of WMIC](https://isc.sans.edu/diary/The+Grammar+of+WMIC/2376)
	* **Tools**
		* [Socat](http://www.dest-unreach.org/socat/)
			* socat is a relay for bidirectional data transfer between two independent data channels. Each of these data channels may be a file, pipe, device (serial line etc. or a pseudo terminal), a socket (UNIX, IP4, IP6 - raw, UDP, TCP), an SSL socket, proxy CONNECT connection, a file descriptor (stdin etc.), the GNU line editor (readline), a program, or a combination of two of these.  These modes include generation of "listening" sockets, named pipes, and pseudo terminals.
			* [Examples of use](http://www.dest-unreach.org/socat/doc/socat.html#EXAMPLES)
			* [Socat Cheatsheet](http://www.blackbytes.info/2012/07/socat-cheatsheet/)
		* **Discovery**
			* [nextnet](https://github.com/hdm/nextnet)
				* nextnet is a pivot point discovery tool written in Go.
		* **DNS**
			* [ThunderDNS: How it works - fbkcs.ru](https://blog.fbkcs.ru/en/traffic-at-the-end-of-the-tunnel-or-dns-in-pentest/)
		* **HTTP/HTTPS**
			* [SharpSocks](https://github.com/nettitude/SharpSocks)
				* Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
			* [Chisel](https://github.com/jpillora/chisel)
				* Chisel is a fast TCP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network. 
			* [Crowbar](https://github.com/q3k/crowbar)
				* Crowbar is an EXPERIMENTAL tool that allows you to establish a secure circuit with your existing encrypting TCP endpoints (an OpenVPN setup, an SSH server for forwarding...) when your network connection is limited by a Web proxy that only allows basic port 80 HTTP connectivity.  Crowbar will tunnel TCP connections over an HTTP session using only GET and POST requests. This is in contrast to most tunneling systems that reuse the CONNECT verb. It also provides basic authentication to make sure nobody who stumbles upon the server steals your proxy to order drugs from Silkroad.
			* [A Black Path Toward The Sun(ABPTTS)](https://github.com/nccgroup/ABPTTS)
				* ABPTTS uses a Python client script and a web application server page/package[1] to tunnel TCP traffic over an HTTP/HTTPS connection to a web application server. In other words, anywhere that one could deploy a web shell, one should now be able to establish a full TCP tunnel. This permits making RDP, interactive SSH, Meterpreter, and other connections through the web application server.
		* **SMB**
			* [Piper](https://github.com/p3nt4/Piper)
				* Creates a local or remote port forwarding through named pipes.
			* [flatpipes](https://github.com/dxflatline/flatpipes)
				* A TCP proxy over named pipes. Originally created for maintaining a meterpreter session over 445 for less network alarms.
			* [Invoke-PipeShell](https://github.com/threatexpress/invoke-pipeshell)
				* This script demonstrates a remote command shell running over an SMB Named Pipe. The shell is interactive PowerShell or single PowerShell commands
			* [Invoke-Piper](https://github.com/p3nt4/Invoke-Piper)
				* Forward local or remote tcp ports through SMB pipes.
		* **PowerShell**
			* [PowerShellDSCLateralMovement.ps1](https://gist.github.com/mattifestation/bae509f38e46547cf211949991f81092)
		* **SSH**
			* [SSHDog](https://github.com/Matir/sshdog)
				* SSHDog is your go-anywhere lightweight SSH server. Written in Go, it aims to be a portable SSH server that you can drop on a system and use for remote access without any additional configuration.	
			* [MeterSSH](https://github.com/trustedsec/meterssh)
				* MeterSSH is a way to take shellcode, inject it into memory then tunnel whatever port you want to over SSH to mask any type of communications as a normal SSH connection. The way it works is by injecting shellcode into memory, then wrapping a port spawned (meterpeter in this case) by the shellcode over SSH back to the attackers machine. Then connecting with meterpreter's listener to localhost will communicate through the SSH proxy, to the victim through the SSH tunnel. All communications are relayed through the SSH tunnel and not through the network.
		* **Sockets/TCP/UDP**
			* [SOCKS: A protocol for TCP proxy across firewalls](https://www.openssh.com/txt/socks4.protocol) 
			* [shootback](https://github.com/aploium/shootback)
				* shootback is a reverse TCP tunnel let you access target behind NAT or firewall
			* [ssf - Secure Socket Funneling](https://github.com/securesocketfunneling/ssf)
				* Network tool and toolkit. It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS tunnel to a remote computer. SSF is cross platform (Windows, Linux, OSX) and comes as standalone executables.
			* [PowerCat](https://github.com/secabstraction/PowerCat)
				* A PowerShell TCP/IP swiss army knife that works with Netcat & Ncat
			* [Udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel)
				* A Tunnel which tunnels UDP via FakeTCP/UDP/ICMP Traffic by using Raw Socket, helps you Bypass UDP FireWalls(or Unstable UDP Environment). Its Encrypted, Anti-Replay and Multiplexed. It also acts as a Connection Stabilizer.)
			* [reGeorg](https://github.com/sensepost/reGeorg)
				* The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
			* [redsocks – transparent TCP-to-proxy redirector](https://github.com/darkk/redsocks)
				* This tool allows you to redirect any TCP connection to SOCKS or HTTPS proxy using your firewall, so redirection may be system-wide or network-wide.
			* [Tunna](https://github.com/SECFORCE/Tunna)
				* Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments.
		* **WMI**
		* **VNC**
			* [Invoke-Vnc](https://github.com/klsecservices/Invoke-Vnc)
				* Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.
			* [jsmpeg-vnc](https://github.com/phoboslab/jsmpeg-vnc)
				* A low latency, high framerate screen sharing server for Windows and client for browsers




----------------
### <a name="av">Avoiding/Bypassing AV(Anti-Virus)/UAC/Whitelisting/Sandboxes/Logging/etc</a>
* **101**
	* [Noob 101: Practical Techniques for AV Bypass - Jared Hoffman - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/103-noob-101-practical-techniques-for-av-bypass-jared-hoffman)
		* The shortcomings of anti-virus (AV) solutions have been well known for some time. Nevertheless, both public and private organizations continue to rely on AV software as a critical component of their information security programs, acting as a key protection mechanism over endpoints and other information systems within their networks. As a result, the security posture of these organizations is significantly jeopardized by relying only on this weakened control.
* **Educational**
	* [Bypass Antivirus Dynamic Analysis: Limitations of the AV model and how to exploit them - Emeric Nasi(2014)](https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf)
	* [Learn how to hide your trojans, backdoors, etc from anti virus.](https://www.hellboundhackers.org/articles/read-article.php?article_id=842)
	* [Easy Ways To Bypass Anti-Virus Systems - Attila Marosi -Trooper14](https://www.youtube.com/watch?v=Sl1Sru3OwJ4)
	* [Muts Bypassing AV in Vista/Pissing all over your AV](https://web.archive.org/web/20130514172102/http://www.shmoocon.org/2008/videos/Backtrack%20Demo.mp4)
		* presentation, listed here as it was a bitch finding a live copy
	* [How to Bypass Anti-Virus to Run Mimikatz - **Spoiler, AV still suck, changing strings is helpful**](http://www.blackhillsinfosec.com/?p=5555)
	* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - labofapenetrationtester](http://www.labofapenetrationtester.com/2016/09/amsi.html)
	* [WinPwnage](https://github.com/rootm0s/WinPwnage)
		* The goal of this repo is to study the Windows penetration techniques.
	* [Art of Anti Detection 1 – Introduction to AV & Detection Techniques - Ege Balci](https://pentest.blog/art-of-anti-detection-1-introduction-to-av-detection-techniques/)
	* [Art of Anti Detection 2 – PE Backdoor Manufacturing - Ege Balci](https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/)
	* [Art of Anti Detection 3 – Shellcode Alchemy - Ege Balci](https://pentest.blog/art-of-anti-detection-3-shellcode-alchemy/)
	* [Art of Anti Detection 4 – Self-Defense - Ege Balci](https://pentest.blog/art-of-anti-detection-4-self-defense/)
	* [Breaking Antivirus Software - Joxean Koret, COSEINC(SYSCAN2014)](http://mincore.c9x.org/breaking_av_software.pdf)
	* [Documenting and Attacking a Windows Defender Application Control Feature the Hard Way — A Case Study in Security Research Methodology - Matt Graeber](https://posts.specterops.io/documenting-and-attacking-a-windows-defender-application-control-feature-the-hard-way-a-case-73dd1e11be3a)
		* My goal for this blog post is to not only describe the mechanics of this new feature, but more importantly, I wanted to use this opportunity to paint a picture of the methodology I applied to understand and attempt to bypass the feature. So, if you’re already interested in WDAC features, great. If you’re not, that’s also cool but I hope you’ll follow along with the specific strategies I took to understand an undocumented Windows feature.
	* [Enneos](https://github.com/hoodoer/ENNEoS)
		* Evolutionary Neural Network Encoder of Shenanigans. Obfuscating shellcode with an encoder that uses genetic algorithms to evolve neural networks to contain and output the shellcode on demand.
	* [Evasion & Obfuscation Techniques - z3roTrust](https://medium.com/@z3roTrust/evasion-obfuscation-techniques-87c33429cee2)
	* [Subverting Sysmon: Application of a Formalized Security Product Evasion Methodology - Lee Christensen, Matt Graeber(BHUSA2018)](https://www.youtube.com/watch?v=R5IEyoFpZq0)
		* While security products are a great supplement to the defensive posture of an enterprise, to well-funded nation-state actors, they are an impediment to achieving their objectives. As pentesters argue the efficacy of a product because it doesn't detect their specific offensive technique, mature actors recognize a need to holistically subvert the product at every step during the course their operation.
		* [Whitepaper](https://github.com/mattifestation/BHUSA2018_Sysmon/blob/master/Whitepaper_Subverting_Sysmon.pdf)
		* [Slides](https://github.com/mattifestation/BHUSA2018_Sysmon/blob/master/Slides_Subverting_Sysmon.pdf)
		* [Code](https://github.com/mattifestation/BHUSA2018_Sysmon)
* **Articles/Blogposts/Writeups**
	* [Distribution of malicious JAR appended to MSI files signed by third parties](https://blog.virustotal.com/2019/01/distribution-of-malicious-jar-appended.html)
	* [Bypass Cylance Memory Exploitation Defense & Script Cntrl](https://www.xorrior.com/You-Have-The-Right-to-Remain-Cylance/)
	* [Three Simple Disguises for Evading Antivirus - BHIS](https://www.blackhillsinfosec.com/three-simple-disguises-for-evading-antivirus/)
	* [AVLeak: Fingerprinting Antivirus Emulators Through Black-Box Testing](https://www.usenix.org/system/files/conference/woot16/woot16-paper-blackthorne_update.pdf)
	* [How to Accidently Win Against AV - RastaMouse](https://rastamouse.me/2017/07/how-to-accidently-win-against-av/)
	* [Learn how to hide your trojans, backdoors, etc from anti virus.](https://www.hellboundhackers.org/articles/read-article.php?article_id=842)
	* [[Virus] Self-modifying code-short overview for beginners](http://phimonlinemoinhat.blogspot.com/2010/12/virus-self-modifying-code-short.html)
	* [Escaping The Avast Sandbox Using A Single IOCTL](https://www.nettitude.co.uk/escaping-avast-sandbox-using-single-ioctl-cve-2016-4025)
	* [AVLeak: Fingerprinting Antivirus Emulators Through Black-Box Testing](https://www.usenix.org/system/files/conference/woot16/woot16-paper-blackthorne_update.pdf)
	* [Antivirus Evasion for Penetration Testing Engagements - Nathu Nandwani(2018)](https://www.alienvault.com/blogs/security-essentials/antivirus-evasion-for-penetration-testing-engagements)
	* [Bypassing Kaspersky Endpoint Security 11 - 0xc0ffee.io](http://0xc0ffee.io/blog/kes11-bypass)
	* [Executing Meterpreter in Memory on Windows 10 and Bypassing AntiVirus - n00py](https://www.n00py.io/2018/06/executing-meterpreter-in-memory-on-windows-10-and-bypassing-antivirus/)
	* [Simple AV Evasion Symantec and P4wnP1 USB - Frans Hendrik Botes](https://medium.com/@fbotes2/advance-av-evasion-symantec-and-p4wnp1-usb-c7899bcbc6af)
	* [How to Bypass Anti-Virus to Run Mimikatz - Carrie Roberts(2017)](https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/)
	* [DeepSec 2013 Talk: Easy Ways To Bypass Anti-Virus Systems - Attila Marosi](https://blog.deepsec.net/deepsec-2013-talk-easy-ways-to-bypass-anti-virus-systems/)
	* [Bypassing CrowdStrike in an enterprise production network [in 3 different ways] - KomodoResearch(2019-June)](https://www.komodosec.com/post/bypassing-crowdstrike)
	* [Incapacitating Windows Defender - offensiveops.io](http://www.offensiveops.io/tools/incapacitating-windows-defender/)
	* [Endpoint Protection, Detection and Response Bypass Techniques Index - p3zx.blogspot](https://pe3zx.blogspot.com/2019/01/endpoint-protection-detection-and.html)
	* [Tradecraft - This is why your tools and exploits get detected by EDR - Xentropy](https://netsec.expert/2020/01/11/getting-detected-by-EDRs.html)
	* [Silencing Cylance: A Case Study in Modern EDRs - Adam Chester, Dominic Chell](https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/)
	* [Bypassing Detection for a Reverse Meterpreter Shell - Mohit Suyal(2018)](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)
* **Talks & Presentations**
	* [Adventures in Asymmetric Warfare by Will Schroeder](https://www.youtube.com/watch?v=53qQfCkVM_o)
		* As a co-founder and principal developer of the Veil-Framework, the speaker has spent a considerable amount of time over the past year and a half researching AV-evasion techniques. This talk will briefly cover the problem space of antivirus detection, as well as the reaction to the initial release of Veil-Evasion, a tool for generating AV-evading executables that implements much of the speaker’s research. We will trace through the evolution of the obfuscation techniques utilized by Veil-Evasion’s generation methods, culminating in the release of an entirely new payload language class, as well as the release of a new ..NET encryptor. The talk will conclude with some basic static analysis of several Veil-Evasion payload families, showing once and for all that antivirus static signature detection is dead.
	* [EDR, ETDR, Next Gen AV is all the rage, so why am I enraged? - Michael Gough - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t416-edr-etdr-next-gen-av-is-all-the-rage-so-why-am-i-enraged-michael-gough)
		* A funny thing happened when I evaluated several EDR, ETDR and Next Gen AV products, currently all the rage and latest must have security solution. Surprisingly to me the solutions kinda sucked at things we expected them to do or be better at, thus this talk so you can learn from our efforts. While testing, flaws were discovered and shared with the vendors, some of the flaws, bugs, or vulns that were discovered will be discussed. This talk takes a look at what we initially expected the solutions to provide us, the options or categories of what these solutions address, what to consider when doing an evaluation, how to go about testing these solutions, how they would fit into our process, and what we found while testing these solutions. What enraged me about these EDR solutions were how they were all over the place in how they worked, how hard or ease of use of the solutions, and the fact I found malware that did not trigger an alert on every solution I tested. And this is the next new bright and shiny blinky security savior solution? The news is not all bad, there is hope if you do some work to understand what these solutions target and provide, what to look for, and most importantly how to test them! What we never anticipated or expected is the tool we used to compare the tests and how well it worked and how it can help you. 
	* [Next Gen AV vs My Shitty Code by James Williams - SteelCon 2018](https://www.youtube.com/watch?v=247m2dwLlO4)
	* [Modern Evasion Techniques - Jason Lang(Derbycon7 2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
		* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.
		* [Slides](https://www.slideshare.net/JasonLang1/modern-evasion-techniques)
	* [Tricking modern endpoint security products - Michel Coene(SANS2020)](https://www.youtube.com/watch?v=xmNpS9mbwEc)
		* The current endpoint monitoring capabilities we have available to us are unprecedented. Many tools and our self/community-built detection rules rely on parent-child relationships and command-line arguments to detect malicious activity taking place on a system. There are, however, ways the adversaries can get around these detections. During this presentation, we'll talk about the following techniques and how we can detect them: Parent-child relationships spoofing; Command-line arguments spoofing; Process injection; Process hollowing
* **Techniques**
	* **Code Injection**
	* **Debuggers**
		* [Batch, attach and patch: using windbg’s local kernel debugger to execute code in windows kernel](https://vallejo.cc/2015/06/07/batch-attach-and-patch-using-windbgs-local-kernel-debugger-to-execute-code-in-windows-kernel/)
			* In this article I am going to describe a way to execute code in windows kernel by using windbg local kernel debugging. It’s not a vulnerability, I am going to use only windbg’s legal functionality, and I am going to use only a batch file (not powershell, or vbs, an old style batch only) and some Microsoft’s signed executables (some of them that are already in the system and windbg, that we will be dumped from the batch file). With this method it is not necessary to launch executables at user mode (only Microsoft signed executables) or load signed drivers. PatchGuard and other protections don’t stop us. We put our code directly into kernel memory space and we hook some point to get a thread executing it. As we will demonstrate, a malware consisting of a simple batch file would be able to jump to kernel, enabling local kernel debugging and using windbg to get its code being executed in kernel.
	* **Loading-after-execution**
		* **Tools**
			* [foolavc](https://github.com/hvqzao/foolavc)
				* This project is foolav continuation. Original foolav was offered only as x86 executable, used single encoding for externally kept payload file. Once foolav is executed, payload is loaded into memory and executed as a shellcode in separate thread. foolavc on the other hand supports both x86 and x86_64 architectures, allows use of both internal (built-in) or external payloads. Those can be interpreted in one of three ways: shellcode, DLL and EXEcutable.
			* [MemoryModule](https://github.com/fancycode/MemoryModule)
				* MemoryModule is a library that can be used to load a DLL completely from memory - without storing on the disk first.
	* **Native Binaries/Functionality**
		* [Research on CMSTP.exe](https://msitpros.com/?p=3960)
			* Methods to bypass UAC and load a DLL over webdav 
		* [rundll32 lockdown testing goodness](https://www.attackdebris.com/?p=143)	
		* [Hack Microsoft Using Microsoft Signed Binaries - Pierre-Alexandre Braeken](https://www.youtube.com/watch?v=V9AJ9M8_-RE&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=15)
		* [Hack Microsoft Using Microsoft Signed Binaries - BH17 - pierre - alexandre braeken](https://www.blackhat.com/docs/asia-17/materials/asia-17-Braeken-Hack-Microsoft-Using-Microsoft-Signed-Binaries-wp.pdf)
			* Imagine being attacked by legitimate software tools that cannot be detected by usual defender tools. How bad could it be to be attacked by malicious threat actors only sending bytes to be read and bytes to be written in order to achieve advanced attacks? The most dangerous threat is the one you can’t see. At a time when it is not obvious to detect memory attacks using API like VirtualAlloc, what would be worse than having to detect something like `f0xffffe0010c79ebe8+0x8 L4 0xe8 0xcb 0x04 0x10`? We will be able to demonstrate that we can achieve every kind of attacks you can imagine using only PowerShell and a Microsoft Signed Debugger. We can retrieve passwords from the userland memory, execute shellcode by dynamically parsing loaded PE or attack the kernel achieving advanced persistence inside any system.
		* [RogueMMC](https://github.com/subTee/RogueMMC)
			* Execute Shellcode And Other Goodies From MMC
* **Anti-Virus**
	* **Articles/Writeups**
		* [pecloak.py - An Experiment in AV evasion](http://www.securitysift.com/pecloak-py-an-experiment-in-av-evasion/)
		* [How to Bypass Anti-Virus to Run Mimikatz](http://www.blackhillsinfosec.com/?p=5555)
		* [Practical Anti-virus Evasion - Daniel Sauder](https://govolutionde.files.wordpress.com/2014/05/avevasion_pentestmag.pdf)
		* [Why Anti-Virus Software Fails](https://deepsec.net/docs/Slides/2014/Why_Antivirus_Fails_-_Daniel_Sauder.pdf)
		* [Sacred Cash Cow Tipping 2017 - BlackHills Infosec](https://www.youtube.com/watch?v=SVwv1dZCtWM)
			* We're going to bypass most of the major antivirus programs. Why? 1) Because it's fun. 2) Because it'll highlight some of the inherent weaknesses in our environments today.
		* [Sacred Cash Cow Tipping 2020 - BHIS](https://www.youtube.com/watch?v=7t1lV0AH-HE&feature=share)
		* [Deep Dive Into Stageless Meterpreter Payloads](https://blog.rapid7.com/2015/03/25/stageless-meterpreter-payloads/)
		* [Execute ShellCode Using Python](http://www.debasish.in/2012/04/execute-shellcode-using-python.html)
			* In this article I am going to show you, how can we use python and its "ctypes" library to execute a "calc.exe" shell code or any other shell code.
	    * [Executing Meterpreter in Memory on Windows 10 and Bypassing AntiVirus - noopy.io](https://www.n00py.io/2018/06/executing-meterpreter-in-memory-on-windows-10-and-bypassing-antivirus/)    
	    * [Executing Meterpreter in Memory on Windows 10 and Bypassing AntiVirus (Part 2) - noopy.io](https://www.n00py.io/2018/06/executing-meterpreter-in-memory-on-windows-10-and-bypassing-antivirus-part-2/)
	    * [Bypassing Kaspersky 2017 AV by XOR encoding known malware with a twist - monoc.com](https://blog.m0noc.com/2017/08/bypassing-kaspersky-2017-av-by-xor.html)
		* [Bypassing Static Antivirus With Ten Lines of Code - Attactics](https://attactics.org/2016/03/bypassing-static-antivirus-with-ten-lines-of-code/)
	* **Sandbox Detection**
		* [CheckPlease](https://github.com/Arvanaghi/CheckPlease)
	* **Tools**
		* [avepoc](https://github.com/govolution/avepoc)
			* some pocs for antivirus evasion
		* [AVSignSeek](https://github.com/hegusung/AVSignSeek)
			* Tool written in python3 to determine where the AV signature is located in a binary/payload
		* [SpookFlare: Stay In Shadows](https://artofpwn.com/spookflare.html?)
			* [SpookFlare - Github](https://github.com/hlldz/SpookFlare)
		* [avet framework](https://github.com/govolution/avet)
			* AVET is an AntiVirus Evasion Tool, which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. In version 1.1 lot of stuff was introduced, for a complete overview have a look at the CHANGELOG file. Now 64bit payloads can also be used, for easier usage I hacked a small build tool (avet_fabric.py).
		* [Don't Kill My Cat (DKMC)](https://github.com/Mr-Un1k0d3r/DKMC)
			* Don't kill my cat is a tool that generates obfuscated shellcode that is stored inside of polyglot images. The image is 100% valid and also 100% valid shellcode. The idea is to avoid sandbox analysis since it's a simple "legit" image. For now the tool rely on PowerShell the execute the final shellcode payload.
			* [Presentation - Northsec2017](https://www.youtube.com/watch?v=7kNwbXgWdX0&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=9)
		* [Dr0p1t-Framework](https://github.com/D4Vinci/Dr0p1t-Framework)
			* Have you ever heard about trojan droppers ? In short dropper is type of trojans that downloads other malwares and Dr0p1t gives you the chance to create a stealthy dropper that bypass most AVs and have a lot of tricks ( Trust me :D ) ;)
 		* [PowerLine](https://github.com/fullmetalcache/powerline)
			* [Presentation](https://www.youtube.com/watch?v=HiAtkLa8FOc)
		* [Invoke-CradleCrafter: Moar PowerShell obFUsk8tion by Daniel Bohannon](https://www.youtube.com/watch?feature=youtu.be&v=Nn9yJjFGXU0&app=desktop)
		* [Invoke-CradleCrafter v1.1](https://github.com/danielbohannon/Invoke-CradleCrafter)
		* [wePWNise](https://github.com/mwrlabs/wePWNise)
			* WePWNise generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software
		* [katz.xml](https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8)
			* Downloads Mimikatz From GitHub, Executes Inside of MsBuild.exe
		* [Shellter](https://www.shellterproject.com/)
		* [SigThief](https://github.com/secretsquirrel/SigThief)
			* Stealing Signatures and Making One Invalid Signature at a Time
		* [SideStep](https://github.com/codewatchorg/SideStep)
			* SideStep is yet another tool to bypass anti-virus software. The tool generates Metasploit payloads encrypted using the CryptoPP library (license included), and uses several other techniques to evade AV.
		* [peCloak.py - An Experiment in AV Evasion](http://www.securitysift.com/pecloak-py-an-experiment-in-av-evasion/)
		* [Making FinFisher Undetectable](https://lqdc.github.io/making-finfisher-undetectable.html)
		* [Bypass AV through several basic/effective techniques](http://packetstorm.foofus.com/papers/virus/BypassAVDynamics.pdf)
		*  [stupid_malware](https://github.com/andrew-morris/stupid_malware)
			* Python malware for pentesters that bypasses most antivirus (signature and heuristics) and IPS using sheer stupidity
		* [InfectPE](https://github.com/secrary/InfectPE)
			* Using this tool you can inject x-code/shellcode into PE file. InjectPE works only with 32-bit executable files.
		* [MorphAES](https://github.com/cryptolok/MorphAES)
			* IDPS & SandBox & AntiVirus STEALTH KILLER. MorphAES is the world's first polymorphic shellcode engine, with metamorphic properties and capability to bypass sandboxes, which makes it undetectable for an IDPS, it's cross-platform as well and library-independent.
		* [Inception](https://github.com/two06/Inception)
			* Provides In-memory compilation and reflective loading of C# apps for AV evasion.
		* [recomposer](https://github.com/secretsquirrel/recomposer)
			* Randomly changes Win32/64 PE Files for 'safer' uploading to malware and sandbox sites.
		* [Phantom-Evasion](https://github.com/oddcod3/Phantom-Evasion)
			* Phantom-Evasion is an interactive antivirus evasion tool written in python capable to generate (almost) FUD executable even with the most common 32 bit msfvenom payload (lower detection ratio with 64 bit payloads). The aim of this tool is to make antivirus evasion an easy task for pentesters through the use of modules focused on polymorphic code and antivirus sandbox detection techniques. Since version 1.0 Phantom-Evasion also include a post-exploitation section dedicated to persistence and auxiliary modules.
* **EDR**
	* **Articles/Blogposts/Writeups**
		* [Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR - Cornelis de Plaa](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
		* [Dechaining Macros and Evading EDR](https://www.countercept.com/blog/dechaining-macros-and-evading-edr/)
		* [Bypass EDR’s memory protection, introduction to hooking](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6)
		* [Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs - ired.team](https://ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis)
		* [Silencing Cylance: A Case Study in Modern EDRs](https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/)
		* [Cylance, I Kill You! - Shahar Zini](https://skylightcyber.com/2019/07/18/cylance-i-kill-you/)
			* [Slides](https://skylightcyber.com/2019/07/18/cylance-i-kill-you/Cylance%20-%20Adversarial%20Machine%20Learning%20Case%20Study.pdf)
	* **Talks & Presentations**
		* [Red Teaming in the EDR age - Will Burgess](https://www.youtube.com/watch?v=l8nkXCOYQC4)
	* **Tools**
		* [Sharp-Suite - Process Argument Spoofing](https://github.com/FuzzySecurity/Sharp-Suite)
	* [Zombie Ant Farm](https://github.com/dsnezhkov/zombieant)
		* Primitives and Offensive Tooling for Linux EDR evasion.
* **Logging**
	* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
		* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
* **Secured Environment Escape**<a name="secure-env"></a>
	* **101**
		* [Sandboxes from a pen tester’s view - Rahul Kashyap](http://www.irongeek.com/i.php?page=videos/derbycon3/4303-sandboxes-from-a-pen-tester-s-view-rahul-kashyap)
			* Description: In this talk we’ll do an architectural decomposition of application sandboxing technology from a security perspective. We look at various popular sandboxes such as Google Chrome, Adobe ReaderX, Sandboxie amongst others and discuss the limitations of each technology and it’s implementation. Further, we discuss in depth with live exploits how to break out of each category of sandbox by leveraging various kernel and user mode exploits – something that future malware could leverage. Some of these exploit vectors have not been discussed widely and awareness is important.
	* **Adobe Sandbox**
		* [Adobe Sandbox: When the Broker is Broken - Peter Vreugdenhill](https://cansecwest.com/slides/2013/Adobe%20Sandbox.pdf)
	* **chroot**
		* [chw00t: chroot escape tool](https://github.com/earthquake/chw00t)
		* [Breaking Out of a Chroot Jail Using PERL](http://pentestmonkey.net/blog/chroot-breakout-perl)
	* **Breaking out of Contained Linux Shells**
		* [Escaping Restricted Linux Shells - SANS](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells#)
		* [Breaking out of rbash using scp - pentestmonkey](http://pentestmonkey.net/blog/rbash-scp)
		* [Escape From SHELLcatraz - Breaking Out of Restricted Unix Shells - knaps](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells)
		* [How to break out of restricted shells with tcpdump - Oiver Matula](https://insinuator.net/2019/07/how-to-break-out-of-restricted-shells-with-tcpdump/)
	* **Python Sandbox**
		* [Escaping a Python sandbox with a memory corruption bug](https://hackernoon.com/python-sandbox-escape-via-a-memory-corruption-bug-19dde4d5fea5)
		* [Breaking out of secured Python environments](http://tomforb.es/breaking-out-of-secured-python-environments)
		* [Sandboxed Execution Environment ](http://pythonhosted.org/python-see)
		* [Documentation](http://pythonhosted.org/python-see)
			* Sandboxed Execution Environment (SEE) is a framework for building test automation in secured Environments.  The Sandboxes, provided via libvirt, are customizable allowing high degree of flexibility. Different type of Hypervisors (Qemu, VirtualBox, LXC) can be employed to run the Test Environments.
		* [Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)
	* **ssh**
		* [ssh environment - circumvention of restricted shells](http://www.opennet.ru/base/netsoft/1025195882_355.txt.html)
	* **Windows**
		* [Windows Desktop Breakout](https://www.gracefulsecurity.com/windows-desktop-breakout/)
		* [Kiosk/POS Breakout Keys in Windows - TrustedSec](https://www.trustedsec.com/2015/04/kioskpos-breakout-keys-in-windows/)
		* [menu2eng.txt - How To Break Out of Restricted Shells and Menus, v2.3(1999)](https://packetstormsecurity.com/files/14914/menu2eng.txt.html)
		* [Kiosk Escapes Pt 2 - Ft. Microsoft Edge!! - H4cklife](https://h4cklife.org/posts/kiosk-escapes-pt-2/)
			* TL/DR: Microsoft Edge brings up Windows Explorer when you navigate to C:\ in the URL; Win+x can be used to access the start menu when shortcut keys are limited
			* An excellent whitepaper detailing methods for breaking out of virtually any kind of restricted shell or menu you might come across.
	* **VDI**
		* [Breaking Out! of Applications Deployed via Terminal Services, Citrix, and Kiosks](https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/)
		* [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
		* [Pentests in restricted VDI environments - Viatcheslav Zhilin](https://www.tarlogic.com/en/blog/pentests-in-restricted-vdi-environments/)
	* **VirtualMachine**
		* [Exploiting the Hyper-V IDE Emulator to Escape the Virtual Machine - Joe Bialek](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_08_BlackHatUSA/BHUSA19_Exploiting_the_Hyper-V_IDE_Emulator_to_Escape_the_Virtual_Machine.pdf)
		* [L1TF (Foreshadow) VM guest to host memory read PoC](https://github.com/gregvish/l1tf-poc)
			* This is a PoC for CVE-2018-3646. This is a vulnerability that enables malicious/compromised VM guests to read host machine physical memory. The vulnerability is exploitable on most Intel CPUs that support VT-x and EPT (extended page tables). This includes all Intel Core iX CPUs. This PoC works only on 64 bit x86-64 systems (host and guest).










 

---------------------------
### <a name="payloads"></a>Payloads & Shells
* **101**
* **Payloads**
	* [Staged vs Stageless Handlers - OJ Reeves](https://buffered.io/posts/staged-vs-stageless-handlers/)
	* [Toying with inheritance - hexacorn](http://www.hexacorn.com/blog/2019/06/15/toying-with-inheritance/)
	* [Proxy-Aware Payload Testing - redxorblue](https://blog.redxorblue.com/2019/09/proxy-aware-payload-testing.html)
    	* "I get told that I am too wordy, so if you want the summary, here are some steps to setup a virtual testing environment to test payloads to see if they can handle HTTP(S) proxies and if so, can they authenticate properly through them as well. This post will cover the proxy setup without authentication since that is the easier part, and I will do a second post shortly to hack together the authentication portion of it."
* **Handling Shells**
	* [Alveare](https://github.com/roccomuso/alveare)
		* Multi-client, multi-threaded reverse shell handler written in Node.js. Alveare (hive in italian) lets you listen for incoming reverse connection, list them, handle and bind the sockets. It's an easy to use tool, useful to handle reverse shells and remote processes.
* **Tools to help generate payloads**
	* [How to use msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
	* [msfpc](https://github.com/g0tmi1k/mpc)
		* A quick way to generate various "basic" Meterpreter payloads via msfvenom (part of the Metasploit framework).
	* [Unicorn](https://github.com/trustedsec/unicorn)
		* Magic Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.
	* [MorphAES](https://github.com/cryptolok/MorphAES)
		* MorphAES is the world's first polymorphic shellcode engine, with metamorphic properties and capability to bypass sandboxes, which makes it undetectable for an IDPS, it's cross-platform as well and library-independent.
	* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
		* SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. SharpShooter is capable of creating payloads in a variety of formats, including HTA, JS, VBS and WSF. It leverages James Forshaw's DotNetToJavaScript tool to invoke methods from the SharpShooter DotNet serialised object. Payloads can be retrieved using Web or DNS delivery or both; SharpShooter is compatible with the MDSec ActiveBreach PowerDNS project. Alternatively, stageless payloads with embedded shellcode execution can also be generated for the same scripting formats.
	* [gscript](https://github.com/gen0cide/gscript)
		* Gscript is a framework for building multi-tenant executors for several implants in a stager. The engine works by embedding runtime logic (powered by the V8 Javascript Virtual Machine) for each persistence technique. This logic gets run at deploy time on the victim machine, in parallel for every implant contained with the stager. The Gscript engine leverages the multi-platform support of Golang to produce final stage one binaries for Windows, Mac, and Linux.
* **Techniques**
	* **Keying**
		* [GoGreen](https://github.com/leoloobeek/GoGreen)
			* This project was created to bring environmental (and HTTP) keying to scripting languages. As its common place to use PowerShell/JScript/VBScript as an initial vector of code execution, as a result of phishing or lateral movement, I see value of the techniques for these languages.
	* **Polyglot**
		* [BMP / x86 Polyglot](https://warroom.securestate.com/bmp-x86-polyglot/)
* **(Ex)/(S)ample Payloads and supporting tools written in various languages**
	* **C & C++**
		* [Undetectable C# & C++ Reverse Shells - Bank Security](https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15)
			* Technical overview of different ways to spawn a reverse shell on a victim machine
	* **C#**
		* [EasyNet](https://github.com/TheWover/EasyNet)
			* Packs/unpacks arbitrary data using a simple Data -> Gzip -> AES -> Base64 algorithm. Generates a random AES-256 key and and IV and provides them to the user. Can be used to pack or unpack arbitrary data. Provided both as a program and a library.
		* [Inception Framework](https://github.com/two06/Inception)
			* Inception provides In-memory compilation and reflective loading of C# apps for AV evasion. Payloads are AES encrypted before transmission and are decrypted in memory. The payload server ensures that payloads can only be fetched a pre-determined number of times. Once decrypted, Roslyn is used to build the C# payload in memory, which is then executed using reflection.
	* **Go**
		* [Go-deliver](https://github.com/0x09AL/go-deliver/)
			* Go-deliver is a payload delivery tool coded in Go. This is the first version and other features will be added in the future.
		* [Hershell](https://github.com/sysdream/hershell)	
			* Simple TCP reverse shell written in Go. It uses TLS to secure the communications, and provide a certificate public key fingerprint pinning feature, preventing from traffic interception.
			* [[EN] Golang for pentests : Hershell](https://sysdream.com/news/lab/2018-01-15-en-golang-for-pentests-hershell/)
	* **HTA** 
		* [genHTA](https://github.com/vysec/GenHTA)
			* Generates anti-sandbox analysis HTA files without payloads
		* [morpHTA](https://github.com/vysec/MorphHTA)
			* Morphing Cobalt Strike's evil.HTA 
		* [Demiguise](https://github.com/nccgroup/demiguise)
			* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place, and (if you use environmental keying) to avoid it being sandboxed.
	* **LNK Files**
		* [LNKUp](https://github.com/Plazmaz/LNKUp)
			* Generates malicious LNK file payloads for data exfiltration
		* [Embedding reverse shell in .lnk file or Old horse attacks](http://onready.me/old_horse_attacks.html)
	* **MSI Binaries**
		* [Wix Toolkit](http://wixtoolset.org/)
			* Tool for crafting msi binaries
		* [Distribution of malicious JAR appended to MSI files signed by third parties](https://blog.virustotal.com/2019/01/distribution-of-malicious-jar-appended.html)
	* **.NET**
		* [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
			* A tool to create a JScript file which loads a .NET v2 assembly from memory.
		* [Payload Generation with CACTUSTORCH](https://www.mdsec.co.uk/2017/07/payload-generation-with-cactustorch/)
			* [Code](https://github.com/mdsecactivebreach/CACTUSTORCH)
	* **Powershell**
		* [Powershell Download Cradles - Matthew Green](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)
		* [Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage)
			* Invoke-PSImage takes a PowerShell script and embeds the bytes of the script into the pixels of a PNG image. It generates a oneliner for executing either from a file of from the web (when the -Web flag is passed). The least significant 4 bits of 2 color values in each pixel are used to hold the payload. Image quality will suffer as a result, but it still looks decent. The image is saved as a PNG, and can be losslessly compressed without affecting the ability to execute the payload as the data is stored in the colors themselves. It can accept most image types as input, but output will always be a PNG because it needs to be lossless. Each pixel of the image is used to hold one byte of script, so you will need an image with at least as many pixels as bytes in your script. This is fairly easy—for example, Invoke-Mimikatz fits into a 1920x1200 image.
		* [Reverse Encrypted (AES 256-bit) Shell over TCP - using PowerShell SecureString.](https://github.com/ZHacker13/ReverseTCPShell)
		* [PowerDNS](https://github.com/mdsecactivebreach/PowerDNS)	
			* PowerDNS is a simple proof of concept to demonstrate the execution of PowerShell script using DNS only. PowerDNS works by splitting the PowerShell script in to chunks and serving it to the user via DNS TXT records.
	* **Python**
		* [Pupy](https://github.com/n1nj4sec/pupy)
			* Pupy is a remote administration tool with an embeded Python interpreter, allowing its modules to load python packages from memory and transparently access remote python objects. The payload is a reflective DLL and leaves no trace on disk
		* [Winpayloads](https://github.com/nccgroup/Winpayloads)
			* Undetectable Windows Payload Generation with extras Running on Python2.7
		* [Cloak](https://github.com/UltimateHackers/Cloak)
			* Cloak generates a python payload via msfvenom and then intelligently injects it into the python script you specify.
	* **SCT Files**
		* [SCT-obfuscator](https://github.com/Mr-Un1k0d3r/SCT-obfuscator)
			* SCT payload obfuscator. Rename variables and change harcoded char value to random one.
	* **VBA**
		* [VBad](https://github.com/Pepitoh/VBad)
			* VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.









---------------------------------
### <a name="inject"></a>Code Injection Stuff
* I Swear I'll get around to this soon™, and make it actually useful/document things
* **Agnostic**
* **Linux**
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Pure In-Memory (Shell)Code Injection In Linux Userland - blog.sektor7](https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md)
	* **Talks & Presentations**
	* **Tools**
		* [Jugaad - Thread Injection Kit](https://github.com/aseemjakhar/jugaad)
			* Jugaad is an attempt to create CreateRemoteThread() equivalent for `*nix` platform. The current version supports only Linux operating system. For details on what is the methodology behind jugaad and how things work under the hood visit http://null.co.in/section/projects for a detailed paper.
		* [linux-injector](https://github.com/dismantl/linux-injector)
			* Utility for injecting executable code into a running process on x86/x64 Linux. It uses ptrace() to attach to a process, then mmap()'s memory regions for the injected code, a new stack, and space for trampoline shellcode. Finally, the trampoline in the target process is used to create a new thread and execute the chosen shellcode, so the main thread is allowed to continue. This project borrows from a number of other projects and research, see References below.
		* [linux-inject](https://github.com/gaffe23/linux-inject)
			* Tool for injecting a shared object into a Linux process
		* [injectso64](https://github.com/ice799/injectso64)
			* This is the x86-64 rewrite of Shaun Clowes' i386/SPARC injectso which he presented at Blackhat Europe 2001.
* **OS X**
	* **101**
	* **Articles/Blogposts/Writeups**
	* **Talks & Presentations**
	* **Tools**
* **Python**
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Code injection on Windows using Python: a simple example - andreafortuna](https://www.andreafortuna.org/programming/code-injection-on-windows-using-python-a-simple-example/)
	* **Talks & Presentations**
	* **Tools**
		* [pyrasite](https://github.com/lmacken/pyrasite)
			* Tools for injecting arbitrary code into running Python processes.
		* [Equip: python bytecode instrumentation](https://github.com/neuroo/equip)
			* equip is a small library that helps with Python bytecode instrumentation. Its API is designed to be small and flexible to enable a wide range of possible instrumentations. The instrumentation is designed around the injection of bytecode inside the bytecode of the program to be instrumented. However, the developer does not need to know anything about the Python bytecode since the injected code is Python source.
* **Windows**
	* **101**
	* **DLL**
		* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
			* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
			* [Inject All the Things - Shut up and hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
	* **Articles/Blogposts/Writeups**
		* [InjectProc - Process Injection Techniques](https://github.com/secrary/InjectProc)
		* [Injecting Code into Windows Protected Processes using COM - Part 1 - James Forshaw(P0)](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html)
		* [Injecting Code into Windows Protected Processes using COM - Part 2 - James Forshaw(P0)](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)
	* **Talks & Presentations**
		* [Injection on Steroids: Code less Code Injections and 0 Day Techniques - Paul Schofield Udi Yavo](https://www.youtube.com/watch?v=0BAaAM2wD4s)
			* [Blogpost](https://breakingmalware.com/injection-techniques/code-less-code-injections-and-0-day-techniques/)
		* [Less is More, Exploring Code/Process-less Techniques and Other Weird Machine Methods to Hide Code (and How to Detect Them)](https://cansecwest.com/slides/2014/less%20is%20more3.pptx)
	* **Tools**
		* [InfectPE](https://github.com/secrary/InfectPE)
			* Using this tool you can inject x-code/shellcode into PE file. InjectPE works only with 32-bit executable files.
		* [PowerLoaderEX](https://github.com/BreakingMalware/PowerLoaderEx)
			* Advanced Code Injection Technique for x32 / x64



