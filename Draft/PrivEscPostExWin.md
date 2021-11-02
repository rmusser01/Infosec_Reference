# Windows Privilege Escalation & Post-Exploitation
----------------------------------------------------------------------
## Table of Contents
- Quick Jump List:
	- [Windows Post Exploitation](#winpost)
		- [Execution](#winexec)
		- [Persistence](#winpersist)
		- [Privilege Escalation](#winprivesc)
		- [Windows Defense Evasion](#windefev)
		- [Credential Access](#wincredac)
		- [Discovery](#windisco)
		- [Lateral Movement](#winlater)
		- [Collection](#wincollect)
	- [Windows Specific Technologies](#wintech)
- [101](#win101)
- [Living_off_The_Land](#lolbins-win)
- [CSharp & .NET Stuff](#csharp-stuff)
- [Powershell Stuff](#powershell-stuff)
- [Windows Code Injection Techniques](#wcit)
	- [APC](#APC)
	- [Atom Bombing](#abomb)
	- [Breaking BaDDEr](#bbad)
	- ['Code-Less'](#cless)
	- [Command Line and Environment Variables](#clev)
	- [Console Window Class](#clw)
	- [Ctrl Injection](#ctrli)
	- [DLL Injection](#dlli)
	- [Reflective DLL Injection](#rdlli)
	- [DNS Client API](#dnscla)
	- [Process Doppelganging](#procdoppel)
	- [DoppelGate](#doppg)
	- [DoubleAgent](#dai)
	- [EarlyBird Injection](#ebi)
	- [Extra Window Bytes Injection](#ewbi)
	- [Fibers](#fii)
	- [Gargoyle](#gii)
	- [GhostWriting Injection](#gwi)
	- [Process Herpaderping](#proch)
	- [Process Hollowing](#prochollow)
	- [Inject-Me](#injme)
	- [Kernel Callback Table](#kcti)
	- [KnownDlls Cache Poisoning](#kdlli)
	- [Mapping Injection](#mappi)
	- [Multiple Provider Router (MPR) DLL and Shell Notifications](#mpri)
	- [NINA](#nina)
	- [NtCreate](#ntcreate)
	- [PE Injection](#peinject)
	- [PowerLoader(Ex)](#powex)
	- [Print Spooler](#pspool)
	- [PROPagate](#propagate)
	- [Service Control Handler](#schi)
	- [Shatter](#shatter)
	- [Stack Bomber](#stackbomb)
	- [Thread Execution Hijacking](#tehi)
	- [ThreadLocal Storage Injection](#tlsi)
	- [Tooltips/Common Controls](#tcci)
	- [Windows Notification Facility](#wnfi)
	- [WinSock Helper Functions(WSHX)](#wshx)
- [Windows Post Exploitation](#winpost)
	- [Execution](#winexec)
		- [lolbins](#winlolexec)
		- [Command and Scripting Interpreter](#wincmdexec)
		- [Compiled HTML Files](#winchmexec)
		- [Component-Object-Model](#wincomexec)
		- [ontrolPanel Items](#wincplexec)
		- [DLL-Related](#windllexec)
		- [Downloaders](#dlers) - FIX
		- [Exploitation for Client Execution](#) - FIX
		- [Indirect Execution](#indirexec)
		- [Inter-Process Communication](#eipc)
		- [Scripting Host](#esch) - FIX(Add langs)
		- [Native API(Syscalls & WinAPI)](#enapi)
		- [Power API](#epowerapi)
		- [Processes](#epx)
		- [Scheduled Task/Job](#sctj) - FIX
		- [Shared Modules](#eshm)
		- [Shellcode Stuff](#winshellcode)
		- [Software Deployment Tools](#sdtexec) - FIX
		- [System Services](#winserviceexec)
		- [Third-Party Software](#tpswinexec)
		- [User Execution](#winuserexec)
		- [Windows Diagnostic Tool](#wdtexec)
		- [WIndows Management Instrumentation](#wmiexec)
		- [Windows Remote Management(WinRM)](#winrmexec)
		- [Windows Trouble shooting Packs](#wtspexec)
		- 
	- [Persistence](#winpersist)
		- [101](#p101)
		- [Tactics](#ptactics)
		- [3rd Part Applications](#p3rd)
		- [Account Manipulation](#pacm)
		- [Accessibility Features](#pacf)
		- [Active Directory Specific](#pads)
		- [Alternate Data Streams](#pads)
		- [AMSI Provider](#pamsi)
		- [APPX/UWP](#papp)
		- [BITS Jobs](#pbits)
		- [Boot or Logon Autostart Execution](#pboot)
		- [Boot or Logon Initialization Scripts](#pbl)
		- [Compromise Client Software Binary](#ccsb)
		- [Create account](#pacc)
		- [Create or Modify System Process](#cmsp)
		- [DLL Injection/Hijacking](#pdll)
		- [Drivers](#pdriver)
		- [Event Triggered Execution](#pete)
		- [Extension Handlers](#pexth)
		- [External Remote Services](#pers)
		- [Filesystem](#pfs)
		- [Hijack Execution Flow](#phef)
		- [IIS Module](#piis)
		- [Implant Container Image
		- [LAPS](#plaps)
		- [Library Files](#plf)
		- [MS Distributed Transaction Coordinator](#pdtcs)
		- [.NET](#pnet)
		- [Netsh](#pnetsh)
		- [Office Applications](#poffice)
		- [Password Filter DLL](#pfdll)
		- [Port Monitors](#pportmon)
		- [Pre-OS Boot](#peboot)
		- [Print Processor](#pprint)
		- [Processes](#pppp)
		- [Registry](#preg)
		- [Scheduled Task/Job](#psctj)
		- [ScreenSaver](#pss)
		- [Services](#pss)
		- [Server Software Component](#pssc)
		- [SMB](#psmb)
		- [Windows Telemetry](#pwtm)
		- [Traffic Signaling](#pts)
		- [UEFI](#puefi)
		- [URI Scheme](#puri)
		- [Valid Accounts](#pva)
		- [VisualStudio](#pvs)
		- [WaitFor](#pwf)
		- [Windows Subsystem for Linux](#pwsl)
		- [WMI](#pwmi)
		- 
	- [Privilege Escalation](#winprivesc)
		- [101](#pe101)
		- DLL Stuff](#dllstuff)
		- Exploits/Missing Patches](#peemp)
		- Fax/Printer/Network Service](#pfp)
		- Group Policy (Preferences)](#gppf)
		- Intel SYSRET](#peis)
		- LAPS](#pelaps)
		- Local Phishing](#pelp)
		- Logic Bugs](#pelb)
		- Named Pipes](#penp)
		- Privileged File Operation Abuse](#pepfoa)
		- NTLM-Related](#pentlm)
		- Privilege Abuse](#pepa)
		- Privileged File Operations](#pepfo)
		- Registry Paths/Permissions](#perpp)
		- Services](#peservices)
		- Unquoted Service Paths](#peusp)
		- Stored Creds/Passwords on disk](#pescp)
		- Tokens](#petokens)
		- Obtaining System Privileges](#peosp)
		- Talks & Presentations](#petalks)
		- Tools](#petools)
		- Writeups](#pewriteups)
		- Exploits](#peexploits)
		- Just-Enough-Administration(JEA)](#pejea)
		- Microsoft](#pems)
		- MSSQL](#pemssql)
		- VirtualMachines](#pevm)
		- VMWare](#pemvw)
		- 
	- [Windows Defense Evasion](#windefev)
		- [Anti-Malware Scan Interface](#amsi)
		- [Anti-Virus](#winav)
		- [Application Whitelisting](#appwhitelist)
		- [Windows Defender](#defender)
		- [Microsoft ATA/P](#msatap)
		- [Callbacks](#callevade) - FIX
		- [Device Guard](#deviceguard)
		- [Event Tracing](#evtevade) - FIX
		- [Event Log](#eventlogevade) - FIX
		- 
	- [Credential Access](#wincredac)
		- [101](#wc101)
		- [Articles/Blogposts/Writeups](#wcabw)
		- [3rd Party](#wc3rd)
		- [Active Directory Environment](#wcad)
		- [AWS](#wcaws)
		- [AutoLogon](#wcal)
		- [Azure](#wcazure)
		- [Clipboard](#wcclip)
		- [CredSSP](#wcssp)
		- [DPAPI](#wcdpapi) - FIX
		- [Internal Monologue](#wcim)
		- [Keylogger](#wck)
		- [Local Account](#wcla)
		- [Local Phishing](#wclp)
		- [Logon](#wclog)
		- [Local Files](#wclocal)
		- [Local Security Authority Subsystem Service(LSA & LSASS)](#wclsass)
		- [Mimikatz/Similar](#wcmimi)
		- [MsvpPasswordValidate Hooking](#wcmpvh)
		- [NPLogonNotify()](#wcnpln)
		- [Dumping NTDS.dit](#wcntds)
		- [NTLM-related](#wcntlm)
		- [Password Filter DLL](#wcpfdll)
		- [Physical Memory](#wcpm)
		- [Dumping Process Memory](#wcdpm)
		- [RDP](#wcrdp)
		- [SeTrustedCredManaAccess](#wcstcma)
		- [Service Accounts](#wcsa)
		- [Tokens](#wctokens)
		- [Volume Shadow Copy Service](#wcvss)
		- [WDigest](#wcwd)
		- [Web Browsers -wcwb
		- [Wifi](#wcwifi)
		- [Tools](#wctools)
		- 
	- [Discovery](#windisco)
		- [101](#d101)
		- [AD](#dad)
		- [AppLocker](#dapp)
		- [Browser Cookies](#dbc)
		- [COM](#ddcom)
		- [Endpoint Protection](#dend)
		- [Event Log](#del)
		- [Files](#dfiles)
		- [Logs](#dlog)
		- [Mail](#dmail)
		- [NetworkCapture](#dcap)
		- [RPC](#drpc)
		- [SitRep](#dsit)
		- [User Awareness](#dua)
		- [General Tools](#dgt)
		- 
	- [Lateral Movement](#winlater)
		- [Articles/Blogposts/Writeups](#lmab)
		- [AppInit.dlls](#lappinit)
		- [BGInfo](#latbg)
		- [DCOM](#latdcom)
		- [Desired State Configuration](#latdsc)
		- [DLL Hijacking](#latdll)
		- [Excel](#latexcel)
		- [NTLM Relay](#ntlmr)
		- [Pass-The-Hash](#latpth)
		- [PS-Remoting](#latpsr)
		- [Protocol Handler](#latph)
		- [Port-Forwarding & Proxies](#latpfp)
		- [RDP](#latrdp)
		- [Registry](#latr)
		- [SCM](#latscm)
		- [Services](#latservices)
		- [ShadowMove](#latshadow)
		- [SMB](#latsmb)
		- [SSH](#latssh)
		- [WinRM](#latwinrm)
		- [WMI](#latwmi)
		- [WSH](#latwsh)
		- [Abusing Already Installed Applications](#latabuse)
		- 
	- [Collection](#wincollect)
		- [Articles/Blogposts/Writeups](#cabw)
		- [Browser](#cb)
		- [CC](#ccc)
		- [Code Storage](#ccs)
		- [KeePass](#ckp)
		- [Outlook](#cou)
		- [PCAP](#cpcap)
		- [Skype](#cskype)
		- [Video](#cvideo)
		-	
- [Windows Specific Technologies](#wintech)
	- [Alternate Data Streams](#wads)
	- [AppLocker](#winapplocker)
	- [Application Shims](#winappshim)
	- [Bitlocker](#bitlocker)
	- [ClickOnce](#clickonce)
	- [Credential Guard](#credguard)
	- [Code Signing](#codesign)
	- [(Distributed) Component-Object-Model(COM)](#dcom)
	- [Data Protection API(DPAPI)](#dpapi)
	- [Device Guard](#devguard)
	- [Dynamic Link Library](#dll)
	- [Event Tracing for Windows](#etw)
	- [Print & Fax](#printfax)
	- [Fibers](#winfiber)
	- [File Extensions](#winfex)
	- [Hooking in Windows](#winhook)
	- [Kernel Operations](#winkernel)
	- [LNK Files](#LNK)
	- [Windows Logging](#winlog)
	- [MS-SQL Server](#ms-sql-server)
	- [Named Pipes](#namedpipes)
	- [PowerShell](#powershell)
	- [PowerShell Desired State](#winpsc)
	- [Privileges](#winprivs)
	- [Processes](#winprocesses)
	- [Tokens](#wintokens)
	- [Windows Communication Foundation](#wcf)
	- [Windows Managemet Instrumentation](#wmi)
	- [Windows Notification Facility](#wnf)
	- [Windows Remote Management](#winrm)
	- [Windows Scripting Host](#wsh)
	- 
----------------------------------------------------------------------










------------------------------------------------------------------------------------------------------------------------------------
### <a name="winpost">Post-Exploitation Windows</a>
* **101**<a name="win101"></a>
	* [Windows CMD Reference - ms](https://www.microsoft.com/en-us/download/details.aspx?id=56846)
* **Unsorted**
	* [Abusing DComposition to render on external windows - yousif(2020)](https://secret.club/2020/05/12/abusing-compositions.html)
		* [Code](https://github.com/thesecretclub/window_hijack)
* **Living_off_The_Land**<a name="lolbins-win"></a>
	* **101**
		* [Living Off The Land: A Minimalist's Guide To Windows Post Exploitation - Christopher Campbell, Matthew Graeber(Derbycon3)](https://www.youtube.com/watch?v=j-r6UonEkUw)
		* [LOLBins - Living Off The Land Binaries & Scripts & Libraries](https://github.com/LOLBAS-Project/LOLBAS)
			* "Living off the land" was coined by Matt Graeber - @mattifestation <3"
			* The term LOLBins came from a twitter discussion on what to call these binaries. It was first proposed by Philip Goh - @MathCasualty here: https://twitter.com/MathCasualty/status/969174982579273728
			* The term LOLScripts came from Jimmy - @bohops: https://twitter.com/bohops/status/984828803120881665
		* [Installers – Interactive Lolbins - Hexacorn](http://www.hexacorn.com/blog/2019/04/18/installers-interactive-lolbins/)
		* [WinBinDex - The Windows Binaries Index](https://winbindex.m417z.com/)
			* [Introducing Winbindex - the Windows Binaries Index - Michael Maltsev(2020)](https://m417z.com/Introducing-Winbindex-the-Windows-Binaries-Index/)
			* [winbindex](https://github.com/m417z/winbindex)
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
		* [Living Off Windows Land – A New Native File “downldr” - Gal Kristal(2020)](https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/)
		* [Also Node.js has been used to perform a Living off the Land (LotL) attack - Andrea Fortuna(2019)](https://www.andreafortuna.org/2019/10/02/also-node-js-has-been-used-to-perform-a-living-off-the-land-lotl-attack/)
		* [Upload and download small files with CertReq.exe - DTM(2020)](https://dtm.uk/certreq/)
		* [Staying Off the Land: A Threat Actor Methodology - Crowdstrike(2020)](https://www.crowdstrike.com/blog/staying-off-the-land-methodology/)
		* [Load/Inject malicious DLL using Microsoft Tools - safe(2018)](https://web.archive.org/web/20180203110920/https://safe-cyberdefense.com/load-inject-malicious-dll-using-microsoft-tools/)
		* [FalconFriday — Masquerading; LOLBin file renaming— 0xFF0C - Olaf Hartong(2021)](https://medium.com/falconforce/falconfriday-masquerading-lolbin-file-renaming-0xff0c-b01e0ab5a95d)
		* [Abusing and Detecting LOLBIN Usage of .NET Development Mode Features - BOHOPS(2021](https://bohops.com/2021/05/30/abusing-and-detecting-lolbin-usage-of-net-development-mode-features/)
			* From an attacker’s perspective, configuration adjustments provide interesting opportunities for living-off-the-land-binary (lolbin) execution. In this short post, we’ll highlight a technique for turning pretty much any .NET executable into an opportunistic lolbin that abuses .NET development features by overriding Global Assembly Cache (GAC) path lookups. Furthermore, we’ll examine several defensive considerations for detecting malicious use of the presented technique.
		* [Living off the land - Slayerlabs(2021)](https://posts.slayerlabs.com/living-off-the-land/)
		* [BYOT – Bring Your Own Telemetry - Hexacorn(2021)](https://www.hexacorn.com/blog/2021/05/20/byot-bring-your-own-telemetry/)
		* [Symantec Endpoint Protection Meets COM — Using “Symantec.SSHelper” As A LOLBIN - Nasreddine Bencherchali(2021)](https://nasbench.medium.com/symantec-endpoint-protection-meets-com-using-symantec-sshelper-as-a-lolbin-40d515a121ce)
	* **Talks/Presentations/Videos**
		* [Living Off the Land: A Minimalist’s Guide to Windows Post-Exploitation - Christopher Campbell, Matthew Graeber(Derybcon2013)](https://www.irongeek.com/i.php?page=videos/derbycon3/1209-living-off-the-land-a-minimalist-s-guide-to-windows-post-exploitation-christopher-campbell-matthew-graeber)
			* Two of the biggest challenges of long-term penetration tests are advanced security products and active administrators. Host intrusion prevention, application white-listing and antivirus software are all looking for your tools. Administrators and network defenders are doing everything they can to find you. Surprisingly, the easiest way to hide from them and homestead in a Windows enterprise is to live off the land. Microsoft provides you with all the tools you need to get into a network and live there forever. Tools such as Wmic, Netsh and PowerShell are well-known to administrators, but they also provide an attacker a whole range of virtually untapped features. By simply leveraging PowerSploit and a few tricks you can reliably bypass antivirus, get around whitelisting, escalate privileges, redirect network traffic, take full packet captures, log keystrokes, take screenshots, dump hashes, persist and pivot to other hosts all without introducing a single binary!
		* [Code Execution with JDK Scripting Tools & Nashorn Javascript Engine - Brett Hawkins(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-4-13-code-execution-with-jdk-scripting-tools-nashorn-javascript-engine-brett-hawkins)
			* There are several languages and methods used to execute code on a computer system, such as C#, Powershell, Python, VBA, and many more. The defense is getting better, which has caused the offense to adapt and look for innovative ways to “live off the land”. One area that has not been explored deeply is utilizing tools that the Java Development Kit (JDK) provides. According to a statement by Oracle, Java runs on 3 billion devices. Enterprises depend on Java running on their user endpoints and servers in order to keep their businesses running. This makes using tools installed with the JDK very enticing to attackers. This talk will explore using JDK command-line scripting tools and the Nashorn Javascript Engine to perform several actions, such as downloading files, executing scripts locally and remotely, and gaining a remote interactive shell to a computer system. Detective and preventive controls will also be discussed for the usage of these JDK scripting tools.
		* [Living off the land: enterprise post-exploitation - Adam Reiser(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-3-19-living-off-the-land-enterprise-post-exploitation-adam-reiser)
			* You've compromised that initial server and gained a foothold in the target network: congratulations! But wait - the shadow file has no hashes but root, the ssh keys have strong passphrases, and all the interesting traffic is encrypted - there's nothing of value here! Or is there? In this talk, I will explore post-exploitation techniques for turning your compromised bastion hosts into active credential interceptors under a variety of blue team monitoring scenarios.
		* [WEBCAST: Hacker Tools, Compliments of Microsoft - David Fletcher & Sally Vandeven(2018)](https://www.blackhillsinfosec.com/webcast-hacker-tools-compliments-of-microsoft/)
			* [Slides](https://blackhillsinformationsecurity.shootproof.com/gallery/6973715/)
			* Join David “Fletch” and Sally as they explore the cornucopia of wonderful, free tools in the SysInternals Suite that conveniently are signed by Microsoft and that they use on a daily basis to hack their customers.		
		* [#LOLBins - Nothing to LOL about! - Oddvar Moe(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-1-01-lolbins-nothing-to-lol-about-oddvar-moe)
			* You have probably heard the term LOLBin, LOLScript or LOLLib by now. Want to get more insights on that? Then this is the talk you want to attend.This talk will cover the Living Off The Land Binaries and Scripts (LOLBAS) project, what the project is, how it became and how you can help this evolve into the future. The talk will also go over some of my favorite LOLBins that has came to light due to this project (at least that's what I like to think) and show you some cool stuff! I mean, everybody loves to see binaries misbehave.
		* [Covert Attack Mystery Box: A few novel techniques for exploiting Microsoft "features" - Mike Felch and Beau Bullock (WWHF2018)](https://www.youtube.com/watch?v=XFk-b0aT6cs)
			* Over the last few months we’ve been doing a bit of research around various Microsoft “features”, and have mined a few interesting nuggets that you might find useful if you’re trying to be covert on your red team engagements. This talk will be “mystery surprise box” style as we’ll be weaponizing some things for the first time. There will be demos and new tools presented during the talk. So, if you want to win at hide-n-seek with the blue team, come get your covert attack mystery box!
	* **In-the-Spirit-Of**
		* [BADministration](https://github.com/ThunderGunExpress/BADministration)
			* BADministration is a tool which interfaces with management or administration applications from an offensive standpoint. It attempts to provide offsec personnel a tool with the ability to identify and leverage these non-technical vulnerabilities. As always: use for good, promote security, and fight application propagation.
	* **Not really**
		* [Windows Store Apps Can Compromise PC Security - Russell Smith](https://www.petri.com/windows-store-apps-can-compromise-pc-security)
* **Bring-Your-Own-Land**
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
		* [BYOI (Bring Your Own Interpreter) payloads - Marcello Salvati(RomHack2020)](https://www.youtube.com/watch?v=KvMBHNo7mZk&list=PL1UJVNzpT9Z4fWDJnVbq_gEs0udEKpat6&index=2)
			* [Slides](https://www.romhack.io/dl-2020/RH2020-slides-Salvati.pdf)
			* Offensive PowerShell tradecraft is in “Zombie Mode”: it’s sort of dead, but not entirely. With all of the defenses Microsoft has implemented in the PowerShell runtime over the past few years Red Teamers / Pentesters & APT groups have started too shy away from using PowerShell based payloads/delivery mechanisms and migrate over to C#. However, C# is a compiled language. Operationally this has a few major downsides: we can’t be as “flexible” as setting up a proper development environment has an overhead and can be time consuming and you have to compile all the things all the time etc.
* **Bring-Your-Own-Driver**
	* **Articles/Blogposts/Writeups**
		* [Mimidrv In Depth: Exploring Mimikatz’s Kernel Driver - Matt Hand(2020)](https://posts.specterops.io/mimidrv-in-depth-4d273d19e148)
		* [Defeating RunAsPPL: Utilizing Vulnerable Drivers to Read Lsass with Mimikatz - Gorkem Karadeniz(2020)](https://medium.com/@gorkemkaradeniz/defeating-runasppl-utilizing-vulnerable-drivers-to-read-lsass-with-mimikatz-28f4b50b1de5)
		* [LoJax: First UEFI rootkit found in the wild, courtesy of the Sednit group - ESET(2018)](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/)
* **Execution**<a name="winexec"></a>
	* **Articles/Blogposts/Writeups**
		* [CodeExecutionOnWindows](https://github.com/pwndizzle/CodeExecutionOnWindows)
			* A list of ways to execute code, including examples, are shown below. Note that UAC bypasses and DLL hijacking will not be included as these are covered elsewhere.
	* **LoLBins**<a name="winlolexec"></a>
		* **Certreq.exe**
			* [Upload and download small files with CertReq.exe - dtm(2020)](https://dtm.uk/certreq/)
		* **Nuget/Squirrel/Electron**
			* [Squirrel packages’ manager as a lolbin (a.k.a. many Electron apps are lolbins by default) - hexacorn(2019)](http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/)
			* [Nuget/Squirrel uncontrolled endpoints leads to arbitrary code execution - Reegun J](https://medium.com/@reegun/nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-80c9df51cf12)
				* [Part 2](https://medium.com/@reegun/update-nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-b55295144b56)
		* **Microsoft.Workflow.Compiler.exe**
			* [Arbitrary, Unsigned Code Execution Vector in Microsoft.Workflow.Compiler.exe - Matt Graeber(2018)](https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb)
			* [How to Port Microsoft.Workflow.Compiler.exe Loader to Veil - FortyNorthSecurity(2018)](https://fortynorthsecurity.com/blog/how-to-port-microsoft-workflow-compiler-exe-loader-to-veil/)
		* **MSBuild**
			* **101**
				* [MSBuild - docs.ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild?view=vs-2019)
				* [MSBuild Inline Tasks - docs.ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks?view=vs-2015)
				* [Understanding the Project File(MSBuild) - docs.ms](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/deployment/web-deployment-in-the-enterprise/understanding-the-project-file)
				* [Understanding the project file - docs.ms](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/deployment/web-deployment-in-the-enterprise/understanding-the-project-file)
					* Microsoft Build Engine (MSBuild) project files lie at the heart of the build and deployment process. This topic starts with a conceptual overview of MSBuild and the project file. It describes the key components you'll come across when you work with project files, and it works through an example of how you can use project files to deploy real-world applications.
			* **Articles/Blogposts/Writeups**
				* [MSBuild: A Profitable Sidekick! - Sarah Norris(2020)](https://www.trustedsec.com/blog/msbuild-a-profitable-sidekick/)
				* [MSBuild without MSBuild - pentestlaboratories(2020)](https://pentestlaboratories.com/2020/01/27/msbuild-without-msbuild/)
					* [...]MSBuild is no longer required to execute code since it is possible to use a .NET assembly that will call the malicious .csproj from a remote location (UNC path). This technique doesn’t leave any artifacts since it doesn’t touch the disk and the code is injected into a legitimate Windows process Internet Explorer. 
				* [Doing More With MSBuild - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-MSBuild-To-Do-More/)
				* [Remotely Host MSBuild Payloads - Joe Leon(2020)](https://fortynorthsecurity.com/blog/remotely-host-msbuild-payloads/)
					* tl;dr Separate your C# payload from a MSBuild XML file and host it remotely on a WebDav server.
				* [Another MSBuild Invocation (February 2020 Edition) - Joe Leon(2020)](https://fortynorthsecurity.com/blog/another-msbuild-bypass-february-2020-edition/)
					* TL;DR: Use MSBuild’s UnregisterAssembly task to execute arbitrary code in a .NET assembly.
			* **Tools**
				* [MSBuild](https://github.com/dotnet/msbuild)
				* [MSBuildAPICaller](https://github.com/rvrsh3ll/MSBuildAPICaller)
					* MSBuild Without MSBuild.exe
				* [NoMSBuild](https://github.com/rvrsh3ll/NoMSBuild)
					* MSBuild without MSbuild.exe
		* **MSI**
			* [Windows Installer - docs.ms](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-portal)
			* [Windows Installer - Wikipedia](https://en.wikipedia.org/wiki/Windows_Installer)
			* [The Return of Raining SYSTEM Shells with Citrix Workspace app - ](https://www.pentestpartners.com/security-blog/the-return-of-raining-system-shells-with-citrix-workspace-app/)
				* Back in July I documented a new Citrix Workspace vulnerability that allowed attackers to remotely execute arbitrary commands under the SYSTEM account.  Well after some further investigation on the initial fix I discovered a new vector that quite frankly should not exist at all since the previous reported vulnerability.  The core of the issue lies with a remote command line injection vulnerability that allows attackers to bypass Citrix signed MSI installers using a malicious MSI transform.
			* [PwnyForm](https://github.com/CCob/PwnyForm)
				* PwnyForm will take an MSI installer as input and generate an MSI transform (mst) that can be used to inject arbitrary command execution by adding a custom action that will execute during the UI or Install sequence of an MSI file. The generated MST produces a JScript custom action that will by default launch cmd.exe, the executed command can be overriden using the CMD MSI property
		* **MSHTA**
			* [Internet Explorer MSHTA Security Threat - Dennis Faas(2003)](https://www.infopackets.com/news/252/internet-explorer-mshta-security-threat)
			* [The Malware Hiding in Your Windows System32 Folder: Mshta, HTA, and Ransomware - Andy Green(2020)](https://www.varonis.com/blog/living-off-the-land-lol-with-microsoft-part-ii-mshta-hta-and-ransomware/)
			* [MSHTA code execution - bypass application whitelisting. - @spottheplanet](https://ired.team/offensive-security/code-execution/t1170-mshta-code-execution)
			* [Bypass Application Whitelisting using mshta.exe (Multiple Methods) - Raj Chandel](https://www.hackingarticles.in/bypass-application-whitelisting-using-mshta-exe-multiple-methods/)
			* [w.e w.e Internet Explorer Does What It Wants - Aaron Heikkila(GrrCON2018)](https://www.irongeek.com/i.php?page=videos/grrcon2018/grrcon-2018-augusta16-we-we-internet-explorer-does-what-it-wants-aaron-heikkila)
		* **MS Office**
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
		* **MS Teams**
			* [Microsoft Teams Can Be Used to Download and Run Malicious Packages - Ionut Ilascu(2019)](https://www.bleepingcomputer.com/news/security/microsoft-teams-can-be-used-to-download-and-run-malicious-packages/)
		* **Windows Update Client(wuauclt)**
			* [Code execution via the Windows Update client (wuauclt) - dtm(2020)](https://dtm.uk/wuauclt/)
		* **3rd-Party LoLbins**
			* [Exploring an Assembly Loading Technique and Detection Mechanism for the GfxDownloadWrapper.exe LOLBIN - bohops(2020)](https://bohops.com/2020/10/21/exploring-an-assembly-loading-technique-and-detection-mechanism-for-the-gfxdownloadwrapper-exe-lolbin/)
	* **Command and Scripting Interpreter**<a name="wincmdexec"></a>
		* **Cmd.exe**
			* **Articles/Blogposts/Writeups**
				* [Create Your Own CMD.XLS - Didier Stevens(2016](https://blog.didierstevens.com/2016/02/10/create-your-own-cmd-xls/)
				* [cmd.exe running any file no matter what extension - Hexacorn](http://www.hexacorn.com/blog/2019/04/21/cmd-exe-running-any-file-no-matter-what-extension/)
				* [Command line do-nothingness - hexacorn(2020)](https://www.hexacorn.com/blog/2020/05/23/command-line-do-nothingness/)
			* **CMD Arg Spoofing**
				* **Articles/Blogposts/Writeups**
					* [How to Argue like Cobalt Strike - Adam Chester(2019)](https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/)
					* [The return of the spoof part 2: Command line spoofing](https://blog.nviso.eu/2020/02/04/the-return-of-the-spoof-part-2-command-line-spoofing/)
				* **Tools**
					* [Sharp-Suite - Process Argument Spoofing](https://github.com/FuzzySecurity/Sharp-Suite)
			* **Obfuscation**
				* **Articles/Blogposts/Writeups**
					* [DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and Detection Techniques - Daniel Bohannon(2018)](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)
					* [Cmd Hijack - a command/argument confusion with path traversal in cmd.exe - Julian Horoszkiewicz(2020)](https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/)
					* [Hiding process creation and cmd line with a long com… - Hexacorn(2020)](https://www.hexacorn.com/blog/2020/03/29/hiding-process-creation-and-cmd-line-with-a-long-com/)
					* [Tried and True Hacker Technique: DOS Obfuscation - John Hammond(2020)](https://blog.huntresslabs.com/tried-and-true-hacker-technique-dos-obfuscation-400b57cd7dd)
					* [Windows Command-Line Obfuscation - @Wietze(2021)](https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation)
				* **Tools**
					* [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
						* Cmd.exe Command Obfuscation Generator & Detection Test Harness
			* **PPID Spoofing**
				* **Articles/Blogposts/Writeups**
					* [Quickpost: SelectMyParent or Playing With the Windows Process Tree - Didier Stevens(2009)](https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/)
					* [The return of the spoof part 1: Parent process ID spoofing - Jean-Francois Maes(2020)](https://blog.nviso.eu/2020/01/31/the-return-of-the-spoof-part-1-parent-process-id-spoofing/)
					* [Parent Process ID (PPID) Spoofing - @spotheplanet](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing)		
		* **.NET**
			* **Articles/Blogposts/Writeups**
				* [Running a .NET Assembly in Memory with Meterpreter - Thomas Hendrickson(2019)](https://www.praetorian.com/blog/running-a-net-assembly-in-memory-with-meterpreter)
					* In this blog post I will discuss leveraging Meterpreter’s powershell module to execute .NET assemblies in-memory.
		* **WebAssembly**
			* **Articles/Blogposts/Writeups**
				* [WebAssembly – Executing malicious code using System() - Kartik Durg(2020)](https://iamroot.blog/2020/06/29/webassembly-executing-malicious-code-using-system/)
			* **Tools**
				* [WASSUP-WASM](https://github.com/kartikdurg/WASSUP-WASM)
					* "WASSUP-WASM" is a tiny application that can be used to download and execute the WebAssembly binary using Node.JS.
		* **XSL Script Processing**
			* **Articles/Blogposts/Writeups**
			* **Tools**
	* **Compiled HTML Files**<a name="winchmexec"></a>
		* **101**
			* [Microsoft Compiled HTML Help - Wikipedia](https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help)
			* [List of CHM readers and viewers for Window - kowalczyk.info](https://blog.kowalczyk.info/articles/chm-reader-viewer-for-windows.html)
			* [Unofficial (Preliminary) HTML Help Specification - Paul Wise, Jed Wing(2005)](https://www.nongnu.org/chmspec/latest/)
		* **Articles/Blogposts/Writeups**
			* [CHM Badness Delivers a Banking Trojan - Rodel Mendrez(2017)](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/)
			* [Malicious CHM Files Being Used to Install Brazilian Banking Trojans - Lawrence Abrams(2017)](https://www.bleepingcomputer.com/news/security/malicious-chm-files-being-used-to-install-brazilian-banking-trojans/)
			* [PuTTY vulnerability vuln-chm-hijack - chiark.greenend.org(2019)](https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-chm-hijack.html)
				* Potential malicious code execution via CHM hijacking
			* [What the Shell? New Security Breach Uses CHM Files to Cover Banking Trojans - Douglas Bonderud(2017)](https://securityintelligence.com/news/what-the-shell-new-security-breach-uses-chm-files-to-cover-banking-trojans/)
		* **Tools**
			* [Malicious-CHM-Guide.md - mgeeky](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7)
				* CheatSheet describing how to create malicious CHM file by hand (another approach is to use Nishang's Out-Chm scriptlet).
			* [PuTTY vulnerability vuln-chm-hijack](https://github.com/yasinyilmaz/vuln-chm-hijack)
				* Potential malicious code execution via CHM hijacking (CVE-2019-9896)
			* [Out-CHM.ps1](https://github.com/samratashok/Kautilya/blob/master/extras/Out-CHM.ps1)
	* **Component-Object-Model**<a name="wincomexec"></a>
		* **101**
			* See [(D)COM](#dcom)
		* **Articles/Blogposts/Writeups**
			* [COM XSL Transformation: Bypassing Microsoft Application Control Solutions (CVE-2018-8492) - BOHOPS(2019)](https://bohops.com/2019/01/10/com-xsl-transformation-bypassing-microsoft-application-control-solutions-cve-2018-8492/)
	* **ControlPanel Items**<a name="wincplexec"></a>
		* **101**
			* [Description of Control Panel (.cpl) Files - support.ms](https://support.microsoft.com/en-us/help/149648/description-of-control-panel-cpl-files)
			* [Implementing Control Panel Items - docs.ms](https://docs.microsoft.com/en-us/windows/win32/shell/control-panel-applications)
		* **Articles/Blogposts/Writeups**
			* [Starting a Dynamic-link Library as a Control Panel File(Vault7)](https://wikileaks.org/ciav7p1/cms/page_13763468.html)
			* [FalconFriday — Process injection and malicious CPL files — 0xFF03 - Henri Hambartsumyan(2020)](https://medium.com/falconforce/falconfriday-process-injection-and-malicious-cpl-files-0xff03-8ba1ee5da64)
			* [Executing Code as a Control Panel Item through an Exported Cplapplet Function - @spottheplanet](https://www.ired.team/offensive-security/code-execution/executing-code-in-control-panel-item-through-an-exported-cplapplet-function)
			* [Code Execution through Control Panel Add-ins - @spottheplanet](https://www.ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins)
		* **Tools**
			* [CPLResourceRunner](https://github.com/rvrsh3ll/CPLResourceRunner)
				* Run shellcode from resource
	* **DLL-Related**<a name="windllexec"></a>
		* **101**
			* [DLLsForHackers](https://github.com/Mr-Un1k0d3r/DLLsForHackers)
				* Dlls that can be used for side loading and other attack vectors. This Dll will not cause deadlock since it only use functions that are DllMain safe as described below.
		* **DLL Injection**
			* See [DLL Injection](#dllinject)
		* **Hijacking**
			* **Articles/Blogposts/Writeups**
				* [MITRE ATT&CK turned purple – Part 1: Hijack execution flow - NVISO(2020)](https://blog.nviso.eu/2020/10/06/mitre-attack-turned-purple-part-1-hijack-execution-flow/)
			* **Tools**
				* [DLLHijackTest](https://github.com/slyd0g/DLLHijackTest)
		* **Proxying**<a name="dllproxy"></a>
				* [DLL Import Redirection in Windows 10 1909 - James Forshaw(2020)](https://www.tiraniddo.dev/2020/02/dll-import-redirection-in-windows-10_8.html)
			* **Articles/Blogposts/Writeups**
				* [I’M SO excited - Hexacorn(2019)](http://www.hexacorn.com/blog/2019/10/03/im-so-excited/)
				* [DLL Proxying for Persistence - @spottheplanet](https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence)
				* [Sideloading DLL like APT1337 - flangvik.com(2019)](https://flangvik.com/privesc/windows/bypass/2019/06/25/Sideload-like-your-an-APT.html)
				* [Bypassing AV's using DLL Side-Loading - flangvik.com(2019)](https://flangvik.com/2019/07/24/Bypassing-AV-DLL-Side-Loading.html)
				* [DLL Proxy Loading Your Favourite C# Implant - Flangvik(2020)](https://redteaming.co.uk/2020/07/12/dll-proxy-loading-your-favorite-c-implant/)
				* [Adding DLL Exports with dnlib - RastaMouse(2020)](https://offensivedefence.co.uk/posts/dnlib-dllexport/)
			* **Tools**
				* [dll-exports](https://github.com/magnusstubman/dll-exports)
					* Collection of DLL function export forwards for DLL export function proxying
	* **Downloaders**<a name="dlers"></a>
		* [Using signed Installshield installers as downloaders - hexacorn(2019)](https://www.hexacorn.com/blog/2019/06/02/using-signed-installshield-installers-as-downloaders/)
	* **Exploitation for Client Execution**
		* **Articles/Blogposts/Writeups**
			* [CVE-2019-0726 - MWRLabs](https://labs.mwrinfosecurity.com/advisories/windows-dhcp-client/)
				* DHCP client rce
			* [Analysis of CVE-2020-0605 – Code Execution using XPS Files in .NET - MDSec(2020)](https://www.mdsec.co.uk/2020/05/analysis-of-cve-2020-0605-code-execution-using-xps-files-in-net/)
				* Microsoft patched a number of deserialisation issues using the XPS files. Although the patch for CVE-2020-0605 was released in January 2020, it was incomplete and an additional update was released in May 2020. The patched issue could be useful to exploit any code that deals with the XPS file using .NET libraries. The identified issues could also be helpful as bridged gadgets when exploiting XAML deserialisation related issue.
	* **Indirect Execution**<a name="indirexec"></a>
		* [Indirect Command Execution - penetestlab.blog](https://pentestlab.blog/2020/07/06/indirect-command-execution/)
	* **Inter-Process Communication**<a name="eipc"></a>
		* **Component Object Model and Distributed COM**
			* **Articles/Blogposts/Writeups**
				* [Forcing Iexplore.exe to Load a Malicious DLL via COM Abuse - ired.team](https://ired.team/offensive-security/code-execution/forcing-iexplore.exe-to-load-a-malicious-dll-via-com-abuse)
			* **Tools**
		* **DDE**
			* See [Phishing.md](./Phishing.md)
			* **Articles/Blogposts/Writeups**
				* [DDE Downloaders, Excel Abuse, and a PowerShell Backdoor - rinseandREpeat analysis](https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html)
			* **Tools**
	* **Scripting Host**<a name="esch"></a>
		* **Articles/Blogposts/Writeups**
			* [Executing Arbitrary Assemblies In The Context Of Windows Script Hosts - realoriginal(2019)](https://gist.github.com/realoriginal/4d1dc116452c47e0a5b46cd4f63e96ec)
		* **Talks/Presentations/Videos**
			* [Establishing A Foothold With JavaScript - Casey Smith(Derbycon2016)](https://www.irongeek.com/i.php?page=videos/derbycon6/522-establishing-a-foothold-with-javascript-casey-smith)
				* Yes, you read that right. JavaScript is everywhere, and is often overlooked. This talk will briefly outline some tactics you can use to establish a foothold and persist in an Enterprise network using only JavaScript. I will demonstrate some fileless persistence mechanisms.
	* **Native API(Syscalls & WinAPI)**<a name="enapi"></a>
		* **101**
			* [Windows API - Wikipedia](https://en.wikipedia.org/wiki/Windows_API)
			* [How Do Windows NT System Calls REALLY Work? - John Gulbrandsen](https://www.codeguru.com/cpp/w-p/system/devicedriverdevelopment/article.php/c8035/How-Do-Windows-NT-System-Calls-REALLY-Work.htm)
			* [FreshyCalls: Syscalls Freshly Squeezed! - ElephantSe4l(2020)](https://www.crummie5.club/freshycalls/)
		* **(Un)Official Documentation**
			* [Windows API index - docs.ms](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
				* The following is a list of the reference content for the Windows application programming interface (API) for desktop and server applications. Using the Windows API, you can develop applications that run successfully on all versions of Windows while taking advantage of the features and capabilities unique to each version. (Note that this was formerly called the Win32 API. The name Windows API more accurately reflects its roots in 16-bit Windows and its support on 64-bit Windows.)
			* [System calls: What are system calls and why are they necessary? - ionos.com](https://www.ionos.com/digitalguide/server/know-how/what-are-system-calls/)
			* [System Calls - docs.ms](https://docs.microsoft.com/en-us/cpp/c-runtime-library/system-calls?view=msvc-160&viewFallbackFrom=vs-2019)
			* [WinAPI Documentation - Steve Donovan](https://stevedonovan.github.io/winapi/api.html)
		* **Learning**
			* [Struggling between syscall or sysenter (Windows) - StackOverflow](https://reverseengineering.stackexchange.com/questions/16454/struggling-between-syscall-or-sysenter-windows/16511#16511)
			* [System calls on Windows x64 - n4r1b(2019)](https://www.n4r1b.com/posts/2019/03/system-calls-on-windows-x64/)
			* [Introduction to Windows API - ZetCode(2020)](https://zetcode.com/gui/winapi/introduction/)
			* [Tutorial Understanding Windows SysCalls - SysCall Dumper - Timb3r](https://guidedhacking.com/threads/understanding-windows-syscalls-syscall-dumper.14470/)
			* [Undocumented Windows API Functions & Structures - Rake(2020)](https://guidedhacking.com/threads/undocumented-windows-functions-structures.14438/)
			* [Windows Native API - Roger Orr(ACCU 2019)](https://www.youtube.com/watch?v=a0KozcRhotM)
				* Many programmers are familiar with the Windows "Win32" API that provides access to a large variety of services, from user interface to memory management; but far fewer have much idea about the Windows "Native" API which is the mechanism used to access the operating system services located in the kernel.  While it is rare to need to use these services directly (since the Win32 API provides a richer, better supported, and documented interface) it can be very useful to have some understanding of what is going on 'under the covers' inside this API.  I will look at the Native API from the application programmer’s point of view and will also touch on how Microsoft provides a 32bit subsystem in the 64bit version of Windows.  I hope this session will be of interest to all those who like to know more about how things work!
		* **Syscall Numbers**
			* [Windows X86-64 System Call Table (XP/2003/Vista/2008/7/2012/8/10) - Mateusz "j00ru" Jurczyk](https://j00ru.vexillium.org/syscalls/nt/64/)
			* [On Windows Syscall Mechanism and Syscall Numbers Extraction Methods  - Simone Margaritelli(2014)](https://www.evilsocket.net/2014/02/11/on-windows-syscall-mechanism-and-syscall-numbers-extraction-methods/)
		* **Using Them**
			* [SharedUserData SystemCall Hook - bugcheck, skape(2005)](http://uninformed.org/index.cgi?v=3&a=4&p=22)
			* [Making Raw Syscalls on Windows From Python - Spencer(2017)](https://warroom.rsmus.com/making-syscalls-python/)
			* [Calling Syscalls Directly from Visual Studio to Bypass AVs/EDRs - @spottheplanet](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs)
			* [Retrieving ntdll Syscall Stubs from Disk at Run-time - @spottheplanet](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time)
			* [Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR - Cornelis de Plaa(2019)](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
				* In this blog post we will explore the use of direct system calls, restore hooked API calls and ultimately combine this with a shellcode injection technique called sRDI. We will combine these techniques in proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike, while not touching disk and evading AV/EDR monitored user-mode API calls.
			* [Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams - @modexpblog(2020)](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
			* [Implementing Direct Syscalls Using Hell’s Gate - N4kedTurtle(2020)](https://teamhydra.blog/2020/09/18/implementing-direct-syscalls-using-hells-gate/)
			* [Syscalls with D/Invoke - RastaMouse2021](https://offensivedefence.co.uk/posts/dinvoke-syscalls/)
			* [Hiding your syscalls - passthehashbrowns(2021](https://passthehashbrowns.github.io/hiding-your-syscalls)
				* [Code](https://github.com/passthehashbrowns/hiding-your-syscalls)
		* **Syscall Filtering**
			* [Rainbow Over the Windows: More Colors Than You Could Expect - @zer0mem, @long123king(2016)](https://www.slideshare.net/PeterHlavaty/rainbow-over-the-windows-more-colors-than-you-could-expect)
			* [Win32k System Call Filtering Deep Dive - Morten Schenk(2017)](https://improsec.com/tech-blog/win32k-system-call-filtering-deep-dive)
		* **Articles/Blogposts/Writeups**
			* [Accessing the Windows API Directly - Osanda Malith(2015](https://osandamalith.com/2015/02/19/accessing-the-windows-api-directly/)
			* [I Like Syscalls (And I Cannot Lie) - Steiner(2015)](https://warroom.rsmus.com/i-like-syscalls-and-i-cannot-lie/)
			* [Using Syscalls to Inject Shellcode on Windows - Solomon Sklash(2020)](https://www.solomonsklash.io/syscalls-for-shellcode-injection.html)
			* [Red Team Tactics: Utilizing Syscalls in C# - Prerequisite Knowledge - Jack Halon](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/)
			* [Red Team Tactics: Utilizing Syscalls in C# - Writing The Code - Jack Halon](https://jhalon.github.io/utilizing-syscalls-in-csharp-2/)
			* [The Windows 10 TH2 INT 2E mystery - Adrien Chevalier(2018)](https://blog.amossys.fr/windows10_TH2_int2E_mystery.html)
			* [Malware Mitigation when Direct System Calls are Used - Hod Gavriel(2018)](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/)
			* [System Call Monitoring Despite KPP - Jason(2018](https://redvice.org/2018/system-call-monitoring/)
			* [SharedUserData SystemCall Hook - uninformed Vol.3](http://uninformed.org/index.cgi?v=3&a=4&p=22)
			* [Fuzzing the Windows API for AV Evasion - Winternl(2020)](https://winternl.com/fuzzing-the-windows-api-for-av-evasion/)
			* [Detecting Manual Syscalls from User Mode - jackullrich(2021](https://winternl.com/detecting-manual-syscalls-from-user-mode/)
			* [Detecting Hooked Syscalls - @spotheplanet](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions)
				* It's possible to enumerate which Windows API calls are hooked by an EDR using inline patcihng technique, where a jmp instruction is inserted at the beginning of the syscall stub to be hooked.
		* **Talks/Presentations/Videos**
			* [Getting Windows to Play with Itself: A Pen Testers Guide to Windows API Abuse - Brady Bloxham(Derbycon2014)](https://www.irongeek.com/i.php?page=videos/derbycon4/t122-getting-windows-to-play-with-itself-a-pen-testers-guide-to-windows-api-abuse-brady-bloxham)
				* Windows APIs are often a blackbox with poor documentation, taking input and spewing output with little visibility on what actually happens in the background. By reverse engineering (and abusing) some of these seemingly benign APIs, we can effectively manipulate Windows into performing stealthy custom attacks using previously unknown persistent and injection techniques. In this talk, we’ll get Windows to play with itself nonstop while revealing 0day persistence, previously unknown DLL injection techniques, and Windows API tips and tricks. To top it all off, a custom HTTP beaconing backdoor will be released leveraging the newly released persistence and injection techniques. So much Windows abuse, so little time.
		* **Tools**
			* [SysWhispers](https://github.com/jthuraisamy/SysWhispers)
				* SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.
			* [directInjectorPOC](https://github.com/badBounty/directInjectorPOC)
				*  Small POC written in C# that performs shellcode injection on x64 processes using direct syscalls as a way to bypass user-land EDR hooks.
			* [hunter - fdiskyou](https://github.com/fdiskyou/hunter)
			* [CallObfuscator](https://github.com/d35ha/CallObfuscator)
				* Obfuscate specific windows apis with different apis 
			* [SyscallPOC](https://github.com/SolomonSklash/SyscallPOC)
				* A simple proof of concept shellcode injector using syscalls.
			* [VBA-RunPE](https://github.com/itm4n/VBA-RunPE)
				* A VBA implementation of the RunPE technique or how to bypass application whitelisting.
			* [SharpSploit.Execution.DynamicInvoke](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/SharpSploit%20-%20Quick%20Command%20Reference.md#sharpsploitexecutiondynamicinvoke)
			* [CallMon](https://github.com/DownWithUp/CallMon)
				* CallMon is an experimental system call monitoring tool that works on Windows 10 versions 2004+ using PsAltSystemCallHandlers
			* [Windows-API-Fuzzer](https://github.com/jackullrich/Windows-API-Fuzzer)
				* Designed to learn OS specific anti-emulation patterns by fuzzing the Windows API. 
			* [WinAltSyscallHandler](https://github.com/0xcpu/WinAltSyscallHandler)
				* Some research on AltSystemCallHandlers functionality in Windows 10 20H1 18999
			* [FreshyCalls PoC](https://github.com/Crummie5/Freshycalls_PoC/)
				* A simple dumper as FreshyCalls' PoC. That's what's trendy, isn't it? `¯\_(ツ)_/¯`		
			* [inline_syscall](https://github.com/JustasMasiulis/inline_syscall)
				* Header only library that allows you to generate direct syscall instructions in an optimized, inlineable and easy to use manner.
			* [Syscall Monitor]()https://github.com/hzqst/Syscall-Monitor)
				* This is a process monitoring tool (like Sysinternal's Process Monitor) implemented with Intel VT-X/EPT for Windows 7+.
	* **Power API**<a name="epowerapi"></a>
		* [Deus Somnum](https://github.com/am0nsec/vx/tree/master/Virus.Win64.DeusSomnum)
			* Leverage the Windows Power Management API for code execution and defense evasion.
			* [Paper](https://vxug.fakedoma.in/papers/VXUG/Exclusive/AbusingtheWindowsPowerManagementAPI.pdf)
	* **Processes**<a name="epx"></a>
		* [Creating a Child Process with Redirected Input and Output - docs.ms](https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
	* **Scheduled Task/Job**<a name="sctj"></a>
		* **AT**
		* **Scheduled Task**
			* **101**
				* [Windows Task Scheduler - Wikipedia](https://en.wikipedia.org/wiki/Windows_Task_Scheduler)
				* [Task Scheduler for developers - docs.ms](https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
					* The Task Scheduler enables you to automatically perform routine tasks on a chosen computer. Task Scheduler does this by monitoring whatever criteria you choose (referred to as triggers) and then executing the tasks when those criteria are met.You can use the Task Scheduler to execute tasks such as starting an application, sending an email message, or showing a message box. Tasks can be scheduled to execute in response to these events, or triggers.
			* **Articles/Blogposts/Writeups**		
				* [A Deep Dive Into Windows Scheduled Tasks and The Processes Running Them - Nasreddine Bencherchali(2020)](https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce)
	* **Shared Modules**<a name="eshm"></a>
		* **Tools**
			* [DueDLLigence](https://github.com/fireeye/DueDLLigence)
				* Shellcode runner framework for application whitelisting bypasses and DLL side-loading. The shellcode included in this project spawns calc.exe.
	* **Shellcode Stuff**<a name="winshellcode"></a>
		* **101**
			* [Shellcode - Wikipedia](https://en.wikipedia.org/wiki/Shellcode)
			* [Shellcoding for Linux and Windows Tutorial - Steve Hanna(2007)](https://vividmachines.com/shellcode/shellcode.html)
			* [shellcode-resources](https://github.com/alphaSeclab/shellcode-resources#b79d65effe22d7dfa216cdfaaede7abd)
				* Resources About Shellcode
		* **Analysis**
			* **How-Tos**
				* [Analyzing Windows shellcode - triage, disassemble, debug. - @malwaredisciple(2018](https://rinseandrepeatanalysis.blogspot.com/2018/12/analyzing-windows-shellcode-triage.html)
				* [Building A Custom Tool For Shellcode Analysis - MalBot(2019)](https://malware.news/t/building-a-custom-tool-for-shellcode-analysis/34358)
			* **Writeups**
				* [How To Build A Kernel Shellcode Design and Testing Platform For Windows 8 By Using Windbg - cawanblog(2012)](https://cawanblog.blogspot.com/2012/11/how-to-build-kernel-shellcode-design_5.html)
				* [Network detection of x86 buffer overflow shellcode - Gary Golomb(2012)](https://community.rsa.com/t5/netwitness-blog/network-detection-of-x86-buffer-overflow-shellcode/ba-p/518621)
				* [Phishing with obfuscated javascript, shellcode and malware - Manuel Pelaacuteez(2012)](https://isc.sans.edu/forums/diary/Phishing+with+obfuscated+javascript+shellcode+and+malware/12700/)
				* [Shellcode Detection with XORSearch - Didier Stevens(2014)](https://isc.sans.edu/forums/diary/Guest+Diary+Didier+Stevens+Shellcode+Detection+with+XORSearch/18929/)
				* [Obfuscated shellcode inside a malicious RTF document - zairon(2014)](https://zairon.wordpress.com/2014/03/06/obfuscated-shellcode-inside-a-malicious-rtf-document/)
				* [Converting Shellcode to Portable Executable (32- and 64- bit) - hexacorn(2015)](https://www.hexacorn.com/blog/2015/12/10/converting-shellcode-to-portable-executable-32-and-64-bit/)
				* [VB Dropper and Shellcode for Hancitor Reveal New Techniques Behind Uptick - Jeff White(2016)](https://unit42.paloaltonetworks.com/unit42-vb-dropper-and-shellcode-for-hancitor-reveal-new-techniques-behind-uptick/)
				* [VBA Shellcode and EMET - Didier Stevens(2016)](https://isc.sans.edu/forums/diary/VBA+Shellcode+and+EMET/21705/)
				* [Threat Actors Employ COM Technology in Shellcode to Evade Detection - Haifei Li(2016)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/threat-actors-employ-com-technology-shellcode-evade-detection/)
				* [UAF Bug Affects Internet Explorer, Runs Shellcode - Elliot Cao(2018)](https://www.trendmicro.com/en_us/research/18/h/use-after-free-uaf-vulnerability-cve-2018-8373-in-vbscript-engine-affects-internet-explorer-to-run-shellcode.html)
					* [runsc.c](https://github.com/odzhan/shellcode/blob/master/runsc.c)
				* [Malicious Excel documents with macros running shellcodes - Angel Alonso-Parrizas(2016)](https://blog.angelalonso.es/2016/05/malicious-excel-documents-vba-running.html)
				* [Reversing shellcode using blobrunner and Olly - @malwarenailed(2018)](https://malwarenailed.blogspot.com/2018/09/reversing-shellcode-using-blobrunner.html)		
				* [Those Pesky Powershell Shellcode’s And How To Understand Them - pcsxcetrasupport3(2019)](https://pcsxcetrasupport3.wordpress.com/2019/07/07/those-pesky-powershell-shellcodes-and-how-to-understand-them/)
				* [Shellcode Tester](https://github.com/tophertimzen/shellcodetester)
					* GUI Application in C# to run and disassemble shellcode
				* [A look at a bmp file with embedded shellcode - pcsxcetrasupport3(2019)](https://pcsxcetrasupport3.wordpress.com/2019/03/02/a-look-at-a-bmp-file-with-embedded-shellcode/)
				* [Solving MalwareTech Shellcode challenges with some radare2 magic! - Alan Vivona(2019)](https://medium.com/syscall59/solving-malwaretech-shellcode-challenges-with-some-radare2-magic-b91c85babe4b)
				* [ShellCodeEmulator](https://github.com/ohjeongwook/shellcodeemulator)
					* ShellcodeEmulator emulates Windows shellcode with the help of windbg process memory dumps. You can provide shellcode to analyze with any Windows process dump image. The tool will emulate as much as of the userland code using the shellcode bytes and the provided dump image.		
				* [Let's Learn: Dissecting Operation ShadowHammer Shellcode Internals in crt_ExitProcess - Vitali Kremez(2019)](https://www.vkremez.com/2019/03/lets-learn-dissecting-operation.html)
				* [Maldoc with Nonfunctional Shellcode - Didier Stevens(2019)](https://isc.sans.edu/forums/diary/Maldoc+with+Nonfunctional+Shellcode/24478/)
				* [bdshemu: The Bitdefender shellcode emulator - Andrei Lutas(2020)](https://hvmi.github.io/blog/2020/11/11/bdshemu.html)
				* [RIFT: Analysing a Lazarus Shellcode Execution Method - Research and Intelligence Fusion Team(RIFT)(2021](https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/)
				* [A Look at Metasploit’s Shellcodes - Hido Cohen(2021)](https://blog.usejournal.com/a-look-at-metasploits-shellcodes-4c21de5e4580?gi=6bb06e6f2f82)
				* [Reversing a shellcode with import by hash - jeremy@bidouillesecurity](https://bidouillesecurity.com/reversing-a-shellcode-with-hash-import/)
			* **Videos**
				* [Shellcode detection techniques - Svetlana Gaivoronski(2014)](https://www.youtube.com/watch?v=bbzH-y93hq0)
				* [Debugging shellcode using BlobRunner and IDA Pro - OALabs(2017](https://www.youtube.com/watch?v=q9q8dy-2Jeg)
				* [Extract Shellcode from Fileless Malware like a Pro - ](https://www.youtube.com/watch?v=jbieGfML0Bs)
					* Here I demonstrate how to extract shellcode from the context of a malicious Word doc which uses VBA to inject shellcode into the memory space of a victim process.
				* [Beginner Reversing #2 (Shellcode1 & MEMZ Malware) - Marcus Hutchins(2018](https://www.youtube.com/watch?v=b0WQwCQGjv4)
					* Walkthrough of static analysis challenge Shellcode1 from https://www.malwaretech.com/beginner-malware-reversing-challenges, some live reversing of the MEMZ trojan, and viewer Q&A.
				* [Beginner Reversing #3 (Shellcode2 & Lab Overview) - Marcus Hutchins(2018)](https://www.youtube.com/watch?v=jm4DmdygLvw)
					* Walkthrough of static analysis challenge Shellcode2 from https://www.malwaretech.com/beginner-malware-reversing-challenges, some overview of my home malware analysis lab, and viewer Q&A.
				* [Excel 4.0 Macros Analysis - Cobalt Strike Shellcode Injection - Colin Hardy(2019)](https://www.youtube.com/watch?v=XnN_UWfHlNM)
					* Here I describe how you can analyse a very stealthy technique to execute shellcode via Process Injection from an old-skool Excel Macro technique, known as Excel 4.0 Macros. This seems to be a technique favoured by many APT's and Red Teams given the lack of detection by lots of anti-malware technology. The sample attempts to inject shellcode which transpires to be a Cobalt Strike beacon which uses Domain Fronting to access its C2. 
			* **Tools**
				* [Shellcode2Exe](https://edge-security.blogspot.com/2008/12/shellcode2exe.html)
				* [Shellcode Analysis - Rolf Rolles(2007)](https://www.msreverseengineering.com/blog/tag/shellcode)
					* "My solution to this is a small python script, based upon Ero's pefile, that creates an IDC declaration of an IDA enumeration for each DLL. The enum serves as a mapping between each exported name and its hash. Since the API hashing function may change, the Python function to do this is extensible via a function pointer which defaults to the standard hash presented above."
				* [BlobRunner](https://github.com/OALabs/BlobRunner)
					* BlobRunner is a simple tool to quickly debug shellcode extracted during malware analysis. BlobRunner allocates memory for the target file and jumps to the base (or offset) of the allocated memory. This allows an analyst to quickly debug into extracted artifacts with minimal overhead and effort.
		**Writing Shellcode**
			* **101**
				* [Introduction to Shellcode Development - Ionut Popescu](https://owasp.org/www-pdf-archive/Introduction_to_shellcode_development.pdf)
			* **Multi-Platform**
				* [Architecture Spanning Shellcode - eugene(2002)](https://web.archive.org/web/20100805034535/http://www.groar.org/expl/intermediate/p57-0x0e.txt)
					* The general idea behind an architecture spanning shellcode is trying to come up with a sequence of bytes that would execute a jump instruction on one architecture while executing a nop-like instruction on another architecture. That way we can branch to architecture specific code depending on the platform our code is running on.
				* [isX64 Gem - ragestorm.net(2012)](https://web.archive.org/web/20160406173335/http://www.ragestorm.net/blogs/?p=376)
				* [Building multi-architecture shellcode with shellcodecs - chokepoint.net(2013)](https://web.archive.org/web/20160312145414/http://www.chokepoint.net/2013/08/building-multi-architecture-shellcode.html)
				* [Building a multiplatform shellcode header - chokepoint.net(2013)](https://web.archive.org/web/20160312145320/http://www.chokepoint.net/2013/09/building-multiplatform-shellcode-header.html)
				* [Shellcode: Detection between Windows/Linux/BSD on x86 architecture - odzhan(2016)](https://modexp.wordpress.com/2016/06/02/shellcode-detection/)
				* [Shellcode: Execute command for x32/x64 Linux / Windows / BSD - odzhan(2016)](https://modexp.wordpress.com/2016/06/04/winux/)
					* "I was hoping to present here a code that would execute perfectly on 32/64-bit Linux/BSD and Windows systems"
				* [Shellcodes: Executing Windows and Linux Shellcodes - modexp(2016)](https://modexp.wordpress.com/2016/03/28/winux-shellcodes/)
				* [CPU signatures for OS identification - modexp](https://github.com/odzhan/shellcode/tree/master/detection)
			* **Agnostic**
				* [Not all shellcode locations are made equal - seanhn(2009)](https://sean.heelan.io/2009/05/13/not-all-shellcode-locations-are-made-equal/)
				* [Morphing shellcode using CFGs and SAT - seanhn(2009)](https://sean.heelan.io/2009/06/02/model-checking-smt-solving-and-morphing-shellcode/)
			**(De/En)coders**
				* [Writing Custom Shellcode Encoders and Decoders - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/writing-custom-shellcode-encoders-and-decoders)
				* [Synesthesia: Modern Shellcode Synthesis (Ekoparty 2016 Talk) - Rolf Rolles(2016)](https://www.msreverseengineering.com/blog/2016/11/8/synesthesia-modern-shellcode-synthesis-ekoparty-2016-talk)
				 	* Here are the slides and code for my recent presentation at Ekoparty 2016. The full abstract can be found below. In brief, this research involved automatically generating shellcodes when there are restrictions on legal encodings. We explore examples ranging from well-known ones (no NULL bytes, no '%' character, printable, alphanumeric, all letters uppercase, etc.) to weird and challenging ones (bytes must alternate even and odd, no duplicate bytes, all words are prime numbers, etc). We also explore automated encoding and decoder generation: e.g., given some existing shellcode, transform it into (for example) alphanumeric bytes, and generate a decoder to revert the encoding at run-time. We also explore tasks like finding the shortest or longest solutions, re-writing existing shellcodes into a given encoding, exploiting known facts about the input state, and integration with automated exploit generation.
				* [Creating a Custom shellcode encoder - Dhayalan(2017)](https://d3fa1t.ninja/2017/07/18/creating-an-custom-shellcode-encoder/)
				* [Custom shellcode encoder - Snowscan(2018)](https://snowscan.io/custom-encoder/)
				* [Creating a Custom Shellcode Encoder - rastating(2018)](https://rastating.github.io/creating-a-custom-shellcode-encoder/)
				* [Custom base64 alphabet encoder/decoder - Matteo Malvica(2019)](https://www.matteomalvica.com/blog/2019/01/21/custom-base64-alphabet-encoder/decoder/)
				* [Converting win shellcode from msfvenom to FASM - Matteo Malvica(2019)](https://www.matteomalvica.com/blog/2019/06/13/converting-win-shellcode-from-msfvenom-to-fasm/)
				* [Shikata Ga Nai Encoder Still Going Strong - Steve Miller, Evan Reese, Nick Carr(2019)](https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html)
				* [The Lost Art of Shellcode Encoder/Decoders - Dave Aitel(2019](https://cybersecpolitics.blogspot.com/2019/03/the-lost-art-of-shellcode.html)
				* [In-Memory shellcode decoding to evade AVs/EDRs - Askar(2020)](https://shells.systems/in-memory-shellcode-decoding-to-evade-avs/)
				* [x86 ASCII AND-SUB Encoder - phra(2019)](https://iwantmore.pizza/posts/and-sub-encoder.html)
				* [Shellcode: Encoding Null Bytes Faster With Escape Sequences - odzhan(2020](https://modexp.wordpress.com/2020/06/26/shellcode-encoding-null-bytes-faster/)
				* [The Shikata Ga Nai Encoder - Nick Hoffman, Jeremy Humble, and Toby Taylor](https://www.boozallen.com/c/insight/blog/the-shikata-ga-nai-encoder.html)
				* [The x86 Countdown Encoder, Explained](https://www.boozallen.com/c/insight/blog/the-x86-countdown-encoder-explained.html)
				* [Modifying Metasploit Shellcode Decoders to Bypass Static Analysis - Alexander Bode, Jelle Ermerins(2020)](https://ermerins.com/assets/docs/shikataganai.pdf)
			* **Obfuscators**
				* **Articles/Blogposts/Writeups**
					* [X86 Shellcode Obfuscation - Part 1 - Kuba Gretzky(2016)](https://breakdev.org/x86-shellcode-obfuscation-part-1/)
						* [Part 2](https://breakdev.org/x86-shellcode-obfuscation-part-2/)
						* [Part 3](https://breakdev.org/x86-shellcode-obfuscation-part-3/)
					* [Explained polymorphic obfuscation using the difference within two asm codes - Stackoverflow(2018)](https://stackoverflow.com/questions/49166509/explained-polymorphic-obfuscation-using-the-difference-within-two-asm-codes)
					* [Revisiting the Art of Encoder-Fu for novel shellcode obfuscation techniques - Harpreet Singh, Yashdeep Saini(2021](https://passthesalt.ubicast.tv/videos/2021-revisiting-the-art-of-encoder-fu-for-novel-shellcode-obfuscation-techniques/)
				* **Papers**
					* [PMASCE-Polymorphic and Metamorphic Shellcode Creation Engine - Navneet Kaur Popli, Dr. Anup Girdhar(2019](http://meri.edu.in/journal/wp-content/uploads/2019/01/Paper-4-OCT-17.pdf)
				* **Tools**
			   	* [OWASP ZSC](https://github.com/OWASP/ZSC)
			   		* OWASP ZSC is open source software written in python which lets you generate customized shellcode and convert scripts to an obfuscated script. This software can be run on Windows/Linux/OSX with python.				
					* [Shellcoding(Mr-Un1k0d3r)](https://github.com/Mr-Un1k0d3r/Shellcoding)
						* Shellcoding Utilities and shellcode obfuscator generator.					
					* [Obfuscator](https://github.com/3xpl01tc0d3r/Obfuscator)
						* [Blogpost](https://3xpl01tc0d3r.blogspot.com/2020/08/introduction-to-obfuscator.html)
					* [UniByAv](https://github.com/Mr-Un1k0d3r/UniByAv)
					* [Simple x64 XOR Shellcode Obfuscation - Entropy(2011](https://www.exploit-db.com/papers/17775)
					* [Obfusion](https://github.com/kgretzky/obfusion)
						* This library handles obfuscation of assembled X86 machine code in order to make it harder to read and analyze during the reverse engineering process.
					* [PythonAESObfuscate](https://github.com/offsecginger/pythonaesobfuscate)
					* [ADDMutate](https://github.com/k2/admmutate)
						* A shellcode mutation engine, can evade NIDS.
			* **Windows**
				* **101/&Stuff**
					* [Understanding Windows Shellcode - Skape(2003)](http://hick.org/code/skape/papers/win32-shellcode.pdf)
					* [Understanding the PEB Loader - dzzie](https://web.archive.org/web/20160328043604/http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html)
					* [High Level Windows Shellcode Development Methods - Stephen Bradhshaw(2011)](https://thegreycorner.com/2011/04/24/high-level-windows-shellcode.html)
					* [The Art of Win32 Shellcoding - AmrThabet(2012)](https://www.codeproject.com/Articles/325776/The-Art-of-Win32-Shellcoding)
					* [Create a custom shellcode using System() function - Peru@gosecure.it(2014)](http://www.gosecure.it/blog/art/452/sec/create-a-custom-shellcode-using-system-function/)
					* [Part 6: Writing W32 shellcode - b33f](https://www.fuzzysecurity.com/tutorials/expDev/6.html)
					* [Shellcode - Massimiliano Tomassoli(2015)](https://web.archive.org/web/20150522211938/http://expdev.byethost7.com/2015/05/22/shellcode/)
					* [How to write a Windows Shellcode... (beginners)  - Abdel Harbi(2016)](https://www.linkedin.com/pulse/how-write-windows-shellcode-beginners-abdel-harbi)
					* [Basics of Windows shellcode writing - Iliya Dafchev(2017)](https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html)
					* [Win32 Shellcode - Intro - bolo(2019)](https://blackcloud.me/Win32-shellcode-1/)
					* [(Windows 32-bit) Shellcoding 101 - ivanitlearning.wordpress.com(2018)](https://ivanitlearning.wordpress.com/2018/10/13/windows-32-bit-shellcoding-101/)
					* [Introduction to Windows shellcode development – Part 1 - Ionut Popescu(2015)](https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/)
						* [Part 2](https://securitycafe.ro/2015/12/14/introduction-to-windows-shellcode-development-part-2/)
						* [Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/)
					* [Safer Shellcode Implants - Stuart Morgan(2016)](https://labs.f-secure.com/archive/safer-shellcode-implants/)
					* [Writing Shellcode in Visual Studio - UserExistsError(2018)](https://userexistserror.blogspot.com/2018/11/writing-shellcode-in-visual-studio.html)
					* [Windows x86 Manual Shellcode - Part 1 - bugtree(2018)](https://marcosvalle.github.io/re/exploit/2018/10/20/windows-manual-shellcode-part1.html)
						* In this series we are going to write a Reverse Shell shellcode for Win32 from scratch while trying to reduce its size.
						* [Part 2](https://marcosvalle.github.io/re/exploit/2018/10/21/windows-manual-shellcode-part2.html)
						* [Part 3](https://marcosvalle.github.io/re/exploit/2018/10/21/windows-manual-shellcode-part3.html)
					* [Dynamic Shellcode Execution - Noora Hyvärinen(2019](https://blog.f-secure.com/dynamic-shellcode-execution/)
					* [Weaponizing dnscat with shellcode and Metasploit - skullsecurity(2010)](https://blog.skullsecurity.org/2010/weaponizing-dnscat-with-shellcode-and-metasploit)
					* [masm_shc](https://github.com/hasherezade/masm_shc)
						* A helper utility for creating shellcodes. Cleans MASM file generated by MSVC, gives refactoring hints.
					* [Binary to shellcode - superkojiman(2013)](https://blog.techorganic.com/2013/03/02/binary-to-shellcode/)
					* [Staying Hidden on the Endpoint: Evading Detection with Shellcode - Evan Pena, Casey Erikson(2019)](https://www.fireeye.com/blog/threat-research/2019/10/staying-hidden-on-the-endpoint-evading-detection-with-shellcode.html)
					* [Baby’s First Win32 Shellcode - h0mbre(2019)](https://h0mbre.github.io/Babys-First-Shellcode/)
					* [Windows x86 MessageBox shellcode - Marcos Valle(2019)](https://marcosvalle.github.io/re/exploit/2019/01/19/messagebox-shellcode.html)
					* [Leveraging from PE parsing technique to write x86 shellcode - Mohamed Fakroud(2021)](https://mohamed-fakroud.gitbook.io/t3nb3w/shellcoding/leveraging-from-pe-parsing-technique-to-write-x86-shellcode)
				* **Talks/Presentations**
					* [Windows Shellcode Mastery - Benjamin Caillat(BHEU2009)](https://www.blackhat.com/presentations/bh-europe-09/Caillat/BlackHat-Europe-09-Caillat-Wishmaster-slides.pdf)
					* [Teaching Old Shellcode New Tricks - @midnite_runr(Defcon25)](https://www.youtube.com/watch?v=jk1VAuPH4-w)
						* [Slides](https://raw.githubusercontent.com/secretsquirrel/fido/master/Defcon_25_2017.pdf)
						* [Code](https://github.com/secretsquirrel/fido)
						* Metasploit x86 shellcode has been defeated by EMET and other techniques not only in exploit payloads but through using those payloads in non-exploit situations (e.g. binary payload generation, PowerShell deployment, etc..). This talk describes taking Metasploit payloads (minus Stephen Fewer's hash API), incorporating techniques to bypass Caller/EAF[+] checks (post ASLR/DEP bypass) and merging those techniques together with automation to make something better.
				* **Techniques**
					* **x86 vs x64**
						* [Windows x64 Shellcode - Topher Timzen(2014)](https://www.tophertimzen.com/blog/windowsx64Shellcode/)
							* I will go over the differences between 32 and 64 bit assembly that I have noticed and how to work with them as well as some of the structures windows uses that are useful to know about for shellcode in the 64bit environment. I will also introduce two tools that I have created in helping my exploit development process.
						* [Asmcodes: Platform Independent PIC for Loading DLL and Executing Commands - odzhan(2015)](https://modexp.wordpress.com/2015/11/17/asmcodes-pic/)
						* [Shellcode: Dual mode PIC for x86 (Reverse and Bind Shells for Windows) - odzhan(2017)](https://modexp.wordpress.com/2017/01/24/shellcode-x84/)
						* [Writing shellcodes for Windows x64 - nytrosecurity(2019)](https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/)
					* **Dumping LSASS**
						* [Shellcode to Dump the Lsass Process - Osanda Malith(2019)](https://osandamalith.com/2019/05/11/shellcode-to-dump-the-lsass-process/)
					* **Encryption**
						* [Shellcode: Encrypting traffic - odzhan(2018)](https://modexp.wordpress.com/2018/08/17/shellcode-encrypting-traffic/)
					* **Execute a PE in memory/RDI**
							* [Shellcode: In-Memory Execution of DLL - modexp(2019)](https://modexp.wordpress.com/2019/06/24/inmem-exec-dll/)
					* **HTA->ActiveX**
						* [Office Shellcode Execution - subTee(2016)](https://evi1cg.me/archives/Office_Shellcode_Execution.html)
					* **Hiding WinAPI imports**
						* [Hidden in PEB Sight: Hiding Windows API Imports With a Custom Loader - Christophe Tafani-Dereeper(2020)](https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/)
					* **Kernel-related**
						* [Win32 Reverse Shell Shellcode - h0mbre(2019)](https://h0mbre.github.io/Win32_Reverse_Shellcode/#)
						* [Returning to usermode shellcode from windows kernel (Win10) - StackExchange(2019)](https://reverseengineering.stackexchange.com/questions/20768/returning-to-usermode-shellcode-from-windows-kernel-win10)
					* **Resolving Function Addresses Statically**
						* [Tutorial - Writing Hardcoded Windows Shellcodes (32bit) - Daniel Solstad(2020)](https://dsolstad.com/shellcode/2020/02/02/Tutorial-Hardcoded-Windows-Shellcodes-32bit.html)
					* **Resolving Function Addresses Dynamically**
						* [PE infection under Win32 - Mister Sandman, Jack Qwerty, GriYo(](https://raw.githubusercontent.com/odzhan/shellcode/master/os/win/docs/29A-4.227)
						* [Impersonation, your friend - Ratter/29A](https://raw.githubusercontent.com/odzhan/shellcode/master/os/win/docs/29A-6.024)
						* [GetProcAddress-alike utility - Jack Qwerty](https://raw.githubusercontent.com/odzhan/shellcode/master/os/win/docs/29A%232.3_5)
						* [RETRIEVING API'S ADRESSES - LethalMind](https://raw.githubusercontent.com/odzhan/shellcode/master/os/win/docs/29A-4.227)
						* [Retrieving Kernel32's Base Address - Stephen Fewer(2009)](https://web.archive.org/web/20171021140810/http://blog.harmonysecurity.com/2009_06_01_archive.html)
						* [Customizing the GetProcAddress  - Marc Kranz(2011)](https://web.archive.org/web/20150816171303/https://sites.google.com/site/x64lab/home/notes-on-x64-windows-gui-programming/customizing-the-getprocaddress)
						* [Finding Kernel32 Base Address Shellcode - ragestorm.net(2016)](https://web.archive.org/web/20160406171827/http://www.ragestorm.net/blogs/?p=369)
						* [Shellcode: Fido and how it resolves GetProcAddress and LoadLibraryA - odzhan(2017)](https://modexp.wordpress.com/2017/02/03/shellcode-iat/)
						* [Shellcode: Using the Exception Directory to find GetProcAddress - odzhan(2019)](https://modexp.wordpress.com/2019/05/19/shellcode-getprocaddress/)
						* [Shellcode: Resolving API addresses in memory - Odzhan(2017)](https://modexp.wordpress.com/2017/01/15/shellcode-resolving-api-addresses/)
						* [Finding Kernel32 Base and Function Addresses in Shellcode - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode)
						* [Windows Shellcoding x86 – Hunting Kernel32.dll – Part 1 - paranoidninja(2018)](https://0xdarkvortex.dev/index.php/2019/03/18/windows-shellcoding-x86-hunting-kernel32-dll-part-1/)
							* [Part 2](https://0xdarkvortex.dev/windows-shellcoding-x86-calling-functions-in-kernel32-dll-part-2/)
						* [How to implement GetProcAddress in shellcode using x86-64 and x86 assembly language. - Dennis A. Babkin(2020](https://dennisbabkin.com/blog/?t=how-to-implement-getprocaddress-in-shellcode)
					* **Writing Minimized Shellcode**
						* [Writing Small Shellcode - Dafydd Stuttard(2005)](http://index-of.es/Exploit/Writing%20Small%20Shellcode.pdf)
							* This paper describes an attempt to write Win32 shellcode that is as small as possible, to perform a common task subject to reasonable constraints. The solution presented implements a bindshell in 191 bytes of null-free code, and outlines some general ideas for writing small shellcode.
						* [Shellcode Golf: Every Byte is Sacred - egypt(2014)](https://www.rapid7.com/blog/post/2014/02/14/shellcode-golf/)
						* [Shellcode reduction tips (x86) - abatchy(2017)](https://www.abatchy.com/2017/04/shellcode-reduction-tips-x86)
						* [Shellcode: x86 optimizations part 1 - odzhan(2017)](https://modexp.wordpress.com/2017/06/07/x86-trix-one/)
						* [Shellcode: Data Compression - odzhan(2019)](https://modexp.wordpress.com/2019/12/08/shellcode-compression/)
						* [Shellcode: Recycling Compression Algorithms for the Z80, 8088, 6502, 8086, and 68K Architectures. - odzhan(2020)](https://modexp.wordpress.com/2020/05/27/komposite-shellcode/)
					* **Writing Using a Compiler**
						* [Writing WIN32 Shellcode With a C-compiler - Didier Stevens(2010)](https://blog.didierstevens.com/2010/05/04/writing-win32-shellcode-with-a-c-compiler/)
						* [Writing Shellcode with a C Compiler - Nick Harbour(2010)](https://nickharbour.wordpress.com/)
						* [Writing Optimized Windows Shellcode in C - Matt Graeber(2013)](https://web.archive.org/web/20210305190309/http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html)
						* [Writing shellcode in C++ - zwclose7(2014)](http://www.rohitab.com/discuss/topic/40820-writing-shellcode-in-c/)
						* [Shellcode Techniques in C++ - Topher Timzen(2015)](https://www.tophertimzen.com/blog/shellcodeTechniquesCPP/)
						* [Shellcode: A Windows PIC using RSA-2048 key exchange, AES-256, SHA-3 - odzhan(2016](https://modexp.wordpress.com/2016/12/26/windows-pic/)
						* [Writing and Compiling Shellcode in C - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c)
						* [Write Windows Shellcode in Rust](https://github.com/b1tg/rust-windows-shellcode)
				* **Talks/Presentations/Videos**
					* [POP POP RETN An Introduction to Writing Win32 Shellcode - Christopher Maddalena(Derbycon2017)](https://www.youtube.com/watch?v=UstWmavrWwk)
						* [Slides](https://github.com/chrismaddalena/Presentations/tree/master/2017%20DerbyCon)
						* If you have ever worked with an exploit or Metasploit, you have probably used shellcode, but do you know how it is made? This talk has been designed to walk you through the ins and outs of basic shellcode, with a focus on Windows and the x86 architecture. There will be a review of the basic computer science behind shellcode, a look under the hood of msfvenom works and how you can recreate msfvenom’s shellcode in Assembly, and then a walkthrough and a demo of how you can create a custom connectback stager using Assembly.
				* **Tools**
					* [Donut](https://github.com/TheWover/donut)
						* Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters
					* [Venom](https://github.com/r00t-3xp10it/venom)
						* The script will use msfvenom (metasploit) to generate shellcode in diferent formats ( `C#, python, ruby, dll, msi, hta-psh, docm, apk, macho, elf, deb, mp4, etc` ) injects the shellcode generated into one template (example: python) "the python funtion will execute the shellcode into ram" and uses compilers like gcc (gnu cross compiler) or mingw32 or pyinstaller to build the executable file. It also starts a multi-handler to recive the remote connection (shell or meterpreter session). 'venom generator' reproduces some of the technics used by Veil-Evasion.py, unicorn.py, powersploit.py, etc..
					* [Cross Arch Shellcode Compiler](https://github.com/ixty/xarch_shellcode)
						* Cross Architecture Shellcode in C
					* [shellcode](https://github.com/binject/shellcode)
						* Shellcode library as a Go package.
					* [Shellsploit](https://github.com/vasco2016/shellsploit-framework)
						* Shellsploit let's you generate customized shellcodes, backdoors, injectors for various operating system. And let's you obfuscation every byte via encoders.
					* [Shellcode Compiler](https://github.com/NytroRST/ShellcodeCompiler)
						* Shellcode Compiler is a program that compiles C/C++ style code into a small, position-independent and NULL-free shellcode for Windows (x86 and x64) and Linux (x86 and x64). It is possible to call any Windows API function or Linux syscall in a user-friendly way.
				* **Samples**
					* [Windows x64 Shellcode - mcdermottcybersecurity(2011)](https://mcdermottcybersecurity.com/articles/windows-x64-shellcode)
					* [Windows Kernel Shellcodes - a compendium - Matteo Malvica](https://www.matteomalvica.com/blog/2019/07/06/windows-kernel-shellcode/)
					* [Shellcode - Didier Stevens](https://blog.didierstevens.com/programs/shellcode/)
					* [SelfDefense](https://github.com/EgeBalci/SelfDefense)
						* Several self defense shellcodes
					* [x86_shellcode_tutorial](https://github.com/bruce30262/x86_shellcode_tutorial)
					* [ShellcodeOfDeath](https://github.com/hacksysteam/shellcodeofdeath)
					* [In-Memory Shellcode](https://github.com/csandker/inmemoryshellcode)
					* [PIC_Bindshell](https://github.com/mattifestation/pic_bindshell)
						* Position Independent Windows Shellcode Written in C
					* [Windows Reverse Shell Shellcode I. - elcapitan(2015)](http://sh3llc0d3r.com/windows-reverse-shell-shellcode-i/)
					* [Shellcode to Invert Colors - Osanda Malith(2017)](https://osandamalith.com/2017/02/28/shellcode-to-invert-colors/)
					* [Shellcode to Scroll Your Desktop Horizontally - Osanda Malith(2017)](https://osandamalith.com/2017/02/28/shellcode-to-scroll-your-desktop-horizontally/)
					* [Shellcode to Scroll your Desktop Vertically and Horizontally - Osanda Malith(2017)](https://osandamalith.com/2017/03/02/shellcode-to-scroll-your-desktop-vertically-and-horizontally/)
					* [Windows XP PRO SP3 - Full ROP calc shellcode - b33f](http://fuzzysecurity.com/exploits/ropshell2.html)
					* [FreeFloat FTP (custom shellcode) - b33f](http://fuzzysecurity.com/exploits/12.html)
					* [ProfessionallyEvil x86 ASM](https://github.com/ProfessionallyEvil/x86_asm)
					* [Expiring Shellcode update - averagejoe(2019)](https://www.gironsec.com/blog/2019/06/expiring-shellcode-update/)
					* [A Shellcode Idea - averagejoe(2019)](https://www.gironsec.com/blog/2019/07/a-shellcode-idea/)
					* [Shellcode: A Tweetable Reverse Shell for x86 Windows - odzhan(2017)](https://modexp.wordpress.com/2017/11/16/tweetable-shellcode-windows/)
					* [Windows/x86 - Download File (http://127.0.0.1/file.exe) + Execute Shellcode (124 bytes) - weiss](https://www.exploit-db.com/exploits/13517)
					* [rev_overlap32.asm](https://packetstormsecurity.com/files/71775/rev_overlap32.asm.html)
						* ASM that provides a win32 reverse connect shell with no null bytes.
					* [block_api.asm - Stephen Fewer](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm)
						* Input: The hash of the API to call and all its parameters must be pushed onto stack. Output: The return value from the API call will be in EAX.
					* [Download and Execute Payload Using MSIEXEC - Kartik Durg(2019)](https://iamroot.blog/2019/01/28/windows-shellcode-download-and-execute-payload-using-msiexec.html)
						* [win-exec-calc-shellcode](https://github.com/peterferrie/win-exec-calc-shellcode)
							* Small null-free shellcode that execute calc.exe. Runs on x86 and x64 versions of Windows 5.0-6.3 (2000, XP, 2003, 2008, 7, 8, 8.1), all service packs.
					* [Windows x86 - spawn calc.exe Win7/10 (176 bytes) - bolonobolo](https://blackcloud.me/win_calc/)
					* [Windows x86 - spawn custom MessageBox Win7/10 (223 bytes) - bolonobolo](https://blackcloud.me/win_messagebox/)
					* [Windows x86 - spawn reverse shell Win7/10 (387 bytes) - bolonobolo](https://blackcloud.me/win_reverse_shell/)
					* [Windows x86 - hashed reverse shell Win7/10 (222 bytes) - bolonobolo](https://blackcloud.me/win_reverse_shell_hashed/)
		* **Execution of Shellcode**
			* **Linux**
			* **Windows**
				* **Dyna-legacy**
					* [IActiveScript - MSDN](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/reference/iactivescript)
						* Provides the methods necessary to initialize the scripting engine. The scripting engine must implement the `IActiveScript` interface.
					* [Last-minute presentation: Novel code obfuscation with COM - Robert Freeman(VB2007)](https://www.virusbulletin.com/conference/vb2007/abstracts/last-minute-presentation-novel-code-obfuscation-com/)
					* [A DynaCall() Function for Win32 - Ton Plooy(1998)](https://www.drdobbs.com/a-dynacall-function-for-win32/184416502)
					* [An Automation Object for Dynamic DLL Calls - Jeff Strong(1998)](https://www.drdobbs.com/windows/an-automation-object-for-dynamic-dll-cal/210200078)
						* "Here's an OLE automation object for dynamically declaring and accessing functions in external DLLs"
					* [Additional exe encoder option "vbsmem" - Metasploit(2011)](https://web.archive.org/web/20110921221342/http://dev.metasploit.com/redmine/issues/3894)
					* [Shellcode Via JScript / VBScript - Happening Now! - Casey Smith(2016)](https://web.archive.org/web/20160913080156/http://subt0x10.blogspot.com/2016/09/shellcode-via-jscript-vbscript.html)
					* [Shellcode: In-Memory Execution of JavaScript, VBScript, JScript and XSL - Osanda Malith(2019)](https://modexp.wordpress.com/2019/07/21/inmem-exec-script/)
					* [DynamicWrapper](http://www.borncity.com/web/WSHBazaar1/WSHDynaCall.htm)
					* [DynamicWrapperX](http://dynwrapx.script-coding.com/dwx/pages/dynwrapx.php?lang=en)
					* [DynamicWrapperEx – Registration-Free In-Process COM Automation Server - Paul Laîné(2020)](https://www.youtube.com/watch?v=JbQyIcIyOvI)
					* DynamicWrapperEx – Windows API Invocation from Windows Script Host - Paul Laine(2021)](https://www.contextis.com/en/blog/dynamicwrapperex-windows-api-invocation-from-windows-script-host)
					* [In-Memory Execution of an Executable - Amit Malik](https://securityxploded.com/memory-execution-of-executable.php)
			  	* **Runners**
			  		* **Articles**
				   	* [Syringe utility provides ability to inject shellcode into processes - firebits(2011)](https://firebitsbr.wordpress.com/2011/07/08/syringe-utility-provides-ability-to-inject-shellcode-into-processes/)
						* [Making your Shellcode Undetectable using .NET - Osanda Malith(2016](https://osandamalith.com/2016/08/01/making-your-shellcode-undetectable-using-net/)
							* [code](https://github.com/osandamalith/vbshellcode)
				   	* [A patch for PowerSploit’s Invoke-Shellcode.ps1 - Marco Ivaldi(2017)](https://techblog.mediaservice.net/2017/11/a-patch-for-powersploits-invoke-shellcode-ps1/)
						* [Using native code/shellcode and assembly language with C# - Fergo(2019)](https://www.fergonez.net/post/shellcode-csharp)				   	
			   		* [C_Shot - Just What The Doctor Ordered - redxorblue(2020)](http://blog.redxorblue.com/2020/07/cshot-just-what-doctor-ordered.html)
						* [Executing shellcode with Unsafe Native Methods in PowerShell - mez0(2020)](https://mez0.cc/posts/cobaltstrike-powershell-exec/)
				   	* [Alaris](https://github.com/cribdragg3r/Alaris)
							* [Blogpost](https://sevrosecurity.com/2020/10/14/alaris-a-protective-loader/)
			   		* [A Fundamental Tool in the Toolkit: Evasive Shellcode Launchers – Part 1 - Nichoali Wang(2020)](https://www.nagarrosecurity.com/blog/evasive-shellcode-launchers)
			   		* [ScatterBrain](https://github.com/djhohnstein/ScatterBrain)
							* ScatterBrain is a shell code runner with a variety of execution and elevation options. Given unencoded shellcode, it will then be encoded with the XOR key SecretKey (found in Cryptor/Program.cs and ScatterBrain/Headers/RawData.h) using the Cryptor binary. Cryptor.exe generates an encrypted.bin, which can be copied into ScatterBrain/Headers/RawData.h. You can then build ScatterBrain as a DLL which can be leveraged in one of the templates. Additionally, this will build the .NET Profiler UAC Bypass to use in your operations.
				   	* [Bypassing EDR real-time injection detection logic - @_lpvoid(2021)](https://blog.redbluepurple.io/offensive-research/bypassing-injection-detection)
				   	* [DLLhijack-ShellcodeLoader](https://github.com/LDrakura/DLLhijack-ShellcodeLoader/tree/master/winmm_fb)
						* [SyscallPOC](https://github.com/SolomonSklash/SyscallPOC)
							* Shellcode injection POC using syscalls.
			   * **Techniques**
			   	**101**
			   		* [A Beginner’s Guide to Windows Shellcode Execution Techniques - Carsten Sandker(2019)](https://csandker.io/2019/07/24/ABeginnersGuideToWindowsShellcodeExecutionTechniques.html)
							* [Code](https://github.com/csandker/inMemoryShellcode)
							* This blog post is aimed to cover basic techniques of how to execute shellcode within the memory space of a process.
						* [Execute Shellcode, Bypassing Anti-Virus… - dusty(2014)](https://penturalabs.wordpress.com/2014/07/18/execute-shellcode-bypassing-anti-virus/)
						* [Bypass Windows Defender with A Simple Shell Loader - Joshua(2019)](https://sevrosecurity.com/2019/05/25/bypass-windows-defender-with-a-simple-shell-loader/)
							* [code](https://github.com/cribdragg3r/Simple-Loader)
					* **Syscalls**
						* [Using Syscalls to Inject Shellcode on Windows - Solomon Sklash(2020)](https://www.solomonsklash.io/syscalls-for-shellcode-injection.html)
						* [Invoking System Calls and Windows Debugger Engine - odzhan(2020](https://modexp.wordpress.com/2020/06/01/syscalls-disassembler/)
				   * **Callbacks**
			    		* **Articles/Blogposts/Writeups**
			    			* [Shellcode. I’ll Call you back. - hexacorn(2016](http://www.hexacorn.com/blog/2016/12/17/shellcode-ill-call-you-back/)
			    			* [Abusing native Windows functions for shellcode execution - Jeff White(2017)](http://ropgadget.com/posts/abusing_win_functions.html)
								* "I've been doing a lot of analysis on malicious docs (maldocs) lately and, among a popular variant circulating right now, is a technique that I found particularly interesting. Effectively, it abuses native Windows function calls to transfer execution to shellcode that it loads into memory. I thought it was cool in this context, and not something that I was super familiar with, even though I've since learned it's a very old technique, so I set out to do some research in identifying additional functions that could be abused in a similar way and how to leverage them
			    			* [Executing Shellcode via Callbacks - Osanda Malith(2021](https://osandamalith.com/2021/04/01/executing-shellcode-via-callbacks/)
			    			* [Shellcode Execution via CreateThreadpoolWait - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-via-createthreadpoolwait)
			    			* [TLS Injector: running shellcodes through TLS callbacks - Borja Merino(2015)](https://www.shelliscoming.com/2015/06/tls-injector-running-shellcodes-through.html)
			    			* [Windows Data Structures and Callbacks, Part 1 - odzhan(2020](https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/)
			    		* **Samples**
			    			* [Alternative Code Execution](https://github.com/S4R1N/AlternativeShellcodeExec)
			    				* According to Microsoft, a callback function is code within a managed application that helps an unmanaged DLL function complete a task. Calls to a callback function pass indirectly from a managed application, through a DLL function, and back to the managed implementation. This repository contains a list of callback functions that can be used to execute position independent shellcode so that CreateThread would be a thing of the past :P.
			    	* **Debugging APIs**
			    		* **Articles/Blogposts/Writeups**
			    			* [debug_inject](https://github.com/conix-security/debug_inject)
			    				* Shellcode injection using debugging APIs
			    	* **Embedded within a File**
			    		* [Punk Ode - Hiding shellcode in plain sight - Michael Sutton, Greg MacManus(BHUSA2006)](https://archive.org/details/podcast_black-hat-briefings-las-vegas_michael-sutton-greg-macmanus_1000013270989)
							* [Slides](https://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Sutton.pdf)
							* "Injecting shellcode into a vulnerable program so you can find it reliably can be tricky. With image format vulnerabilities, sometimes the only place you can put your code is in the image itself. If a file attempting to exploit one of these vulnerabilities was rendered using a non-vulnerable application, the ‘strange’ files might raise some suspicion; a file containing a NOP-sled and shellcode does not tend to look like any normal photo. What if shellcode could be injected in this way without significantly altering the appearance of the file? What if the entire file could be transformed into executable code but the original image or sound could still be rendered? In this presentation we will present Punk Ode, which combines concepts from steganography, psychophysics and restricted character-set shellcode encoding to hide shellcode in plain sight. We will discuss how to convert a media file into a stream of valid instructions while leaving the initial images/sounds intact so as not to raise suspicion. We will also release a series of tools designed to automate the generation of such files.
					* **'Empty' PE**
						* [PE Trick #1: A Codeless PE Binary File That Runs - Alex Ionescu(2014)](http://www.alex-ionescu.com/?p=211)
						* [Executing Shellcode Directly - Osanda Malith(2017)](https://osandamalith.com/2017/04/11/executing-shellcode-directly/)
			    	* **Execution through a language**
			    		* [Execute ShellCode Using Python - Debasish Mandal(2012)](http://www.debasish.in/2012/04/execute-shellcode-using-python.html)
						* [Executing Shellcode with Python - doyler(2015)](https://www.doyler.net/security-not-included/executing-shellcode-with-python)
						* [PythonShellcode](https://github.com/doyler/SecurityTools/tree/master/PythonShellcode)
							* A simple script for executing shellcode in Python (as opposed to C)
			    	* **File Installers**
			    		* **Articles/Blogposts/Writeups**
			    			* [InnoSetup Execute Shellcode PoC](https://github.com/DarkCoderSc/inno-shellcode-example/)
			    				* Run shellcode through InnoSetup code engine.	
			    	* **In-Line Assembly**
			    		* **Articles/Blogposts/Writeups**
			    			* [Executing Shellcode with Inline Assembly in C/C++ - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-inline-assembly-in-c-c++)
			    	* **.NET**
			    		* [Shellcode in .NET - How the PEB Changes - Topher Timzen(2015](https://www.tophertimzen.com/blog/shellcodeDotNetPEB/)
			    	* **PE Resources**
			    		* **Articles/Blogposts/Writeups**
			    			* [Embedding a shellcode in a PE file - Joxean Koret(2012)](http://joxeankoret.com/blog/2012/05/06/embedding-a-shellcode-in-a-pe-file/)
			    			* [Loading and Executing Shellcode From PE Resources - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources)
			    	* **PIC in C**
			    		* [Running Shellcode Directly in C - Osanda Malith(2019)](https://osandamalith.com/2019/08/27/running-shellcode-directly-in-c/)
			    	* **sRDI**
			    		* [sRDI – Shellcode Reflective DLL Injection - Nick Landers(2017)](https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/)
						* [sRDI - Shellcode Reflective DLL Injection](https://github.com/monoxgas/sRDI)
							* sRDI allows for the conversion of DLL files to position independent shellcode. It attempts to be a fully functional PE loader supporting proper section permissions, TLS callbacks, and sanity checks. It can be thought of as a shellcode PE loader strapped to a packed DLL.
						* [Shellcode Reflective DLL Injection - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-shellcode-dll-injection)
						* [Beginners guide to Reflective DLL Injection - quantumcore(2021)](https://quantumcored.com/index.php/2021/03/26/beginners-guide-to-reflective-dll-injection/)
							* [ReflectiveDLLInjectionTutorial](https://github.com/quantumcore/ReflectiveDLLInjectionTutorial)
			    	* **UUid**
			    		* **Articles/Blogposts/Writeups**
			   * **Tools**
					* [go-shellcode(Ne0nd0g)](https://github.com/Ne0nd0g/go-shellcode)
						* A repository of Windows Shellcode runners and supporting utilities. The applications load and execute Shellcode using various API calls or techniques.
					* [C_Shot](https://github.com/anthemtotheego/C_Shot)
						* C_Shot is an offensive security tool written in C which is designed to download, inject, and execute shellcode in memory.
					* [go-shellcode](https://github.com/brimstone/go-shellcode)
						* This is a program to run shellcode as its own process, all from memory. This was written to defeat anti-virus detection.
					* [Go4aRun](https://github.com/D00MFist/Go4aRun)
						* [GOing 4 A Run - Leo Pitt(2020)](https://posts.specterops.io/going-4-a-run-eb263838b944)
						* Shellcode runner in GO that incorporates shellcode encryption, remote process injection, block dlls, and spoofed parent process
					* [UrbanBishopLocal](https://github.com/slyd0g/UrbanBishopLocal)
						* A port of FuzzySecurity's UrbanBishop project for inline shellcode execution 
					* [DueDLLigence](https://github.com/fireeye/DueDLLigence)
						* Shellcode runner framework for application whitelisting bypasses and DLL side-loading. The shellcode included in this project spawns calc.exe.
					* [Crab-Runner](https://github.com/cdong1012/Crab-Runner)
					* [shellcode-process-injection](https://github.com/mhaskar/shellcode-process-injection)
						* Simple C implementation to perform shellcode process injection via win32 APIs
					* [fido](https://github.com/secretsquirrel/fido)
					* [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
						* Converts PE so that it can be then injected just like a normal shellcode. (At the same time, the output file remains to be a valid PE). Supports both 32 and 64 bit PEs  Authors: @hasherezade & @hh86
					* [ShellcodeWrapper](https://github.com/Arno0x/ShellcodeWrapper)
						*  Shellcode wrapper with encryption for multiple target languages
			   	* [Ridgway](https://github.com/m0rv4i/ridgway)
			   		* A quick tool for hiding a new process running shellcode.
			    	* [go-shellcode](https://github.com/Ne0nd0g/go-shellcode)
			    		* A repository of Windows Shellcode runners and supporting utilities. The applications load and execute Shellcode using various API calls or techniques.
			    	* [RemoteCryptoShellcodeLoader](https://github.com/uknowsec/RemoteCryptoShellcodeLoader)
			    	* Doge-Loader](https://github.com/timwhitez/Doge-Loader)
			    	* [ShellcodeLoader](https://github.com/knownsec/shellcodeloader)
			    		* ShellcodeLoader of windows can bypass AV.
			    	* [SimpleShellcodeInjector (SSI)](https://github.com/DimopoulosElias/SimpleShellcodeInjector)
			    		* SimpleShellcodeInjector receives as an argument a shellcode in hex and executes it. It DOES NOT inject the shellcode in a third party application.
			    	* [SharpZipRunner](https://github.com/jfmaes/SharpZipRunner)
			    		* Executes position independent shellcode from an encrypted zip Get PIC code from your assembly either by using donut or metasploit or cobaltstrike RAW format.
			    	* [RedTeamFSharp](https://github.com/Mr-Un1k0d3r/RedTeamFSharp)
			    		* Red Team Toolset written in F# (Experimental)
			    	* [DripLoader](https://github.com/xinbailu/DripLoader)
			    	* [DripLoader-Ops](https://github.com/xinbailu/DripLoader-Ops)
	* **Software Deployment Tools**<a name="sdtexec"></a>
	* **System Services**<a name="winserviceexec"></a>
		* **Service Execution**
			* **Articles/Blogposts/Writeups**
				* [Penetration Testing: Stopping an Unstoppable Windows Service - Scott Sutherland](https://blog.netspi.com/penetration-testing-stopping-an-unstoppable-windows-service/)
	* **Third-Party Software**<a name="tpswinexec"></a>
		* **Articles/Blogposts/Writeups**
			* [Abusing Firefox in Enterprise Environments - Daniil Vylegzhanin(2020)](https://www.mdsec.co.uk/2020/04/abusing-firefox-in-enterprise-environments/)
				* In this blogpost, we will describe a technique that abuses legacy Firefox functionality to achieve command execution in enterprise environments. The security issue was that the compromised domain user had Full Control rights on the files stored in the GPO, which were then subsequently deployed by SCCM to the Mozilla Firefox installation folder for all computer objects within the OU where the GPO was applied.
	 	* **Talks/Presentations/Videos**
		* **Tools**
	* **User Execution**<a name="winuserexec"></a>
		* **Malicious Link**
			* **Articles/Blogposts/Writeups**
				* [ClickOnce Security and Deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2015)
				* [ClickOnce (Twice or Thrice): A Technique for Social Engineering and (Un)trusted Command Execution - bohops](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)
				* [Simple Trick For Red Teams - secrary.com](https://secrary.com/Random/RedTeamTrick/)
					* Change from yellow, to blue.
		* **Malicious File**
	* **Windows Diagnostic Tools**<a name="wdtexec"></a>
		* **Articles/Blogposts/Writeups**
	 	* **Talks/Presentations/Videos**
	 		* [Using Windows diagnostics for system compromise - Nicholas Berthaume "aricon"(Derbycon2015)](https://www.irongeek.com/i.php?page=videos/derbycon5/teach-me15-using-windows-diagnostics-for-system-compromisea-nicholas-berthaume-aricon)
		 		* This talk will discuss the merits of using Microsoft diagnostic tools in order to deliver payloads to modern Microsoft operating systems with little or no scrutiny by anti-virus and network intrusion sensors.Ê In it I will go over the reasons for using this tool-set including the advantages of more conventional techniques as well as the reasoning behind its exploration vs. more invasive payloads including those reliant on bugs to provide system compromise.Ê Additionally a tool will be introduced that will provide for the creation of payloads on compatible `*nix` operating systems whereas previously they could only be generated using the Microsoft SDK on their operating systems.Ê Additionally there will be an element of privilege escalation by way of UAC bypass on default configurations of the windows operating system.
	* **Windows Management Instrumentation**<a name="wmiexec"></a>
		* **Articles/Blogposts/Writeups**
			* [WMIC - Take Command-line Control over WMI - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742610(v=technet.10))
			* [WMIC - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/wmic)
			* [Abusing Windows Management  Instrumentation (WMI) to Build a Persistent,  Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
		* **Talks/Presentations/Videos**
			* [Abusing Windows Management Instrumentation (WMI) - Matthew Graeber(BH USA 2015)](https://www.youtube.com/watch?v=0SjMgnGwpq8)
				* Imagine a technology that is built into every Windows operating system going back to Windows 95, runs as System, executes arbitrary code, persists across reboots, and does not drop a single file to disk. Such a thing does exist and it's called Windows Management Instrumentation (WMI). With increased scrutiny from anti-virus and 'next-gen' host endpoints, advanced red teams and attackers already know that the introduction of binaries into a high-security environment is subject to increased scrutiny. WMI enables an attacker practicing a minimalist methodology to blend into their target environment without dropping a single utility to disk. WMI is also unlike other persistence techniques in that rather than executing a payload at a predetermined time, WMI conditionally executes code asynchronously in response to operating system events. This talk will introduce WMI and demonstrate its offensive uses. We will cover what WMI is, how attackers are currently using it in the wild, how to build a full-featured backdoor, and how to detect and prevent these attacks from occurring.
		* **Tools**
	* **Windows Remote Management(WinRM)**<a name="winrmexec"></a>
		* **Tools**
			* [CSharpWinRM](https://github.com/mez-0/CSharpWinRM)
				* CsharpWinRM is a .NET 4.0 implementation of WinRM using the WinRM C++ API. This project takes in credentials and a command, then executes it on the remote host using Win32_Process.
	* **Windows Trouble Shooting Packs**<a name="wtspexec"></a>
		* **101**
			* [Windows Troubleshooting Platform - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/wintt/windows-troubleshooting-toolkit-portal)
				* Windows Troubleshooting Platform (WTP) provides ISVs, OEMs, and administrators the ability to write troubleshooting packs that are used to discover and resolve issues found on the computer. Previously, troubleshooting software and hardware issues was a manual process; however, using WTP you can automate the process of fixing the most common detectable issues that the user might encounter using your software or hardware.
			* [Built-in Troubleshooting Packs - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/ee424311(v=ws.10)?redirectedfrom=MSDN)
				* Windows 7 includes built-in troubleshooting packs to deal with common problems such as problems that are related to printers, displays, sound, networking, system performance, and hardware compatibility. Microsoft designed these troubleshooting packs to correlate to the top ten categories of Microsoft support calls.
			* [Windows Update Troubleshooter for Windows 10](https://support.microsoft.com/en-us/windows/windows-update-troubleshooter-for-windows-10-19bc41ca-ad72-ae67-af3c-89ce169755dd)
			* [TroubleshootingPack(PowerShell) - docs.ms](https://docs.microsoft.com/en-us/powershell/module/troubleshootingpack/?view=win10-ps)
				* This reference provides cmdlet descriptions and syntax for all Troubleshooting Pack cmdlets. It lists the cmdlets in alphabetical order based on the verb at the beginning of the cmdlet.
		* **Articles/Blogposts/Writeups**
			* [Looking for Trouble: Windows Troubleshooting Platform Leveraged to Deliver Malware - Matthew Mesa, Axel F(2016)](https://www.proofpoint.com/us/threat-insight/post/windows-troubleshooting-platform-leveraged-deliver-malware)
		* **Talks/Presentations/Videos**
		* **Tools**
	* **Payloads**
		* **Articles/Blogposts/Writeups**
		* **Papers**
			* [Post-Exploitation on Windows using ActiveX Controls](http://uninformed.org/?v=all&a=3&t=sumry)
				* When exploiting software vulnerabilities it is sometimes impossible to build direct communication channels between a target machine and an attacker's machine due to restrictive outbound filters that may be in place on the target machine's network. Bypassing these filters involves creating a post-exploitation payload that is capable of masquerading as normal user traffic from within the context of a trusted process. One method of accomplishing this is to create a payload that enables ActiveX controls by modifying Internet Explorer's zone restrictions. With ActiveX controls enabled, the payload can then launch a hidden instance of Internet Explorer that is pointed at a URL with an embedded ActiveX control. The end result is the ability for an attacker to run custom code in the form of a DLL on a target machine by using a trusted process that uses one or more trusted communication protocols, such as HTTP or DNS.
		* **Tools**
			* [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT)
				* Remote Command Execution as SYSTEM on Windows IoT Core; The method is exploiting the Sirep Test Service that’s built in and running on the official images offered at Microsoft’s site. This service is the client part of the HLK setup one may build in order to perform driver/hardware tests on the IoT device. It serves the Sirep/WPCon/TShell protocol. We broke down the Sirep/WPCon protocol and demonstrated how this protocol exposes a remote command interface for attackers, that include RAT abilities such as get/put arbitrary files on arbitrary locations and obtain system information. Based on the findings we have extracted from this research about the service and protocol, we built a simple python tool that allows exploiting them using the different supported commands. We called it SirepRAT. It features an easy and intuitive user interface for sending commands to a Windows IoT Core target. It works on any cable-connected device running Windows IoT Core with an official Microsoft image.
				* [Whitepaper](https://github.com/SafeBreach-Labs/SirepRAT/blob/master/docs/SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_White_Paper.pdf)
				* [Slides](https://github.com/SafeBreach-Labs/SirepRAT/blob/master/docs/SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_Slides.pdf)
* **Persistence**<a name="winpersist"></a>
	* **101**<a name="p101"></a>
		* [Windows Userland Persistence Fundamentals - b33f](http://www.fuzzysecurity.com/tutorials/19.html)	
		* [Persistence - pentestlab.blog](https://pentestlab.blog/methodologies/red-teaming/persistence/)
		* [alphaseclab Persistence](https://github.com/alphaSeclab/persistence/blob/master/Readme_en.md)
		* [Windows Persistence - Chad Duffey(2020)](https://www.chadduffey.com/2020/06/Windows-Persistence.html)
		* [Wicked malware persistence methods - Hasherezade(2017)](https://speakerdeck.com/hshrzd/wicked-malware-persistence-methods)
	* **Tactics**<a name="ptactics"></a>
		* [Hiding Registry keys with PSReflect - Brian Reitz](https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353)
		* [Hiding Files by Exploiting Spaces in Windows Paths](http://blakhal0.blogspot.com/2012/08/hiding-files-by-exploiting-spaces-in.html)
	* **Talks/Presentations/Videos**
		* [Evading Autoruns - Kyle Hanslovan, Chris Bisnet(Derbycon2017)](https://www.youtube.com/watch?v=AEmuhCwFL5I&feature=youtu.be)
			* When it comes to offense, maintaining access to your endpoints is key. For defenders, it's equally important to discover these footholds within your network. During this talk, Kyle and Chris will expose several semi-public and private techniques used to evade the most common persistence enumeration tools. Their techniques will explore ways to re-invent the run key, unconventionally abuse search order, and exploit trusted applications. To complement their technical explanations, each bypass will include a live demo and recommendations for detection.
			* [Materials](https://github.com/huntresslabs/evading-autoruns)
		* [Here to stay: Gaining persistency by Abusing Advanced Authentication Mechanisms - Marina Simakov, Igal Gofman](https://www.youtube.com/watch?v=JvormRcth9w)
			* [Slides](https://paper.seebug.org/papers/Security%20Conf/Defcon/2017/DEFCON-25-Marina-Simakov-and-Igal-Gofman-Here-to-stay-Gaining-persistence-by-abusing-auth-mechanisms.pdf)
		* [Killsuit the equation group's swiss army knife for persistence - Francisco J Donoso(BlueHat v18)](https://www.youtube.com/watch?v=R5mgAsd2VBM)
			* This talk expands on my research into the Equation Group's post exploitation tools. My previous research focused on providing a general overview of DanderSpritz, a full-featured post-exploitation toolkit included in the ShadowBroker's "Lost in Translation" leak. This talk provides a deep dive into KillSuit which is the Equation Group's Swiss Army Knife for persistence, information gathering, defense evasion, and data exfiltration in unique and interesting ways.   During the talk, we will dissect the capabilities and functionality of the KillSuit framework, a little-known (and somewhat overlooked) component of the much larger DanderSpritz post-exploitation toolkit, leaked by the Shadow Brokers in April 2017. KillSuit is a full featured and versatile framework used by a variety of the Equation Group's tools and implants. KillSuit provides the ability to quietly establish persistence on machines via bootkits and other persistence methods and then allows operators to install persistent modules such as keyloggers, packet capture tools, tools that perform WiFi MITM, and other more information gathering tools. KillSuit also includes support for many plugins that provide interesting ways to silently exfiltrate data - some specifically designed to make data exfiltration across air gapped networks possible - including custom written IPSEC-like protocols and misuse of "disabled" WIFI cards and nearby open networks.
	* **Tools**
	* **3rd Party Applications**<a name="p3rd"></a>
		* [Zoom Persistence via Symlink Abuse](https://github.com/S4R1N/ZoomPersistence)
		* [Persistence with KeePass - Part 1 - two06(2019](https://blog.two06.info/Persistence-with-KeePass-Part-1/)
			* [Part 2](https://blog.two06.info/Persistence-with-KeePass-Part-2/)
	* **Account Manipulation**<a name="pacm"></a>
		* **Additional Azure Service Principal Credentials**
		* **Exchange Email Delegate Permissions**
		* **Add Office 365 Global Administrator Role**
		* **RID Hijack**
			* **Articles/Blogposts/Writeups**
				* [RID Hijacking: Maintaining access on Windows machines - r4wd3r(2017)](https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html)
				* [RID Hijacking - @spottheplanet](https://www.ired.team/offensive-security/persistence/rid-hijacking)
			* **Talks/Presentations/Videos**
				* [ RID Hijacking: Maintaining Access on Windows Machines - Sebastián Castro(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/stable-26-rid-hijacking-maintaining-access-on-windows-machines-sebastin-castro)
					* [Slides](https://github.com/r4wd3r/RID-Hijacking/blob/master/slides/derbycon-8.0/RID_HIJACKING_DERBYCON_2018.pdf)
					* The art of persistence is (and will be...) a matter of concern when successfully exploitation is achieved. Sometimes it is pretty tricky to maintain access on certain environments, especially when it is not possible to execute common vectors like creating or adding users to privileged groups, dumping credentials or hashes, deploying a persistent shell, or anything that could trigger an alert on the victim. This statement ratifies why it's necessary to use discrete and stealthy techniques to keep an open door right after obtaining a high privilege access on the target. What could be more convenient that only use OS resources in order to persist an access? This presentation will provide a new post-exploitation hook applicable to all Windows versions called RID Hijacking, which allows setting desired privileges to an existent account in a stealthy manner by modifying some security attributes. To show its effectiveness, the attack will be demonstrated by using a module which was recently added by Rapid7 to their Metasploit Framework, and developed by the security researcher Sebastián Castro.
			* **Tools**
				* [RID Hijacking: Maintaining Access on Windows Machines](https://github.com/r4wd3r/RID-Hijacking)
					* The RID Hijacking hook, applicable to all Windows versions, allows setting desired privileges to an existent account in a stealthy manner by modifying some security attributes of an user. By only using OS resources, it is possible to replace the RID of an user right before the primary access token is created, allowing to spoof the privileges of the hijacked RID owner.
		* **SSH Authorized Keys**
	* **Accessibility Features**<a name="pacf"></a>
		* [Windows Persistence: Accessibility Features - Pavandeep Singh(2020](https://www.hackingarticles.in/windows-persistence-accessibility-features/)
	* **Active Directory Specific**<a name="pads"></a>
		* **Articles/Blogposts/Writeups**
			* [Sneaky Active Directory Persistence Tricks - adsecurity.org](https://adsecurity.org/?p=1929)
			* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most - Asaf Hect](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
			* [Thousand ways to backdoor a Windows domain (forest)](http://jumpespjump.blogspot.com/2015/03/thousand-ways-to-backdoor-windows.html)
			* [Remote Hash Extraction On Demand Via Host Security Descriptor Modification - Will Harmjoy](https://posts.specterops.io/remote-hash-extraction-on-demand-via-host-security-descriptor-modification-2cf505ec5c40)
				* Tl;dr if you gain “administrative” access to a remote machine, you can modify a few host security descriptors and have a security principal/trustee of your choice generate Silver Tickets indefinitely, as well as remotely retrieve local hashes and domain cached credentials.
		* **Talks/Presentations/Videos**
			* [Obtaining and Detecting Domain Persistence - Grant Bugher(DEF CON 23)](https://www.youtube.com/watch?v=gajEuuC2-Dk)
				* When a Windows domain is compromised, an attacker has several options to create backdoors, obscure his tracks, and make his access difficult to detect and remove. In this talk, I discuss ways that an attacker who has obtained domain administrator privileges can extend, persist, and maintain control, as well as how a forensic examiner or incident responder could detect these activities and root out an attacker.
		* **Tools**
		* **Directory Services Restore Mode**
			* [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
			* [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)
		* **Golden(Silver) Ticket**
			* [Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)
			* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)
			* [Silver & Golden Tickets - hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/)
			* [Mimikatz 2.0 - Golden Ticket Walkthrough - Ben Lincoln `https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html`
		* **Security Support Provider**
			* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760)
		* **SeEnableDelegationPrivilege**
			* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
			* [SeEnableDelegationPrivilege Active Directory Backdoor](https://www.youtube.com/watch?v=OiqaO9RHskU)
		* **SID History**
			* [Sneaky Active Directory Persistence #14: SID History](https://adsecurity.org/?p=1772)
	* **Alternate Data Streams**<a name="pads"></a>
		* **Articles/Blogposts/Writeups**
			* [Stealth Alternate Data Streams and Other ADS Weirdness - @mattifestation(2011)](http://www.exploit-monday.com/2011/09/stealth-alternate-data-streams-and.html)
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
	* **AMSI Provider**<a name="pamsi"></a>
		* [Antimalware Scan Interface Provider for Persistence - B4rtik(2020)](https://b4rtik.github.io/posts/antimalware-scan-interface-provider-for-persistence/)
		* [AMSI-Provider](https://github.com/netbiosX/AMSI-Provider)
			* A fake AMSI Provider which can be used to gain persistence on a host when a specific text is triggered. By default calc.exe will open.
	* **APPX/UWP**<a name="papp"></a>
		* [Persistence using Universal Windows Platform apps (APPX) - oddvarmoe](https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/)
			* Persistence can be achieved with Appx/UWP apps using the debugger options. This technique will not be visible by Autoruns.
	* **BITS Jobs**<a name="pbits"></a>
		* **Articles/Blogposts/Writeups**
		 	* [Background Intelligent Transfer Service - docs.ms](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal?redirectedfrom=MSDN)
		 	* [BITSAdmin tool - docs.ms](https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool?redirectedfrom=MSDN)
 				* BITSAdmin is a command-line tool that you can use to create download or upload jobs and monitor their progress.
			* [Temporal Persistence with bitsadmin and schtasks](http://0xthem.blogspot.com/2014/03/t-emporal-persistence-with-and-schtasks.html)
		
		* **Talks/Presentations/Videos**
		* **Tools**
	* **Boot or Logon Autostart Execution**<a name="pboot"></a>
		* [Windows Startup Application Database](http://www.pacs-portal.co.uk/startup_content.php)
		* [Windows Program Automatic Startup Locations(2004) BleepingComputer](https://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)
		* [Hijacking the Boot Process - Ransomware Style - Raul Alvarez(ShowMeCon2018)](https://www.irongeek.com/i.php?page=videos/showmecon2018/showmecon-2018-track-2-03-hijacking-the-boot-process-ransomware-style-raul-alvarez)
			* Have you ever wondered how a boot process works? How a computer detects which operating system it needs to load? Or what is the impact if that single sector in your harddisk is compromised? In this presentation, we are going to look into how Petya, a ransomware, can overwrite an MBR (Master Boot Record), both in MBR- and GPT-style disk, with its malicious code. Then, we are going to follow the code in the MBR and show how a simple malicious kernel code can take control of the boot process until you pay the ransom. I will show a demo on how to debug the MBR to see how the actual native code executes without any API. We are also going to see how we can use a combination of different tools to figure out how a ransomware can infect the very first sector of a harddisk. Tools, such as, Disk Management, DISKPART, WinObj, Process Monitor, and HDHacker. And of course, x64dbg and ollydbg for debugging the ransomware in application-level. And finally, we are going to see how to use Bochs debugger to analyze the malware while it runs its own kernel code.
		* **Authentication Package**
		* **Kernel Modules and Extensions**
		* **LSASS Driver**
		* **GPO**
			* [SYSTEM Context Persistence in GPO Startup Scripts](https://cybersyndicates.com/2016/01/system-context-persistence-in-gpo-startup/)
		* **Port Monitors**
		* **Plist Modification**
		* **Re-opened Applications**
		* **Registry Run Keys / Startup Folder**
		* **Security Support Provider**
		* **Shortcut Modification**
			* [Persistence – Shortcut Modification - NetbiosX](https://pentestlab.blog/2019/10/08/persistence-shortcut-modification/)
		* **Time Providers**
		* **Winlogon Helper DLL**
	* **Boot or Logon Initialization Scripts**<a name="pbl"></a>
		* **Browser Extensions**
		* **Logon Script (Mac)**
		* **Logon Script (Windows)**
		* **Network Logon Script**
		* **Rc.common**
		* **Startup Items**
	* **Compromise Client Software Binary**<a name="ccsb"></a>
		* **Articles/Blogposts/Writeups**
			* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence - bohops](https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/)
			* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence (Part 2) - bohops](https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/)
		* **Application Plugins**
			* [Backdooring Plugins - Averagejoe](https://www.gironsec.com/blog/2018/03/backdooring-plugins/)
	* **Create Account**<a name="pacc"></a>
		* **Local Account**
			* [Backdoorplz](https://github.com/jfmaes/Backdoorplz)
				* adding a backdooruser using win32api
		* **Domain Account**
		* **Cloud Account**
	* **Create or Modify System Process**<a name="cmsp"></a>
		* **Launch Agent**
		* **Systemd Service**
		* **Windows Service**
		* **Launch Daemon**	
	* **DLL Injection/Hijacking**<a name="pdll"></a>
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [bait](https://github.com/imag0r/bait)
				* Bait for dll injection and executable planting
	* **Drivers**<a name="pdriver"></a>
		* [Windows Firewall Hook Enumeration](https://www.nccgroup.com/en/blog/2015/01/windows-firewall-hook-enumeration/)
			* We’re going to look in detail at Microsoft Windows Firewall Hook drivers from Windows 2000, XP and 2003. This functionality was leveraged by the Derusbi family of malicious code to implement port-knocking like functionality. We’re going to discuss the problem we faced, the required reverse engineering to understand how these hooks could be identified and finally how the enumeration tool was developed.
	* **Event Triggered Execution**<a name="pete"></a>
		* **.bash_profile and .bashrc**
		* **Accessibility Features**
		* **AppCert DLLs**
		* **AppInit DLLs**
			* **Articles/Blogposts/Writeups**
				* [AppInit_DLLs in Windows 7 and Windows Server 2008 R2 - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2)
				* [AppInit DLLs and Secure Boot - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dlls/secure-boot-and-appinit-dlls)
					* Starting in Windows 8, the AppInit_DLLs infrastructure is disabled when secure boot is enabled.
				* [Alternative psexec: no wmi, services or mof needed - Diablohorn](https://diablohorn.com/2013/10/19/alternative-psexec-no-wmi-services-or-mof-needed/)
					* [Poc](https://github.com/DiabloHorn/DiabloHorn/tree/master/remote_appinitdlls)		
		* **Application Shimming**
			* **Articles/Blogposts/Writeups**
				* [Windows Persistence using Application Shimming - Kavish Tyagi(2020)](https://www.hackingarticles.in/windows-persistence-using-application-shimming/)
				* [Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)
				* [Shimming for Post Exploitation(blog)](http://www.sdb.tools/)
				* [Demystifying Shims – or – Using the App Compat Toolkit to make your old stuff work with your new stuff](https://web.archive.org/web/20170910104808/https://blogs.technet.microsoft.com/askperf/2011/06/17/demystifying-shims-or-using-the-app-compat-toolkit-to-make-your-old-stuff-work-with-your-new-stuff/)
				* [Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)
				* [Shim Database Talks](http://sdb.tools/talks.html)
				* [Using Application Compatibility Shims](https://web.archive.org/web/20170815050734/http://subt0x10.blogspot.com/2017/05/using-application-compatibility-shims.html)
				* [Persistence via Shims - liberty-shell](https://liberty-shell.com/sec/2020/02/25/shim-persistence/)
			* **Tools**
				* [Windows 0wn3d By Default - Mark Baggett(Derbycon2013)](https://www.irongeek.com/i.php?page=videos/derbycon3/4206-windows-0wn3d-by-default-mark-baggett)
					* Description: “In this talk we will discuss API Hooking, Process Execution Redirection, Hiding Registry keys and hiding directories on the hard drive. We must be talking about rootkits, right? Well yes, but not in the way you think. The Windows family of operating systems has all of these capabilities built right in! Using nothing but tools and techniques distributed and documented by Microsoft we can implement all of these rootkit functions. During this exciting talk I will present new attacks against Windows operating system that provide rootkit like functionality with built-in OS tools. In session, we’ll demonstrate how to leverage the Microsoft Application Compatibility Toolkit to help hide an attacker’s presence on your system. The Application Compatibility Toolkit allows you to create application shims that intercept and redirect calls from applications to the operating system. This native rootkit like capability is intended to make the Windows operating system compatible with very old or poorly written applications. Do DEP, ASLR, UAC, and Windows Resource Protection, File system ACLS and other modern OS security measures get it your way? No problem. Turn them off! Do you want to hide files and registry keys and from the user? The Application Compatibility toolkit allows you to create a virtual world for any application and hide resources from view. If someone inspects the registry with regedit they will see exactly what the attacker wants them to see and not what the OS sees when it launches programs. Did they patch your target so your exploit doesn’t work? Guess what, making applications backwards compatible is what this tool is intended to do. Make your favorite applications “old exploit compatible” insuring you can re-exploit the target with this awesome untapped resource. Everything you need to subvert windows applications is built right into the windows kernel. Come learn how to use the application compatibility toolkit to tap this great resource.”
		* **Component Object Model Hijacking**
			* [COM Object hijacking: the discreet way of persistence](https://blog.gdatasoftware.com/blog/article/com-object-hijacking-the-discreet-way-of-persistence.html)
			* [Userland Persistence with Scheduled Tasks and COM Handler Hijacking - enigma0x3(2016)](https://enigma0x3.net/2016/05/25)
			* [How To Hunt: Detecting Persistence & Evasion With The COM - Blake Strom](https://www.endgame.com/blog/technical-blog/how-hunt-detecting-persistence-evasion-com)
			* [Persistence: “the continued or prolonged existence of something”: Part 2 – COM Hijacking - MDSec](https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-2-com-hijacking/)
			* [Use COM Object hijacking to maintain persistence——Hijack CAccPropServicesClass and MMDeviceEnumerator - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-CAccPropServicesClass-and-MMDeviceEnumerator/)
			* [Use COM Object hijacking to maintain persistence——Hijack explorer.exe - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-explorer.exe/)
			* [Activation Contexts — A Love Story - Philip Tsukerman(2019)](https://medium.com/philip-tsukerman/activation-contexts-a-love-story-5f57f82bccd)
				* TL;DR — Windows loads a version of the Microsoft.Windows.SystemCompatible assembly manifest into every process. Tampering with it lets you inject DLL side-loading opportunities into every process, and to perform COM hijacking without touching the registry. Unfortunately, the manifest could be replaced by another version, possibly killing your persistence by surprise.
			* [Persistence – COM Hijacking - NetbiosX](https://pentestlab.blog/2020/05/20/persistence-com-hijacking/)
		* **Emond**
		* **Event Log**
			* [Windows Event Log Driven Back Doors](http://blakhal0.blogspot.com/2015/03/windows-event-log-driven-back-doors.html)
		* **Image File Execution Options Injection**
			* [Image File Execution Options - Vault7 Leaks](https://wikileaks.org/ciav7p1/cms/page_2621770.html)
			* [Persistence using GLOBALFLAGS in image file execution options – hidden from autoruns.exe - Oddvar Moe](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)
		* **LC_LOAD_DYLIB Addition**
		* **Netsh Helper DLL**
		* **PowerShell-relatd**
			* **Articles/Blogposts/Writeups**
				* [Using and Abusing Aliases with PowerShell - notoriousrebel.space](https://notoriousrebel.space/2019-11-24-using-and-abusing-aliases-with-powershell/)
					* Shimming Aliases with PowerShell
			* **Tools**
				* [Remapper](https://github.com/NotoriousRebel/Remapper)
					* PowerShell script that will shim aliases throughout PowerShell sessions through the use of PowerShell profiles.
				* [p0shkiller(2016)](https://github.com/Cn33liz/p0shKiller)
					* Proof of Concept exploit to bypass Microsoft latest AntiMalware Scan Interface technology within PowerShell5 on Windows 10. With this exploit/patch applied, you can take control over powershells program flow by using DLL Hijacking and UAC Bypasstechniques. Every time powershell is started, a local admin named BadAss with password FacePalm01 will be added to the system (when run by an non elevated administrator account) and a reverse (SYSTEM) https meterpreter session (default 192.168.1.120) will be started every hour using a scheduled task.
		* **Screensaver**
		* **Trap**
		* **Windows Management Instrumentation Event Subscription**
	* **Extension Handlers**<a name="pexth"></a>
		* [Hijacking extensions handlers as a malware persistence method - hasherezade(2017)](https://hshrzd.wordpress.com/2017/05/25/hijacking-extensions-handlers-as-a-malware-persistence-method/)
	* **External Remote Services**<a name="pers"></a>
	* **Filesystem**<a name="pfs"></a>
		* **NTFS**
			* [Pentester’s Windows NTFS Tricks Collection - Rene Freingruber](https://sec-consult.com/en/blog/2018/06/pentesters-windows-ntfs-tricks-collection/)
	* **Hijack Execution Flow**<a name="phef"></a>
		* **COR_PROFILER**
		* **DLL Search Order Hijacking**
		* **DLL Side-Loading**
		* **Dylib Hijacking**
		* **Executable Installer File Permissions Weakness**
		* **Implant Container Image**
		* **LD_PRELOAD**
		* **Path Interception by PATH Environment Variable**
		* **Path Interception by Search Order Hijacking**
		* **Path Interception by Unquoted Path**
		* **Services File Permissions Weakness**
		* **Services Registry Permissions Weakness**
	* **IIS Modules**<a name="piis"></a>
		* [IIS Raid – Backdooring IIS Using Native Modules - Rio Sherri(2020)](https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/)
			* Back in 2018, PaloAlto Unit42 publicly documented RGDoor, an IIS backdoor used by the APT34. The article highlighted some details which sparked my interest and inspired me to write IIS-Raid, an IIS backdoor module that allows red-team operators to keep a stealthy persistence on IIS web-servers. In this blogpost, we will discuss some of the key components of this tool, how it was built and demonstrate its features.
	* **Implant Container Image**
	* **LAPS**<a name="plaps"></a>
		* **Articles/Blogposts/Writeups**
			* [Mise en place d'une Backdoor LAPS via modification de l'attribut SearchFlags avec DCShadow - Gregory Lucand](https://adds-security.blogspot.com/2018/08/mise-en-place-dune-backdoor-laps-via.html)
			* [Adding a Backdoor to AD in 400 Milliseconds - David Rowe](https://www.secframe.com/blog/persistence-in-400-milliseconds)
			* [LAPS - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/域渗透-利用SYSVOL还原组策略中保存的密码/)
			* [LAPS - liuhaihua](http://www.liuhaihua.cn/archives/179102.html)
	* **Library Files**<a name="plf"></a>
		* **101**
			* [Windows libraries - docs.ms](https://docs.microsoft.com/en-us/windows/client-management/windows-libraries)
				* Libraries are virtual containers for users’ content. A library can contain files and folders stored on the local computer or in a remote storage location. In Windows Explorer, users interact with libraries in ways similar to how they would interact with other folders. Libraries are built upon the legacy known folders (such as My Documents, My Pictures, and My Music) that users are familiar with, and these known folders are automatically included in the default libraries and set as the default save location.
		* **Articles/Blogposts/Writeups**
			* [Windows Library Files (.library-ms) - Vault7 Leaks](https://wikileaks.org/ciav7p1/cms/page_13763381.html)
			* [Abusing Windows Library Files for Persistence - F-Secure](https://blog.f-secure.com/abusing-windows-library-files-for-persistence/)
	* **MS Distributed Transaction Coordinator Service**<a name="pdtcs"></a>
		* **Articles/Blogposts/Writeups**
			* [Distributed Transaction Coordinator - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms684146(v=vs.85))
			* [The Microsoft Distributed Transaction Coordinator service must run under the NT AUTHORITY\NetworkService Windows account - support.ms](https://support.microsoft.com/en-us/help/903944/the-microsoft-distributed-transaction-coordinator-service-must-run-und)
			* [Shadow Force Uses DLL Hijacking, Targets South Korean Company - Dove Chiu(2015)](https://blog.trendmicro.com/trendlabs-security-intelligence/shadow-force-uses-dll-hijacking-targets-south-korean-company/)
			* [Use msdtc to maintain persistence - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-msdtc-to-maintain-persistence/)
	* **.NET**<a name="pnet"></a>
		* **Articles/Blogposts/Writeups**
			* [Common Language Runtime Hook for Persistence - Paul Laine](https://www.contextis.com/en/blog/common-language-runtime-hook-for-persistence)
				* This blog post explains how it is possible to execute arbitrary code and maintain access to a Microsoft Windows system by leveraging the Common Language Runtime application domain manager.
			* [CLR-Persistence](https://github.com/3gstudent/CLR-Injection)
				* Use CLR to inject all the .NET apps
			* [Using CLR to maintain Persistence](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-maintain-persistence/)
			* [SharPersist: Windows Persistence Toolkit in C# - Brett Hawkins](https://www.fireeye.com/blog/threat-research/2019/09/sharpersist-windows-persistence-toolkit.html)
			* [Configuring our Machine for Persistence - NotoriousRebel(2020)](https://web.archive.org/web/20200227092613if_/https://secbytes.net/Configuring-our-Machine-for-Persistence)
		* **Tools**
			* [SharPersist](https://github.com/fireeye/SharPersist)
				* Windows persistence toolkit written in C#
			* [ConfigPersist](https://github.com/NotoriousRebel/ConfigPersist)
				* Utilizes modifying machine.config for persistence through CLR hooking, after installing signed .NET assembly onto Global Assembly Cache.
		* **AppDomain**
			* [Use AppDomainManager to maintain persistence](https://3gstudent.github.io/3gstudent.github.io/Use-AppDomainManager-to-maintain-persistence/)
	* **Netsh**<a name="pnetsh"></a>
		* [Windows Persistence using Netsh - Pavandeep Singh(2020)](https://www.hackingarticles.in/windows-persistence-using-netsh/)
		* [Persistence – Netsh Helper DLL - NetbiosX](https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/)
	* **Office Applications**<a name="poffice"></a>
		* **Articles/Blogposts/Writeups**
			* [Use Office to maintain persistence - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/)
			* [Office Persistence on x64 operating system - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Office-Persistence-on-x64-operating-system/)
			* [Persistence: “the continued or prolonged existence of something” - Dominic Chell](https://medium.com/@dmchell/persistence-the-continued-or-prolonged-existence-of-something-e29ea63e5c9a)
			* [app-password-persistence](https://github.com/rgeoghan/app-password-persistence/blob/master/README.md)
		* **Add-ins**
			* [Add-In Opportunities for Office Persistence - William Knowles](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
		* **Extensibility Features**
			* [Persisting with Microsoft Office: Abusing Extensibility Options - William Knowles](https://labs.mwrinfosecurity.com/assets/BlogFiles/WilliamKnowles-MWR-44con-PersistingWithMicrosoftOffice.pdf)
		* **Office Template Macros**
			* [One Template To Rule 'Em All - Kostas Lintovois](https://labs.f-secure.com/archive/one-template-to-rule-em-all/)
				* Introduction of wePWNize
		* **Outlook Forms**
		* **Outlook Rules**
			* [XRulez](https://github.com/FSecureLABS/XRulez)
				* "XRulez" is a Windows executable that can add malicious rules to Outlook from the command line of a compromised host.
		* **Outlook Home Page**
		* **Office Test**
	* **Password Filter DLL**<a name="pfdll"></a>
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
	* **Port Monitors**<a name="pportmon"></a>
		* [Windows Persistence: Port Monitors - Aarti Singh(2020)](https://www.hackingarticles.in/windows-persistence-port-monitors/)
		* [Windows Persistence via Port Monitors - Slayerlabs(2020](https://posts.slayerlabs.com/monitor-persistence/)
	* **Pre-OS Boot**<a name="peboot"></a>
		* **System Firmware**
		* **Component Firmware**
		* **Bootkit**
	* **Print Processor**<a name="pprint"></a>
		* [No “Game over” for the Winnti Group - Mathieu Tartare, Martin Smolár(2020)](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/)
		* [New PipeMon malware uses Windows print processors for persistence - Ionut Ilascu(2020)](https://www.bleepingcomputer.com/news/security/new-pipemon-malware-uses-windows-print-processors-for-persistence/)
	* **Processes**<a name="pppp"></a>
		* [Mayhem](https://github.com/zeroSteiner/mayhem)
			* The Mayhem packages aims to provide a Python interface for the programmatic manipulation of executable files at runtime on both the Linux and Windows platforms.
	* **Registry**<a name="preg"></a>
		* [Windows Registry Attacks: Knowledge Is the Best Defense](https://www.redcanary.com/blog/windows-registry-attacks-threat-detection/)
		* [Windows Registry Persistence, Part 1: Introduction, Attack Phases and Windows Services](http://blog.cylance.com/windows-registry-persistence-part-1-introduction-attack-phases-and-windows-services)
		* [Windows Registry Persistence, Part 2: The Run Keys and Search-Order](http://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order)
		* [List of autorun keys / malware persistence Windows registry entries](https://www.peerlyst.com/posts/list-of-autorun-keys-malware-persistence-windows-registry-entries-benjamin-infosec)
		* [How to Evade Detection: Hiding in the Registry - David Lu](https://www.tripwire.com/state-of-security/mitre-framework/evade-detection-hiding-registry/)
		* [Persistence – Registry Run Keys - NetbiosX](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/)
		* [InvisiblePersistence](https://github.com/ewhitehats/InvisiblePersistence)
			* Persisting in the Windows registry "invisibly". Whitepaper and POC
	* **Scheduled Task/Job**<a name="psctj"></a>
		* **At (Windows)**
			* [Userland Persistence with Scheduled Tasks and COM Handler Hijacking - enigma0x3](https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
		* **Scheduled Task**
			* [Sc](https://technet.microsoft.com/en-us/library/cc754599.aspx)
				* Communicates with the Service Controller and installed services. The SC.exe program provides capabilities similar to those provided in Services in the Control Panel.
			* [schtasks](https://technet.microsoft.com/en-us/library/cc725744.aspx)
			* [Script Task](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task)
				* Persistence Via MSSQL
			* [Persistence using Task Scheduler without a Scheduled Task - marpie(2019](https://www.a12d404.net/windows/2019/10/30/schedsvc-persist-without-task.html)
		* **Scheduled Job**
			* [How to create PowerShell Scheduled Jobs on the Local Computer and on Remote Hosts - Patrick Gruenauer(2018](https://sid-500.com/2018/08/25/how-to-create-powershell-scheduled-jobs-on-the-local-computer-and-on-remote-hosts/)
	* **ScreenSaver**<a name="pss"></a>
		* [Persistence – Screensaver - NetbiosX](https://pentestlab.blog/2019/10/09/persistence-screensaver/)	
	* **Services**<a name="pss"></a>
			* [Create A Windows Service In C# - Faisal Pathan(2020](https://www.c-sharpcorner.com/article/create-windows-services-in-c-sharp/)
			* [Stealthier persistence using new services purposely vulnerable to path interception - Christophe Tafani-Dereeper](https://blog.christophetd.fr/stealthier-persistence-using-new-services-purposely-vulnerable-to-path-interception/)
			* [Persistence – New Service - NetbiosX](https://pentestlab.blog/2019/10/07/persistence-new-service/)
			* [Persisting in svchost.exe with a Service DLL - @spotheplanet](https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain)
	* **Server Software Component**<a name="pssc"></a>
		* **IIS**
			* [IIS Raid – Backdooring IIS Using Native Modules - MDSec](https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/)
		* **MS-SQL Server**
			* [Maintaining Persistence via SQL Server – Part 1: Startup Stored Procedures - NETSPI](https://blog.netspi.com/sql-server-persistence-part-1-startup-stored-procedures/)
			* [Script Task - doc.ms](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task?redirectedfrom=MSDN&view=sql-server-2017)
		* **SQL Stored Procedures**
		* **Transport Agent**
		* **Web Shell**
	* **SMB**<a name="psmb"></a>
		* [smbdoor](https://github.com/zerosum0x0/smbdoor)
			* The proof-of-concept smbdoor.sys driver is a silent remote backdoor that does not bind new sockets or perform function modification hooking. Instead it abuses undocumented APIs in srvnet.sys to register itself as a valid SMB handler. It then listens on the already-bound ports 139/445 for special packets in which to execute secondary shellcode. In several ways, it has similarities with DoublePulsar and DarkPulsar, as well as ToxicSerpent.
	* **Windows Telemetry**<a name="pwtm"></a>
		* [Abusing Windows Telemetry for Persistence -Christopher Paschen(2020)](https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/)
		* [Telemetry](https://github.com/Imanfeng/Telemetry)
	* **Third-Party Programs**
		* [Persistence with KeePass - Part 1 - James](https://web.archive.org/web/20190816125156/https://medium.com/@two06/persistence-with-keepass-part-1-d2e705326aa6)	
	* **Traffic Signaling**<a name="pts"></a>
		* **Port Knocking**
	* **UEFI**<a name="puefi"></a>
		* [MIDNIGHTTRAIN](https://github.com/slaeryan/MIDNIGHTTRAIN)
		* [Blogpost](https://slaeryan.github.io/posts/midnighttrain.html)
			* Covert Stage-3 Persistence Framework utilizing NVRAM variables
	* **URI Scheme**<a name="puri"></a>
		* [Registering an Application to a URI Scheme - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa767914(v=vs.85)?redirectedfrom=MSDN)
		* [Exploiting custom protocol handlers in Windows - Andrey Polkovnychenko](https://www.vdoo.com/blog/exploiting-custom-protocol-handlers-in-windows)
			* In this article we would like to present the mechanism for custom protocol handling in Windows, and how it can be exploited using a simple command injection vulnerability.		
		* [backoori](https://github.com/giuliocomi/backoori)
			* Tool aided persistence via Windows URI schemes abuse
	* **Valid Accounts**<a name="pva"></a>
		* **Default Accounts**
		* **Domain Accounts**
		* **Local Accounts**
		* **Cloud Accounts**
	* **VisualStudio**<a name="pvs"></a>
		* [Using Visual Studio Code Extensions for Persistence - Charley Célice(2020)](https://medium.com/secarmalabs/using-visual-studio-code-extensions-for-persistence-a65c940b7ea6)
	* **WaitFor**<a name="pwf"></a>
		* [waitfor - docs.ms](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/waitfor)
		* [Persistence – WaitFor - NetbiosX(2020)](https://pentestlab.blog/2020/02/04/persistence-waitfor/)
			* "Waitfor is a Microsoft binary which is typically used to synchronize computers across a network by sending signals. This communication mechanism can be used in a red team operation in order to download and execution arbitrary code and for persistence. The binary is stored in C:\Windows\System32 folder which means that local administrator privileges are required to perform this activity and both hosts (sender and receiver) needs to be on the same network segment. "
	* **Windows Subsystem for Linux**<a name="pwsl"></a>
		* [Unremovable malware with WSL - foresixchange(2019](https://www.forensixchange.com/posts/19_11_01_unremovable_malware_with_wsl/)
	* **WMI**<a name="pwmi"></a>
		* [Playing with MOF files on Windows, for fun & profit - xst3nz(2016)](https://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)
		* [Windows Management Instrumentation (WMI) Offense, Defense, and Forensics - William Ballenthin, Matt Graeber, Claudiu Teodorescu](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)
		* [WMI Persistence using wmic.exe - @mattifestation(2016)](http://www.exploit-monday.com/2016/08/wmi-persistence-using-wmic.html)
	* **WPAD**
		* [WPAD Persistence](http://room362.com/post/2016/wpad-persistence/)
* **Unsorted**
	* [Quiet in the Windows: Dropping Network Connections - Eviatar Gerzi](https://medium.com/@eviatargerzi/quiet-in-the-windows-dropping-network-connections-a5181b874116)
	* **Tools**
		* [Invisible Persistence](https://github.com/ewhitehats/InvisiblePersistence)
			* [Code](https://github.com/ewhitehats/InvisiblePersistence/tree/master/InvisibleKeys)
			* [Paper](https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf)
		* [DropNet](https://github.com/g3rzi/DropNet)
			* A tool that can be used to close network connections automatically with a given parameters
	* **Miscellaneous**
		* [backdoorme](https://github.com/Kkevsterrr/backdoorme)
			* Tools like metasploit are great for exploiting computers, but what happens after you've gained access to a computer? Backdoorme answers that question by unleashing a slew of backdoors to establish persistence over long periods of time. Once an SSH connection has been established with the target, Backdoorme's strengths can come to fruition. Unfortunately, Backdoorme is not a tool to gain root access - only keep that access once it has been gained.
* **Privilege Escalation**<a name="winprivesc"></a>
	* **101**<a name="pe101"></a>
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
		* **DLL Stuff** <a name="dllstuff"></a>
			* [Creating a Windows DLL with Visual Basic](http://www.windowsdevcenter.com/pub/a/windows/2005/04/26/create_dll.html)
			* [Calling DLL Functions from Visual Basic Applications - msdn](https://msdn.microsoft.com/en-us/library/dt232c9t.aspx)
			* **DLL Hijacking/Plant/Proxying**
				* **101**
					* [Dynamic-Link Library Search Order - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/Dlls/dynamic-link-library-search-order)
					* [Dynamic-Link Library Hijacking](https://www.exploit-db.com/docs/31687.pdf)
					* [Crash Course in DLL Hijacking](https://blog.fortinet.com/2015/12/10/a-crash-course-in-dll-hijacking)
					* [VB.NET Tutorial - Create a DLL / Class Library](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)
					* [Exploiting DLL Hijacking by DLL Proxying Super Easily](https://github.com/tothi/dll-hijack-by-proxying)
						* This is a tutorial about exploiting DLL Hijack vulnerability without crashing the application. The method used is called DLL Proxying.
					* [Hijacking DLLs in Windows - Wietze(2020)](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)
						* DLL Hijacking is a popular technique for executing malicious payloads. This post lists nearly 300 executables vulnerable to relative path DLL Hijacking on Windows 10 (1909), and shows how with a few lines of VBScript some of the DLL hijacks can be executed with elevated privileges, bypassing UAC.
					* [dll-hijack-by-proxying](https://github.com/tothi/dll-hijack-by-proxying)
						* This is a tutorial about exploiting DLL Hijack vulnerability without crashing the application. The method used is called DLL Proxying.
				* **Articles/Blogposts/Writeups**
					* [Adaptive DLL Hijacking - Nick Landers](https://silentbreaksecurity.com/adaptive-dll-hijacking/)
					* [DLL Hijacking - @spotheplanet](https://www.ired.team/offensive-security/privilege-escalation/t1038-dll-hijacking)
					* [Windows 10 - Task Scheduler service - Privilege Escalation/Persistence through DLL planting - remoteawesomethoughts.blogspot](https://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html)
					* [DLL Hijacking via URL files - InsertScript](https://insert-script.blogspot.com/2018/05/dll-hijacking-via-url-files.html)
					* [DLL Hijacking - pentestlab.blog(2017)](https://pentestlab.blog/2017/03/27/dll-hijacking/)
					* [Understanding how DLL Hijacking works - Astr0baby(2018)](https://astr0baby.wordpress.com/2018/09/08/understanding-how-dll-hijacking-works/)
					* [ Microsoft File Checksum Integrity Verifier "fciv.exe" v2.05 / DLL Hijack Arbitrary Code Execution - hyp3rlinx(2019)](https://seclists.org/fulldisclosure/2019/Jul/1)
					* [DLL Hijacking - libertyshell.com(2019)](https://liberty-shell.com/sec/2019/03/12/dll-hijacking/)
					* [Lateral Movement — SCM and DLL Hijacking Primer - Dwight Hohnstein(2019)](https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992)
					* [Windows Server 2008R2-2019 NetMan DLL Hijacking - itm4n(2020](https://itm4n.github.io/windows-server-netman-dll-hijacking/)
					* [Automating DLL Hijack Discovery - Justin Bui(2020)](https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0)
					* [UAC bypass through Trusted Folder abuse - Jean Maes(2020)](https://redteamer.tips/uac-bypass-through-trusted-folder-abuse/)
					* [My First 2020 [NonTroll] CVE - DLL Hijacking in NVIDIA System Management Interface (SMI) - Andy Gill(2020)](https://blog.zsec.uk/nvidia-cve-2020/)
					* [Windows 10 - Task Scheduler service - Privilege Escalation/Persistence through DLL planting - remoteawesomethoughts.blogspot](https://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html)
						* I was recently busy doing some reverse on an antivirus solution. During this review, I figured out the Windows 10 Task Scheduler service was looking for a missing DLL exposing it to DLL hijacking/planting. It opens for persistence and privilege escalation in case one can write a rogue DLL in a folder pointed by the PATH environment variable. It can also be used as a UAC bypass.
					* [Use CLR to bypass UAC - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-bypass-UAC/)
					* [UAC bypass via elevated .NET applications - @clavoillotte(2017)](https://offsec.almond.consulting/UAC-bypass-dotnet.html)
						* TL;DR .NET Framework can be made to load a profiling DLL or a COM component DLL via user-defined environment variables and CLSID registry entries, even when the process is elevated. This behavior can be exploited to bypass UAC in default settings on Windows 7 to 10 (including the latest RS3 builds) by making an auto-elevate .NET process (such as MMC snap-ins) load an arbitrary DLL.
					* [.NET Profiler DLL Hijack](https://github.com/djhohnstein/.NET-Profiler-DLL-Hijack)
						* The .NET Framework can be coerced into loading a profiling DLL into any .NET assembly when launched. This is done when a handful of environment variables and registry keys are set. For a full write-up you can view this blog here: https://offsec.provadys.com/UAC-bypass-dotnet.html
				* **Tools**
					* [Siofra](https://github.com/cys3c/Siofra)
						* DLL hijacking vulnerability scanner and PE infector tool
					* [DLLSpy](https://github.com/cyberark/DLLSpy)
						* DLLSpy is a that detects DLL hijacking in running processes, services and in their binaries.
					* [Robber](https://github.com/MojtabaTajik/Robber)
						*  Robber is open source tool for finding executables prone to DLL hijacking 
					* [Koppeling](https://github.com/monoxgas/Koppeling)
						* This project is a demonstration of advanced DLL hijack techniques. It was released in conjunction with the ["Adaptive DLL Hijacking" blog post](https://silentbreaksecurity.com/adaptive-dll-hijacking/). I recommend you start there to contextualize this code.
					* [TrustJack](https://github.com/jfmaes/TrustJack)
					* [HijackHunter](https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter)
					* [RunHijackHunter](https://github.com/fashionproof/RunHijackHunter)
			* **DLL Tools**
				* [Dependencies - An open-source modern Dependency Walker](https://github.com/lucasg/Dependencies)
					* A rewrite of the old legacy software "depends.exe" in C# for Windows devs to troubleshoot dll load dependencies issues.
				* [rattler](https://github.com/sensepost/rattler)
					* Rattler is a tool that automates the identification of DLL's which can be used for DLL preloading attacks.
				* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings)
					* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
				* [Pazuzu](https://github.com/BorjaMerino/Pazuzu)
					* Pazuzu is a Python script that allows you to embed a binary within a precompiled DLL which uses reflective DLL injection. The goal is that you can run your own binary directly from memory. This can be useful in various scenarios.	
				* [Bleak](https://github.com/Akaion/Bleak)
					* A Windows native DLL injection library written in C# that supports several methods of injection.
		* **Exploits/Missing Patches**<a name="peemp"></a>
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
				* [CVE-2020-0796 Windows SMBv3 LPE Exploit POC Analysis - Sung Lin(2020)](https://paper.seebug.org/1165/)
				* [Exploiting SMBGhost (CVE-2020-0796) for a Local Privilege Escalation: Writeup + POC - Zecops(2020)](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/)
				* [CVE-2020-0796 Windows SMBv3 Client/Server Remote Code Execution Vulnerability - portal.msrc](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796)
				* [I'm SMBGhost, daba dee daba da - Lucas Georges(2020)](https://www.synacktiv.com/en/publications/im-smbghost-daba-dee-daba-da.html)
				* [CVE-2020-0796 Memory Corruption Vulnerability in Windows 10 SMB Server - Yije Wang(2020)](https://www.fortinet.com/blog/threat-research/cve-2020-0796-memory-corruption-vulnerability-in-windows-10-smb-server#.Xndfn0lv150.twitter)
				* [SMBGhost – Analysis of CVE-2020-0796 - Eoin Carroll, Philippe Laulheret, Kevin McGrath, Steve Povolny(2020)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/smbghost-analysis-of-cve-2020-0796/)
				* [微软SMBv3客户端/服务端远程代码执行漏洞（CVE-2020-0796）技术分析 - blogs.360.cn](微软SMBv3客户端/服务端远程代码执行漏洞（CVE-2020-0796）技术分析https://blogs.360.cn/post/CVE-2020-0796.html)
				* [Vulnerability Reproduction: CVE-2020-0796 POC - Zecops](https://blog.zecops.com/vulnerabilities/vulnerability-reproduction-cve-2020-0796-poc/)
			* **CVE-2020-1362**	
				* [Exploiting an Elevation of Privilege bug in Windows 10 (CVE-2020-1362)](https://github.com/Q4n/CVE-2020-1362)
					* writeup of CVE-2020-1362 
			* **Miscellaneous**
				* [CVE-2019-1405 and CVE-2019-1322 – Elevation to SYSTEM via the UPnP Device Host Service and the Update Orchestrator Service - Phillip Langlois and Edward Torkington](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/)
					* This blog post discusses two vulnerabilities discovered by NCC Group consultants during research undertaken on privilege elevation via COM local services. The first of these vulnerabilities (CVE-2019-1405) is a logic error in a COM service and allows local unprivileged users to execute arbitrary commands as a LOCAL SERVICE user. The second vulnerability (CVE-2019-1322) is a simple service misconfiguration that allows any user in the local SERVICE group to reconfigure a service that executes as SYSTEM (this vulnerability was independently also discovered by other researchers). When combined, these vulnerabilities allow an unprivileged local user to execute arbitrary commands as the SYSTEM user on a default installation of Windows 10.
				* [Thanksgiving Treat: Easy-As-Pie Windows 7 Secure Desktop Escalation Of Privilege - Simon Zuckerbraun](https://www.zerodayinitiative.com/blog/2019/11/19/thanksgiving-treat-easy-as-pie-windows-7-secure-desktop-escalation-of-privilege)
				* [Docker Desktop for Windows PrivEsc (CVE-2020-11492) - Ceri Coburn(2020)](https://www.pentestpartners.com/security-blog/docker-desktop-for-windows-privesc-cve-2020-11492/)
				* [Windows Telemetry service elevation of privilege - secret.club(2020)](https://secret.club/2020/07/01/diagtrack.html)
					* [Example](https://github.com/thesecretclub/diagtrack/blob/master/example.cpp)
				* [CVE-2016-5237: Valve Steam 3.42.16.13 Local Privilege Escalation](https://www.exploit-db.com/exploits/39888)
		* **Fax/Printer/Network Service**<a name="pfp"></a>
			* **Articles/Blogposts/Writeups**
				* [PrintDemon: Print Spooler Privilege Escalation, Persistence & Stealth (CVE-2020-1048 & more) - Yarden Shafir & Alex Ionescu(2020)](https://windows-internals.com/printdemon-cve-2020-1048/)
				* [Faxing Your Way to SYSTEM — Part Two - Yarden Shafir & Alex Ionescu(2020)](https://windows-internals.com/faxing-your-way-to-system/)
				* [Sharing a Logon Session a Little Too Much - James Forshaw](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)
			* **Tools**	
				* [faxhell ("Fax Shell")](https://github.com/ionescu007/faxhell)
					* A Proof-of-Concept bind shell using the Fax service and a DLL hijack based on `Ualapi.dll`.
				* [RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
		* **Group Policy (Preferences)**<a name="gppf"></a>
			* [Get-GPPermission - docs.ms](https://docs.microsoft.com/en-us/powershell/module/grouppolicy/get-gppermission?view=win10-ps)
			* [Exploiting Windows 2008 Group Policy Preferences](http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html)
			* [Decrypting Windows 2008 GPP user passwords using Gpprefdecrypt.py](https://web.archive.org/web/20160408235812/http://www.leonteale.co.uk/decrypting-windows-2008-gpp-user-passwords-using-gpprefdecrypt-py/)
			* [Group Policy Preferences and Getting Your Domain 0wned - Carnal0wnage](http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html)
			* [Compromise Networks Through Group Policy Preferences - securestate.com(archive.org)](https://web.archive.org/web/20150108083024/http://blog.securestate.com/how-to-pwn-systems-through-group-policy-preferences/)
			* [Group Policy Preferences - NetbiosX](https://pentestlab.blog/2017/03/20/group-policy-preferences/)
			* [Credential Dumping: Group Policy Preferences (GPP) - Yashika Dhir(2020)](https://www.hackingarticles.in/credential-dumping-group-policy-preferences-gpp/)
		* **Intel SYSRET**<a name="peis"></a>
			* [Windows Kernel Intel x64 SYSRET Vulnerability + Code Signing Bypass Bonus](https://repret.wordpress.com/2012/08/25/windows-kernel-intel-x64-sysret-vulnerability-code-signing-bypass-bonus/)
			* [Windows Kernel Intel x64 SYSRET Vulnerability Exploit + Kernel Code Signing Bypass Bonus](https://github.com/shjalayeri/sysret)
		* **LAPS Misconfiguration**<a name="pelaps"></a>
			* [Taking over Windows Workstations thanks to LAPS and PXE - Rémi ESCOURROU](https://www.securityinsider-wavestone.com/2020/01/taking-over-windows-workstations-pxe-laps.html)
				* In this article we will examine how the combination of two good security solutions with no apparent connection to each other can lead to the takeover of all workstations in a Windows environment. The main advantage of this technique is that it is exploitable in black box, i.e. without any prior knowledge of the target.
			* [Who Can See LAPS Passwords? - David Rowe](https://www.secframe.com/blog/when-can-you-see-a-laps-password)
			* [Credential Dumping: LAPS - Kavish Tyagi(2020)](https://www.hackingarticles.in/credential-dumpinglaps/)
		* **Local Phishing**<a name="pelp"></a>
			* **Articles/Blogposts/Writeups**
				* [Ask and ye shall receive - Impersonating everyday applications for profit - FoxIT](https://www.fox-it.com/en/insights/blogs/blog/phishing-ask-and-ye-shall-receive/)
				* [Phishing for Credentials: If you want it, just ask! - enigma0x3](http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
				* [Phishing Windows Credentials - NetbiosX](https://pentestlab.blog/2020/03/02/phishing-windows-credentials/)
				* [Credentials Collection via CredUIPromptForCredentials - @spottheplanet](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/credentials-collection-via-creduipromptforcredentials)
				* [ICU: A Red Teamer’s Hail Mary - Jean Maes](https://redteamer.tips/icu-a-red-teamers-hail-mary/)
					* [Code](https://github.com/WingsOfDoom/ICU)
				* [Phishing Windows Credentials - NetbiosX(2020)](https://pentestlab.blog/2020/03/02/phishing-windows-credentials/ )
				* [How to Phish for User Passwords with PowerShell - tokyoneon(2021)](https://www.blackhillsinfosec.com/how-to-phish-for-user-passwords-with-powershell/)
			* **Tools**
				* [Invoke-CredentialPhisher](https://github.com/fox-it/Invoke-CredentialPhisher)
					* The first one is a powershell script to send toast notifications on behalf on an (installed) application or the computer itself. The user will be asked to supply credentials once they click on the notification toast. The second one is a Cobalt Strike module to launch the phishing attack on connected beacons.
				* [Powershell Popups + Capture - mubix(2015)](https://malicious.link/post/2015/powershell-popups-and-capture/)
				* [Invoke-CredentialsPhish.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Invoke-CredentialsPhish.ps1)
				* [Invoke-LoginPrompt](https://github.com/enigma0x3/Invoke-LoginPrompt)
					* Invokes a Windows Security Login Prompt and outputs the clear text password. 
				* [CredsLeaker](https://github.com/Dviros/CredsLeaker)
					* Credsleaker allows an attacker to craft a highly convincing credentials prompt using Windows Security, validate it against the DC and in turn leak it via an HTTP request.
		* **Logic Bugs**<a name="pelb"></a>
			* [Introduction to Logical Privilege Escalation on Windows - James Forshaw](https://conference.hitb.org/hitbsecconf2017ams/materials/D2T3%20-%20James%20Forshaw%20-%20Introduction%20to%20Logical%20Privilege%20Escalation%20on%20Windows.pdf)
			* [Windows Logical EoP Workbook](https://docs.google.com/document/d/1qujIzDmFrcFCBeIgMjWDZTLNMCAHChAnKDkHdWYEomM/edit)
			* [Abusing Token Privileges For EoP](https://github.com/hatRiot/token-priv)
				* This repository contains all code and a Phrack-style paper on research into abusing token privileges for escalation of privilege. Please feel free to ping us with questions, ideas, insults, or bugs.				
			* [awesome_windows_logical_bugs](https://github.com/sailay1996/awesome_windows_logical_bugs)
		* **Named Pipes**<a name="penp"></a>
			* [Discovering and Exploiting Named Pipe Security Flaws for Fun and Profit - Blake Watts(2002)](http://www.blakewatts.com/namedpipepaper.html)
			* [Named Pipe Filename Local Privilege Escalation - Securiteam(2003)](https://securiteam.com/windowsntfocus/5bp012kaki/)
			* [Windows Named Pipes & Impersonation - decoder.cloud(2019)](https://decoder.cloud/2019/03/06/windows-named-pipes-impersonation/)
			* [Windows NamedPipes 101 + Privilege Escalation - @spottheplanet](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
			* [Part I: The Fundamentals of Windows Named Pipes - Robert Hawes](https://versprite.com/blog/security-research/microsoft-windows-pipes-intro/)
			* [Part II: Analysis of a Vulnerable Microsoft Windows Named Pipe Application - Robert Hawes](https://versprite.com/blog/security-research/vulnerable-named-pipe-application/)
		* **Privileged File Operation Abuse**<a name="pepfoa"></a>
			* James Forshaw's work
			* **Articles/Blogposts/Writeups**
				* [ Windows 10^H^H Symbolic Link Mitigations - James Forshaw(2015)](https://googleprojectzero.blogspot.com/2015/08/windows-10hh-symbolic-link-mitigations.html)
				* [ Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read - James Forshaw(2017)](https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html)
				* [ Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege - James Forshaw(2018)](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html)
				* [An introduction to privileged file operation abuse on Windows - @Claviollotte](https://offsec.provadys.com/intro-to-file-operation-abuse-on-Windows.html)
					* TL;DR This is a (bit long) introduction on how to abuse file operations performed by privileged processes on Windows for local privilege escalation (user to admin/system), and a presentation of available techniques, tools and procedures to exploit these types of bugs.
				* [CVE-2018-0952: Privilege Escalation Vulnerability in Windows Standard Collector Service - Ryan Hanson(2018)](https://www.atredis.com/blog/cve-2018-0952-privilege-escalation-vulnerability-in-windows-standard-collector-service)
				* [Escalating Privileges with CylancePROTECT - Ryan Hanson(2018)](https://www.atredis.com/blog/cylance-privilege-escalation-vulnerability)
				* [CVE-2020–1088 — Yet another arbitrary delete EoP - Søren Fritzbøger(2020)](https://medium.com/csis-techblog/cve-2020-1088-yet-another-arbitrary-delete-eop-a00b97d8c3e2)
				* [From directory deletion to SYSTEM shell - Jonas L(2020)](https://secret.club/2020/04/23/directory-deletion-shell.html)
					* "Vulnerabilities that enable an unprivileged profile to make a service (that is running in the SYSTEM security context) delete an arbitrary directory/file are not a rare occurrence. These vulnerabilities are mostly ignored by security researchers on the hunt as there is no established path to escalation of privilege using such a primitive technique. By chance I have found such a path using an unlikely quirk in the Windows Error Reporting Service. The technical details are neither brilliant nor novel, though a writeup has been requested by several Twitter users."
					* [Code](https://github.com/thesecretclub/ArbitraryDirectoryDeletion/blob/master/wer.h)
				* [Weaponizing Privileged File Writes with the USO Service - Part 1/2 - itm4n(2019)](https://itm4n.github.io/usodllloader-part1/)
					* [Part 2](https://itm4n.github.io/usodllloader-part2/)
				* [DACL Permissions Overwrite Privilege Escalation (CVE-2019-0841) - Nabeel Ahmed(2019)](https://krbtgt.pw/dacl-permissions-overwrite-privilege-escalation-cve-2019-0841/)
					* This vulnerability allows low privileged users to hijack file that are owned by NT AUTHORITY\SYSTEM by overwriting permissions on the targeted file. Successful exploitation results in "Full Control" permissions for the low privileged user. 
				* [CVE-2020-1170 - Microsoft Windows Defender Elevation of Privilege Vulnerability - itm4n(2020)](https://itm4n.github.io/cve-2020-1170-windows-defender-eop/)
					* "Here is my writeup about CVE-2020-1170, an elevation of privilege bug in Windows Defender."
			* **Talks/Presentations/Videos**
				* [Abusing privileged file operations - Clément Lavoillotte(Troopers19)](https://www.youtube.com/watch?v=xQKtdMO5FuE)
					* [Slides](https://troopers.de/downloads/troopers19/TROOPERS19_AD_Abusing_privileged_file_operations.pdf)
			* **Tools**
				* [UsoDllLoader](https://github.com/itm4n/UsoDllLoader)
					* This PoC shows a technique that can be used to weaponize privileged file write vulnerabilities on Windows. It provides an alternative to the DiagHub DLL loading "exploit" found by James Forshaw (a.k.a. @tiraniddo), which was fixed by Microsoft starting from build version 1903.
		* **NTLM-related**<a name="pentlm"></a>
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
				* **Articles/Blogposts/Writeups**
					* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes) - byt3bl33d3r](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
					* [NTLM Relay - Pixis](https://en.hackndo.com/ntlm-relay/)
					* [Playing with Relayed Credentials - @agsolino(2018)](https://www.secureauth.com/blog/playing-relayed-credentials)
					* [Server Message Block: SMB Relay Attack (Attack That Always Works) - CQURE Academy](https://cqureacademy.com/blog/penetration-testing/smb-relay-attack)
					* [An SMB Relay Race – How To Exploit LLMNR and SMB Message Signing for Fun and Profit - Jordan Drysdale](https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/)
					* [Effective NTLM / SMB Relaying - mubix](https://malicious.link/post/2014/effective-ntlm-smb-relaying/)
					* [SMB Relay with Snarf - Jeff Dimmock](https://bluescreenofjeff.com/2016-02-19-smb-relay-with-snarfjs-making-the-most-of-your-mitm/)
					* [Responder with NTLM relay and Empire - chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/execution/responder-with-ntlm-relay-and-empire.html)
					* [What is old is new again: The Relay Attack - @0xdeaddood, @agsolino(2020)](https://www.secureauth.com/blog/what-old-new-again-relay-attack)
						* The purpose of this blog post is to present a new approach to ntlmrelayx.py allowing multi-relay attacks, that means, using just a single connection to attack several targets. On top of this, we added the capability of relaying connections for specific target users.
					* [Capturing and Relaying NTLM Authentication: Methods and Techniques - Acebond(2020)](https://shellz.club/capturing-and-relaying-ntlm-authentication-methods-and-techniques/)
				* **Mitigation**
					* Enforce SMB Signing.
					* [How to enable SMB signing in Windows NT - support.ms](https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt)
					* [All You Need To Know About Windows SMB Signing - Lavanya Rathnam(2018)](http://techgenix.com/windows-smb-signing/)
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
		* **Privilege Abuse**<a name="pepa"></a>
			* [Priv2Admin](https://github.com/gtworek/Priv2Admin)
				* Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS. 
		* **Privileged File Operations**<a name="pepfo"></a>
			* **101**
				* [An introduction to privileged file operation abuse on Windows - @clavoillotte(2019)](https://offsec.almond.consulting/intro-to-file-operation-abuse-on-Windows.html)
					* TL;DR This is a (bit long) introduction on how to abuse file operations performed by privileged processes on Windows for local privilege escalation (user to admin/system), and a presentation of available techniques, tools and procedures to exploit these types of bugs.
			* **Articles/Blogposts/Writeups**
				* [CVE-2020–1088 — Yet another arbitrary delete EoP - Søren Fritzbøger(2020)](https://medium.com/csis-techblog/cve-2020-1088-yet-another-arbitrary-delete-eop-a00b97d8c3e2)
		* **Registry Paths/Permissions**<a name="perpp"></a>
			* [Insecure Registry Permissions - NetbiosX](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
			* [RegSLScan](https://github.com/Dankirk/RegSLScan)
				* This tool scans registery keys under Local Machine (HKLM) and lists out any keys non-admins have access to create symbolic links in.
		* **Services**<a name="peservices"></a>
			* **Articles/Blogposts/Writeups**				
				* [The power of backup operators - decoder.cloud](https://decoder.cloud/2018/02/12/the-power-of-backup-operatos/)
					* [Associated Code](https://github.com/decoder-it/BadBackupOperator)
				* [Unquoted Service Path - NetbiosX](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
				* [Give Me Back My Privileges! Please? - itm4n(2019)](https://itm4n.github.io/localservice-privileges/)
			* **Tools**
				* [FullPowers](https://github.com/itm4n/FullPowers)
					* FullPowers is a Proof-of-Concept tool I made for automatically recovering the default privilege set of a service account including SeAssignPrimaryToken and SeImpersonate.
		* **Unquoted Service Paths**<a name="peusp"></a>
			* **Articles/Blogposts/Writeups**
			* **Tools**
		* **Stored Creds/Passwords on Disk**<a name="pescp"></a>
			* [Stored Credentials - NetbiosX](https://pentestlab.blog/2017/04/19/stored-credentials/)
		* **Tokens**<a name="petokens"></a>
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
				* **General**
					* [WindowsPotatoes](https://github.com/d4rckh/WindowsPotatoes)
					* [Potatoes and tokens - decoder.cloud(2018)](https://decoder.cloud/2018/01/13/potato-and-tokens/)
					* [Potato privilege escalation exploits for Windows - @ivanlu986(2019)](https://ivanitlearning.wordpress.com/2019/07/20/potato-privilege-escalation-exploits-for-windows/)				
					* [Potatoes - Windows Privilege Escalation - Jorge Lajara(2020)](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
						* "Hot, Rotten, Lonely, Juicy, Rogue potatoes. There are a lot of different potatoes used to escalate privileges from Windows Service Accounts to NT AUTHORITY/SYSTEM. But, what are the differences? When should I use each one? Do they still work? This post is a summary of each kind of potato, when to use it and how to achieve successful exploitation."
				* **Hot Potato**
					* [Hot Potato – Windows Privilege Escalation - @breenmachine(2016)](https://foxglovesecurity.com/2016/01/16/hot-potato/)
						* Hot Potato (aka: Potato) takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.
				* **Rotten**
					* **Articles/Talks/Writeups**
						* [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM - @breenmachine(2016](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
						* [Rotten Potato Privilege Escalation from Service Accounts to SYSTEM - Stephen Breen Chris Mallz - Derbycon6](https://www.youtube.com/watch?v=8Wjs__mWOKI)
						* [The lonely potato - decoder.cloud(2017)](https://decoder.cloud/2017/12/23/the-lonely-potato/)
						* [No more rotten/juicy potato? - decoder.cloud(2018)](https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/)
							* Rotten potato inadvertently patched on Win10 1809
					* **Tools**
						* [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)
							* New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.
				* **Juicy Potato**
					* [Juicy Potato (abusing the golden privileges) - Andrea Pierini, Giuseppe Trotta(2018)](https://decoder.cloud/2018/08/10/juicy-potato/)
						* [Github)](https://github.com/decoder-it/juicy-potato)
					* [Juicy Potato - hunter2](https://hunter2.gitbook.io/darthsidious/privilege-escalation/juicy-potato)
					* [JuicyPotato(Reference for testing) - Carlos Polop](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato)
					* [SweetPotato – Service to SYSTEM - Ceri Coburn(2020)](https://www.pentestpartners.com/security-blog/sweetpotato-service-to-system/)
						* [Code](https://github.com/CCob/SweetPotato)
					* [Candy Potato (Caramelized Juicy Potato)](https://github.com/klezVirus/CandyPotato)
						* This tool has been made on top of the original JuicyPotato, with the main focus on improving/adding some functionalities which was lacking. It is known to work against both Windows Workstation and Server versions up to 8.1 and Server 2016, respectively.
					* [The Power of SeImpersonation - Micah Van Duesen(2021)](https://micahvandeusen.com/the-power-of-seimpersonation/)
						* [GenericPotato](https://github.com/micahvandeusen/GenericPotato)
				* **Rogue Potato**
					* [No more JuicyPotato? Old story, welcome RoguePotato! - @decoder_it(2020)](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
					* [RoguePotato on Remote - 0xdf(2020)](https://0xdf.gitlab.io/2020/09/08/roguepotato-on-remote.html)
				* **Remote Potato**
					* [Relaying Potatoes: Another Unexpected Privilege Escalation Vulnerability in Windows RPC Protocol - Antonio Cocomazzi, Andrea Pierini(2021)](https://labs.sentinelone.com/relaying-potatoes-dce-rpc-ntlm-relay-eop/)
					* [RemotePotato0](https://github.com/antonioCoco/RemotePotato0)
						* "It abuses the DCOM activation service and trigger an NTLM authentication of any user currently logged on in the target machine. It is required that a privileged user is logged on the same machine (e.g. a Domain Admin user). Once the NTLM type1 is triggered we setup a cross protocol relay server that receive the privileged type1 message and relay it to a third resource by unpacking the RPC protocol and packing the authentication over HTTP. On the receiving end you can setup a further relay node (eg. ntlmrelayx) or relay directly to a privileged resource."
		* **PentestLab Windows PrivEsc Writeup List**
			* [Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)
			* [Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
			* [Intel SYSRET](https://pentestlab.blog/2017/06/14/intel-sysret/)
			* [Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/)
		**Obtaining System Privileges**<a name="peosp"></a>
			* [The “SYSTEM” challenge](https://decoder.cloud/2017/02/21/the-system-challenge/)
			* Writeup of achieving system from limited user privs.
			* [All roads lead to SYSTEM]`https://labs.mwrinfosecurity.com/system/assets/760/original/Windows_Services_-_All_roads_lead_to_SYSTEM.pdf`
			* [Alternative methods of becoming SYSTEM - Adam Chester(2017)](https://blog.xpnsec.com/becoming-system/)
			* [admin to SYSTEM win7 with remote.exe - carnal0wnage](http://carnal0wnage.attackresearch.com/2013/07/admin-to-system-win7-with-remoteexe.html)
			* [Getting a CMD prompt as SYSTEM in Windows Vista and Windows Server 2008 - blogs.technet](https://blogs.technet.microsoft.com/askds/2008/10/22/getting-a-cmd-prompt-as-system-in-windows-vista-and-windows-server-2008/)
			* [Another way to get to a system shell – Assistive Technology -oddvar.moe](https://oddvar.moe/2018/07/23/another-way-to-get-to-a-system-shell/)
				* `Manipulate HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\magnifier` – StartExe to run other binary when pressing WinKey and plus to zoom.
    			* `Can load binary from Webdav and also start webbrowser and browse to desired link`
    			* `Runs command as system during UAC prompt and logon screen`
	* **Talks/Videos**<a name="petalks"></a>
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
	* **Tools**<a name="petools"></a>
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
	* **Writeups**<a name="pewriteup"></a>
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
			* [DisplayLink USB Graphics Software arbitrary file write Elevation of Privilege - Yannick Méheut(2020)](https://offsec.almond.consulting/displaylink-usb-graphics-arbitrary-file-write-eop.html)
	* **Exploits**<a name="peexploits"></a>
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
		* [[CVE49] Microsoft Windows LNK Remote Code Execution Vulnerability - CVE-2020-1299 - linhlhq from Infiniti Team - VinCSS](https://movaxbx.ru/2020/06/26/microsoft-windows-lnk-remote-code-execution-vulnerability-cve-2020-1299/)
	* **Just-Enough-Administration(JEA)**<a name="pejea"></a>
		* [Get $pwnd: Attacking Battle Hardened Windows Server - Lee Holmes - Defcon25](https://www.youtube.com/watch?v=ahxMOAAani8)
        	* Windows Server has introduced major advances in remote management hardening in recent years through PowerShell Just Enough Administration ("JEA"). When set up correctly, hardened JEA endpoints can provide a formidable barrier for attackers: whitelisted commands, with no administrative access to the underlying operating system. In this presentation, watch as we show how to systematically destroy these hardened endpoints by exploiting insecure coding practices and administrative complexity. 
	* **Microsoft**<a name="pems"></a>
		* [From Hyper-V Admin to SYSTEM - decoder.cloud](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/)
		* [Windows Credential Theft: RDP & Internet Explorer 11](https://vdalabs.com/2019/09/25/windows-credential-theft-rdp-internet-explorer-11/)
			* NTLM Hashes/relay through RDP files/IE11 XXE explained
    * **MSSQL**<a name="pemssql"></a>
		* [PowerUpSQL - 2018 Blackhat USA Arsenal](https://www.youtube.com/watch?reload=9&v=UX_tBJQtqW0&feature=youtu.be)
        	* This is the presentation we provided at the 2018 Blackhat USA Arsenal to introduce PowerUpSQL. PowerUpSQL includes functions that support SQL Server discovery, weak configuration auditing, privilege escalation on scale, and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server. This should be interesting to red, blue, and purple teams interested in automating day to day tasks involving SQL Server.
	* **VirtualMachines**<a name="pevm"></a>
		* [InviZzzible](https://github.com/CheckPointSW/InviZzzible)
			* InviZzzible is a tool for assessment of your virtual environments in an easy and reliable way. It contains the most recent and up to date detection and evasion techniques as well as fixes for them. Also, you can add and expand existing techniques yourself even without modifying the source code.
	* **VMWare**<a name="pevmw"></a>
		* [VMware Escape Exploit](https://github.com/unamer/vmware_escape)
			* VMware Escape Exploit before VMware WorkStation 12.5.5	
		* [A bunch of Red Pills: VMware Escapes - Marco Grassi, Azureyang, Jackyxty](https://keenlab.tencent.com/en/2018/04/23/A-bunch-of-Red-Pills-VMware-Escapes/)
		* [VMware Exploitation](https://github.com/xairy/vmware-exploitation)
			* A bunch of links related to VMware escape exploits
* **Defense Evasion**<a name="windefev"></a>
	* **101**
		* String Replacement & Obfuscation
		* Runtime modification(Polymorphism)
		* Sandbox detection & Avoidance
		* Log Avoidance & Deletion
	* **Articles/Blogposts/Writeups**
		* [Quiet in the Windows: Dropping Network Connections - Eviatar Gerzi](https://medium.com/@eviatargerzi/quiet-in-the-windows-dropping-network-connections-a5181b874116)
			* [DropNet](https://github.com/g3rzi/DropNet)
				* A tool that can be used to close network connections automatically with a given parameters
		* [Evade the analyst - Forensics|Exchange(2019)](https://www.forensixchange.com/posts/19-03-31_evade-the-analyst/)
	* **Talks/Presentations/Videos**
		* [Noob 101: Practical Techniques for AV Bypass - Jared Hoffman - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/103-noob-101-practical-techniques-for-av-bypass-jared-hoffman)
			* The shortcomings of anti-virus (AV) solutions have been well known for some time. Nevertheless, both public and private organizations continue to rely on AV software as a critical component of their information security programs, acting as a key protection mechanism over endpoints and other information systems within their networks. As a result, the security posture of these organizations is significantly jeopardized by relying only on this weakened control.
		* [Evading Autoruns - Kyle Hanslovan, Chris Bisnett(DerbyCon7)](https://www.youtube.com/watch?v=AEmuhCwFL5I&app=desktop)
			* When it comes to offense, maintaining access to your endpoints is key. For defenders, it's equally important to discover these footholds within your network. During this talk, Kyle and Chris expose several semi-public and private techniques used to evade the most common persistence enumeration tools. Their techniques will explore ways to re-invent the run key, unconventionally abuse search order, and exploit trusted applications. To complement their technical explanations, each bypass includes a live demo and recommendations for detection.
			* [RE: Evading Autoruns PoCs on Windows 10 - Kyle Hanslovan](https://medium.com/@KyleHanslovan/re-evading-autoruns-pocs-on-windows-10-dd810d7e8a3f)
			* [Evading Autoruns - DerbyCon 7.0](https://github.com/huntresslabs/evading-autoruns)
			* [Antivirus Evasion: Lessons Learned – thelightcosine(Derbycon2013)](https://www.irongeek.com/i.php?page=videos/derbycon3/3202-antivirus-evasion-lessons-learned-thelightcosine)
				* Over the past year, the speaker has spent alot of time talking with people in the infoSec Community and doing research on antivirus evasion techniques. Learning what works and what doesn't. There are a lot of good ideas floating around out there. In this talk we're going to pull those ideas all together. We'll discuss the basics of the AV evasion problem, what techniques work, which ones don't and why. The talk will have a particular focus on AV evasion as it relates to Metasploit payloads.
			* [Antivirus Evasion through Antigenic Variation (Why the Blacklisting Approach to AV is Broken) - Trenton Ivey, Neal Bridges(Derbycon2013)](https://www.irongeek.com/i.php?page=videos/derbycon3/4108-antivirus-evasion-through-antigenic-variation-why-the-blacklisting-approach-to-av-is-broken-trenton-iveyneal-bridges)
				* Description: Think of the last time you got sick. Your immune system is an amazing piece of machinery, but every now and then, something gets past it. Antivirus evasion techniques can become more effective when modeled after infectious diseases. This talk highlights many of the antivirus evasion techniques in use today. Going further, this talk shows how genetic algorithms can quickly and repeatedly “evolve” code to evade many malicious code detection techniques in use today.
			* [Bypassing Antivirus: With Understanding Comes Ease - Jeff McJunkin(WWHF Deadwood2020)](https://www.youtube.com/watch?v=UO3PjJIiBIE)
				* The job of a penetration tester is to emulate real-world, realistic adversaries to compromise the client and explain the business risks of the technical findings. Those pesky real-world adversaries bypass AV all the time, even with essentially the same malware, over and over.  How do they do it? Simple. By understanding what traps AV is setting, you can step around, jump over, or disable those traps before sauntering to your destination unhindered. I can't help with your saunter, but I can help you understand and bypass AV using arbitrary payloads (whether Cobalt Strike, Metasploit, Covenant, Mystic, SILENTTRINITY, or whichever) in many ways, all in less than an hour.
			* [The Art of bypassing endpoint protections for red teaming engagements - Eslam Reda, Jameel Nabbo(2020)](https://youtu.be/2X7zktVqBaY)
				* [Slides](https://bufferoverflows.net/wp-content/uploads/2020/08/BSides-Munich-2020-presentation.pptx)
				* [Blogpost](https://web.archive.org/web/20201029012004/https://bufferoverflows.net/the-art-of-bypassing-endpoint-protections-for-red-teaming-engagements/)
			* [Evading Detection A Beginner's Guide to Obfuscation - BC-Security(2021)](https://www.youtube.com/watch?v=lP2KF7_Kwxk)
				* Have you wanted to learn some more advanced Windows evasion techniques? Here is your chance to learn from the experts. This 2-hour long webinar will cover the basics of Windows Defenses such as Event and Script Block Logging, Anti-Malware Scan Interface (AMSI), and Windows Defender. Next, we will demonstrate obfuscations and evasion techniques that Advanced Persistent Threats (APTs) employ to evade modern defenses.
	* **AMSI**<a name="amsi"></a>
		* **101**
			* Remember kids, it's not a security boundary according to MS. Just like UAC, and AppLocker. Just something they threw in there for funsies. Totally not about security. Nope. No way. Nuh uh. Never in a _million years_. (Just a little salty after reading some _official_ documentation saying so)
			* [Antimalware Scan Interface (AMSI) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
			* [Developer audience, and sample code - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/dev-audience)
			* [Antimalware Scan Interface (AMSI) functions - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-functions)
			* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - Nikhil Mittal(BHUS16)](https://www.youtube.com/watch?v=7A_rgu3kbvw)
				* [Blogpost](http://www.labofapenetrationtester.com/2016/09/amsi.html)
				* [Paper](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
				* In Windows 10, Microsoft introduced the AntiMalware Scan Interface (AMSI) which is designed to target script-based attacks and malware. Script-based attacks have been lethal for enterprise security and with advent of PowerShell, such attacks have become increasingly common. AMSI targets malicious scripts written in PowerShell, VBScript, JScript etc. and drastically improves detection and blocking rate of malicious scripts. When a piece of code is submitted for execution to the scripting host, AMSI steps in and the code is scanned for malicious content. What makes AMSI effective is, no matter how obfuscated the code is, it needs to be presented to the script host in clear text and unobfuscated. Moreover, since the code is submitted to AMSI just before execution, it doesn't matter if the code came from disk, memory or was entered interactively. AMSI is an open interface and MS says any application will be able to call its APIs. Currently, Windows Defender uses it on Windows 10. Has Microsoft finally killed script-based attacks? What are the ways out? The talk will be full of live demonstrations.
			* [Announcing the .NET Framework 4.8 - devblogs.ms](https://devblogs.microsoft.com/dotnet/announcing-the-net-framework-4-8/)
			* [whoamsi](https://github.com/subat0mik/whoamsi)
				* The purpose of this page is to be a repository of endpoint protection (AV, EDR, etc) that uses Microsoft's Antimalware Scan Interface (AMSI). This will provide some context around endpoint protection and possible attack vectors. Products with information missing have not been verified yet. This project expands on the work done by @Lee_Holmes and @PyroTek3 by keeping a publicly available list up-to-date.
		* **AMSI Internals**
			* [The Rise and Fall of AMSI - Tal Liberman(BHAsia 2018)](https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf)
			* [IAmsiStream interface sample - MS Github](https://github.com/Microsoft/Windows-classic-samples/tree/master/Samples/AmsiStream)
				* Demonstrates how to use the Antimalware Scan Interface to scan a stream.
			* [Antimalware Scan Interface (AMSI) functions - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-functions)
			* [AMSI Bypass - Paul Laine(2019)](https://www.contextis.com/en/blog/amsi-bypass)
				* This blog post explains the inner workings of AMSI, and describes a new bypass technique.(related to AmsiScanBuffer)
			* [AMSI Module Remote In-Memory Patch - Paul Laine(2020)](https://ntamonsec.blogspot.com/2020/05/amsi-module-remote-in-memory-patch.html)
			* [MS Office file format sorcery - Stan Hegt, Pieter Ceelen(Troopers19)](https://www.youtube.com/watch?v=iXvvQ5XML7g)
				* [Slides](https://github.com/outflanknl/Presentations/raw/master/Troopers19_MS_Office_file_format_sorcery.pdf)
				* A deep dive into file formats used in MS Office and how we can leverage these for offensive purposes. We will show how to fully weaponize ‘p-code’ across all MS Office versions in order to create malicious documents without using VBA code, successfully bypassing antivirus and other defensive measures. In this talk Stan and Pieter will do a deep dive into the file formats used in MS Office, demonstrating many features that can be used offensively. They will present attacks that apply to both the legacy formats (OLE streams) and the newer XML based documents. Specific focus is around the internal representation of VBA macros and pseudo code (p-code, execodes) and how these can be weaponized. We will detail the inner logic of Word and Excel regarding VBA and p-code, and release scripts and tools for creating malicious Office documents that bypass anti-virus, YARA rules, AMSI for VBA and various MS Office document analyzers.
		* **Bypasses**
			* **Compilations**
				* [Amsi-Bypass-PowerShell - S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
					* List of Bypasses
				* [Antimalware Scan Interface (AMSI) — A Red Team Analysis on Evasion - iwantmore.pizza](https://iwantmore.pizza/posts/amsi.html)
				* [Exploring PowerShell AMSI and Logging Evasion - Adam Chester(2018)](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
				* [Adventures in the Wonderful World of AMSI. - byte_st0rm(2019)](https://medium.com/@byte_St0rm/adventures-in-the-wonderful-world-of-amsi-25d235eb749c)
					* Overview + Rather then use “LoadLibrary” and “GetProcAddress” to locate the memory addresses of “amsi.dll” and “amsiScanBuffer”, walk the “PEB” of the process and the export directory of “amsi.dll”.
				* [How Red Teams Bypass AMSI and WLDP for .NET Dynamic Code - modexp(2019)](https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/)
				* [AMSI - Resurrecting the Dead - Crawl3r(2020)](https://crawl3r.github.io/2020-05-22/AMSI_Resurrecting_the_dead)
					* [FunWithAMSI](https://github.com/crawl3r/FunWithAMSI)
				* [AMSI Bypass Methods - pentestlaboratories.com(2021)](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)
			* **General Stuff**
				* [How to bypass AMSI and execute ANY malicious Powershell code - zc00l](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
				* [Weaponizing AMSI bypass with PowerShell - @0xB455(2019)](http://ha.cker.info/weaponizing-amsi-bypass-with-powershell/)
				* [AMSI.fail](https://github.com/Flangvik/AMSI.fail)
					* C# Azure Function with an HTTP trigger that generates obfuscated PowerShell snippets that break or disable AMSI for the current process. The snippets are randomly selected from a small pool of techniques/variations before being obfuscated. Every snippet is obfuscated at runtime/request so that no generated output share the same signatures.
				* [AMSI.fail4](https://github.com/shutingrz/AMSI.fail4)
					* Converted AMSI.fail to a .NET Framework 4 solution so that it can be called from PowerShell 5.
				* [Bypassing AV (Windows Defender) … the tedious way. - CB Hue(2019)](https://www.cyberguider.com/bypassing-windows-defender-the-tedious-way/)
				* [AMSI Bypass Using Memory Patching - Andres Roldan(2021)](https://fluidattacks.com/blog/amsi-bypass/)
				* [Microsoft Windows Antimalware Scan Interface Bypasses - Thalpius(2021)](https://thalpius.com/2021/10/14/microsoft-windows-antimalware-scan-interface-bypasses/)
			* **Use PSv2**
			* **Obfuscation**
				* [Red Team TTPs Part 1: AMSI Evasion - paranoidninja(2019)](https://0xdarkvortex.dev/index.php/2019/07/17/red-team-ttps-part-1-amsi-evasion/)
				* [Bypass AMSI by manual modification - s3cur3th1ssh1t(2020)](https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/)
				* [Bypass AMSI by manual modification part II - Invoke-Mimikatz - s3cur3th1ssh1t(2020)](https://s3cur3th1ssh1t.github.io/Bypass-AMSI-by-manual-modification-part-II/)
			* **DLL Hijack**
				* [Bypassing Amsi using PowerShell 5 DLL Hijacking - cn33liz(2016)](https://cn33liz.blogspot.com/2016/05/bypassing-amsi-using-powershell-5-dll.html)
				* [Disabling AMSI in JScript with One Simple Trick - James Forshaw(2018)](https://www.tiraniddo.dev/2018/06/disabling-amsi-in-jscript-with-one.html)
				* [Resurrecting an old AMSI Bypass - Philippe Vogler(2020)](https://sensepost.com/blog/2020/resurrecting-an-old-amsi-bypass/)
					* Before the latest Windows Defender update, and possibly with other endpoint security products, regardless of access rights on a host, users can bypass AMSI for PowerShell. Other scripting engines such as jscript or cscript do not suffer from this DLL hijack and directly load AMSI from the System32 folder.
			* **COM Server Hijack**
				* [Bypassing AMSI via COM Server Hijacking - Enigma0x3](https://enigma0x3.net/2017/07/19/bypassing-amsi-via-com-server-hijacking/)
					*  This post will highlight a way to bypass AMSI by hijacking the AMSI COM server, analyze how Microsoft fixed it in build #16232 and then how to bypass that fix. This issue was reported to Microsoft on May 3rd, and has been fixed as a Defense in Depth patch in build #16232.
			* **Null Character**
				* [AMSI Bypass With a Null Character - Satoshi Tanda(2018)](https://standa-note.blogspot.com/2018/02/amsi-bypass-with-null-character.html)
			* **Registry Key**
				* [The Rise and Fall of AMSI - Tal Liberman(BH Asia18)]https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf)
			* **Patching AmsiScanString**
				* [AMSI Bypass: Patching Technique - Avi Gimpel & Zeev Ben Porat(2018)](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/)
			* **Patching AmsiScanBuffer**
				* RastaMouse AmsiScanBuffer Bypass Series(2018)
					* [Part 1](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/)
					* [Part 2](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-2/)
					* [Part 3](https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/)
					* [Part 4](https://rastamouse.me/2018/12/amsiscanbuffer-bypass-part-4/)
				* [How to bypass AMSI and execute ANY malicious Powershell code - zc00l(2018)](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
				* [AMSI Bypass Redux - Avi Gimpel(2018)](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/)
				* [Alternative AMSI bypass - Benoit Sevens(2018)](https://medium.com/@benoit.sevens/alternative-amsi-bypass-554dc61d70b1)
				* [Yet another update to bypass AMSI in VBA - Khris Tolbert(2019)](https://medium.com/maverislabs/yet-another-update-to-bypass-amsi-in-vba-19ddf9065c04)
				* [Hunting for AMSI bypasses - Wee-Jing Chung(2019)](https://blog.f-secure.com/hunting-for-amsi-bypasses/)
				* [Execute any "evil" Powershell code by bypassing AMSI - Dec0ne(2019)](https://dec0ne.github.io/research/2019-11-08-Amsi-bypass-post/)
				* [AMSI Bypass - Paul Laine(2019)](https://www.contextis.com/en/blog/amsi-bypass)
					* This blog post explains the inner workings of AMSI, and describes a new bypass technique.(related to AmsiScanBuffer)
				* [Understanding and Bypassing AMSI - Tom Carver(2020)](https://x64sec.sh/understanding-and-bypassing-amsi/)
					* [AmsiHook](https://github.com/tomcarver16/AmsiHook)
						* AmsiHook is a DLL that when injected to a process containing AMSI logging, will hook the AMSI functions and allow them to execute with dummy parameters.
				* [Using Reflection for AMSI Bypass - ](https://www.redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass)
				* [Defense Evasion Series Part 1 AMSI Bypass - Dazzy Ddos(2021)](https://dazzyddos.github.io/posts/AMSI-Bypass/)
				* [Memory Patching AMSI Bypass - Rasta Mouse(2021)](https://rastamouse.me/memory-patching-amsi-bypass/)
				* **Tools**
					* [AmsiScanBufferBypass](https://github.com/rasta-mouse/AmsiScanBufferBypass)
						* Circumvent AMSI by patching AmsiScanBuffer
			* **AmsiInitialize**
				* [Patchless AMSI bypass using SharpBlock - Ceri Coburn(2020)](https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock/)
				* [SharpBlock](https://github.com/CCob/SharpBlock)
					 * A method of bypassing EDR's active projection DLL's by preventing entry point execution.
			* **Forcing an Error**
			* **Manually set the `amsiInitFailed` field to `$true`**
				* [First(Public) Example by Matt Graeber(2016)](https://twitter.com/mattifestation/status/735261120487772160)
				* [Exploring PowerShell AMSI and Logging Evasion - Adam Chester(2018)](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
			* **Jscript9.dll**
				* [Sneaking Past Device Guard - Philip Tsukerman](https://conference.hitb.org/hitbsecconf2019ams/materials/D2T1%20-%20Sneaking%20Past%20Device%20Guard%20-%20Philip%20Tsukerman.pdf)
			* **Heap-based**
				* [How Red Teams Bypass AMSI and WLDP for .NET Dynamic Code - modexp(2019)](https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/)
				* [Heap-based AMSI bypass for MS Excel VBA and others  - Dan@CodeWhite(2019)](https://codewhitesec.blogspot.com/2019/07/heap-based-amsi-bypass-in-vba.html)
					* This blog post describes how to bypass Microsoft's AMSI (Antimalware Scan Interface) in Excel using VBA (Visual Basic for Applications). In contrast to other bypasses this approach does not use hardcoded offsets or opcodes but identifies crucial data on the heap and modifies it. The idea of an heap-based bypass has been mentioned by other researchers before but at the time of writing this article no public PoC was available. This blog post will provide the reader with some insights into the AMSI implementation and a generic way to bypass it.
				* [CorruptCLRGlobal.ps1 - Matt Graeber](https://offensivedefence.co.uk/posts/making-amsi-jump/)
					* A PoC function to corrupt the g_amsiContext global variable in clr.dll in .NET Framework Early Access build 3694 
				* [AMSI in the HEAP x32 - secureyourit.co.uk(2020)](https://secureyourit.co.uk/wp/2020/04/17/amsi-in-the-heap/)
			* **...**
				* [How to Bypass AMSI with an Unconventional Powershell Cradle - Mohammed Danish(2019)](https://medium.com/@gamer.skullie/bypassing-amsi-with-an-unconventional-powershell-cradle-6bd15a17d8b9)
			* **Hooking**
				* [Goodbye Obfuscation, Hello Invisi-Shell: Hiding Your Powershell Script in Plain Sight - Omer Yair(Derbycon2018)](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-15-goodbye-obfuscation-hello-invisi-shell-hiding-your-powershell-script-in-plain-sight-omer-yair)
					* “The very concept of objective truth is fading out of the world. Lies will pass into history.” George Orwell. Objective truth is essential for security. Logs, notifications and saved data must reflect the actual events for security tools, forensic teams and IT managers to perform their job correctly. Powershell is a prime example of the constant cat and mouse game hackers and security personnel play every day to either reveal or hide the “objective truth” of a running script. Powershell’s auto logging, obfuscation techniques, AMSI and more are all participants of the same game playing by the same rules. We don’t like rules, so we broke them. As a result, Babel-Shellfish and Invisi-Shelltwo new tools that both expose and disguise powershell scripts were born. Babel-Shellfish reveals the inner hidden code of any obfuscated script while Invisi-Shell offers a new method of hiding malicious scripts, even from the Powershell process running it. Join us as we present a new way to think about scripts.
				* [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)
				* [Understanding and Bypassing AMSI - Tom Carver(2020)](https://x64sec.sh/understanding-and-bypassing-amsi/)
			* **Vectored-Exception Handling**
				* [veh_AmsiBypass.cpp](https://gist.github.com/aaaddress1/5536d27b4d7ec29e474551086a2f0b63)
		* **Bypass Talks**
			* [AMSI: How Windows 10 Plans To Stop Script Based Attacks And How Well It Does It - Nikhil Mittal(BHUSA16)](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
			* [Antimalware Scan Interface (AMSI) - Dave Kennedy(WWHF2018)](https://www.youtube.com/watch?v=wBK1fTg6xuU)
				* This talk will dive into the Antimalware Scan Interface (AMSI) as well as other alternatives in the “NextGen” series of preventative measures and show how trivial it is to write code that doesn’t get snagged.  The security market is focusing on open source data collection sources and security researchers as the main method to write signatures to detect attacks, much like what we saw in the 90s with traditional anti-virus tech. Not much has changed, let’s dive into the reality in security and how little these protective measures really do in the grand scheme of things. We’ll also be covering solid practices in defending against attacks, and what we should be focusing on.
			* [PSAmsi An offensive PowerShell module for interacting with the Anti Malware Scan Interface in Windows - Ryan Cobb(Derbycon7)](https://www.youtube.com/watch?v=rEFyalXfQWk)
			* [Red Team TTPs Part 1: AMSI Evasion - paranoidninja](https://0xdarkvortex.dev/index.php/2019/07/17/red-team-ttps-part-1-amsi-evasion/)
		* **Bypass Tools**
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
				* [Dynamic Microsoft Office 365 AMSI In Memory Bypass Using VBA - Richard Davy, Gary Nield(2019)](https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/)
				* [The Document that Eluded AppLocker and AMSI - ZLAB-YOROI](https://blog.yoroi.company/research/the-document-that-eluded-applocker-and-amsi/)
				* [Office 365 AMSI Bypass (fixed) - Iliya Dafchev(2019)](https://idafchev.github.io/research/2019/03/23/office365_amsi_bypass.html)
				* [Bypassing AMSI for VBA - Pieter Ceelen](https://outflank.nl/blog/2019/04/17/bypassing-amsi-for-vba/)
					* This blog is a writeup of the various AMSI weaknesses presented at [the Troopers talk ‘MS Office File Format Sorcery‘](https://github.com/outflanknl/Presentations/raw/master/Troopers19_MS_Office_file_format_sorcery.pdf) and [the Blackhat Asia presentation ‘Office in Wonderland’](https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Hegt-MS-Office-in-Wonderland.pdf).
				* [Adventures in the Wonderful World of AMSI. - byte_st0rm(2019)](https://medium.com/@byte_St0rm/adventures-in-the-wonderful-world-of-amsi-25d235eb749c)
					* Overview + Rather then use “LoadLibrary” and “GetProcAddress” to locate the memory addresses of “amsi.dll” and “amsiScanBuffer”, walk the “PEB” of the process and the export directory of “amsi.dll”.
				* [AMSI in the HEAP x32 - secureyourit.co.uk(2020)](https://secureyourit.co.uk/wp/2020/04/17/amsi-in-the-heap/)
		*  **Instrumenting AMSI**
			* **Articles/Blogposts/Writeups**
				* [AMSI as a Service — Automating AV Evasion - James(2019)](https://medium.com/@two06/amsi-as-a-service-automating-av-evasion-2e2f54397ff9)
				* [Hunting for malicious strings using AmsiTrigger - RythmStick(2020)](https://www.rythmstick.net/posts/amsitrigger/)
				* [Antimalware Scan Interface Detection Optics Analysis Methodology: Identification and Analysis of AMSI for WMI - Matt Graeber(2019)](https://posts.specterops.io/antimalware-scan-interface-detection-optics-analysis-methodology-858c37c38383)
			* [Using Windows Antimalware Scan Interface in .NET - Gérald Barré(2020)](https://www.meziantou.net/using-windows-antimalware-scan-interface-in-dotnet.htm)
			* **Tools**
				* [MalwareScan.AMSI](https://github.com/NewOrbit/MalwareScan.AMSI)
				* [AMSITrigger v3](https://github.com/RythmStick/AMSITrigger)
					* The Hunt for Malicious Strings
				* [SimpleAmsiProvider](https://github.com/pathtofile/SimpleAmsiProvider)
					* A simple provider to analyse what gets passed into Microsoft's Anti-Malware Scan Interface 
				* [AMSI Scanner](https://github.com/atxsinn3r/amsiscanner)
					* A C/C++ implementation of Microsoft's Antimalware Scan Interface 
				* [amsi-tracer](https://github.com/manyfacedllama/amsi-tracer)
					* Leverage AMSI (Antimalware Scan Interface) technology to aid your analysis. This tool saves all buffers (scripts, .NET assemblies, etc) passed into AMSI during dynamic execution. 
	* **Anti-Virus**<a name="winav"></a>
		* **General Articles/Blogposts/Writeups**
			* [Bypass Antivirus Dynamic Analysis: Limitations of the AV model and how to exploit them - Emeric Nasi(2014)](https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf)
			* [Evasion & Obfuscation Techniques - z3roTrust](https://medium.com/@z3roTrust/evasion-obfuscation-techniques-87c33429cee2)
			* [Learn how to hide your trojans, backdoors, etc from anti virus.](https://www.hellboundhackers.org/articles/read-article.php?article_id=842)
			* [How to Bypass Anti-Virus to Run Mimikatz](http://www.blackhillsinfosec.com/?p=5555)
			* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - labofapenetrationtester](http://www.labofapenetrationtester.com/2016/09/amsi.html)
			* [Art of Anti Detection 1 – Introduction to AV & Detection Techniques - Ege Balci](https://pentest.blog/art-of-anti-detection-1-introduction-to-av-detection-techniques/)
			* [Art of Anti Detection 2 – PE Backdoor Manufacturing - Ege Balci](https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/)
			* [Art of Anti Detection 3 – Shellcode Alchemy - Ege Balci](https://pentest.blog/art-of-anti-detection-3-shellcode-alchemy/)
			* [Art of Anti Detection 4 – Self-Defense - Ege Balci](https://pentest.blog/art-of-anti-detection-4-self-defense/)
			* [Breaking Antivirus Software - Joxean Koret, COSEINC(SYSCAN2014)](http://mincore.c9x.org/breaking_av_software.pdf)
			* [Antimalware-Research](https://github.com/NtRaiseHardError/Antimalware-Research)
				* Research on Anti-malware and other related security solutions
			* [Bypassing Signature-Based AV - RedSiege(2021)](https://www.redsiege.com/blog/2021/08/bypass-sig-av/)
		* **Talks/Presentations**
			* [Muts Bypassing AV in Vista/Pissing all over your AV](https://web.archive.org/web/20130514172102/http://www.shmoocon.org/2008/videos/Backtrack%20Demo.mp4)
				* presentation, listed here as it was a bitch finding a live copy
			* [Easy Ways To Bypass Anti-Virus Systems - Attila Marosi(Troopers14)](https://www.youtube.com/watch?v=Sl1Sru3OwJ4)
			* [Noob 101 Practical Techniques for AV Bypass Jared Hoffman(Anycon2017)](https://www.youtube.com/watch?v=AbmRKODAoAQ)
			* [Web attacks against AV software - Juho Nurminen(Disobey2018)](https://www.youtube.com/watch?v=GXNM0-smVcE&list=PLLvAhAn5sGfhnVt1IhgrqCvBGe6AxwsjQ&index=12)
			* [Subverting Sysmon: Application of a Formalized Security Product Evasion Methodology - Lee Christensen, Matt Graeber(BHUSA2018)](https://www.youtube.com/watch?v=R5IEyoFpZq0)
				* While security products are a great supplement to the defensive posture of an enterprise, to well-funded nation-state actors, they are an impediment to achieving their objectives. As pentesters argue the efficacy of a product because it doesn't detect their specific offensive technique, mature actors recognize a need to holistically subvert the product at every step during the course their operation.
				* [Whitepaper](https://github.com/mattifestation/BHUSA2018_Sysmon/blob/master/Whitepaper_Subverting_Sysmon.pdf)
				* [Slides](https://github.com/mattifestation/BHUSA2018_Sysmon/blob/master/Slides_Subverting_Sysmon.pdf)
				* [Code](https://github.com/mattifestation/BHUSA2018_Sysmon)			
			* [Bypassing Antivirus: With Understanding Comes Ease - Jeff McJunkin(WWHF Deadwood2020-Virtual)](https://www.youtube.com/watch?v=UO3PjJIiBIE)
				* [Slides](https://bit.ly/bypassingav)
		* **Papers**
			* [Understanding behavioural detection of antivirus - Liangyu Chai, R. Holloway, A. Lanzi(2016)](https://www.semanticscholar.org/paper/Understanding-behavioural-detection-of-antivirus-1-Chai-Holloway/8d9fed95412be6472c06f844029583862e4d4098)
				* In this project, we study the behavioural detection engines of the antivirus in both the 32-bit and 64-bit versions of Windows 7 by using specialised modules to identify the technologies that the antivirus are using to monitor application behaviours. Our analysis revealed that the 64-bit versions of the antivirus are generally weaker than their 32-bit versions. To determine the effectiveness of the antivirus behavioural detection engines, we propose replaying the actions of applications from sandbox logs to the antivirus and observing the reaction of the antivirus. Our experiments demonstrated that this approach can illustrate the capabilities of the antivirus behavioural detection engines and uncover the behavioural detection signatures of the antivirus at the same time.
			* [Bare Knuckled Antivirus Breaking - Balin Varga-Perke(2018)](https://blog.silentsignal.eu/2018/01/08/bare-knuckled-antivirus-breaking/)
				* [Paper](https://blog.silentsignal.eu/wp-content/uploads/2018/01/S2_BareKnuckledAVBreaking_180108.pdf)
			* [ERNW Whitepaper 71 – Analysis of Anti-Virus Software Quarantine Files(2021)](https://insinuator.net/2021/01/ernw-whitepaper-71-analysis-of-anti-virus-software-quarantine-files/)
			* [Python and Malware: Developing Stealth and Evasive Malware Without Obfuscation - Vasilios Koutsokostas, Constantinos Patsakis(2021)](https://arxiv.org/abs/2105.00565)
				* With the continuous rise of malicious campaigns and the exploitation of new attack vectors, it is necessary to assess the efficacy of the defensive mechanisms used to detect them. To this end, the contribution of our work is twofold. First, it introduces a new method for obfuscating malicious code to bypass all static checks of multi-engine scanners, such as VirusTotal. Interestingly, our approach to generating the malicious executables is not based on introducing a new packer but on the augmentation of the capabilities of an existing and widely used tool for packaging Python, PyInstaller but can be used for all similar packaging tools. As we prove, the problem is deeper and inherent in almost all antivirus engines and not PyInstaller specific. Second, our work exposes significant issues of well-known sandboxes that allow malware to evade their checks. As a result, we show that stealth and evasive malware can be efficiently developed, bypassing with ease state of the art malware detection tools without raising any alert.
			* [Cut-and-Mouse and Ghost Control: Exploiting Antivirus Software with Synthesized Inputs - Ziya Alper Genc, Gabriele Lenzini, Daniele Sgandurra(2021)](https://dl.acm.org/doi/pdf/10.1145/3431286)
		* **Exploiting AV Engines/Software**
			* [#AVGater: Getting Local Admin by Abusing the Anti-Virus Quarantine(2017)](https://bogner.sh/2017/11/avgater-getting-local-admin-by-abusing-the-anti-virus-quarantine/)
				* Abuse NTFS paths for privilege escalation from a DLL Hijack to modify the file restore process of the targeted AV.
			* [Hacking Antiviruses - Jaanus Kääp(Disobey 2017)](https://www.youtube.com/watch?v=YHbDB9CPz1w&list=PLLvAhAn5sGfj05ej8QG0DEl1WRgJYmXMs&index=3)
			* [SELF-DEFENSELESS - Balint Varga-Perke(SilentSignal2019)](https://raw.githubusercontent.com/v-p-b/kaspy_toolz/master/S2_EUSKALHACK_Self-defenseless.pdf)
			* [BitDefender Antivirus Free 2020 Elevation of Privilege (CVE-2020-8103) - Elias Dimopoulos(2020)](https://labs.redyops.com/index.php/2020/04/24/bitdefender-antivirus-free-escalation-of-privileges/)
			* [Exploiting Bitdefender Antivirus: RCE from any website - Wladimir Palant(2020)](https://palant.info/2020/06/22/exploiting-bitdefender-antivirus-rce-from-any-website/)
			* [Bitdefender: UPX Unpacking Featuring Ten Memory Corruptions - landave(2020)](https://landave.io/2020/11/bitdefender-upx-unpacking-featuring-ten-memory-corruptions/)
			* [Oh, so you have an antivirus… name every bug - halov(2020)](https://halove23.blogspot.com/2020/12/oh-so-you-have-antivirus-nameevery-bug.html)
		* **Code Runners**
			* [Execute ShellCode Using Python](http://www.debasish.in/2012/04/execute-shellcode-using-python.html)
				* In this article I am going to show you, how can we use python and its "ctypes" library to execute a "calc.exe" shell code or any other shell code.
			* [Bypassing AV's like its 2001 - Flangvik(2020)](https://flangvik.com/windows/lolbin/bypass/2020/05/03/bypassing-avs-like-its-2001.html)
			* [EXOCET-AV-Evasion](https://github.com/tanc7/EXOCET-AV-Evasion)
		* **Code Signing**
			* **101**
				* [Authenticode Digital Signatures - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
			* **Articles/Blogposts/Writeups**
				* [Authenticode and Antivirus Detection - Arkhem(2011)](http://memeover.arkem.org/2011/08/authenticode-and-antivirus-detection.html)
				* [Authenticode and Antivirus Detection part 2 - Arkhem(2011)](http://memeover.arkem.org/2011/08/authenticode-and-antivirus-detection_08.html)
				* [Authenticode and Antivirus Detection Revisited - Arkhem(2013)](http://memeover.arkem.org/2013/11/authenticode-and-antivirus-detection.html)
			* **Talks/Presentations/Videos**
				* [Code Signing Certificates - Barry Vengerik(Cyber Defense Summit 2019)](https://www.youtube.com/watch?v=J8WGJtCy0ek)
		* **History**
			* [VX-Underground](https://vx-underground.org/)
		* **Obfuscation**
			* [Cobalt Strike – Bypassing Windows Defender with Obfuscation - @taso_x](http://www.offensiveops.io/tools/cobalt-strike-bypassing-windows-defender-with-obfuscation/)
		* **Polymorphism**
			* See 'Polymorphism' under 'Specific Techniques'
		* **String Modification**
		* **Tools**
			* [WinPwnage](https://github.com/rootm0s/WinPwnage)
				* The goal of this repo is to study the Windows penetration techniques.
			* [Find-AVSignature.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1)














	* **Application Whitelisting**<a name="appwhitelist"></a>
		* **101**
			* [Whitelist Evasion revisited](https://khr0x40sh.wordpress.com/2015/05/27/whitelist-evasion-revisited/)
			* [Shackles, Shims, and Shivs - Understanding Bypass Techniques](http://www.irongeek.com/i.php?page=videos/derbycon6/535-shackles-shims-and-shivs-understanding-bypass-techniques-mirovengi)
			* [$@|sh – Or: Getting a shell environment from Runtime.exec](https://codewhitesec.blogspot.ro/2015/03/sh-or-getting-shell-environment-from.html)
		* **Articles/Blogposts/Writeups**
			* [Bypassing Application Whitelisting By Using dnx.exe - enigma0x3(2016)](https://sec-consult.com/en/blog/2017/04/application-whitelisting-application/)
			* [WSH Injection: A Case Study - enigma0x3(2017)](https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/)
			* [Abusing NVIDIA’s Node.js To Bypass Application Whitelisting - René Freingruber(2017)](https://sec-consult.com/blog/detail/application-whitelisting-application/)
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
				* [Blogpost](https://fortynorthsecurity.com/blog/how-to-bypass-wdac-with-dbgsrv-exe/)
		* **Talks**
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
				* [AppLocker architecture and components - docs.ms(2017](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-architecture-and-components)
				* [AppLocker - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
					* This topic provides a description of AppLocker and can help you decide if your organization can benefit from deploying AppLocker application control policies. AppLocker helps you control which apps and files users can run. These include executable files, scripts, Windows Installer files, dynamic-link libraries (DLLs), packaged apps, and packaged app installers.
				* [AppLocker architecture and components - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-architecture-and-components)
				* [Windows Applocker Policy – A Beginner’s Guide - AArti Singh(2019)](https://www.hackingarticles.in/windows-applocker-policy-a-beginners-guide/)
				* [Ultimate AppLocker ByPass List](https://github.com/api0cradle/UltimateAppLockerByPassList)
					* "The goal of this repository is to document the most common and known techniques to bypass AppLocker. Since AppLocker can be configured in different ways I maintain a verified list of bypasses (that works against the default AppLocker rules) and a list with possible bypass technique (depending on configuration) or claimed to be a bypass by someone. I also have a list of generic bypass techniques as well as a legacy list of methods to execute through DLLs."
				* [myAPPLockerBypassSummary](https://github.com/0xVIC/myAPPLockerBypassSummary)
					* Simple APPLocker bypass summary based on the extensive work of @api0cradle
			* **Articles/Blogposts/Writeups**
				* [AppLocker Bypass Checklist - netbiosX](https://github.com/netbiosX/Checklists/blob/master/AppLocker.md)
				* [AppLocker Case study: How insecure is it really? Part 1 oddvar.moe](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-1/)
				* AppLocker Case study: How insecure is it really? Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
				* [AppLocker Bypass – Weak Path Rules(2017](https://pentestlab.blog/2017/05/22/applocker-bypass-weak-path-rules/)
				* [Applocker Bypass via Registry Key Manipulation](https://www.contextis.com/resources/blog/applocker-bypass-registry-key-manipulation/)
				* [Bypassing AppLocker Custom Rules - 0x09AL Security Blog(2018)](https://0x09al.github.io/security/applocker/bypass/custom/rules/windows/2018/09/13/applocker-custom-rules-bypass.html)
				* [AppLocker Bypass – CMSTP - netbiosX(2018](https://pentestlab.blog/2018/05/10/applocker-bypass-cmstp/)
				* [Bypassing AppLocker Custom Rules(2018)](https://0x09al.github.io/security/applocker/bypass/custom/rules/windows/2018/09/13/applocker-custom-rules-bypass.html)
				* [Babushka Dolls or How To Bypass Application Whitelisting and Constrained Powershell - Morten Schenk(2018](https://improsec.com/tech-blog/babushka-dolls-or-how-to-bypass-application-whitelisting-and-constrained-powershell)
					* [Code](https://github.com/MortenSchenk/Babuska-Dolls)
				* [A small discovery about AppLocker - oddvar.moe(2019)](https://oddvar.moe/2019/05/29/a-small-discovery-about-applocker/)
					* 'While I was prepping for a session a while back I made a a little special discovery about AppLocker. Turns out that the files that AppLocker uses under C:\Windows\System32\AppLocker can be used in many cases to bypass a Default AppLocker ruleset.'
				* [Applocker Bypass via Registry Key Manipulation - Francesco Mifsud](https://www.contextis.com/en/blog/applocker-bypass-via-registry-key-manipulation)
				* [Applocker and PowerShell: how do they tightly work together? - Emin Atac(2019)](https://p0w3rsh3ll.wordpress.com/2019/03/07/applocker-and-powershell-how-do-they-tightly-work-together/)
				* [Bypassing AppLocker Custom Rules - 0x09AL](https://0x09al.github.io/security/applocker/bypass/custom/rules/windows/2018/09/13/applocker-custom-rules-bypass.html)
				* [myAPPLockerBypassSummary](https://github.com/0xVIC/myAPPLockerBypassSummary)
					* Simple APPLocker bypass summary based on the extensive work of @api0cradle
				* [Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies - sixdub(2014)](https://www.sixdub.net/?p=367)
				* [AppLocker Bypass – File Extensions - pentestlab.blog(2017)](https://pentestlab.blog/2017/06/12/applocker-bypass-file-extensions/)
					* Bypassing AppLocker restrictions usually requires the use of trusted Microsoft binaries that can execute code or weak path rules. However it is possible in a system that it has been configured with default rules and it is allowing the use of command prompt and PowerShell to the users to bypass AppLocker by using payloads with different file extensions.
				* [Bring your own .NET Core Garbage Collector - Paul Laine(2020)](https://www.contextis.com/en/blog/bring-your-own-.net-core-garbage-collector)
					* This blog post explains how it is possible to abuse a legitimate feature of .Net Core, and exploit a directory traversal bug to achieve application whitelisting bypass.
					* [Code](https://github.com/am0nsec/MCGC)
				* [Abusing .NET Core – Evasion - pentestlaboratories.com](https://pentestlaboratories.com/2020/06/23/abusing-net-core-application-whitelisting/)
				* [Bypassing Windows protection mechanisms & Playing with OffensiveNim - s3cur3th1ssh1t(2020)](https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/)
				* [Signed Binary Proxy Execution via PyCharm - ArchCloudLabs(2021)](https://www.archcloudlabs.com/projects/signed_binary_proxy_execution/)
			* **Talks/Presentations/Videos**
				* [GreatSCT: Gotta Catch 'Em AWL - Chris Spehn(CircleCityCon2018)](https://www.irongeek.com/i.php?page=videos/circlecitycon2018/global00-greatsct-gotta-catch-em-awl-chris-spehn)
					* Great Scott Marty, we went all the way back to 1995! The project is called Great SCT (Great Scott). GreatSCT is an open source project to generate application whitelist (AWL) bypasses. This tool is intended for BOTH red and blue team. Blue team can benefit by testing the publicly known application whitelisting bypass methods. We will review the most common application whitelisting bypass methods and how to utilize these methods with GreatSCT.
				* [Shackles, Shims, and Shivs - Understanding Bypass Techniques - Mirovengi(Derbycon2016](https://www.irongeek.com/i.php?page=videos/derbycon6/535-shackles-shims-and-shivs-understanding-bypass-techniques-mirovengi)
					* Our industry recognizes the importance of physical security, but often, we focus on the lock core itself and the challenges with picking it. This talk discuss an overview of the common retention mechanisms and how many of the common forms can be bypassed quicker than picking the lock.
				* [App-o-Lockalypse now! - Oddvar Moe(Derbycon2018](https://www.irongeek.com/i.php?page=videos/derbycon8/track-2-07-app-o-lockalypse-now-oddvar-moe)
					* Want to get a good overview of AppLocker and the different AppLocker bypasses and at the same time learn how defenders can harden their environments to prevent them? Then this is a talk you don't want to miss. This talk will cover a vast amount of bypass techniques and how to harden AppLocker to make it even harder to bypass. Giving you help to either start or avoid an App-o-Lockalypse.
			* **Tools**
				* [Backdoor-Minimalist.sct](https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302)
					* Applocker bypass
				* [Evasor](https://github.com/cyberark/Evasor)
					* The Evasor is an automated security assessment tool which locates existing executables on the Windows operating system that can be used to bypass any Application Control rules. It is very easy to use, quick, saves time and fully automated which generates for you a report including description, screenshots and mitigations suggestions, suites for both blue and red teams in the assessment of a post-exploitation phase.
		* **Windows Defender Application Control**<a name="wdacev"></a>
			* **101**
				* [Application Control for Windows - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control)
				* [Windows Defender Application Control and AppLocker Overview - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-and-applocker-overview)
				* [Windows Defender Application Control design guide - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-design-guide)
				* [Deploy Windows Defender Application Control policies by using Group Policy - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-group-policy)
				* [Plan for Windows Defender Application Control lifecycle policy management - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/plan-windows-defender-application-control-management)
				* [Planning and getting started on the Windows Defender Application Control deployment process](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-deployment-guide)
			* **Articles/Blogposts/Writeups**
				* [Documenting and Attacking a Windows Defender Application Control Feature the Hard Way — A Case Study in Security Research Methodology - Matt Graeber](https://posts.specterops.io/documenting-and-attacking-a-windows-defender-application-control-feature-the-hard-way-a-case-73dd1e11be3a)
					* My goal for this blog post is to not only describe the mechanics of this new feature, but more importantly, I wanted to use this opportunity to paint a picture of the methodology I applied to understand and attempt to bypass the feature. So, if you’re already interested in WDAC features, great. If you’re not, that’s also cool but I hope you’ll follow along with the specific strategies I took to understand an undocumented Windows feature.
				* [Exploring the WDAC Microsoft Recommended Block Rules: VisualUiaVerifyNative - BOHOPS(2020)](https://bohops.com/2020/10/15/exploring-the-wdac-microsoft-recommended-block-rules-visualuiaverifynative/)
			* **Talks/Presentations/Videos**
			* **Tools**
		* **Attack Surface Reduction**
			* **101**
				* [Overview of attack surface reduction - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/overview-attack-surface-reduction)
				* [Attack surface reduction frequently asked questions (FAQ) - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction-faq)
				* [Use attack surface reduction rules to prevent malware infection - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)
			* **Articles/Blogposts/Writeups**
				* [Bypass Windows Defender Attack Surface Reduction - Emeric Nasi](https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf)
				* [Windows ASR Rules & (Re)Enabling WMI When Blocked - FortyNorthSecurity(2018](https://fortynorthsecurity.com/blog/windows-asr-rules/)
			* **Talks/Presentations/Videos**
				* [Bypass Windows Exploit Guard ASR - Emeric Nasi(OffensiveCon2019](https://www.youtube.com/watch?v=YMHsuu3qldE)
			* **Tools**
		* [Bypass Windows Exploit Guard ASR - Emeric Nasi(OffensiveCon2020)](https://www.youtube.com/watch?v=YMHsuu3qldE&list=PLYvhPWR_XYJmwgLkZbjoEOnf2I1zkylz8&index=16&t=0s)
			* How to bypass all Microsoft latest "Attack Surface Reduction" rules with malicious Office documents and scripts. The last years, I have been doing some research around Windows security. I liked exploring APT/Redteam techniques and payload used for social engineering and airgap bypass attacks. I am naturally interested into new security features such as ASR. Microsoft introduced Attack Surface Reduction (ASR) as part of Windows defender exploit guard. ASR is composed of a set of configurable rules such as: "Block Office applications from creating child process". While these rules seem effective against common Office and scripts malwares, there are ways to bypass all of them. We will go over each rule related to malicious Office or VB scripts behavior, analyze how It work behind the scene and find a way to bypass it. As example we will take common attack scenario and see how they can be achieved with all rules enforced: Download execute DLL/EXE/script from Office/VBscript; Drop execute embedded DLL/EXE/script from Office/VBscript; Machine takeover with Meterpreter shell from Office/VBscript; Lateral movement/UAC bypass/AMSI bypass/etc.



	* **Defender**<a name="defender"></a>
		* **101**
			* [Next-generation protection in Windows 10, Windows Server 2016, and Windows Server 2019 - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/microsoft-defender-antivirus-in-windows-10)
			* [Microsoft Defender Advanced Threat Protection - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/microsoft-defender-advanced-threat-protection)
			* [Microsoft Defender ATP Blog - Microsoft](https://techcommunity.microsoft.com/t5/microsoft-defender-atp/bg-p/MicrosoftDefenderATPBlog)
			* [Configure Microsoft Defender Antivirus exclusions on Windows Server - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/configure-server-exclusions-microsoft-defender-antivirus#opt-out-of-automatic-exclusions)
				* "Microsoft Defender Antivirus on Windows Server 2016 and 2019 automatically enrolls you in certain exclusions, as defined by your specified server role. See the list of automatic exclusions (in this article). These exclusions do not appear in the standard exclusion lists that are shown in the Windows Security app."
			* [Security intelligence updates for Microsoft Defender Antivirus and other Microsoft antimalware - ms.com](https://www.microsoft.com/en-us/wdsi/defenderupdates)
				* Manual updates for Defender
			* [DisableAntiSpyware - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware)
				* Reg key to disable Defender on 1903 and prior.
				* Fun times trying to get this working in later versions....
			* [Reverse engineering Windows Defender's signature for Metasploit Framework's metsrv.dll - plowsec(StackOverflow2018)](https://reverseengineering.stackexchange.com/questions/19712/reverse-engineering-windows-defenders-signature-for-metasploit-frameworks-mets)
			* [comment by plowsec on Metasploit Project(2018)](https://github.com/rapid7/metasploit-framework/issues/10815#issuecomment-447126146)
		* **Articles/Blogposts/Writeups**
 			* [Untangling the “Windows Defender” Naming Mess - Lenny Zeltser](https://blog.minerva-labs.com/untangling-the-windows-defender-naming-mess)
 			* [Bypass Windows Defender Attack Surface Reduction - Emeric Nasi](https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf)
			* [Documenting and Attacking a Windows Defender Application Control Feature the Hard Way — A Case Study in Security Research Methodology - Matt Graeber](https://posts.specterops.io/documenting-and-attacking-a-windows-defender-application-control-feature-the-hard-way-a-case-73dd1e11be3a)
			* [Bypassing AV (Windows Defender) … the tedious way. - CB Hue](https://www.cyberguider.com/bypassing-windows-defender-the-tedious-way/)
			* [Dear Windows Defender, please tell me where I can drop my malicious code. - Simone Aonzo](https://medium.com/@simone.aonzo/dear-windows-defender-please-tell-me-where-i-can-drop-my-malicious-code-9c4f50f417a1)
				* 'The Get-MpPreference cmdlet exposes the field ExclusionPath without administrator privilege.'
			* [Hiding Metasploit Shellcode to Evade Windows Defender - Rapid7](https://blog.rapid7.com/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/)
			* [Incapacitating Windows Defender - offensiveops.io](http://www.offensiveops.io/tools/incapacitating-windows-defender/)
			* [Evading Windows Defender with 1 Byte Change - @spottheplanet](https://www.ired.team/offensive-security/defense-evasion/evading-windows-defender-using-classic-c-shellcode-launcher-with-1-byte-change)
			* [Bypassing Windows Defender Runtime Scanning - Charalampos Billinis(2020)](https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/)
			* [Silencing Microsoft Defender for Endpoint using firewall rules - Søren Fritzbøger(2021)](https://medium.com/csis-techblog/silencing-microsoft-defender-for-endpoint-using-firewall-rules-3839a8bf8d18)
			* [Bypass Defender and other thoughts on Unicode RTLO attacks - Emeric Nasi(2020)](http://blog.sevagas.com/?Bypass-Defender-and-other-thoughts-on-Unicode-RTLO-attacks)
		* **Talks/Presentations/Videos**
			* [Reverse Engineering Windows Defender’s JavaScript Engine - Alexei Bulazel(REcon Brussels18)](https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Reverse-Engineering-Windows-Defender-s-JavaScript-Engine.pdf)
				* [Defcon Videos](https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/Alexei%20Bulazel/Alexei-Bulazel-Reverse-Engineering-Windows-Defender-Demo-Videos/)
				* [Windows Offender: Reverse Engineering Windows Defender's Antivirus Emulator - Alexei Bulazel(BHEU2018)](https://www.youtube.com/watch?v=wDNQ-8aWLO0)
					* [Blackhat2018 Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf)
				* [Inside MpEngine.dll: Reverse Engineering Windows Defender’s JavaScript Engine](https://vimeo.com/273964590)
				* [Reverse Engineering Windows Defenders Emulator - Alexei Bulazel(Defcon26)](https://www.youtube.com/watch?v=2NawGCUOYT4)
				* [Tools](https://github.com/0xAlexei/WindowsDefenderTools)
			* [Auditing and Bypassing Windows Defender Application Control - Matt Graeber](https://www.youtube.com/watch?v=GU5OS7UN8nY)
			* [Bypass Windows Exploit Guard ASR - Emeric Nasi(OffensiveCon2020)](https://www.youtube.com/watch?v=YMHsuu3qldE&list=PLYvhPWR_XYJmwgLkZbjoEOnf2I1zkylz8&index=16&t=0s)
				* How to bypass all Microsoft latest "Attack Surface Reduction" rules with malicious Office documents and scripts. The last years, I have been doing some research around Windows security. I liked exploring APT/Redteam techniques and payload used for social engineering and airgap bypass attacks. I am naturally interested into new security features such as ASR. Microsoft introduced Attack Surface Reduction (ASR) as part of Windows defender exploit guard. ASR is composed of a set of configurable rules such as: "Block Office applications from creating child process". While these rules seem effective against common Office and scripts malwares, there are ways to bypass all of them. We will go over each rule related to malicious Office or VB scripts behavior, analyze how It work behind the scene and find a way to bypass it. As example we will take common attack scenario and see how they can be achieved with all rules enforced: Download execute DLL/EXE/script from Office/VBscript; Drop execute embedded DLL/EXE/script from Office/VBscript; Machine takeover with Meterpreter shell from Office/VBscript; Lateral movement/UAC bypass/AMSI bypass/etc.
			* [Adapting Exploit Frameworks to Evade Microsoft ATP - Jake Krasnov, Anthony Rose(Defcon27)](https://www.youtube.com/watch?v=WJgUJLmpKho)
		* **Tools**
	 		* [Windows Defender Emulator Tools](https://github.com/0xAlexei/WindowsDefenderTools)
				* Tools for instrumenting Windows Defender's mpengine.dll
				* [Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf)
				* [Video](https://www.youtube.com/watch?v=xbu0ARqmZDc)
			* [ExpandDefenderSig.ps1](https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866)
				* Decompresses Windows Defender AV signatures for exploration purposes
			* [Ninjasploit](https://github.com/FSecureLABS/Ninjasploit)
				* A meterpreter extension for applying hooks to avoid windows defender memory scans
			* [ThreatCheck - RastaMouse](https://github.com/rasta-mouse/ThreatCheck)
				* Modified version of Matterpreter's DefenderCheck. Takes a binary as input (either from a file on disk or a URL), splits it until it pinpoints that exact bytes that the target engine will flag on and prints them to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.
		* **DeviceGuard**
			* **101**
			* **Articles/Blogposts/Writeups**
			* **Talks/Presentations/Videos**
				* [AgentlessPost-Exploitation on Device Guarded Systems - Chris Truncer(OPCDE2017)](https://raw.githubusercontent.com/comaeio/OPCDE/master/2017/Agentless%20Post%20Exploitation%20on%20Device%20Guarded%20Systems%20-%20Christopher%20Truncer/Agentless%20Post-Exploitation%20on%20Device%20Guarded%20Systems.pdf)
		* **ExploitGuard**
			* **101**
				* [Protect devices from exploits - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exploit-protection)
					* Exploit protection automatically applies a number of exploit mitigation techniques to operating system processes and apps. Exploit protection is supported beginning with Windows 10, version 1709 and Windows Server, version 1803.
				* [Windows Defender Exploit Guard under the hood - Artur Wojtkowski](https://cqureacademy.com/blog/cqlabs-windows-defender-exploit-guard)
					* In this article, we will explain the main functionality of Exploit Protection and ASR rules and its’ internals.
			* **Articles/Blogposts/Writeups**
				* [Exploit Protection Event Documentation - Palantir & Matt Graeber](https://github.com/palantir/exploitguard)
					* Documentation and supporting script sample for Windows Exploit Guard 
				* [Assessing the effectiveness of a new security data source: Windows Defender Exploit Guard - Palantir(2019)](https://medium.com/palantir/assessing-the-effectiveness-of-a-new-security-data-source-windows-defender-exploit-guard-860b69db2ad2)
				* [Vulnserver Exploit vs Windows Defender Exploit Guard - Chad Duffey(2020)](https://www.chadduffey.com/2020/06/VulnServerVSExploitGuard.html)
				* [Exploit Guard Mistakes - Chad Duffey(2020)](https://www.chadduffey.com/2020/07/ExploitGuardMistakes.html)
				* [Exploit Guard vs Process (DLL) Injection - Chad Duffey(2020)](https://www.chadduffey.com/2020/07/ExploitGuardImageLoads.html)
			* **Talks/Presentations/Videos**
	* **Windows Event Log Avoidance & Deletion**<a name="windlogev"></a>
		* **Articles/Writeups**
			* [Remove individual lines from Windows XML Event Log (EVTX) files](https://github.com/3gstudent/Eventlogedit-evtx--Evolution)
				* Remove individual lines from Windows XML Event Log (EVTX) files
			* [Phant0m: Killing Windows Event Log - artofpwn.com](https://web.archive.org/web/20200228004851/https://artofpwn.com/phant0m-killing-windows-event-log.html)
			* [Universally Evading Sysmon and ETW - Dylan Halls(2020)](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)
			* [Mute Sysmon - Silence Sysmon via event manifest tampering - SecurityJosh(2020)](https://securityjosh.github.io/2020/04/23/Mute-Sysmon.html)
			* [Deletion and Bypass of Windows Logs - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/渗透技巧-Windows日志的删除与绕过/)
			* [Domain Controller Security Logs – how to get at them *without* being a Domain Admin - girlgerms(2016)](https://girl-germs.com/?p=1538)
			* [Pwning Windows Event Logging with YARA rules - Dylan Halls(2020)](https://blog.dylan.codes/pwning-windows-event-logging/)
			* [Disabling Windows Event Logs by Suspending EventLog Service Threads - @spottheplanet](https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads)
			* [肚脑虫组织（ APT-C-35）疑似针对巴基斯坦军事人员的最新攻击活动 - ](https://blogs.360.cn/post/APT-C-35_target_at_armed_forces_in_Pakistan.html)
			* [Windows XML Event Log (EVTX)单条日志清除（五）——通过DuplicateHandle获取日志文件句柄删除当前系统单条日志记录 - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%94-%E9%80%9A%E8%BF%87DuplicateHandle%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)
		* **Tools**
			* [Ghost In The Logs](https://github.com/bats3c/Ghost-In-The-Logs)
				* This tool allows you to evade sysmon and windows event logging, my blog post about it can be found [here](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)
			* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
				* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
			* [Log-killer](https://github.com/Rizer0/Log-killer)
				* Clear all your logs in [linux/windows] servers
			* [MuteSysmon](https://github.com/SecurityJosh/MuteSysmon)
				* A PowerShell script to prevent Sysmon from writing its events
			* [Windwos-EventLog-Bypass](https://github.com/3gstudent/Windows-EventLog-Bypass)
				* Use subProcessTag Value From TEB to identify Event Log Threads. Use NtQueryInformationThread API and I_QueryTagInformation API to get service name of the thread. Auto kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
			* [EvtMute](https://github.com/bats3c/EvtMute)
				* This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging.	
	* **Microsoft ATA & ATP**<a name="msatap"></a>
		* **Articles/Blogposts/Talks/Writeups**
			* [Red Team Techniques for Evading, Bypassing, and Disabling MS Advanced Threat Protection and Advanced Threat Analytics](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
			* [Red Team Revenge - Attacking Microsoft ATA](https://www.slideshare.net/nikhil_mittal/red-team-revenge-attacking-microsoft-ata)
			* [Evading Microsoft ATA for Active Directory Domination](https://www.slideshare.net/nikhil_mittal/evading-microsoft-ata-for-active-directory-domination)
			* [Week of Evading Microsoft ATA - Announcement and Day 1 - Nikhil Mittal(Aug 2017)](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day1.html)
			* [Week of Evading Microsoft ATA - Day 2 - Overpass-the-hash and Golden Ticket - Nikhil Mittal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day2.html)
			* [Week of Evading Microsoft ATA - Day 3 - Constrained Delegation, Attacks across trusts, DCSync and DNSAdmins - Nikhil Mittal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day3.html)
			* [Week of Evading Microsoft ATA - Day 4 - Silver ticket, Kerberoast and SQL Servers - Nikhil Mittal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day4.html)
			* [Week of Evading Microsoft ATA - Day 5 - Attacking ATA, Closing thoughts and Microsoft's response - Nikhil MIttal](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day5.html)
			* [Microsoft Advanced Threat Analytics – My best practices - Oddvar Moe](https://msitpros.com/?p=3509)
			* [Evading WinDefender ATP credential-theft: kernel version - B4rtik](https://b4rtik.github.io/posts/evading-windefender-atp-credential-theft-kernel-version/)
		* **Talks/Presentations/Videos**
			* [Red Team Techniques for Evading, Bypassing, and Disabling MS Advanced Threat Protection and Advanced Threat Analytics - Chris Thompson(BHUSA2017)](https://www.youtube.com/watch?v=2HNuzUuVyv0)
				* Windows Defender Advanced Threat Protection is now available for all Blue Teams to utilize within Windows 10 Enterprise and Server 2012/16, which includes detection of post breach tools, tactics and techniques commonly used by Red Teams, as well as behavior analytics.	
			* [Evading Microsoft ATA for Active Directory Domination - Nikhil Mittal(BH USA17)](https://www.youtube.com/watch?v=bHkv63-1GBY)
				* [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Mittal-Evading-MicrosoftATA-for-ActiveDirectory-Domination.pdf)
				* [BruCON 0x09 Talk](https://www.youtube.com/watch?v=5gu4r-IDDwU)
			* [Hack to Basics – Adapting Exploit Frameworks to Evade Microsoft ATP - BC-Security(2019)](https://github.com/BC-SECURITY/DEFCON27)
		* **Tools**
			* [DefenderCheck](https://github.com/matterpreter/DefenderCheck)
				* Takes a binary as input and splits it until it pinpoints that exact byte that Microsoft Defender will flag on, and then prints those offending bytes to the screen.
	* **DeviceGuard Bypass**<a name="deviceguard"></a>
		* **101**
		* **Articles/Blogposts/Talks/Writeups**
			* [Defeating Device Guard: A look into CVE-2017-0007](https://enigma0x3.net/2017/04/03/defeating-device-guard-a-look-into-cve-2017-0007/)
			* [Consider Application Whitelisting with Device Guard - subt0x10(2017)](https://web.archive.org/web/20170517232357/http://subt0x10.blogspot.com:80/2017/04/consider-application-whitelisting-with.html)
			* [Bypassing Application Whitelisting using MSBuild.exe - Device guard Example and Mitigations - subt0x10(2017)](https://web.archive.org/web/20170714075746/http://subt0x10.blogspot.com:80/2017/04/bypassing-application-whitelisting.html)
			* [Defeating Device Guard: A look into CVE-2017–0007 - Matt Nelson](https://posts.specterops.io/defeating-device-guard-a-look-into-cve-2017-0007-25c77c155767)
			* [UMCI vs Internet Explorer: Exploring CVE-2017–8625 - Matt Nelson](https://posts.specterops.io/umci-vs-internet-explorer-exploring-cve-2017-8625-3946536c6442)
			* [Windows: LUAFV NtSetCachedSigningLevel Device Guard Bypass - Google](https://www.exploit-db.com/exploits/46716)
		* **Talks/Presentations/Videos**
			* [Sneaking Past Device Guard - Philip Tsukerman(Troopers19)](https://www.youtube.com/watch?v=VJqr_UIwB_M&list=PL1eoQr97VfJlV65VBem99gRd6r4ih9GQE&index=6)
		* **Tools**
			* [DeviceGuard Bypasses - James Forshaw](https://github.com/tyranid/DeviceGuardBypasses)
				* This solution contains some of my UMCI/Device Guard bypasses. They're are designed to allow you to analyze a system, such as Windows 10 S which comes pre-configured with a restrictive UMCI policy.
			* [Window 10 Device Guard Bypass](https://github.com/tyranid/DeviceGuardBypasses)
	* **DLL Execution-Related**
		* **DLL Hijacking**
			* [DLL Stuff](#dllstuff)
		* **DLL Hollowing/Module Stomping/Overloading**
			* **101**
				* [DLL Hollowing - idiotc4t](https://idiotc4t.com/code-and-dll-process-injection/dll-hollowing)
				* [Module Stomping for Shellcode Injection - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection#overview)
				* [Living Dangerously with Module Stomping: Leveraging Code Coverage Analysis for Injecting into Legitimately Loaded DLLs - William Knowles](https://williamknowles.io/living-dangerously-with-module-stomping-leveraging-code-coverage-analysis-for-injecting-into-legitimately-loaded-dlls/)
			* **Articles/Blogposts/Writeups**
				* [Remote DLL Injection, Plus… - Security Ninja(2016)](https://resources.infosecinstitute.com/topic/code-injection-types-part-1/)
				* [Dissecting a NETWIRE Phishing Campaign’s Usage of Process Hollowing - Sumith Maniath, Prashanth Krushna Kadam(2019)](http://www.fireeye.com/blog/threat-research/2019/03/dissecting-netwire-phishing-campaign-usage-of-process-hollowing.html)
				* [Hiding malicious code with “Module Stomping”: Part 1 - Aliz Hammdond(2019)](https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/)
				* [Hiding malicious code with “Module Stomping”: Part 2 - Aliz Hammdond(2019)](https://blog.f-secure.com/hiding-malicious-code-with-module-stomping-part-2/)
				* [Understanding And Detecting Dll 1nj3ct0n & Process Hollowing - Alparslan Akyıldız academy(2019)](https://alparslanakyildiz.medium.com/understanding-and-detecting-dll-1nj3ct0n-process-hollowing-fcd87676d36b)
				* [Detecting VBA Process Hollowing With Cortex XDR - Stav Setty and Aviad Meyer(2020)](https://blog.paloaltonetworks.com/security-operations/detecting-vba-process-hollowing-with-cortex-xdr/)
				* [](https://medium.com/@alpinoacademy/understanding-and-detecting-dll-1nj3ct0n-process-hollowing-fcd87676d36b)
			* **Talks/Presentations/Videos**
				* [Module Stomping - Aliz Hammond(BSidesSG19)](https://bsidessg.org/files/2019/Module%20Stomping-bsides.pdf)
			* **Papers**
				* [Detecting Malware With Memory Forensics - Hal Pomeranz](http://www.deer-run.com/~hal/Detect_Malware_w_Memory_Forensics.pdf)
				* [Process Hollowing - John Leitch(2016)](https://web.archive.org/web/20201112024129/http://www.autosectools.com/process-hollowing.pdf)
				* [Evasion Tactics in Malware from the Inside Out - Lenny Zeltser(RSA2019)](https://published-prd.lanyonevents.com/published/rsaus19/sessionsFiles/13934/LAB4-W11_Evasion%20Tactics%20in%20Malware%20from%20the%20Inside%20Out.pdf)
			* **Articles/Blogposts/Writeups**
				* [Masking Malicious Memory Artifacts – Part I: Phantom DLL Hollowing - Forrest Orr(2019)](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing)
			* **Tools**
				* [Phantom DLL hollowing](https://github.com/forrest-orr/phantom-dll-hollower-poc)
					* DLL hollowing is a technique which can be used to provide stealth for malware in memory, either within the local process or a remote one (in combination with process injection/hollowing).
				* [CodeCoverageModuleStomping](https://github.com/williamknows/CodeCoverageModuleStomping)
	* **Drivers**			
		* **101**
			* [Overview of Device and Driver Installation - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/overview-of-device-and-driver-installation)
			* [Getting a kernel mode driver signed for Windows 10 - Christoph Lüders(2016)](http://wrogn.com/getting-a-kernel-mode-driver-signed-for-windows-10/)
			* [Methodology for Static Reverse Engineering of Windows Kernel Drivers - Matt Hand(2020)](https://posts.specterops.io/methodology-for-static-reverse-engineering-of-windows-kernel-drivers-3115b2efed83)
			* [Kernel Hacking With HEVD Part 1 - The Setup - Brian Beaudry(2016)](https://sizzop.github.io/2016/07/05/kernel-hacking-with-hevd-part-1.html)
				* [Part 2 - The Bug](https://sizzop.github.io/2016/07/06/kernel-hacking-with-hevd-part-2.html)
				* [Part 3 - The Shellcode](https://sizzop.github.io/2016/07/07/kernel-hacking-with-hevd-part-3.html)
			* [HackSys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)
				* HackSys Extreme Vulnerable Driver is intentionally vulnerable Windows driver developed for security enthusiasts to learn and polish their exploitation skills at Kernel level.
			* See `Rootkits.md`
		* **Articles/Blogposts/Writeups**
					* [Shhmon — Silencing Sysmon via Driver Unload - Matt Hand(2019)](https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650)
					* [How to Bypass Kernel Anticheat & Develop Drivers - Rake(2018)](https://guidedhacking.com/threads/how-to-bypass-kernel-anticheat-develop-drivers.11325/)
					* [Undocumented Windows API Functions & Structures - Rake(2020)](https://guidedhacking.com/threads/undocumented-windows-functions-structures.14438/)
					* [Ring 0 / 3 Protection - Jitsumi(2020)](https://www.jitsumibooster.com/blogs/jitsumi/cyber-security/ring-0-3-protection/56/#)
		* **Debugging**
			* [Setting Up KDNET Network Kernel Debugging Automatically - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection-automatically)
			* [Attaching to Windows Kernel with KDNET — a Short Guide - Ophir Harpaz(2019)](https://medium.com/@ophirharpaz/kdnet-tutorial-for-noobs-68669778bbd4)
		* **Filter Drivers**
			* **101**
				* [Filter Drivers - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/filter-drivers)
				* [About file system filter drivers - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers)
				* [Filter driver - Wikipedia](https://en.wikipedia.org/wiki/Filter_driver)
				* [File systems driver design guide](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/)
					* This section of the WDK provides conceptual information related to file systems and filter drivers.
				* [How File System Filter Drivers Are Similar to Device Drivers - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/how-file-system-filter-drivers-are-similar-to-device-drivers)
				* [The Role of a Filter Driver - Flylib.com](https://flylib.com/books/en/4.168.1.100/1/)
				* [FLTMC.exe - SS64](https://ss64.com/nt/fltmc.html)
			* **Articles**
				* [Understanding Minifilters: Why and How File System Filter Drivers Evolved - OSR.com](https://www.osr.com/nt-insider/2019-issue1/the-state-of-windows-file-system-filtering-in-2019/)
				* [How File System Filter Drivers Are Different from Device Drivers](https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/ifs/how-file-system-filter-drivers-are-different-from-device-drivers.md)
				* [Introduction to File System Filter Drivers - EaseFilter](https://www.easefilter.com/Forums_Files/Introduction_To_File_System_Filter_Drivers.htm)
				* [Understanding Windows File System Filter Driver - EaseFilter](https://www.easefilter.com/kb/understand-minifilter.htm)
				* [Filter Drivers in Windows - MohanKumar(2017)](https://mohankumar-k.blogspot.com/2017/02/filter-drivers-in-windows.html)
				* [Mimidrv In Depth: Exploring Mimikatz’s Kernel Driver - Matt Hand(2020)](https://posts.specterops.io/mimidrv-in-depth-4d273d19e148)
				* [Hunting for Bugs in Windows Mini-Filter Drivers  - James Forshaw(2021)](https://googleprojectzero.blogspot.com/2021/01/hunting-for-bugs-in-windows-mini-filter.html)
		* **Driver Loading/Unloading**
			* **Articles/Blogposts/Writeups**
				* [Shhmon — Silencing Sysmon via Driver Unload - Matt Hand(2019)](https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650)
		* **Attacking**
			* **Articles/Blogposts/Writeups**
				* [Kernel exploitation: weaponizing CVE-2020-17382 MSI Ambient Link driver - Matteo Malvica(2020)](https://www.matteomalvica.com/blog/2020/09/24/weaponizing-cve-2020-17382/)
				* [Windows SMEP Bypass: U=S - Enrique Nissim, NicolasEconomou(2015)](https://www.coresecurity.com/sites/default/files/private-files/publications/2016/05/Windows%20SMEP%20bypass%20U%3DS.pdf)
			* **Talks/Presentations/Videos**
				* [Who’s Watching the Watchdog? Uncovering a Privilege Escalation Vulnerability in OEM Driver - Amit Rapaport(BlueHat IL2019)](https://www.youtube.com/watch?v=Ltzye0Cj9G8)
					* With Microsoft continuously improving kernel mitigations and raising the exploitation bar for native kernel components, third-party kernel drivers are becoming a more appealing target for real attackers and security researchers. A vulnerability in a signed third-party driver can have a dramatic impact as it can be abused by attackers to escalate their privileges, without the complexity of a kernel zero-day. Computer manufacturers usually ship devices with software and tools to facilitate device management. This software often contains components running with ring-0 privileges in kernel. With these components installed by default, they must be as secure as the kernel, otherwise they can become the Achilles Heel for the whole kernel security design. In this session, we’ll explain exactly how we discovered such a driver. From an anomalous behavior alerted by a kernel sensor of Windows Defender ATP, we dug deeper into a specific device management driver, where we found a highly obscure design. This led us to the discovery of a zero-day vulnerability, which resulted in a local privilege escalation that affected millions of devices.
					* [Device Driver Debauchery and MSR Madness - Ryan Warns, Timothy Harrison(INFILTRATE2019)](https://vimeo.com/335216903)
				* **Papers**
					* [VDM: Vulnerable Driver Manipulation - Xeroxz](https://github.com/AXI4L/Community-Papers/tree/master/Vulnerable%20Driver%20Manipulation)
						* Abstract—This research paper documents the process of usinga vulnerable Windows kernel driver exposing a physical memoryread and write1primitive to call any function inside of theWindows kernel; while also teaching you the basics of pagingand physical memory.
				* **Training**
					* [Bypassing Driver Signature Enforcement - Csaba Fitzl(Defcon26Workshop)](https://raw.githubusercontent.com/theevilbit/workshops/master/DSE%20Bypass%20Workshop/dc26%20-%20Csaba%20Fitzl%20-%20DSE%20Bypass%20Workshop%20-%20Presentation.pdf)
				* **Tools**
					* [ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
						* This is a standalone exploit for a vulnerable feature in Capcom.sys. The feature is exposed through IOCTL and to execute an arbitrary user supplied function pointer with disabling SMEP. This exploit simply abuses the feature to perform token stealing to get the SYSTEM privileges, and then launches the command prompt with the elevated privilege.
					* [Reflective-Driver-Loader](https://github.com/Professor-plum/Reflective-Driver-Loader)
						* Reflective Kernel Driver injection is a injection technique base off Reflective DLL injection by Stephen Fewer. The technique bypasses Windows driver signing enforcement (KMCS). Reflective programming is employed to perform the loading of a driver from memory into the kernel. As such the driver is responsible for loading itself by implementing a minimal Portable Executable (PE) file loader. Injection works on Windows Vista up to Windows 10, running on x64.
					* [IRPMon](https://github.com/MartinDrab/IRPMon)
						* The goal of the tool is to monitor requests received by selected device objects or kernel drivers. The tool is quite similar to IrpTracker but has several enhancements. It supports 64-bit versions of Windows (no inline hooks are used, only modifications to driver object structures are performed) and monitors IRP, FastIo, AddDevice, DriverUnload and StartIo requests.
					* [gdrv-loader](https://github.com/alxbrn/gdrv-loader)
					* [Windows10 - Custom Kernel Signers](https://github.com/HyperSine/Windows10-CustomKernelSigners)
						* Load self-signed drivers without TestSigning or disable DSE. 
					* [KsDumper](https://github.com/EquiFox/KsDumper)
						* Dumping processes using the power of kernel space ! 
					* [drvmap](https://github.com/not-wlan/drvmap)
						* driver mapper / capcom wrapper
					* [KernelBhop](https://github.com/Zer0Mem0ry/KernelBhop)
						* Cheat that uses a driver instead WinAPI for Reading / Writing memory.
					* [Shhmon - Neuter Sysmon by unloading its driver](https://github.com/matterpreter/Shhmon)
					* [TitanHide](https://github.com/mrexodia/titanhide)
						* TitanHide is a driver intended to hide debuggers from certain processes. The driver hooks various Nt* kernel functions (using SSDT table hooks) and modifies the return values of the original functions. To hide a process, you must pass a simple structure with a ProcessID and the hiding option(s) to enable, to the driver. The internal API is designed to add hooks with little effort, which means adding features is really easy.
		* **Writeups**
			* [Part 19: Kernel Exploitation -> Logic bugs in Razer rzpnk.sys - FuzzySec](https://www.fuzzysecurity.com/tutorials/expDev/23.html)
			* [MSI ntiolib.sys/winio.sys local privilege escalation - rewolf(2016)](http://blog.rewolf.pl/blog/?p=1630)
			* [Dell SupportAssist Driver - Local Privilege Escalation - hatRiot(2018)](http://dronesec.pw/blog/2018/05/17/dell-supportassist-local-privilege-escalation/)
			* [Mother of All Drivers – New Vulnerabilities Found in Windows Drivers - Jesse Michael, Mickey Shkatov](https://eclypsium.com/2019/11/12/mother-of-all-drivers/)
			* [CVE-2019-9730: LPE in Synaptics Sound Device Driver - @Jackson_T(2019)](http://www.jackson-t.ca/synaptics-cxutilsvc-lpe.html)
			* [Viper RGB Driver Local Privilege Escalation (CVE-2019-18845) - ActiveCyber.us(2020)](https://www.activecyber.us/activelabs/viper-rgb-driver-local-privilege-escalation-cve-2019-18845)
			* [CORSAIR iCUE Driver Local Privilege Escalation (CVE-2020-8808) - ActiveCyber.us(2020)](https://www.activecyber.us/activelabs/corsair-icue-driver-local-privilege-escalation-cve-2020-8808)
			* [MSI Ambient Link Multiple Vulnerabilities - CoreSecurity(2020)](https://www.coresecurity.com/core-labs/advisories/msi-ambient-link-multiple-vulnerabilities)
			* [CVE-2020-12138 Exploit Proof-of-Concept, Privilege Escalation in ATI Technologies Inc. Driver atillk64.sys - h0mbre(2020)](https://h0mbre.github.io/atillk64_exploit/#)
			* [Dissecting the Windows Defender Driver - WdFilter (Part 1) - n4r1b(2020)](https://www.n4r1b.com/posts/2020/01/dissecting-the-windows-defender-driver-wdfilter-part-1/)
				* For those who don’t know, WdFilter is the main kernel component of Windows Defender. Roughly, this Driver works as a Minifilter from the load order group “FSFilter Anti-Virus”, this means that is attached to the File System stack (Actually, quite high - Big Altitude) and handles I/O operations in some Pre/Post callbacks. Not only that, this driver also implements other techniques to get information of what’s going on in the system. The goal of this series of post is to have a solid understanding on how this works under the hood.
				* [Part 2](https://www.n4r1b.com/posts/2020/02/dissecting-the-windows-defender-driver-wdfilter-part-2/)
				* [Part 3](https://www.n4r1b.com/posts/2020/03/dissecting-the-windows-defender-driver-wdfilter-part-3/)
				* [Part 4](https://www.n4r1b.com/posts/2020/04/dissecting-the-windows-defender-driver-wdfilter-part-4/)
			* [How to Bypass Kernel Anticheat & Develop Drivers - Rake(2018)](https://guidedhacking.com/threads/how-to-bypass-kernel-anticheat-develop-drivers.11325/)
			* [Undocumented Windows API Functions & Structures - Rake(2020)](https://guidedhacking.com/threads/undocumented-windows-functions-structures.14438/)
			* [Ring 0 / 3 Protection - Jitsumi(2020)](https://www.jitsumibooster.com/blogs/jitsumi/cyber-security/ring-0-3-protection/56/#)
		* **Papers**
			* [Windows Kernel-mode Payload Fundamentals - bugcheck, skape(2006)](http://www.uninformed.org/?v=3&a=4&t=sumry)
				* This paper discusses the theoretical and practical implementations of kernel-mode payloads on Windows. At the time of this writing, kernel-mode research is generally regarded as the realm of a few, but it is hoped that documents such as this one will encourage a thoughtful progression of the subject matter. To that point, this paper will describe some of the general techniques and algorithms that may be useful when implementing kernel-mode payloads. Furthermore, the anatomy of a kernel-mode payload will be broken down into four distinct units, known as payload components, and explained in detail. In the end, the reader should walk away with a concrete understanding of the way in which kernel-mode payloads operate on Windows. 
		* **MS ELAM**
			* **101**
				* [Overview of Early Launch AntiMalware - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware)
			* **Articles/Blogposts/Writeups**
				* [Understanding WdBoot (Windows Defender ELAM) - n4r1b(2019)](https://n4r1b.netlify.app/posts/2019/11/understanding-wdboot-windows-defender-elam/)
				* [Transition from an EFI Bootloader to the Kernel in Windows x64 - n4r1b(2020)](https://www.n4r1b.com/posts/2019/09/transition-from-an-efi-bootloader-to-the-kernel-in-windows-x64/)
				* [How does the OS Loader loads the essential Drivers - n4r1b](https://www.n4r1b.com/posts/2019/03/how-does-the-os-loader-loads-the-essential-drivers/)
		* **Writing**
			* [Drivers ( Kernel Mode ) - jitsumi(2020)](https://www.jitsumibooster.com/blogs/jitsumi/cyber-security/drivers-kernel-mode/54/)
		* **Tools**
			* [Physmem drivers](https://github.com/namazso/physmem_drivers)
				* A collection of various vulnerable (mostly physical memory exposing) drivers.
			* [Vulnerable Driver Manipulation](https://githacks.org/xerox/vdm)
				* A library to manipulate drivers exposing a physical memory read/write primitive to allow the user to call any function in the kernel. There are thousands of drivers exposing physical memory read/write, a bunch are listed in this repo. Currently the project is using gdrv.sys. This is basiclly what physmeme was about but that project is not truly "physical read and write" whereas this project is. This project can be used more broadly then physmeme.
			* [DriverMon](https://github.com/zodiacon/DriverMon)
				* Monitor activity of (almost) any driver
			* [Capcom Rootkit Proof-Of-Concept](https://github.com/FuzzySecurity/Capcom-Rootkit)
				* Capcom Rootkit POC 
			* [Windows kernel driver exploits](https://github.com/FULLSHADE/Kernel-exploits)
			* [ColdHide](https://github.com/Rat431/ColdHide_V2)
				* ColdHide is a mini and simple open source user mode anti-anti debug library x86/x64 for Windows. To inject this library try using ColdMDLoader.
			* [Canadian Furious Beaver](https://github.com/hugsy/CFB)
				* Canadian Furious Beaver is a tool for hijacking IRPs handler in Windows drivers, and facilitating the process of analyzing Windows drivers for vulnerabilities 
			* [TDL (Turla Driver Loader)](https://github.com/hfiref0x/TDL)
				* Driver loader for bypassing Windows x64 Driver Signature Enforcement 
			* [injdrv](https://github.com/wbenny/injdrv)
				* injdrv is a proof-of-concept Windows Driver for injecting DLL into user-mode processes using APC.
	* **Endpoint Detection & Response**<a name="edr"></a>
		* **Articles/Blogposts/Talks/Writeups**
			* [Lets Create An EDR… And Bypass It! Part 1 - Ceri Coburn(2020)](https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/)
				* [Part 2](https://ethicalchaos.dev/2020/06/14/lets-create-an-edr-and-bypass-it-part-2/)
				* [SylantStrike](https://github.com/CCob/SylantStrike)
			* [A Guide to Reversing and Evading EDRs: Part 1 - @Jackson_T](http://jackson-t.ca/edr-reversing-evading-03.html)
				* [Part 2](http://jackson-t.ca/edr-reversing-evading-02.html)
				* [Part 3](http://jackson-t.ca/edr-reversing-evading-03.html)
			* [Endpoint Protection, Detection and Response Bypass Techniques Index - p3zx.blogspot](https://pe3zx.blogspot.com/2019/01/endpoint-protection-detection-and.html)
			* [Generic bypass of next-gen intrusion / threat / breach detection systems](https://blog.mrg-effitas.com/generic-bypass-of-next-gen-intrusion-threat-breach-detection-systems/)
				* The focus of this blog post is to bypass network monitoring tools, e.g. good-old IDS or next-generation threat detection systems in a generic way. The focus is on the exploit delivery.
			* [Relying on usermode data is a bad idea (AKA Stop Trusting The Enemy) - krabsonsecurity(2020](https://krabsonsecurity.com/2020/07/04/relying-on-usermode-data-is-a-bad-idea-aka-stop-trusting-the-enemy/)
			* [Dechaining Macros and Evading EDR](https://www.countercept.com/blog/dechaining-macros-and-evading-edr/)
			* [A tale of EDR bypass methods - s3cur3th1ssh1t(2021)](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
		* **Talks/Presentations/Videos**
			* [EDR, ETDR, Next Gen AV is all the rage, so why am I enraged? - Michael Gough - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t416-edr-etdr-next-gen-av-is-all-the-rage-so-why-am-i-enraged-michael-gough)
				* A funny thing happened when I evaluated several EDR, ETDR and Next Gen AV products, currently all the rage and latest must have security solution. Surprisingly to me the solutions kinda sucked at things we expected them to do or be better at, thus this talk so you can learn from our efforts. While testing, flaws were discovered and shared with the vendors, some of the flaws, bugs, or vulns that were discovered will be discussed. This talk takes a look at what we initially expected the solutions to provide us, the options or categories of what these solutions address, what to consider when doing an evaluation, how to go about testing these solutions, how they would fit into our process, and what we found while testing these solutions. What enraged me about these EDR solutions were how they were all over the place in how they worked, how hard or ease of use of the solutions, and the fact I found malware that did not trigger an alert on every solution I tested. And this is the next new bright and shiny blinky security savior solution? The news is not all bad, there is hope if you do some work to understand what these solutions target and provide, what to look for, and most importantly how to test them! What we never anticipated or expected is the tool we used to compare the tests and how well it worked and how it can help you. 
			* [Modern Evasion Techniques - Jason Lang(Derbycon7 2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
				* [Slides](https://www.slideshare.net/JasonLang1/modern-evasion-techniques)
				* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.
			* [Next Gen AV vs My Shitty Code by James Williams - SteelCon 2018](https://www.youtube.com/watch?v=247m2dwLlO4)
			* [Red Teaming in the EDR age - Will Burgess(WWHF2018)](https://www.youtube.com/watch?v=l8nkXCOYQC4)
			* [An Inconvenient Truth: Evading the Ransomware Protection in Windows 10 - Soya Aoyama(GrrCON2018)](https://www.irongeek.com/i.php?page=videos/grrcon2018/grrcon-2018-augusta01-an-inconvenient-truth-evading-the-ransomware-protection-in-windows-10-soya-aoyama)
			* [Maintaining post-exploitation opsec in a world with EDR - Michael Roberts, Martin Roberts(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/stable-09-maintaining-post-exploitation-opsec-in-a-world-with-edr-michael-roberts-martin-roberts)
				* How a modern pentesting or red team can remain stealthy during post exploitation activities. Will go in depth on various code execution and lateral movement techniques and indicate ways to improve upon these methods.
			* [Reversing & bypassing EDRs - Christopher Vella(CrikeyCon2019)](https://www.youtube.com/watch?v=85H4RvPGIX4)
				* Endpoint Detection and Response (EDR) product vendors will give you the spiel on what they do and their capabilities, but how do they actually work at the lowest level? And how can we discover weaknesses in these products to develop bypasses or evaluate them?  Christopher will reverse engineer an EDR product and the windows kernel to unveil its inner-workings, alongside the windows kernel structures and functions EDR products rely on to operate, and by doing so discover weaknesses and gaps in their protections that allow actors to bypass the product’s defenses, rendering them null & void. Finally, by abusing an identified weakness, he’ll use a custom-built mimikatz to dump all the hashes on a machine protected by EDR.
			* [Testing Endpoint Protection: How Anyone Can Bypass Next Gen AV - Kevin Gennuso(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/1-11-testing-endpoint-protection-how-anyone-can-bypass-next-gen-av-kevin-gennuso)
				* Well-known antivirus vendors all have "next gen" solutions, and most newer players in the market claim to be "better" simply because they're new.This software is a significant investment for any organization, so it should do what it claims to do, right?In this talk, we'll discuss methodologies for testing these products, known and lesser-known payload generation frameworks, and how you can use these to inform your choice in EDR solutions.
			* [Unveiling the Underground World of Anti-Cheats - Joel Noguera(BHEU2019)](https://www.youtube.com/watch?v=yJHyHU5UjTg)
				* [Slides](http://i.blackhat.com/eu-19/Thursday/eu-19-Noguera-Unveiling-The-Underground-World-Of-Anti-Cheats-2.pdf)
				* During our research, we analyzed, tested and discovered multiple bypassing techniques against different current market Anti-Cheat technologies such as XignCode3, EasyAntiCheat and BattleEye, to understand and determine the current state of the art of Anti-Cheat software. We use a combination of static and dynamic techniques to document the different techniques to protect and unprotect gaming software. As a result, we put together a tool "AntiCheat-Testing-Framework" that contains a series of bypassing techniques to test them against current market Anti-Cheats software, this will allow attendees and researchers to understand the virtues and weaknesses of them.  This talk pretends to catch everyone's attention from new people to experts on the field, starting with a state of the market and interesting cases around the cheating world, and finishing with a deep explanation of each analyzed technique and the results we obtained during the journey.
			* [Tricking modern endpoint security products - Michel Coene(SANS2020)](https://www.youtube.com/watch?v=xmNpS9mbwEc)
				* The current endpoint monitoring capabilities we have available to us are unprecedented. Many tools and our self/community-built detection rules rely on parent-child relationships and command-line arguments to detect malicious activity taking place on a system. There are, however, ways the adversaries can get around these detections. During this presentation, we'll talk about the following techniques and how we can detect them: Parent-child relationships spoofing; Command-line arguments spoofing; Process injection; Process hollowing
			* [Tradecraft - This is why your tools and exploits get detected by EDR - xentropy(2020)](https://netsec.expert/2020/01/11/getting-detected-by-EDRs.html)
			* [Offensive Development: Post-Exploitation Tradecraft in an EDR World - Dominic Chell(x33fcon2020)](https://raw.githubusercontent.com/mdsecresearch/Publications/master/presentations/Offensive%20Development%20-%20Post-Exploitation%20Tradecraft%20in%20an%20EDR%20World%20-%20x33fcon%202020.pdf)
			* [Detection and Efficiency Testing of Endpoint Security Sensors - Filipi Pires(HTBCyberWeek2020)](https://www.youtube.com/watch?v=0pp6xcFsXgE&list=PLmv8T5-GONwQq16OhfaU77KCq7UQGiZsr&index=6)
				* During this presentation we’ll show our tests performed in three different endpoint security solutions (CrowdStrike, Sophos, and Cybereason)  where we simulate targeted attacks using many strategies of attacks to obtain a panoramic view of the resilience presented by the solutions, with regard to the efficiency in its detection by signatures, NGAV and Machine Learning, running scripts, such as: Download many malwares within the victim machine, moving all those malware to other folders (expectation of detection without execution), and as well as, an idea in to download these artifacts directly on the victim’s machine using malware from The Zoo Repository  while also running scripts with powershell downloading daily malwares batches, provide by MalwaresBazaar using API access.
		* **Tools**
			* [SharpBlock](https://github.com/CCob/SharpBlock)
				* A method of bypassing EDR's active projection DLL's by preventing entry point execution
			* [WhiteBeam](https://github.com/WhiteBeamSec/WhiteBeam)
			* [BLUESPAWN](https://github.com/ION28/BLUESPAWN)
				* BLUESPAWN is an active defense and endpoint detection and response tool which means it can be used by defenders to quickly detect, identify, and eliminate malicious activity and malware across a network.
			* [ProcessThis](https://github.com/jamcut/ProcessThis)
				* Small C# tool to call out AV/EDR processes running. 
			* [Invoke-EDRChecker](https://github.com/PwnDexter/Invoke-EDRChecker)
				* Checks running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services, the registry and running drivers for the presence of known defensive products such as AV's, EDR's and logging tools. 
			* [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker)
				* Checks running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services and each service binaries metadata, installed drivers and each drivers metadata, all for the presence of known defensive products such as AV's, EDR's and logging tools. 
			* [Telemetry Sourcerer](https://github.com/jthuraisamy/TelemetrySourcerer)
				* Enumerate and disable common sources of telemetry used by AV/EDR. 
		* **Specific EDRs**
			* **Cybereason**
				* [Why not catching exception hurts security products? A case study with Cybereason EDR (CVE-2020-26562 & CVE-2020-26871) - Nicolas Delhaye(2020)](https://airbus-cyber-security.com/a-case-study-with-cybereason-edr-cve-2020-26562-cve-2020-26871/)
			* **Cylance**
				* [Bypass Cylance Memory Exploitation Defense & Script Cntrl - Chris Ross(2017)](https://www.xorrior.com/You-Have-The-Right-to-Remain-Cylance/)
				* [How I evaded “next-generation” Cylance Smart AntiVirus in less than 15 minutes - slaeryan](https://slaeryan.github.io/posts/cylance-smartav-bypass.html)
				* [Silencing Cylance: A Case Study in Modern EDRs - Adam Chester, Dominic Chell(2019)](2019(https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/)
				* [Cylance, I Kill You! - Adi Ashkenazy, Shahar Zini(2019)](https://skylightcyber.com/2019/07/18/cylance-i-kill-you/)
					* "By carefully analyzing the engine and model of Cylance’s AI based antivirus product, we identify a peculiar bias towards a specific game. Combining an analysis of the feature extraction process, its heavy reliance on strings, and its strong bias for this specific game, we are capable of crafting a simple and rather amusing bypass. Namely, by appending a selected list of strings to a malicious file, we are capable of changing its score significantly, avoiding detection. This method proved successful for 100% of the top 10 Malware for May 2019, and close to 90% for a larger sample of 384 malware."
			* **Crowdstrike**
				* [Bypassing CrowdStrike in an enterprise production network [in 3 different ways] - KomodoResearch(2019-June)](https://www.komodosec.com/post/bypassing-crowdstrike)
				* [Bypassing CrowdStrike Endpoint Detection and Response - RedCursor(2020)](https://www.redcursor.com.au/blog/bypassing-crowdstrike-endpoint-detection-and-response)
				* [How I Bypassed Crowdstrike Restriction - Vivek Chauhan(2020)](https://medium.com/@viveik.chauhan/how-i-bypass-crowdstrike-restriction-1bc558abd464)
			* **Kaspersky**
				* [Bypassing Kaspersky Endpoint Security 11 - 0xc0ffee.io(2018)](http://0xc0ffee.io/blog/kes11-bypass)
			* **McAfee**
				* [Bypass McAfee with McAfee - Donny Maasland(2019)](https://blog.unauthorizedaccess.nl/2019/10/12/bypass-mcafee-with-mcafee.html)
			* **Palo Alto**
				* [Bypassing PaloAlto Traps EDR Solution - @c0d3xpl0it(2019)](https://www.c0d3xpl0it.com/2019/01/bypassing-paloalto-traps-edr-solution.html)
				* [Play with katz, get scratched - SkelSec(2020)](https://skelsec.medium.com/play-with-katz-get-scratched-6c2c350fadf2)
			* **Symantec**
				* [Bypassing Symantec Endpoint Protection for Fun & Profit (Defense Evasion) - Zubin(2020)](https://cognosec.com/bypassing-symantec-endpoint-protection-for-fun-profit-defense-evasion/)
	* **Kernel Callbacks**
		* **Articles/Blogposts/Writeups**
			* [Silencing the EDR. How to disable process, threads and image-loading detection callbacks. - matteomalvica.com](https://www.matteomalvica.com/blog/2020/07/15/silencing-the-edr/)
				* This post is about resuming the very inspiring Rui’s piece on Windows Kernel’s callbacks and taking it a little further by extending new functionalities and build an all-purpose AV/EDR runtime detection bypass. Specifically, we are going to see how Kaspersky Total Security and Windows Defender are using kernel callbacks to either inhibit us from accessing LSASS loaded module or detect malicious activities. We’ll then use our evil driver to temporarily silence any registered AV’s callbacks and restore EDR original code once we are done with our task. The resulting tool has been tested on the following Windows 10 builds: 1903,1909 and 2004.
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
			* [Isolated to Constrained Language Mode - Living within the Confines - Christopher Truncer(BSidesDC2018)](https://www.youtube.com/watch?v=d_1P0rLb8gM)
				* This talk will cover what constrained language mode is, what works, and what doesn’t compared with the tools you are likely used to using. I’ll talk about building out tools in constrained language mode, the frustrations, and tips to make it easier. I’ll also cover existing tools for operating within a constrained language mode environment, and add a new update to WMImplant based on my approach to building out constrained language mode capabilities.
			* [PowerShell Constrained Language Mode Enforcement and Bypass Deep Dive - Matt Graeber(2020)](https://www.youtube.com/watch?v=O6dtIvDfyuI&t=253s)
		* **Tools**
	* **Sysmon**
		* **Articles/Blogposts/Writeups**
			* [Sysmon Enumeration Overview - @./pwn(2017)](https://ackroute.com/post/2017/08/08/sysmon-enumeration-overview/)
			* [Sysmon doing lines - hexacorn(2017)](https://www.hexacorn.com/blog/2017/10/02/sysmon-doing-lines/)
			* [Sysmon doing lines, part 3 - hexacorn(2018)](http://www.hexacorn.com/blog/2018/06/29/sysmon-doing-lines-part-3/)
			* [Sysmon doing lines, part 4 - hexacorn(2018)](http://www.hexacorn.com/blog/2018/07/07/sysmon-doing-lines-part-4/)
			* [Operating Offensively Against Sysmon - Carlos Perez(2018)](https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon)
			* [Subverting Sysmon: Application of a Formalized Security Product Evasion Methodology - Matt Graber(BlackHatUSA2018)](https://specterops.io/assets/resources/Subverting_Sysmon.pdf)
			* [Subverting Sysmon materials](https://github.com/mattifestation/BHUSA2018_Sysmon)
			* [Evading Sysmon DNS Monitoring - Adam Chester(2019)](https://blog.xpnsec.com/evading-sysmon-dns-monitoring/)
			* [Sysmon Image File Name Evasion - NtRaiseHardError(2020)](https://undev.ninja/sysmon-image-file-name-evasion/)
			* [Sysmon Internals - From File Delete Event to Kernel Code Execution - NtRaiseHardError(2020)](https://undev.ninja/sysmon-internals-from-file-delete-event-to-kernel-code-execution/)
		* **Talks/Presentations/Videos**
		* **Tools**
			* [Shhmon - Neuter Sysmon by unloading its driver](https://github.com/matterpreter/Shhmon)
			* [Sysmon configuration bypass finder](https://github.com/mkorman90/sysmon-config-bypass-finder)
				* Detect possible sysmon logging bypasses given a specific configuration
	* **System Calls**
		* **101**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tools**
			* [SysWhispers](https://github.com/jthuraisamy/SysWhispers)
				* SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.
	* **Windows User Account Control(UAC)**<a name="wuac"></a>
		* **101**
			* [User Account Control - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/user-account-control)
			* [User Account Control Step-by-Step Guide - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc709691(v=ws.10))
			* User Account Control - Steven Sinofsky(blogs.msdn)](https://blogs.msdn.microsoft.com/e7/2008/10/08/user-account-control/)
			* [Inside Windows Vista User Account Control - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc138019(v=msdn.10)?redirectedfrom=MSDN)
			* [User Account Control: Inside Windows 7 User Account Control - Mark Russinovich(2016)](https://web.archive.org/web/20201112050831/https://docs.microsoft.com/en-us/previous-versions/technet-magazine/dd822916%28v=msdn.10%29?redirectedfrom=MSDN)
			* [How User Account Control Works - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/user-account-control/how-user-account-control-works)
			* [Abuse Elevation Control Mechanism: Bypass User Account Control - MITRE ATT&CK(2021)](https://attack.mitre.org/techniques/T1548/002/)
			* [User Account Control – What Penetration Testers Should Know - cobalstrike.com](https://blog.cobaltstrike.com/2014/03/20/user-account-control-what-penetration-testers-should-know/)
		* **Articles/Blogposts/Writeups**
			* [Anatomy of UAC Attacks - b33f](https://www.fuzzysecurity.com/tutorials/27.html)
			* [Reading Your Way Around UAC (Part 1) - James Forshaw(2017)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-1.html)
				* [Reading Your Way Around UAC (Part 2)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-2.html)
				* [Reading Your Way Around UAC (Part 3)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-3.html)
			* [Exploiting Environment Variables in Scheduled Tasks for UAC Bypass - James Forshaw(2017)](https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html)
			* [Farewell to the Token Stealing UAC Bypass - James Forshaw(2018)](https://tyranidslair.blogspot.com/2018/10/farewell-to-token-stealing-uac-bypass.html)
			* [ Accessing Access Tokens for UIAccess - James Forshaw(2019)](https://www.tiraniddo.dev/2019/02/accessing-access-tokens-for-uiaccess.html)
			* [CQLabs – How UAC bypass methods really work - Adrian Denkiewicz(2020)](https://cqureacademy.com/cqure-labs/cqlabs-how-uac-bypass-methods-really-work-by-adrian-denkiewicz)
				* In this article, we will analyze a couple of knowns, still working, UAC bypasses – how they work, what are the requirements, and potential mitigation techniques. Before we dive into this, we need to briefly explain what UAC is.
			* [UACMe 3.5, WD and the ways of mitigation - hfiref0x(2020)](https://swapcontext.blogspot.com/2020/10/uacme-35-wd-and-ways-of-mitigation.html)
			* [UAC bypasses from COMAutoApprovalList - hfiref0x(2020)](https://swapcontext.blogspot.com/2020/11/uac-bypasses-from-comautoapprovallist.html)
			* [Abusing COM & DCOM objects - Haboob(2020)](https://dl.packetstormsecurity.net/papers/general/abusing-objects.pdf)
		* **Talks/Presentations/Videos**
			* [Not a Security Boundary: Bypassing User Account Control - Matt Nelson(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t114-not-a-security-boundary-bypassing-user-account-control-matt-nelson)
				* Microsoft's User Account Control feature, introduced in Windows Vista, has been a topic of interest to many in the security community. Since UAC was designed to force user approval for administrative actions, attackers (and red teamers) encounter UAC on nearly every engagement. As a result, bypassing this control is a task that an actor often has to overcome, despite its lack of formal designation as a security boundary. This talk highlights what UAC is, previous work by others, research methodology, and details several technical UAC bypasses developed by the author.
			* [FromALPC to UAC-Bypass - @hakril(2017)](https://www.rump.beer/2017/slides/from_alpc_to_uac_bypass.pdf)
		* **Papers**
			* [Testing UAC on Windows 10 - Ernesto Fernandez(2017)](https://www.researchgate.net/publication/319454675_Testing_UAC_on_Windows_10)
				* User Account Control (UAC) is a mechanism implemented in Windows systems from Vista to prevent malicious software from executing with administrative privileges without user consent. However, this mechanism does not provide a secure solution to that problem, since can be easily bypassed in some ways, something we will show by means of different methods such as DLL hijacking, token impersonation or COM interface elevation, also we will show a new method which we have developed based on a previous one. Moreover, this new Proof of Concept has been ported to the Metasploit Framework as a new module, which indeed is the only UAC bypass module that works in the latest Windows 10 build version.
		* **Bypasses**
			* [Fileless UAC Bypass in Windows Store Binary - Activecyber.us(2019)](https://www.activecyber.us/activelabs/windows-uac-bypass)
			* [UAC Bypass via SPPLUAObject Class](https://github.com/deroko/SPPLUAObjectUacBypass)
			* [ALPC-BypassUAC](https://github.com/DimopoulosElias/alpc-mmc-uac-bypass)
				* UAC Bypass with mmc via alpc 
			* [Bypassing Windows User Account Control (UAC) and ways of mitigation - Parvez(2014)](https://www.greyhathacker.net/?p=796)
			* [Bypassing User Account Control (UAC) using TpmInit.exe - uacmeltdown.blogspot](https://uacmeltdown.blogspot.com/)
			* [UAC Bypass in System Reset Binary via DLL Hijacking - activecyber.us](https://www.activecyber.us/activelabs/uac-bypass-in-system-reset-binary-via-dll-hijacking)
			* [Bypassing UAC on Windows 10 using Disk Cleanup](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/)
			* [Research on CMSTP.exe](https://msitpros.com/?p=3960)
				* Methods to bypass UAC and load a DLL over webdav 
			* [Bypassing UAC using App Paths - enigma0x3(2017)](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/)
			* [“Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
			* [Fileless UAC Bypass using sdclt](https://posts.specterops.io/fileless-uac-bypass-using-sdclt-exe-3e9f9ad4e2b3)
			* [Eventvwr File-less UAC Bypass CNA - @vysecurity.(2016)](https://www.mdsec.co.uk/2016/12/cna-eventvwr-uac-bypass/)
			* [UAC Bypass or a Story of Three Elevations - xi-tauw(2017)](https://amonitoring.ru/article/uac_bypass_english/)
			* [How to bypass UAC in newer Windows versions - zcool(Oct2018)](https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html)
			* [Fileless UAC Bypass in Windows Store Binary - activecyber.us](https://www.activecyber.us/activelabs/windows-uac-bypass)
			* [User Account Control & odbcad32.exe - secureyourit.co.uk](https://secureyourit.co.uk/wp/2019/09/18/user-account-control-odbcad32-exe/)
			* [More Than a Penetration Test (Microsoft Windows CVE-2019–1082) - Michal Bazyli(2019)](https://medium.com/@bazyli.michal/more-than-a-penetration-test-cve-2019-1082-647ba2e59034)	
			* [UAC bypass through Trusted Folder abuse - Jean Maes(2020)](https://redteamer.tips/uac-bypass-through-trusted-folder-abuse/)
			* [Fileless_UAC_bypass_WSReset](https://github.com/sailay1996/Fileless_UAC_bypass_WSReset)
			* [Windows 10 LPE (UAC Bypass) in Windows Store (WSReset.exe) - abcdef(2019)](https://heynowyouseeme.blogspot.com/2019/08/windows-10-lpe-uac-bypass-in-windows.html)
			* [Slui File Handler Hijack LPE](https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation)
			* [UAC_bypass_windows_store](https://github.com/sailay1996/UAC_bypass_windows_store)
			* [SilentClean UAC bypass via binary planting](https://github.com/EncodeGroup/UAC-SilentClean)
			* [UAC Bypass by Mocking Trusted Directories - David Wells(2018)](https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e)
			* [Bypassing Windows 10 UAC with mock folders and DLL hijacking - Ax Sharma(2020)](https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/)
			* [Offense and Defense – A Tale of Two Sides: Bypass UAC - Anthony Giandomenico(2020)](https://www.fortinet.com/blog/threat-research/offense-and-defense-a-tale-of-two-sides-bypass-uac)
			* [SystemPropertiesAdvanced.exe DLL Hijacking UAC Bypass - egre55](https://egre55.github.io/system-properties-uac-bypass/)
			* [UAC_Exploit](https://github.com/0xyg3n/UAC_Exploit)
		* **Talks & Presentations**
			* [Not a Security Boundary: Bypassing User Account Control - Matt Nelson(Derbycon7)](https://www.youtube.com/watch?v=c8LgqtATAnE&index=21&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
			* [UAC 0day, all day - Ruben Boonen(Defcon25)](https://labs.f-secure.com/assets/resourceFiles/DefCon25-UAC-0day-All-Day-v2.2.pdf)
				* [Code](https://github.com/FSecureLABS/defcon25_uac_workshop)
		* **Tools**
			* [UACME](https://github.com/hfiref0x/UACME)
				* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
			* [DccwBypassUAC](https://github.com/L3cr0f/DccwBypassUAC)
				* This exploit abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. It supports "x86" and "x64" architectures. Moreover, it has been successfully tested on Windows 8.1 9600, Windows 10 14393, Windows 10 15031 and Windows 10 15062.
			* [Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
				* Bypass-UAC provides a framework to perform UAC bypasses based on auto elevating IFileOperation COM object method calls. This is not a new technique, traditionally, this is accomplished by injecting a DLL into "explorer.exe". This is not desirable because injecting into explorer may trigger security alerts and working with unmanaged DLL's makes for an inflexible work-flow. To get around this, Bypass-UAC implements a function which rewrites PowerShell's PEB to give it the appearance of "explorer.exe". This provides the same effect because COM objects exclusively rely on Windows's Process Status API (PSAPI) which reads the process PEB.
			* [Fileless_UAC_bypass_WSReset](https://github.com/sailay1996/Fileless_UAC_bypass_WSReset)
			* [ByeIntegrity — Windows UAC Bypass](https://github.com/AzAgarampur/byeintegrity-uac)
				* Bypass UAC by hijacking a DLL located in the Native Image Cache 
			* [ByeIntegrity 2.0 — Windows UAC Bypass](https://github.com/AzAgarampur/byeintegrity2-uac)
				* Bypass UAC by abusing the Internet Explorer Add-on installer
			* [ByeIntegrity 3.0 — Windows UAC Bypass](https://github.com/AzAgarampur/byeintegrity3-uac)
				* Bypass UAC by abusing the Security Center CPL and hijacking a shell protocol handler
			* [byeintegrity8-uac](https://github.com/AzAgarampur/byeintegrity8-uac)
			* [SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC)
	* **Specific Techniques**
		* **CMD Obfuscation**
			* **Articles/Blogposts/Writeups**
				* [DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and Detection Techniques - Daniel Bohannon](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)
				* [cmd.exe running any file no matter what extension - Hexacorn](http://www.hexacorn.com/blog/2019/04/21/cmd-exe-running-any-file-no-matter-what-extension/)
			* **Talks/Presentations/Videos**
				* [Invoke-DOSfuscation: Techniques FOR %F IN (-style) DO (S-level CMD Obfuscation) - Daniel Bohannon(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-2-09-invoke-dosfuscation-techniques-for-f-in-style-do-s-level-cmd-obfuscation-daniel-bohannon)
					* Skilled attackers continually seek out new attack vectors and effective ways of obfuscating old techniques to evade detection. Active defenders can attest to attackers’ prolific obfuscation of JavaScript, VBScript and PowerShell payloads given the ample availability of obfuscation frameworks and their effectiveness at evading many of today’s defenses. However, advanced defenders are increasingly detecting this obfuscation with help from the data science community. This approach paired with deeper visibility into memory-resident payloads via interfaces like Microsoft’s Antimalware Scan Interface (AMSI) is causing some Red Teamers to shift tradecraft to languages that offer defenders less visibility. But what are attackers using in the wild? In the past year numerous APT and FIN (Financial) threat actors have increasingly introduced obfuscation techniques into their usage of native Windows binaries like wscript.exe, regsvr32.exe and cmd.exe. Some simple approaches entail randomly adding cmd.exe’s caret (^) escape character to command arguments. More interesting techniques like those employed by APT32, FIN7 and FIN8 involve quotes, parentheses and standard input.The most interesting obfuscation technique observed in the wild was FIN7’s use of cmd.exe’s string replacement functionality identified in June 2017. This discovery single-handedly initiated my research into cmd.exe’s surprisingly effective but vastly unexplored obfuscation capabilities. In this presentation I will dive deep into cmd.exe’s multi-faceted obfuscation opportunities beginning with carets, quotes and stdin argument hiding. Next I will extrapolate more complex techniques including FIN7’s string removal/replacement concept and two never-before-seen obfuscation and full encoding techniques - all performed entirely in memory by cmd.exe. Finally, I will outline three approaches for obfuscating binary names from static and dynamic analysis while highlighting lesser-known cmd.exe replacement binaries. I will conclude this talk by giving a live demo of my cmd.exe obfuscation framework called Invoke-DOSfuscation that obfuscates payloads using these multi-layered techniques. I will also share detection implications and approaches for this genre of obfuscation.
			* **Tools**
		* **Debuggers**
			* [Batch, attach and patch: using windbg’s local kernel debugger to execute code in windows kernel](https://vallejo.cc/2015/06/07/batch-attach-and-patch-using-windbgs-local-kernel-debugger-to-execute-code-in-windows-kernel/)
				* In this article I am going to describe a way to execute code in windows kernel by using windbg local kernel debugging. It’s not a vulnerability, I am going to use only windbg’s legal functionality, and I am going to use only a batch file (not powershell, or vbs, an old style batch only) and some Microsoft’s signed executables (some of them that are already in the system and windbg, that we will be dumped from the batch file). With this method it is not necessary to launch executables at user mode (only Microsoft signed executables) or load signed drivers. PatchGuard and other protections don’t stop us. We put our code directly into kernel memory space and we hook some point to get a thread executing it. As we will demonstrate, a malware consisting of a simple batch file would be able to jump to kernel, enabling local kernel debugging and using windbg to get its code being executed in kernel.
		* **`He*`'s Gate**
			* **Heaven's Gate**
				* **101**
					* [Ten years later, malware authors are still abusing 'Heaven's Gate' technique - Catalin Cimpanu (2019)](https://www.zdnet.com/article/malware-authors-are-still-abusing-the-heavens-gate-technique/)
					* [Heaven's Gate: 64-bit code in 32-bit file - defjam(2011)](https://github.com/darkspik3/Valhalla-ezines/blob/master/Valhalla%20%231/articles/HEAVEN.TXT)
					* [Knockin’ on Heaven’s Gate – Dynamic Processor Mode Switching - George Nicolaou(2012)](http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/)
						* This post presents the research conducted under the domain of dynamic processor mode (or context) switching that takes place prior to the invocation of kernel mode functions in 32bit processes running under a 64bit Windows kernel. Processes that are designed and compiled to execute under a 32bit environment get loaded inside the Windows-on-Windows64 ( WoW64 ) subsystem and are assigned threads running in IA-32e compatibility mode ( 32bit mode ). When a kernel request is being made through the standard WoW64 libraries, at some point, the thread switches to 64bit mode, the request is executed, the thread switches back to compatibility mode and execution is passed back to the caller.  The switch from 32bit compatibility mode to 64bit mode is made through a specific segment call gate referred to as the Heaven’s Gate, thus the title of this topic. All threads executing under the WoW64 environment can execute a FAR CALL through this segment gate and switch to the 64bit mode.  The feature of mode switch can also be viewed from the security and maliciousness point of view. It can be used as an anti reverse engineering technique for protecting software up to the malicious ( or not ) intends of cross process generic library injection or antivirus and sandbox evasion. The result of this research is a library named W64oWoW64 which stands for Windows64 On Windows On Windows64.
					* [Rise of the dual architecture usermode rootkit - MalwareTech(2013)](https://www.malwaretech.com/2013/06/rise-of-dual-architecture-usermode.html)
					* [The 0x33 Segment Selector (Heavens Gate) - MalwareTech(2014)](https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html)
				* **Articles/Blogposts/Writeups**
					* [Code obFU(N)scation mixing 32 and 64 bit mode instructions - giula](https://web.archive.org/web/20200203175832/http://scrammed.blogspot.com/2014/10/code-obfunscation-mixing-32-and-64-bit.html)
					* [Closing “Heaven’s Gate” - Alex Ionescu(2015)](https://web.archive.org/web/20200127165829/http://www.alex-ionescu.com:80/?p=300)
					* [Crowbar: Breaking through Heaven’s Gate - KrabsOnSecurity](https://krabsonsecurity.com/2019/11/29/crowbar-breaking-through-heavens-gate/)
					* [Heaven's Gate: 64-bit code in 32-bit file - roy_g_biv(2009)](https://web.archive.org/web/20120316222751/http://vx.netlux.org:80/lib/vrg02.html)
					* [The power of WOW64 - int0h(2009)](https://int0h.wordpress.com/2009/12/24/the-power-of-wow64/)
					* [Anti-Anti-Debugging via WOW64 - int0h(2011)](https://int0h.wordpress.com/2011/02/22/anti-anti-debugging-via-wow64/)
					* [DLL Injection and WoW64 - Corsix.org(2010)](http://www.corsix.org/content/dll-injection-and-wow64)
					* [Mixing x86 with x64 code - ReWolf(2011)](http://blog.rewolf.pl/blog/?p=102)
					* [Heaven’s gate and a chameleon code (x86/64) - Hexacorn(2015)](http://www.hexacorn.com/blog/2015/10/26/heavens-gate-and-a-chameleon-code-x8664/)
					* [Jumping into heaven’s gate - Yarden Shafir(2018)](https://www.slideshare.net/YardenShafir/jumping-into-heavens-gate)
					* [Hooking Heaven’s Gate — a WOW64 hooking technique - Hoang Bui(2019)](https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73)
					* [How to Hook 64-Bit Code from WOW64 32-Bit Mode - Ruslan Valiakhmetov(2020)](https://www.apriorit.com/dev-blog/665-win-hook-64-bit-code-from-32-bit-mode)
					* [Deep Hooks: Monitoring native execution in WoW64 applications – Part 1 - Yarden Shafir, Assaf Carlsbad(2018)](https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-1/)
						* [Part 2](https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-2/)
						* [Part 3](https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-1/)
					* [A Pony Hidden in Your Secret Garden - David Cohen(2019)](https://www.cyberark.com/resources/threat-research-blog/a-pony-hidden-in-your-secret-garden)
						* Pony is the name of the malware
					* [VB2019 paper: Exploring Emotet, an elaborate everyday enigma - Luca Nagy(2019)](https://www.virusbulletin.com/virusbulletin/2019/10/vb2019-paper-exploring-emotet-elaborate-everyday-enigma/)
						* Based on Sophos detection numbers, the Emotet trojan is the most widespread malware family in the wild. Since its appearance more than five years ago, it has been – and remains – the most notorious and costly active malware. Emotet owes its reputation to its constant state of evolution and change. The malware’s rapid advancement helps support its highly sophisticated operation. This paper will discuss the reverse engineering of its components, as well as the capabilities and features of Emotet: a detailed overview of its multi-layered operation, starting with the spam lure, the malicious attachments (and their evolution), and the malware executable itself, from its highly sophisticated packer to its C2 server communications.
					* [WoW64 internals ...re-discovering Heaven's Gate on ARM](https://wbenny.github.io/2018/11/04/wow64-internals.html)
					* ["Heaven’s Gate" Một kĩ thuật cũ nhưng hiệu quả - Tran Trung Kien(2020)](https://blog.vincss.net/2020/06/re015-heavens-gate-mot-ki-thuat-cu-nhung-hieu-qua.html)
					* [How to Hook 64-Bit Code from WOW64 32-Bit Mode It was originally published on https://www.apriorit.com/ - apriorit.com(2020)](https://www.apriorit.com/dev-blog/665-win-hook-64-bit-code-from-32-bit-mode)
					* [GuLoader: Peering Into a Shellcode-based Downloader - Umesh Wanve(2020)](https://www.crowdstrike.com/blog/guloader-malware-analysis/)
				* **Talks/Presentations/Videos**
					* [DEEP Hooks: Monitoring Native Execution In WOW64 Applications - Assaf Carlsbad, Yarden Shafir(2018)](https://gsec.hitb.org/materials/sg2018/D2%20COMMSEC%20-%20Monitoring%20Native%20Execution%20in%20WoW64%20Applications%20-%20Assaf%20Carlsbad%20&%20Yarden%20Shafir.pdf)
				* **Tools**
					* [Heavens-Gate-2.0](https://github.com/dadas190/Heavens-Gate-2.0)
						* "Unable to find any properly implemented/working code that works on Windows 10, I have decided to open the Heaven's Gate on my own. Yes, this one is working on an updated Windows 10 (as of 22th July 2017) Tested on Windows 7 too"
					* [HeavenInjector](https://github.com/georgenicolaou/HeavenInjector)
						* Simple proof of concept code for injecting libraries on 64bit processes from a 32bit process
					* [rewolf-wow64ext](https://github.com/rwfpl/rewolf-wow64ext)
						*  Helper library for x86 programs that runs under WOW64 layer on x64 versions of Microsoft Windows operating systems. It enables x86 applications to read, write and enumerate memory of a native x64 applications. There is also possibility to call any x64 function from 64-bits version of NTDLL through a special function called X64Call(). As a bonus, wow64ext.h contains definitions of some structures that might be useful for programs that want to access PEB, TEB, TIB etc.
					* [W64oWoW64](https://github.com/georgenicolaou/W64oWoW64)
					* [wow64pp](https://github.com/JustasMasiulis/wow64pp)
						* An easy to use header only heavens gate implementation based on wow64ext X64Call however not using inline assembly allowing it to work on other compilers like MinGW.
					* [gopherheaven](https://github.com/aus/gopherheaven)
						* Go implementation of the Heaven's Gate technique 
			* **Hell's Gate**
				* **101**
					* [Hells Gate - smelly__vx(@RtlMateusz), am0nsec(@am0nsec)](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf)
						* "However, we are happy to report that we havelifted the veil, we have identified an approach capable of programmatically aggregating syscalls, at run-time, shedding us of unnecessary dependencies. For the sake of brevity, this paper will primarily focus on dynamically retrieving syscalls. This paperassumes you possess knowledge pertaining to both Windows internals and the Windows PE file format."
				* **Articles/Blogposts/Writeups**
					* [Implementing Direct Syscalls Using Hell’s Gate - N4kedTurtle(2020)](https://teamhydra.blog/2020/09/18/implementing-direct-syscalls-using-hells-gate/)
					* [Reading memory of x64 process from x86 process - ReWolf(2012)](http://blog.rewolf.pl/blog/?p=319)
					* [wow64ext library update - ReWolf(2012)](http://blog.rewolf.pl/blog/?p=344)
					* [WoW64 internals: Tale of GetSystemFileCacheSize - ReWolf(2013)](http://blog.rewolf.pl/blog/?p=621)
					* [wow64ext finally compatible with Windows 8 - ReWolf(2013)](http://blog.rewolf.pl/blog/?p=757)
					* [WoW64 internals: Unexpected behaviour of NtQueryDirectoryObject - ReWolf(2015)](http://blog.rewolf.pl/blog/?p=1273)
				* **Tools**
					* [Hell's Gate](https://github.com/am0nsec/HellsGate)
						* Original C Implementation of the Hell's Gate VX Technique 
						* [HellsGatePoC](https://github.com/N4kedTurtle/HellsGatePoC)
					* [C# Hell's Gate](https://github.com/am0nsec/SharpHellsGate)
						* C# Implementation of the Hell's Gate VX Technique
					* [BananaPhone](https://github.com/C-Sto/BananaPhone)
			* **Heresy's Gate**
				* **Articles/Blogposts/Writeups**
					* [Heresy's Gate: Kernel `Zw*`/NTDLL Scraping + "Work Out": Ring 0 to Ring 3 via Worker Factories](https://zerosum0x0.blogspot.com/2020/06/heresys-gate-kernel-zwntdll-scraping.html)
				* **Tools**
					* [Heresy's Gate](https://github.com/zerosum0x0/heresy)		
		* **In-Memory Execution**
			* **`*` Injection**
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
		* **Path Obfuscation**
			* [DOS File Path Magic Tricks - Carrie Roberts(2020)](https://webcache.googleusercontent.com/search?q=cache:RRHRn9qzPHoJ:https://medium.com/walmartlabs/dos-file-path-magic-tricks-5eda7a7a85fa+&cd=1&hl=en&ct=clnk&gl=us&client=firefox-b-1-d)
				* In this article I give a variety of examples of how to refer to the notepad.exe executable from the C:\Windows\System32 directory using various path notations. I also discuss how some of these tricks can be used to annoy or fool system administrators and information security analysts.
		* **Polymorphism**
			* **101**
			* **Articles/Blogposts/Writeups**
				https://blog.scrt.ch/2020/06/19/engineering-antivirus-evasion/
				https://blog.scrt.ch/2020/07/15/engineering-antivirus-evasion-part-ii/
			* **Talks/Presentations/Videos**
				* [Antivirus Evasion through Antigenic Variation (Why the Blacklisting Approach to AV is Broken) - Trenton Ivey, Neal Bridges(Derbycon 2013)](https://www.irongeek.com/i.php?page=videos/derbycon3/4108-antivirus-evasion-through-antigenic-variation-why-the-blacklisting-approach-to-av-is-broken-trenton-iveyneal-bridges)
					* Description: Think of the last time you got sick. Your immune system is an amazing piece of machinery, but every now and then, something gets past it. Antivirus evasion techniques can become more effective when modeled after infectious diseases. This talk highlights many of the antivirus evasion techniques in use today. Going further, this talk shows how genetic algorithms can quickly and repeatedly “evolve” code to evade many malicious code detection techniques in use today.
			* **Papers**
			* **Tools**
				* [Enneos](https://github.com/hoodoer/ENNEoS)
					* Evolutionary Neural Network Encoder of Shenanigans. Obfuscating shellcode with an encoder that uses genetic algorithms to evolve neural networks to contain and output the shellcode on demand.
				* [MorphAES](https://github.com/cryptolok/MorphAES)
					* MorphAES is the world's first polymorphic shellcode engine, with metamorphic properties and capability to bypass sandboxes, which makes it undetectable for an IDPS, it's cross-platform as well and library-independent.
		* **Process-Argument Spoofing**
			* [How to Argue like Cobalt Strike - Adam Chester(2019)](https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/)
			* [Winning Your 'Arguments' with EDRs. - Chinedu Onwukike(2019)](https://secureallofus.blogspot.com/2019/11/winning-your-arguments-with-edrs.html)
			* [A stealthier approach to spoofing process command line - KrabsOnSecurity(2020)](https://krabsonsecurity.com/2020/02/23/stealthier-approach-to-spoofing-process-command-line/)
		* **Process Un-Linking**
			* [Manipulating ActiveProcessLinks to Hide Processes in Userland - @spotheplanet](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/manipulating-activeprocesslinks-to-unlink-processes-in-userland)
		* **Process 'Hardening'**
			https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/
			https://www.youtube.com/watch?v=i5po8REiFXw
			* [Bypassing VirtualBox Process Hardening on Windows - James Forshaw(2017)](https://googleprojectzero.blogspot.com/2017/08/bypassing-virtualbox-process-hardening.html)
				* This blog post will describe the implementation of Oracle’s VirtualBox protected process and detail three different, but now fixed, ways of bypassing the protection and injecting arbitrary code into the process. The techniques I’ll present can equally be applied to similar implementations of “protected” processes in other applications.)
		* **REPL**
		* **Sandbox Detection & Evasion**
			* See RT.md
		* **Signatures**
			* **Articles/Writeups**			
				* [Discovering The Anti-Virus Signature and Bypassing it - Oddvar Moe(2019)](https://www.trustedsec.com/blog/discovering-the-anti-virus-signature-and-bypassing-it/)
				* [Building a custom Mimikatz binary - s3cur3th1ssh1t(2020)](https://s3cur3th1ssh1t.github.io/Building-a-custom-Mimikatz-binary/)
* **Credential Access**<a name="wincredac"></a>
	* **Want to learn this stuff? What should you know/study?**
    	* Windows Authentication Concepts
		* Windows Logon Scenarios
    	* Windows Authentication Architecture
      	* Security Support Provider Interface Architecture
		* Credentials Processes in Windows Authentication
		* Group Policy Settings Used in Windows Authentication
	* **101**<a name="wc101"></a>
		* [An Overview of KB2871997 - msrc-blog.ms](https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/)
			* Increasing complexity of retrieving clear-text creds
		* [Cached and Stored Credentials Technical Overview - docs.ms(2016)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11))
			* Applies To: Windows Vista, Windows Server 2008, Windows 7, Windows 8.1, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2012, Windows 8
		* [Cached and Stored Credentials - ldapwiki](https://ldapwiki.com/wiki/Cached%20and%20Stored%20Credentials)
		* [Windows Credential Management, Logon Sessions and the Double Hop Problem - Acebond(2019)](https://shellz.club/windows-credential-management/)
			* "I wanted to provide a quick overview on Windows credential management in relation to penetration testing, why passwords are not always stored in memory and the Double Hop problem."
			* [Fantastic Windows Logon types and Where to Find Credentials in Them - Chirag Salva, Anas Jamal(2021)](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
			* [Hunting for credentials and building a credential type reference catalog - wunderwuzzi(2020)](https://embracethered.com/blog/posts/2020/hunting-for-credentials/)			
			* [Using built-in OS indexing features for credential hunting - wunderwuzzi(2020)](https://embracethered.com/blog/posts/2020/invoke-windowssearch-credential-hunt/)
	* **Articles/Blogposts/Writeups**<a name="wcabw"></a>
		* **Collection/Overview of techniques**
			* [Dump Windows password hashes efficiently - Part 1(2011)](http://www.bernardodamele.blogspot.com/2011/12/dump-windows-password-hashes.html)
			* [Dumping user passwords in plaintext on Windows 8.1 and Server 2012 - labofapenetrationtester](http://www.labofapenetrationtester.com/2015/05/dumping-passwords-in-plain-on-windows-8-1.html)
			* [Intercepting Password Changes With Function Hooking - clymb3r(2013)](https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/)
			* [Dumping Windows Credentials](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)
			* [Hunting for Credentials  Dumping in Windows  Environment - Teymur Kheirhabarov - ZeroNights(2017)](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
			* [Dumping Clear-Text Credentials - NetbiosX(2018)](https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/)
			* [Dump-Clear-Text-Password-after-KB2871997-installed - 3gstudent](https://github.com/3gstudent/Dump-Clear-Password-after-KB2871997-installed)
			* [Extracting credentials from a remote Windows system - Living off the Land - bitsadmin.in(2020)](https://bitsadm.in/blog/extracting-credentials-from-remote-windows-system)
			* [Where we can find different kinds of passwords in the operating system? - Paula Januszkiewicz(2020)](https://cqureacademy.com/blog/hacks/passwords-operating-system)
			* [MITRE ATT&CK T1003 Credential Dumping - Süleyman Özarslan(2020)](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1003-credential-dumping)
				* In this article, we review: the fundamentals of the credential dumping technique; resources targeted by adversaries for credential dumping; its use cases by threat actors and malware; the most used OS resources for credential dumping; 11 red team exercises for this technique
		* **DMA**
			* [The True Story of Windows 10 and the DMA-protection - Sami Laiho](http://blog.win-fu.com/2017/02/the-true-story-of-windows-10-and-dma.html)
				* This blog post will tell you if / how Windows 10 protects against DMA (Direct Memory Access) bases attacks used against BitLocker and other encryption mechanisms by stealing the encryption key from the memory of a running computer. The story might be long(ish) but rest assured you want to read it through.
		* **From a Memory Dump**
			* [Dumping passwords in a VMware .vmem file - Remko Weijnen](https://www.remkoweijnen.nl/blog/2013/11/25/dumping-passwords-in-a-vmware-vmem-file/)
			* [How to retrieve user’s passwords from a Windows memory dump using Volatility - Andrea Fortuna](https://www.andreafortuna.org/2017/11/15/how-to-retrieve-users-passwords-from-a-windows-memory-dump-using-volatility/)
			* [Extracting passwords from hiberfil.sys and memory dumps - Kost(2019)](https://diverto.github.io/2019/11/05/Extracting-Passwords-from-hiberfil-and-memdumps)
		* **Specific Programs**
			* [SecretsDump Demystified - Mike Benich(2020)](https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b)
			* [Password Managers: Under the Hood of Secrets Management - ISE](https://www.securityevaluators.com/casestudies/password-manager-hacking/)
				* Password managers allow the storage and retrieval of sensitive information from an encrypted database. Users rely on them to provide better security guarantees against trivial exfiltration than alternative ways of storing passwords, such as an unsecured flat text file. In this paper we propose security guarantees password managers should offer and examine the underlying workings of five popular password managers targeting the Windows 10 platform: 1Password 7, 1Password 4, Dashlane, KeePass, and LastPass. We anticipated that password managers would employ basic security best practices, such as scrubbing secrets from memory when they are not in use and sanitization of memory once a password manager was logged out and placed into a locked state. However, we found that in all password managers we examined, trivial secrets extraction was possible from a locked password manager, including the master password in some cases, exposing up to 60 million users that use the password managers in this study to secrets retrieval from an assumed secure locked state.
	* **3rd Party**<a name="wc3rd"></a>
		* Erlang Portmapper Daemon
			* [Erlang Authenticated Remote Code Execution - mubix](https://malicious.link/post/2018/erlang-arce/)
		* PulseSecure
			* [Reversing Pulse Secure Client Credentials Store - qkaiser(2020)](https://quentinkaiser.be/reversing/2020/10/27/pule-secure-credentials/)
		* Solarwinds Orion
			* [SolarFlare Release: Password Dumper for SolarWinds Orion - mubix(2020)](https://malicious.link/post/2020/solarflare-release-password-dumper-for-solarwinds-orion/)
			* [solarflare](https://github.com/mubix/solarflare)
				* Credential Dumping Tool for SolarWinds Orion
			* [Exploitation of Remote WCF Vulnerabilities](https://versprite.com/blog/security-research/exploitation-of-remote-services/)
			* [Fun with SolarWinds Orion Cryptography - HD Moore(2018)](https://www.atredis.com/blog/2018/10/24/fun-with-the-solarwinds-orion-platform)
			* [SolarWinds Orion Cryptography](https://github.com/atredispartners/solarwinds-orion-cryptography)
				* Utilities for decrypting and hashing SolarWinds Orion credentials
	* **Active Directory Environment**<a name="wcad"></a>
		* **Articles/Blogposts/Writeups**
			* [Dumping Domain Password Hashes - pentestlab.blog](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
			* [How Attackers Dump Active Directory Database Credentials - adsecurity.org](https://adsecurity.org/?p=2398)
			* [Compromising Plain Text Passwords In Active Directory](https://blog.stealthbits.com/compromising-plain-text-passwords-in-active-directory)
			* [Safely Dumping Domain Hashes, with Meterpreter - Rapid7](https://blog.rapid7.com/2015/07/01/safely-dumping-domain-hashes-with-meterpreter/)
			* [Active Directory Domain Services Database Mounting Tool (Snapshot Viewer or Snapshot Browser) Step-by-Step Guide](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753609(v=ws.10))
				* This guide shows how you can use an improved version of Ntdsutil and a new Active Directory® database mounting tool in Windows Server® 2008 to create and view snapshots of data that is stored in Active Directory Domain Services (AD DS) or Active Directory Lightweight Directory Services (AD LDS), without restarting the domain controller or AD LDS server. A snapshot is a shadow copy—created by the Volume Shadow Copy Service (VSS)—of the volumes that contain the Active Directory database and log files.
			* [Pwning with Portals: How Rick Sanchez Dumps DITs - deadjakk](https://deadjakk.github.io/pivoting.html)
			* [How To Export LAPS Passwords from Active Directory with Powershell - Danny(2021)](https://smarthomepursuits.com/export-laps-passwords-powershell/)
	* **AWS**<a name="wcaws"></a>
		* **Articles/Blogposts/Writeups**
			* [CloudCopy — Stealing hashes from Domain Controllers in the Cloud - Tanner Barnes](https://medium.com/@_StaticFlow_/cloudcopy-stealing-hashes-from-domain-controllers-in-the-cloud-c55747f0913)
	* **AutoLogon**<a name="wcal"></a>
		* **Tools**
			* [DecryptAutoLogon](https://github.com/securesean/DecryptAutoLogon)
				* Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
	* **Azure**<a name="wcazure"></a>
		* **Articles/Blogposts/Writeups**
			* [PowerShell, Azure, and Password Hashes in 4 steps - FortyNorth Security](https://www.fortynorthsecurity.com/powershell-azure-and-password-haswinposthes-in-4-steps/)
				* this blog post will walk you through the process of obtaining hashes from a domain controller within Azure using PowerShell.
	* **Clipboard**<a name="wcclip"></a>
		* [Credential Dumping: Clipboard - Yashika Dhir(2020)](https://www.hackingarticles.in/credential-dumping-clipboard/)
		* [How to Turn On or Off Clipboard History in Windows 10 - Shawn Brink(2020)](https://www.tenforums.com/tutorials/109799-turn-off-clipboard-history-windows-10-a.html#option3)
	* **CredSSP**<a name="wcssp"></a>
		* [Credential theft without admin or touching LSASS with Kekeo by abusing CredSSP / TSPKG (RDP SSO) - Clement Notin](https://clement.notin.org/blog/2019/07/03/credential-theft-without-admin-or-touching-lsass-with-kekeo-by-abusing-credssp-tspkg-rdp-sso/)
		* [渗透技巧——通过CredSSP导出用户的明文口令(Penetration Techniques - Export the user's clear text password via TheCredSSP) - 3gstudent(2020)](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%80%9A%E8%BF%87CredSSP%E5%AF%BC%E5%87%BA%E7%94%A8%E6%88%B7%E7%9A%84%E6%98%8E%E6%96%87%E5%8F%A3%E4%BB%A4/)
	* **DPAPI**<a name="wcdpapi"></a>
		* **Articles/Blogposts/Writeups**
			* [TBAL: an (accidental?) DPAPI Backdoor for local users a.k.a how a convenience feature undermined a security feature - vztekoverflow(2018)](http://vztekoverflow.com/2018/07/31/tbal-dpapi-backdoor/)
				* In this article, we have demonstrated that in some scenarios, the default Windows configuration leads to the SHA‑1 hash of the user’s password being stored to the disk in a way that is retrievable without any further knowledge about the password. We argue that this is an issue for DPAPI, because if the secret necessary for decrypting the master key was to be stored on the disk by design, Microsoft could have kept on using the NTLM hash it uses in domain settings (and supposedly used in the first implementation of DPAPI). We then demonstrated how this attack can be executed using readily available tools.
		* **Talks/Presentations/Videos**
		* **Tools**
			* [Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump)
				* PowerShell Script to Dump Windows Credentials from the Credential Manager
	* **Dumping NTDS.dit**<a name="wcntds"></a>
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
			* [gosecretsdump](https://github.com/C-Sto/gosecretsdump)
				* This is a conversion of the impacket secretsdump module into golang. It's not very good, but it is quite fast. Please let me know if you find bugs, I'll try and fix where I can - bonus points if you can provide sample .dit files for me to bash against.
	* **Dumping Process Memory**<a name="wcdpm"></a>
		* **101**
			* [MiniDumpWriteDump function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
				* Writes user-mode minidump information to the specified file.
			* [MiniDumpWriteDump function (minidumpapiset.h) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
			* [minidump.c File Reference - ReactOS](https://doxygen.reactos.org/d8/d5d/minidump_8c.html#a9a74c45722230d9f89a34fd843050937)
			* [Why is SeDebugPrivilege enabled in PowerShell? - Lee Holmes(2017)](https://www.leeholmes.com/blog/2017/03/20/why-is-sedebugprivilege-enabled-in-powershell/)
				* This is enabled by .NET when PowerShell uses the System.Diagnostics.Process class in .NET, which it does for many reasons. One example is the Get-Process cmdlet. Another example is the method it invokes to get the current process PID for the $pid variable. Any .NET application that uses the System.Diagnostics.Process class also enables this privilege.
		* **Articles/Blogpost/Writeups**				
			* [MiniDumpWriteDump via COM+ Services DLL - modexp(2019)](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/)
			* [Dumping Process Memory with Custom C# Code -  3xpl01tc0d3r(2019)](https://3xpl01tc0d3r.blogspot.com/2019/07/dumping-process-memory-with-custom-c-sharp.html])
			* [SassyKitdi: Kernel Mode TCP Sockets + LSASS Dump - @zerosum0x0(2020)](https://zerosum0x0.blogspot.com/2020/08/sassykitdi-kernel-mode-tcp-sockets.html)
				* This post describes a kernel mode payload for Windows NT called "SassyKitdi" (LSASS + Rootkit + TDI). This payload is of a nature that can be deployed via remote kernel exploits such as EternalBlue, BlueKeep, and SMBGhost, as well as from local kernel exploits, i.e. bad drivers.
			* [How to Capture a Minidump: Let Me Count the Ways - John Robbins(2020)](https://www.wintellect.com/how-to-capture-a-minidump-let-me-count-the-ways/)
			* [The curious case of Realtek and LSASS - Henri Hambartsumyan(2020)](https://medium.com/falconforce/the-curious-case-of-realtek-and-lsass-33fc0c8482ff)
			* [Code Note 0x2: ATPMiniDump - P. Boonyakarn(2020)](https://pandora.sh/posts/code-note-0x2-atpminidump/)
			* [Mimikatz Under The Hood - Magnus Stubman(2021)](https://improsec.com/tech-blog/mimikatz-under-the-hood)
			* [Deception in Depth - LSASS Injection - spookysec(2021)](https://blog.spookysec.net/DnD-LSASS-Injection/)
			* [Dumping LSASS in memory undetected using MirrorDump - Ceri Coburn(2021)](https://www.pentestpartners.com/security-blog/dumping-lsass-in-memory-undetected-using-mirrordump/)
				* [Code](https://github.com/CCob/MirrorDump)
			* [Lsass Memory Dumps are Stealthier than Ever Before - Asaf Gilboa(2021)](https://www.deepinstinct.com/2021/01/24/lsass-memory-dumps-are-stealthier-than-ever-before/)
				* [Part 2](https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/)
			* [Dumping LSASS with SharpShere - James Coote(2021)](https://jamescoote.co.uk/Dumping-LSASS-with-SharpShere/)
			* [A physical graffiti of LSASS: getting credentials from physical memory for fun and learning - @AdeptsOf0xCC](https://adepts.of0x.cc/physical-graffiti-lsass/)
		* **Tools**
			* [KsDumper](https://github.com/EquiFox/KsDumper)
				* Dumping processes using the power of kernel space!
			* [PyKDumper](https://github.com/uf0o/PykDumper)
				* PykDumper is mimimkatz inspired PyKD based script that retrieves and decrypt usernames,logonservers and credentials from the lsass process.
			* [SassyKitdi](https://github.com/zerosum0x0/SassyKitdi)
				* Kernel Mode TCP Sockets + LSASS Dump (Rust Shellcode) 
			* [MiniDumpWriteDump BOF](https://github.com/rookuu/BOFs/tree/main/MiniDumpWriteDump)
			* [MiniDump](https://github.com/cube0x0/MiniDump)
				* C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps.
			* [MiniDumpWriteDumpPoC](https://github.com/Adepts-Of-0xCC/MiniDumpWriteDumpPoC)
				* This is a function hook that allows to access the buffer generated by MiniDumpWriteDump before it gets to disk. Once accessed, it will encrypt the buffer and send it through a socket to a given host.
			* [minidump](https://github.com/w1u0u1/minidump)
				* Custom implementation of DbgHelp's MiniDumpWriteDump function. Uses static syscalls to replace low-level functions like NtReadVirtualMemory.
			* [TransactedSharpMiniDump](https://github.com/PorLaCola25/TransactedSharpMiniDump)
				* Implementation of b4rtiks's SharpMiniDump using NTFS transactions to avoid writting the minidump to disk and exfiltrating it via HTTPS using sockets.
			* [LsassSilentProcessExit](https://github.com/deepinstinct/LsassSilentProcessExit)
				*  Command line interface to dump LSASS memory to disk via SilentProcessExit 
			* [PPLdump](https://github.com/itm4n/PPLdump)
				* This tool implements a userland exploit that was initially discussed by James Forshaw (a.k.a. @tiraniddo) - in this [blog post](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html) - for dumping the memory of any PPL as an administrator.
			* [AndrewSpecial](https://github.com/hoangprod/AndrewSpecial/tree/master)
				* AndrewSpecial, dumping lsass' memory stealthily and bypassing "Cylance" since 2019.
			* [SnoopyOwl](https://github.com/Adepts-Of-0xCC/SnoopyOwl)
			* [ntfsDump](https://github.com/3gstudent/ntfsDump)
				* Use to copy a file from an NTFS partitioned volume by reading the raw volume and parsing the NTFS structures.
			* [Chalumeau](https://github.com/cyberstruggle/chalumeau)
				* Chalumeau is automated,extendable and customizable credential dumping tool based on powershell and python.
			* [CredBandit](https://github.com/xforcered/CredBandit)
				* Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel
	* **Internal Monologue**<a name="wcim"></a>
		* **101**
			* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue/)
		        * In secure environments, where Mimikatz should not be executed, an adversary can perform an Internal Monologue Attack, in which they invoke a local procedure call to the NTLM authentication package (MSV1_0) from a user-mode application through SSPI to calculate a NetNTLM response in the context of the logged on user, after performing an extended NetNTLM downgrade.
		* **Articles/Blogposts/Writeups**
			* [Retrieving NTLM Hashes without touching LSASS: the “Internal Monologue” Attack - Andrea Fortuna(2018)](https://www.andreafortuna.org/2018/03/26/retrieving-ntlm-hashes-without-touching-lsass-the-internal-monologue-attack/)
			* [Getting user credentials is not only admin’s privilege - Anton Sapozhnikov(Syscan14)](https://infocon.org/cons/SyScan/SyScan%202014%20Singapore/SyScan%202014%20presentations/SyScan2014_AntonSapozhnikov_GettingUserCredentialsisnotonlyAdminsPrivilege.pdf)
			* [Stealing Hashes without Admin via Internal Monologue - Practical Exploitation(mubix@hak5)](https://www.youtube.com/watch?v=Q8IRcO0s-fU)
		* **Tools**
			* [selfhash](https://github.com/snowytoxa/selfhash)
				* Selfhash allows you to get password hashes of the current user. This tool doesn't requere high privileges i.e. SYSTEM, but on another hand it returns NTLM Challenge Response, so you could crack it later.
	* **Keylogger**<a name="wck"></a>
		* **Articles/Blogpost/Writeups**
			* [Keylogging by Using Windows’ Built-in Mechanisms Only - Paula Januszkiewicz(2020)](https://cqureacademy.com/blog/windows-internals/keylogging)
			* [How to create a keylogger in PowerShell? - Juan Manuel Fernandez](https://www.tarlogic.com/en/blog/how-to-create-keylogger-in-powershell/)
		* **Papers**
			* [You Can Type, but You Can’t Hide: A Stealthy GPU-based Keylogger](http://www.cs.columbia.edu/~mikepo/papers/gpukeylogger.eurosec13.pdf) 
				* Keyloggers are a prominent class of malware that harvests sensitive data by recording any typed in information. Key- logger implementations strive to hide their presence using rootkit-like techniques to evade detection by antivirus and other system protections. In this paper, we present a new approach for implementing a stealthy keylogger: we explore the possibility of leveraging the graphics card as an alterna- tive environment for hosting the operation of a keylogger. The key idea behind our approach is to monitor the system’s keyboard buffer directly from the GPU via DMA, without any hooks or modifications in the kernel’s code and data structures besides the page table. The evaluation of our pro- totype implementation shows that a GPU-based keylogger can effectively record all user keystrokes, store them in the memory space of the GPU, and even analyze the recorded data in-place, with negligible runtime overhead.
		* **Tools**
			* [Puffadder](https://github.com/xp4xbox/Puffader/blob/master/readme.md)
				* Puffader is an opensource, hidden and undetectable keylogger for windows written in Python 2.7 which can also capture screenshots, mouse window clicks and clipboard data.
	* **Local Account**<a name="wcla"></a>
		* [Win Brute Logon (Proof Of Concept)](https://github.com/DarkCoderSc/win-brute-logon)
			*  Crack any Microsoft Windows users password without any privilege (Guest account included)
	* **Local Phishing**<a name="wclp"></a>
		* **Articles/Blogposts/Writeups**
			* [Post exploitation trick - Phish users for creds on domains, from their own box](https://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
		* **Tools**
			* [Pickl3](https://github.com/hlldz/pickl3)
				* Pickl3 is Windows active user credential phishing tool. You can execute the Pickl3 and phish the target user credential.
			* [FakeLogonScreen](https://github.com/bitsadmin/fakelogonscreen)
				* FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user's password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk.
	* **Logon**<a name="wclog"></a>
		* [Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
			* The quick lowdown: I wrote a DLL capable of logging the credentials entered at logon for Windows Vista, 7 and future versions which you can download at http://www.leetsys.com/programs/credentialprovider/cp.zip. The credentials are logged to a file located at c:\cplog.txt. Simply copy the dll to the system32 directory and run the included register.reg script to create the necessary registry settings.
		* [LogonCredentialsSteal](https://github.com/oxfemale/LogonCredentialsSteal)
				* Hook msv1_0!SpAcceptCredentials from LSASS.exe and dump [...] in cleartext to text file. 
	* **Local Files**<a name="wclocal"></a>
		* **Articles/Blogposts/Writeups**
			* [Extracting SSH Private Keys from Windows 10 ssh-agent - ropnop](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)
			* [Stored passwords found all over the place after installing Windows in company networks :( - Win-Fu Official Blog](http://blog.win-fu.com/2017/08/stored-passwords-found-all-over-place.html)
		* **Tools**
			* [windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)
				* PoC code to extract private keys from Windows 10's built in ssh-agent service
	* **Local Security Authority Subsystem Service(LSA & LSASS)**<a name="wclsass"></a>
		* **101**
			* [Local Security Authority Subsystem Service - Wikipedia](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)
			* [Local Security Authority SubSystem Service - ldapwiki](https://ldapwiki.com/wiki/Local%20Security%20Authority%20Subsystem%20Service)
			* [Security Subsystem Architecture - 2012](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN)
			* [LSA Authentication - docs.ms(2018)](https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication?redirectedfrom=MSDN)
		* **Articles/Blogposts/Writeups**
			* [Windows LSA secrets - passcape.com](https://www.passcape.com/index.php?section=docsys&cmd=details&id=23)
			* [Dumping LSA Secrets - @spottheplanet(2019)](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets)
			* [Dumping Lsass.exe to Disk Without Mimikatz and Extracting Credentials - @spotheplanet](https://ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
			* [Some ways to dump LSASS.exe - Mark Mo](https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf)
			* [Extract credentials from lsass remotely - hackndo](https://en.hackndo.com/remote-lsass-dump-passwords/)
			* [Bypassing SACL Auditing on LSASS - James Forshaw(2017)](https://www.tiraniddo.dev/2017/10/bypassing-sacl-auditing-on-lsass.html)
			* [Hidden Gems in Windows: The Hunt is On -  Nate Caroe(2019)](https://risksense.com/blog/hidden-gems-in-windows-the-hunt-is-on/)
			* [Bypassing LSA Protection (aka Protected Process Light) without Mimikatz on Windows 10 - RedCursor.com.au(2020)](https://www.redcursor.com.au/blog/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10)
			* [Dumping LSASS without Mimikatz with MiniDumpWriteDump == Reduced Chances of Getting Flagged by AVs - @spotheplanet](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass)
			* [Protecting the LSASS.EXE process with RunAsPPL - adamcouch.co.uk](https://www.adamcouch.co.uk/protecting-the-lsass-exe-process-with-runasppl/)
			* [Credential Dumping: Local Security Authority (LSA|LSASS.EXE) - Yashika Dhir(2020)](https://www.hackingarticles.in/credential-dumping-local-security-authority-lsalsass-exe/)
			* [Mimikatz Under The Hood - Magnus Stubman(2021)](https://improsec.com/tech-blog/mimikatz-under-the-hood)
				* [MagnuzKatz](https://github.com/magnusstubman/MagnusKatz)
		* **Tools**
			* [Dumpert](https://github.com/outflanknl/Dumpert)
				* Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike, while not touching disk and evading AV/EDR monitored user-mode API calls.
			* [AndrewSpecial](https://github.com/hoangprod/AndrewSpecial)
				* AndrewSpecial, dumping lsass' memory stealthily and bypassing "Cilence" since 2019.
			* [PhysMem2Profit](https://github.com/FSecureLABS/physmem2profit)
				* Physmem2profit can be used to create a minidump of a target host's LSASS process by analysing physical memory remotely. The intention of this research is to propose an alternative approach to credential theft and create a modular framework that can be extended to support other drivers that can access physical memory. Physmem2profit generates a minidump (.dmp) of LSASS that can be further analyzed with Mimikatz. The tool does not require Cobalt Strike but should work fine over beacon with a SOCKS proxy.
				* [Blogpost](https://labs.f-secure.com/blog/rethinking-credential-theft/)
				* [Talk](https://www.youtube.com/watch?v=DXkd56WP_Oc&list=PLLvAhAn5sGfiZKg9GTUzljNmuRupA8igX&index=15)
			* [lsassy](https://github.com/hackndo/lsassy)
				* Python library to remotely extract credentials on a set of hosts
				* [Blogpost](https://en.hackndo.com/remote-lsass-dump-passwords/)
			* [SharpMiniDump](https://github.com/b4rtik/SharpMiniDump)
				* Create a minidump of the LSASS process from memory (Windows 10 - Windows Server 2016). The entire process uses: dynamic API calls, direct syscall and Native API unhooking to evade the AV / EDR detection.
			* [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)
				* Tool to bypass LSA Protection (aka Protected Process Light) I’ve noticed there is a common misconception that LSA Protection prevents attacks that leverage SeDebug or Administrative privileges to extract credential material from memory, like Mimikatz. LSA Protection does NOT protect from these attacks, at best it makes them slightly more difficult as an extra step needs to be performed.
				* [Bypassing LSA Protection (aka Protected Process Light) without Mimikatz on Windows 10 - Acebond(2020)](https://shellz.club/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10/)
			* [Spraykatz](https://github.com/aas-n/spraykatz)
				* Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments. It simply tries to procdump machines and parse dumps remotely in order to avoid detections by antivirus softwares as much as possible.
			* [SharpKatz](https://github.com/b4rtik/SharpKatz)
				* Porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands
			* [SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump)
				* .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py. By default runs in the context of the current user.
	* **Mimikatz/Similar**<a name="wcmimi"></a>
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
			* [Uncovering Mimikatz ‘msv’ and collecting credentials through PyKD - Matteo Malvica(2020)](https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/)
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
			* [Play with katz, get scratched - Skelsec(2020)](https://skelsec.medium.com/play-with-katz-get-scratched-6c2c350fadf2)
			* [BetterSafetyKatz](https://github.com/Flangvik/BetterSafetyKatz)
				*  Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory. 
		* **pypykatz**
			* [pypykatz](https://github.com/skelsec/pypykatz)
				* Mimikatz implementation in pure Python
			* [pypykatz_server](https://github.com/skelsec/pypykatz_server)
			* [pypykatz_dn](https://github.com/skelsec/pypykatz_agent_dn)
	* **MsvpPasswordValidate Hooking**<a name="wcmpvh"></a>
		* [MsvpPasswordValidate hooking - Federico Lagasta](https://offnotes.notso.pro/abusing-credentials/dumping-credentials/msvppasswordvalidate-hook)
			* Dumping local credentials by hooking MsvpPasswordValidate in NtlmShared.dll
		* [HppDLL](https://github.com/last-byte/HppDLL)
			* Source code for HppDLL - local password dumping using MsvpPasswordValidate hooks.
		* [MyHashDump](https://github.com/securifera/MyHashDump)
		 	* Project to inject into lsass and use a function hook on MsvpPasswordValidate to collect hashes. 
	* **NPLogonNotify()**<a name="wcnpln"></a>
		* [NPLogonNotify function (npapi.h) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify)
			* MPR calls this function to notify the credential manager that a logon event has occurred, allowing the credential manager to return a logon script. The NPLogonNotify function is implemented by a credential manager DLL (see Remarks).
		* [Getting Windows Passwords in ClearText - Aaladha(2020)](https://aaladha0.medium.com/getting-windows-passwords-in-cleartext-2ff5d3bc5efe)
		* [NPPSpy](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy)
			* Simple (but fully working) code for NPLogonNotify(). The function obtains logon data, including cleartext password.
	* **NTLM-related**<a name="wcntlm"></a>
		* **Info**
			* [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge](http://davenport.sourceforge.net/ntlm.html)
		* **Cracking**
			* **Articles/Blogposts/Writeups**
				* [Live off the Land and Crack the NTLMSSP Protocol](https://www.mike-gualtieri.com/posts/live-off-the-land-and-crack-the-ntlmssp-protocol)
					* Last month Bleeping Computer published an article about PKTMON.EXE, a little known utility in Windows 10 that provides the ability to sniff and monitor network traffic.  I quickly wondered if it would be feasible to use this utility, and other native tools within Windows, to capture NTLMv2 network authentication handshakes. TL;DR: Yes it is possible and I wrote a Python3 script called NTLMRawUnHide that can extract NTLMv2 password hashes from packet dumps of many formats!
			* **Tools**
				* [NTLMRawUnhide.py](https://github.com/mlgualtieri/NTLMRawUnHide)
					* NTLMRawUnhide.py is a Python3 script designed to parse network packet capture files and extract NTLMv2 hashes in a crackable format. The tool was developed to extract NTLMv2 hashes from files generated by native Windows binaries like NETSH.EXE and PKTMON.EXE without conversion.
		* **Leaking**
			* **Articles/Blogposts/Writeups**
				* [Abusing Microsoft Outlook 365 to Capture NTLM - Raj Chandel(2020)](https://www.hackingarticles.in/abusing-microsoft-outlook-365-to-capture-ntlm/)
				* [How to steal NTLMv2 hashes using file download vulnerability in web application - Mannu Linux(2018)](http://www.mannulinux.org/2018/12/how-to-steal-ntlmv2-hashes-using-file.html)
				* [SMB hash hijacking & user tracking in MS Outlook - Soroush Dalili(2018)](https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2018/may/smb-hash-hijacking-and-user-tracking-in-ms-outlook/)			
			* **Tools**
	* **Password Filter DLL**<a name="wcpfdll"></a>
		* [PasswordStealing -PSBits](https://github.com/gtworek/PSBits/tree/master/PasswordStealing)
			* "Password stealing DLL I wrote around 1999, some time before Active Directory was announced. And of course it still works. First, it was written in 32-bit Delphi (pardon my language) and when it stopped working as everything changed into 64-bit - in (so much simpler when it comes to Win32 API) C, as I did not have 64-bit Delphi. The original implementation was a bit more complex, including broadcasting the changed password over the network etc. but now it works as a demonstration of an idea, so let's keep it as simple as possible. It works everywhere - on local machines for local accounts and on DCs for domain accounts."
		* [Credential Access – Password Filter DLL - NetbiosX](https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/)
	* **Password Spraying**<a name="wcps"></a>
		* **Linux**
			* [Raining shells on Linux environments with Hwacha](https://www.n00py.io/2017/12/raining-shells-on-linux-environments-with-hwacha/)
			* [Hwacha](https://github.com/n00py/Hwacha)
				* Hwacha is a tool to quickly execute payloads on `*`Nix based systems. Easily collect artifacts or execute shellcode on an entire subnet of systems for which credentials are obtained.
		* **Articles/Blogposts/Writeups**
			* [Comprehensive Guide on Password Spraying Attack - Pavandeep Singh(2020)](https://www.hackingarticles.in/comprehensive-guide-on-password-spraying-attack/)
			* [Use PowerShell to Get Account Lockout and Password Policy](https://blogs.technet.microsoft.com/heyscriptingguy/2014/01/09/use-powershell-to-get-account-lockout-and-password-policy/)
		* **Tools**
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
			* [Spray](https://github.com/Greenwolf/Spray)
				* A Password Spraying tool for Active Directory Credentials by Jacob Wilkin(Greenwolf)
			* [Sharphose](https://github.com/ustayready/SharpHose)
				* SharpHose is a C# password spraying tool designed to be fast, safe, and usable over Cobalt Strike's execute-assembly. It provides a flexible way to interact with Active Directory using domain-joined and non-joined contexts, while also being able to target specific domains and domain controllers. SharpHose takes into consideration the domain password policy, including fine grained password policies, in an attempt to avoid account lockouts. Fine grained password policies are enumerated for the users and groups that that the policy applies to. If the policy applied also to groups, the group users are captured. All enabled domain users are then classified according to their password policies, in order of precedence, and marked as safe or unsafe. The remaining users are filtered against an optional user-supplied exclude list. Besides just spraying, red team operators can view all of the password policies for a domain, all the users affected by the policy, or just view the enabled domain users. Output can be sent directly to the console or to a user-supplied output folder.
	* **Physical Memory**<a name="wcpm"></a>
		* **Tools**
			* [VirtToPhys](https://github.com/FuzzySecurity/Sharp-Suite#virttophys)
				* VirtToPhys is a small POC to demonstrate how you can calculate the physical address for a kernel virtual address when exploiting driver bugs that allow you to map physical memory. VirtToPhys uses MsIo.sys, a WHQL signed driver that gives you colorful lights on your RAM (?lolwut), CVE-2019-18845. Hat tips and full credits to @UlfFrisk for his very insightful MemProcFS project and @hFireF0X for KDU.
			* [physmem2profit](https://github.com/FSecureLABS/physmem2profit)
				* [Blogpost](https://labs.f-secure.com/blog/rethinking-credential-theft/)
				* Physmem2profit can be used to create a minidump of a target host's LSASS process by analysing physical memory remotely. The intention of this research is to propose an alternative approach to credential theft and create a modular framework that can be extended to support other drivers that can access physical memory. Physmem2profit generates a minidump (.dmp) of LSASS that can be further analyzed with Mimikatz. The tool does not require Cobalt Strike but should work fine over beacon with a SOCKS proxy.
	* **RDP**<a name="wcrdp"></a>
		* **Articles/Blogposts/Writeups**
			* [Vol de session RDP - Gentil Kiwi](http://blog.gentilkiwi.com/securite/vol-de-session-rdp)
			* [Passwordless RDP Session Hijacking Feature All Windows versions - Alexander Korznikov](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)
			* [Dumping RDP Credentials - NetbiosX](https://pentestlab.blog/2021/05/24/dumping-rdp-credentials)
			* [Dumping Plaintext RDP credentials from svchost.exe - n00py(2021)](https://www.n00py.io/2021/05/dumping-plaintext-rdp-credentials-from-svchost-exe/)
			* [RdpThief – Extracting Clear Text Passwords from mstsc.exe using API Hooking - Stella Sebastian(2021)](https://reconshell.com/rdpthief-extracting-clear-text-passwords-from-mstsc-exe-using-api-hooking/)
		* **Tools**
			* [SharpRDPDump](https://github.com/jfmaes/SharpRDPDump)
				* Create a minidump of TermService for clear text pw extraction
	* **SeTrustedCredManaAccess**<a name="wcstcma"></a>
		* **Articles/Blogposts/Writeups**
			* [Dumping Stored Credentials with SeTrustedCredmanAccessPrivilege - James Forshaw(2021)](https://www.tiraniddo.dev/2021/05/dumping-stored-credentials-with.html)
		* **Tools**
			* [forkatz](https://github.com/Barbarisch/forkatz)
				* Credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
	* **Service Accounts**<a name="wcsa"></a>
		* **Tools**
			* [serviceFu](https://github.com/securifera/serviceFu)
				* Automates credential skimming from service accounts in Windows Registry 
	* **Tokens**<a name="wctokens"></a>
		* **Articles/Blogposts/Writeups**
			* [Another alternative to LSASS dumping - Magnus Stubman(2021)](https://improsec.com/tech-blog/another-alternative-to-lsass-dumping)
		* **Tools**
			* [tokenduplicator](https://github.com/magnusstubman/tokenduplicator/)
				* Tool to start processes as SYSTEM using token duplication
	* **Volume Shadow Copy Service**<a name="wcvss"></a>
		* [Shadow Copy - Wikipedia](https://en.wikipedia.org/wiki/Shadow_Copy)
		* [Manage Volume Shadow Copy Service from the Vssadmin Command-Line - technet.ms](https://technet.microsoft.com/en-us/library/dd348398.aspx)
		* [vssadmin - ss64](https://ss64.com/nt/vssadmin.html)
		* [vssown.vbs](https://github.com/lanmaster53/ptscripts/blob/master/windows/vssown.vbs)
		* [Using Shadow Copies to Steal the SAM - dcortesi.com](http://www.dcortesi.com/blog/2005/03/22/using-shadow-copies-to-steal-the-sam/)
	* **WDigest**<a name="wcwd"></a>
		* [Dumping WDigest Creds with Meterpreter Mimikatz/Kiwi in Windows 8.1 - TrustedSec](https://www.trustedsec.com/2015/04/dumping-wdigest-creds-with-meterpreter-mimikatzkiwi-in-windows-8-1/)
	* **Web Browsers**<a name="wcwb"></a>
		* [SharpCookieMonster](https://github.com/m0rv4i/SharpCookieMonster)
			* Extracts cookies from Chrome.
			* [Blogpost](https://jmpesp.me/sharpcookiemonster/)
	* **Wifi(saved)**<a name="wcwifi"></a>
		* [Credential Dumping: Wireless - Yashika Dhir(2020)](https://www.hackingarticles.in/credential-dumping-wireless/)
	* **Tools**<a name="wctools"></a>
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
	* **101**<a name="d101"></a>
		* [Red Team Play-book - Initial Enumeration - HunnicCyber](https://blog.hunniccyber.com/red-team-play-book-initial-enumeration/)
	* **Talks/Presentations/Videos**
		* [Post Exploitation: Striking Gold with Covert Recon - Derek Rook(WWHF19)](https://www.youtube.com/watch?v=04H1s9z0JDo)
			* You're on a covert penetration test focusing on the client's monitoring and alerting capabilities. You've just established a foothold, maybe even elevated to admin, but now what? You want to know more about the internal network but careless packet slinging will get you caught. Join me on a mining expedition where you can't swing your pick axe without striking gold. We'll be mining logs, pilfering connection statistics, and claim jumping process network connections. Without leaving the comfort of your beachhead, you'll be shouting "Eureka!" in no time.
	* **AD**<a name="dad"></a>
		* **Articles/Blogposts/Writeups**
			* [Push it, Push it Real Good - harmj0y](http://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
			* [Script to Create an Overview and Full Report of all Group Objects in a Domain - Jeremy Saunders](http://www.jhouseconsulting.com/2015/01/02/script-to-create-an-overview-and-full-report-of-all-group-objects-in-a-domain-1455)
			* [PowerQuinsta - harmj0y](http://www.harmj0y.net/blog/powershell/powerquinsta/)
		* **Tools**
			* [Low Privilege Active Directory Enumeration from a non-Domain Joined Host - matt](https://www.attackdebris.com/?p=470)
	* **AppLocker**<a name="dapp"></a>
		* **Articles/Blogposts/Writeups**		
			* [AppLocker Policy Enumeration in C - Paul Laine(2020)](https://ntamonsec.blogspot.com/2020/08/applocker-policy-enumeration-in-c.html)
		* **Tools**
	* **Browser Cookies**<a name="dbc"></a>
		* [cookie_crimes](https://github.com/defaultnamehere/cookie_crimes)
			* Read local Chrome cookies without root or decrypting
	* **COM**<a name="ddcom"></a>
		* [Enumerating COM Objects and their Methods - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-com-objects-and-their-methods)
		* [Using COM to Enumerate Hostname, Username, Domain, Network Drives - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/using-com-to-enumerate-hostname-username-domain-network-drives)
	* **Endpoint Protections**<a name="dend"></a>
		* **Articles/Blogposts/Writeups**
			* [Remotely Enumerate Anti-Virus Configurations - FortyNorthSecurity(2018))](https://fortynorthsecurity.com/blog/remotely-enumerate-anti-virus-configurations/)
			* [Get-MpPreference - docs.ms](https://docs.microsoft.com/en-us/powershell/module/defender/get-mppreference?view=win10-ps)
			* [PowerShell: Getting Windows Defender Status from all Domain Joined Computers (Get-AntiMalwareStatus) - Patrick Gruenauer(2018)](https://sid-500.com/2018/08/27/powershell-getting-windows-defender-status-from-all-domain-joined-computers-get-antimalwarestatus/)
			* [Detecting Sysmon on the Victim Host - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/detecting-sysmon-on-the-victim-host)
	* **Event Log**<a name="del"></a>
		* [Windows Event IDs and Others for Situational Awareness - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/windows-event-ids-for-situational-awareness)
	* **Files**<a name="dfiles"></a>
		* **Articles/Blogposts/Writeups**
			* [Build a Query to Search the Windows Index from PowerShell - Dr Scripto(2012)](https://devblogs.microsoft.com/scripting/build-a-query-to-search-the-windows-index-from-powershell/)
				* Guest blogger, James O’Neill, discusses using Windows PowerShell to build a query to search the Windows Index.
				* [Hey, Scripting Guy! Weekend Scripter: Using the Windows Search Index to Find Specific Files - Dr Scripto(2010)](https://devblogs.microsoft.com/scripting/hey-scripting-guy-weekend-scripter-using-the-windows-search-index-to-find-specific-files/)
			* [Reading Windows Sticky Notes - two06(2020)](https://blog.two06.info/Reading-Windows-Sticky-Notes/)
				* [Code](https://github.com/two06/SharpStick)
			* [Red Team Enumeration: A corner rarely explored - Mohammed Danish(2020)](https://medium.com/@gamer.skullie/red-team-enumeration-a-corner-rarely-explored-75bfae8d8944)
			* [StickyReader](https://github.com/whitej3rry/StickyReader)
				* Read Sticky Notes from Windows 10
			* [Unmanaged file searching with Filesearcher.exe - Jean-François Maes(2020)](https://blog.nviso.eu/2020/06/29/unmanaged-file-searching-with-filesearcher-exe/)
		* **Tools**
			* [Snaffler](https://github.com/SnaffCon/Snaffler/)
				* Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly, but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment).
			* [diskover](https://github.com/shirosaidev/diskover)
				*  File system crawler, disk space usage, file search engine and file system analytics powered by Elasticsearch 
			* [FileSearcher](https://github.com/NVISO-BE/FileSearcher)
				* Unmanaged assembly file searcher for when a fully interactive beacon session is not opsec safe enough.
	* **Logs**<a name="dlog"></a>
		* **Articles/Blogposts/Writeups**
			* [Offensive Event Parsing – Bringing Home Trophies - sixdub](https://www.sixdub.net/?p=315)
	* **Mail**<a name="dmail"></a>
		* **Articles/Blogposts/Writeups**
			* [Compliance search – a pentesters dream - Oddvar Moe](https://msitpros.com/?p=3678)
		* **Tools**
	* **NetworkCapture**<a name="dcap"></a>
		* **Articles/Blogposts/Writeups**
			* [Capture a Network Trace without installing anything (& capture a network trace of a reboot) - Chad Duffey(blogs.mdsn)](https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/)
		* **Tools**
			* [raw-socket-sniffer](https://github.com/nospaceships/raw-socket-sniffer)
	* **RPC**<a name="drpc"></a>
		* [The OXID Resolver [Part 1] – Remote enumeration of network interfaces without any authentication - Nicolas Delhaye(2020](https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/)
		* [The OXID Resolver [Part 2] – Accessing a Remote Object inside DCOM - Nicolas Delhaye(2020)](https://airbus-cyber-security.com/the-oxid-resolver-part-2-accessing-a-remote-object-inside-dcom/)
	* **Sitrep**<a name="dsit"></a>
		* **Articles/Blogposts/Writeups**
			* [Windows Driver and Service enumeration with Python - slacker007(2015)](https://web.archive.org/web/20161001105036/http://cybersyndicates.com/2015/09/windows-driver-and-service-enumeration-with-python/)
			* [Finding Hidden Treasure on Owned Boxes: Post-Exploitation Enumeration with wmiServSessEnum - RedXORBlue(2019)](http://blog.redxorblue.com/2019/08/finding-hidden-treasure-on-owned-boxes.html)
				* TLDR: We can use WMI queries to enumerate accounts configured to run any service on a box (even non-started / disabled), as well as perform live session enumeration.  Info on running the tool is in the bottom section.
			* [Detecting Hypervisor Presence On Windows 10 - Daax Rynd](https://revers.engineering/detecting-hypervisor-presence-on-windows-10/)
			* [Windows information gathering using Powershell: a brief cheatsheet - Andrea Fortuna(2019)](https://www.andreafortuna.org/2019/08/29/windows-information-gathering-with-powershell-a-brief-cheatsheet/)
			* [Get Process List with Command Line Arguments - mubix(2020)](https://malicious.link/post/2020/get-process-list/)
			* [What was my IP? Ask DoSvc on Windows 10 - Forense nella Nebbia(2018)](https://forensenellanebbia.blogspot.com/2018/12/what-was-my-ip-ask-dosvc-on-windows-10.html)
			* [Windows Event IDs and Others for Situational Awareness - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/windows-event-ids-for-situational-awareness)
		* **Tools**
			* [netview](https://github.com/mubix/netview)
				* Netview enumerates systems using WinAPI calls
			* [ListSSP](https://github.com/salehmuhaysin/ListSSP)
				* List Security Support Provider (SSP)
	* **User Awareness**<a name="dua"></a>
		* [Enumerating Users without net, Services without sc and Scheduled Tasks without schtasks - @spotheplanet]
		* [T1010: Application Window Discovery - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/t1010-application-window-discovery)
		* [T1087: Account Discovery & Enumeration - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery)
	* **General Tools**<a name="dgt"></a>
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
		* [hunter](https://github.com/fdiskyou/hunter/)
			*  (l)user hunter using WinAPI calls only
		* [NetRipper](https://github.com/NytroRST/NetRipper)
			* NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.
		* [NCC Group Scrying](https://github.com/nccgroup/scrying)
			* A tool for collecting RDP, web and VNC screenshots all in one place
* **Lateral Movement**<a name="winlater"></a>
	* **Articles/Blogposts/Writeups**<a name="lmab"></a>
		* [Using Credentials to Own Windows Boxes - Part 1 (from Kali) - ropnop](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
		* [Authenticated Remote Code Execution Methods in Windows](https://www.scriptjunkie.us/2013/02/authenticated-remote-code-execution-methods-in-windows/)
		* [Lateral Movement and Persistence: tactics vs techniques - hexacorn(2018)](https://www.hexacorn.com/blog/2018/10/05/lateral-movement-and-persistence-tactics-vs-techniques/)
		* [Offensive Lateral Movement - Hausec](https://hausec.com/2019/08/12/offensive-lateral-movement/)
		* [Lateral Movement - Riccardo Carrani(2019)](https://riccardoancarani.github.io/2019-10-04-lateral-movement-megaprimer/)
		* [Description of User Account Control and remote restrictions in Windows Vista - support.ms](https://support.microsoft.com/en-us/help/951016/description-of-user-account-control-and-remote-restrictions-in-windows)
		* [LAteral Movement Encryption technique (a.k.a. The "LAME" technique) - dotelite.gr(2018)](https://dotelite.gr/the-lame-technique)
	* **Talks/Presentations/Videos**
		* [The Industrial Revolution of Lateral Movement - Tal Be'ery, Tal Maor(BH USA17)](https://www.blackhat.com/docs/us-17/thursday/us-17-Beery-The-Industrial-Revolution-Of-Lateral-Movement.pdf)
		* [Look what you could be up against soon - FX, Hadez(Offensivecon2020)](https://www.youtube.com/watch?v=fgp0KQNjrMQ)
			* Lateral movement is essential for offensive operations during CNO. Exploiting the inherent trust relationships is what makes spreading within the chewy inside of a network so easy once the crunchy outside is broken. But what if the chewy inside is bitchy and challenges you everywhere you want to go? That's what P3KI is all about: To make the chewy inside more bitchy. Hear about how we intend to make your life harder and why the often dismissed "social engineering" aspect might become essential in cases where you face a network employing P3KI's technology deployed.
	* **AppInit.dlls**<a name="lappinit"></a>
		* [AppInit DLLs and Secure Boot - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dlls/secure-boot-and-appinit-dlls)
		* [AppInit_DLLs in Windows 7 and Windows Server 2008 R2 - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2)
		* [Alternative psexec: no wmi, services or mof needed - Diablohorn](https://diablohorn.com/2013/10/19/alternative-psexec-no-wmi-services-or-mof-needed/)
			* [Poc](https://github.com/DiabloHorn/DiabloHorn/tree/master/remote_appinitdlls)
	* **BGInfo**<a name="latbg"></a>
		* [Exploiting BGInfo to Infiltrate a Corporate Network - Dolev Taler(2020)](https://www.varonis.com/blog/exploiting-bginfo-to-infiltrate-a-corporate-network/)
	* **DCOM**<a name="latdcom"></a>
		* [Lateral movement using excel application and dcom(2017)](https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)
		* [Lateral Movement Using Outlook’s CreateObject Method and DotNetToJScript - Matt Nelson(2017)](https://posts.specterops.io/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript-a88a81df27eb)
		* [New lateral movement techniques abuse DCOM technology - Philip Tsukerman(2018)](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
		* [Lateral Movement Using internetexplorer.Application Object (COM) - homjxi0e(2018)](https://homjxi0e.wordpress.com/2018/02/15/lateral-movement-using-internetexplorer-application-object-com/)
		* [Lateral Movement with PowerPoint and DCOM - Attactics(2018)](https://attactics.org/2018/02/dcom-lateral-movement-powerpoint/)
		* [T1175: Lateral Movement via DCOM - @spotheplanet](https://www.ired.team/offensive-security/lateral-movement/t1175-distributed-component-object-model)
		* [I Like to Move It: Windows Lateral Movement Part 2 – DCOM - Dominic Chell(2020)](https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-2-dcom/)
	* **Desired State Configuration**<a name="latdsc"></a>
		* [Lateral Movement via Desired State Configuration(DSC) - Matt Graeber](https://twitter.com/mattifestation/status/970440419485007872?s=19)
	* **DLL Hijacking**<a name="latdll"></a>
		* [I Like to Move It: Windows Lateral Movement Part 3: DLL Hijacking - Dominic Chell(2020)](https://www.mdsec.co.uk/2020/10/i-live-to-move-it-windows-lateral-movement-part-3-dll-hijacking/)
	* **Excel**<a name="latexcel"></a>
		* [Excel4.0 Macros - Now With Twice The Bits! - Philip Tsukerman](https://www.cybereason.com/blog/excel4.0-macros-now-with-twice-the-bits)
		* [Excel4-DCOM](https://github.com/outflanknl/Excel4-DCOM)
			* PowerShell and Cobalt Strike scripts for lateral movement using Excel 4.0 / XLM macros via DCOM (direct shellcode injection in Excel.exe)
		* [Invoke-ExShellcode.ps1 - Philts](https://gist.github.com/Philts/f7c85995c5198e845c70cc51cd4e7e2a)
			* Lateral movement and shellcode injection via Excel 4.0 macros
	* **NTLM Relay**<a name="ntlmr"></a>
		* [Skip Cracking Responder Hashes and Relay Them - Richard de la Cruz](https://threat.tevora.com/quick-tip-skip-cracking-responder-hashes-and-replay-them/)		
	* **Pass-The-Hash**<a name="latpth"></a>
		* **101**
		* **Articles/Blogposts/Writeups**
			* [*Puff* *Puff* PSExec - Jonathan Renard](https://www.toshellandback.com/2017/02/11/psexec/)
			* [PsExec and the Nasty Things It Can Do](http://www.windowsecurity.com/articles-tutorials/misc_network_security/PsExec-Nasty-Things-It-Can-Do.html)
				* An overview of what PsExec is and what its capabilities are from an administrative standpoint.
			* [Pass-the-Hash is Dead: Long Live Pass-the-Hash - harmj0y](http://www.harmj0y.net/blog/penetesting/pass-the-hash-is-dead-long-live-pass-the-hash/)
			* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - harmj0y](http://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
			* [Still Passing the Hash 15 Years Later: Using Keys to the Kingdom to Access Data - BH 2012](https://www.youtube.com/watch?v=O7WRojkYR00)
			* [Still Passing the Hash 15 Years Later](http://passing-the-hash.blogspot.com/)
			* [The Evolution of Protected Processes Part 1: Pass-the-Hash Mitigations in Windows 8.1](http://www.alex-ionescu.com/?p=97)
			* [Pass-the-Hash in Windows 10 - Lukasz Cyra(2019)](https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-windows-10-39170)
				* Attackers have used the Pass-the-Hash (PtH) attack for over two decades. Its effectiveness has led to several changes to the design of Windows. Those changes influenced the feasibility of the attack and the effectiveness of the tools used to execute it. At the same time, novel PtH attack strategies appeared. All this has led to confusion about what is still feasible and what configurations of Windows are vulnerable. This paper examines various methods of hash extraction and execution of the PtH attack. It identifies the prerequisites for the attack and suggests hardening options. Testing in Windows 10 v1903 supports the findings. Ultimately, this paper shows the level of risk posed by PtH to environments using the latest version of Windows 10.
			* [Et tu Kerberos - Christopher Campbell](https://www.youtube.com/watch?v=RIRQQCM4wz8)
				* For over a decade we have been told that Kerberos is the answer to Microsoft’s authentication woes and now we know that isn’t the case. The problems with LM and NTLM are widely known- but the problems with Kerberos have only recently surfaced. In this talk we will look back at previous failures in order to look forward. We will take a look at what recent problems in Kerberos mean to your enterprise and ways you could possibly mitigate them. Attacks such as Spoofed-PAC- Pass-the-Hash- Golden Ticket- Pass-the-Ticket and Over-Pass-the-Ticket will be explained. Unfortunately- we don’t really know what is next – only that what we have now is broken.
			* [Battle Of SKM And IUM How Windows 10 Rewrites OS Architecture - Alex Ionescu - BHUSA2015](https://www.youtube.com/watch?v=LqaWIn4y26E&index=15&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7)
				* [Slides](http://www.alex-ionescu.com/blackhat2015.pdf)
			* [Psexec: The Ultimate Guide - Adam Bertram](https://adamtheautomator.com/psexec-ultimate-guide/)
			* [Pass the Hash with Kerberos - mubix](https://malicious.link/post/2018/pass-the-hash-with-kerberos/)
				* This blog post may be of limited use, most of the time, when you have an NTLM hash, you also have the tools to use it. But, if you find yourself in a situation where you don’t have the tools and do happen to have kerberos tools, you can pass the hash with it.
			* [Pass-The-Hash with RDP in 2019 - Acebond](https://shellz.club/pass-the-hash-with-rdp-in-2019/)
			* [Named Pipe Pass-the-Hash - s3cur3th1ssh1t(2021)](https://s3cur3th1ssh1t.github.io/Named-Pipe-PTH/)
		* **Tools**
			* [smbexec](https://github.com/pentestgeek/smbexec)
				* A rapid psexec style attack with samba tools
				* [Blogpost that inspired it](http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html)
			* [pth-toolkit I.e Portable pass the hash toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
				* A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
			* [SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec)
				* Get file less command execution for lateral movement.
	* **PS-Remoting**<a name="latpsr"></a>
		* **101**
			* [Running Remote Commands - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7)
			* [PowerShell remoting over SSH - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell-core?view=powershell-7)
			* [Enable-PSRemoting - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7)
			* [Enable-PSRemoting - ss64](https://ss64.com/ps/enable-psremoting.html)
			* [Disable-PSRemoting - ss64](https://ss64.com/ps/disable-psremoting.html)
		* **Articles/Blogposts/Writeups**
			* [PowerShell Remoting from Linux to Windows - William Martin](https://blog.quickbreach.io/ps-remote-from-linux-to-windows/)
			* [PowerShell Remoting Cheatsheet - Scott Sutherland(2015)](https://blog.netspi.com/powershell-remoting-cheatsheet/)
			* [PowerShell Remoting: Cheat Sheet and Guide - Jeff Peters](https://www.varonis.com/blog/powershell-remoting/)
			* [Lateral Movement: PowerShell Remoting - Subham Misra(2020)](https://medium.com/@subhammisra45/lateral-movement-powershell-remoting-89da402a9885)
	* **Protocol Handler**<a name="latph"></a>
		* **Articles/Blogposts/Writeups**
			* [Lateral movement using URL Protocol - Matt harr0ey](https://medium.com/@mattharr0ey/lateral-movement-using-url-protocol-e6f7d2d6cf2e)
			* [Attack Surface Analysis - Part 2 - Custom Protocol Handlers - Parsia(2021)](https://parsiya.net/blog/2021-03-17-attack-surface-analysis-part-2-custom-protocol-handlers/)
		* **Tools**
			* [PoisonHandler](https://github.com/Mr-Un1k0d3r/PoisonHandler)
				* This technique is registering a protocol handler remotely and invoke it to execute arbitrary code on the remote host. The idea is to simply invoke start handler:// to execute commands and evade detection.
	* **Port-Forwarding & Proxies**<a name="latpfp"></a>
		* [Port Forwarding in Windows - WindowsOSHub](http://woshub.com/port-forwarding-in-windows/)
		* [WinPortPush](https://github.com/itsKindred/winPortPush)
			* win PortPush is a small PowerShell utility used for pivoting into internal networks upon compromising a Windows public-facing host.
	* **RDP**<a name="latrdp"></a>
		* [Remote Desktop Services Shadowing – Beyond the Shadowed Session - Roman Maximov(2020)](https://swarm.ptsecurity.com/remote-desktop-services-shadowing/)
		* [RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation - Kevin Beaumont])(https://doublepulsar.com/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
		* [RDPInception - MDsec](https://www.mdsec.co.uk/2017/06/rdpinception/)
		* [The RDP Through SSH Encyclopedia - Carrie Roberts](https://www.blackhillsinfosec.com/the-rdp-through-ssh-encyclopedia/)
			* I have needed to remind myself how to set up RDP access through an SSH connection so many times that I’ve decided to document it here for future reference. I hope it proves useful to you as well. I do “adversary simulation” for work and so I present this information using terms like “attacker” and “target” but this info is also useful for performing system administration tasks.
		* [Remote Desktop tunneling tips & tricks - Maurizio Agazzini](https://techblog.mediaservice.net/2019/10/remote-desktop-tunneling-tips-tricks/)
		* [Jumping Network Segregation with RDP - Rastamouse](https://rastamouse.me/2017/08/jumping-network-segregation-with-rdp/)
		* [Revisiting Remote Desktop Lateral Movement - 0xthirteen(2020)](https://0xthirteen.com/2020/01/21/revisiting-remote-desktop-lateral-movement/)
			* Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
	* **Registry-related**<a name="latr"></a>
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [WMIReg](https://github.com/airzero24/WMIReg)
				* This PoC was started from a code snippet of @harmj0y's that I thought was pretty cool. Using the StdRegProv management class through WMI, you are able to read and write to local and remote registry keys. This doesn't seem very special, but the biggest advantage is that remote registry interaction is done through WMI, therefore it does not require the Remote Registry service to be enabled/started on the remote host!
	* **SCM**<a name="latscm"></a>
		* **Articles/Blogposts/Writeups**
			* [Lateral Movement — SCM and DLL Hijacking Primer - Dwight Hohnstein](https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992)
		* **Tools**
	* **Services**<a name="latservices"></a>
		* **Articles/Blogposts/Writeups**
			* [Lateral Movement – Services - netbiosx(2020)](https://pentestlab.blog/2020/07/21/lateral-movement-services/)
		* **Tools**
			* [MoveScheduler](https://github.com/mez-0/MoveScheduler)
				* "MoveScheduler is another weekend binge that focuses on lateral movement via several different methods of scheduling tasks"
			* [SharpMove](https://github.com/0xthirteen/SharpMove)
			* [SCShell](https://github.com/Mr-Un1k0d3r/SCShell)
				* SCShell is a fileless lateral movement tool that relies on ChangeServiceConfigA to run commands. The beauty of this tool is that it does not perform authentication against SMB. Everything is performed over DCERPC.
	* **ShadowMove**<a name="latshadow"></a>
		* [ShadowMove: Lateral Movement by Duplicating Existing Sockets - @spotheplanet](https://www.ired.team/offensive-security/lateral-movement/shadowmove-lateral-movement-by-stealing-duplicating-existing-connected-sockets)
		* [Windows ShadowMove Socket Duplication](https://github.com/0xcpu/winsmsd)
			* The tool (/POC) is a simple programming exercise in order to replicate the socket duplication technique explained in [ShadowMove: A Stealthy Lateral Movement Strategy](https://www.usenix.org/system/files/sec20summer_niakanlahiji_prepub.pdf).
	* **SMB**<a name="latsmb"></a>
		* **Articles/Blogposts/Writeups**
			* [Lateral movement: A deep look into PsExec - Daniel Munoz(2018)](https://www.contextis.com/en/blog/lateral-movement-a-deep-look-into-psexec)
		* **Tools**
			* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
				* A swiss army knife for pentesting networks 
	* **SSH**<a name="latssh"></a>
		* **Articles/Blogposts/Writeups**
			* [SSH Command - ssh.com](https://www.ssh.com/ssh/command/)
			* [SSH tunnel - ssh.com](https://www.ssh.com/ssh/tunneling/)
			* [SSH Port Forwarding Example - ssh.com](https://www.ssh.com/ssh/tunneling/example/)
			* [SSH Essentials: Working with SSH Servers, Clients, and Keys - Justin Ellingwood(2014)](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys)
			* [SSH/OpenSSH/PortForwarding - help.ubuntu](https://help.ubuntu.com/community/SSH/OpenSSH/PortForwarding)
	* **WinRM**<a name="latwinrm"></a>
		* **101**
			* [About Windows Remote Management - docs.ms](https://docs.microsoft.com/en-us/windows/win32/winrm/about-windows-remote-management)
			* [Authentication for Remote Connections - docs.ms](https://docs.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections?redirectedfrom=MSDN)
			* [Is WinRM Secure or do I need HTTPs? - Stephen Owen(2017)](https://foxdeploy.com/2017/02/08/is-winrm-secure-or-do-i-need-https/)
		* **Articles/Blogposts/Writeups**
			* [Windows Remote Management - dmcxblue](https://dmcxblue.gitbook.io/red-team-notes/lateral-movement/windows-remote-management)
			* [WS-Management COM: Another Approach for WinRM Lateral Movement - bohops(2020)](https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/)
			* [WinRM Penetration Testing - Yashika Dhir(2020)](https://www.hackingarticles.in/winrm-penetration-testing/)
			* [Lateral Movement Using WinRM and WMI - Tony Lambert(2017)](https://redcanary.com/blog/lateral-movement-winrm-wmi/)
			* [Lateral Movement – WinRM - pentestlab.blog(2018)](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)
			* [T1028: WinRM for Lateral Movement - @spottheplanet](https://www.ired.team/offensive-security/lateral-movement/t1028-winrm-for-lateral-movement)
		* **Tools**
 			* [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
 				* The ultimate WinRM shell for hacking/pentesting 
			* [WS-Management COM: Another Approach for WinRM Lateral Movement - BOHOPS(2020)](https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/)
			* [WSMan-WinRM](https://github.com/bohops/WSMan-WinRM)
				*  A collection of proof-of-concept source code and scripts for executing remote commands over WinRM using the WSMan.Automation COM object 			
			* [rudder](https://github.com/MSAdministrator/rudder)
				* rudder is a Python package to run commands remotely on Windows, macOS or nix systems using PowerShell Remoting/WinRM or SSH.
	* **WMI**<a name="latwmi"></a>
		* **101**
		* **Articles/Blogposts/Writeups**
			* [T1047: WMI for Lateral Movement - @spottheplanet](https://www.ired.team/offensive-security/lateral-movement/t1047-wmi-for-lateral-movement)
			* [Lateral Movement: WMI - Pavandeep Singh(2020)](https://www.hackingarticles.in/lateral-movement-wmi/)
			* [No Win32_Process Needed – Expanding the WMI Lateral Movement Arsenal - Philip Tsukerman](https://www.cybereason.com/blog/no-win32-process-needed-expanding-the-wmi-lateral-movement-arsenal?hs_preview=UbvcDFUZ-5764480077)
			* [Lateral Movement in an Environment with Attack Surface Reduction - Michael Bielenberg(2019)](https://ionize.com.au/lateral-movement-in-an-environment-with-attack-surface-reduction/)
			* [I Like to Move It: Windows Lateral Movement Part 1 – WMI Event Subscription - Dominic Chell(2020)](https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/)
		* **Papers**
			* [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor - Matt Graeber(2015)](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
			* [No Win32_Process Needed – Expanding the WMI Lateral Movement Arsenal - Philip Tsukerman(2018)](https://conference.hitb.org/hitbsecconf2018ams/materials/D2T1%20-%20Philip%20Tsukerman%20-%20Expanding%20Your%20WMI%20Lateral%20Movement%20Arsenal.pdf)
		* **Tools**
			* [WMI Shell Tool](https://github.com/secabstraction/Create-WMIshell)
				* The WMI shell tool that we have developed allows us to execute commands and get their output using only the WMI infrastructure, without any help from other services, like the SMB server. With the wmi-shell tool we can execute commands, upload files and recover Windows passwords remotely using only the WMI service available on port 135.
			* [WMIcmd](https://github.com/nccgroup/WMIcmd)
				* A command shell wrapper using only WMI for Microsoft Windows
			* [WMIHACKER](https://github.com/360-Linton-Lab/WMIHACKER)
				* A Bypass Anti-virus Software Lateral Movement Command Execution Tool 
	* **WSH**
		* [Lateral Movement using WSHController/WSHRemote objects (IWSHController and IWSHRemote interfaces) - hexacorn(2018)](https://www.hexacorn.com/blog/2018/08/18/lateral-movement-using-wshcontroller-wshremote-objects-iwshcontroller-and-iwshremote-interfaces/)
	* **(Ab)Using 'Legitimate' Applications Already Installed**<a name="latabuse"></a>
		* [How I Hacked Into Your Corporate Network Using Your Own Antivirus Agent - Angelo Ruwantha](https://pentestmag.com/how-i-hacked-into-your-corporate-network-using-your-own-anti-virus-agent/)
			* Code exec through admin access to eset admin console
		* [Abusing Common Cluster Configuration for Lateral Movement](https://www.lares.com/abusing-common-cluster-configuration-privileged-lateral-movement/)
			* Tech sites have published articles that walk a Windows Systems Administrator through the process of adding a machine account to the Local Administrators group on another machine. These accounts end in a $ (dollar sign) and look like SERVER$ in Active Directory. While this may be useful for simplifying the installation of clusters such as Lync, Exchange, or SQL Server, it’s not always the best idea. Servers that are set up in this way weaken the overall security posture of the cluster, and ultimately the organization, by allowing a single vulnerability or misconfiguration on one server the ability to move laterally without having to escalate privileges or compromise additional credentials. Using SQL Server as the example, any user who has READ permissions to a database essentially has SYSTEM-level permissions on a remote server. We’ll walk through that path below.
		* [Abusing Firefox in Enterprise Environments - MDSec](https://www.mdsec.co.uk/2020/04/abusing-firefox-in-enterprise-environments/)
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
	* **Generic**
		* [Pillager](https://github.com/brittonhayes/pillager)
			* Pillager is designed to provide a simple means of leveraging Go's strong concurrency model to recursively search directories for sensitive information in files. Pillager does this by standing on the shoulders of a few giants. Once pillager finds files that match the specified pattern, the file is scanned using a series of concurrent workers that each take a line of the file from the job queue and hunt for sensitive pattern matches. The available pattern filters can be defined in a rules.toml file or you can use the default ruleset.
	* **Browser**<a name="cb"></a>
		* [Adamantium-Thief](https://github.com/LimerBoy/Adamantium-Thief)
			* Get chromium based browsers: passwords, credit cards, history, cookies, bookmarks, autofill.
		* [BrowserStealer](https://github.com/SaulBerrenson/BrowserStealer)
	* **CC**<a name="ccc"></a>
		* [SearchForCC](https://github.com/eelsivart/SearchForCC)
			* A collection of open source/common tools/scripts to perform a system memory dump and/or process memory dump on Windows-based PoS systems and search for unencrypted credit card track data.
	* **Code Storage**<a name="ccs"></a>
		* [dvcs-ripper](https://github.com/kost/dvcs-ripper)
			* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even when directory browsing is turned off.
		* [cred_scanner](https://github.com/disruptops/cred_scanner)
			* A simple command line tool for finding AWS credentials in files. Optimized for use with Jenkins and other CI systems.
	* **KeePass**<a name="ckp"></a>
		* [KeeFarce](https://github.com/denandz/KeeFarce)
			* Extracts passwords from a KeePass 2.x database, directly from memory.
		* [KeeThief](https://github.com/HarmJ0y/KeeThief)
			* Methods for attacking KeePass 2.X databases, including extracting of encryption key material from memory.
	* **Outlook**<a name="cout"></a>
		* [Pillaging .pst Files](https://warroom.securestate.com/pillaging-pst-files/)
	* **PCAP/Live Interface**<a name="cpcap"></a>
		* [net-creds](https://github.com/DanMcInerney/net-creds)
			* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification.
		* [PCredz](https://github.com/lgandx/PCredz)
			* This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
	* **Skype**<a name="cskype"></a>
		* [skype log viewer](https://github.com/lordgreggreg/skype-log-viewer)
			* Download and View Skype History Without Skype This program allows you to view all of your skype chat logs and then easily export them as text files. It correctly organizes them by conversation, and makes sure that group conversations do not get jumbled with one on one chats.
	* **Video Streaming**<a name="cvideo"></a>
		* [Stream a target's Desktop using MJPEG and PowerShell - Nikhil Mittal(2015)](http://www.labofapenetrationtester.com/2015/12/stream-targets-desktop-using-mjpeg-and-powershell.html)
* **Exfiltration**
	* **Articles/Blogposts/Writeups**
		* [WMI & PowerShell: An Introduction to Copying Files - FortyNorthSecurity](https://fortynorthsecurity.com/blog/wmi/)
----------------------------------------------------------------------------------------------------------------------------------






































----------------------------------------------------------------------------------------------------------------------------------
#### Windows Technologies<a name="wintech"></a>
* **Alternate Data Streams**<a name="wads"></a>
	* **101**
		* 
* **AppLocker**<a name="winapplocker"></a>
	* **101**
		* [AppLocker - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
			* This topic provides a description of AppLocker and can help you decide if your organization can benefit from deploying AppLocker application control policies. AppLocker helps you control which apps and files users can run. These include executable files, scripts, Windows Installer files, dynamic-link libraries (DLLs), packaged apps, and packaged app installers.
		* [What Is AppLocker? - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)
		* [AppLocker design guide - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-design-guide)
		* [AppLocker deployment guide - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-deployment-guide)
		* [AppLocker technical reference - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-technical-reference)
		* [How AppLocker works - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/how-applocker-works-techref)
		* [Security considerations for AppLocker - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/security-considerations-for-applocker)
	* **Articles/Blogposts/Writeups**
		* [Getting Started With AppLocker - John Strand(2019)](https://www.blackhillsinfosec.com/getting-started-with-applocker/)
		* [Script Rules in AppLocker - technet](https://technet.microsoft.com/en-us/library/ee460958.aspx)
		* [DLL Rules in AppLocker](https://technet.microsoft.com/en-us/library/ee460947.aspx)
		* [Application Whitelisting Using Microsoft AppLocker](https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)
		* [Harden Windows with AppLocker – based on Case study Part 1 - oddvar.moe](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
		* [Harden Windows with AppLocker – based on Case study part 2 - oddvar.moe](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
		* [AppLocker Case study: How insecure is it really? Part 1 oddvar.moe](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-1/)
		* AppLocker Case study: How insecure is it really? Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
	* **Talks/Presentations/Videos**
* **Application Shims**<a name="winappshim"></a>
	* [Windows - Application Shims](https://technet.microsoft.com/en-us/library/dd837644%28v=ws.10%29.aspx)
* **AutoDiscover**
	* **Articles/Blogposts/Writeups**
		* [Outlook 2016 implementation of Autodiscover - support.ms](https://support.microsoft.com/en-au/help/3211279/outlook-2016-implementation-of-autodiscover)
		* [Fixing Autodiscover Root Domain Lookup Issues for Mobile Devices - Paul Cunningham(2016)](https://practical365.com/exchange-server/fixing-autodiscover-root-domain-lookup-issues-mobile-devices/)
		* [Obtaining Corporate Credentials via the Autodiscover Circus - lolware(2020)](https://lolware.net/2020/09/02/autodiscover-circus.html)
* **BitLocker**<a name="bitlocker"></a>
	* **101**
	* **Bypassing**
		* [BitLocker Lockscreen bypass - Jonas Lyk(2021)](https://secret.club/2021/01/15/bitlocker-bypass.html)
* **ClickOnce Applications**<a name="clickonce"></a>
	* [ClickOnce - Wikipedia](https://en.wikipedia.org/wiki/ClickOnce)
	* [ClickOnce security and deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2019)
	* [ClickOnce Deployment for Windows Forms - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/winforms/clickonce-deployment-for-windows-forms)
	* [ClickOnce Applications in Enterprise Environments - Remko Weijnen](https://www.remkoweijnen.nl/blog/2013/08/05/clickonce-applications-in-enterprise-environments/)
		* ClickOnce is a Microsoft technology that enables an end user to install an application from the web without administrative permissions.
	* [Eight Evil Things Microsoft Never Showed You in the ClickOnce Demos (and What You Can Do About Some of Them) - Chris Williams](https://www.codemag.com/Article/0902031/Eight-Evil-Things-Microsoft-Never-Showed-You-in-the-ClickOnce-Demos-and-What-You-Can-Do-About-Some-of-Them)
* **Credential Guard/Device Guard/Application Guard**<a name="credguard"></a>
	* **101**
		* [Protect derived domain credentials with Windows Defender Credential Guard - docs.ms(2017)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
		* [How Windows Defender Credential Guard works - docs.ms(2017)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)
		* [Device Guard signing - docs.ms(2017)](https://docs.microsoft.com/en-us/microsoft-store/device-guard-signing-portal)
		* [Windows Defender System Guard: How a hardware-based root of trust helps protect Windows 10 - docs.ms(2019)](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-how-hardware-based-root-of-trust-helps-protect-windows)
		* [Microsoft Defender Application Guard overview - docs.ms(2021](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/md-app-guard-overview)
		* [Microsoft Edge support for Microsoft Defender Application Guard - docs.ms(2021)](https://docs.microsoft.com/en-us/deployedge/microsoft-edge-security-windows-defender-application-guard)
		* [Windows 10 Device Guard and Credential Guard Demystified - Priyanka Pillai(2021)](https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419)
		* [Application Guard testing scenarios - docs.ms(2020)](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/test-scenarios-md-app-guard)
		* [Windows Defender Application Control and virtualization-based protection of code integrity - docs.ms(2021)](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control)
		* [Frequently asked questions - Microsoft Defender Application Guard - docs.ms(2021)](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/faq-md-app-guard)
	* **Articles/Blogposts/Writeups**
		* [Windows Credential Guard & Mimikatz - Didier Stevens(2018)](https://blog.nviso.eu/2018/01/09/windows-credential-guard-mimikatz/)
		* [How Windows Defender Credential Guard Works - Steve Syfuhs(2020](https://syfuhs.net/how-windows-defender-credential-guard-works)
		* [Bypassing Credential Guard - N4kedTurtle(2020)](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/)
	* **Talks/Presentations/Videos**
		* [Sneaking Past Device Guard - Philip Tsukerman(HITB2019 Amsterdam)](https://www.youtube.com/watch?v=uxTuHL94Rn4)
			* This talk will exhibit rarely discussed and novel techniques to bypass Device Guard, some requiring admin access, some requiring Microsoft Office (but no user interaction), and one available under low privileges and using nothing but native OS executables. All techniques presented will eventually allow an attacker to run arbitrary code without disabling Device Guard. As of now, Microsoft decided not to service most of these techniques with an update (except for one which will be serviced as CVE-2018-8417).
	* **Tools**
* **Code Signing**<a name="codesign"></a>
	* **Articles/Blogposts/Writeups**
		* [Windows File Confusion: Masquerading Unsigned Binaries as Signed Ones - Matt Graeber(2013)](http://www.exploit-monday.com/2013/02/WindowsFileConfusion.html)
		* [Inside Code Signing - Thomas 'toto' Kollbach(2014)](https://www.objc.io/issues/17-security/inside-code-signing/)
		* [Code Signing Certificate Cloning Attacks and Defenses - Matt Graeber](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
		* [MetaTwin – Borrowing Microsoft Metadata and Digital Signatures to “Hide” Binaries - Joe Vest(2017)](https://web.archive.org/web/20190303110249/http://threatexpress.com/2017/10/metatwin-borrowing-microsoft-metadata-and-digital-signatures-to-hide-binaries/)
		* [Borrowing Microsoft Code Signing Certificates - lopi(2017)](https://blog.conscioushacker.io/index.php/2017/09/27/borrowing-microsoft-code-signing-certificates/)
		* [Application of Authenticode Signatures to Unsigned Code - mattifestation(2017)](http://www.exploit-monday.com/2017/08/application-of-authenticode-signatures.html)
		* [Subverting Trust in Windows - Matt Graeber](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
		* [Masquerading as a Windows System Binary Using Digital Signatures - Stuart Morgan](https://labs.mwrinfosecurity.com/archive/masquerading-as-a-windows-system-binary-using-digital-signatures/)
		* [Hijack Digital Signatures – PowerShell Script - pentestlab.blog(2017)](https://pentestlab.blog/2017/11/08/hijack-digital-signatures-powershell-script/)
		* [Code Signing Certificates - Barry Vengerik(FireEye Summit(2019)](https://www.youtube.com/watch?v=J8WGJtCy0ek)
		* [Code Signing on a Budget - @Jackson_T(2020)](http://jackson-t.ca/certificate-theft.html)
			* "Summary: This post goes over how attackers could use search engines to find and abuse legitimate code-signing certificates. With this technique, I was able to find a valid code-signing certificate belonging to a leading tech company and disclosed it to them. This isn't particularly novel but I'm writing this to raise defensive awareness that abusing code-signing certificates is not limited to well-resourced attackers."
		* [CarbonCopy](https://github.com/paranoidninja/CarbonCopy)
			* A tool which creates a spoofed certificate of any online website and signs an Executable for AV Evasion. Works for both Windows and Linux
		* [Signing .jar files with an existing certificate on Windows - Chad Duffey(2020)](https://www.chadduffey.com/2020/06/Signing-JAR.html)
	* **Talks/Videos**
		* [Hi, My Name is "CN=Microsoft Windows, O=Microsoft Corporation… - Matt Graeber(BlueHat IL 2018)](https://www.youtube.com/watch?v=I3jCGBzMmzw)
			* [Slides](http://www.bluehatil.com/files/Matt%20Graeber%20BlueHat%20IL%202018.pdf)
		* [Subverting Sysmon - Application of a Formalized Security Product Evasion Method - Matt Graeber, Lee Christensen(BHUSA18)](https://i.blackhat.com/us-18/Wed-August-8/us-18-Graeber-Subverting-Sysmon-Application-Of-A-Formalized-Security-Product-Evasion-Methodology.pdf)
	* **Tools**
		* [certerator](https://github.com/stufus/certerator)
			* This is the code relating to a project to simplify the act of creating a CA, signing a binary with the CA and then installing the CA on the target machine. It investigates the extent to which this can be achieved without the benefit of a GUI and shows how this can be modified to generate valid EV certificates which are trusted by Windows. It is intended for penetration testers who are looking to install an implant binary which looks as legitimate as possible. None of these techniques are new, but it is hoped that this tool and project will make them easier and more accessible.
		* [LimeLighter](https://github.com/Tylous/Limelighter)
			* "A tool which creates a spoof code signing certificates and sign binaries and DLL files to help evade EDR products and avoid MSS and sock scruitney. LimeLighter can also use valid code signing certificates to sign files. Limelighter can use a fully qualified domain name such as acme.com."
* **Containers**
	* **101**
* **(Distributed) Component-Object-Model(COM)**<a name="dcom"></a>		
	* [COM_Mapper](https://github.com/hotnops/COM_Mapper)
	* **101**
		* [Component Object Model - Wikipedia](https://en.wikipedia.org/wiki/Component_Object_Model)
		* [Distributed Component Object Model - Wikipedia](https://en.wikipedia.org/wiki/Distributed_Component_Object_Model)
		* [DCOM Technical Overview - docs.ms(2014]((https://docs.microsoft.com/en-us/previous-versions//cc722925(v=technet.10)?redirectedfrom=MSDN)
		* [The Component Object Model - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model)
			* COM is a platform-independent, distributed, object-oriented system for creating binary software components that can interact. COM is the foundation technology for Microsoft's OLE (compound documents) and ActiveX (Internet-enabled components) technologies.
		* [[MS-DCOM]: Distributed Component Object Model (DCOM) Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0)
			* Specifies the Distributed Component Object Model (DCOM) Remote Protocol, which exposes application objects via remote procedure calls (RPCs) and consists of a set of extensions layered on the Microsoft Remote Procedure Call Extensions.
		* [[MS-RPCE]: Remote Procedure Call Protocol Extensions - msdn.ms](https://msdn.microsoft.com/en-us/library/cc243560.aspx)
		* [Guide(to COM) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/guide)
			* This guide introduces the Microsoft Component Object Model (COM).
		* [COM Fundamentals - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/com-fundamentals)
		* [COM Objects and Interfaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/com-objects-and-interfaces)
			* COM is a technology that allows objects to interact across process and computer boundaries as easily as within a single process. COM enables this by specifying that the only way to manipulate the data associated with an object is through an interface on the object. When this term is used in this documentation, it refers to an implementation in code of a COM binary-compliant interface that is associated with an object.
		* [COM Reference - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/reference)
		* [COM Glossary](https://docs.microsoft.com/en-us/windows/win32/com/com-glossary)
	* **Articles/Blogposts/Writeups**
		* [Component Object Model Technical Overview -  The ActiveX Core Technology Reference(1999)](https://pubs.opengroup.org/onlinepubs/009899899/CHP03CHP.HTM)
		* [Mike Panitz's Introduction to COM](https://faculty.cascadia.edu/mpanitz/COM_Tutorial/index.htm)
		* [The Component Object Model: Technical Overview(1994)](https://www.cs.umd.edu/~pugh/com/)
			* This paper is adapted from an article appearing in Dr. Dobbs Journal, December 1994. 
		* [Exploiting .NET Managed DCOM - James Forshaw(2017)](https://googleprojectzero.blogspot.com/2017/04/exploiting-net-managed-dcom.html)
			* One of the more interesting classes of security vulnerabilities are those affecting interoperability technology. This is because these vulnerabilities typically affect any application using the technology, regardless of what the application actually does. Also in many cases they’re difficult for a developer to mitigate outside of not using that technology, something which isn’t always possible. I discovered one such vulnerability class in the Component Object Model (COM) interoperability layers of .NET which make the use of .NET for Distributed COM (DCOM) across privilege boundaries inherently insecure. This blog post will describe a couple of ways this could be abused, first to gain elevated privileges and then as a remote code execution vulnerability.
		* [Finding and Identifying JScript/VBScript Callable COM Objects - Christopher Paschen(2019](https://www.trustedsec.com/blog/finding-and-identifying-jscript-vbscript-callable-com-objects/)
		* [Abusing Catalog Hygiene to Bypass Application Whitelisting - BOHOPS(2019)](https://bohops.com/2019/05/04/abusing-catalog-file-hygiene-to-bypass-application-whitelisting/)		
		* [COM and the PowerThIEf - Rob Malsen](https://labs.nettitude.com/blog/com-and-the-powerthief/)
		* [The OXID Resolver [Part 1] – Remote enumeration of network interfaces without any authentication - Airbus(2020)](https://airbus-cyber-security.com/fr/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/amp/)
		* [Discovering and exploiting McAfee COM-objects (CVE-2021-23874) - Denis Skvortcov(2021)](https://the-deniss.github.io/posts/2021/05/17/discovering-and-exploiting-mcafee-com-objects.html)
		* [Automating Microsoft Office to Achieve Red Teaming Objectives - wunderwuzzi(2021)](https://embracethered.com/blog/posts/2021/automating-office-to-achieve-redteaming-objectives/)
	* **Talks/Presentations/videos**
		* [Exploiting DCOM - Yoshiaki Komoriya, Hidenobu Seki(2002)](https://web.archive.org/web/20071215152948/http://www.blackhat.com/html/win-usa-03/win-usa-03-speakers.html#Yoshiaki%20Komoriya)
		* [COM in Sixty Seconds! (well minutes more likely) - James Forshaw(Infiltrate2017)](https://vimeo.com/214856542)
		* [COM Under The Radar Circumventing Application Control Solutions - Jimmy Bayne(BSides Charm2019)](https://www.youtube.com/watch?v=shsEpbpQL-Y)
			* Application Control is the practice of restricting unauthorized code execution. Application Whitelisting (AWL) is the most popular approach, which permits code execution from trusted applications based on managed policies and rules. This talk will highlight several ways to bypass AWL policies using the Component Object Model (COM) and provide recommendations to defend against such techniques.
		* [COM-PROMISE Attacking Windows development environments - Stan Hegt - (Nullcon Goa2020)](https://www.youtube.com/watch?v=1cgBv8X-oNw&list=PLWv48qIcomCY1klVobWUQfkFNysQY47B0&index=28&t=108s)
			* [Slides](https://github.com/outflanknl/Presentations/blob/master/Nullcon2020_COM-promise_-_Attacking_Windows_development_environments.pdf)
			* In this talk we will demonstrate how compiling, reverse engineering or even just viewing source code can lead to compromise of a developer’s workstation. With the emergence of code sharing platforms such as GitHub, it has become common practice to download and view potentially untrusted code. However, due to the way in which integrated development environments for Windows interact with code and the Component Object Model (COM), such behavior can be exploited by attackers to achieve remote code execution. Our research presents full and practical exploit chains for Visual Studio that demonstrate that opening (not running!) code is dangerous. Expect a journey into COM, type libraries and the inner workings of Visual Studio.
	* **Papers**
		* [The Dangers of Per-User COM Objects - Jon Larimer(2011)](https://www.virusbulletin.com/uploads/pdf/conference_slides/2011/Larimer-VB2011.pdf)
		* [Automating the enumeration of possibleDCOM vulnerabilities - Axel Boesenach(2018)](https://hackdefense.com/assets/downloads/automating-the-enumeration-of-possible-dcom-vulnerabilities-axel-boesenach-v1.0.pdf)
			* This paper describes the research into DCOM applications that might be used forlateral movement on Microsoft Windows domains. ’Living off the land’ techniquesare used more and more by attackers, but also pentesters and red teams. The re-search builds on the previous methods and their correlations to develop an auto-mated manner to enumerate these DCOM applications that might provide lateralmovement.
	* **COM Hijacking**
		* **Articles/Blogposts/Writeups**
			* [Hunting COM Objects - Charles Hamilton(2019)](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html)
			* [Abusing the COM Registry Structure: CLSID, LocalServer32, & InprocServer32 - BOHOPS(2018)](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
			* [COM Hijacking – Windows Overlooked Security Vulnerability - Yaniv Assor](https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/)
			* [Abusing COM objects - 0xpat](https://0xpat.github.io/Abusing_COM_Objects/)
			* [Hunting COM Objects - Charles Hamilton(2019)](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html)
			* [Hunting COM Objects (Part Two) - Brett Hawkins(2019)](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects-part-two.html)
		* **Talks/Presentations/Videos**
			* [COM Hijacking Techniques - David Tulis(Derbycon2019](https://www.irongeek.com/i.php?page=videos/derbycon9/3-07-com-hijacking-techniques-david-tulis)
				* [Slides](https://www.slideshare.net/DavidTulis1/com-hijacking-techniques-derbycon-2019)
				* The COM interface lies at the core of Windows, and subtle registry changes can interfere with this the OS in unexpected ways. COM hijacking allows an attacker to load a library into a calling COM-enabled process. It?s a feature, not a bug. While it is commonly used for persistence, some famous COM hijacks have led to more severe exploits. COM hijacking is already used by several families of malware, and it?s time that pentesters caught up on how to abuse this feature. This presentation will cover COM hijacking from start to finish; showing how discover hijackable COM objects, how to use them offensively, and how to make the calling process remain stable. The blue team will not be forgotten; the talk will cover detection strategies for identifying and defending against COM hijacks.
			* [Dancing with COM - Deep dive into understanding Component Object Model -  DuMp-GuY TrIcKsTeR(2021)](https://www.youtube.com/watch?v=8tjrFm2K30Q)
				* Content: What is The Microsoft Component Object Model (COM); Functionality of COM; COM in Registry (Tools - COM viewers); COM Client-Server (Using Powershell/.NET COM Client); Reversing COM instances and methods in IDA (Structures, Types, ComIDA plugin); Interesting way of using COM Method in LokiBot malware sample
	* **COM Proxying**
		* **Articles/Blogposts/Writeups**
			* [Proxying COM For Stable Hijacks - leolobeek(2019)](https://adapt-and-attack.com/2019/08/29/proxying-com-for-stable-hijacks/)
	* **Tools**
		* Helpful
			* [COMMethodSearcher](https://github.com/hausec/COMMethodSearcher)
				* Script that searches through all COM objects for any methods containing a key word of your choosing. 
			* [DCOMrade](https://github.com/sud0woodo/DCOMrade)
				* [Article](https://hackdefense.com/blog/DCOMrade-automating-the-enumeration-of-DCOM-applications/)
				* Powershell script for enumerating vulnerable DCOM Applications 
			* [Go OLE](https://github.com/go-ole/go-ole)
				* Go bindings for Windows COM using shared libraries instead of cgo.
			* [ReaCOM](https://github.com/homjxi0e/ReaCOM)
		* Discovery
			* [OxidBindings](https://github.com/vletoux/OxidBindings)
				*  Extract all IP of a computer using DCOM without authentication (aka detect network used for administration)
			* [COM_Mapper](https://github.com/hotnops/COM_Mapper)
				* A tool to create COM class/interface relationships in neo4j. It is designed to be run once on a developer system, and it will take a few hours to complete. Once completed, a user can issue cypher queries via Neo4j and get COM class/interface relationships. This is very much a quick and dirty prototype that was created to serve my needs for doing Microsoft Office OLE research. Please feel free to expand or shoot me ideas to make this better.
		* Hijacking
			* [acCOMplice](https://github.com/nccgroup/acCOMplice)
			* [MessageBox](https://github.com/enigma0x3/MessageBox)
				* PoC dlls for Task Scheduler COM Hijacking
			* [PS1jacker](https://github.com/cybercitizen7/Ps1jacker)
				* Ps1jacker is a tool for generating COM Hijacking payload.
			* [COMProxy](https://github.com/leoloobeek/COMProxy)
				* A COM client and server for testing COM hijack proxying. If you are running a COM hijack, proxying the legitimate COM server may result in better stability, thats the idea around this PoC.
			* [COM-Hijacking](https://github.com/SolomonSklash/COM-Hijacking)
				* An example of COM hijacking using a proxy DLL.
		* Lateral Movement
			* [DVS](https://github.com/ScorpionesLabs/DVS)
				* D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects 
		* Privilege Escalation
			* [COMahawk](https://github.com/apt69/COMahawk)
				* Privilege Escalation: Weaponizing CVE-2019-1405 and CVE-2019-1322
	* **Execution**
		* [Building a COM Server for Initial Execution - leoloobeek(2020)](https://adapt-and-attack.com/2020/05/12/building-a-com-server-for-initial-execution/)
			* This post will expand on previous research and cover writing your own COM server DLL, loading it from scripting languages with registration-free activation, and discussion around weaponization and OPSEC. This was a personal journey that helped me learn a lot more about what happens when you create and use a COM object from JScript. I will also be releasing a PoC COM server that runs provided shellcode.
		* **Tools**
			* [COMRunner](https://github.com/leoloobeek/COMRunner)
				* A simple COM server which provides a component to run shellcode. Also includes a Windows JScript file to load the COM server and create the object with registration-free activation. This PoC COM server provides an object with a method that takes in base64 encoded shellcode and a method to run the shellcode.
	* **Serialization/Marshalling**
		* [Marshalling to SYSTEM - An analysis of CVE-2018-0824 - codewhitesec](https://codewhitesec.blogspot.com/2018/06/cve-2018-0624.html)
			* [Code](https://github.com/codewhitesec/UnmarshalPwn)
	* **Programming with**
		* **C#**
		* **C/C++**
		* **Python**
		* **VBA**
			* [VB Programmers are COM Programmers - James Cleverley()](http://www1.idc.ac.il/ed/An%20introduction%20to%20COM%20for%20VB%20programmers.htm)
* **Containers(Windows)**
	* **101**
			* [Containers on Windows documentation - docs.ms](https://docs.microsoft.com/en-us/virtualization/windowscontainers/)
			* [Base image servicing lifecycles - docs.ms(2021)](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/base-image-lifecycle)
	* **Articles**
		* [What I Learned from Reverse Engineering Windows Containers - Daniel Prizmant(2019](https://unit42.paloaltonetworks.com/what-i-learned-from-reverse-engineering-windows-containers/)
* **DLLs**<a name="dll"></a>
	* **101**
		* [What is a DLL? - support.ms](https://support.microsoft.com/en-us/help/815065/what-is-a-dll)
		* [Dynamic-Link-Library - Wikipedia](https://en.wikipedia.org/wiki/Dynamic-link_library)
		* [DLL Hell - Wikipedia](https://en.wikipedia.org/wiki/DLL_Hell)
		* [Dynamic-Link Library Redirection - doc.ms](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection)
			* Applications can depend on a specific version of a shared DLL and start to fail if another application is installed with a newer or older version of the same DLL. There are two ways to ensure that your application uses the correct DLL: DLL redirection and side-by-side components. Developers and administrators should use DLL redirection for existing applications, because it does not require any changes to the application. If you are creating a new application or updating an application and want to isolate your application from potential problems, create a side-by-side component.
	* **Articles/Blogposts/Writeups**
		* [What is `*.local` file in windows ? - abcdef(2020)](https://heynowyouseeme.blogspot.com/2020/05/what-is-local-file-in-windows.html)
		* [Debugging DLL’s – 3 techniques to help you get started - Jean-François Maes(2020)](https://blog.nviso.eu/2020/08/04/debugging-dlls-3-techniques-to-help-you-get-started/)
		* [Using Pragmas to Create a Proxy DLL - Kontza(2007)](https://www.codeproject.com/Articles/17863/Using-Pragmas-to-Create-a-Proxy-DLL)
			* This article explains a way to create a Proxy DLL employing the MSVC compiler `'#pragma comment'` feature.
		* [Quickpost: DllDemo - Didier Stevens(2017)](https://blog.didierstevens.com/2017/09/08/quickpost-dlldemo/)
		* [How to turn a DLL into a standalone EXE - Hasherezade(2016)](https://hshrzd.wordpress.com/2016/07/21/how-to-turn-a-dll-into-a-standalone-exe/)
			* [Staying Hidden on the Endpoint: Evading Detection with Shellcode - Evan Pena, Casey Erikson](https://www.fireeye.com/blog/threat-research/2019/10/staying-hidden-on-the-endpoint-evading-detection-with-shellcode.html)
			* [Abusing DLL Misconfigurations — Using Threat Intelligence to Weaponize R&D - Evan Pena, Ruben Boonen, Brett Hawkins](https://www.fireeye.com/blog/threat-research/2020/01/abusing-dll-misconfigurations.html)
			* [edgegdi.dll for persistence - Chad Duffey(2020)](https://www.chadduffey.com/2020/10/edgegdi.html)
			* [Abusing Delay Load DLLs for Remote Code Injection - Bryan Alexander(2017)](http://dronesec.pw/blog/2017/09/19/abusing-delay-load-dll/)
	* **Talks/Presentations/Videos**
		* [Memory-Based Library Loading: Someone Did That Already. - Casey Rosini(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t108-memory-based-library-loading-someone-did-that-already-casey-rosini)
			* The technique of using memory-based library loading has been around for a number of years. It is available in different forms and for different operating systems. It has been popularized in the security-space with long-standing techniques perhaps even longer than some are aware. And here I thought that I found or did some new evasion. This talk discusses a library for Windows that is still maintained but has been seemingly overlooked for over a decade (or has it?), and how it can be used against the next-generation securing of the digitals.
	* **Tools**
		* [CMDLL](https://github.com/jfmaes/CMDLL)
			* the most basic DLL ever to pop a cmd.
			* [DLL_to_EXE](https://github.com/hasherezade/dll_to_exe)
				* Converts a DLL into a ready-to-use EXE.
			* [DllToShellCode](https://github.com/killeven/DllToShellCode)
				* Fast Conversion Windows Dynamic Link Library To ShellCode
			* [DLLoader](https://github.com/NVISO-BE/DLLoader)
				* Surrogate DLL carrier for debugging purposes.
			* [DLL loading shellcode](https://github.com/UserExistsError/DllLoaderShellcode)
				* Shellcode to load an appended Dll 
			* [MaliciousDLLGenerator](https://github.com/Mr-Un1k0d3r/MaliciousDLLGenerator)
				* DLL Generator for side loading attack
	* **DLL Hijacking**
		* **See [DLL Stuff](#dllstuff)**
	* **DLL Hollowing**
		* **See [DLL Hollowing](#dllhollow)
	* **DLL Proxying**
		* **See [DLL Proxying](#dllproxy)
* **DPAPI** <a name="dpapi"></a>
	* **101**
		* [CNG DPAPI - docs.ms](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-dpapi)
		* [Data Protection API - Wikipedia](https://en.wikipedia.org/wiki/Data_Protection_API)
		* [DPAPI Secrets. Security analysis and data recovery in DPAPI - Passcape](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28)
		* [Windows Data Protection - docs.ms(WinXP)](https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)
		* [module ~ dpapi - mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)
	* **Articles/Blogposts/Writeups** 
		* [DPAPI Primer for Pentesters - WebstersProdigy(2013)](https://webstersprodigy.net/2013/04/05/dpapi-primer-for-pentesters/)
		* [Grab the Windows secrets! - decoder.cloud(2017)](https://decoder.cloud/2017/02/11/grab-the-windows-secrets/)
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
		* [The Blackbox of DPAPI the gift that keeps on giving - Bartosz Inglot(OPCDE2017)](https://github.com/comaeio/OPCDE/tree/master/2017/The%20Blackbox%20of%20DPAPI%20the%20gift%20that%20keeps%20on%20giving%20-%20Bartosz%20Inglot)
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
* **Device Guard**<a name="devguard"></a>
	* **101**
		* 
* **ETW**<a name="etw"></a>
	* **101**
		* [Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
		* [About Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
		* [Using Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/using-event-tracing)
		* [Writing an Instrumentation Manifest - docs.ms(2018)](https://docs.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest)
			* Applications and DLLs use an instrumentation manifest to identify their instrumentation providers and the events that the providers write. A manifest is an XML file that contains the elements that identify your provider. The convention is to use .man as the extension for your manifest. The manifest must conform to the event manifest XSD.
		* [Event Metadata Overview - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/event-metadata-overview)
		* [ETW: Event Tracing for Windows 101 - @spothteplanet](https://www.ired.team/miscellaneous-reversing-forensics/etw-event-tracing-for-windows-101)
		* [Introduction to Threat Intelligence ETW - NtRaiseHardError(2020)](https://undev.ninja/introduction-to-threat-intelligence-etw/)
		* [Windows10EtwEvents](https://github.com/jdu2600/Windows10EtwEvents)
			*  Events from all manifest-based and mof-based ETW providers across Windows 10 versions 
	* **Articles/Blogposts/Writeups**
		* [Logging Keystrokes with Event Tracing for Windows (ETW) - SRT Team(2016)](https://www.cyberpointllc.com/srt/posts/srt-logging-keystrokes-with-event-tracing-for-windows-etw.html)
		* [Hiding Your .NET – ETW - Adam Chester(2020)](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)
		* [Another method of bypassing ETW and Process Injection via ETW registration entries. - modexp(2020)](https://modexp.wordpress.com/2020/04/08/red-teams-etw/)
		* [Data Source Analysis and Dynamic Windows RE using WPP and TraceLogging - Matt Graeber(2019)](https://posts.specterops.io/data-source-analysis-and-dynamic-windows-re-using-wpp-and-tracelogging-e465f8b653f7)
		* [Hidden Treasure: Intrusion Detection with ETW, Part 1 - Zac Brown(2017)](https://zacbrown.org/hidden-treasure-intrusion-detection-with-etw-part-1/)
			* [Part 2](https://zacbrown.org/hidden-treasure-intrusion-detection-with-etw-part-2/)
		* [SilkETW: Because Free Telemetry is … Free! - Ruben Boonnen](https://www.fireeye.com/blog/threat-research/2019/03/silketw-because-free-telemetry-is-free.html)
			* [Slides](https://github.com/FuzzySecurity/BH-Arsenal-2019/blob/master/Ruben%20Boonen%20-%20BHArsenal_SilkETW_v0.2.pdf)
		* [Tampering with Windows Event Tracing: Background, Offense, and Defense - Palantir](https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
		* [Getting started with Event Tracing for Windows in C# - Alex Khanin](https://medium.com/@alexkhanin/getting-started-with-event-tracing-for-windows-in-c-8d866e8ab5f2)
		* [ETW Event Tracing for Windows and ETL Files - Nicole Ibrahim](https://www.hecfblog.com/2018/06/etw-event-tracing-for-windows-and-etl.html)
	* **Talks/Videos**
		* [Hidden Treasure: Detecting Intrusions with ETW - Zac Brown(2017)](https://www.youtube.com/watch?v=ppGmRUhQO80&feature=emb_title)
			* [Slides/Code](https://github.com/zacbrown/hiddentreasure-etw-demo)
		* [Production tracing with Event Tracing for Windows (ETW) - Doug Cook(2017)](https://channel9.msdn.com/Events/Build/2017/P4099)
		* [ETW - Monitor Anything, Anytime, Anywhere - Dina Goldshtein(NDC Oslo 2017)](https://www.youtube.com/watch?v=ZNdpLM4uIpw)
			* You’ll learn how to diagnose incredibly complex issues in production systems such as excessive garbage collection pauses, slow startup due to JIT and disk accesses, and even sluggishness during the Windows boot process. We will also explore some ways to automate ETW collection and analysis to build self-diagnosing applications that identify high CPU issues, resource leaks, and concurrency problems and produce alerts and reports. In the course of the talk we will use innovative performance tools that haven’t been applied to ETW before — flame graphs for visualising call stacks and a command-line interface for dynamic, scriptable ETW tracing. ETW is truly a window into everything happening on your system, and it doesn’t require expensive licenses, invasive tools, or modifying your code in any way. It is a critical, first-stop skill on your way to mastering application performance and diagnostics.
	* **Tools**
		* [CollectDotNetEvents.ps1](https://gist.github.com/mattifestation/444323cb669e4747373833c5529b29fb)
			* A PoC script to capture relevant .NET runtime artifacts for the purposes of potential detections 
		* [krabsetw](https://github.com/microsoft/krabsetw)
			* KrabsETW provides a modern C++ wrapper and a .NET wrapper around the low-level ETW trace consumption functions. 
		* [PerfView](https://github.com/microsoft/perfview)
			* PerfView is a free performance-analysis tool that helps isolate CPU and memory-related performance issues. It is a Windows tool, but it also has some support for analyzing data collected on Linux machines. It works for a wide variety of scenarios, but has a number of special features for investigating performance issues in code written for the .NET runtime.
		* [WindowsEventLogMetadata](https://github.com/mattifestation/WindowsEventLogMetadata)
			* Event metadata collected across all manifest-based ETW providers on Window 10 1903 
		* [NiftyETWProviders.json](https://gist.github.com/mattifestation/04e8299d8bc97ef825affe733310f7bd)
		* [TLGMetadataParser.psm1](https://gist.github.com/mattifestation/edbac1614694886c8ef4583149f53658)
			* Retrieves TraceLogging metadata from a file.
		* [EtwExplorer](https://github.com/zodiacon/EtwExplorer)
		* [SilkETW & SilkService](https://github.com/fireeye/SilkETW)
			* SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection. While both projects have obvious defensive (and offensive) applications they should primarily be considered as research tools. For easy consumption, output data is serialized to JSON. The JSON data can either be written to file and analyzed locally using PowerShell, stored in the Windows eventlog or shipped off to 3rd party infrastructure such as Elasticsearch.
		* [WEPExplorer](https://github.com/lallousx86/WinTools/tree/master/WEPExplorer)
			* This tool is very helpful when you want to explore all the Windows Event providers installed on your system and what kind of metadata they have. The Explorer GUI sports a comprehensive filter that helps you sift through a complex provider's metadata.
		* [TamperETW ](https://github.com/outflanknl/TamperETW)
			* PoC to demonstrate how CLR ETW events can be tampered.
* **Faxes & Printers**<a name="printfax"></a>	
	* **101**
		* [[MS-RPRN]: Print System Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)
		* [[MS-RPRN]: Print System Remote Protocol - msdn.ms](https://msdn.microsoft.com/en-us/library/cc244528.aspx)
	* **Articles/Blogposts/Writeups**
* **Fibers**<a name="winfibers"></a>
	* **101**
		* [Fibers - docs.ms](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers)
	* **Articles/Blogposts/Writeups**
* **File Extensions**<a name="winfex"></a>
	* [Common file name extensions in Windows - support.ms](https://support.microsoft.com/en-us/help/4479981/windows-10-common-file-name-extensions)
	* [File Types - docs.ms](https://docs.microsoft.com/en-us/windows/win32/shell/fa-file-types)
		* This topic explains how to create new file types and how to associate your app with your file type and other well-defined file types. Files with a shared common file name extension (.doc, .html, and so on) are of the same type. For example, if you create a new text editor, then you can use the existing .txt file type. In other cases, you might need to create a new file type.
	* [The case of the missing file extensions - NCCGroup(2014)](https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2014/may/the-case-of-the-missing-file-extensions/)
	* `.libary-ms`
		* [Windows Library Files (.library-ms) - Vault7](https://wikileaks.org/ciav7p1/cms/page_13763381.html)
	* `desktop.ini`
	* `.lnk`
	* `autorun.inf`
	* `.mum`
	* `.mui`
		* [MUI Poisoning in practice - Hexacorn(2020)](https://www.hexacorn.com/blog/2020/08/22/mui-poisoning-in-practice/)
	* `.pif`
			* [Program information file - Wikipedia](https://en.wikipedia.org/wiki/Program_information_file)
	* `.local`
	* `.theme`
		* [Windows Theme Files (.theme) - Vault7](https://wikileaks.org/ciav7p1/cms/page_13763384.html)
* **Hooking in Windows**<a name="winhook"></a>
	* **101**
		* [Bypass EDR’s memory protection, introduction to hooking](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6)
		* [Windows API Hooking - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++)
		* [The different ways of hooking - Ch40zz(2015)](http://www.rohitab.com/discuss/topic/41855-tutorial-the-different-ways-of-hooking/)
		* [PE Parsing and Defeating AV/EDR API Hooks in C++ - Solomon Sklash(2020)](https://www.solomonsklash.io/pe-parsing-defeating-hooking.html)
			* [Code](https://github.com/SolomonSklash/UnhookingPOC)
		* [Application Introspection & Hooking With Frida - b33f](https://www.fuzzysecurity.com/tutorials/29.html)
		* [Hooking - alphaSeclab](https://github.com/alphaSeclab/hooking/blob/master/Readme_en.md)
		* [Defeating Antivirus Real-time Protection From The Inside - Kuba Gretzky(2016)](https://breakdev.org/defeating-antivirus-real-time-protection-from-the-inside/)
		* [Inline Hooking for Programmers (Part 1: Introduction) - MalwareTech(2015)](https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html)
		* [Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams - @modexpblog](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
		* [A Comprehensive Guide to Hooking Windows APIs with Python It was originally published on https://www.apriorit.com/ - Vadim N, Ivan Komarov(2021)](https://www.apriorit.com/dev-blog/727-win-guide-to-hooking-windows-apis-with-python)
	* **Hooking Syscalls**
		* [Intercepting System Calls on x86_64 Windows - Jurriaan Bremer(2012)](http://jbremer.org/intercepting-system-calls-on-x86_64-windows/)
	* **Hooking Techniques**
		* **API/Function/In-Line Hooking aka Detours/Trampoline**
			* **Articles/Blogposts/Writeups**
				* [API hooking revealed - Ivo Ivanov(2002)](https://www.codeproject.com/Articles/2082/API-hooking-revealed)
				* [x86 API Hooking Demystified - Juriaan Brerner(2012)](http://jbremer.org/x86-api-hooking-demystified/)
				* [Intercepting DLL libraries calls. API hooking in practice - Bartosz Wójcik(2013)](https://www.pelock.com/articles/intercepting-dll-libraries-calls-api-hooking-in-practice)
				* [Inline Hooking for Programmers (Part 1: Introduction) - MalwareTech(2015](https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html)
			* **Tools**
				* [Microsoft Detours](https://www.microsoft.com/en-us/research/project/detours/?from=http%3A%2F%2Fresearch.microsoft.com%2Fsn%2Fdetours)
			* **Tools**
				* [Detours](https://github.com/microsoft/Detours)
				* [DetoursNT](https://github.com/wbenny/DetoursNT)
					* Detours with just single dependency - NTDLL 
		* **Hardware Breakpoint Hooking**
		* **Export-Address Table Hooking**
			* **Articles/Blogposts/Writeups**			
				* [EAT Hooking On DLL's - Jimster480(2007)](https://www.unknowncheats.me/forum/c-and-c/50426-eat-hooking-dlls.html)
				* [Hook Functions via Export Address Table (MISCHookFunctions_EAT_NTRN) - Vault7](https://wikileaks.org/ciav7p1/cms/page_17072425.html)
				* [Tutorial How to Hook Export Address Table - EAT Hooking - (2021)](https://guidedhacking.com/threads/how-to-hook-export-address-table-eat-hooking.17083/)
		* **Import-Address Table Hooking**
			* **Articles/Blogposts/Writeups**			
				* [Understanding the Import Address Table - dzzie](http://sandsprite.com/CodeStuff/Understanding_imports.html)
				* [Userland hooking, IAT - c0llateral(2009)](https://c0llateral.wordpress.com/2009/12/27/userland-hooking-iat/)
				* [IAT Hooking Revisited - John Leitch(2011)](https://github.com/m0n0ph1/IAT-Hooking-Revisited)
					* Import address table (IAT) hooking is a well documented technique for intercepting calls to imported functions. However, most methods rely on suspicious API functions and leave several easy to identify artifacts. This paper explores different ways IAT hooking can be employed while circumventing common detection mechanisms.
				* [Hooking Series PART I : Import Address Table Hooking - ReLearEx(2017](https://relearex.wordpress.com/2017/12/26/hooking-series-part-i-import-address-table-hooking/)
				* [IAT Function Hooking - dzzie](http://sandsprite.com/CodeStuff/IAT_Hooking.html)
				* [Offensive IAT Hooking - Ege Balci(2018](https://pentest.blog/offensive-iat-hooking/)
				* [IAT hooking - F3real(2019](https://f3real.github.io/iat_hooking.html)
				* [Import Adress Table (IAT) Hooking - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking)
			* **Papers**
				* [Study on the API Hooking Method Based on the Windows - Wan-Kyung Kim, Woo-Young Soh, Kyung Sung(2009](https://www.researchgate.net/publication/264192703_Study_on_the_API_Hooking_Method_Based_on_the_Windows)
					* "Recently, malicious attacks for Windows operate through Window API hooking in the Windows Kernel. This paper presents the API hooking attack and protection techniques based on Windows kernel. Also this paper develops a detection tool for Windows API hooking that enables to detect dll files which are operated in the kernel. Proposed tool can detect behaviors that imports from dll files or exports to dll files such as kernel32.dll, snmpapi.dll, ntdll.dll and advapidll.dll, etc.. Test results show that the tool can check name, location, and behavior of API in testing system."
			* **Tools**
				* [hooks](https://github.com/hMihaiDavid/hooks)
					* A DLL that performs IAT hooking
				* [IAT patcher](https://github.com/hasherezade/IAT_patcher)
					* [Article](https://hasherezade.github.io/IAT_patcher/)
					* Persistent IAT hooking application (for PE files).
				* [win32_hook.h](https://gist.github.com/ghorsington/93ea22c1f4e79e68466a26cbfc58af05)
		* **Forced-Exception**
			* **101**
				* [Single Step Debugging Explained - Neil Sikka(2012)](https://www.a1logic.com/2012/10/23/single-step-debugging-explained/)
				* [Vectored Exception Handling - docs.ms](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
				* [Microsoft-specific exception handling mechanisms - Wikipedia](https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms)
			* **Articles/Blogposts/Writeups**
				* [Vectored Exception Handling, Hooking Via Forced Exception - Hoang Bui(2019)](https://medium.com/@fsx30/vectored-exception-handling-hooking-via-forced-exception-f888754549c6)
				* [Branch Tracing with Intel MSR Registers - pedram(2006)](http://www.openrce.org/blog/view/535/Branch_Tracing_with_Intel_MSR_Registers)
				* [Last branch records and branch tracing - nick.p.everdox(2013)](https://www.codeproject.com/Articles/517466/Last-branch-records-and-branch-tracing)
		* **Interrupt-Descriptor-Table Hooking**
			* **Articles/Blogposts/Writeups**
				* [Handling Interrupt Descriptor Table for fun and profit - kad(2002)](http://phrack.org/issues/59/4.html)
				* [Hooking IDT - Dejan Lukan(2014](https://resources.infosecinstitute.com/topic/hooking-idt/)
				* [Hooking Series PART II: Interrupt Descriptor Table Hooking - ReLearEx(2017](https://relearex.wordpress.com/2017/12/27/hooking-series-part-ii-interrupt-descriptor-table-hooking/)
				* [Interrupt Descriptor Table - @spotheplanet](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/interrupt-descriptor-table-idt)
			* **Tools**
				* [IDTClient.c](https://gist.github.com/Barakat/89002a26937a2da353868fc5130812a5)
					* Windows x86 Interrupt Descriptor Table (IDT) hooking driver 
		* **Mini-Filters**
			* **Articles/Blogposts/Writeups**
				* [Part 1: Fs Minifilter Hooking - Aviad Shamriz(2020)](https://aviadshamriz.medium.com/part-1-fs-minifilter-hooking-7e743b042a9d)
				* [Part 2: Display Miniport Hooking - Aviad Shamriz(2021)](https://aviadshamriz.medium.com/part-2-display-miniport-hooking-e1a54661d2e1)
		* **Msv**
			* [MsvpPasswordValidate hooking - Federico Lagrasta()](https://offnotes.notso.pro/abusing-credentials/dumping-credentials/msvppasswordvalidate-hook)
				* [HppDLL](https://github.com/last-byte/HppDLL)
		* **System Service Dispatch Table(SSDT)**
			* **101**
				* [Hooking the System Service Dispatch Table (SSDT) - Dejan Lukan(2014)](https://resources.infosecinstitute.com/topic/hooking-system-service-dispatch-table-ssdt/)
			* **Articles/Blogposts/Writeups**
				* [Fun with SSDT Hooks and DEP - Matt Olney(2008](https://blog.talosintelligence.com/2008/11/fun-with-ssdt-hooks-and-dep.html)
				* [Hide files using SSDT hooking - Emeric Nasi(2011](https://blog.sevagas.com/?Hide-files-using-SSDT-hooking)
				* [Investigating Memory Analysis Tools – SSDT Hooking via Pointer Replacement - Frank Block(2015](https://insinuator.net/2015/12/investigating-memory-analysis-tools-ssdt-hooking-via-pointer-replacement/)
			* **Tools**
				* [ProcessIsolator](https://github.com/int0/processisolator)
					* Utility to hook SSDT of specific process and transfer control to a service (usermode app) for handling to determine action allow/deny API call etc. currenly only NTAPI/WIN32K logging is supposeted no handlers were implemented. Ideally this should use virtualization to hook LSTAR CSTAR MSRs and don't implement own KiSystemCall.
				* [Hackshield Bypass for Windows Xp/7](https://github.com/s18leoare/hackshield-driver-bypass)
				* [SHD](https://github.com/papadp/shd)
					* Ssdt Hook Detection tool packaged into a small cli utility. The drivers are packed as resources in the cli tool and are extraced upon use. Currently only tested on Win7SP1x86, Win7SP1x64.
		* **Vectored Exception Handling**
					* [Vectored Exception Handling, Hooking Via Forced Exception - Hoang Bui(2019)](https://medium.com/@fsx30/vectored-exception-handling-hooking-via-forced-exception-f888754549c6)
						* [LeoSpecial](https://github.com/hoangprod/LeoSpecial-VEH-Hook)
		* **C#/.NET**
			* **Articles/Blogposts/Writeups**
				* [Host startup hook - dotnet github repo](https://github.com/dotnet/core-setup/blob/master/Documentation/design-docs/host-startup-hook.md)
				* [C# Have some fun with .net core startup hooks - Kevin Gosse(2019)](https://medium.com/criteo-labs/c-have-some-fun-with-net-core-startup-hooks-498b9ad001e1)
			* **Tools**
				* [DotNetHooking](https://github.com/tandasat/dotnethooking)
					* Sample use cases of the .NET native code hooking technique 
				* [PlayHooky](https://github.com/wledfor2/playhooky)
					* PlayHooky is a simple C# Class that can be used to hook C# Methods at runtime. PlayHooky works on both .NET and Mono of any version, and Unity 4-5+ as long as you are running Windows x86/x64.
				* [Loader2](https://github.com/thaisenpm/loader2)
				* [Open.WinKeyboardHook](https://github.com/lontivero/open.winkeyboardhook)
					* A simple and easy-to-use .NET managed wrapper for Low Level Keyboard hooking.
				* [Loader1](https://github.com/thaisenpm/loader1)
					* Nova Hook is an open source VB.NET cheat loader currently built for CS:GO
				* [GlobalHook](https://github.com/20chan/GlobalHook)
					* Simple global keyboard, mouse hook and simulation library written C#
				* [DotNetHook](https://github.com/elliesaur/dotnethook)
					* A hook proof of concept with no native dependencies. Hook both .NET methods (even framework methods) and Native methods entirely in .NET.
				* [MonoHook](https://github.com/Misaka-Mikoto-Tech/MonoHook)
					* hook C# method at runtime without modify dll file (such as UnityEditor.dll)
				* [Dendrobate](https://github.com/xforcered/Dendrobate)
					* Managed code hooking template.	
	




	* **Un-Hooking**<a name="un-hooking"></a>
		* **Articles/Blogposts/Writeups**
			* [Why Usermode Hooking Sucks – Bypassing Comodo Internet Security - George Nicalaou(2012)](http://rce.co/why-usermode-hooking-sucks-bypassing-comodo-internet-security/)
			* [Universal Unhooking: Blinding Security Software - Jeffrey Tang(2017)](https://blogs.blackberry.com/en/2017/02/universal-unhooking-blinding-security-software)
			* [Defeating Userland Hooks (ft. Bitdefender) - dtm(2019)](https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496)
			* [Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs - @spottheplanet](https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis)
		* **Talks/Presentations/Videos**
			* [Bypassing User-Mode Hooks: Analyzing Malware Evasion Trend - Omri Misgav, Udi Yavo(FIRST Tel Aviv2019)](https://www.first.org/resources/papers/telaviv2019/Ensilo-Omri-Misgav-Udi-Yavo-Analyzing-Malware-Evasion-Trend-Bypassing-User-Mode-Hooks.pdf)
			* [EPP/EDRUnhooking their protections - Daniel Feichter(DeepSec 2020)](https://raw.githubusercontent.com/Strong-IT-IBK/Conferences-Slides/main/DeepSec2020_EPP_Unhooking.pdf)
		* **Tools**
			* [Memfuck](https://github.com/jackullrich/memfuck)
				* [MemFuck: Bypassing User-Mode Hooks - winternl.com](https://winternl.com/memfuck/)
				* A PoC designed to bypass all usermode hooks in a WoW64 environment. 
			* [UnhookMe](https://github.com/mgeeky/UnhookMe)
				* UnhookMe is an universal Windows API resolver & unhooker addressing problem of invoking unmonitored system calls from within of your Red Teams malware
			* [minhook](https://github.com/khchen/minhook)
			* [Shellycoat](https://github.com/slaeryan/AQUARMOURY/tree/master/Shellycoat)
				* Shellycoat is a utility designed to aid in bypassing User-Mode hooks utilised by AV/NGAV/EDR/Sandboxes/DLP etc. to gain visibility into potentially suspicious actions since SSDT hooking was made obsolete with the advent of Kernel Patch Protection(KPP)/Patch Guard in x64 systems.

	* **Articles/Blogposts/Writeups**
					* [Bypass EDR’s memory protection, introduction to hooking - Hoang Bui(2019](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6)
						* [Andrew Special](https://github.com/hoangprod/AndrewSpecial/tree/master)

					* [Endpoint Detection and Response: How Hackers Have Evolved - Matthew Eidelberg(2021)](https://www.optiv.com/insights/source-zero/blog/endpoint-detection-and-response-how-hackers-have-evolved)
					* [EDR and Blending In: How Attackers Avoid Getting Caught - Matthew Eidelberg(2021)](https://www.optiv.com/insights/source-zero/blog/edr-and-blending-how-attackers-avoid-getting-caught)

		* [Windows x64 System Service Hooks and Advanced Debugging - nick.p.everdox(2013)](https://www.codeproject.com/Articles/543542/Windows-x64-system-service-hooks-and-advanced-debu)
			* This article will explain how we can work alongside patchguard to hook system services in a less invasive way, but still retain the powerful aspects behind it.
		* [Userland API Monitoring and Code Injection Detection - dtm(2018)](https://0x00sec.org/t/userland-api-monitoring-and-code-injection-detection/5565)
		* [Full DLL Unhooking with C++ - @spotheplanet](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)
		* [API Monitoring and Hooking for Offensive Tooling - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/api-monitoring-and-hooking-for-offensive-tooling)
		* [FireWalker: A New Approach to Generically Bypass User-Space EDR Hooking - Peter Winter-Smith(2020)](https://www.mdsec.co.uk/2020/08/firewalker-a-new-approach-to-generically-bypass-user-space-edr-hooking/)
		* [Adventures in Dynamic Evasion - Matt Hand(2020)](https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa)
		* [User-mode API hooks and bypasses - dumpco.re(2020)](http://dumpco.re/blog/user-mode-api-hooks-and-bypasses)
		* [SMOOTHPHERRET - generic hooking evasion](https://blog.sektor7.net/#!res/2020/smoothpherret.md)
		* [Hooks-On Hoot-Off: Vitaminizing MiniDump - Adepts of 0xCC](https://adepts.of0x.cc/hookson-hootoff/)
		* [WOW64!Hooks: WOW64 Subsystem Internals and Hooking Techniques - Stephen Eckels(2020)](https://www.fireeye.com/blog/threat-research/2020/11/wow64-subsystem-internals-and-hooking-techniques.html)
		* [Pushing back on userland hooks with Cobalt Strike - Ralphael Mudge(2021)](https://blog.cobaltstrike.com/2021/01/13/pushing-back-on-userland-hooks-with-cobalt-strike/)
	* **Talks/Presentations/Videos**							
		* [Hooking Nirvana: Stealthy Instrumentation Techniques for Windows 10 - Alex Ionescu(REcon2015)](https://www.youtube.com/watch?v=bqU0y4FzvT0)
			* [PDF](https://github.com/ionescu007/HookingNirvana/blob/master/Esoteric%20Hooks.pdf)
		* [Rendering Ransomware Detection and EDR Products Blind - Rene Kolga(BSidesSLC 2020)](https://www.youtube.com/watch?v=W7-zTdz-ORA&list=PLqVzh0_XpLfSJ2Okt38acDdO_xu2zKYmK&index=5&t=0s)
		* [EPP/EDR Unhooking their protections - Daniel Feichter(DeepSec2020)](https://www.youtube.com/watch?v=a22aBofbv2g)
			* [Slides](https://github.com/Strong-IT-IBK/Conferences-Slides)
			* Enclosed you will find the video of our virtual appearance at the DeepSec 2020 about strengths and weaknesses of EPP/EDR products. In the first step, we go into the basics of the Windows OS architecture. In the second step we take a closer look at two mechanisms which can be used by EPP/EDR products under Windows. Afterwards we look at possibilities how these mechanisms can be bypassed by an attacker. And at the end we also take a short look at what defenders can do to prevent these attacks
	* **Papers**
		* [PreVice: Static Detection of Hooking Capabilities in Machine Code - Claudiu Teodorescu, Derek Soeder, Andy Wortman(REcon2018)](https://infocondb.org/con/recon/recon-2018/previce-static-detection-of-hooking-capabilities-in-machine-code)
		* [HookFinder: Identifying and Understanding Malware Hooking Behaviors - Heng Yin, Zhenkai Lian, Dawn Song(2017)](https://www.ndss-symposium.org/wp-content/uploads/2017/09/yin2.pdf)
	* **Input/Output Request Packet**




	* **Tools**
		* **Unsorted**
			* [HookLib](https://github.com/HoShiMin/HookLib)
				* The functions interception library written on pure C and NativeAPI with UserMode and KernelMode support 
			* [APIunhooker](https://github.com/RedLectroid/APIunhooker)
				* C++ function that will automagically unhook a specified Windows API
			* [Crystal Anti-Exploit Protection 2012](https://github.com/peterwintersmith/crystalaep)
			* [CoreHook](https://github.com/unknownv2/CoreHook)
				* A library that simplifies intercepting application function calls using managed code and the .NET Core runtime 
			* [NtdllUnpatcher](https://github.com/Kharos102/NtdllUnpatcher)
			* [subhook](https://github.com/Zeex/subhook)
				* SubHook is a super-simple hooking library for C and C++ that works on Windows, Linux and macOS. It supports x86 only (32-bit and 64-bit).
			* [ddimon](https://github.com/tandasat/ddimon)
				* Monitoring and controlling kernel API calls with stealth hook using EPT
			* [hyperbone](https://github.com/darthton/hyperbone)
				* Minimalistic VT-x hypervisor with hooks 
			* [KasperskyHook](https://github.com/iPower/KasperskyHook/)
				* Hook system calls on Windows by using Kaspersky's hypervisor 
			* [List of API Hook Libraries](https://github.com/kubo/funchook/wiki/List-of-API-Hook-Libraries)
			* [Juno](https://github.com/Akaion/Juno)
				* A Windows managed method detouring library that supports both x86 and x64 detours. 
			* [mhook(2014)](https://github.com/martona/mhook)
			* [InfinityHook](https://github.com/everdox/infinityhook)
			* [minhook](https://github.com/tsudakageyu/minhook)
				* [Fork](https://github.com/sentinel-one/minhook)
			* [PolyHook](https://github.com/stevemk14ebr/PolyHook)
			* [PolyHook 2.0](https://github.com/stevemk14ebr/PolyHook_2_0)
				* [PolyHook - The C++11 x86/x64 Hooking Library](https://www.codeproject.com/articles/1100579/polyhook-the-cplusplus-x-x-hooking-library)
				* [PolyHook 2: C++17 x86/x64 Hooking Library](https://www.codeproject.com/Articles/1252212/PolyHook-2-Cplusplus17-x86-x64-Hooking-Library)
			* [Probatorum EDR Userland Hook Checker](https://github.com/asaurusrex/Probatorum-EDR-Userland-Hook-Checker)
				* Probatorum will check which Nt/Zw functions your local EDR is hooking. Most credit for this code goes to SolomonSklash, who has great blogs on a variety of security topics (https://www.solomonsklash.io). He wrote most of this code; I just cleaned it up a bit.
			* [ScyllaHide](https://github.com/x64dbg/ScyllaHide)
				* Advanced usermode anti-anti-debugger.
* **Windows Kernel Operations**<a name="winkernel"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
	* **Tools**	
* **LNK Files**<a name="LNK"></a>
	* **101**
		* [[MS-SHLLINK]: Shell Link (.LNK) Binary File Format - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)
			* Specifies the Shell Link Binary File Format, which contains information that can be used to access another data object. The Shell Link Binary File Format is the format of Windows files with the extension "LNK".
		* [Windows Shortcut File format specification - liblnk](https://github.com/libyal/liblnk/blob/master/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc)
			* This document is intended as a working document for the Windows Shortcut File (LNK) format specification. Which should allow existing Open Source forensic tooling to be able to process this file type.
	* **Articles/Blogposts/Writeups**
		* [You down with LNK? - Nathan Drier(2012)](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/you-down-with-lnk/)
		* [Tracking threat actors through .LNK files - Michel Conene(2017)](https://blog.nviso.eu/2017/04/04/tracking-threat-actors-through-lnk-files/)
		* [.LNK downloader and bitsadmin.exe in malicious Office document - Michel Coene(2017)](https://blog.nviso.eu/2017/03/24/lnk-downloader-and-bitsadmin-exe-in-malicious-office-document/)
		* [Pwned by a Shortcut - Tom Melo(2018)](https://medium.com/secjuice/pwned-by-a-shortcut-b21473970944)
		* [Persistence – Shortcut Modification - Pentestlab.blog(2019)](https://pentestlab.blog/2019/10/08/persistence-shortcut-modification/)
		* [Deep Dive: A LNK in the Chain - John Ferrell(2019)](https://blog.huntresslabs.com/deep-dive-a-lnk-in-the-chain-6c0d1072160d?gi=da1f252846c3)		
		* [Analyzing the Windows LNK file attack method - 0xd3xt3r(2019)](https://dexters-lab.net/2019/02/16/analyzing-the-windows-lnk-file-attack-method/)
		* [Suspected Sapphire Mushroom (APT-C-12) malicious LNK files - @mattnotmax(2020)](https://bitofhex.com/2020/02/10/sapphire-mushroom-lnk-files/)
		* [LNK & ISESteroids Powershell dropper - Max Kersten(2020)](https://maxkersten.nl/binary-analysis-course/malware-analysis/lnk-isesteroids-powershell-dropper/)
		* [The Missing LNK — Correlating User Search LNK files - Ashley Frazer(2020)](https://www.fireeye.com/blog/threat-research/2020/02/the-missing-lnk-correlating-user-search-lnk-files.html)
		* [Using Shell Links as zero-touch downloaders and to initiate network connections - Jan Kopriva(2020)](https://isc.sans.edu/forums/diary/Using+Shell+Links+as+zerotouch+downloaders+and+to+initiate+network+connections/26276/)
		* [CVE-2020-0729: Remote Code Execution Through .LNK Files - Trend Micro Research Team(2020)](https://www.thezdi.com/blog/2020/3/25/cve-2020-0729-remote-code-execution-through-lnk-files)
		* [ [CVE49] Microsoft Windows LNK Remote Code Execution Vulnerability - CVE-2020-1299 - linhlhq(2020](https://blog.vincss.net/2020/06/cve49-microsoft-windows-lnk-remote-code-execution-vuln-cve-2020-1299-eng.html)
		* [Abusing LNK "Features" for Initial Access and Persistence - V3ded(2021](https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence)
	* **Talks/Presentations/Videos**
		* [A Chain Is No Stronger Than Its Weakest LNK - David French(BSidesSLC2020)](https://www.youtube.com/watch?v=nJ0UsyiUEqQ&list=PLqVzh0_XpLfSJ2Okt38acDdO_xu2zKYmK&index=6)
	* **Papers**
		* [The Meaning of Linkfiles In Forensic Examinations - Harry Parsonage(2010)](http://computerforensics.parsonage.co.uk/downloads/TheMeaningofLIFE.pdf)
			* A look at the practical value to forensic examinations of dates and times, and object identifiers in Windows   shortcut files.
	* **Tools**
		* [LNKMod](https://github.com/slyd0g/LNKMod)
			* C# project to create or modify existing LNKs
		* [lnk2pwn](https://github.com/it-gorillaz/lnk2pwn)
			* lnk2pwn is a gui tool that automates the process of generating malicious .lnk(Windows shortcut) files.
* **Logging**<a name="winlog"></a>
	* See [L-SM-TH.md](./L-SM-TH.md)
	* **Articles/Blogposts/Writeups**
		* [Stopping the Event Logger via Service Control Handler - modexp(2018)](https://modexp.wordpress.com/2018/06/08/stop-event-logger/)
		* [Crash Windows Event Logging Service - limbenjamin(2020)](https://limbenjamin.com/articles/crash-windows-event-logging-service.html)
	* **Tools**
		* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
			* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
		* [GENE: Go Evtx sigNature Engine](https://github.com/0xrawsec/gene)
			* The idea behind this project is to provide an efficient and standard way to look into Windows Event Logs (a.k.a EVTX files). For those who are familiar with Yara, it can be seen as a Yara engine but to look for information into Windows Events.
			* [Documentation](https://rawsec.lu/doc/gene/1.6/)
		* [LogServiceCrash](https://github.com/limbenjamin/LogServiceCrash)
			*  POC code to crash Windows Event Logger Service
		* [SharpCrashEventLog](https://github.com/slyd0g/SharpCrashEventLog)
			* C# port of LogServiceCrash 
		* [EventCleaner](https://github.com/QAX-A-Team/EventCleaner)
			* A tool mainly to erase specified records from Windows event logs, with additional functionalities. 
* **MS-SQL Server**<a name="ms-sql-server"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [How to Get Started with SQL Server and .NET - Artemakis Artemiou(2018)](https://www.mssqltips.com/sqlservertip/5677/how-to-get-started-with-sql-server-and-net/)
		* [Evil SQL Client Console: Msbuild All the Things - Scott Sutherland(2020)](https://blog.netspi.com/evil-sql-client-console-msbuild-all-the-things/)
		* [Incoming .NET SQLClient - FortyNorthSecurity(2020)](https://fortynorthsecurity.com/blog/sql-client-post/)
	* **Tools**
		* [DAFT: Database Audit Framework & Toolkit](https://github.com/NetSPI/DAFT)
			* This is a database auditing and assessment toolkit written in C# and inspired by PowerUpSQL. 
		* [Evil SQL Client (ESC)](https://github.com/NetSPI/ESC)
			* Evil SQL Client (ESC) is an interactive .NET SQL console client with enhanced SQL Server discovery, access, and data exfiltration features. While ESC can be a handy SQL Client for daily tasks, it was originally designed for targeting SQL Servers during penetration tests and red team engagements. The intent of the project is to provide an .exe, b… 
		* [QuickSQL](https://github.com/trustedsec/quicksql)
			* QuickSQL is a simple MSSQL query tool that allows you to connect to MSSQL databases and does not require administrative level rights to use. 
		* [SqlClient](https://github.com/FortyNorthSecurity/SqlClient)
			* POC for .NET mssql client for accessing database data through beacon 
* **Named Pipes**<a name="namedpipes"></a>
	* **101**
		* [Named Pipe - Wikipedia](https://en.wikipedia.org/wiki/Named_pipe)
		* [Named Pipes - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
		* [Named Pipe Security and Access Rights - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
		* [Named Pipe client](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-client)
	* **Articles/Blogposts/Writeups**
		* [Learn Pipe Fitting for all of your Offense Projects - Raphael Mudge(2021)](https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/)
	* **Tools**
		* [AsyncNamedPipes](https://github.com/rasta-mouse/AsyncNamedPipes)
			* Quick PoC to send and receive messages over Named Pipes asynchronously.
		* [Named-Pipe-Sniffer](https://github.com/OmerYa/Named-Pipe-Sniffer)
		* [getnamedpipes.cs](https://gist.github.com/dmchell/e0d32ffdc02d91a73d8806acd1c192a8)
* **PowerShell**<a name="powershell"></a>
	* **PowerShell Logging**
		* **101**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
			* [DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)
				* One of the many ways one could disabled PS logging/AMSI if there's prior code execution.
	* **PowerShell Profiles**
		* **101**
			* [Understanding the Six PowerShell Profiles - Dr Scripto(devblogs.ms)](https://devblogs.microsoft.com/scripting/understanding-the-six-powershell-profiles/)
			* [About Profiles - docs.ms(2017)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7)
			* [How-to: Configure the PowerShell startup profile [$Profile] - ss64.com](https://ss64.com/ps/syntax-profile.html)
			* [Understanding different (Six and more!) PowerShell profiles - Mohit Goyal](https://mohitgoyal.co/2017/04/30/understanding-different-six-and-more-powershell-profiles/)
			* [PowerShell for Beginners (Part 6): PowerShell Profiles and the ISE - Patrick Gruenauer](https://sid-500.com/2018/01/16/powershell-for-beginners-part-6-powershell-profiles-and-the-ise/)
		* **Articles/Blogposts/Writeups**
			* [Abusing PowerShell Profiles - enigma0x3(2014)(https://enigma0x3.net/2014/06/16/abusing-powershell-profiles/)
			* [Investigating Subversive PowerShell Profiles - Matt Graeber(2015)](http://www.exploit-monday.com/2015/11/investigating-subversive-powershell.html)
			* [Persistence – PowerShell Profile - PentestLab.blog(2019)](https://pentestlab.blog/2019/11/05/persistence-powershell-profile/)
			* [Persistent PowerShell: The PowerShell Profile - ](https://www.red-gate.com/simple-talk/sysadmin/powershell/persistent-powershell-the-powershell-profile/)
	* **PowerShell without PowerShell**
		* **101**
		* **Articles/Blogposts/Writeups**
			* [InsecurePowerShell - PowerShell without System.Management.Automation.dll - Ryan Cobb](https://cobbr.io/InsecurePowershell-PowerShell-Without-System-Management-Automation.html)
			* [We don’t need powershell.exe - decoder.cloud](https://decoder.cloud/2017/11/02/we-dont-need-powershell-exe/)
				* [Part 2](https://decoder.cloud/2017/11/08/we-dont-need-powershell-exe-part-2/)
				* [Part 3](https://decoder.cloud/2017/11/17/we-dont-need-powershell-exe-part-3/)
		* **Custom Runspace**
			* [Executing PowerShell scripts from C# - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/kebab/executing-powershell-scripts-from-c)
			* [Calling C# code in Powershell and vice versa - Karthik Kk](https://blog.executeautomation.com/calling-c-code-in-powershell-and-vice-versa/)
			* [How to run PowerShell Core scripts from .NET Core applications - keithbabinec(2020)](https://keithbabinec.com/2020/02/15/how-to-run-powershell-core-scripts-from-net-core-applications/)
				* [Code](https://github.com/keithbabinec/PowerShellHostedRunspaceStarterkits)
			* [How to execute PowerShell script or cmdlets from C# code? - Mitesh Sureja(2018)](https://miteshsureja.blogspot.com/2018/07/how-to-execute-powershell-script-or.html)
				* [Code](https://gist.github.com/miteshsureja/f9cbc2f09264a01277a6555a7425debc)
			* Project: [NotPowerShell](https://github.com/Ben0xA/nps)
			* [We don’t need powershell.exe - decoder.cloud(2017)](https://decoder.cloud/2017/11/02/we-dont-need-powershell-exe/)
			* [Powershell CLM Bypass Using Runspaces - Shaksham Jaiswal(2019)](https://www.secjuice.com/powershell-constrainted-language-mode-bypass-using-runspaces/)
		* **Tools**
			* [InsecurePowerShell](https://github.com/cobbr/InsecurePowerShell)
				* InsecurePowershell is a fork of PowerShell Core v6.0.0, with key security features removed.
			* [InsecurePowerShellHost](https://github.com/cobbr/InsecurePowerShellHost)
				* InsecurePowerShellHost is a .NET Core host process for InsecurePowerShell, a version of PowerShell Core with key security features removed.
			* [PowerTools](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)
				* This project focuses on allowing the execution of Powershell functionality without the use of Powershell.exe. Primarily this project uses.NET assemblies/libraries to start execution of the Powershell scripts.
			* [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)
				* Executes PowerShell from an unmanaged process.
			* [PowerShdll](https://github.com/p3nt4/PowerShdll)
				* Run PowerShell with dlls only.
			* [NoPowerShell](https://github.com/bitsadmin/nopowershell)
				* NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used; only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll,main.
			* [A Powerful New Tool: PowerLine - BHIS(2017)](https://www.youtube.com/watch?v=HiAtkLa8FOc)
				* [PowerLine](https://github.com/fullmetalcache/PowerLine)
				* Running into environments where the use of PowerShell is being monitored or is just flat-out disabled?  Have you tried out the fantastic PowerOps framework but are wishing you could use something similar via Meterpreter, Empire, or other C2 channels?  Look no further! In this talk, Brian Fehrman talks about his new PowerLine framework. He overviews the tool, walks you through how to use it, shows you how you can add additional PowerShell scripts with little effort, and demonstrates just how powerful (all pun intended) this little program can be!
			* [psfire](https://github.com/curi0usJack/psfire)
				* simple demo of using C# & System.Management.Automation.dll to run powershell code (b64 encoded) without powershell.exe
			* [PowerShellArmoury](https://github.com/cfalta/PowerShellArmoury)
				* The PowerShell Armoury is meant for pentesters, "insert-color-here"-teamers and everyone else who uses a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, encrypted file.
* **PowerShell Desired State Configuration**<a name="winpsc"></a>
	* **Documentation**
		* [Windows PowerShell Desired State Configuration Overview - docs.ms](https://docs.microsoft.com/en-us/powershell/dsc/overview)
	* [DSCompromised: A Windows DSC Attack Framework - Matt Hastings, Ryan Kazanciyan - BH Asia16](https://www.blackhat.com/docs/asia-16/materials/asia-16-Kazanciyan-DSCompromised-A-Windows-DSC-Attack-Framework.pdf)
	* [DSCompromised](https://github.com/matthastings/DSCompromised)
		* PowerShell framework for managing and infecting systems via Windows Desired State Configuration (DSC) DSC is a built-in feature in Windows Management Framework 4.0 (PowerShell v4) and is installed natively on Windows operating systems beginning with Server 2012 R2 and Windows 8.1.
* **Privileges**<a name="winprivs"></a>
	* **101**
		* [Privilege Constants (Authorization) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
			* Privileges determine the type of system operations that a user account can perform. An administrator assigns privileges to user and group accounts. Each user's privileges include those granted to the user and to the groups to which the user belongs.
* **Services**<a name="winservices"></a>
	* **101**
		* [About Services - docs.ms](https://docs.microsoft.com/en-us/windows/win32/services/about-services)
			* The service control manager (SCM) maintains a database of installed services and driver services, and provides a unified and secure means of controlling them. The database includes information on how each service or driver service should be started. It also enables system administrators to customize security requirements for each service and thereby control access to the service.
		* [Service Control Handler Function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/services/service-control-handler-function)
			* Each service has a control handler, the Handler function, that is invoked by the control dispatcher when the service process receives a control request from a service control program. Therefore, this function executes in the context of the control dispatcher.
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [ExploitRemotingService](https://github.com/tyranid/ExploitRemotingService)
			* A tool to exploit .NET Remoting Services vulnerable to CVE-2014-1806 or CVE-2014-4149. It only works on Windows although some aspects might work in Mono on `*nix`.
* **Windows Privileges & Tokens**<a name="wintokens"></a>
	* **101**
		* [Access token - Wikipedia](https://en.wikipedia.org/wiki/Access_token)
		* [Access Tokens - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
			* An access token is an object that describes the security context of a process or thread. The information in a token includes the identity and privileges of the user account associated with the process or thread. When a user logs on, the system verifies the user's password by comparing it with information stored in a security database. If the password is authenticated, the system produces an access token. Every process executed on behalf of this user has a copy of this access token. The system uses an access token to identify the user when a thread interacts with a securable object or tries to perform a system task that requires privileges.
		* [Credentials Processes in Windows Authentication - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)
		* [How Access Tokens Work - docs.ms](https://docs.microsoft.com/pt-pt/previous-versions/windows/server/cc783557(v=ws.10)?redirectedfrom=MSDN)
	* **Articles/Blogposts/Writeups**
		* [Introduction to Windows tokens for security practitioners - Will Burgess(2020)](https://www.elastic.co/blog/introduction-to-windows-tokens-for-security-practitioners)
		* [About Windows Process/Thread Tokens and Pass The Hash - Kevin Dick(2019)]
		* [Windows Privilege Abuse: Auditing, Detection, and Defense - Palantir(2019)](https://medium.com/palantir/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)
		* [Token Manipulation Attacks (Part 1: Introduction to Tokens and Privileges) - Susan Ghosh(2019)](https://niiconsulting.com/checkmate/2019/11/token-manipulation-attacks-part-1-introduction-to-tokens-and-privileges/)
			* [Part 2](https://niiconsulting.com/checkmate/2019/11/token-manipulation-attacks-part-2-process-of-impersonation/)
		* [Give Me Back My Privileges! Please? - itm4n(2019)](https://itm4n.github.io/localservice-privileges/)
			* I want to tell you the story of a service account which lost all its powers (a.k.a. privileges). Windows world is getting increasingly ruthless and when the system considers you are not worthy, this is what happens. Fortunately for our service account, all is not lost, there’s still hope. In this merciless world, you can always turn to the old sages to find some comfort and support. Among them, the Task Scheduler might be willing to help and restore what was lost, provided that you ask kindly…
		* [Accessing Access Tokens for UIAccess - James Forshaw(2019)](https://www.tiraniddo.dev/2019/02/accessing-access-tokens-for-uiaccess.html)
		* [Sharing a Logon Session a Little Too Much - James Forshaw(2020)](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)
		* [Understanding and Abusing Process Tokens — Part I - seemant bisht(2020)](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfahttps://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
		* [The impersonation game - decoder.cloud(2020)](https://decoder.cloud/2020/05/30/the-impersonation-game/)
		* [Don't Use SYSTEM Tokens for Sandboxing (Part 1 of N) - James Forshaw(2020)](https://www.tiraniddo.dev/2020/01/dont-use-system-tokens-for-sandboxing.html)
		* [Game Over Privileges - Acebond(2020)](https://shellz.club/game-over-privileges/)
	* **Talks/Presentations/Videos**
		* [Abusing Access Tokens for UAC Bypasses - James Forshaw(ZeroNights18)](https://www.youtube.com/watch?v=UTvOfmtNVKI&feature=youtu.be)
			* UAC, specifically Admin-Approval mode, has been known to be broken ever since it was first released in Windows Vista. Most of the research of bypassing UAC has focused on abusing bad elevated application behavior, auto elevation or shared registry and file resources. However, UAC was fundamentally broken from day one due to the way Microsoft implemented the security around elevated processes, especially their access tokens. This presentation will go into depth on why this technique works, allowing you to silently gain administrator privileges if a single elevated application is running. It will describe how Microsoft tried to fix it in Windows 10, and how you can circumvent their defences. It will also go into detail on a previously undocumented technique to abuse the assumed, more secure, Over-The-Shoulder elevation on Windows 10.
		* [Understanding Windows Access Token Manipulation - Justin Bui(Hushcon2019)](https://www.slideshare.net/JustinBui5/understanding-windows-access-token-manipulation)
			* Finding alternatives to winlogon.exe to steal SYSTEM access tokens from. 
		* [The Backup Operators Guide to the Galaxy - Dave Mayer](https://www.irongeek.com/i.php?page=videos/derbycon9/2-16-the-backup-operators-guide-to-the-galaxy-dave-mayer)
			* Backup Operator accounts are ubiquitous and often overlooked by both blue and red teams.These accounts have abusable permissions and are rarely maintained properly.In this talk we will examine and demonstrate novel techniques to stealthily compromise Active Directory through the Backup Operator?s account.We will use the Backup Operator account to gain local Admin privilege, establish persistence, and pivot laterally throughout a domain.However, all is not lost in that we can further lockdown our systems and enable auditing measures to deter and detect these attacks.
	* **Papers**
		* [Security Implications of Windows Access Tokens –  A Penetration Tester’s Guide - Luke Jennings(2008)](https://labs.f-secure.com/assets/BlogFiles/mwri-security-implications-of-windows-access-tokens-2008-04-14.pdf)
	* **Tools**
		* [PrimaryTokenTheft](https://github.com/slyd0g/PrimaryTokenTheft)
			* Steal a primary token and spawn cmd.exe using the stolen token.
		* [One Token to Rule Them All: Post-Exploitation Fun in Windows Environments - Luke Jennings](https://media.defcon.org/DEF%20CON%2015/DEF%20CON%2015%20video/DEF%20CON%2015%20Hacking%20Conference%20Presentation%20By%20Luke%20Jennings%20One%20Token%20to%20Rule%20Them%20All%20-%20Video.m4v)
			* [Slides](http://www.defcon.org/images/defcon-15/dc15-presentations/dc-15-jennings.pdf)
		* [Token Kidnapping's Revenge - ](https://media.defcon.org/DEF%20CON%2018/DEF%20CON%2018%20video%20and%20slides/DEF%20CON%2018%20Hacking%20Conference%20Presentation%20By%20Cesar%20Cerrudo%20-%20Token%20Kidnappings%20Revenge%20-%20Video%20and%20Slides.m4v)
			* [Slides](https://www.defcon.org/images/defcon-18/dc-18-presentations/Cerrudo/DEFCON-18-Cerrudo-Token-Kidnapping-Revenge.pdf)
		* [FullPowers](https://github.com/itm4n/FullPowers)
			* FullPowers is a Proof-of-Concept tool I made for automatically recovering the default privilege set of a service account including SeAssignPrimaryToken and SeImpersonate.
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
* **Windows Management Instrumentation**<a name="WMI"></a>
	* **101**
    	* [Windows Management Instrumentation - Wikipedia](https://en.wikipedia.org/wiki/Windows_Management_Instrumentation)
	    * [Windows Management Instrumentation - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
    	* [About WMI - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi)
	    * [WMIC - Take Command-line Control over WMI - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742610(v=technet.10))
	* **Official Documentation**
    	* [WMI Reference - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-reference)
	    * [Introduction to CIM Cmdlets - MS](https://devblogs.microsoft.com/powershell/introduction-to-cim-cmdlets/)
    	* [A Description of the Windows Management Instrumentation (WMI) Command-Line Utility (Wmic.exe) - support.ms](https://support.microsoft.com/en-us/help/290216/a-description-of-the-windows-management-instrumentation-wmi-command-li)
	    * [wmic - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic)
    	* [WMIC - Take Command-line Control over WMI - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742610(v=technet.10))
	    * [Using Windows Management Instrumentation Command-line - docs.ms(2009)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc779482(v=ws.10))
    	* [WMI Classes - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-classes)
	    * [Access to WMI Namespaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces)
    	* [WMI Tasks: Accounts and Domains - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--accounts-and-domains)
	    * [WMI Tasks -- Services - docs.ms ](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--services)
    	* [WMI Tasks: Files and Folders - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--files-and-folders)
	    * [Search for files using WMI - Jaap Brasser](https://www.jaapbrasser.com/search-for-files-using-wmi/)
    	* [Using the PowerShell CIM cmdlets for fun and profit - Dr Scripto](https://devblogs.microsoft.com/scripting/using-the-powershell-cim-cmdlets-for-fun-and-profit/)
	    * [Use PowerShell and WMI to Get Processor Information - Dr Scripto](https://devblogs.microsoft.com/scripting/use-powershell-and-wmi-to-get-processor-information/)
    	* [Using the Get-Member Cmdlet - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-powershell-1.0/ee176854(v=technet.10))
	    * [Get-Process - docs.ms](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Management/Get-Process?view=powershell-5.1)
	* **General**
    	* (Book) Understanding WMI Scripting: Exploiting Microsoft's Windows Management Instrumentation in Mission-Critical Computing Infrastructures - Alain Lissoir
	* **Articles/Blogposts/Writeups**
    	* [Examples of WMIC commands for Windows .NET SERVER Family - cs.cmu.edu(2002)](https://www.cs.cmu.edu/~tgp/scsadmins/winadmin/WMIC_Queries.txt)
	    * [WMIC Command Line Kung-Fu - tech-wreck.blogspot.com(2009)](https://tech-wreckblog.blogspot.com/2009/11/wmic-command-line-kung-fu.html)
	  	* [Playing with MOF files on Windows, for fun & profit - dimanche(2011)](https://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)
		* [MOF-tastic tricks or how to use MOF and powershell together - khr0x40sh(2014](https://khr0x40sh.wordpress.com/2014/06/10/moftastic_powershell/)
    	* [WMIS: The Missing Piece of the Ownage Puzzle - Christopher Campbell, Exorcyst(2013)](http://passing-the-hash.blogspot.com/2013/07/WMIS-PowerSploit-Shells.html)
	    * [PowerShell and Events: WMI Temporary Event Subscriptions - Boe Prox(2013)](https://learn-powershell.net/2013/08/02/powershell-and-events-wmi-temporary-event-subscriptions/)
    	* [Introduction to WMI Basics with PowerShell Part 1 (What it is and exploring it with a GUI) - Carlos Perez(2013)](https://www.darkoperator.com/blog/2013/1/31/introduction-to-wmi-basics-with-powershell-part-1-what-it-is.html)
		* [Thoughts on Exploiting a Remote WMI Query Vulnerability  - Matt Graeber(2015)](http://www.exploit-monday.com/2015/12/thoughts-on-exploiting-remote-wmi-query.html)
		* [WMI Process Watcher - Vault7 Leaks](https://wikileaks.org/ciav7p1/cms/page_52920355.html)
			* A technique to asynchronously detect when a process is created using WMI.
		* [WMI object correlation using 'ASSOCIATORS OF'- Matt Graeber(2015)](http://www.exploit-monday.com/2015/12/wmi-object-correlation-using.html)
		* [A Novel WMI Persistence Implementation - Counter Threat Unit Research Team(Dell2016)](https://www.secureworks.com/blog/wmi-persistence)
    	* [Creeping on Users with WMI Events: Introducing PowerLurk - Sw4mp_f0x(2016)](https://pentestarmoury.com/2016/07/13/151/)
	    * [A Brief Usage Guide for Wmic - xorrior(2016)](https://www.xorrior.com/wmic-the-enterprise/)
    	* [Getting Started with WMI Weaponization – Part 2 - Alexander Leary](https://blog.netspi.com/getting-started-wmi-weaponization-part-2/)	
		* [Getting Started with WMI Weaponization – Part 5 - Alexander Leary(2017)](https://blog.netspi.com/getting-started-wmi-weaponization-part-5/)
    	* [Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY) - Matthew Dunwoody(2017)](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html)
	    * [Lateral Movement Using WinRM and WMI - Tony Lambert(2017)](https://redcanary.com/blog/lateral-movement-winrm-wmi/)
    	* [Post Exploitation Using WMIC (System Command) - hackingarticles.in(2018)](https://www.hackingarticles.in/post-exploitation-using-wmic-system-command/)    
	    * [Windows Userland Persistence Fundamentals - FuzzySecurity](http://www.fuzzysecurity.com/tutorials/19.html)
    	* [Detecting & Removing an Attacker’s WMI Persistence - David French(2018)](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96)
	    * [An intro into abusing and identifying WMI Event Subscriptions for persistence - @rebootuser(2019)](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)
	* **Papers**
    	* [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor - Matt Graeber(BHUSA15)](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
	    * [Windows Management Instrumentation(WMI) Offense, Defense, and Forensics - William Ballenthin, Matt Graeber, Claudiu Teodorescu](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)
	* **Presentations/Talks/Videos**
		* [WMI AttacksFrom Theory To Practice - ](https://raw.githubusercontent.com/Orange-Cyberdefense/cme-wmi/master/slides/WMI-Attacks_From_Theory2Practice.pdf)
	    * [Abusing Windows Management Instrumentation (WMI) - Matthew Graeber(BH USA 2015)](https://www.youtube.com/watch?v=0SjMgnGwpq8)
    	    * Imagine a technology that is built into every Windows operating system going back to Windows 95, runs as System, executes arbitrary code, persists across reboots, and does not drop a single file to disk. Such a thing does exist and it's called Windows Management Instrumentation (WMI). With increased scrutiny from anti-virus and 'next-gen' host endpoints, advanced red teams and attackers already know that the introduction of binaries into a high-security environment is subject to increased scrutiny. WMI enables an attacker practicing a minimalist methodology to blend into their target environment without dropping a single utility to disk. WMI is also unlike other persistence techniques in that rather than executing a payload at a predetermined time, WMI conditionally executes code asynchronously in response to operating system events. This talk will introduce WMI and demonstrate its offensive uses. We will cover what WMI is, how attackers are currently using it in the wild, how to build a full-featured backdoor, and how to detect and prevent these attacks from occurring.
	    * [Building Better Backdoors with WMI - Alexander Leary(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/s01-building-better-backdoors-with-wmi-alexander-leary)
	    	* [Slides](https://www.slideshare.net/AlexanderLeary/building-better-backdoors-with-wmi-derbycon-2017)
    		* This presentation will provide a brief overview of WMI, and how creating WMI providers can be leveraged to create a reliable and covert persistence mechanism for offensive security professionals to use.
	    * [Basic Offensive Application of MOF Files in WMI Scripting - Devon Bordonaro(BSidesCharm2018)](https://www.irongeek.com/i.php?page=videos/bsidescharm2018/track-1-03-basic-offensive-application-of-mof-files-in-wmi-scripting-devon-bordonaro)
    		* A basic introduction on how to use MOF files and the Windows Management Instrumentation (WMI) database to alter how programs execute and implement your own processes. Join us for a walkthrough of MOF design and an overview of the vulnerabilities presented by the WMI database. Finally, learn how the hardest part of using MOF files is making yourself known to the user.
	    * [Fud WMI for lateral movement (PoC) - ##BsidesDub 2019##](https://github.com/kmkz/PowerShell/tree/master/BsidesDublin-2019)
    		* This repository contains the PowerShell WMI based Proof of Concept for advanced lateral movement as presented at BsidesDub 2019.The main goal of this project was to demonstrate the techniques an attacker might use to bypass detection mechanisms using many techniques in real-life condition.It implement random class name derivation mechanism, payload obfuscation, in-memory execution without any call to IEX nor IWR for the stage 1 dropper and an EventViewer logs removal through WMI un-subscription method.
	* **Reference**
    	* [Connecting to WMI Remotely with C# - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/connecting-to-wmi-remotely-with-c-)
	    * [Windows Command Line cheatsheet (part 1): some useful tips - Andrea Fortuna](https://www.andreafortuna.org/2017/08/03/windows-command-line-cheatsheet-part-1-some-useful-tips/)
    	* [Windows Command Line cheatsheet (part 2): WMIC - Andrea Fortuna](https://www.andreafortuna.org/2017/08/09/windows-command-line-cheatsheet-part-2-wmic/)
	* **Tools**
    	* [WMI_Backdoor](https://github.com/mattifestation/WMI_Backdoor)
        	* A PoC WMI backdoor presented at Black Hat 2015
		* [cme-wmi](https://github.com/Orange-Cyberdefense/cme-wmi)
        	* Experimental plugin for CrackMapExec that adds a new protocol based on pure WMI : all of CrackMapExec's traffic passes via DCOM (TCP/135 and dynamic ports).
		* [WMIOps](https://github.com/FortyNorthSecurity/WMIOps)
        	* This repo is for WMIOps, a powershell script which uses WMI for various purposes across a network.
      * [WMImplant](https://github.com/FortyNorthSecurity/WMImplant)
			* This is a PowerShell based tool that is designed to act like a RAT. Its interface is that of a shell where any command that is supported is translated into a WMI-equivalent for use on a network/remote machine. WMImplant is WMI based. 
		* [PowerProvider](https://github.com/0xbadjuju/PowerProvider)
		* [WheresMyImplant: A C# Bring-Your-Own-Land toolkit](https://github.com/0xbadjuju/WheresMyImplant)
			* A Bring Your Own Land Toolkit that Doubles as a WMI Provider 
* **Windows Notification Facility**<a name="wnf"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Windows Process Injection : Windows Notification Facility - modexp(2019)](https://modexp.wordpress.com/2019/06/15/4083/)
		* [Playing with the Windows Notification Facility (WNF) - Gwaby(2019)](https://blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf.html)
	* **Talks/Presentations/Videos**
		* [Windows Notification Facility: Peeling the Onion of the Most Undocumented Kernel Attack Surface Yet - Alex Ionescu, Gabrielle Viala](https://www.youtube.com/watch?v=MybmgE95weo)
			* [Slides](https://web.archive.org/web/20200109034333/http://www.alex-ionescu.com:80/publications/BlackHat/blackhat2018.pdf)
			* All Windows researchers know about RPC and ALPC, and the attack surface provided through the kernel's system call layer. As they know about shared memory, the object manager, the registry, and countless other more 'creative' kernel mechanisms which allow cross-process data sharing and communication, such as raw ETW or atom tables.
	* **Tools**
		* [wnfun](https://github.com/ionescu007/wnfun)
			* WNF Utilities 4 Newbies (WNFUN) is the repository for the Python scripts and C tools that Gabrielle Viala (@pwissenlit) and Alex Ionescu (@aionescu) wrote for their BlackHat 2018 presentation on the Windows Notification Facility.
* **Windows Remote Management**<a name="winrm"></a>
	* **101**
		* [Windows Remote Management - Wikipedia](https://en.wikipedia.org/wiki/Windows_Remote_Management)
		* [Windows Remote Management - docs.ms](https://docs.microsoft.com/en-us/windows/win32/winrm/portal)
			* Windows Remote Management (WinRM) is the Microsoft implementation of WS-Management Protocol, a standard Simple Object Access Protocol (SOAP)-based, firewall-friendly protocol that allows hardware and operating systems, from different vendors, to interoperate. The WS-Management protocol specification provides a common way for systems to access and exchange management information across an IT infrastructure. WinRM and Intelligent Platform Management Interface (IPMI), along with the Event Collector are components of the Windows Hardware Management features.
		* [Installation and configuration for Windows Remote Management - docs.ms](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
		* [winrs - docs.ms](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs)
	* **Articles/Blogposts/Writeups**
		* [WinRM is my Remote Access Tool - Raphael Mudge(2015)](https://blog.cobaltstrike.com/2015/07/22/winrm-is-my-remote-access-tool/)
		* [Lateral Movement – WinRM - Pentestlab.blog(2018)](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)
		* [Group Policies: Enabling WinRM for Windows Client Operating Systems (Windows 10, Windows 8, Windows 7) -  Patrick Gruenauer(2018)](https://sid-500.com/2018/08/16/enabling-winrm-for-windows-client-operating-systems-windows-10-windows-8-windows-7/)
		* [Hacking Windows Remote Management (WinRM) - Securethelogs(2019)](https://securethelogs.com/2019/08/30/hacking-windows-remote-management-winrm/)
		* [WinRM - JPCert](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WinRM.htm)
		* [WinRM Penetration Testing - Raj Chandel(2020)](https://www.hackingarticles.in/winrm-penetration-testing/)
		* [Evil-Winrm : Winrm Pentesting Framework - Raj Chandel(2020)](https://www.hackingarticles.in/evil-winrm-winrm-pentesting-framework/)
	* **Talks/Presentations/Videos**
	* **Tools**
		* [winrs - docs.ms](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs)
		* [Scripting in Windows Remote Management - docs.ms](https://docs.microsoft.com/en-us/windows/win32/winrm/scripting-in-windows-remote-management)
		* [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
			* "The ultimate WinRM shell for hacking/pentesting"
		* [CSharpWinRM](https://github.com/mez-0/CSharpWinRM)
			* .NET 4.0 WinRM API Command Execution
		* [WinRMDLL](https://github.com/mez-0/winrmdll)
			* C++ WinRM API via Reflective DLL
		* [WSMan-WinRM](https://github.com/bohops/WSMan-WinRM)
			* A collection of proof-of-concept source code and scripts for executing remote commands over WinRM using the WSMan.Automation COM object.
		* [pywinrm](https://pypi.org/project/pywinrm/0.2.2/)
			* pywinrm is a Python client for the Windows Remote Management (WinRM) service. It allows you to invoke commands on target Windows machines from any machine that can run Python.
		* [winrm.py - CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/winrm.py)
		* [Metasploit](https://www.rapid7.com/blog/post/2012/11/08/abusing-windows-remote-management-winrm-with-metasploit/)
		* [WinRb/WinRM](https://github.com/WinRb/WinRM)
			* Ruby library for Windows Remote Management 
* **Windows Sandbox**<a name="wsbx"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [The Windows Sandbox Paradox - James Forshaw(Nullcon2015)](https://www.youtube.com/watch?v=w1O3b9cZEtE)
			* [Slides](https://nullcon.net/website/archives/ppt/goa-15/the-windows-sandbox-paradox.pdf)
		* [The Windows Sandbox Paradox: Flashback - James Forshaw(Nullcon2019)](https://www.youtube.com/watch?v=qg3sr677srY)
			* [Slides](https://nullcon.net/website/archives/pdf/The-Windows-Sandbox-Paradox-(Flashback)-James-Forshaw-nullcon-goa-2019.pdf)
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
		* [The wscript.Shell + Shell.Application objects - SS64](https://ss64.com/vb/shell.html)
		* [WScript - devguru.com](https://www.devguru.com/content/technologies/wsh/objects-wscript.html)
	* **VBS**
		* [On VBScript - Ivan Fratric(2018)](https://googleprojectzero.blogspot.com/2018/12/on-vbscript.html)
* **Malicious Butler**
	* [The Remote Malicious Butler Did It! - Tal Be'ery, Chaim Hoch(BHUSA 2015)](https://www.youtube.com/watch?v=xujWesUS1ZQ)
		* An Evil Maid attack is a security exploit that targets a computing device that has been left unattended. An evil maid attack is characterized by the attacker's ability to physically access the target multiple times without the owner's knowledge. On BlackHat Europe 2015, Ian Haken in his talk "Bypassing Local Windows Authentication to Defeat Full Disk Encryption" had demonstrated a smart Evil Maid attack which allows the attacker to bypass Bitlocker disk encryption in an enterprise's domain environment. The attacker can do so by connecting the unattended computer into a rogue Domain Controller and abusing a client side authentication vulnerability. As a result, Microsoft had released a patch to fix this vulnerability and mitigate the attack. While being a clever attack, the physical access requirement for the attack seems to be prohibitive and would prevent it from being used on most APT campaigns. As a result, defenders might not correctly prioritize the importance of patching it. In our talk, we reveal the "Remote Malicious Butler" attack, which shows how attackers can perform such an attack, remotely, to take a complete control over the remote computer. We will dive into the technical details of the attack including the rogue Domain Controller, the client-side vulnerability and the Kerberos authentication protocol network traffic that ties them. We would explore some other attack avenues, all leveraging on the rogue Domain Controller concept. We would conclude with the analysis of some practical generic detection and prevention methods against rogue Domain Controllers.
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Beery-The-Remote-Malicious-Butler-Did-It.pdf)
----------------------------------------------------------------------------------------------------------------------------------




































----------------------------------------------------------------------------------------------------------------------------------
#### <a name="csharp-stuff">C# & .NET Stuff</a>
* **101**
	* **.NET & .NET Core**
		* **101**
			* [Overview of .NET Framework - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/get-started/overview)
			* [Introduction to .NET Core - docs.ms](https://docs.microsoft.com/en-us/dotnet/core/introduction)
			* [.NET Core CLI overview - docs.ms](https://docs.microsoft.com/en-us/dotnet/core/tools/)
			* [.NET Standard - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/net-standard)
			* [Tour of .NET - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/tour)
				* This article offers a guided tour through some of the key features of the .NET.
			* [.NET architectural components - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/components)
				* A .NET app is developed for and runs in one or more implementations of .NET. Implementations of .NET include the .NET Framework, .NET Core, and Mono. There is an API specification common to all implementations of .NET that's called the .NET Standard. This article gives a brief introduction to each of these concepts.
			* [Common Language Runtime (CLR) overview - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/clr)
			* [An Introduction to Writing .NET Executables for Pentesters - Peew.pw(2017](https://www.peew.pw/blog/2017/11/24/an-introduction-to-writing-net-executables-for-pentesters)
				* [Part 2](https://www.peew.pw/blog/2017/12/4/writing-net-executables-for-penteters-part-2)
		* **Application Domains**
			* [AppDomain Class - docs.ms](https://docs.microsoft.com/en-us/dotnet/api/system.appdomain?view=netcore-3.1)
				* Represents an application domain, which is an isolated environment where applications execute. This class cannot be inherited.
		* **Internals**
			* [Ninja Patching .NET - Jon McCoy(Dojocon2010)](https://web.archive.org/web/20170321162306/http://www.irongeek.com/i.php?page=videos/dojocon-2010-videos#Ninja%20Patching%20.NET)
				* [Youtube](https://www.youtube.com/watch?v=3jit5unJzys)
			* [Hacking .NET Applications at Runtime: A Dynamic Attack - Jon McCoy(Defcon18)](https://web.archive.org/web/20191203175515/https://www.defcon.org/html/defcon-18/dc-18-speakers.html#McCoy)
				* [Slides](https://www.defcon.org/images/defcon-19/dc-19-presentations/McCoy/DEFCON-19-McCoy-Hacking-Net.pdf)
			* [Attacking .Net at Runtime - Jonathan McCoy(2013)](https://web.archive.org/web/20181028060806/http://www.digitalbodyguard.com/Papers/Attacking%20.Net%20at%20Runtime.pdf)
				* This paper will introduce methodology forattacking  .NET programs at runtime. Thisattack will grant control over the targetsvariables, core logic, and the GUI. Thisattack is implemented with .NET code,and is heavily based on reflection. 
			* [.NET Method Internals - Common Intermediate Language (CIL) Basics - @mattifestation(2014)](http://www.exploit-monday.com/2014/07/dotNETMethodInternals.html)
			* [Acquiring .NET Objects from the Managed Heap - Topher Timzen(2015)](https://www.tophertimzen.com/resources/grayStorm/AcquiringDotNetObjectsFromTheManagedHeap.pdf)
				* This paper will describe how to use any instantiated objectin the .NET CLR managed heap as if it were declared locally.It will be shown that by referencing object pointers fromthe managed heap, an attacker control objects being used inan application. Reflective techniques will be discussed and asignature will be introduced to find any object on the managedheap
			* [Attacking Microsoft’s .NET Framework Through CLR - Yu Hong, Shikang Xing(HITB2018AMS)](https://conference.hitb.org/hitbsecconf2018ams/sessions/attacking-microsofts-net-framework-through-clr/)
				* In this talk, we first introduce managed execution environment and managed code under .NET Framework and discuss the security weaknesses of this code execution method . After that, we show a exploit for SQL Server through CLR and our automated tools for this exploitation. We will introduce a backdoor with administrator privilege based on CLR hijacking arbitrary .NET Applications.
			* [.NET Malware Threat: Internals and Reversing - Alexandre Borges(Defcon2019)](http://www.blackstormsecurity.com/docs/ALEXANDREBORGES_DEFCON_2019.pdf)
			* [Hijacking .NET to Defend PowerShell - Amanda Rosseau](https://arxiv.org/pdf/1709.07508.pdf)
				* Abstract—With the rise of attacks using PowerShell in the recent months, there has not been a comprehensive solution for monitoring or prevention. Microsoft recently released the AMSI solution for PowerShell v5, however this can also be bypassed. This paper focuses on repurposing various stealthy runtime .NET hijacking techniques implemented for PowerShell attacks for defensive monitoring of PowerShell. It begins with a brief introduction to .NET and PowerShell, followed by a deeper explanation of various attacker techniques, which is explained from the perspective of the defender, including assembly modification, class and method injection, compiler profiling, and C based function hooking. Of the four attacker techniques that are repurposed for defensive real-time monitoring of PowerShell execution, intermediate language binary modification, JIT hooking, and machine code manipulation provide the best results for stealthy run-time interfaces for PowerShell scripting analysis		
			* [How .NET executables are loaded - repnz(2019)](https://repnz.github.io/posts/dotnet-executable-load/)
			* [Common Language Runtime: Who? why? how? - Mez0](https://mez0.cc/posts/common-language-runtime-1/)
			* [Common Language Runtime 2: In memory execution - Mez0](https://mez0.cc/posts/common-language-runtime-2/)
		* **Managed vs Unmanaged code**
			* [What is "managed code"? - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/managed-code)
				* When working with .NET Framework, you will often encounter the term "managed code". This document will explain what this term means and additional information around it.
		* **Papers**
			* [Reflection’s Hidden Power: “Modifying Programs at Run-Time”](https://web.archive.org/web/20171208224139/http://www.digitalbodyguard.com/Papers/ReflectionsHiddenPower.pdf)
				* This paper will demonstrate using Reflection to take control over a DotNet (.Net)compiled code. The focus of this paper will be on how to use Reflection to navigate and gainaccess to values and functionality that would normally be off limits. This paper will be gearedfor any DotNet programmer (focus will be in C#). No special knowledge of Reflection isnecessary. The basic concept of Reflection and DotNet will be given, along with some lighttraining on using reflection. This paper is written for the DotNet v2.0 and v3.5 versions ofDotNet. Examples will be given on attacks, like forcing a program to change values and executefunctionality
			* [ASM in .NET: The old is new again - Jon McCoy(2015)](https://web.archive.org/web/20170829012346/http://www.digitalbodyguard.com/Papers/ASM%20in%20.NET-The%20old%20is%20new%20again.pdf)
				* This paper will cover running raw Machine Code(ASM) from within .NET. As we all know .NET runson IL(Intermediate Language) also known as “Managed byte code”. A program can declare an unsafesection of code and drop out from the managed area to run something like unmanaged C++ or the like.This paper will show how to run raw/unmanaged ASM in a normal safe C# application.
	* **C#**
		* **101**
			* [A tour of the C# language - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/tour-of-csharp/)
				* C# (pronounced "See Sharp") is a modern, object-oriented, and type-safe programming language. C# has its roots in the C family of languages and will be immediately familiar to C, C++, Java, and JavaScript programmers. This tour provides an overview of the major components of the language in C# 8 and earlier. 
		* **Learning**
			* [Get started with C# - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/getting-started/)
			* [Inside a C# program - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/)
				* The section discusses the general structure of a C# program, and includes the standard "Hello, World!" example.
			* [C# 101 - Channel9 MSDN](https://channel9.msdn.com/Series/CSharp-101)
		* **Reflection**
			* [Security Considerations for Reflection - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/security-considerations-for-reflection)
			* [Securing the loading of dynamic code - F-Secure(2016)](https://labs.f-secure.com/archive/securing-the-loading-of-dynamic-code/)
			* [Use reflection to list a class’s properties in C# - Rod Stephens(2018)](http://csharphelper.com/blog/2018/02/use-reflection-to-list-a-classs-properties-in-c/)	
		* **Scripting/ClearScript**
			* [ClearScript](https://github.com/microsoft/ClearScript)
				* A library for adding scripting to .NET applications. Supports V8 (Windows, Linux, macOS) and JScript/VBScript (Windows). 
			* [ClearScript FAQtorial](https://microsoft.github.io/ClearScript/Tutorial/FAQtorial)
			* [Cutting Edge : A Look at ClearScript - Dino Esposito(2014 docs.ms)](https://docs.microsoft.com/en-us/archive/msdn-magazine/2014/september/cutting-edge-a-look-at-clearscript)
	* **Detection**
		* [Interesting DFIR traces of .NET CLR Usage Logs - MenaSec(2019)](https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html)
		* [Hijacking .NET to Defend PowerShell - Amanda Rosseau](https://arxiv.org/pdf/1709.07508.pdf)
			* Abstract—With the rise of attacks using PowerShell in the recent months, there has not been a comprehensive solution for monitoring or prevention. Microsoft recently released the AMSI solution for PowerShell v5, however this can also be bypassed. This paper focuses on repurposing various stealthy runtime .NET hijacking techniques implemented for PowerShell attacks for defensive monitoring of PowerShell. It begins with a brief introduction to .NET and PowerShell, followed by a deeper explanation of various attacker techniques, which is explained from the perspective of the defender, including assembly modification, class and method injection, compiler profiling, and C based function hooking. Of the four attacker techniques that are repurposed for defensive real-time monitoring of PowerShell execution, intermediate language binary modification, JIT hooking, and machine code manipulation provide the best results for stealthy run-time interfaces for PowerShell scripting analysis
		* [Sniper](https://github.com/dmchell/Sniper)
	* **Informational**
		* [A Lesson in .NET Framework Versions - Rastamouse](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)
* **Training**
	* [Writing custom backdoor payloads with C# - Mauricio Velazco, Olindo Verrillo(Defcon27Workshops)](https://github.com/mvelazc0/defcon27_csharp_workshop)
* **Discovery**
	* **Clipboard**
		* [Clippi-B](https://github.com/jfmaes/Clippi-B)
			* Steals clipboard data written in c#, executable by cobalt-strike or any other unmanaged CLR loader. you'll need costura.fody NuGet package to compile. Targets .NET 4.0 or above, but is potentially backwards compatible with 3.5 if you use an older costura fody NuGet (untested)
	* **ActiveDirectory**
		* [Recon-AD](https://github.com/outflanknl/Recon-AD)
			* As a proof of concept, we[OutflankNL] developed an C/C++ Active Directory reconnaissance tool based on ADSI and reflective DLLs which can be used within Cobalt Strike. The tool is called “Recon-AD” and at this moment consist of seven Reflective DLLs and a corresponding aggressor script. This tool should help you moving away from PowerShell and .NET when enumerating Active Directory and help you stay under the radar from the latest monitoring and defense technologies being applied within modern environments.
		* [SharpView](https://github.com/tevora-threat/SharpView)
	* **Browser**
		* [SharpChromium](https://github.com/djhohnstein/SharpChromium)
			* SharpChromium is a .NET 4.0+ CLR project to retrieve data from Google Chrome, Microsoft Edge, and Microsoft Edge Beta.
	* **File Discovery/Hunting**
		* [SharpShares](https://github.com/djhohnstein/SharpShares)
			* Enumerate all network shares in the current domain. Also, can resolve names to IP addresses. 
		* [SauronEye](https://github.com/vivami/SauronEye)
			* Search tool to find specific files containing specific words, i.e. files containing passwords.. 
		* [SharpFiles](https://github.com/fullmetalcache/SharpFiles)
		* [SharpFinder](https://github.com/s0lst1c3/SharpFinder)
			* Searches for files matching specific criteria on readable shares within the domain.
	* **Network Services**
		* [SharpSSDP](https://github.com/rvrsh3ll/SharpSSDP)
			* SSDP Service Discovery
	* **Printers**
		* [SharpPrinter](https://github.com/rvrsh3ll/SharpPrinter)
			* Printer is a modified and console version of ListNetworks
	* **Screenshots**
		* [ScreenShooter](https://github.com/FortyNorthSecurity/Screenshooter)
			* C# program to take a full size screenshot of the window. Takes in 0 or 1 flag for a filename. 
			* [Blogpost](https://fortynorthsecurity.com/blog/screenshooter/)
	* **Services**
		* [AtYourService](https://github.com/mitchmoser/AtYourService)
			* C# .NET Assembly and python script for Service Enumeration. Queries all services on a host and filters out services running as LocalSystem, NT Authority\LocalService, and NT Authority\NetworkService
	* **Situational Awarness**
		* [Reconerator](https://github.com/stufus/reconerator)
			* This is a custom .NET assembly which will perform a number of situational awareness activities. 
		* [Scout](https://github.com/jaredhaight/scout)
			* Scout is a .NET assembly used to perform recon on hosts during a pentest. Specifically, this was created as a way to check a host before laterally moving to it.
		* [SitRep](https://github.com/mdsecactivebreach/sitrep)
			* SitRep is intended to provide a lightweight, extensible host triage alternative. Checks are loaded dynamically at runtime from stand-alone files. This allows operators to quickly modify existing checks, or add new checks as required.
		* [SharpAppLocker](https://github.com/Flangvik/SharpAppLocker)
			* C# port of the Get-AppLockerPolicy PS cmdlet
		* [Seatbelt](https://github.com/GhostPack/Seatbelt)
			* Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
		* [HastySeries](https://github.com/obscuritylabs/HastySeries)
			* A C# toolset to support offensive operators to triage, asses and make intelligent able decisions. Provided operators access to toolsets that can be integrated into other projects and workflow throughout a Red Team, Pentest or host investigation. We built this toolset over a period of a few days, hence the tool prefix of "Hasty".
	* **User-Hunting**
		* [SharpSniper](https://github.com/HunnicCyber/SharpSniper)
			*  Find specific users in active directory via their username and logon IP address 
	* **Web**
		* [SharpWitness](https://github.com/rasta-mouse/SharpWitness)
			* SharpWitness is my attempt at cobbling together a C# version of EyeWitness by Christopher Truncer. It still barely functions right now, but will hopefully become more useful once I put some dev time into it.
		* [SharpFruit](https://github.com/rvrsh3ll/SharpFruit)
			* A C# penetration testing tool to discover low-haning web fruit via web requests.
		* [SharpShot](https://github.com/two06/SharpShot)
			* Capture screenshots from .NET, using either native Windows APIs or .NET methods. Screenshots can be saved to disk using a randomly generated file name, or output to the console in base64 encoded form (does not touch disk).
* **Execution Tactics/Techniques**
	* **101**
		* [Reflection in the .NET Framework - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/reflection)
		* [Reflection (C#) - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/reflection)
		* [Reflection (Visual Basic) - docs.ms](https://docs.microsoft.com/en-us/dotnet/visual-basic/programming-guide/concepts/reflection)
		* [Reflection in .NET - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/reflection)
		* [Application Domains - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/app-domains/application-domains)
		* [Platform Invoke (P/Invoke) - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)
		* [Mixed (native and managed) assemblies - docs.ms](https://docs.microsoft.com/en-us/cpp/dotnet/mixed-native-and-managed-assemblies?view=vs-2019)
	* **Articles/Blogposts/Writeups**
		* [Create a Trimmed Self-Contained Single Executable in .NET Core 3.0 - talkingdotnet.com](https://www.talkingdotnet.com/create-trimmed-self-contained-executable-in-net-core-3-0/)
		* [The 68 things the CLR does before executing a single line of your code - mattwarren.org](https://web.archive.org/web/20170614215931/http://mattwarren.org:80/2017/02/07/The-68-things-the-CLR-does-before-executing-a-single-line-of-your-code/)
		* [In Process Execute Assembly and Mail Slots - N4kedTurtle(2020)](https://teamhydra.blog/2020/10/12/in-process-execute-assembly-and-mail-slots/)
			* [Poc](https://github.com/N4kedTurtle/ExecuteAssembly_Mailslot)
		* [SharpNado - Teaching an old dog evil tricks using .NET Remoting or WCF to host smarter and dynamic payloads - redxorblue](http://blog.redxorblue.com/2018/12/sharpnado-teaching-old-dog-evil-tricks.html)
			* SharpNado is proof of concept tool that demonstrates how one could use .Net Remoting or Windows Communication Foundation (WCF) to host smarter and dynamic .NET payloads.  SharpNado is not meant to be a full functioning, robust, payload delivery system nor is it anything groundbreaking. It's merely something to get the creative juices flowing on how one could use these technologies or others to create dynamic and hopefully smarter payloads. I have provided a few simple examples of how this could be used to either dynamically execute base64 assemblies in memory or dynamically compile source code and execute it in memory.  This, however, could be expanded upon to include different kinds of stagers, payloads, protocols, etc.
		* [Detecting and Advancing In-Memory .NET Tradecraft - Dominic Chell(2020)](https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/)	
	* **Talks/Presentations/Videos**
		* [.NET Manifesto - Win Friends and Influence the Loader - Casey Smith(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-28-net-manifesto-win-friends-and-influence-the-loader-casey-smith)
			* Everything you never wanted to know about .NET manifests and influencing binary loading. A growing number of security tools, both offensive and defensive rely on the .NET Framework. This talk will focus on a narrow but important aspect. We will cover Application and Machine configuration files, as well as Registration-Free and Side-By-Side Assembly loading. What do all these have in common?Manifests. XML manifest can influence how the Operating System locates and executes binaries. We will explore additional concepts around influencing assembly loads. This talk will provide excellent insight into how these mechanisms work. How they can be subverted, and how they can be instrumented to aid defenders.
		* [Staying # & Bringing Covert Injection Tradecraft to .NET - The Wover, Ruben Boonen(BlueHat IL 2020)](https://www.youtube.com/watch?v=FuxpMXTgV9s&feature=share)
			* As .NET has taken over as the preferred platform for development on Windows, many attackers have chosen to take advantage of its features for post-exploitation tradecraft. Legitimate APIs can be leveraged for nearly every imaginable task, managed code can be loaded and executed from memory with extraordinary ease, and scalable monitoring for suspicious usage of .NET APIs is a problem yet to be solved. However, offensive .NET tools are still hindered by a fundamental weakness: the inability to leverage unmanaged code (such as the Win32/NT APIs) safe from observation by EDR. Managed code must eventually invoke unmanaged code in order to interface with the operating system. It is here that the attacker may be caught in the hooks of any system keen on watching for fundamentally malicious behavior. To expose the depth of tradecraft still unexplored in .NET and highlight the fragility of many existing detections, we will detail the tools we have built for evading these hooks. All of our efforts have been integrated into SharpSploit, a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers. Over the past few months we have added numerous new tools and techniques for loading and executing unmanaged code safely from .NET. Unmanaged APIs may be safely accessed and modules loaded either from memory or from disk in the new DInvoke API, a dynamic replacement for .NET's PInvoke API. It also includes manual mapping, a generic syscall wrapper, a new technique we call Module Overloading, and more. Additionally, we have added a modular process injection API that allows tool developers to build their own injection technique. Simply select an allocation and injection primitive, pass in any options, and execute the result with your preferred payload. This exposes all possible design decisions to the user, and allows for easy adaptation when existing tools fail. In our talk we will focus on explaining the fundamental tradecraft behind these new developments, the challenges and requirements associated with them, and how they can be adapted to suit your needs. Additionally, we will discuss how SharpSploit can be combined with other open-source projects to be integrated into a red team's tooling. As much as possible, we will also discuss how to counter and detect the techniques that we have developed. Finally, we will explain the community-focused development of these projects and how you too can contribute to advance open-source .NET tradecraft
	* **Papers**
		* [.NET Instrumentation via MSIL bytecode injection - Antonio "s4tan" Parata(2018)](http://phrack.org/papers/dotnet_instrumentation.html)
	* **Tools**
		* [SharpCollection - Flangvik](https://github.com/Flangvik/SharpCollection)
			* Nightly builds of common C# offensive tools, fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
		* [SharpGen](https://github.com/cobbr/SharpGen)
			*  SharpGen is a .NET Core console application that utilizes the Rosyln C# compiler to quickly cross-compile .NET Framework console applications or libraries.
		* [SharpCompile](https://github.com/SpiderLabs/SharpCompile)
			* SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing using beacon's 'execute-assembly' in seconds.
		* [NetLoader](https://github.com/Flangvik/NetLoader)
			* Loads any C# binary from filepath or url, patching AMSI and bypassing Windows Defender on runtime
		* [AppDomainExample](https://github.com/xfox64x/AppDomainExample)
			* A .NET tool that uses AppDomain's to enable dynamic execution and escape detection. 
		* [SharpAttack](https://github.com/jaredhaight/SharpAttack)
			* SharpAttack is a console for certain things I use often during security assessments. It leverages .NET and the Windows API to perform its work. It contains commands for domain enumeration, code execution, and other fun things.
		* [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack)
			* Many usefull offensive CSharp Projects wraped into Powershell for easy usage.
		* [peloader.cs](https://github.com/Arno0x/CSharpScripts/blob/master/peloader.cs)
			* This scripts loads a base64 encoded x64 PE file (eg: Mimikatz or a Meterpreter) into memory and reflectively executes it.
		* [RunSharp](https://github.com/fullmetalcache/RunSharp)
			* Simple program that allows you to run commands as another user without being prompted for their password. This is useful in cases where you don't always get feedback from a prompt, such as the case with some remote shells.
		* [GrayFrost](https://github.com/graykernel/GrayFrost)
			* GrayFrost is a C++ DLL delivery system for C# payloads. Once compiled, GrayFrost can be injected into .NET applications using any DLL injection technique you wish!
			* [RunPE](https://github.com/nettitude/RunPE)
				* C# Reflective loader for unmanaged binaries.
			* [RunasCs](https://github.com/antonioCoco/RunasCs)
				* RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials.
			* [RunDLL.Net](https://github.com/p3nt4/RunDLL.Net)
				* Execute .Net assemblies using Rundll32.exe
			* [Fork-n-Run](https://github.com/rasta-mouse/Fork-n-Run)
				* Experimenting with reusable components for fork n' run operations.
			* [ExecuteAssembly](https://github.com/med0x2e/ExecuteAssembly)
				* ExecuteAssembly is an alternative of CS execute-assembly, built with C/C++ and it can be used to Load/Inject .NET assemblies by; reusing the host (spawnto) process loaded CLR Modules/AppDomainManager, Stomping Loader/.NET assembly PE DOS headers, Unlinking .NET related modules, bypassing ETW+AMSI, avoiding EDR hooks via NT static syscalls (x64) and hiding imports by dynamically resolving APIs via superfasthash hashing algorithm.
			* [SharpZipRunner](https://github.com/jfmaes/SharpZipRunner)
				* Executes position independent shellcode from an encrypted zip. Get PIC code from your assembly either by using donut or metasploit or cobaltstrike RAW format.
			* [RunDllMShim](https://github.com/dsnezhkov/RunDllMShim)
				* A bridge DLL to make calling a managed assembly/type/method from an unmanaged dll invoker rundll32.exe easier)
			* [Marauders Map](https://github.com/NVISOsecurity/blogposts/tree/master/MaraudersMap)
				* The internal attacker toolkit heavily inspired by the folks of MDSec and their SharpPack, highly recommend checking that post out. The Marauders Map is meant to be used on assessments where you have gained GUI access to an enviornment. The Marauders Map is a DLL written in C#, enriched by the DllExport project to export functions that can serve as an entrypoint of invocation for unmanaged code such as rundll32.
			* [CSharpExec](https://github.com/mez-0/CSharpExec)
				* This project can use both the current context and credentials to connect to a remote host, copy the payload, and then create and start a service. Once the service is running, it will then remove it.
			* [CSharpRunAs](https://github.com/mez-0/CSharpRunAs)
				* Run As... In C#...
			* [DInvoke](https://github.com/TheWover/DInvoke)
				* Dynamically invoke arbitrary unmanaged code from managed code without PInvoke. 
			* [InMemoryNET](https://github.com/mez-0/InMemoryNET)
				*  Exploring in-memory execution of .NET 
			* [CoreSploit](https://github.com/checkymander/CoreSploit)
				* A Post-Exploitation Framework written for .NET 5.0 (Previously known as .NET Core)
			* [SharpMapExec](https://github.com/cube0x0/SharpMapExec)
				* A sharpen version of CrackMapExec. This tool is made to simplify penetration testing of networks and to create a swiss army knife that is made for running on Windows which is often a requirement during insider threat simulation engagements.
			* [ExecutionTesting.cs](https://github.com/leoloobeek/csharp)
				* Execute process under a different PID and retrieve the output.
			* [metasploit-execute-assembly](https://github.com/b4rtik/metasploit-execute-assembly)
				* Custom Metasploit post module to executing a .NET Assembly from Meterpreter session 
			* [Vanara](https://github.com/dahall/Vanara)
				* A set of .NET libraries for Windows implementing PInvoke calls to many native Windows APIs with supporting wrappers.
			* [AggressiveGadgetToJScript](https://github.com/EncodeGroup/AggressiveGadgetToJScript)
				* A Cobalt Strike Aggressor script to generate GadgetToJScript payloads
			* [Emulating Covert Operations - Dynamic Invocation (Avoiding PInvoke & API Hooks) - TheWover](https://thewover.github.io/Dynamic-Invoke/)
			* [go-dotnet](https://github.com/matiasinsaurralde/go-dotnet)
				* Go wrapper for the .NET Core Runtime. 
			* [go-execute-assembly](https://github.com/lesnuages/go-execute-assembly)
				* Allow a Go process to dynamically load .NET assemblies 
			* [SharpDllProxy](https://github.com/Flangvik/SharpDllProxy)
				* Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading
			* [Massaging your CLR: Preventing Environment.Exit in In-Process .NET Assemblies - Peter Winter-Smith(2020](https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies/)
	* **Adversary Simulation**
		* [PurpleSharp](https://github.com/mvelazc0/PurpleSharp)
			* PurpleSharp is a C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments
	* **Assemblies & AppDomains**
		* **101**
			* [Assemblies in .NET - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/assembly/)
				* Assemblies form the fundamental units of deployment, version control, reuse, activation scoping, and security permissions for .NET-based applications. An assembly is a collection of types and resources that are built to work together and form a logical unit of functionality. Assemblies take the form of executable (.exe) or dynamic link library (.dll) files, and are the building blocks of .NET applications. They provide the common language runtime with the information it needs to be aware of type implementations.
			* [Strong-named assemblies - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/assembly/strong-named)
			* [Global Assembly Cache - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/app-domains/gac)
			* [Working with Assemblies and the Global Assembly Cache - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/app-domains/working-with-assemblies-and-the-gac)
			* [Application Domains and Assemblies How-to Topics - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/app-domains/application-domains-and-assemblies-how-to-topics)
				* The following sections contain links to all How-to topics found in the conceptual documentation for programming with application domains and assemblies.
		* **Articles/Blogposts/Writeups**
			* [Mixed Assemblies - Crafting Flexible C++ Reflective Stagers for .NET Assemblies - TheWover](https://thewover.github.io/Mixed-Assemblies/)
			* [Linking dependencies together in C# - Jean Maes(2020)](https://redteamer.tips/linking-dependencies-together-in-c/)
			* [Jeffrey Richter: Excerpt #2 from CLR via C#, Third Edition - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/microsoft_press/jeffrey-richter-excerpt-2-from-clr-via-c-third-edition)
			* [.Net over .net – Breaking the Boundaries of the .Net Framework - Jim Shaver(2018)](https://jimshaver.net/2018/02/22/net-over-net-breaking-the-boundaries-of-the-net-framework/)
		* **Tools**
			* [dnlib](https://github.com/0xd4d/dnlib)
				* .NET module/assembly reader/writer library
			* [ILMerge](https://github.com/dotnet/ILMerge)
				* ILMerge is a utility that merges multiple .NET assemblies into a single assembly.
			* [il-repack](https://github.com/gluck/il-repack)
				* Open-source alternative to ILMerge
		* **Execution of**
			* **Articles/Blogposts/Writeups**
				* [RunDLL32 your .NET (AKA DLL exports from .NET) - Adam Chester](https://blog.xpnsec.com/rundll32-your-dotnet/)
					* In this post I wanted to look at a technique which is by no means new to .NET developers, but may prove useful to redteamers crafting their tools... exporting .NET static methods within a DLL... AKA using RunDLL32 to launch your .NET assembly.
				* [Running a .NET Assembly in Memory with Meterpreter - Thomas Hendrickson](https://www.praetorian.com/blog/running-a-net-assembly-in-memory-with-meterpreter)
				* [Shellcode: Loading .NET Assemblies From Memory(2019)](https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/)
			* **Tools**
			* **DotNetToJScript**
				* **Articles/Blogposts/Writeups**
					* [Executing C# Assemblies from Jscript and wscript with DotNetToJscript - @spottheplanet](https://www.ired.team/offensive-security/defense-evasion/executing-csharp-assemblies-from-jscript-and-wscript-with-dotnettojscript)
					* [Advanced TTPs – DotNetToJScript (Part 1) - Jerry Odegaard(2020)](https://whiteoaksecurity.com/blog/2020/1/16/advanced-ttps-dotnettojscript-part-1)
					* [Advanced TTPs – DotNetToJScript – Part 3 - Jerry Odegaard(2020)](https://whiteoaksecurity.com/blog/2020/2/3/advanced-ttps-dotnettojscript-part-3)
					* [CSharp, DotNetToJScript, XSL - RastaMouse](https://rastamouse.me/blog/xsl/)
					* [Extracting DotNetToJScript’s PE Files - Didier Stevens(2018)](https://blog.didierstevens.com/2018/07/25/extracting-dotnettojscripts-pe-files/)
				* **Tools**
					* [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
						* ﻿This file is part of DotNetToJScript - A tool to generate a JScript which bootstraps an arbitrary .NET Assembly and class.
			* **Inject-as-Shellcode**
				* **Articles/Blogposts/Writeups**
					* [Donut - Injecting .NET Assemblies as Shellcode - TheWover](https://thewover.github.io/Introducing-Donut/)
				* **Tools**
					* [CLRVoyance](https://github.com/Accenture/CLRvoyance)
						* CLRvoyance is a shellcode kit that supports bootstrapping managed assemblies into unmanaged (or managed) processes. It provides three different implementations of position independent shellcode for CLR hosting, as well as a generator script for quickly embedding a managed assembly in position independent shellcode.
					* [Donut](https://github.com/TheWover/donut)
						* Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters
			* **From Native Code**
				* **Tools**
					* [CLRHosting](https://github.com/TheWover/Manager/tree/master/CLRHosting)
    					* Library for reflectively loading .NET Assemblies using only the unmanaged CLR Hosting APIs provided by mscoree.dll. This imitates how the Windows Loader loads .NET EXEs and DLLS. This is the most OpSec friendly way to load Assemblies, since it is bootstrapped by an unmanaged executable (and is therefore harder to reverse) and does not use any .NET Framework libraries (such as System.Reflection). Because the result is an unmanaged PE-formatted EXE or DLL, the result may be injected into processes using standard process injection techniques. Therefore, managed Assemblies may be injected into unmanaged processes. Additionally, unmanaged on-disk stagers (written in C/C++) may be built that load .NET payloads (written in C#, etc.).
    				* [DotNetReflectiveLoading](https://github.com/ambray/DotNetReflectiveLoading)
        				* This project is the culmination of playing around with the native application CLR hosting APIs. It provides the ability to reflectively load and execute code from .NET assemblies, and will be a bit of an exploration of the COM and reflection facilities underpinning .NET on Windows.
    					* [AssemblyLoader](https://github.com/TheWover/AssemblyLoader)
    					    * Loads .NET Assembly Via CLR Loader
    				* [Donut](https://github.com/TheWover/donut)
    					* "Donut contains a CLR Host loader that is converted to shellcode"

	* **MSBuild-related**
		* [Another MSBuild Invocation (February 2020 Edition) - Joe Leon(2020)](https://fortynorthsecurity.com/blog/another-msbuild-bypass-february-2020-edition/)
	* **MS-SQL-related**
		* [Attacking SQL Server CLR Assemblies - Scott Sutherland](https://www.netspi.com/webinars/attacking-sql-server-clr-assemblies-on-demand/)
			* During this webinar we’ll review how to create, import, export, and modify CLR assemblies in SQL Server with the goal of privilege escalation, OS command execution, and persistence. Scott will also share a few PowerUpSQL functions that can be used to execute the CLR attacks on a larger scale in Active Directory environments.
	* **Payloads**
		* [SharPyShell](https://github.com/antonioCoco/SharPyShell)
			* tiny and obfuscated ASP.NET webshell for C# web applications
		* [TCPRelayInjecter2](https://github.com/Arno0x/TCPRelayInjecter2)
			* Tool for injecting a "TCP Relay" managed assembly into an unmanaged process 
		* [Salsa Tools](https://github.com/Hackplayers/Salsa-tools)
			* Salsa Tools is a collection of three different tools that combined, allows you to get a reverse shell on steroids in any Windows environment without even needing PowerShell for it's execution. In order to avoid the latest detection techniques (AMSI), most of the components were initially written on C#. Salsa Tools was publicly released by Luis Vacas during his Talk “Inmersión en la explotación tiene rima” which took place during h-c0n in 9th February 2019.
		* [CasperStager](https://github.com/ustayready/CasperStager)
			* PoC for persisting .NET payloads in Windows Notification Facility (WNF) state names using low-level Windows Kernel API calls.
* **Privilege Escalation**
	* [SharpUp](https://github.com/GhostPack/SharpUp)
		* SharpUp is a C# port of various PowerUp functionality. Currently, only the most common checks have been ported; no weaponization functions have yet been implemented.
	* [Net-GPPPassword](https://github.com/outflanknl/Net-GPPPassword)
		* .NET/C# implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
	* **Active Directory**
		* [Grouper2](https://github.com/l0ss/Grouper2)
			* Find vulnerabilities in AD Group Policy
		* [SharpExchangePriv](https://github.com/panagioto/SharpExchangePriv)
			* A C# implementation of PrivExchange by `@_dirkjan`. Kudos to @g0ldenGunSec, as I relied on his code.
	* **Patches**
		* [Watson](https://github.com/rasta-mouse/Watson)
			* Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
	* **Registry**
		* [Reg1c1de: Windows Registry Privesc Scanner](https://github.com/deadjakk/reg1c1de)
			* Reg1c1de is a tool that scans specified registry hives and reports on any keys where the user has write permissions In addition, if any registry values are found that contain file paths with certain file extensions and they are writeable, these will be reported as well.
		* [Blogpost](https://deadjakk.github.io/registry_privesc.html)
	* **Services**
		* [SneakyService](https://github.com/malcomvetter/SneakyService)
			* A simple C# windows service implementation that can be used to demonstrate privilege escalation from misconfigured windows services.
* **Collection**
	* [Sharp-Profit](https://github.com/Z3R0th-13/Sharp-Profit)
		* "Sharp-Profit is a C# version of my Profit script. This version can be utilized with Cobalt Strike's execute-assembly function."
	* **Browser**
		* [FirePwd.Net](https://github.com/gourk/FirePwd.Net)
			* FirePwd.Net is an open source tool wrote in C# to decrypt Mozilla stored password.
		* [SharpWeb](https://github.com/djhohnstein/SharpWeb)
			* SharpWeb is a .NET 2.0 CLR compliant project that can retrieve saved logins from Google Chrome, Firefox, Internet Explorer and Microsoft Edge. In the future, this project will be expanded upon to retrieve Cookies and History items from these browsers.
	* **File-Hunting**
		* [SharpSearch](https://github.com/djhohnstein/SharpSearch)
			* Search files for extensions as well as text within.
	* **Monitoring**
	    * [WireTap](https://github.com/djhohnstein/WireTap)
			* .NET 4.0 Project to interact with video, audio and keyboard hardware.
		* [SharpLogger](https://github.com/djhohnstein/SharpLogger)
			* Keylogger written in C# 
* **Persistence**
	* **Scheduled Tasks**
	* **General**
		* [SharpStay](https://github.com/0xthirteen/SharpStay)
			* .NET project for installing Persistence
		* [SharpHide](https://github.com/outflanknl/SharpHide)
			* [Technique Whitepaper](https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf)
			* Just a nice persistence trick to confuse DFIR investigation. Uses NtSetValueKey native API to create a hidden (null terminated) registry key. This works by adding a null byte in front of the UNICODE_STRING key valuename.
	* **Golden Tickets**
		* [GoldenTicket](https://github.com/ZeroPointSecurity/GoldenTicket)
			* This .NET assembly is specifically designed for creating Golden Tickets. It has been built with a custom version of SharpSploit and an old 2.0 alpha (x64) version of Powerkatz.
	* **Registry-related**
		* [Reg_Built](https://github.com/P1CKLES/Reg_Built)
			* C# Userland Registry RunKey persistence
	* **Scheduled Tasks**
		* **Articles/Blogposts/Writeups**
			* [Creating Scheduled Tasks(C#) - StackOverflow](https://stackoverflow.com/questions/7394806/creating-scheduled-tasks)
			* [Creating a Task Using NewWorkItem Example - docs.ms](https://docs.microsoft.com/en-us/windows/win32/taskschd/creating-a-task-using-newworkitem-example)
		* **Tools**
			* [Task Scheduler](https://github.com/dahall/taskscheduler)
				* Provides a .NET wrapper for the Windows Task Scheduler. It aggregates the multiple versions, provides an editor and allows for localization.
	* **Services**
		* [Unstoppable Service](https://github.com/malcomvetter/UnstoppableService)
			* A pattern for a self-installing Windows service in C# with the unstoppable attributes in C#.
* **Credential Attacks**
	* **Process Memory**
		* [Writing Minidumps in C# - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/dondu/writing-minidumps-in-c)
		* [Dumping Process Memory with Custom C# Code - 3xplo1tcod3r](https://3xpl01tc0d3r.blogspot.com/2019/07/dumping-process-memory-with-custom-c-sharp.html)
		* [SharpDump](https://github.com/GhostPack/SharpDump)
			* SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
		* [ATPMiniDump](https://github.com/b4rtik/ATPMiniDump)
			* Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft.
			* [Blogpost](https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/)
		* [SafetyKatz](https://github.com/GhostPack/SafetyKatz)
			* SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subtee's .NET PE Loader.
		* [KittyLitter](https://github.com/djhohnstein/KittyLitter)
			* This project was made for an upcoming event. It is comprised of two components, KittyLitter.exe and KittyScooper.exe. This will bind across TCP, SMB, and MailSlot channels to communicate credential material to lowest privilege attackers.
	* **Clipboard**
		* [SharpClipboard](https://github.com/slyd0g/SharpClipboard)
			* C# Clipboard Monitor
			* [Blogpost](https://grumpy-sec.blogspot.com/2018/12/i-csharp-your-clipboard-contents.html)
		* [SharpClipHistory](https://github.com/FSecureLABS/SharpClipHistory)
			* SharpClipHistory is a .NET application written in C# that can be used to read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.
	* **Credentials on Disk/Stored in files**
    	* [SharpCloud](https://github.com/chrismaddalena/SharpCloud)
        	* SharpCloud is a simple C# utility for checking for the existence of credential files related to Amazon Web Services, Microsoft Azure, and Google Compute.
	* **DPAPI**
		* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
			* SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
	* **Fake UI Prompt**
		* **Tools**
			* [SharpLocker](https://github.com/Pickfordmatt/SharpLocker)
				* SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike. It is written in C# to allow for direct execution via memory injection using techniques such as execute-assembly found in Cobalt Strike or others, this method prevents the executable from ever touching disk. It is NOT intended to be compilled and run locally on a device.
	* **Kerberos**
		* [Rubeus](https://github.com/GhostPack/Rubeus)
			* Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpy's Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUX's MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.https://www.slideshare.net/aj0612/a-study-on-net-framework-for-red-team-part-i
	* **LLMNR/NBNS Spoofing**
		* [InveighZero](https://github.com/Kevin-Robertson/InveighZero)
			* Windows C# LLMNR/mDNS/NBNS/DNS spoofer/man-in-the-middle tool
	* **Multi-Tools**
		* [SafetyKatz](https://github.com/GhostPack/SafetyKatz)
			* SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subtee's .NET PE Loader.
	* **Password Spray**
		* [SharpSpray](https://github.com/jnqpblc/SharpSpray)
			* SharpSpray a simple code set to perform a password spraying attack against all users of a domain using LDAP and is compatible with Cobalt Strike.
	* **Proxy**
		* [FreshCookies](https://github.com/P1CKLES/FreshCookees)
			* C# .NET 3.5 tool that keeps proxy auth cookies fresh by maintaining a hidden IE process that navs to your hosted auto refresh page. Uses WMI event listeners to monitor for InstanceDeletionEvents of the Internet Explorer process, and starts a hidden IE process via COM object if no other IE processes are running.
	* **Password Spraying**
		* [SharpDomainSpray](https://github.com/HunnicCyber/SharpDomainSpray)
			* SharpDomainSpray is a very simple password spraying tool written in .NET. It takes a password then finds users in the domain and attempts to authenticate to the domain with that given password.
	* **RDP**
		* [RdpThief](https://github.com/0x09AL/RdpThief)
			* RdpThief by itself is a standalone DLL that when injected in the mstsc.exe process, will perform API hooking, extract the clear-text credentials and save them to a file.
			* [Blogpost](https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/)
		* [SharpRDPCheck](https://github.com/3gstudent/SharpRDPCheck)
			* Use to check the valid account of the Remote Desktop Protocol(Support plaintext and ntlmhash)
	* **Vault Credentials**
		* [SharpEdge](https://github.com/rvrsh3ll/SharpEdge)
			* C# Implementation of Get-VaultCredential - Get-VaultCredential enumerates and displays all credentials stored in the Windows vault. Web credentials, specifically are displayed in cleartext. This script was inspired by the following C implementation: http://www.oxid.it/downloads/vaultdump.txt
	* **ActiveDirectory-related**
		* [ADFSpoof](https://github.com/fireeye/ADFSpoof)
			* A python tool to forge AD FS security tokens. - Meant to be used with ADFSDump
		* [ADFSDump](https://github.com/fireeye/ADFSDump)
			* ADFSDump is a tool that will read information from Active Directory and from the AD FS Configuration Database that is needed to generate forged security tokens. This information can then be fed into ADFSpoof to generate those tokens. - Meant to be used with ADFSpoof
		* [SharpAdidnsdump](https://github.com/b4rtik/SharpAdidnsdump)
			* c# implementation of Active Directory Integrated DNS dumping (authenticated user)
		* [SprayAD](https://github.com/outflanknl/Spray-AD)
			* This tool can help Red and Blue teams to audit Active Directory useraccounts for weak, well known or easy guessable passwords and can help Blue teams to assess whether these events are properly logged and acted upon. When this tool is executed, it generates event IDs 4771 (Kerberos pre-authentication failed) instead of 4625 (logon failure). This event is not audited by default on domain controllers and therefore this tool might help evading detection while password spraying.
* **Lateral Movement**
	* **Multiple**
		* [SharpExec](https://github.com/anthemtotheego/sharpexec-lateral-movement-with-your)
			* [SharpExec - Lateral Movement With Your Favorite .NET Bling - RedXORBlue](http://blog.redxorblue.com/2019/04/sharpexec-lateral-movement-with-your.html)
		* [SharpMove](https://github.com/0xthirteen/SharpMove)
			* .NET Project for performing Authenticated Remote Execution
	* **.NET Remoting**
		* [An Introduction to Microsoft .NET Remoting Framework - docs.ms](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/ms973864(v=msdn.10))
	* **DCOM**
		* [SharpCOM](https://github.com/rvrsh3ll/SharpCOM)
			* SharpCOM is a c# port of Invoke-DCOM
		* [SharpExcel4-DCOM](https://github.com/rvrsh3ll/SharpExcel4-DCOM)
			* Port of Invoke-Excel4DCOM
	* **MSSQL**
		* [Lateral movement via MSSQL: a tale of CLR and socket reuse - Juan Manuel Fernandez, Pablo Martínez](https://www.blackarrow.net/mssqlproxy-pivoting-clr/)
			* Recently, our Red Team had to deal with a restricted scenario, where all traffic from the DMZ to the main network was blocked, except for connections to specific services like databases and some web applications. In this article, we will explain how we overcame the situation, covering the technical details. We also introduce [mssqlproxy](https://github.com/blackarrowsec/mssqlproxy), a tool for turning a Microsoft SQL Server into a socks proxy.
	* **RDP**
		* **Articles/Blogposts/Writeups**
			* [Revisiting Remote Desktop Lateral Movement - Steven F](https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3)
		* **Tools**
			* [SharpRPD](https://github.com/0xthirteen/SharpRDP)
				* Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
			* [SharpDoor](https://github.com/infosecn1nja/SharpDoor)
				* SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file, for opsec considerations SharpDoor still using cmd.exe to run sc services to impersonating as trustedinstaller in the future will be avoiding cmd.exe usage, currently only support for Windows 10.
			* [SharpRDP](https://github.com/0xthirteen/SharpRDP)
				* [Blogpost](https://0xthirteen.com/2020/01/21/revisiting-remote-desktop-lateral-movement/)
				* Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
	* **Registry**
		* [SCShell](https://github.com/Mr-Un1k0d3r/SCShell)	
			* Fileless lateral movement tool that relies on ChangeServiceConfigA to run command
	* **SMB**
		* [CSExec](https://github.com/malcomvetter/CSExec)
			* This is an example for how to implement psexec (from SysInternals Suite) functionality, but in open source C#. This does not implement all of the psexec functionality, but it does implement the equivalent functionality to running: psexec -s \\target-host cmd.exe
		* [SharpInvoke-SMBExec](https://github.com/checkymander/Sharp-SMBExec)
			* A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script.
	* **WinRM**
		* [CSharp-WinRM](https://github.com/mez-0/CSharpWinRM)
			* .NET 4.0 WinRM API Command Execution 
	* **WMI**
		* [SharpWMI](https://github.com/GhostPack/SharpWMI)
			* SharpWMI is a C# implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods.
		* [SharpInvoke-WMIExec](https://github.com/checkymander/Sharp-WMIExec)
			* A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script
* **Evasion**
	* **Articles/Blogposts/Writeups**
		* [DotNet Core: A Vector For AWL Bypass & Defense Evasion - bohops](https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/)
		* [AppLocker Bypass – Assembly Load - pentestlab.blog](https://pentestlab.blog/2017/06/06/applocker-bypass-assembly-load/)
		* [Hiding Your .NET – ETW - Adam Chester(2020)](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)
		* [Red Team Tradecraft: Loading Encrypted C# Assemblies In Memory - Mike Gualtieri(2020](https://www.mike-gualtieri.com/posts/red-team-tradecraft-loading-encrypted-c-sharp-assemblies-in-memory)
		* [Bring your own .NET Core Garbage Collector - Paul Laine(2020)](https://www.contextis.com/us/blog/bring-your-own-.net-core-garbage-collector)
			* [Code](https://github.com/am0nsec/MCGC)
		* [Dynamic Invocation in .NET to bypass hooks - Jean-Francois Maes(2020](https://blog.nviso.eu/2020/11/20/dynamic-invocation-in-net-to-bypass-hooks/)
			* TLDR: This blogpost showcases several methods of dynamic invocation that can be leveraged to bypass inline and IAT hooks. A proof of concept can be found here: [DInvisibleRegistry](https://github.com/NVISO-BE/DInvisibleRegistry)
		* [Abusing .NET Core – Evasion - pentestlaboratories.com](https://pentestlaboratories.com/2020/06/23/abusing-net-core-application-whitelisting/)
		* [Defeating EDRs using Dynamic invocation - Jean-Francois Maes(Mayhem2021 RTV)](https://www.youtube.com/watch?v=LXfhyTpQ7TM&list=PLruly0ngXhPEOYACFCsUfoGehbjNflUfu&index=3)
			* Abstract: How can red team operators emulate covert operations and operate at the same level as a real threat group? EDR solutions can make the life of a red team operator significantly harder. Dynamic invocation (also known as D/Invoke) – a sub branch of the popular “Sharpsploit” project, can help with evading those pesky EDR’s and execute your payloads successfully. In this presentation, we will go over D/Invokes capabilities and how to leverage them in your red team operations.
			https://www.virusbulletin.com/virusbulletin/2016/07/journey-evasion-enters-behavioural-phase/
		* [Bypassing Anti-Viruses by C#.NET Programming - Damon Mohammadbagher](https://damonmohammadbagher.github.io/Posts/ebookBypassingAVsByCsharpProgramming/index.htm)
		* [Crimson Forge](https://github.com/zeroSteiner/crimson-forge)
			* Crimson Forge intends to provide sustainable evasion capabilities for native code on the x86 and AMD64 architectures. It achieves this by rewriting the input code utilizing the following two techniques: Shuffling: Instructions are shuffled into a new order at the basic block level. This is a reliable technique and does not modify the size of resulting binary; Alterations: Instructions are swapped with functional equivalents, effectively de-optimizing them. New instructions are inserted into the same graph used by the Shuffling technique, allowing them to be reordered as well.
		* [LoGiC .NET](https://github.com/AnErrupTion/LoGiC.NET)
			* LoGiC.NET is a free and open-source .NET obfuscator that uses dnlib for folks that want to see how obfuscation works with more complex obfuscations than Goldfuscator for example.
		* [Assembly.Lie – Using Transactional NTFS and API Hooking to Trick the CLR into Loading Your Code “From Disk” - redxorblue.com](https://blog.redxorblue.com/2021/05/assemblylie-using-transactional-ntfs.html)
	* **Talks/Presentations/Videos**
		* [Simple Windows Application Whitelisting Evasion - Casey Smith(ShmooCon 2015)](https://www.youtube.com/watch?v=XVuboBH5TYo)
		* [Quick Retooling in .Net for Red Teams - Dimitry Snezhkov(CircleCityCon2018](https://www.irongeek.com/i.php?page=videos/circlecitycon2018/circle-city-con-50-112-quick-retooling-in-net-for-red-teams-dimitry-snezhkov)
			* Quick Retooling in .Net for Red Teams PowerShell gave us a super-highway of convenient building blocks for offensive toolkits and operational automation. However, use of standalone .Net implants may be a desirable option in cases where PowerShell is heavily inspected and logged. While there are great toolkits to invoke unmanaged PowerShell or directly interface with .Net CLR - they are also statically compiled, and therefore easier identified by the defense. Red Teams are faced with specific challenges when they need to retool quickly in the field with .Net payloads. Can .Net toolkits accomplish their goals while maintaining flexibility, quick in-field retooling and operational security in the face of current detection mechanisms? We think so. This talk walks through some of the options present to the operators for .Net code compilation and presents ideas for extensibility of .Net tools at runtime, with the help of Dynamic Language Runtime (DLR). We will dive deeper into operational security lessons learned from dynamic code compilation. We will attempt to move beyond static nature of .Net assemblies into reflective DLR, achieving on-the-fly access to native Windows API. We will also discuss some methods of hiding sensitive aspects of execution in managed code memory. We will also touch on ways to help Defense fingerprint the attacks involving dynamic compilation of .Net assemblies, use of DLR and building blocks of offensive tooling involved in the process. A concept tool built on these ideas will be presented and released. It will be used as basis for our discussion.
	* **Tools**
		* [tvasion](https://github.com/loadenmb/tvasion)
			* Anti virus evasion based on file signature change via AES encryption with Powershell and C# AV evasion templates which support executable and Powershell payloads with Windows executable, Powershell or batch output. Developed with Powershell on Linux for Windows targets :)
		* [AVIator](https://github.com/Ch0pin/AVIator)
			* Antivirus evasion project 
		* [PEunion](https://github.com/bytecode77/pe-union)
			* PEunion bundles multiple executables (or any other file type) into a single file. Each file can be configured individually to be compressed, encrypted, etc. In addition, an URL can be provided for a download to be executed. The resulting binary is compiled from dynamically generated C# code. No resources are exposed that can be harvested using tools like Resource Hacker. PEunion does not use managed resources either. Files are stored in byte[] code definitions and when encryption and compression is applied, files become as obscure as they can get.
		* [Self-Morphing C# Binary](https://github.com/bytecode77/self-morphing-csharp-binary)
			* C# binary that mutates its own code, encrypts and obfuscates itself on runtime 
		* [Inception-Framework](https://github.com/two06/Inception)
			* Inception provides In-memory compilation and reflective loading of C# apps for AV evasion. Payloads are AES encrypted before transmission and are decrypted in memory. The payload server ensures that payloads can only be fetched a pre-determined number of times. Once decrypted, Roslyn is used to build the C# payload in memory, which is then executed using reflection.
		* [SharpLoadImage](https://github.com/b4rtik/SharpLoadImage)
			* Hide .Net assembly into png images
		* [BlockETW](https://github.com/Soledge/BlockEtw)
			* .Net Assembly to block ETW telemetry in current process
		* [SharpPack](https://github.com/mdsecactivebreach/SharpPack)
			* [Blogpost](https://www.mdsec.co.uk/2018/12/sharppack-the-insider-threat-toolkit/)
			* SharpPack is a toolkit for insider threat assessments that lets you defeat application whitelisting to execute arbitrary DotNet and PowerShell tools.
* **Script Repos/Good Stuff**
	* [GhostPack](https://github.com/GhostPack)
	* [SharpSploit](https://github.com/cobbr/SharpSploit)
		* SharpSploit is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
	* [Sharp-Suite](https://github.com/FuzzySecurity/Sharp-Suite)
		* FuzzySecurity: 'My musings with C#'
	* [OffensiveCSharp-matterpreter](https://github.com/matterpreter/OffensiveCSharp)
		* This is a collection of C# tooling and POCs I've created for use on operations. Each project is designed to use no external libraries. Open each project's .SLN in Visual Studio and compile as "Release".
	* [bytecode-api](https://github.com/bytecode77/bytecode-api)
		* C# library with common classes, extensions and additional features in addition to the .NET Framework. BytecodeApi implements lots of extensions and classes for general purpose use. In addition, specific classes implement more complex logic for both general app development as well as for WPF apps. Especially, boilerplate code that is known to be part of any Core DLL in a C# project is likely to be already here. In fact, I use this library in many of my own projects. For this reason, each class and method has been reviewed numerous times. BytecodeApi is highly consistent, particularly in terms of structure, naming conventions, patterns, etc. The entire code style resembles the patterns used in the .NET Framework itself. You will find it intuitive to understand.
	* [OutlookToolbox](https://github.com/ThunderGunExpress/OutlookToolbox)
		* OutlookToolbox is a C# DLL that uses COM to do stuff with Outlook. Also included is a Cobalt Strike aggressor script that uses Outlooktoolbox.dll to give it a graphical and control interface.
		* [Blogpost](https://ijustwannared.team/2017/10/28/outlooktoolbox/)
	* [OffensiveDLR](https://github.com/byt3bl33d3r/OffensiveDLR)
		* Toolbox containing research notes & PoC code for weaponizing .NET's DLR
	* [RedTeamCSharpScripts -  Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts)
	* [CSharpScripts - Arno0x](https://github.com/Arno0x/CSharpScripts)
	* [Named Pipes](https://github.com/malcomvetter/NamedPipes)
		* This is a proof of concept / pattern concept for creating a client/server communication model with named pipes in C#. In this example, a client passes a message to the server over a named pipe which is then executed as a command on the server. The standard out and standard error are redirected back to the client over the named pipe and printed to the terminal screen.
* **Utiltiies**
	* **Compression**
		* [MiddleOut](https://github.com/FortyNorthSecurity/MiddleOut)
			* This tool was created to compress files through the command line and will work with Cobalt Strike's execute-assembly.
	* **Files**
		* [FileWriter](https://github.com/0xthirteen/FileWriter)
			* .NET project for writing files to local or remote hosts
		* [LockLess](https://github.com/GhostPack/Lockless)
			* LockLess is a C# tool that allows for the enumeration of open file handles and the copying of locked files.
	* **Scheduled Tasks**
		* [Creating Scheduled Tasks(C#) - StackOverflow](https://stackoverflow.com/questions/7394806/creating-scheduled-tasks)
		* [Creating a Task Using NewWorkItem Example - docs.ms](https://docs.microsoft.com/en-us/windows/win32/taskschd/creating-a-task-using-newworkitem-example)
		* [SharpTask](https://github.com/jnqpblc/SharpTask)
			* SharpTask is a simple code set to interact with the Task Scheduler service API using the same DCERPC process as schtasks.exe, which open with TCP port 135 and is followed by the use of an ephemeral TCP port. This code is compatible with Cobalt Strike.
	* **Unsorted**
		* [SharpWebServer](https://github.com/mgeeky/SharpWebServer)
			* A Red Team oriented simple HTTP & WebDAV server written in C# with functionality to capture Net-NTLM hashes. To be used for serving payloads on compromised machines for lateral movement purposes.
		* [C# CmdLineHelper.cs Command line Parser](https://github.com/AltF5/CSharp-CmdLineHelper-Parser)
		* [Cecil](https://github.com/jbevain/cecil)
			* Mono.Cecil is a library to generate and inspect programs and libraries in the ECMA CIL form.
-----------------------------------------------------------------------------------------------------------------------------------









































-----------------------------------------------------------------------------------------------------------------------------------
### <a name="powershell-stuff">Powershell Things</a>
* **101**
	* [Why I Choose PowerShell as an Attack Platform - @mattifestation(2012)](http://www.exploit-monday.com/2012/08/Why-I-Choose-PowerShell.html)
	* [The PowerSploit Manifesto - @mattifestation(2015)](http://www.exploit-monday.com/2015/12/the-powersploit-manifesto.html)
	* [PowerShell is Not Special - An Offensive PowerShell Retrospective - @mattifestation(2017)](http://www.exploit-monday.com/2017/01/powershell-is-not-special-offensive.html)
	* [APTs ❤️PowerShell You Should Too - Anthony Rose, Jake Krasnov(Defcon Safe Mode RTV)](https://www.youtube.com/watch?v=GhfiNTsxqxA)
		* Quite often, you may have heard people mention, “Why should you bother learning PowerShell, isn’t it dead?” or “Why not just use C#?” Many individuals in the offensive security field have a common misconception that PowerShell is obsolete for red team operations. Meanwhile, it remains one of the primary attack vectors employed by Advanced Persistent Threats (APTs). APTs are known for implementing sophisticated hacking tactics, techniques, and procedures (TTPs) to gain access to a system for an extended period of time. Their actions typically focus on high-value targets, which leave potentially crippling consequences to both nation-states and corporations. It is crucial that Red Teams accurately emulate real-world threats and do not ignore viable attack options. For this talk, we will walk through how many threat actors adapt and employ PowerShell tools. Our discussion begins with examining how script block logging and AMSI are powerful anti-offensive PowerShell measures. However, the implementation of script block logging places a technical burden on organizations to conduct auditing on a substantial amount of data. While AMSI is trivial to bypass for any capable adversary. Finally, we will demonstrate APT-like PowerShell techniques that remain incredibly effective against the latest generation of network defenses.
	* **Learning**
		* **Articles/Blogposts/Writeups**
			* [PowerShell 101 - Carlos Perez](https://www.darkoperator.com/powershellbasics/)
			* [Get-Help: An Intro to PowerShell and How to Use it for Evil - Jared Haight](https://www.psattack.com/presentations/get-help-an-intro-to-powershell-and-how-to-use-it-for-evil/)
			* [Brosec](https://github.com/gabemarshall/Brosec)
				* Brosec is a terminal based reference utility designed to help us infosec bros and broettes with usefuPowershelll (yet sometimes complex) payloads and commands that are often used during work as infosec practitioners. An example of one of Brosec's most popular use cases is the ability to generate on the fly reverse shells (python, perl, powershell, etc) that get copied to the clipboard.
		* **Talks/Presentations/Videos**
		    * [PowerShell Inside Out: Applied .NET Hacking for Enhanced Visibility - Satoshi Tanda(CodeBlueTokyo2017)](https://www.youtube.com/watch?v=EzpJTeFbe8c)
		    	* [Slides](https://www.slideshare.net/codeblue_jp/powershell-inside-out-applied-net-hacking-for-enhanced-visibility-by-satoshi-tanda)
		    	* [Code](https://github.com/tandasat/DotNetHooking)
		    	* This talk will discuss how to gain greater visibility into managed program execution, especially for PowerShell, using a .NET native code hooking technique to help organizations protect themselves from such advanced attacker techniques. In this session, we will demonstrate how to enhance capabilities provided by AMSI and how to overcome its limitations, through a realistic implementation of the technique, all while analyzing the internals of .NET Framework and the PowerShell engine. 
		    * [Defensive Coding Strategies for a High-Security Environment - Matt Graeber - PowerShell Conference EU 2017](https://www.youtube.com/watch?reload=9&v=O1lglnNTM18)
        		* How sure are you that your PowerShell code is prepared to handle anything that a user might throw at it? What if the user was an attacker attempting to circumvent security controls by exploiting a vulnerability in your script? This may sound unrealistic but this is a legitimate concern of the PowerShell team when including PowerShell code in the operating system. In a high-security environment where strict AppLocker or Device Guard rules are deployed, PowerShell exposes a large attack surface that can be used to circumvent security controls. While constrained language mode goes a long way in preventing malicious PowerShell code from executing, attackers will seek out vulnerabilities in trusted signed code in order to circumvent security controls. This talk will cover numerous different ways in which attackers can influence the execution of your code in unanticipated ways. A thorough discussion of mitigations against such attacks will then follow.
			* [APTs LOVE PowerShell and Why You Should Too - Anthony Rose & Jake Krasnov(Defcon28RedTeamVillage)](https://www.youtube.com/watch?v=rLWySkU0U1U&list=PLruly0ngXhPHlQ0ebMbB3XuKVJPq3B0qS&index=33)
				* "Quite often, you may have heard people mention, “Why should you bother learning PowerShell, isn’t it dead?” or “Why not just use C#?” Many individuals in the offensive security field have a common misconception that PowerShell is obsolete for red team operations. Meanwhile, it remains one of the primary attack vectors employed by Advanced Persistent Threats (APTs). APTs are known for implementing sophisticated hacking tactics, techniques, and procedures (TTPs) to gain access to a system for an extended period of time. Their actions typically focus on high-value targets, which leave potentially crippling consequences to both nation-states and corporations. It is crucial that Red Teams accurately emulate real-world threats and do not ignore viable attack options. For this talk, we will walk through how many threat actors adapt and employ PowerShell tools. Our discussion begins with examining how script block logging and AMSI are powerful anti-offensive PowerShell measures. However, the implementation of script block logging places a technical burden on organizations to conduct auditing on a substantial amount of data. While AMSI is trivial to bypass for any capable adversary. Finally, we will demonstrate APT-like PowerShell techniques that remain incredibly effective against the latest generation of network defenses.
    * **File Parsing**
    	* [Parsing Binary File Formats with PowerShell - @mattifestation(2013)](http://www.exploit-monday.com/2013/03/ParsingBinaryFileFormatsWithPowerShell.html)
	* **Logging**
		* [About Eventlogs(PowerShell) - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1)
		* [Script Tracing and Logging - docs.ms](https://docs.microsoft.com/en-us/powershell/wmf/whats-new/script-logging)
		* [Attack and Defense Around PowerShell Event Logging - Mina Hao(2019)](https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging)
* **Discovery**
	* **AD**
		* [Powersploit-PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
			* PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net \*" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.
		* [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
			* AD PowerShell Recon Scripts
		* [PowEnum](https://github.com/whitehat-zero/PowEnum)
			* PowEnum executes common PowerSploit Powerview functions and combines the output into a spreadsheet for easy analysis. All network traffic is only sent to the DC(s). PowEnum also leverages PowerSploit Get-GPPPassword and Harmj0y's ASREPRoast.
	* **Files**
		* [SessionGopher](https://github.com/fireeye/SessionGopher)
			* SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.
		* [CC_Checker](https://github.com/NetSPI/PS_CC_Checker)
			* CC_Checker cracks credit card hashes with PowerShell.
	* **LocalHost**
		* PowerView
		* [HostRecon](https://github.com/dafthack/HostRecon)
	* **Memory & Processes**
		* [Powershell Live-Memory Analysis Tools: Dump-Memory, Dump-Strings, Check-MemoryProtection - @mattifestation(2012)](http://www.exploit-monday.com/2012/03/powershell-live-memory-analysis-tools.html)
		* [Invoke-ProcessScan](https://github.com/vysec/Invoke-ProcessScan)
			* Gives context to a system. Uses EQGRP shadow broker leaked list to give some descriptions to processes.
	* **SQLite**
		* [PSSQLite PowerShell Module](https://github.com/RamblingCookieMonster/PSSQLite)
			*  PowerShell module to query SQLite databases 
	* **WebBrowser**
		* [BrowserGatherer](https://github.com/sekirkity/BrowserGather)
			* Fileless Extraction of Sensitive Browser Information with PowerShell
		* [BrowserGather](https://github.com/sekirkity/BrowserGather)
			* Fileless Extraction of Sensitive Browser Information with PowerShell. This project will include various cmdlets for extracting credential, history, and cookie/session data from the top 3 most popular web browsers (Chrome, Firefox, and IE). The goal is to perform this extraction entirely in-memory, without touching the disk of the victim. Currently Chrome credential and cookie extraction is supported. 
* **Execution**
	* **Articles/Blogposts/Writeups**
		* [Meterpreter New Windows PowerShell Extension - Carlos Perez(2016)](https://www.darkoperator.com/blog/2016/4/2/meterpreter-new-windows-powershell-extension)
		* [Introducing PowerShell into your Arsenal with PS>Attack - Jared Haight(Derbycon206)](http://www.irongeek.com/i.php?page=videos/derbycon6/119-introducing-powershell-into-your-arsenal-with-psattack-jared-haight)
			* PS>Attack is a custom tool that was created to make it easier for Penetration Testers to incorporate PowerShell into their bag of tricks. It combines a lot of the best offensive tools from the offensive PowerShell community into a custom, encrypted console that emulates a PowerShell environment. It also includes a custom command, "Get-Attack" to act a search engine for attacks making it easy to find the right attack for any situation. In this presentation we will cover how PowerShell can be used during every part of a penetration test and how PS>Attack can help make the whole process a lot easier.
    * **Tools**
    	* [Invoke-ReflectivePEInjection.ps1](https://github.com/clymb3r/PowerShell/blob/master/Invoke-ReflectivePEInjection/Invoke-ReflectivePEInjection.ps1)
			* This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,  or it can reflectively load a DLL in to a remote process.
		* [Managing Privileges using PoshPrivilege - Boe Prox(2015)](https://learn-powershell.net/2015/06/03/managing-privileges-using-poshprivilege/)
    * **Add-Type & Reflection**
    	* **101**
    		* [Add-Type - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7)
    			* Adds a Microsoft .NET Core class to a PowerShell session.
    		* [Add-Type - SS64](https://ss64.com/ps/add-type.html)
    		* [Add-Type vs. [reflection.assembly] in PowerShell - Tim Curwick(2013)](https://web.archive.org/web/20200315070535/http://www.madwithpowershell.com/2013/10/add-type-vs-reflectionassembly-in.html)
    		* [Using Add-Type in a PowerShell script that is run as a Scheduled Task - Craig Tolley(2016)](https://www.craig-tolley.co.uk/2016/02/09/using-add-type-in-a-powershell-script-that-is-run-as-a-scheduled-task/)
    * **Constrained-Language Mode**
		* **101**
	 		* [About Language Modes - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7)
	 			* Explains language modes and their effect on PowerShell sessions.
	 		* [PowerShell Constrained Language Mode - PowerShell Team(2017)](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
			* [A Comparison of Shell and Scripting Language Security - PowerShell Team](https://devblogs.microsoft.com/powershell/a-comparison-of-shell-and-scripting-language-security/)
		* **Articles/Blogposts/Writeups**
			* [AppLocker CLM Bypass via COM - MDSec](https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/)
	 		* [Detecting and Preventing PowerShell Downgrade Attacks - Lee Holmes(2017)](https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)
	 		* [Simple Bypass for PowerShell Constrained Language Mode - DaveHardy20(2017)](https://pentestn00b.wordpress.com/2017/03/20/simple-bypass-for-powershell-constrained-language-mode/)
	 		* [Powershell Constrained Language Mode ByPass - @spottheplanet](https://www.ired.team/offensive-security/code-execution/powershell-constrained-language-mode-bypass)
	 		* [Exploiting PowerShell Code Injection Vulnerabilities to Bypass Constrained Language Mode - @mattifestation(2017)](http://www.exploit-monday.com/2017/08/exploiting-powershell-code-injection.html)
	 		* [A Look at CVE-2017-8715: Bypassing CVE-2017-0218 using PowerShell Module Manifests - enigma0x3(2017)](https://enigma0x3.net/2017/11/06/a-look-at-cve-2017-8715-bypassing-cve-2017-0218-using-powershell-module-manifests/)
	 		* [Pentesting and .hta (bypass PowerShell Constrained Language Mode) - Josh Graham(2018)](https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997)
	 		* [Bypassing Applocker and Powershell constrained language mode - DarthSidious](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
			* [Powershell CLM Bypass Using Runspaces - Shaksham Jaiswal(2019)](https://www.secjuice.com/powershell-constrainted-language-mode-bypass-using-runspaces/)
				* [Code](https://github.com/MinatoTW/CLMBypassBlogpost)
	 	* **Talks/Presentations/Videos**
	 		* [PowerShell Constrained Language Mode Enforcement and Bypass Deep Dive - Matt Graeber(2020)](https://www.youtube.com/watch?v=O6dtIvDfyuI)
	 	* **Tools**
			* [DotNetToJScript Constrained/Restricted LanguageMode Breakout](https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout/blob/master/README.md)
				* This repository is based on a post by [@xpn](https://twitter.com/_xpn_), [more details available here.](https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/) Xpn's post outlines a bug of sorts where ConstrainedLanguage, when enforced through AppLocker does not prevent COM invocation. Because of this it is possible to define a custom COM object in the registry and force PowerShell to load a Dll. On load it is possible to change the LanguageMode to FullLanguage and break out of the restricted shell. This repo is a variation on this technique where a DotNetToJScript scriptlet is used to directly stage a .Net assembly into the PowerShell process.
			* [PoSH_Bypass](https://github.com/davehardy20/PoSHBypass)
				* PoSHBypass is a payload and console proof of concept that allows an attatcker or for that matter a legitimate user to bypass PowerShell's 'Constrianed Language Mode, AMSI and ScriptBlock and Module logging'. The bulk of this concept is the combination of 3 separate pieces of research, I've stuck these 3 elements together as my first attempt at non 'Hello World!' C# project.
			* [PSByPassCLM](https://github.com/padovah4ck/PSByPassCLM)
				* Bypass for PowerShell Constrained Language Mode
			* [powershellveryless](https://github.com/decoder-it/powershellveryless)
				* Constrained Language Mode + AMSI bypass all in one(Currently Blocked without modification)
	* **C# in PS**
		* **Articles/Blogposts/Writeups**
				* [Weekend Scripter: Run C# Code from Within PowerShell - Dr Scripto(2013)](https://devblogs.microsoft.com/scripting/weekend-scripter-run-c-code-from-within-powershell/)
				* [Using CSharp (C#) code in Powershell scripts - Stefan Gobner(2010)](https://blog.stefan-gossner.com/2010/05/07/using-csharp-c-code-in-powershell-scripts/)
				* [PowerShell – .NET Scripting how to ? - audministrator](https://audministrator.wordpress.com/scripting/powershell/powershell-net-scripting-using-howto/)
				* [Executing C# code using PowerShell script - Adam Furmanek(2016)](https://blog.adamfurmanek.pl/2016/03/19/executing-c-code-using-powershell-script/)
				* [Use .Net Code (C#) and DLLs in Powershell - Hannes Hayashi(2016)](https://activedirectoryfaq.com/2016/01/use-net-code-c-and-dlls-in-powershell/)
				* [Powershell: How do you add inline C#? - Dot Jim(2018)](https://dandraka.com/2018/11/12/powershell-how-do-you-add-inline-c/)
    			* [Add-Type - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7)
    				* Adds a Microsoft .NET Core class to a PowerShell session.
    			* [Add-Type - SS64](https://ss64.com/ps/add-type.html)
    			* [Add-Type vs. [reflection.assembly] in PowerShell - Tim Curwick(2013)](https://web.archive.org/web/20200315070535/http://www.madwithpowershell.com/2013/10/add-type-vs-reflectionassembly-in.html)
    			* [Using Add-Type in a PowerShell script that is run as a Scheduled Task - Craig Tolley(2016)](https://www.craig-tolley.co.uk/2016/02/09/using-add-type-in-a-powershell-script-that-is-run-as-a-scheduled-task/)
	* **Access Managed Code from Unmanaged Code**
		* [Native interoperability - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/)
			* "The following articles show the various ways of doing "native interoperability" in .NET."
		* [Platform Invoke (P/Invoke) - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)
		* [Platform Invocation Services - Wikipedia](https://en.wikipedia.org/wiki/Platform_Invocation_Services)
		* [How to: Call Native DLLs from Managed Code Using PInvoke - docs.ms](https://docs.microsoft.com/en-us/cpp/dotnet/how-to-call-native-dlls-from-managed-code-using-pinvoke?view=vs-2019)
			* Functions that are implemented in unmanaged DLLs can be called from managed code using Platform Invoke (P/Invoke) functionality. If the source code for the DLL is not available, P/Invoke is the only option for interoperating. However, unlike other .NET languages, Visual C++ provides an alternative to P/Invoke. For more information, see [Using C++ Interop (Implicit PInvoke)](https://docs.microsoft.com/en-us/cpp/dotnet/using-cpp-interop-implicit-pinvoke?view=vs-2019).
		* [pinvoke](https://github.com/dotnet/pinvoke)
			* A library containing all P/Invoke code so you don't have to import it every time. Maintained and updated to support the latest Windows OS.
	* **Download Cradles**
	 	* [Dropping Executables with Powershell - @mattifestation(2011)](http://www.exploit-monday.com/2011/09/dropping-executables-with-powershell.html)
		* [PowerShell: In-Memory Injection Using CertUtil.exe - mov a, xbx(2018)](https://movaxbx.ru/2018/06/01/powershell-in-memory-injection-using-certutil-exe/)
			* In this blog post I will discuss the steps to use PowerShell, Invoke-CradleCrafter and Microsoft’s Certutil.exe to craft a payload and one-liner that can be used to evade the latest version of Windows Defender (as of this writing), as well as tips for not getting caught by Intrusion Detection Systems and behavior analysis.
		* [Invoke-Cradlecrafter - Daniel Bohannon](https://github.com/danielbohannon/Invoke-CradleCrafter)
			* PowerShell Remote Download Cradle Generator & Obfuscator
	* **Execution Policy**
			* [15 Ways to Bypass the PowerShell Execution Policy - NetSPI](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
    	* **Tools**
    		* [Bat Armor](https://github.com/klsecservices/bat-armor)
				* Bypass PowerShell execution policy by encoding ps script into bat file.
    * **In-Memory**
		* **Articles/Blogposts/Writeups**
    		* [PowerSyringe - PowerShell-based Code/DLL Injection Utility - @mattifestation(2011)](http://www.exploit-monday.com/2011/11/powersyringe-powershell-based-codedll.html)
    		* [In-Memory Managed Dll Loading With PowerShell - @mattifestation(2012)](http://www.exploit-monday.com/2012_11_25_archive.html)
    		* [Surgical .NET Dissection - Using PowerShell Proxy Functions to Extend Get-Member - @mattifestation]
    		* [Deep Reflection - Defining Structs and Enums in PowerShell - @mattifestation(2012)](http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html)
    		* [Accessing the Windows API in PowerShell via internal .NET methods and reflection - @mattifestation(2012)](http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html)
			* [In-Memory Managed Dll Loading With PowerShell - @mattifestation(2012)](http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html)
    		* [Working with Unmanaged Callback Functions in PowerShell - @mattifestation(2013)](http://www.exploit-monday.com/2013/06/PowerShellCallbackFunctions.html)
    			*  With a little bit of work, you can bind a scriptblock to an unmanaged callback function in PowerShell. The key to accomplishing this is by casting a scriptblock as a non-generic delegate that has the function signature of the desired callback function. Fortunately, creating non-generic delegates is made easy with my Get-DelegateType function.
    		* [Simple CIL Opcode Execution in PowerShell using the DynamicMethod Class and Delegates - @mattifestation(2013)](http://www.exploit-monday.com/2013/10/powershell-cil-opcode-execution.html)
    			* It is possible to assemble .NET methods with CIL opcodes (i.e. .NET bytecode) in PowerShell in only a few lines of code using dynamic methods and delegates.
			* [PowerShell – Run a .Net Assembly DLL from in Memory - audministrator(2014)](https://audministrator.wordpress.com/2014/09/07/powershell-run-a-net-assembly-dll-from-in-memory/)
			* [PowerShell – Run Assembly that is not registered in the GAC - audministrator(2014)](https://audministrator.wordpress.com/2014/09/05/powershell-run-assembly-that-is-not-registered-in-the-gac/)
    		* [PowerShell load .Net Assembly  - PsCustomObject(2019)](https://pscustomobject.github.io/powershell/howto/PowerShell-Add-Assembly/)
    			* One common technique is loading .Net assemblies in PowerShell script or module to leverage functionalities otherwise not available natively in PowerShell. There are multiple methods we can use to add assemblies to PowerShell which we’re going to explore in the post.
    * **Nishang**
		* [Nishang](https://github.com/samratashok/nishang)
			* Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
		* [Hacking In Windows Using Nishang With Windows PowerShell, Like A Boss! - serenity-networks.com](https://serenity-networks.com/hacking-in-windows-using-nishang-with-windows-powershell/)
	* **Powershell without Powershell**
		* **Articles/Blogposts/Writeups**
			* [Empire without PowerShell.exe](https://bneg.io/2017/07/26/empire-without-powershell-exe/)
			* [Powershell without Powershell to bypass app whitelist](https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/)
			* [We don’t need powershell.exe - decoder.cloud](https://decoder.cloud/2017/11/02/we-dont-need-powershell-exe/)
				* [Part 2](https://decoder.cloud/2017/11/08/we-dont-need-powershell-exe-part-2/)
				* [Part 3](https://decoder.cloud/2017/11/17/we-dont-need-powershell-exe-part-3/)
			* [PowerShell: In-Memory Injection Using CertUtil.exe](https://www.coalfire.com/The-Coalfire-Blog/May-2018/PowerShell-In-Memory-Injection-Using-CertUtil-exe)
			* [Run PowerShell without Powershell.exe — Best tools & techniques - Bank Security](https://medium.com/@Bank_Security/how-to-running-powershell-commands-without-powershell-exe-a6a19595f628)
			* [PowerOPS: PowerShell for Offensive Operations](https://labs.portcullis.co.uk/blog/powerops-powershell-for-offensive-operations/)
			* [The Evolution of Offensive PowerShell Invocation - Lee Christensen](https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/)
		* **Talks & Presentations**
		   * [Gray Hat Powershell - Ben0xA(ShowMeCon2015)](https://www.youtube.com/watch?v=OJNWgNARnAs)
		* **Tools**
			* [AwesomerShell](https://github.com/Ben0xA/AwesomerShell)
				* [Talk](https://www.youtube.com/watch?v=OJNWgNARnAs)
				* This is the awesomershell application code that was presented with the Gray Hat PowerShell talk.
			* [OffensivePowerShellTasking](https://github.com/leechristensen/OffensivePowerShellTasking)
				* Run multiple PowerShell scripts concurrently in different app domains. Solves the offensive security problem of running multiple PowerShell scripts concurrently without spawning powershell.exe and without the scripts causing problems with each other (usually due to PInvoke'd functions).
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
			* [PowerOPS](https://github.com/fdiskyou/PowerOPS)
				* PowerOPS is an application written in C# that does not rely on powershell.exe but runs PowerShell commands and functions within a powershell runspace environment (.NET). It intends to include multiple offensive PowerShell modules to make the process of Post Exploitation easier.
			* [PowerLine](https://github.com/fullmetalcache/powerline)
				* [Presentation](https://www.youtube.com/watch?v=HiAtkLa8FOc)
				* Running into environments where the use of PowerShell is being monitored or is just flat-out disabled? Have you tried out the fantastic PowerOps framework but are wishing you could use something similar via Meterpreter, Empire, or other C2 channels? Look no further! In this talk, Brian Fehrman talks about his new PowerLine framework. He overviews the tool, walks you through how to use it, shows you how you can add additional PowerShell scripts with little effort, and demonstrates just how powerful (all pun intended) this little program can be!
	* **Through LoLBins**
		* [How malware can use Powershell without powershell.exe - safe(2018)](https://web.archive.org/web/20180202001408/https://safe-cyberdefense.com/malware-can-use-powershell-without-powershell-exe/)
	* **Reflection**
		* [Use PowerShell to Work with the .NET Framework Classes - devblogs.ms(2010)](https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-the-net-framework-classes/)
		* [PowerShell cmdLet add-type - renenyffenegger.ch](https://renenyffenegger.ch/notes/Windows/PowerShell/command-inventory/noun/type/add/index)
		* [How to do .NET Reflection in PowerShell - Roger Lipscombe(2013)](https://blog.differentpla.net/blog/2013/04/17/how-to-do-net-reflection-in-powershell/)
		* [Using Powershell and Reflection API to invoke methods from .NET Assemblies - Khai Tran(2013)](https://blog.netspi.com/using-powershell-and-reflection-api-to-invoke-methods-from-net-assemblies/)
	* **Reflective DLL Injection**
		* [Reflective DLL Injection with PowerShell - clymb3r(2013)](https://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/)
		* [Invoke-DllInjection.ps1 - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-DllInjection.ps1)
			* Injects a Dll into the process ID of your choosing.
		* [PowerPwning: Post-Exploiting By Overpowering PowerShell - Joe Bialek(Defcon21)](https://www.youtube.com/watch?v=OAd68_SYQc8)
			* [Slides](https://www.defcon.org/images/defcon-21/dc-21-presentations/Bialek/DEFCON-21-Bialek-PowerPwning-Post-Exploiting-by-Overpowering-Powershell.pdf)	
	* **Reflective PE Injection**
		* [Invoke-ReflectivePEInjection.ps1 - PowerSploit](Invoke-ReflectivePEInjection.ps1)
			* This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,  or it can reflectively load a DLL in to a remote process.
		* [Reflective PE Injection In Windows 10 1909 - HUBBL3(2020)](https://www.bc-security.org/post/reflective-pe-injection-in-windows-10-1909/)
	* **Registry**
		* [Working with Registry Keys - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/samples/working-with-registry-keys?view=powershell-7)
	* **Running Shellcode**
		* [Invoke-Shellcode.ps1 - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1)
			* Inject shellcode into the process ID of your choosing or within the context of the running PowerShell process.
	* **Runspaces**
		* [Beginning Use of PowerShell Runspaces: Part 1 - Dr Scripto(2015)](https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-1/)
		* [Creating Runspaces - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/developer/hosting/creating-runspaces?view=powershell-7)
	* **Token Manipulation**
		* **101**
			* [Use PowerShell to Duplicate Process Tokens via P/Invoke - Dr Scripto(2012)](https://devblogs.microsoft.com/scripting/use-powershell-to-duplicate-process-tokens-via-pinvoke/)
				* "Summary: Guest blogger, Niklas Goude, shows how to use P/Invoke to duplicate process tokens from LSASS to elevate privileges."
		* **Articles/Blogposts/Writeups**
			* [PowerShell and Token Impersonation - clymb3r(2013)](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)
		* **Tools**
			* [Invoke-TokenManipulation.ps1 - clymb3r](https://github.com/clymb3r/PowerShell/tree/master/Invoke-TokenManipulation)
			* [Invoke-TokenManipulation.ps1 - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-TokenManipulation.ps1)
	* **WinAPI Access**
		* **Articles/Blogposts/Writeups**
			* [Accessing the Windows API in PowerShell via internal .NET methods and reflection - @mattifestation(2012)](http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html)
				* It is possible to invoke Windows API function calls via internal .NET native method wrappers in PowerShell without requiring P/Invoke or C# compilation. How is this useful for an attacker? You can call any Windows API function (exported or non-exported) entirely in memory. For those familiar with Metasploit internals, think of this as an analogue to railgun.
			* [List All Win32/Native Functions Declared/Used By PowerShell - @mattifestation(2012)](http://www.exploit-monday.com/2012/12/list-all-win32native-functions.html)
			* [Low-Level Windows API Access From PowerShell - b33f(2013/14?)](http://www.fuzzysecurity.com/tutorials/24.html)
			* [Get-PEB – A Tool to Dump the Process Environment Block (PEB) of Any Process - @mattifestation(2013)](http://www.exploit-monday.com/2013/01/Get-PEB.html)
			* [PowerShell and Win32 API Access - harmj0y(2014)](http://www.harmj0y.net/blog/powershell/powershell-and-win32-api-access/)
			* [Use PowerShell to Interact with the Windows API: Part 1 - devblogs.msdn(2014)](https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1/)
				* [Part2]()
				* [Part3](https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-3/)
			* [Accessing the Windows API in PowerShell via internal .NET methods and reflection - Matt Graeber(2012)](http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html)
				* It is possible to invoke Windows API function calls via internal .NET native method wrappers in PowerShell without requiring P/Invoke or C# compilation. How is this useful for an attacker? You can call any Windows API function (exported or non-exported) entirely in memory. For those familiar with Metasploit internals, think of this as an analogue to railgun.
			* [Deep Reflection - Defining Structs and Enums in PowerShell - Matt Graeber(2012)](http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html)
			* [Easily Defining Enums, Structs, and Win32 Functions in Memory - Matt Graeber(2014)](https://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/)
			* [Low-Level Windows API Access From PowerShell - b33f(2016)](https://www.fuzzysecurity.com/tutorials/24.html)
			* [Properly Retrieving Win32 API Error Codes in PowerShell - @mattifestation(2016)](http://www.exploit-monday.com/2016/01/properly-retrieving-win32-api-error.html)
			* [Writing about Windows API functions in Powershell - Dmitriy Kim(2020)](https://medium.com/@dmitriykim/writing-about-windows-api-functions-in-powershell-b03d3abb0862)
		* **Tools**
			* [PSReflect](https://github.com/mattifestation/PSReflect)
				* Easily define in-memory enums, structs, and Win32 functions in PowerShell
* **Persistence**
		* [Practical Persistence with PowerShell - Matt Graeber(2013)](http://www.exploit-monday.com/2013/04/PersistenceWithPowerShell.html)
		* [Nothing Lasts Forever: Persistence with Empire - harmj0y(2016)](https://www.harmj0y.net/blog/empire/nothing-lasts-forever-persistence-with-empire/)
    * **PE Backdooring**
    	* [Powershell PE Injection: This is not the Calc you are looking for! - b33f](http://www.fuzzysecurity.com/tutorials/20.html)
	* **PS Profiles**
		* [Investigating Subversive PowerShell Profiles - @mattifestation(2015)](http://www.exploit-monday.com/2015/11/investigating-subversive-powershell.html)
* **Credential Attacks**
	* **Articles/Blogposts/Writeups**
		* [PowerShell and Token Impersonation](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)
	* **Process Dump**
		* [Dump-Clear-Text-Password-after-KB2871997-installed](https://github.com/3gstudent/Dump-Clear-Password-after-KB2871997-installed)
			* Auto start Wdigest Auth,Lock Screen,Detect User Logon and get clear password.
		* [Out-Minidump.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)
			* Generates a full-memory minidump of a process.
		* [MimiDbg](https://github.com/giMini/mimiDbg)
			* PowerShell oneliner to retrieve wdigest passwords from the memory
		* [PowerMemory](https://github.com/giMini/PowerMemory)
			* Exploit the credentials present in files and memory. PowerMemory levers Microsoft signed binaries to hack Microsoft operating systems.
		* [mimikittenz](https://github.com/putterpanda/mimikittenz/)
			* mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes.
	* **GPO**
		* [PShell Script: Extract All GPO Set Passwords From Domain](http://www.nathanv.com/2012/07/04/pshell-script-extract-all-gpo-set-passwords-from-domain/)
			* This script parses the domain’s Policies folder looking for Group.xml files.  These files contain either a username change, password setting, or both.  This gives you the raw data for local accounts and/or passwords enforced using Group Policy Preferences.  Microsoft chose to use a static AES key for encrypting this password.  How awesome is that!
	* **Mimikatz**
		* [mimikittenz](https://github.com/putterpanda/mimikittenz/)
			* A post-exploitation powershell tool for extracting juicy info from memory.
	* **Broadcast Name Resolution Poisoning (BNRP)**
		* [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
			* Inveigh is a PowerShell LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system.
* **Privilege Escalation**
	* **Local Phishing**
		* [Client Side attacks using Powershell](http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html)
	* **Tools**
		* [PowerUp](https://github.com/HarmJ0y/PowerUp) 
			* PowerUp is a powershell tool to assist with local privilege escalation on Windows systems. It contains several methods to identify and abuse vulnerable services, as well as DLL hijacking opportunities, vulnerable registry settings, and escalation opportunities.
		* [Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/README.md)
			* PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.
		* [Get-System-Techniques](https://github.com/S3cur3Th1sSh1t/Get-System-Techniques)
* **Lateral Movement**
	* **DCOM**
		* [Invoke-DCOM.ps1](https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1)
	* **PS-Remoting**
		* [Secrets of PowerShell Remoting -  Don Jones, Tobias Weltner(2018)](https://devops-collective-inc.gitbook.io/secrets-of-powershell-remoting/about)
			* Introduced in Windows PowerShell 2.0, Remoting is one of PowerShell's most useful, and most important, core technologies. It enables you to run almost any command that exists on a remote computer, opening up a universe of possibilities for bulk and remote administration. Remoting underpins other technologies, including Workflow, Desired State Configuration, certain types of background jobs, and much more. This guide isn't intended to be a complete document of what Remoting is and does, although it does provide a good introduction. Instead, this guide is designed to document all the little configuration details that don't appear to be documented elsewhere.
	* **ScheduleTask**
		* [Invoke-CommandAs](https://github.com/mkellerman/Invoke-CommandAs)
    	   * Invoke Command as System/User on Local/Remote computer using ScheduleTask.
* **Evasion**
	* **Articles/Blogposts/Writeups**
		* [PowerShell Logging: Obfuscation and Some New(ish) Bypasses Part 1 - Hubbl3(2020)](https://www.bc-security.org/post/powershell-logging-obfuscation-and-some-newish-bypasses-part-1/)
	* **Talks/Presentations/Videos**
		* [PowerShell Secrets and Tactics - Ben0xA(Derbycon2016)](https://www.youtube.com/watch?v=mPPv6_adTyg)
			* It used to be that most people were just starting to hear about PowerShell. Over the last 3 years, this has changed dramatically. We now see Offensive and Defensive PowerShell tools, exploits specifically leveraging PowerShell and WMI, and more organizations are starting to be intentional for detection and monitoring of PowerShell scripts and commands. With this visibility, it is becoming a game of cat and mouse to leverage and detect PowerShell. In this talk, I will highlight some secrets I use to ensure my PowerShell exploits are successful and some unique tactics which will bypass common defensive controls. I will also walk you through the creation of a custom PowerShell C# DLL which you can use to compromise your target. If you want to code with me, be sure to bring a laptop with Visual Studio 2013 or later installed.
		* [Goodbye Obfuscation, Hello Invisi Shell: Hiding Your Powershell Script in Plain Sight - Omer Yair(Derbycon2018)](https://www.youtube.com/watch?v=Y3oMEiySxcc)
			* “The very concept of objective truth is fading out of the world. Lies will pass into history.” George Orwell. Objective truth is essential for security. Logs, notifications and saved data must reflect the actual events for security tools, forensic teams and IT managers to perform their job correctly. Powershell is a prime example of the constant cat and mouse game hackers and security personnel play every day to either reveal or hide the “objective truth” of a running script. Powershell’s auto logging, obfuscation techniques, AMSI and more are all participants of the same game playing by the same rules. We don’t like rules, so we broke them. As a result, Babel-Shellfish and Invisi-Shelltwo new tools that both expose and disguise powershell scripts were born. Babel-Shellfish reveals the inner hidden code of any obfuscated script while Invisi-Shell offers a new method of hiding malicious scripts, even from the Powershell process running it. Join us as we present a new way to think about scripts.
		* [APTs <3 PowerShell and Why You Should Too - Anthony Rose, Jake Krasnov(DefconSafeMode RTV 2020)](https://raw.githubusercontent.com/BC-SECURITY/DEFCONSafeMode/master/Red%20Team%20Village%20-%20APTs%20Love%20PowerShell%20and%20You%20Should%20Too.pdf)
	* **Tools**
		* [HiddenPowerShellDll](https://github.com/b4rtik/HiddenPowerShellDll)
			* This .Net class library is used to run PowerShell scripts from c #. The bypasses are executed and then the scriptblock that invokes the stager is executed. Using the DllExport package the .Net DLL exports a function that allows it to be executed via rundll32 and this results in a bypass of the default AppLocker rules
	* **Constrained-Language Mode**
		* See above.
	* **Crypters**
		* [Xencrypt](https://github.com/the-xentropy/xencrypt)
			* This tool is intended as a demo for how easy it is to write your own crypter. It works for its intended purpose and I will not patch it to make it suitable for yours.
	* **Obfuscation**
		* [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
			* Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
				* [Presentation](https://www.youtube.com/watch?v=P1lkflnWb0I)
				* [Invoke-Obfuscation: PowerShell obFUsk8tion Techniques & How To (Try To) D""e`Tec`T 'Th'+'em'](http://www.irongeek.com/i.php?page=videos/derbycon6/121-invoke-obfuscation-powershell-obfusk8tion-techniques-how-to-try-to-detect-them-daniel-bohannon)
		* **Articles/Blogposts/Writeups**
			* [argfuscator - Obfuscating and randomizing PowerShell arguments - Jeff White(2017)](http://ropgadget.com/posts/intro_argfuscator.html)
			* [Pulling Back the Curtains on EncodedCommand PowerShell Attacks - Jeff White(2017)](https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/)
			* [PowerShell Obfuscation using SecureString - @Wietze(2020)](https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring)
				* TL;DR - PowerShell has built-in functionality to save sensitive plaintext data to an encrypted object called `SecureString`. Malicious actors have exploited this functionality as a means to obfuscate PowerShell commands. This blog post discusses `SecureString`, examples seen in the wild, and [presents a tool](https://wietze.github.io/powershell-securestring-decoder/) that helps analyse SecureString obfuscated commands.
			* [pOWershell obFUsCation - N1CFURY](https://n1cfury.com/ps-obfuscation/)
		* **Talks/Presentations/Videos**
			* [Defeating The Latest Advances in Script Obfuscation - Mark Mager(Derbycon2016)](https://www.youtube.com/watch?v=BGWy1R7NyOk&app=desktop)
				* Defeating The Latest Advances in Script Obfuscation Mark Mager Mark Mager - @magerbomb In this age of increasingly sophisticated and devastating malware, adversaries still rely on a multitude of scripting languages and frameworks (e.g. JavaScript, VBA, PowerShell, VBScript) as key components of an attack scenario. These scripts tend to employ obfuscation techniques in order to obscure their true intent and avoid detection by endpoint protection products. Though significant advances have been made in recent years in packing and obfuscating compiled binaries, script obfuscation can still be defeated with time and a determined analyst. This talk will cover some of the most recently seen advanced obfuscation techniques employed by APTs, exploit kits, and other malware authors along with proven methods for circumventing and decoding these techniques. I will then apply these methods to guide the audience through the deobfuscation of a fully obfuscated script. Audience members will walk away with a solid understanding of how common obfuscation techniques are employed in scripting languages along with how they can be defeated.
			* [Invoke-CradleCrafter: Moar PowerShell obFUsk8tion by Daniel Bohannon](https://www.youtube.com/watch?feature=youtu.be&v=Nn9yJjFGXU0&app=desktop)
			* [Invoke-CradleCrafter: Moar PowerShell obFUsk8tion & Detection (@('Tech','niques') -Join'') - Daniel Bohannon(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t103-invoke-cradlecrafter-moar-powershell-obfusk8tion-detection-techniques-join-daniel-bohannon)
				* Attackers, administrators and many legitimate products rely on PowerShell for their core functionality. However, its power has made it increasingly attractive for attackers and commodity malware authors alike. How do you separate the good from the bad? A/V signatures applied to command line arguments work sometimes. AMSI-based (Anti-malware Scan Interface) detection performs significantly better. But obfuscation and evasion techniques like Invoke-Obfuscation can and do bypass both approaches. Revoke-Obfuscation is a framework that transforms evasion into a treacherous deceit. By applying a suite of unique statistical analysis techniques against PowerShell scripts and their structures, what was once a cloak of invisibility is now a spotlight. It works with .evtx files, command lines, scripts, ScriptBlock logs, Module logs, and is easy to extend. Approaches for evading these detection techniques will be discussed and demonstrated. Revoke-Obfuscation has been used in numerous Mandiant investigations to successfully identify obfuscated and non-obfuscated malicious PowerShell scripts and commands. It also detects all obfuscation techniques in Invoke-Obfuscation, including two new techniques being released with this presentation.
		* **Tools**
			* [PyFuscation](https://github.com/CBHue/PyFuscation)
				* Obfuscate powershell scripts by replacing Function names, Variables and Parameters.
			* [Invoke-CradleCrafter v1.1](https://github.com/danielbohannon/Invoke-CradleCrafter)
			* [Invoke-Confusion.ps1](https://github.com/homjxi0e/PowerAvails/blob/master/invoke-Confusion.ps1)
			* [PowerAvails](https://github.com/homjxi0e/PowerAvails)
			* [Powerob](https://github.com/cwolff411/powerob)
				* An on-the-fly Powershell script obfuscator meant for red team engagements. Built out of necessity.
			* [Powerglot](https://github.com/mindcrypt/powerglot)
				* Powerglot encodes offensive powershell scripts using polyglots
		* **De-Obfuscate**
			* [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation)
				* [Blogpost](https://www.fireeye.com/blog/threat-research/2017/07/revoke-obfuscation-powershell.html)
				* [Paper](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf)
				* [Talk](https://www.youtube.com/watch?v=UVbbpZiYnTs)
					* [Talk Paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science-wp.pdf)
				* Revoke-Obfuscation is a PowerShell v3.0+ compatible PowerShell obfuscation detection framework.
			* **Articles/Blogposts/Writeups**
				* [PowerShell: ConvertFrom-SecureString decoder - wietzebeukema.nl](https://www.wietzebeukema.nl/powershell-securestring-decoder/)
			* **Tools**
				* [PowerShell: ConvertFrom-SecureString decoder](https://github.com/wietze/powershell-securestring-decoder/)
					* A simple, pure JavaScript implementation decoding PowerShell's SecureString objects for analysis.
				* [Babel-Shellfish](https://github.com/OmerYa/Babel-Shellfish)
					* Deobfuscate Powershell scripts right before execution. Babel-Shellfish allows to both log and scan through AMSI deobfuscated scripts. If a script is found mallicious it will stop its execution.
				* [CLM-Base64](https://github.com/FortyNorthSecurity/CLM-Base64)
					* [Blogpost](https://fortynorthsecurity.com/blog/base64-encoding/)
					* This project provides Base64 encoding and decoding functionality to PowerShell within Constrained Language Mode. Since this is constrained language mode compliant, it will also run in Full Language Mode.
				* [PowerAvails](https://github.com/homjxi0e/PowerAvails)
					* PowerAvails Powershell .NET Operating system
* **Exfiltration**
	* **Articles/Blogposts/Writeups**
		* [Egress Testing using PowerShell](http://www.labofapenetrationtester.com/2014/04/egress-testing-using-powershell.html)
* **Payloads**
	* **Talks/Presentations/Videos**
		* [Malicious payloads vs. deep visibility: a PowerShell story - Daniel Bohannon(PSConEU19)](https://www.youtube.com/watch?v=h1Sbb-1wRKw)
			* This talk draws from over four years of Incident Response experience to lay out a technical buffet of in-the-wild malicious PowerShell payloads and techniques. In addition to diving deep into the mechanics of each malicious example, this presentation will highlight forensic artifacts, detection approaches and the deep visibility that the latest versions of PowerShell provides security practitioners to defend their organizations against the latest attacks that utilize PowerShell.
	* **Generators**
		* [nps_payload](https://github.com/trustedsec/nps_payload)
			* This script will generate payloads for basic intrusion detection avoidance. It utilizes publicly demonstrated techniques from several different sources.
		* [​psWar.py](https://gist.github.com/HarmJ0y/aecabdc30f4c4ef1fad3)
			* Code that quickly generates a deployable .war for a PowerShell one-liner
	* **Samples
		* [JSRat-Py](https://github.com/Hood3dRob1n/JSRat-Py) 
			* implementation of JSRat.ps1 in Python so you can now run the attack server from any OS instead of being limited to a Windows OS with Powershell enabled
		* [ps1-toolkit](https://github.com/vysec/ps1-toolkit)
			* This is a set of PowerShell scripts that are used by many penetration testers released by multiple leading professionals. This is simply a collection of scripts that are prepared and obfuscated to reduce level of detectability and to slow down incident response from understanding the actions performed by an attacker.
	* **Signatures**
		* [DigitalSignature-Hijack.ps1](https://gist.github.com/netbiosX/fe5b13b4cc59f9a944fe40944920d07c)
			* [Hijack Digital Signatures – PowerShell Script - pentestlab](https://pentestlab.blog/2017/11/08/hijack-digital-signatures-powershell-script/)
		* [PoCSubjectInterfacePackage](https://github.com/mattifestation/PoCSubjectInterfacePackage)
			* A proof-of-concept subject interface package (SIP) used to demonstrate digital signature subversion attacks.
* **Miscellaneous Useful Things** 
	* [Invoke-VNC](https://github.com/artkond/Invoke-Vnc)
		* Powershell VNC injector
	* [Invoke-BSOD](https://github.com/peewpw/Invoke-BSOD)
		* A PowerShell script to induce a Blue Screen of Death (BSOD) without admin privileges. Also enumerates Windows crash dump settings. This is a standalone script, it does not depend on any other files.
	* [Invoke-SocksProxy](https://github.com/p3nt4/Invoke-SocksProxy)
		* Creates a Socks proxy using powershell.
	* [PowerShell-Suite](https://github.com/FuzzySecurity/PowerShell-Suite/)
		* There are great tools and resources online to accomplish most any task in PowerShell, sometimes however, there is a need to script together a util for a specific purpose or to bridge an ontological gap. This is a collection of PowerShell utilities I put together either for fun or because I had a narrow application in mind. - b33f
	* [Powershell-SSHTools](https://github.com/fridgehead/Powershell-SSHTools)
		* A bunch of useful SSH tools for powershell
	* [random-powershell](https://github.com/laconicwolf/random-powershell)
		* Various PowerShell scripts that have come in handy but aren't important enough for their own repository
* **Utilities**
	* [7Zip4Powershell](https://github.com/thoemmi/7Zip4Powershell) 
		* Powershell module for creating and extracting 7-Zip archives
* **Servers**
	* [Dirty Powershell Webserver](http://obscuresecurity.blogspot.com/2014/05/dirty-powershell-webserver.html)
	* [Pode](https://github.com/Badgerati/Pode)
		* Pode is a PowerShell framework that runs HTTP/TCP listeners on a specific port, allowing you to host REST APIs, Web Pages and SMTP/TCP servers via PowerShell. It also allows you to render dynamic HTML using PSHTML files.
	* [PowerHub](https://github.com/AdrianVollmer/PowerHub)
		* Webserver frontend for powersploit with functionality and niceness.
	* [Harness](https://github.com/Rich5/Harness)
		* Harness is remote access payload with the ability to provide a remote interactive PowerShell interface from a Windows system to virtually any TCP socket. The primary goal of the Harness Project is to provide a remote interface with the same capabilities and overall feel of the native PowerShell executable bundled with the Windows OS.
-----------------------------------------------------------------------------------------------------------------------------------









































---------------------------------------------------------------------------------------------------------------------------------
### <a name="wcit"></a>Windows Code Injection Techniques
* **101**
	* [Process Injection Techniques — Gotta Catch Them All - Itzik Kotler, Amit Klein(BHUSA19)](https://www.youtube.com/watch?v=xewv122qxnk)
		* [Paper](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)	
	* [‘Plata o plomo’ code injections/execution tricks - Hexacorn](https://www.hexacorn.com/blog/2019/05/26/plata-o-plomo-code-injections-execution-tricks/)
* **3 Base Primitive Categories**
	* **Process Spawning Techniques**
	* **Injecting During Process Initialization**
	* **Injecting into Running Processes**
	* One day I'll sort the articles/techniques into each.
* **Articles/Blogposts/Writeups that aren't about one sepcific technique**
	* [Windows API index - docs.ms](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
		* The following is a list of the reference content for the Windows application programming interface (API) for desktop and server applications.
	* [Ten process injection techniques: A technical survey of common and trending process injection techniques - Ashkan Hosseini(2017)](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
	* [Memory Injection like a Boss - Noora Hyvärinen(2018)](https://blog.f-secure.com/memory-injection-like-a-boss/)
	* [Process Injection - Part I - 3xpl01tc0d3r(2019)](https://3xpl01tc0d3r.blogspot.com/2019/08/process-injection-part-i.html?m=1)
	* [The state of advanced code injections - David Korczynski(2019)](https://adalogics.com/blog/the-state-of-advanced-code-injections)
	* [Process Injection: a primer - RedCanary(2020)](https://redcanary.com/blog/process-injection-primer/)
		* Experts from Red Canary, VMware Carbon Black, MITRE ATT&CK, and Microsoft break down the many facets of the Process Injection technique.
	* [Hidden in plain sight? - @casheeew(BlackHoodie2018)](https://blackhoodie.re/assets/archive/hidden_in_plain_sight_blackhoodie.pdf)
	* **PoC Examples**
		* [ProcessInjection - 3xpl01tc0d3r](https://github.com/3xpl01tc0d3r/ProcessInjection)
		* [injection - theevilbit](https://github.com/theevilbit/injection)
		* [GoPurple](https://github.com/sh4hin/GoPurple)
* **Generic**
		* [GetEnvironmentVariable as an alternative to WriteProcessMemory in process injections - x-c3ll(2020)](https://x-c3ll.github.io/posts/GetEnvironmentVariable-Process-Injection/)
		* [Injecting Code into Windows Protected Processes using COM - Part 1 - James Forshaw(P0)](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html)
		* [Injecting Code into Windows Protected Processes using COM - Part 2 - James Forshaw(P0)](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)
	* **PoCs**
		* [demos - hasherezade](https://github.com/hasherezade/demos)
		* [Injectopi](https://github.com/peperunas/injectopi)
			* Injectopi is a set of tutorials that I've decided to write down in order to learn about various injection techniques in the Windows' environment.
		* [InjectProc - Process Injection Techniques](https://github.com/secrary/InjectProc)
		* [pinjectra](https://github.com/SafeBreach-Labs/pinjectra)
* **CreateRemoteThread**
	* [Demystifying Code Injection Techniques: Part 1 – Shellcode Injection - Himanshu Khokhar(2019)](https://pwnrip.com/demystifying-code-injection-techniques-part-1-shellcode-injection/)
* **APC**<a name="APC"></a>
	* **101**
		* [Asynchronous Procedure Calls - docs.ms](https://docs.microsoft.com/en-gb/windows/win32/sync/asynchronous-procedure-calls)
		* [Inside NT's Asynchronous Procedure Call - Albert Almeida(2002)](https://www.drdobbs.com/inside-nts-asynchronous-procedure-call/184416590)
		* [Remote Windows Kernel Exploitation Step into the Ring 0 - Barnaby Jack](https://web.archive.org/web/20050512094747/http://www.eeye.com/~data/publish/whitepapers/research/OT20050205.FILE.pdf)
		* [Windows Process Injection: Asynchronous Procedure Call (APC) - modexp(2019)](https://modexp.wordpress.com/2019/08/27/process-injection-apc/)
		* [APC Series: User APC API - Ori Damari(2020)](https://repnz.github.io/posts/apc/user-apc/)
		* [APC Series: User APC Internals - Ori Damari(2020)](https://repnz.github.io/posts/apc/kernel-user-apc-api/)
	* **Informational**
		* [Kernel to User land: APC injection - Vault7Leaks](https://wikileaks.org/ciav7p1/cms/page_7995519.html)
		* [Examining the user-mode APC injection sensor introduced in Windows 10 build 1809 - Souhail Hammou ](https://rce4fun.blogspot.com/2019/03/examining-user-mode-apc-injection.html)
		* [Bypassing the Microsoft-Windows-Threat-Intelligence Kernel APC Injection Sensor - Philip Tsukerman(2019)](https://medium.com/@philiptsukerman/bypassing-the-microsoft-windows-threat-intelligence-kernel-apc-injection-sensor-92266433e0b0)
		* [The Curious Case of QueueUserAPC - Dwight Hohnstein(2019)](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb)
		* [Process Injection - Part V - 3xpl01tc0d3r(2019)](https://3xpl01tc0d3r.blogspot.com/2019/12/process-injection-part-v.html)
	* **Userland-Specific**
	* **Kernel-Specific**
		* [Kernel to User land: APC injection - Eureka Gallo(2019)](https://cloud.tencent.com/developer/article/1534232)
	* **Performing**
		* [APC Queue Code Injection - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection)
	* **Tools**
		* [PoC](https://github.com/odzhan/injection/tree/master/apc)
		* [Inject-dll-by-APC](https://github.com/3gstudent/Inject-dll-by-APC)
		* [APC Internals Research Code](https://github.com/repnz/apc-research)
		* [injdrv](https://github.com/chaos444/APC-injection-x86-x64)
			* injdrv is a proof-of-concept Windows Driver for injecting DLL into user-mode processes using APC.
		* [APCInjector](https://github.com/0r13lc0ch4v1/APCInjector)
			* Windows Kernel Driver dlls injector using APC
		* [APC-PPID](https://github.com/hlldz/APC-PPID)
			*  Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread and spoof the Parent Process. 
* **Atom Bombing**<a name="abomb"></a>
	* **101**
		* [AtomBombing – A New Code Injection Attack - ENISA(2016)](https://www.enisa.europa.eu/publications/info-notes/atombombing-2013-a-new-code-injection-attack)
		* [AtomBombing: Injecting Code Using Windows’ Atoms - Tal Liberman(BSidesSF(2017)](https://www.youtube.com/watch?v=9HV69QGiBAU)
			* In this talk we present a code injection technique, dubbed AtomBombing, which exploits Windows atom tables and Async Procedure Calls (APC). At the time of its release (October 2016), AtomBombing went undetected by common security solutions that focused on preventing infiltration.  AtomBombing affects all Windows versions. In particular, we tested it against Windows 10 and Windows 7.   Unfortunately, this issue cannot be patched by Microsoft since it doesn’t rely on broken or flawed code – rather on how these operating system mechanisms are designed.
	* **Info**
		* [Dridex’s Cold War: Enter AtomBombing - Magal Baz, Or Safran(2017)](https://securityintelligence.com/dridexs-cold-war-enter-atombombing/)
		* [ Detecting stealthier cross-process injection techniques with Windows Defender ATP: Process hollowing and atom bombing  - MS(2017)](https://www.microsoft.com/security/blog/2017/07/12/detecting-stealthier-cross-process-injection-techniques-with-windows-defender-atp-process-hollowing-and-atom-bombing/)
		* [AtomBombing Evasion and Detection](https://web.archive.org/web/20161108162725/https://breakingmalware.com/injection-techniques/atombombing-brand-new-code-injection-for-windows/)
		* [Dridex’s Bag of Tricks: An Analysis of its Masquerading and Code Injection Techniques - Ratnesh Pandey(2019)](https://www.bromium.com/dridex-threat-analysis-july-2019-variant/)
	* **Performing**
	* **PoC**
		* [atom-bombing](https://github.com/BreakingMalwareResearch/atom-bombing)
* **Breaking BaDDEr**<a name="bbad"></a>
	* [Windows Process Injection: Breaking BaDDEr - modexp(2019)](https://modexp.wordpress.com/2019/08/09/windows-process-injection-breaking-badder/)
	* [PoC](https://github.com/odzhan/injection/tree/master/dde)
* **'Code-less' Injection**<a name="cless"></a>
	* **Articles/Blogposts/Writeups**
		* [Injection on Steroids: Code less Code Injections and 0 Day Techniques - Paul Schofield Udi Yavo](https://www.youtube.com/watch?v=0BAaAM2wD4s)
			* [Blogpost](https://breakingmalware.com/injection-techniques/code-less-code-injections-and-0-day-techniques/)
		* [Less is More, Exploring Code/Process-less Techniques and Other Weird Machine Methods to Hide Code (and How to Detect Them)](https://cansecwest.com/slides/2014/less%20is%20more3.pptx)
* **Command Line and Environment Variables**<a name="clev"></a>
	* [Windows Process Injection: Command Line and Environment Variables - modexp(2020)](https://modexp.wordpress.com/2020/07/31/wpi-cmdline-envar/)
* **Console Window Class**<a name="clw"></a>
	* [Windows Process Injection: ConsoleWindowClass - modexp(2018)](https://modexp.wordpress.com/2018/09/12/process-injection-user-data/)
	* [PoC](https://github.com/odzhan/injection/tree/master/conhost)
* **Ctrl Injection**<a name="ctrli"></a>
	* [Ctrl-Inject - Rotem Kerner(2018)](https://web.archive.org/web/20190612183057/https://blog.ensilo.com/ctrl-inject)
    * [PoC](https://github.com/theevilbit/injection/blob/master/Ctrlinject/Ctrlinject/Ctrlinject.cpp)
* **DLL Injection**<a name="dlli"></a>
	* **101**
		* [Dynamic-link library](https://en.wikipedia.org/wiki/Dynamic-link_library)
		* [DllMain entry point - docs.ms](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain?redirectedfrom=MSDN)
		* [Exporting from a DLL - docs.ms](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll?view=vs-2019)
		* [DLL injection - Wikipedia](https://en.wikipedia.org/wiki/DLL_injection)
		* [A More Complete DLL Injection Solution Using CreateRemoteThread - Drew_Benton(2007)](https://www.codeproject.com/Articles/20084/A-More-Complete-DLL-Injection-Solution-Using-Creat)
		* [DLL Injection and WoW64 - corsix(2010)](http://www.corsix.org/content/dll-injection-and-wow64)
		* [Windows DLL Injection Basics - Brad Antoniewicz(2013)](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html)
		* [DLL/PIC Injection on Windows from Wow64 process - modexp(2015)](https://modexp.wordpress.com/2015/11/19/dllpic-injection-on-windows-from-wow64-process/)
	* **Articles/Blogposts/Writeups**
		* **Informational**
			* [Remote Thread Execution in System Process using NtCreateThreadEx for Vista & Windows7 - securityxploded](https://web.archive.org/web/20180803004004/https://securityxploded.com/ntcreatethreadex.php)
			* [DLL Injection and Windows 8 - nagareshwar.securityxploded(2012)](https://web.archive.org/web/20180313152339/http://nagareshwar.securityxploded.com/2012/09/07/dll-injection-and-windows-8/)
			* [Using SetWindowsHookEx for DLL Injection on Windows - Dejan Lukan(2013)](https://web.archive.org/web/20150214173649/http://resources.infosecinstitute.com/using-setwindowshookex-for-dll-injection-on-windows/)
			* [MapViewOfFile or NTmapViewOfSection ?](http://www.rohitab.com/discuss/topic/42777-mapviewoffile-or-ntmapviewofsection/)
				* "NtmapViewOfSection is a low level function in ntdll. All what MapViewOfSection does is just some small extra, like security checks, sanitizing, etc. Or it might be a simple wrapper. The point is that there isn't any special case where you should use this or that. They both do the same thing. - Unc3nZureD"
		* **Performing**
			* [Process Injection - Part II - 3xpl01tc0d3r(2019)](https://3xpl01tc0d3r.blogspot.com/2019/09/process-injection-part-ii.html)
			* [Inject All the Things - Shut up and hack - deniable.org(2017)](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
			* [DLL Injection Part 0: Understanding DLL Usage - Mark Wolters(2015(https://warroom.rsmus.com/dll-injection-part-0-understanding-dll-usage/)
			* [DLL Injection Part 1: SetWindowsHookEx - malarkey(2015)](https://web.archive.org/web/20170714045033/https://warroom.securestate.com/dll-injection-part-1-setwindowshookex/)
			* [DLL Injection Part 2: CreateRemoteThread and More - malarkey(2015)](https://web.archive.org/web/20170714043336/https://warroom.securestate.com/dll-injection-part-2-createremotethread-and-more/)
			* [DLL Injection - pentestlab.blog(2017)](https://pentestlab.blog/2017/04/04/dll-injection/)
			* [DLL Injection and Hooking](http://securityxploded.com/dll-injection-and-hooking.php)
			* [Delivering custom payloads with Metasploit using DLL injection - blog.cobalstrike](https://blog.cobaltstrike.com/2012/09/17/delivering-custom-payloads-with-metasploit-using-dll-injection/)
			* [DLL Injection via a Custom .NET Garbage Collector - @spottheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-dll-via-custom-.net-garbage-collector-environment-variable-complus_gcname)
	* **Tools**
		* [DLL-Injection - mwwolters](https://github.com/mwwolters/DLL-Injection)
		* [dll_inject_test](https://github.com/daanraman/dll_inject_test)
		* [dllinjector](https://github.com/OpenSecurityResearch/dllinjector)
			* dll injection tool that implements various methods
		* [Bleak](https://github.com/Akaion/Bleak)
			* A Windows native DLL injection library that supports several methods of injection. 
		* [Lunar](https://github.com/Dewera/Lunar)
			*  A lightweight native DLL mapping library that supports mapping directly from memory 
		* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
			* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
		* [MemJect](https://github.com/danielkrupinski/MemJect)
			*  Simple Dll injector loading from memory. Supports PE header and entry point erasure. Written in C99. 
		* [Windows-DLL-Injector](https://github.com/KooroshRZ/Windows-DLL-Injector)
* **Reflective Dll Injection**<a name="rdlli"></a>
	* **101**
		* [Reflection (computer programming) - Wikipedia](https://en.wikipedia.org/wiki/Reflection_(computer_programming))
		* [HS-P005_ReflectiveDllInjection.pdf - Stephen Fewer(2008)](https://packetstormsecurity.com/files/71410/HS-P005_ReflectiveDllInjection.pdf.html)
			* Whitepaper on reflective DLL injection. Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process. As such the library is responsible for loading itself by implementing a minimal Portable Executable (PE) loader.
		* [Reflective DLL Injection - Stephen Fewer(2008)](https://www.exploit-db.com/docs/english/13007-reflective-dll-injection.pdf)
			* Alternate hosting of paper
		* [Loading a DLL from memory - Joachim Bauch(2010)](https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/)
		* [Explaining Reflective DLL Injection in 2 min - by Miss Smurfette(2020)](https://www.youtube.com/watch?v=4mYhffBsGeY)
	* **Info**
		* [Reflective DLL Injection with PowerShell - clymb3r(2013)](https://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/)
		* [Upgrade your DLL to Reflective DLL - Ionut Popescu(2015)](https://securitycafe.ro/2015/02/26/upgrade-your-dll-to-reflective-dll/)
		* [An Improved Reflective DLL Injection Technique - Dan Staples(2015)](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html)
		* [Cross-Architecture Reflective DLL Injection - Dan Staples(2015)](https://disman.tl/2015/03/16/cross-architecture-reflective-dll-inection.html)
		* [ThreadContinue - Reflective DLL Injection Using SetThreadContext() and NtContinue(2017)](https://web.archive.org/web/20200406182128/https://zerosum0x0.blogspot.com/2017/07/threadcontinue-reflective-injection.html)
			* [Code](https://github.com/zerosum0x0/ThreadContinue)
		* [DLL Injection - Pentestlab.blog(2017)](https://pentestlab.blog/2017/04/04/dll-injection/)
		* [Inject Dll From Memory Into A Remote Process (InjectLibraryFromMemory_HYPD - Hypodermic) - Vault7Leaks](https://wikileaks.org/ciav7p1/cms/page_14588718.html)
		* [ DoublePulsar Initial SMB Backdoor Ring 0 Shellcode Analysis - zerosum0x0(2017)](https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html)
		* [Reflective DLL Injection - dtm(2017)](https://0x00sec.org/t/reflective-dll-injection/3080)
		* [sRDI – Shellcode Reflective DLL Injection - Nick Landers(2017)](https://silentbreaksecurity.com/srdi-shellcode-reflective-dll-injection/)
	* **Performing**
		* [Portable Executable (P.E.) Code Injection: Injecting an Entire C Compiled Application - Ciro Sisman Pereira(2008)](https://www.codeproject.com/Articles/24417/Portable-Executable-P-E-Code-Injection-Injecting-a)
		* [Loading Win32/64 DLLs "manually" without LoadLibrary() - xenotron(2014)](https://www.codeproject.com/Tips/430684/Loading-Win-DLLs-manually-without-LoadLibrary)
			* How to load DLLs by allocating memory and loading the DLL from file/memory and then relocating/importing.
		* [Reflective DLL Injection - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection)
		* [Exploit Development 5: Reflective DLL Injection - Thomas(2017)]
		* [Reflective DLLs and You - cplsec(2018)](https://ijustwannared.team/2018/02/13/reflective-dlls-and-you/)
			* "This post is about reflective dynamic link libraries (DLL) and will do a simple walk-through on how to write one.  This is a technique developed by Stephen Fewer and will use his code to make the magic happen. I realize this is a topic that has been discussed several times so I’m going to keep this post simple and tight."
		* [Windows - Process Injection Technique: Reflective DLL Injection - t0rchwo0d(2019)](https://t0rchwo0d.github.io/windows/Windows-Process-Injection-Technique-Reflective-DLL-Injection/)
	* **Detection**
    	* [Detecting Reflective Injection - Andrew King(DEFCON 20)](https://www.youtube.com/watch?v=ZB1yD8LlFns)
	        * This talk will focus on detecting reflective injection with some mildly humorous notes and bypassing said protections until vendors start actually working on this problem. It seems amazing that reflective injection still works. Why is that? Because programmers are lazy. They don't want to write new engines, they want to write definitions for an engine that already exists. So what do we do about it? Release a $5 tool that does what $50 AV has failed epically at for several years now...oh and it took me a week or so...Alternately, you could license it to vendors since their programmers are lazy. 
		* [What is Reflective DLL Injection and how can be detected? - Andrea Fortuna(2017)](https://www.andreafortuna.org/2017/12/08/what-is-reflective-dll-injection-and-how-can-be-detected/)
	* **PoCs**
	* **Tools**
		* [ReflectiveDLLInjection - Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection)
			* Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process. As such the library is responsible for loading itself by implementing a minimal Portable Executable (PE) file loader. It can then govern, with minimal interaction with the host system and process, how it will load and interact with the host.
		* [MemJect](https://github.com/danielkrupinski/MemJect)
			*  Simple Dll injector loading from memory. Supports PE header and entry point erasure. Written in C99. 
		* [doublepulsar-usermode-injector](https://github.com/countercept/doublepulsar-usermode-injector)
			* A utility to use the usermode shellcode from the DOUBLEPULSAR payload to reflectively load an arbitrary DLL into another process, for use in testing detection techniques or other security research. 
		* [RemoteFunctions](https://github.com/thereals0beit/RemoteFunctions)
			*  LoadLibrary, GetModuleHandle and GetProcAddress calls for remote processes
		* [ReflectiveDLLInjection - apriorit](https://github.com/apriorit/ReflectiveDLLInjection)
			* This tool demonstrates various remote dll injection methods.
		* [ImprovedReflectiveDLLInjection](https://github.com/dismantl/ImprovedReflectiveDLLInjection)
			* An improvement of the original reflective DLL injection technique by Stephen Fewer of Harmony Security 
		* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
			* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
		* [ReflectCmd](https://github.com/jaredhaight/ReflectCmd)
			* A simple reflective dll example 
		* [Pazuzu](https://github.com/BorjaMerino/Pazuzu)
			* Pazuzu is a Python script that allows you to embed a binary within a precompiled DLL which uses reflective DLL injection. The goal is that you can run your own binary directly from memory. This can be useful in various scenarios.
		* [Injectora](https://github.com/uItra/Injectora)
			*  x86/x64 manual mapping injector using the JUCE library 
		* [ReflectCmd](https://github.com/jaredhaight/ReflectCmd)
			* A simple reflective dll example 
		* [MemoryModule](https://github.com/fancycode/MemoryModule)
			* MemoryModule is a library that can be used to load a DLL completely from memory - without storing on the disk first.
		* [Windows Manage Reflective DLL Injection Module - Metasploit](https://www.rapid7.com/db/modules/post/windows/manage/reflective_dll_inject)
		* [sRDI - Shellcode Reflective DLL Injection](https://github.com/monoxgas/sRDI)
			* sRDI allows for the conversion of DLL files to position independent shellcode. It attempts to be a fully functional PE loader supporting proper section permissions, TLS callbacks, and sanity checks. It can be thought of as a shellcode PE loader strapped to a packed DLL.
		* [ReflectivePELoader - BenjaminSoelberg](https://github.com/BenjaminSoelberg/ReflectivePELoader)
* **DNS Client API**<a name="dnscla"></a>
	* [Code Execution via surgical callback overwrites (e.g. DNS memory functions) - hexacorn(2019)](http://www.hexacorn.com/blog/2019/06/12/code-execution-via-surgical-callback-overwrites-e-g-dns-memory-functions/)
	* [Windows Process Injection: DNS Client API - modexp(2019)](https://modexp.wordpress.com/2019/08/08/windows-process-injection-dnsapi/)
	* [Poc](https://github.com/odzhan/injection/tree/master/dns)
* **Process Doppelganging**<a name="procdoppel"></a>
	* **101**
		* [Lost in Transaction: Process Doppelgänging - Tal Liberman, Eugene Kogan(BHEU 2017)](https://www.youtube.com/watch?v=XmWOj-cfixs)
			* [Slides](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf)
			* Process Hollowing is a technique first introduced years ago by attackers to thwart the mitigation capabilities of security products. However, most of today's solutions are able to detect and prevent such notorious attacks. In this talk, we will present a new technique, dubbed Process Doppelgänging, which has similar advantages but is much harder to detect - let alone prevent. 
		* [What is Process Doppelganging & How is it Executed? - Suvarna Trigune(2018)](https://www.reveantivirus.com/blog/en/process-doppelganging)
		* [TAU-TIN - Process Doppelgang Evasion Technique - esullivan(2017)](https://community.carbonblack.com/t5/Threat-Advisories-Documents/TAU-TIN-Process-Doppelgang-Evasion-Technique/ta-p/62305)
	* **Information**
		* [Process Doppelgänging – a new way to impersonate a process - hasherezade(2017)](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/)
		* [Process Doppelgänging: New Malware Evasion Technique Works On All Windows Versions - Mohit Kumar(2017)](https://thehackernews.com/2017/12/malware-process-doppelganging.html)
		* [Process Doppelgänging meets Process Hollowing in Osiris dropper - hasherezade(2018)](https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/)
		* [On Process Doppelganging and developing an unpacker for it - KrabsOnSecurity(2018)](https://krabsonsecurity.com/2018/01/17/on-process-doppelganging-and-developing-an-unpacker-for-it/)
		* [In NTDLL I Trust – Process Reimaging and Endpoint Security Solution Bypass - Eoin Carroll, Cedric Cochin, Steve Povolny, Steve Hearnden(2019)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/in-ntdll-i-trust-process-reimaging-and-endpoint-security-solution-bypass/)
		* [Process Doppelganging Notes - hyp3rv3locity(2020)](https://hyp3rv3locity.blogspot.com/2019/10/process-doppelganging-notes.html)
		* [Process Doppelganging - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/process-doppelganging)
	* **Performing**
	* **PoCs**
		* [Process Refund](https://github.com/Spajed/processrefund)
		* [process_doppelganging](https://github.com/hasherezade/process_doppelganging)
			* "My implementation of enSilo's Process Doppelganging (PE injection technique)"
		* [Start-Eidolon.ps1](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Start-Eidolon.ps1)
	* **Detection**
		* [Threat Hunting #20 - Detecting Process Doppelgänging using event 4985 - menasec(2019)](https://blog.menasec.net/2019/02/threat-hunting-24-detecting-process.html)
* **DoppelGate**<a name="doppg"></a>
	* **101**
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**
		* [DoppelGate](https://github.com/asaurusrex/DoppelGate)
			*  DoppelGate relies on reading ntdll on disk to grab syscall stubs, and patches these syscall stubs into desired functions to bypass Userland Hooking. 
* **DoubleAgent**<a name="dai"></a>
	* [DOUBLEAGENT: Zero-Day Code Injection AND Persistence Technique - Cybellum(2017)](https://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique/)
	* [Masquerading Windows processes like a DoubleAgent. - Philippe Vogler(2020)](https://sensepost.com/blog/2020/masquerading-windows-processes-like-a-doubleagent./)
* **Earlybird Injection**<a name="ebi"></a>
	* **101**
		* [New ‘Early Bird’ Code Injection Technique Discovered - Hod Gavriel, Boris Erbesfeld(2018)](https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/)
	* **Info**
		* [Hackers Found Using A New Code Injection Technique to Evade Detection - Mohit Kumar(2018)](https://thehackernews.com/2018/04/early-bird-code-injection.html)
		* [DorkBot: An Investigation - Mark Lechtik(2018)](https://research.checkpoint.com/2018/dorkbot-an-investigation/)
		* [The “Early Bird Special” – a new twist on the “Early Bird” injection technique - Avi Lamay(2019)]
	* **Performing**
		* [Early Bird APC Queue Code Injection - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)
	* **Detection**
	* **PoC**	
* **Extra Window Bytes**<a name="ewbi"></a>
	* **101**
		* [Process Injection: Extra Window Memory Injection - MITRE ATT&CK(2020)](https://attack.mitre.org/techniques/T1055/011/)
		* [Windows Process Injection: Extra Window Bytes - modexp(2018)](https://modexp.wordpress.com/2018/08/26/process-injection-ctray/)
	* **Informational**
		* [Win32/Gapz: steps of evolution - Aleksandr Matrosov(2012)](https://www.welivesecurity.com/2012/12/27/win32gapz-steps-of-evolution/)
		* [Through the Window: Creative Code Invocation - Chris Dietrich(2014)](https://www.crowdstrike.com/blog/through-window-creative-code-invocation/)
	* **PoCs**
		* [Poc](https://github.com/odzhan/injection/tree/master/extrabytes)
* **Fibers**<a name="fii"></a>
	* **101**
	* **Info**
		* [Code Execution via Fiber Local Storage - dronesec(2019)](http://dronesec.pw/blog/2019/08/12/code-execution-via-fiber-local-storage/)
		* [Shellcode Execution through Fibers - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber)
* **Gargoyle**<a name="gii"></a>
	* **101**
		* [gargoyle, a memory scanning evasion technique - Josh Lospinoso(2017)](https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html)
	* **Info**
		* [Cobalt Strike 3.12 – Blink and you’ll miss it - CobaltStrike(2018)](https://blog.cobaltstrike.com/2018/09/06/cobalt-strike-3-12-blink-and-youll-miss-it/)
	* **Performing**
		* [Bypassing Memory Scanners with Cobalt Strike and Gargoyle - FSecure Labs(2018)](https://labs.f-secure.com/blog/experimenting-bypassing-memory-scanners-with-cobalt-strike-and-gargoyle/)
	* **Detection**
		* [Hunting for Gargoyle Memory Scanning Evasion - Aliz Hammond(2018)](https://blog.f-secure.com/hunting-for-gargoyle-memory-scanning-evasion/)
		* [Gargoyle Hunting In-Depth — Presented by Aliz Hammond(InfoSec in the City2020)](https://www.youtube.com/watch?v=T73GK1Y8jLU)
			* Detecting certain user-mode code-hiding techniques, such as Josh Lospinoso's 'Gargoyle', is almost impossible from user-space. In this talk, I will examine Gargoyle, and explain how it can be detected from kernel mode. I will first walk through using WinDbg to locate hidden code and then write a Volatility plugin to turn this process into a practical method of detecting real-world attacks — in the process, adding a reliable method of differentiating these from legitimate behavior. No prior kernel knowledge is needed, but those with a background in WinDbg, Windows internals, forensics, and/or Volatility will get the most from this talk.
		* [HookTracer: A System for Automated and Accessible API Hooks Analysis - Andrew Case, Mohammad M.Jalalzai, Md Firoz-Ul-Amin, Ryan D.Maggio, Aisha Ali-Gombe, Mingxuan Sun, Golden G.Richard III(2019)]
			* The use of memory forensics is becoming commonplace in digital investigation and incident response, as it provides critically important capabilities for detecting sophisticated malware attacks, including memory-only malware components. In this paper, we concentrate on improving analysis of API hooks, a technique commonly employed by malware to hijack the execution flow of legitimate functions. These hooks allow the malware to gain control at critical times and to exercise complete control over function arguments and return values. Existing techniques for detecting hooks, such the Volatility plugin apihooks, do a credible job, but generate numerous false positives related to non-malicious use of API hooking. Furthermore, deeper analysis to determine the nature of hooks detected by apihooks typically requires substantial skill in reverse engineering and an extensive knowledge of operating systems internals. In this paper, we present a new, highly configurable tool called hooktracer, which eliminates false positives, provides valuable insight into the operation of detected hooks, and generates portable signatures called hook traces, which can be used to rapidly investigate large numbers of machines for signs of malware infection.
		* [Hunting for Ghosts in Fileless Attacks - Buddy Tancio(2019)](https://www.sans.org/reading-room/whitepapers/malicious/paper/38960)
			* Hunting for a fileless threat can be a tedious and labor-intensive task for any analyst. It is, most often than not, extremely time-consuming and requires a significant amount of data gathering. On top of that, the traditional tools, methods, and defenses seem to be less effective when dealing with these almost invisible threats. Threat actors are frequently using attack techniques that work directly from the memory or using legitimate tools or services pre-installed in the system to achieve their goals (Trend Micro, 2017). It is a popular technique among targeted attacks and advanced persistent threats (APT), and now it has been adopted by conventional malware such as trojans, ransomwares, and even the most recent emerging threat – cryptocurrency miners. In some incidents, searching for a malicious file that resides in the hard drive seems to be insufficient. This study explores the different variations of fileless attacks that targeted the Windows operating system and what kind of artifacts or tools can provide clues for forensic investigation. 
	* **PoC**	   	
      	* [dotnet-gargoyle](https://github.com/countercept/dotnet-gargoyle)
    		* A spiritual .NET equivalent to the Gargoyle memory scanning evasion technique
* **GhostWriting Injection**<a name="gwi"></a>
	* **101**
		* [A paradox: Writing to another process without openning it nor actually writing to it - txipi(2007)](http://blog.txipinet.com/2007/04/05/69-a-paradox-writing-to-another-process-without-openning-it-nor-actually-writing-to-it/)
			* A paradox: Writing to another process without openning it nor actually writing to it
	* **Informational**
		* [Using METASM To Avoid Antivirus Detection (Ghost Writing ASM) - Royce Davis(2012)](https://www.pentestgeek.com/penetration-testing/using-metasm-to-avoid-antivirus-detection-ghost-writing-asm)
		* [Ghost Writing METASM - Vanshit Malhotra(2015)](https://screwnomore.wordpress.com/2015/05/26/ghost-writing-metasm/)
	* **Performing**	
	* **PoCs**
		* [GhostWriting](https://github.com/c0de90e7/GhostWriting)
* **Process Herpaderping**<a name="proch"></a>
	* **101**
	* **Info**
		* [Process Herpaderping](https://jxy-s.github.io/herpaderping/)
			* Process Herpaderping is a method of obscuring the intentions of a process by modifying the content on disk after the image has been mapped.
	* **Performing**
	* **Detection**
	* **PoC**
* **Process Hollowing**<a name="prochollow"></a>
	* **101**
		* [Process Hollowing - John Leitch](https://www.autosectools.com/process-hollowing.pdf)
		* [Process Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
			* Process hollowing is yet another tool in the kit of those who seek to hide the presence of a process. The idea is rather straight forward: a bootstrap application creates a seemingly innocent process in a suspended state. The legitimate image is then unmapped and replaced with the image that is to be hidden. If the preferred image base of the new image does not match that of the old image, the new image must be rebased. Once the new image is loaded in memory the EAX register of the suspended thread is set to the entry point. The process is then resumed and the entry point of the new image is executed.
	* **Information**
		* [Analyzing Malware Hollow Processes - Eric Monti(2011)(https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/analyzing-malware-hollow-processes/)
		* [Understanding Process Hollowing - Andrea Fortuna(2017)](https://www.andreafortuna.org/2017/10/09/understanding-process-hollowing/)
		* [RunPE: a practical example of Process Hollowing technique - Andrea Fortuna(2017)](https://www.andreafortuna.org/2017/11/22/runpe-a-practical-example-of-process-hollowing-technique/)
		* [7th Meetup – Reversing and Investigating Malware Evasive Tactics – Hollow Process Injection - Monnappa(2017)](https://cysinfo.com/7th-meetup-reversing-and-investigating-malware-evasive-tactics-hollow-process-injection/)
		* [New Wave of Hancitor Comes with New Evasive Techniques - Roy Moshailov(2016)](https://blog.morphisec.com/hancitor-macro-malware-with-process-hollowing)
		* [What Malware Authors Don't Want You to Know - Evasive Hollow Process Injection - Monnappa K A(BlackHatUSA2017)](https://www.youtube.com/watch?v=9L9I1T5QDg4)
			* [Paper](https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don%27t-Want-You-To-Know-Evasive-Hollow-Process-Injection-wp.pdf)
			* Hollow process injection is a code injection technique used by the malware authors to blend in with legitimate processes on the system and remain undetected; there are documented procedures to detect hollow process injection. This presentation focuses on undocumented hollow process injection techniques.
	* **Performing**
		* [Process Hollowing and Portable Executable Relocations - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
		* [](https://www.andreafortuna.org/2017/11/22/runpe-a-practical-example-of-process-hollowing-technique/)
		* [Process Injection Techniques andDetection using the Volatility Framework - Sotiria Balaoura(2018)](http://dione.lib.unipi.gr/xmlui/bitstream/handle/unipi/11578/Balaoura_MTE1623.pdf?sequence=1&isAllowed=y)
		* [Process Injection - Part III - 3xpl01tc0d3r(2019)](https://3xpl01tc0d3r.blogspot.com/2019/10/process-injection-part-iii.html)
		* [Parent PID Spoofing - Renos Nikolaou(2019)](https://medium.com/@r3n_hat/parent-pid-spoofing-b0b17317168e)
		* [Process hollowing - unprotect]()
	* **PoCs**
		* [EvasiveProcessHollowing](https://github.com/reevesrs24/EvasiveProcessHollowing)
			* Proof of concept code which demonstrate a few of the "evasive process hollowing" techniques analyzed in the white paper "What Malware Authors Don't want you to know - Evasive Hollow Process Injection" written by Monnappa K A. The PoC code can be used as a testbed to replicate the memory forensics findings discussed in the white paper.
		* [ProcessHollowing](https://github.com/ambray/ProcessHollowing)
			* Simple Process Hollowing in C#
	* **Malware**
		* [Malware Analysis – Dridex & Process Hollowing - Luis Rocha(2015)](https://countuponsecurity.com/2015/12/07/malware-analysis-dridex-process-hollowing/)
		* [Dridex’s Bag of Tricks: An Analysis of its Masquerading and Code Injection Techniques - Ratnesh Pandey(2019)](https://www.bromium.com/dridex-threat-analysis-july-2019-variant/)
	* **Tools**
		* [TikiTorch](https://github.com/rasta-mouse/TikiTorch)
			* TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process, allocates a region of memory, then uses CreateRemoteThread to run the desired shellcode within that target process. Both the process and shellcode are specified by the user.
* **Inject-Me**<a name="injme"></a>
	* **101**
		* [Inject Me x64 Injection-less Code Injection - DeepInstinct(2019)](https://www.deepinstinct.com/2019/07/24/inject-me-x64-injection-less-code-injection/)
			* Malware authors are always looking for new ways to achieve code injection, as it enables them to run their code in remote processes. Code Injection allows hackers to better hide their presence, gain persistence and leverage other processes’ data and privileges. Finding and implementing new, stable methods for code injection is becoming more and more challenging as traditional techniques are now widely detected by various security solutions or limited by native OS protections.  Inject-Me is a new method to inject code into a remote process in x64. Inject-Me is in fact “injection-less”, meaning that the remote (target) process is manipulated to read data from the injecting process, copy and execute it. The manipulation is mainly based on abusing ReadProcessMemory and calling conventions in X64. In addition to presenting Inject-Me, we mention a generalized approach to copying data in remote processes to recreate shellcode from the injecting process.
		* [Please Inject me, a X64 code injection - Alon Weinberg(2019)](https://www.youtube.com/watch?v=8-TcLgkPeLc)
		* [Please Inject me, a X64 code injection - Alon Weinberg(Defcon27)](https://www.youtube.com/watch?v=dKrNJhbGgHY)
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**	
* **Kernel Callback Table**<a name="kcti"></a>
	* **101**
		* [Windows Process Injection: KernelCallbackTable used by FinFisher / FinSpy - odzhan(2019)](https://modexp.wordpress.com/2019/05/25/windows-injection-finspy/)
		* [Windows Process Injection: Multiple Provider Router (MPR) DLL and Shell Notifications - odzhan(2019)](https://modexp.wordpress.com/2019/08/05/windows-process-injection-scn/)
	* **Info**
		* [FinFisher exposed: A researcher’s tale of defeating traps, tricks, and complex virtual machines - Andrea Allievi, Elia Florio](https://www.microsoft.com/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/)
		* [You Failed ! - ivanlef0u.tuxfamily.org(2007)](http://www.ivanlef0u.tuxfamily.org/?p=68)
		* [Kernel exploitation – r0 to r3 transitions via KeUserModeCallback - j00ru(2010)](https://j00ru.vexillium.org/2010/09/kernel-exploitation-r0-to-r3-transitions-via-keusermodecallback/)
		* [Callgate to user : nt!KeUserModeCallback & ROP / MDL - zer0mem(2013)](http://www.zer0mem.sk/?p=410)
		* [How to run userland code from the kernel on Windows - Thierry Franzetti(2014)](https://thisissecurity.stormshield.com/2014/04/08/how-to-run-userland-code-from-the-kernel-on-windows/)
		* [How to run userland code from the kernel on Windows – Version 2.0 - Edouard S(2016)](https://thisissecurity.stormshield.com/2016/10/19/how-to-run-userland-code-from-the-kernel-on-windows-version-2-0/)
	* **Performing**
	* **Detection**
	* **PoC**
		* [kct](https://github.com/odzhan/injection/tree/master/kct)
* **KnownDLLs Cache Poisoning**<a name="kdlli"></a>
	* **101**
		* [Windows Code Injection: Bypassing CIG Through KnownDlls - James Forshaw(2019)](https://www.tiraniddo.dev/2019/08/windows-code-injection-bypassing-cig.html)
			* TL;DR; This blog post describes a technique to inject a DLL into a process using only Duplicate Handle process access (caveats apply) which will also bypass Code Integrity Guard.
		* [Windows Process Injection: KnownDlls Cache Poisoning - odzhan(2019)](https://modexp.wordpress.com/2019/08/12/windows-process-injection-knowndlls/)
	* **Info**
		* [Hotpatchingthe Hotpatcher - Alex Ionescu(Syscan2013)](https://infocondb.org/con/recon/recon-2018/unknown-known-dlls-and-other-code-integrity-trust-violations-breaking-signature-guarantees-in-windows)
	* **Performing**
		* [Injection into a Process Using KnownDlls - Kotik Anton(2012)](https://www.codeproject.com/Articles/325603/Injection-into-a-Process-Using-KnownDlls)
			* In his article, we will consider an interesting, universal and rarely used method of code injection into a Windows process using KnownDlls sections. To demonstrate the method work we will develop a sample project to inject into all running processes and intercept some calls from ws2_32.dll.
	* **Detection**
	* **PoC**
		* [knowndlls](https://github.com/odzhan/injection/tree/master/knowndlls)	
* **Mapping Injection**<a name="mappi"></a>
	* **101**
		* [Mapping-Injection - Antonio Coco(2020)](https://github.com/antonioCoco/Mapping-Injection/tree/1.1)
	* **Info**
	* **Performing**
		* [Weaponizing Mapping Injection with Instrumentation Callback for stealthier process injection - splinter_code(2020)](https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html)
	* **Detection**
	* **PoC**
		* [Mapping-Injection](https://github.com/antonioCoco/Mapping-Injection/tree/1.1)
* **Multiple Provider Router (MPR) DLL and Shell Notifications**<a name="mpri"></a>
	* **101**
		* [Windows Process Injection: Multiple Provider Router (MPR) DLL and Shell Notifications - odzhan(2019)](https://modexp.wordpress.com/2019/08/05/windows-process-injection-scn/)
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**
		* [mpr](https://github.com/odzhan/injection/tree/master/mpr)
* **NINA**<a name="nina"></a>
	* **101**
		* [NINA: x64 Process Injection (NINA: No Injection, No Allocation x64 Process Injection Technique.) - NtRaiseHardError(2020)]
			* [Code](https://github.com/NtRaiseHardError/NINA)
* **NtCreate**<a name="ntcreate"></a>
	* **101**
		* [NtCreateSection - Undocumented functions of NTDLL](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html)
		* [RtlCreateUserThread - Undocumented functions of NTDLL](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html)
		* [Section Objects and Views - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views)
	* **Performing**
		* [NtCreateSection + NtMapViewOfSection Code Injection - @spotheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection)
* **PE Injection**<a name="peinject"></a>
	* **101**
		* [PE Format - docs.ms](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN)
		* [PE Format notes - corkami](https://github.com/corkami/docs/blob/master/PE/PE.md)
		* [Portable Executable File Format - Johannes Plachy](https://blog.kowalczyk.info/articles/pefileformat.html)
		* [CONSTANT INSECURITY: (PECOFF) Portable Executable FIle Format - Mario Vuksan, Tomislav Pericin(BHUSA2011)](https://www.youtube.com/watch?v=uoQL3CE24ls)
		* [Injecting code into executables with C - Michal Strehovsky(2007)](https://migeel.sk/blog/2007/07/30/injecting-code-into-executables-with-c/)
		* [Portable Executable Injection For Beginners - MalwareTech(2013)](https://www.malwaretech.com/2013/11/portable-executable-injection-for.html)
		* [PE injection explained - Advanced memory code injection technique - Emeric Nasi(2014)](https://blog.sevagas.com/PE-injection-explained)
		* [Some thoughts about PE Injection - Andrea Fortuna(2018)](https://www.andreafortuna.org/2018/09/24/some-thoughts-about-pe-injection/)
		* [Code Injection - Process PE Injection Basics - Emeric Nasi(2019)](https://blog.sevagas.com/?Process-PE-Injection-Basics)
		* [Powershell PE Injection: This is not the Calc you are looking for! - b33f](https://www.fuzzysecurity.com/tutorials/20.html)
	* **Info**
		* [Process Injection and Manipulation - David Krivobokov(2019)](https://www.deepinstinct.com/2019/09/15/malware-evasion-techniques-part-1-process-injection-and-manipulation/)
		* [PE Injection: Executing PEs inside Remote Processes - @spottheplanet](https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes)
	* **Performing**
		* [PE Section Header Injection using Code Cave - ]
		* [Reflective PE Injection in Windows 10 1909 - HUBBL3](https://www.bc-security.org/post/reflective-pe-injection-in-windows-10-1909/)
		* [[RedDev Series #1] PE Injection Trick - Chiam Yj(2020)](https://medium.com/@cyjien/pe-injection-trick-d044977f4791)
		* [Bypassing AV via in-memory PE execution - bats3c(2020)](https://blog.dylan.codes/bypassing-av-via/)
	* **Detection**
		* See the [Logging, System Monitoring and Threat Hunting](./L-SM-TH.md) Page.
	* **PoCs**
		* [PE-Inject - DelphiBasics(2010)](http://www.delphibasics.info/home/delphibasicscounterstrikewireleases/pe-inject)
		* [PE-inject - Michal Strehovsky](https://migeel.sk/programming/pe-inject/)
			* [Documentation](http://docs.migeel.sk/PE-inject/)
		* [ReflectivePELoader](https://github.com/BenjaminSoelberg/ReflectivePELoader)
			* POC Reflective PE loader for DLL injection.
		* [SimplePELoader](https://github.com/nettitude/SimplePELoader/)
			* A very simple PE loader for loading DLL's into memory without using LoadLibrary
		* [Mandark](https://github.com/gigajew/Mandark)
			* Tiny 64-bit RunPE written in C#
		* [Loader](https://github.com/Galenika/Loader)
			* C# Loader with BlackBone
		* [RunPE](https://github.com/Zer0Mem0ry/RunPE)
			* Code that allows running another windows PE in the same address space as the host process.
		* [loadlibrayy](https://github.com/vmcall/loadlibrayy)
			* x64 PE injector with kernel handle elevation and thread hijacking capabilities
		* [Invoke-ReflectivePEInjection - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
			* [Documentation](https://powersploit.readthedocs.io/en/latest/CodeExecution/Invoke-ReflectivePEInjection/)
		* [Invoke-ReflectivePEInjection.ps1 - empire](https://github.com/BC-SECURITY/Empire/blob/master/data/module_source/management/Invoke-ReflectivePEInjection.ps1)
		* [darkarmour](https://github.com/bats3c/darkarmour)
* **PowerLoader(Ex)**<a name="powex"></a>
	* **101**
		* [PowerLoader Injection – Something truly amazing - malwaretech(2013)](https://www.malwaretech.com/2013/08/powerloader-injection-something-truly.html)
	* **PoC**
		* [PowerLoaderEx](https://github.com/BreakingMalware/PowerLoaderEx)
* **Print Spooler**<a name="pspool"></a>
	* **101**
		* [Windows Process Injection: Print Spooler - odzhan(2019)](https://modexp.wordpress.com/2019/03/07/process-injection-print-spooler/)
	* **Performing**
	* **Detection**
	* **PoC**
		* [PoC](https://github.com/odzhan/injection/tree/master/spooler)	
* **PROPagate**<a name="propagate"></a>
	* **101**
		* [PROPagate – a new code injection trick - Hexacorn(2017)](http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/)
		* [Propagate – yet another follow-up (hypothetical clipboard execution version) - Hexacorn(2018)](https://www.hexacorn.com/blog/2018/11/19/propagate-yet-another-follow-up-hypothetical-clipboard-execution-version/)
		* [PROPagate – a new code injection trick – 64-bit and 32-bit - Hexacorn(2017)](https://www.hexacorn.com/blog/2017/11/03/propagate-a-new-code-injection-trick-64-bit-and-32-bit/)
		* [PROPagate follow-up #2 – Some more Shattering Attack Potentials - Hexacorn(2018)](https://www.hexacorn.com/blog/2018/02/04/propagate-follow-up-2-some-more-shattering-attack-potentials/)
	* **Info**
		* [Windows Process Injection: PROPagate - odzhan(2018)](https://modexp.wordpress.com/2018/08/23/process-injection-propagate/)	
		* [RIG Exploit Kit Delivering Monero Miner Via PROPagate Injection Technique - Sudhanshu Dubey, Dileep Kumar Jallepalli(2018)](https://www.fireeye.com/blog/threat-research/2018/06/rig-ek-delivering-monero-miner-via-propagate-injection-technique.html)
	* **Performing**
	* **Detection**
	* **PoC**
		* [propagate](https://github.com/odzhan/injection/tree/master/propagate	)
	* **CLIPBRDWNDCLASS**
		* [Propagate – yet another follow-up (hypothetical clipboard execution version) - hexacorn](http://www.hexacorn.com/blog/2018/11/19/propagate-yet-another-follow-up-hypothetical-clipboard-execution-version/)
		* [Windows Process Injection: CLIPBRDWNDCLASS - modexp(2019)](https://modexp.wordpress.com/2019/05/24/4066/)
		* [PoC](https://github.com/odzhan/injection/tree/master/clipboard)
* **Service Control Handler**<a name="schi"></a>
	* **101**
		* [Windows Process Injection: Service Control Handler - odzhan(2018)](https://modexp.wordpress.com/2018/08/30/windows-process-injection-control-handler/)
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**
		* [svcctrl](https://github.com/odzhan/injection/tree/master/svcctrl)
* **Shatter**<a name="shatter"></a>
	* **101**
		* [Shattering By Example - Brett Moore(BHUSA2004)](https://www.blackhat.com/presentations/bh-usa-04/bh-us-04-moore/bh-us-04-moore-whitepaper.pdf)
		* [Exploiting design flaws in the Win32 API for privilege escalation. Or... Shatter Attacks - How to break Windows. - Foon(2002)](https://web.archive.org/web/20060904080018/http://security.tombom.co.uk/shatter.html)
		* [Shattering By Example. - Brett Moore(2003)](https://www.blackhat.com/presentations/bh-usa-04/bh-us-04-moore/bh-us-04-moore-whitepaper.pdf)
		* [Code injection via return-oriented programming - Wayne Low(2012)](https://www.virusbulletin.com/virusbulletin/2012/10/code-injection-return-oriented-programming)
		* [Windows Process Injection: WordWarping, Hyphentension, AutoCourgette, Streamception, Oleum, ListPlanting, Treepoline - odzhan(2019](https://modexp.wordpress.com/2019/04/25/seven-window-injection-methods/)
		* [Windows Process Injection: EM_GETHANDLE, WM_PASTE and EM_SETWORDBREAKPROC - odzhan(2020)](https://modexp.wordpress.com/2020/07/07/wpi-wm-paste/)
	* **List of**
		* WordWarping
			https://www.hexacorn.com/blog/2019/04/23/wordwarper-new-code-injection-trick/
		* Hyphentension
		* AutoCourgette
		* Streamception
		* Oleum
		* ListPlanting
		* Treepoline
* **Stack Bomber**<a name="stackbomb"></a>
	* **101**
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**
		* [Pinjectra](https://github.com/SafeBreach-Labs/pinjectra)
			* Pinjectra is a C/C++ OOP-like library that implements Process Injection techniques (with focus on Windows 10 64-bit) 
* **Thread Execution Hijacking**<a name="tehi"></a>
	* **101**
		* [Process Injection: Thread Execution Hijacking - MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/003/)
		* [Hijacking a thread in another process - Len(2006)](http://www.lenholgate.com/blog/2006/04/hijacking-a-thread-in-another-process.html)
	* **Info**
		* [Ten process injection techniques: A technical survey of common and trending process injection techniques - Ashkan Hosseini(2017)](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
		* [PE 1nj3ct10n and Thread Hijacking For Malware Analysis - Alparslan Akyıldız academy(2019)](https://alparslanakyildiz.medium.com/pe-1nj3ct10n-and-thread-hijacking-for-malware-analysis-790164d681f9)
		* [Dridex’s Bag of Tricks: An Analysis of its Masquerading and Code Injection Techniques - Ratnesh Pandey](https://threatresearch.ext.hp.com/dridex-threat-analysis-july-2019-variant/)
	* **Performing**
		* [Malware Development: Leveraging Beacon Object Files for Remote Process Injection via Thread Hijacking - Connor McGarr(2021)](https://connormcgarr.github.io/thread-hijacking/)
		* [DLL injection via thread hijacking - zwclose7(2015)](http://www.rohitab.com/discuss/topic/40579-dll-injection-via-thread-hijacking/)
	* **Detection**
	* **PoC**
		* [InjectThread.c](https://web.archive.org/web/20050308002548/http://www.catch22.net/source/files/InjectThread.c)
		* [ThreadBoat](https://github.com/DoubleThreatSecurity/ThreadBoat)
			* Program uses Thread Hijacking to Inject Native Shellcode into a Standard Win32 Application.
		* [cThreadHijack](https://github.com/connormcgarr/cThreadHijack)
			* Beacon Object File (BOF) for remote process injection via thread hijacking
* **ThreadLocal Storage Injection**<a name="tlsi"></a>
	* **101**
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**
* **Tooltips/Common Controls**<a name="tcci"></a>
	* **101**
		* [Windows Process Injection: Tooltip or Common Controls - odzhan(2019)](https://modexp.wordpress.com/2019/08/10/windows-process-injection-tooltip-controls/)
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**
		* [tooltip](https://github.com/odzhan/injection/tree/master/tooltip)
* **Windows Notification Facility**<a name="wnfi"></a>
	* **101**
	* **Info**
		* [Windows Process Injection : Windows Notification Facility - odzhan(2019)](https://modexp.wordpress.com/2019/06/15/4083/)
	* **Performing**
		* [Exploit WNF Callback - Emeric Nasi(2020)](https://dl.packetstormsecurity.net/papers/general/code_injection_series_part3.pdf)
	* **Detection**
	* **PoC**
		* [wnf](https://github.com/odzhan/injection/tree/master/wnf)
* **WinSock Helper Functions(WSHX)**<a name="wshx"></a>
	* **101**
		* [Windows Process Injection: Winsock Helper Functions (WSHX) - odzhan(2019)](https://modexp.wordpress.com/2019/07/27/process-injection-winsock/)
	* **Info**
	* **Performing**
	* **Detection**
	* **PoC**
		* [wsh](https://github.com/odzhan/injection/tree/master/wsh)
* **Zombify** - herpaderping?
	* [Zombie Processes as a HIPS Bypass - Malwaretech(2014)](https://www.malwaretech.com/2014/12/zombie-processes-as-hips-bypass.html)
	* [ZombifyProcess](https://github.com/MalwareTech/ZombifyProcess)
		* create a standard Windows process in a suspended state, write our malicious code to the processes’ memory; the PEB and the EPROCESS structures will still be that of the original process, causing the HIPS to see the now malicious process as a legitimate signed executable (this is not RunPE or dynamic forking, because we don’t unmap the original executable and replacing it with our malicious one, as thos can be detected in multiple ways).
* **Tradecraft Tips**
	* [Windows Process Injection: Sharing the payload - odzhan](https://modexp.wordpress.com/2018/07/15/process-injection-sharing-payload/)
* **Unsorted**
	* [New method of injection - w4kfu(2011)](http://blog.w4kfu.com/post/new_method_of_injection)
		* I disovered a new method of injection (I don't know if it is really new) in a malware dropped by duqu. So I want to share it with you and as usual write a p0c. Edit : This method is not new, apparently it have been using by game cheats for years, but instead of using ZwUnmapViewOfSection they use FreeLibrary.
-----------------------------------------------------------------------------------------------------------------------------------







