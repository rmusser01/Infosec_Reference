# Privilege Escalation & Post-Exploitation

----------------------------------------------------------------------
## Table of Contents
- [Privilege Escalation](#privesc)
	- [Hardware-based Privilege Escalation](#hardware)
- [Post-Exploitation](#postex)
	- [General Post Exploitation Tactics](#postex-general)
- [Linux Specific]()
	- [Linux Code Injection Techniques](#lcit)
- [macOS Specific]()
	- [macOS Code Injection Techiques](#mcit)
- [Windows Specific]()
	- [101](#win101)
	- [Living_off_The_Land](#lolbins)
	- [Windows Technologies](#wintech)
	- [Application Shims](#winappshims)
	- [Code Signing](#wincodesign)
	- [CSharp & .NET Stuff](#csharp-stuff) 
	- [Powershell Stuff](#powershell-stuff) 
	- [Windows Code Injection Techniques](#wcit)
- [Pivoting](#pivot)
- [Avoiding/Bypassing Anti-Virus/Whitelisting/Sandboxes/etc](#av)	
- [Payloads](#payloads)

| [Linux Post Exploitation](#linpost)  	| [OS X Post Exploitation](#osxpost)  	|  [Windows Post Exploitation](#winpost) 	|
|:--	|:-	|:-- |
| [Execution](#linexec)	| [Execution](#osxexecute)  	| [Execution](#winexec)  	|
| [Persistence](#linpersist)  	| [Persistence](#osxpersist)  	| [Persistence](#winpersist)  	|
| [Privilege Escalation](#linprivesc) 	| [Privilege Escalation](#osxprivesc)  	| [Privilege Escalation](#winprivesc)  	|
| [Defense Evasion](#lindefe)  	| [Defense Evasion](#osxdefev)  	| [Defense Evasion](#windefev)  	|
| [Credential Access](#lincredac)  	| [Credential Access](#osxcredac)  	| [Credential Access](#wincredac)  	|
| [Discovery](#lindisco)  	| [Discovery](#osxdisco) 	| [Discovery](#windisco)  	|
| [Lateral Movement](#linlat)  	| [Lateral Movement](#osxlat)  	| [Lateral Movement](#winlater)  	|
| [Collection](#lincollect)  	| [Collection](#osxcollect)  	| [Collection](#collection)  	|

| Linux Defense Evasion  | macOS Defense Evasion  | Windows Defense Evasion  |
|:--	|:-	|:-- |
|   | [Application Whitelistng](#whitelist)  | [Anti-Malware Scan Interface](#amsi)  |
|   | [Endpoint Security Framework](#esf)  | [Application Whitelisting](#appwhitelist)   |
|   | [Gatekeeper](#gatekeeper)  | [Windows Defender](#defender)  |
|   | [System Integrity Protection](#sip)  | [Microsoft ATA/P](#msatap)  |
|   | [XProtect](#xprotect)  | [Device Guard](#deviceguard)  |
|   |   |   |

| Linux Specific Technologies  | macOS Specific Technologies  | Windows Specific Technologies  |
|:-- |:-- |:-- |
|   |   | [Alternate Data Streams](#wads)  |
|   | [Code Signing](#osxsign)  | [AppLocker](#winapplocker)  |
|   | [Endpoint Security Framework](#osxesf) | [Application Shims](#winappshim)  |
|   | [GateKeeper](#osxgk)  | [ClickOnce](#clickonce)  |
|   |   | [Credential Guard](#credguard)  |
|   | [System Integrity Protection](#osxsip)  | [Code Signing](#codesign)  |
|   | [Transparency, Consent, and Control](#osxtcc)  | [(Distributed) Component-Object-Model(COM)](#dcom)  |
|   | [XProtect](#osxxprotect)  | [Dynamic Link Library](#dll)  |
|   |   | [Data Protection API(DPAPI)](#dpapi)  |
|   |   | [Device Guard](#devguard)  |
|   |   | [Event Tracing for Windows](#etw)  |
|   |   | [Print & Fax](#printfax)  |
|   |   | [File Extensions](#)  |
|   |   | [LNK Files](#LNK)  |
|   |   | [Windows Logging](#winlog)  |
|   |   | [MS-SQL Server](#ms-sql-server)  |
|   |   | [Named Pipes](#namedpipes)  |
|   |   | [PowerShell](#powershell)  |
|   |   | [PowerShell Desired State](#winpsc)  |
|   |   | [Windows Communication Foundation](#wcf)  |
|   |   | [Windows Notification Facility](#wnf)  |
|   |   | [Windows Remote Management](#winrm)  |
|   |   | [Windows Scripting Host](#wsh)  |
|   |   |   |

----------------------------------------------------------------------

To Do
* Change AV Avoidance stuff to specific OS
* Sort AMSI stuff

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


















-------------------
## Post-Exploitation<a name="postex"></a>

-------------------
### <a name="postex-general"></a>General Post Exploitation
* **Tactics**
	* [MITRE ATT&CK](https://attack.mitre.org/)
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
* **Execution**
	* **Tools**
		* [Shellpaste](https://github.com/andrew-morris/shellpaste)
			* Tiny snippet of code that pulls ASCII shellcode from pastebin and executes it. The purpose of this is to have a minimal amount of benign code so AV doesn't freak out, then it pulls down the evil stuff. People have been doing this kind of stuff for years so I take no credit for the concept. That being said, this code (or similar code) works surprisingly often during pentests when conventional malware fails.
	* **Payloads**
		* [Staged vs Stageless Handlers - OJ Reeves(2013)](https://buffered.io/posts/staged-vs-stageless-handlers/)
		* [Staged Payloads – What Pen Testers Should Know - Raphael Mudge(2013)]
		* [Deep Dive Into Stageless Meterpreter Payloads - OJ Reeves(2015)](https://blog.rapid7.com/2015/03/25/stageless-meterpreter-payloads/)
		* [Payload Types in the Metasploit Framework - offensive-security](https://www.offensive-security.com/metasploit-unleashed/payload-types/)
* **Privilege Escalation**
		* [Finding Privilege Escalationswith strace & SysInternals - Diplom Mathematiker(2017)](https://owasp.org/www-pdf-archive//Finding_Privilege_Escalations_OWASP_Stammtisch_Stuttgart_17-11-06.pdf)
* **Discovery**
	* **Browsers**
		
			* [The Curious case of Firefox’s DevTools Storage - phl4nk(2020)](https://phl4nk.wordpress.com/2020/04/24/the-curious-case-of-firefoxs-devtools-storage/)
				* TL;DR – Firefox stores Dev tool console data permanently (unless manually deleted). Use the script to decompress the stored data and recover any potential goodies (mainly from devs running scripts in the console).
			* [DevToolReader](https://github.com/phl4nk/devtoolreader)
				* Parses Indexeddb files - used to extract devtools console history 
		* **Tools**
			* [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)
				* EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible. 
			* [gowitness](https://github.com/sensepost/gowitness)
				* a golang, web screenshot utility using Chrome Headless 
			* [WitnessMe](https://github.com/byt3bl33d3r/WitnessMe)
				* Web Inventory tool, takes screenshots of webpages using Pyppeteer (headless Chrome/Chromium) and provides some extra bells & whistles to make life easier.
	* **File Discovery**
		* [localdataHog](https://github.com/ewilded/localdataHog)
			* String-based secret-searching tool (high entropy and regexes) based on truffleHog.
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
* **Exfiltration**
	* **Egress Testing**
		* [Egress Testing using PowerShell](http://www.labofapenetrationtester.com/2014/04/egress-testing-using-powershell.html)
		* [Egress Buster Reverse Shell](https://www.trustedsec.com/files/egress_buster_revshell.zip)
			* Egress Buster Reverse Shell – Brute force egress ports until one if found and execute a reverse shell(from trustedsec)
		* [Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess)
			* Egress-Assess is a tool used to test egress data detection capabilities
	* **File Transfer**
		* **Articles/Blogposts/Writeups**
			* [File transfer skills in the red team post penetration test - xax007](https://www.exploit-db.com/docs/english/46515-file-transfer-skills-in-the-red-team-post-penetration-test.pdf)
			* [(Almost) All The Ways to File Transfer - PenTest-Duck](https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65)
		* **Platform-Neutral**
			* [Updog](https://github.com/sc0tfree/updog)
				* Updog is a replacement for Python's SimpleHTTPServer. It allows uploading and downloading via HTTP/S, can set ad hoc SSL certificates and use http basic auth.
			* [ffsend](https://github.com/timvisee/ffsend)
				* Easily and securely share files and directories from the command line through a safe, private and encrypted link using a single simple command. Files are shared using the Send service and may be up to 1GB (2.5GB authenticated). Others are able to download these files with this tool, or through their web browser.
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
* **Discovery**<a name="lindisco"></a>
	* **Articles/Blogposts/Writeups**
		* [Data Collection with Python on Linux Systems - Ogunal(2020)](https://en.ogunal.com/data-collection-with-python-on-linux-system/)
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
* **Execution**<a name="linexec"></a>
	* **Articles/Blogposts/Writeups**
	* **Tools**
	* **LoLBins**
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [GTFOBins](https://gtfobins.github.io/#)
				* GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. The project collects legitimate functions of Unix binaries that can be abused to break out of restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks. 
			* [GTFOPlus](https://github.com/yuudev/gtfoplus)
		    	* GTFOPlus is a helper script that relies on the GTFOBins repo to identify standard Linux binaries that could assist with privilege escalation.
	* **Command and Scripting Interpreter**
		* **Bash**
			* **Tools**
				* [Orc](https://github.com/zMarch/Orc)
					* Orc is a post-exploitation framework for Linux written in Bash
	* **Exploitation for Client Execution**
	* **Inter-Process Communication**
	* **Native API**
		* **Articles/Blogposts/Writeups**	
			* [needle - Linux x86 run-time process manipulation(paper)](http://hick.org/code/skape/papers/needle.txt)
			* [In-Memory-Only ELF Execution (Without tmpfs) - Stuart](https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html)
		* **Tools**
			* [msf-elf-in-memory-execution](https://github.com/fbkcs/msf-elf-in-memory-execution)
				* Post module for Metasploit to execute ELF in memory
	* **Scheduled Task/Job**
		* **At**
		* **Launchd**
		* **Cron**
	* **Shared Modules**
	* **Software Deployment Tools**
	* **System Services**
		* **Launchctl**
		* **Service Execution**
	* **User Execution**
		* **Malicious Link**
		* **Malicious File**
			* **Articles/Blogposts/Writeups**	
				* [Introducing tmpnix - an alternative to static binaries for post exploitation - shiftordie.de](https://shiftordie.de/blog/2019/02/05/introducing-tmpnix-an-alternative-to-static-binaries-for-post-exploitation/)
				* [A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux - muppetlabs](http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html)
				* [No one expect command execution!](http://0x90909090.blogspot.fr/2015/07/no-one-expect-command-execution.html)
					* Command execution through native utilities
	* **Payloads**
		* **Tools**
			* [fireELF](https://github.com/rek7/fireELF)
				* fireELF is a opensource fileless linux malware framework thats crossplatform and allows users to easily create and manage payloads. By default is comes with 'memfd_create' which is a new way to run linux elf executables completely from memory, without having the binary touch the harddrive.
* **Persistence**<a name="linpersist"></a>
	* **Account Manipulation**
		* **Additional Azure Service Principal Credentials**
		* **Exchange Email Delegate Permissions**
		* **Add Office 365 Global Administrator Role**
		* **SSH Authorized Keys**
	* **BITS Jobs**
	* **Boot or Logon Autostart Execution**
		* **Registry Run Keys / Startup Folder**
		* **Authentication Package**
		* **Time Providers**
		* **Winlogon Helper DLL**
		* **Security Support Provider**
		* **Kernel Modules and Extensions**
		* **Re-opened Applications**
		* **LSASS Driver**
		* **Shortcut Modification**
		* **Port Monitors**
		* **Plist Modification**
	* **Boot or Logon Initialization Scripts**
		* **Logon Script (Windows)**
		* **Logon Script (Mac)**
		* **Network Logon Script**
		* **Rc.common**
		* **Startup Items**
		* **Browser Extensions**
	* **Browser Extensions**
	* **Compromise Client Software Binary**
		* **Tools**
			* [Debinject](https://github.com/UndeadSec/Debinject)
				* Inject malicious code into .debs	
	* **Create Account**
		* **Local Account**
		* **Domain Account**
		* **Cloud Account**
	* **Create or Modify System Process**
		* **Launch Agent**
		* **Systemd Service**
		* **Windows Service**
		* **Launch Daemon**
	* **Event Triggered Execution**
		* **Change Default File Association**
		* **Screensaver**
		* **Windows Management Instrumentation Event Subscription**
		* **.bash_profile and .bashrc**
		* **Trap**
		* **LC_LOAD_DYLIB Addition**
		* **Netsh Helper DLL**
		* **Accessibility Features**
		* **AppCert DLLs**
		* **AppInit DLLs**
		* **Application Shimming**
		* **Image File Execution Options Injection**
		* **PowerShell Profile**
		* **Emond**
		* **Component Object Model Hijacking**
	* **External Remote Services**
	* **Hijack Execution Flow**
		* **Services File Permissions Weakness**
		* **Executable Installer File Permissions Weakness**
		* **Services Registry Permissions Weakness**
		* **Path Interception by Unquoted Path**
		* **Path Interception by PATH Environment Variable**
		* **Path Interception by Search Order Hijacking**
		* **DLL Search Order Hijacking**
		* **DLL Side-Loading**
		* **LD_PRELOAD**
		* **Dylib Hijacking**
		* **COR_PROFILER**
		* **Implant Container Image**
	* **Implant Container Image**
	* **Office Application Startup**
		* **Add-ins**
		* **Office Template Macros**
		* **Outlook Forms**
		* **Outlook Rules**
		* **Outlook Home Page**
		* **Office Test**
	* **Pre-OS Boot**
		* **System Firmware**
		* **Component Firmware**
		* **Bootkit**
	* **Scheduled Task/Job**
		* **At (Windows)**
		* **Scheduled Task**
		* **At (Linux)**
		* **Launchd**
		* **Cron**
	* **Server Software Component**
		* **SQL Stored Procedures**
		* **Transport Agent**
		* **Web Shell**
	* **Traffic Signaling**
		* **Port Knocking**
	* **Valid Accounts**
		* **Default Accounts**
		* **Domain Accounts**
		* **Local Accounts**
		* **Cloud Accounts**
* **Privilege Escalation**<a name="linprivesc"></a>
	* **101**
		* [Basic Linux Privilege Escalation - g0tm1lk](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
		* [Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
		* [AllTheThings - Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#checklists)
	* **Articles/Blogposts/Writeups**
		* [How I did not get a shell - NCCGroup](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/how-i-did-not-get-a-shell/)
		* [Linux: VMA use-after-free via buggy vmacache_flush_all() fastpath - projectzero](https://bugs.chromium.org/p/project-zero/issues/detail?id=1664)
		* [Attack and Defend: Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
		* [Abusing PackageKit on Fedora/CentOS for fun & profit (from wheel to root). - sysdream.com](https://sysdream.com/news/lab/2020-05-25-abusing-packagekit-on-fedora-centos-for-fun-profit-from-wheel-to-root/)
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
		* [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
			* Next-Generation Linux Kernel Exploit Suggester 
		* [LinuxPrivChecker](http://www.securitysift.com/download/linuxprivchecker.py)
			* This is a great tool for once again checking a lot of standard things like file permissions etc. The real gem of this script is the recommended privilege escalation exploits given at the conclusion of the sc
			* [Github](https://github.com/oschoudhury/linuxprivchecker)
		* [Unix Privilege Escalation Checker](https://code.google.com/p/unix-privesc-check/)
			* Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases). It is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed). It can run either as a normal user or as root (obviously it does a better job when running as root because it can read more files).
		* [EvilAbigail](https://github.com/GDSSecurity/EvilAbigail/blob/master/README.md)
			* Initrd encrypted root fs attack
		* [kernelpop](https://github.com/spencerdodd/kernelpop)
			* kernel privilege escalation enumeration and exploitation framework
		* [GTFOPlus](https://github.com/netspooky/gtfoplus)
			* GTFOPlus is a helper script that relies on the GTFOBins repo to identify standard Linux binaries that could assist with privilege escalation.
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
			* [linikatz](https://github.com/CiscoCXSecurity/linikatz)
				* This repository contains all of the scripts and source code for "Where 2 Worlds Collide: Bringing Mimikatz et al to UNIX". In addition to the main linikatz.sh script, this also includes auditd policies, John the Ripper rules, Metasploit post-exploitation modules and fuzzers. More will follow in due course.
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
			* [Impost3r](https://github.com/ph4ntonn/Impost3r/blob/master/README_EN.md)
				* Impost3r is a tool that aim to steal many kinds of linux passwords(including ssh,su,sudo) written by C
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
		* [Targeting a macOS Application? Update Your Path Traversal Lists - James Sebree](https://medium.com/tenable-techblog/targeting-a-macos-application-update-your-path-traversal-lists-a1055959a75a)
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
	* **Tools**
		* [Jamf-Attack-Toolkit](https://github.com/FSecureLABS/Jamf-Attack-Toolkit)
			* Suite of tools to facilitate attacks against the Jamf macOS management platform. These tools compliment the talk given by Calum Hall and Luke Roberts at Objective By The Sea V3, slides and video can be found [here](https://objectivebythesea.com/v3/talks/OBTS_v3_cHall_lRoberts.pdf) and [here](https://youtu.be/ZDJsag2Za8w?t=16737).
* **Execution**<a name="osxexecute"></a>
	* **General**
		* [Weaponizing a Lazarus Group Implant - Patrick Wardle(2020)](https://objective-see.com/blog/blog_0x54.html)
			* repurposing a 1st-stage loader, to execute custom 'fileless' payloads
		* [ShellOut](https://github.com/JohnSundell/ShellOut)
			* Welcome to ShellOut, a simple package that enables you to easily “shell out” from a Swift script or command line tool.
	* **Command and Scripting Interpreter**
		* **AppleScript**<a name="osxa"></a>
			* **101**
				* [AppleScript Language Guide - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html#//apple_ref/doc/uid/TP40000983-CH208-SW1)
				* [AppleScript Fundamentals - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/conceptual/ASLR_fundamentals.html)
					* Section from the Language Guide
				* [AppleScript - William R. Cook(2006)](https://www.cs.utexas.edu/users/wcook/Drafts/2006/ashopl.pdf)
				* [Scripting with AppleScript - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptX/Concepts/work_with_as.html#//apple_ref/doc/uid/TP40001568)
					* The following is a brief introduction to AppleScript scripts, tools for working with them, and information on using AppleScript scripts together with other scripting systems. For related documents, see the learning paths in Getting Started with AppleScript.
				* [AppleScript: The Definitive Guide, 2nd Edition - Matt Neuburg](http://books.gigatux.nl/mirror/applescriptdefinitiveguide/toc.html)
				* [AppleScript Reference Library](https://applescriptlibrary.wordpress.com/)
				* [AppleScriptLanguageGuide - Apple](https://applescriptlibrary.files.wordpress.com/2013/11/applescriptlanguageguide-2013.pdf)
				* [Open Scripting Architecture - developer.apple.com](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptX/Concepts/osa.html)
			* **Articles/Blogposts/Writeups**
				* [How Offensive Actors Use AppleScript for Attackign macOS - Phil Stokes](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
				* [macOS Red Team: Spoofing Privileged Helpers (and Others) to Gain Root - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-spoofing-privileged-helpers-and-others-to-gain-root/)
				* [macOS Red Team: Calling Apple APIs Without Building Binaries - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/)
				* [Launch Scripts from Webpage Links - macosxautomation.com](https://www.macosxautomation.com/applescript/linktrigger/)
				* [Using NSAppleScript - appscript.sourceforge](http://appscript.sourceforge.net/nsapplescript.html)
				* [hello, applescript 2: user in, user out - philastokes(applehelpwriter.com)](https://applehelpwriter.com/2018/09/03/hello-applescript-2-user-in-user-out/)
				* [hello, applescript 3: (don’t?) tell me to run - philastokes(appplehelpwriter)](https://applehelpwriter.com/2018/09/14/hello-applescript-3-dont-tell-me-to-run/)
			* **Tools**
		* **Javascript for Automation(JXA)**
			* [Orchard](https://github.com/its-a-feature/Orchard)
				* Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web.
			* **Talks/Presentations/Videos**
				* [Bash-ing Brittle Indicators: Red Teaming macOS without Bash or Python - Cody Thomas(Objective by the Sea v2.0)](https://www.youtube.com/watch?v=E-QEsGsq3uI&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=17)
				    * [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf)
		    		*  In this talk, I'll go into the research, development, and usage of a new kind of agent based on JavaScript for Automation (JXA) and how it can be used in modern red teaming operations. This agent is incorporated into a broader open source project designed for collaborative red teaming I created called Apfell. I will discuss TTPs for doing reconnaissance, persistence, injection, and some keylogging all without using a shell command or spawning another scripting language. I will go into details of how JXA can be used to create an agent complete with encrypted key exchange for secure communications, domain fronting C2, and modular design to load or change key functionality on the fly. I will also cover the defensive considerations of these TTPs and how Apple is starting to secure these capabilities going forward. 
		* **Swift**
			* **Tools**
				* [ShellOut](https://github.com/JohnSundell/ShellOut)
					* Easily run shell commands from a Swift script or command line tool
	* **Exploitation for Client Execution**
		* **Articles/Blogposts/Writeups**
	* **Inter-Process Communication**
		* **Articles/Blogposts/Writeups**
	* **Native API**
		* **Articles/Blogposts/Writeups**
	* **Scheduled Task/Job**
		* **At**
		* **Launchd**
		* **Cron**
	* **Shared Modules**
		* **Articles/Blogposts/Writeups**
	* **Software Deployment Tools**
		* **Articles/Blogposts/Writeups**
	* **System Services**
		* **Launchctl**
		* **Service Execution**
	* **User Execution**
		* **Malicious Link**
			* **Articles/Blogposts/Writeups**
				* [URL Routing on macOS - Florian Schliep](https://medium.com/@floschliep/url-routing-on-macos-c53a06f0a984)
				* [Remote Mac Exploitation Via Custom URL Schemes - Patrick Wardle(2018)](https://objective-see.com/blog/blog_0x38.html)
		* **Malicious File**
			* **Articles/Blogposts/Writeups**
				* [Native Mac OS X Application / Mach-O Backdoors for Pentesters](https://lockboxx.blogspot.com/2014/11/native-mac-os-x-application-mach-o.html)
			* **Tools**
				* [HappyMac](https://github.com/laffra/happymac)
					* A Python Mac app to suspend background processes 
				* [Platypus](https://github.com/sveinbjornt/Platypus)
					* Platypus is a developer tool that creates native Mac applications from command line scripts such as shell scripts or Python, Perl, Ruby, Tcl, JavaScript and PHP programs. This is done by wrapping the script in an application bundle along with a slim app binary that runs the script.
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
		* [Parasite](https://github.com/ParasiteTeam/documentation)
			* Parasite is a powerful code insertion platform for OS X. It enables developers to easily create extensions which change the original behavior of functions. For users Parasite provides an easy way to install these extensions and tweak their OS.
		* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
			* A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.
* **Persistence**<a name="osxpersist"></a>
	* **General**
		* **Articles/Blogposts/Writeups**
			* [Methods Of Malware Persistence On Mac OS X](https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf)
			* [How Malware Persists on macOS - Phil Stokes](https://www.sentinelone.com/blog/how-malware-persists-on-macos/)
			* [What's the easiest way to have a script run at boot time in OS X? - Stack Overflow](https://superuser.com/questions/245713/whats-the-easiest-way-to-have-a-script-run-at-boot-time-in-os-x)
		* [iMessagesBackdoor](https://github.com/checkymander/iMessagesBackdoor)
			* A script to help set up an event handler in order to install a persistent backdoor that can be activated by sending a message. 
	* **Presentations/Talks/Videos**
		* [Userland Persistence On Mac Os X "It Just Works"  -  Shmoocon 2015](http://www.securitytube.net/video/12428?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed:%20SecurityTube%20%28SecurityTube.Net%29)
			* Got root on OSX? Do you want to persist between reboots and have access whenever you need it? You do not need plists, new binaries, scripts, or other easily noticeable techniques. Kext programming and kernel patching can be troublesome! Leverage already running daemon processes to guarantee your access.  As the presentation will show, if given userland administrative access (read: root), how easy it is to persist between reboots without plists, non-native binaries, scripting, and kexts or kernel patching using the Backdoor Factory.
	* **Account Manipulation**
		* **SSH Authorized Keys**
	* **Boot or Logon Autostart Execution**
		* **Authentication Package**
		* **Kernel Modules and Extensions**
		* **Re-opened Applications**
		* **Shortcut Modification**
		* **Port Monitors**
		* **Plist Modification**
	* **Boot or Logon Initialization Scripts**
		* **Logon Script (Mac)**
			* [Adding Login Items - developer.apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLoginItems.html)
			* [Open items automatically when you log in on Mac - developer.apple](https://support.apple.com/en-gb/guide/mac-help/mh15189/mac)
		* **Network Logon Script**
		* **Rc.common**
		* **Startup Items**
		* **Browser Extensions**
	* **Browser Extensions**
	* **Compromise Client Software Binary**
		* **Mail.app**
			* [Using email for persistence on OS X - n00py](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
	* **Create Account**
		* **Local Account**
		* **Domain Account**
		* **Cloud Account**
	* **Create or Modify System Process**
		* **Launch Agent**
		* **Launch Daemon**
	* **Event Triggered Execution**
		* **Change Default File Association**
		* **.bash_profile and .bashrc**
		* **Trap**
		* **LC_LOAD_DYLIB Addition**
		* **Accessibility Features**
		* **Emond**
	* **External Remote Services**
	* **Folder Actions**
		* [Folder Actions for Persistence on macOS - Cody Thomas](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)	
	* **Hijack Execution Flow**
		* **Executable Installer File Permissions Weakness**
		* **Path Interception by Unquoted Path**
		* **Path Interception by PATH Environment Variable**
		* **Path Interception by Search Order Hijacking**
		* **LD_PRELOAD**
		* **Dylib Hijacking**
		* **COR_PROFILER**
		* **Implant Container Image**
	* **Implant Container Image**
	* **Office Application Startup**
	* **Pre-OS Boot**
		* **System Firmware**
		* **Component Firmware**
		* **Bootkit**
	* **Scheduled Task/Job**
		* **Launchd**
		* **Cron**
	* **Traffic Signaling**
		* **Port Knocking**
	* **Valid Accounts**
		* **Default Accounts**
		* **Domain Accounts**
		* **Local Accounts**
		* **Cloud Accounts**
	* **Xcode**
		* [Running and disguising programs through XCode shims on OS X](https://randomtechnicalstuff.blogspot.com.au/2016/05/os-x-and-xcode-doing-it-apple-way.html)
	* **Tools**
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
			* [OSX XPC Revisited - 3rd Party Application Flaws - Tyler Bohan(OffensiveCon2020)](https://www.youtube.com/watch?v=KPzhTqwf0bA&list=PLYvhPWR_XYJmwgLkZbjoEOnf2I1zkylz8&index=8&t=0s)
				* XPC or cross process communication is a way for OSX and iOS processes to communicate with one another and share information. One use for this is to elevate privileges using a daemon who listens as a XPC service. While Apple has released a coding guideline it is all to often ignored or incorrectly implemented in third-party applications. One striking example of this is the Privileged Helper Tool. In this talk I am going to dive into what a Privileged Helper Tool is and why you should care about it. I will show the viewers how to locate these on an OSX computer and walk through the reverse engineering steps needed to identify if the service is vulnerable. We will then set up communications via Objective-C to deliver a privilege escalation attack. I will be showcasing twenty plus vulnerabilities in at least five products. All tooling and code will be released with the talk!
	* **Dylib Hijacking**
		* **Articles/Blogposts/Writeups**
			* [DylibHijack](https://github.com/synack/DylibHijack)
				* python utilities related to dylib hijacking on OS X
		* **Talks/Presentations/Videos**
			* [Gaining Root with Harmless AppStore Apps - Csaba Fitzi](https://www.youtube.com/watch?v=sOtcM-dryF4&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=8)
	    		* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Fitzl.pdf)
			    * This talk is about my journey from trying to find dylib hijacking vulnerability in a particular application to finding a privilege escalation vulnerability in macOS. During the talk I will try to show the research process, how did I moved from one finding to the next and I will also show many of the failures / dead ends I had during the exploit development.First I will briefly cover what is a dylib hijacking, and what is the current state of various application regarding this type of vulnerability. We will see how hard is to exploit these in many cases due to the fact that root access is required. Second I will cover two seemingly harmless bugs affecting the installation process of AppStore apps, and we will see how can we chain these together in order to gain root privileges - for this we will utilise a completely benign app from the macOS App Store. Part of this I will cover how can we submit apps to the store, and what are the difficulties with that process.In the last part I will cover how we can infect and include our malicious file in an App installer without breaking the App’s signature.
			* [Automated Dylib Hijacking - Jimi Sebree(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-11-automated-dylib-hijacking-jimi-sebree)
				* Applications on macOS use a common and flawed method of loading dynamic libraries (dylib), which leaves them vulnerable to a post-exploitation technique known as dylib hijacking. Dylib hijacking is a technique used to exploit this flawed loading method in order to achieve privilege escalation, persistence, or the ability to run arbitrary code. This talk provides an overview of the attack vector and the process involved in exploiting vulnerable applications. Additionally, the process of automating the exploitation of vulnerable applications will be demonstrated and discussed in depth. The tools developed and used for this demonstration will be made publicly available.
		* **Tools**
			* [boko](https://github.com/bashexplode/boko)
				* boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables, as well as scripts an application may use that have the potential to be backdoored. The tool also calls out interesting files and lists them instead of manually browsing the file system for analysis. With the active discovery function, there's no more guess work if an executable is vulnerable to dylib hijacking!
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
	* **Talks/Presentations/Videos**
		* [Bypassing MacOS Detections With Swift - Cedric Owens(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-00-bypassing-macos-detections-with-swift-cedric-owens)
			* This talk is centered around red teaming in MacOS environments. Traditionally, MacOS post exploitation has largely been done in python with a heavy reliance on command line utilities. However, as defender tradecraft continues to evolve with detecting suspicious python usage on MacOS, we (as red teamers) should consider migrating to different post exploitation methods. In this talk, I will share why the Swift language can be beneficial for red teaming macOS environments. I will also share some macOS post exploitation code I have written using the Swift programming language and contrast detection techniques between python and Swift based post exploitation.
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
			* [Fun With Frida - James(2019)](https://web.archive.org/web/20190622025723/https://medium.com/@two06/fun-with-frida-5d0f55dd331a)
	* In this post, we’re going to take a quick look at Frida and use it to steal credentials from KeePass.
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
	* [Mac Quarantine Event Database - menial.co.uk(2011)](http://menial.co.uk/blog/2011/06/16/mac-quarantine-event-database/)
		* After all the fuss surrounding the iPhone location log, you may be interested to know that there is a file on Macs running Snow Leopard or higher that keeps a record of files you've downloaded. This record is not purged when you clear Safari downloads, caches or even reset Safari completely.
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


---------------------------
#### macOS Technologies<a name="osxtech"></a>
* **Code Signing**<a name="osxsign"></a>
	* [macOS Code Signing In Depth](https://developer.apple.com/library/content/technotes/tn2206/_index.html)
	* [Launch Service Keys - `LSFileQuarantineEnabled`](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html#//apple_ref/doc/uid/TP40009250-SW10)
* **Endpoint Security Framework**<a name="osxesf"></a>
	* [EndpointSecurity - developer.apple](https://developer.apple.com/documentation/endpointsecurity)
		* Endpoint Security is a C API for monitoring system events for potentially malicious activity. Your client, which you can write in any language supporting native calls, registers with Endpoint Security to authorize pending events, or receive notifications of events that have already occurred. These events include process executions, mounting file systems, forking processes, and raising signals. Develop your system extension with Endpoint Security and package it in an app that uses the SystemExtensions framework to install and upgrade the extension on the user’s Mac.
* **GateKeeper**<a name="osxgk"></a>
	* [App security overview - support.apple](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/1/web/1)
	* [Protecting against malware - support.apple](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/1/web/1)
	* [Gatekeeper and runtime protection - support.apple](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/1/web/1)
	* [Gatekeeper - Wikipedia](https://en.wikipedia.org/wiki/Gatekeeper_(macOS))
    	* 'macOS includes a technology called Gatekeeper, that's designed to ensure that only trusted software runs on your Mac.'
	* [Safely open apps on your Mac - support.apple](https://support.apple.com/en-us/HT202491)
* **System Integrity Protection**<a name="osxsip"></a>
	* [System Integrity Protection - Wikipedia](https://en.wikipedia.org/wiki/System_Integrity_Protection)
	* [About System Integrity Protection on your Mac - support.apple.com](https://support.apple.com/en-us/HT204899)
	* [Configuring System Integrity Protection - developer.apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html#//apple_ref/doc/uid/TP40016462-CH5-SW1)
* **Transparency, Consent, and Control**<a name="osxtcc"></a>
	* []()
* **XProtect**<a name="osxxprotect"></a>
	* [XProtect Explained: How Your Mac’s Built-in Anti-malware Software Works - Chris Hoffman(2015)](https://www.howtogeek.com/217043/xprotect-explained-how-your-macs-built-in-anti-malware-works/)
	* [How the “antimalware” XProtect for MacOS works and why it detects poorly and badly - ElevenPaths(2019)](https://business.blogthinkbig.com/antimalware-xprotect-macos/)





	


































------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="winpost">Post-Exploitation Windows</a>
* **101**<a name="win101"></a>
	* [Windows CMD Reference - ms](https://www.microsoft.com/en-us/download/details.aspx?id=56846)
* **Unsorted**
	* [Abusing DComposition to render on external windows - yousif(2020)](https://secret.club/2020/05/12/abusing-compositions.html)
		* [Code](https://github.com/thesecretclub/window_hijack)
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
		* [Living Off Windows Land – A New Native File “downldr” - Gal Kristal(2020)](https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/)
		* [Also Node.js has been used to perform a Living off the Land (LotL) attack - Andrea Fortuna(2019)](https://www.andreafortuna.org/2019/10/02/also-node-js-has-been-used-to-perform-a-living-off-the-land-lotl-attack/)
		* [Upload and download small files with CertReq.exe - DTM(2020)](https://dtm.uk/certreq/)
		* [Staying Off the Land: A Threat Actor Methodology - Crowdstrike(2020)](https://www.crowdstrike.com/blog/staying-off-the-land-methodology/)
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
		* [CodeExecutionOnWindows](https://github.com/pwndizzle/CodeExecutionOnWindows)
			* A list of ways to execute code, including examples, are shown below. Note that UAC bypasses and DLL hijacking will not be included as these are covered elsewhere.
	* **LoLBins**
		* **Nuget/Squirrel/Electron**
			* [Squirrel packages’ manager as a lolbin (a.k.a. many Electron apps are lolbins by default) - hexacorn(2019)](http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/)
			* [Nuget/Squirrel uncontrolled endpoints leads to arbitrary code execution - Reegun J](https://medium.com/@reegun/nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-80c9df51cf12)
				* [Part 2](https://medium.com/@reegun/update-nuget-squirrel-uncontrolled-endpoints-leads-to-arbitrary-code-execution-b55295144b56)
		* **Microsoft.Workflow.Compiler.exe**
			* [Arbitrary, Unsigned Code Execution Vector in Microsoft.Workflow.Compiler.exe - Matt Graeber(2018)](https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb)
			* [How to Port Microsoft.Workflow.Compiler.exe Loader to Veil - FortyNorthSecurity(2018)](https://fortynorthsecurity.com/blog/how-to-port-microsoft-workflow-compiler-exe-loader-to-veil/)
		* **MSBuild**
			* **Articles/Blogposts/Writeups**
				* [MSBuild - docs.ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild?view=vs-2019)
				* [MSBuild Inline Tasks - docs.ms](https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks?view=vs-2015)
				* [Understanding the Project File(MSBuild) - docs.ms](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/deployment/web-deployment-in-the-enterprise/understanding-the-project-file)
				* [MSBuild: A Profitable Sidekick! - Sarah Norris](https://www.trustedsec.com/blog/msbuild-a-profitable-sidekick/)
				* [MSBuild without MSBuild - pentestlaboratories(2020)](https://pentestlaboratories.com/2020/01/27/msbuild-without-msbuild/)
					* [...]MSBuild is no longer required to execute code since it is possible to use a .NET assembly that will call the malicious .csproj from a remote location (UNC path). This technique doesn’t leave any artifacts since it doesn’t touch the disk and the code is injected into a legitimate Windows process Internet Explorer. 
				* [Doing More With MSBuild - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-MSBuild-To-Do-More/)
				* [Remotely Host MSBuild Payloads - Joe Leon(2020)](https://fortynorthsecurity.com/blog/remotely-host-msbuild-payloads/)
					* tl;dr Separate your C# payload from a MSBuild XML file and host it remotely on a WebDav server.
				* [Another MSBuild Invocation (February 2020 Edition) - Joe Leon(2020)](https://fortynorthsecurity.com/blog/another-msbuild-bypass-february-2020-edition/)
					* TL;DR: Use MSBuild’s UnregisterAssembly task to execute arbitrary code in a .NET assembly.
			* **Tools**
				* [MSBuildAPICaller](https://github.com/rvrsh3ll/MSBuildAPICaller)
					*  MSBuild Without MSBuild.exe 
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
	* **Command and Scripting Interpreter**
		* **Cmd.exe**
			* **Articles/Blogposts/Writeups**
				* [DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and Detection Techniques - Daniel Bohannon](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)
				* [cmd.exe running any file no matter what extension - Hexacorn](http://www.hexacorn.com/blog/2019/04/21/cmd-exe-running-any-file-no-matter-what-extension/)
			* **Tools**
				* [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
					* Cmd.exe Command Obfuscation Generator & Detection Test Harness
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
	* **Exploitation for Client Execution**
		* **Articles/Blogposts/Writeups**
			* [CVE-2019-0726 - MWRLabs](https://labs.mwrinfosecurity.com/advisories/windows-dhcp-client/)
				* DHCP client rce
			* [Analysis of CVE-2020-0605 – Code Execution using XPS Files in .NET - MDSec(2020)](https://www.mdsec.co.uk/2020/05/analysis-of-cve-2020-0605-code-execution-using-xps-files-in-net/)
				* Microsoft patched a number of deserialisation issues using the XPS files. Although the patch for CVE-2020-0605 was released in January 2020, it was incomplete and an additional update was released in May 2020. The patched issue could be useful to exploit any code that deals with the XPS file using .NET libraries. The identified issues could also be helpful as bridged gadgets when exploiting XAML deserialisation related issue.
	* **Inter-Process Communication**
		* **Component Object Model and Distributed COM**
			* **Articles/Blogposts/Writeups**
				* [Forcing Iexplore.exe to Load a Malicious DLL via COM Abuse - ired.team](https://ired.team/offensive-security/code-execution/forcing-iexplore.exe-to-load-a-malicious-dll-via-com-abuse)
			* **Tools**
		* **DDE**
			* See [Phishing.md](./Phishing.md)
			* **Articles/Blogposts/Writeups**
				* [DDE Downloaders, Excel Abuse, and a PowerShell Backdoor - rinseandREpeat analysis](https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html)
			* **Tools**
	* **Native API**
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [VBA-RunPE](https://github.com/itm4n/VBA-RunPE)
				* A VBA implementation of the RunPE technique or how to bypass application whitelisting.
	* **Scheduled Task/Job**
		* **AT**
		* **Scheduled Task**
	* **Shared Modules**
		* **Tools**
			* [DueDLLigence](https://github.com/fireeye/DueDLLigence)
				* Shellcode runner framework for application whitelisting bypasses and DLL side-loading. The shellcode included in this project spawns calc.exe.
	* **Software Deployment Tools**
	* **System Services**
		* **Service Execution**
			* **Articles/Blogposts/Writeups**
				* [Penetration Testing: Stopping an Unstoppable Windows Service - Scott Sutherland](https://blog.netspi.com/penetration-testing-stopping-an-unstoppable-windows-service/)
	* **Third-Party Software**
		* **Articles/Blogposts/Writeups**
			* [Abusing Firefox in Enterprise Environments - Daniil Vylegzhanin(2020)](https://www.mdsec.co.uk/2020/04/abusing-firefox-in-enterprise-environments/)
				* In this blogpost, we will describe a technique that abuses legacy Firefox functionality to achieve command execution in enterprise environments. The security issue was that the compromised domain user had Full Control rights on the files stored in the GPO, which were then subsequently deployed by SCCM to the Mozilla Firefox installation folder for all computer objects within the OU where the GPO was applied.
		* **Tools**
	* **User Execution**
		* **Malicious Link**
			* **Articles/Blogposts/Writeups**
				* [ClickOnce Security and Deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2015)
				* [ClickOnce (Twice or Thrice): A Technique for Social Engineering and (Un)trusted Command Execution - bohops](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)
				* [Simple Trick For Red Teams - secrary.com](https://secrary.com/Random/RedTeamTrick/)
					* Change from yellow, to blue.
		* **Tools**
		* **Malicious File**
	* **Windows Management Instrumentation**
		* **Articles/Blogposts/Writeups**
			* [WMIC - Take Command-line Control over WMI - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742610(v=technet.10))
			* [WMIC - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/wmic)
			* [Abusing Windows Management  Instrumentation (WMI) to Build a Persistent,  Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
		* **Talks/Presentations/Videos**
			* [Abusing Windows Management Instrumentation (WMI) - Matthew Graeber(BH USA 2015)](https://www.youtube.com/watch?v=0SjMgnGwpq8)
				* Imagine a technology that is built into every Windows operating system going back to Windows 95, runs as System, executes arbitrary code, persists across reboots, and does not drop a single file to disk. Such a thing does exist and it's called Windows Management Instrumentation (WMI). With increased scrutiny from anti-virus and 'next-gen' host endpoints, advanced red teams and attackers already know that the introduction of binaries into a high-security environment is subject to increased scrutiny. WMI enables an attacker practicing a minimalist methodology to blend into their target environment without dropping a single utility to disk. WMI is also unlike other persistence techniques in that rather than executing a payload at a predetermined time, WMI conditionally executes code asynchronously in response to operating system events. This talk will introduce WMI and demonstrate its offensive uses. We will cover what WMI is, how attackers are currently using it in the wild, how to build a full-featured backdoor, and how to detect and prevent these attacks from occurring.
		* **Tools**
	* **Windows Remote Management(WinRM)**
	* **Shellcode Execution & Runners**
		* **Articles/Blogposts/Writeups**
			* [Abusing native Windows functions for shellcode execution - Jeff White(2017)](http://ropgadget.com/posts/abusing_win_functions.html)
				* "I've been doing a lot of analysis on malicious docs (maldocs) lately and, among a popular variant circulating right now, is a technique that I found particularly interesting. Effectively, it abuses native Windows function calls to transfer execution to shellcode that it loads into memory. I thought it was cool in this context, and not something that I was super familiar with, even though I've since learned it's a very old technique, so I set out to do some research in identifying additional functions that could be abused in a similar way and how to leverage them
			* [A Beginner’s Guide to Windows Shellcode Execution Techniques - Carsten Sandker(2019)](https://www.contextis.com/en/blog/a-beginners-guide-to-windows-shellcode-execution-techniques)
				* [Code](https://github.com/csandker/inMemoryShellcode)
				* This blog post is aimed to cover basic techniques of how to execute shellcode within the memory space of a process.
			* [GOing 4 A Run - Leo Pitt(2020)](https://posts.specterops.io/going-4-a-run-eb263838b944)
			* [A Fundamental Tool in the Toolkit: Evasive Shellcode Launchers – Part 1 - Nichoali Wang(2020)](https://www.nagarrosecurity.com/blog/evasive-shellcode-launchers)
		* **Tools**
			* [Go4aRun](https://github.com/D00MFist/Go4aRun)
				* Shellcode runner in GO that incorporates shellcode encryption, remote process injection, block dlls, and spoofed parent process 
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
	* **101**
		* [Windows Userland Persistence Fundamentals - b33f](http://www.fuzzysecurity.com/tutorials/19.html)	
	* **Tactics**
		* [Hiding Registry keys with PSReflect - Brian Reitz](https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353)
		* [Hiding Files by Exploiting Spaces in Windows Paths](http://blakhal0.blogspot.com/2012/08/hiding-files-by-exploiting-spaces-in.html)
	* **Talks/Presentations/Videos**
		* [Evading Autoruns - Kyle Hanslovan, Chris Bisnet(Derbycon2017)](https://www.youtube.com/watch?v=AEmuhCwFL5I&feature=youtu.be)
			* When it comes to offense, maintaining access to your endpoints is key. For defenders, it's equally important to discover these footholds within your network. During this talk, Kyle and Chris will expose several semi-public and private techniques used to evade the most common persistence enumeration tools. Their techniques will explore ways to re-invent the run key, unconventionally abuse search order, and exploit trusted applications. To complement their technical explanations, each bypass will include a live demo and recommendations for detection.
			* [Materials](https://github.com/huntresslabs/evading-autoruns)
		* [Here to stay: Gaining persistency by Abusing Advanced Authentication Mechanisms - Marina Simakov, Igal Gofman](https://www.youtube.com/watch?v=JvormRcth9w)
			* [Slides](https://paper.seebug.org/papers/Security%20Conf/Defcon/2017/DEFCON-25-Marina-Simakov-and-Igal-Gofman-Here-to-stay-Gaining-persistence-by-abusing-auth-mechanisms.pdf)
	* **Tools**
	* **Account Manipulation**
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
	* **Active Directory Specific**
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
			* [Mimikatz 2.0 - Golden Ticket Walkthrough - Ben Lincoln](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html)
		* **Security Support Provider**
			* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760)
		* **SeEnableDelegationPrivilege**
			* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
			* [SeEnableDelegationPrivilege Active Directory Backdoor](https://www.youtube.com/watch?v=OiqaO9RHskU)
		* **SID History**
			* [Sneaky Active Directory Persistence #14: SID History](https://adsecurity.org/?p=1772)
	* **Alternate Data Streams**
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
	* **AMSI Provider**
		* [Antimalware Scan Interface Provider for Persistence - B4rtik(2020)](https://b4rtik.github.io/posts/antimalware-scan-interface-provider-for-persistence/)
	* **APPX/UWP**
		* [Persistence using Universal Windows Platform apps (APPX) - oddvarmoe](https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/)
			* Persistence can be achieved with Appx/UWP apps using the debugger options. This technique will not be visible by Autoruns.
	* **BITS Jobs**
		* **Articles/Blogposts/Writeups**
		 	* [Background Intelligent Transfer Service - docs.ms](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal?redirectedfrom=MSDN)
		 	* [BITSAdmin tool - docs.ms](https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool?redirectedfrom=MSDN)
 				* BITSAdmin is a command-line tool that you can use to create download or upload jobs and monitor their progress.
			* [Temporal Persistence with bitsadmin and schtasks](http://0xthem.blogspot.com/2014/03/t-emporal-persistence-with-and-schtasks.html)
		/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
		* **Talks/Presentations/Videos**
		* **Tools**
	* **Boot or Logon Autostart Execution**
		* [Windows Startup Application Database](http://www.pacs-portal.co.uk/startup_content.php)
		* [Windows Program Automatic Startup Locations(2004) BleepingComputer](https://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)
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
	* **Boot or Logon Initialization Scripts**
		* **Browser Extensions**
		* **Logon Script (Mac)**
		* **Logon Script (Windows)**
		* **Network Logon Script**
		* **Rc.common**
		* **Startup Items**
	* **Compromise Client Software Binary**
		* **Articles/Blogposts/Writeups**
			* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence - bohops](https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/)
			* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence (Part 2) - bohops](https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/)
		* **Application Plugins**
			* [Backdooring Plugins - Averagejoe](https://www.gironsec.com/blog/2018/03/backdooring-plugins/)
	* **Create Account**
		* **Local Account**
		* **Domain Account**
		* **Cloud Account**
	* **Create or Modify System Process**
		* **Launch Agent**
		* **Systemd Service**
		* **Windows Service**
		* **Launch Daemon**	
	* **Drivers**
		* [Windows Firewall Hook Enumeration](https://www.nccgroup.com/en/blog/2015/01/windows-firewall-hook-enumeration/)
			* We’re going to look in detail at Microsoft Windows Firewall Hook drivers from Windows 2000, XP and 2003. This functionality was leveraged by the Derusbi family of malicious code to implement port-knocking like functionality. We’re going to discuss the problem we faced, the required reverse engineering to understand how these hooks could be identified and finally how the enumeration tool was developed.
	* **Event Triggered Execution**
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
			* [Windows Persistence using Application Shimming - Kavish Tyagi(2020)](https://www.hackingarticles.in/windows-persistence-using-application-shimming/)
			* [Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)
			* [Shimming for Post Exploitation(blog)](http://www.sdb.tools/)
			* [Demystifying Shims – or – Using the App Compat Toolkit to make your old stuff work with your new stuff](https://web.archive.org/web/20170910104808/https://blogs.technet.microsoft.com/askperf/2011/06/17/demystifying-shims-or-using-the-app-compat-toolkit-to-make-your-old-stuff-work-with-your-new-stuff/)
			* [Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)
			* [Shim Database Talks](http://sdb.tools/talks.html)
			* [Using Application Compatibility Shims](https://web.archive.org/web/20170815050734/http://subt0x10.blogspot.com/2017/05/using-application-compatibility-shims.html)
			* [Persistence via Shims - liberty-shell](https://liberty-shell.com/sec/2020/02/25/shim-persistence/)
		* **Change Default File Association**
			* [Registering an Application to a URI Scheme - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa767914(v=vs.85)?redirectedfrom=MSDN)
			* [Exploiting custom protocol handlers in Windows - Andrey Polkovnychenko](https://www.vdoo.com/blog/exploiting-custom-protocol-handlers-in-windows)
				* In this article we would like to present the mechanism for custom protocol handling in Windows, and how it can be exploited using a simple command injection vulnerability.
		* **Component Object Model Hijacking**
			* [COM Object hijacking: the discreet way of persistence](https://blog.gdatasoftware.com/blog/article/com-object-hijacking-the-discreet-way-of-persistence.html)
			* [Userland Persistence with Scheduled Tasks and COM Handler Hijacking](https://enigma0x3.net/2016/05/25)
			* [How To Hunt: Detecting Persistence & Evasion With The COM - Blake Strom](https://www.endgame.com/blog/technical-blog/how-hunt-detecting-persistence-evasion-com)
			* [Persistence: “the continued or prolonged existence of something”: Part 2 – COM Hijacking - MDSec](https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-2-com-hijacking/)
			* [Use COM Object hijacking to maintain persistence——Hijack CAccPropServicesClass and MMDeviceEnumerator - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-CAccPropServicesClass-and-MMDeviceEnumerator/)
			* [Use COM Object hijacking to maintain persistence——Hijack explorer.exe - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-explorer.exe/)
			* [Activation Contexts — A Love Story - Philip Tsukerman(2019)](https://medium.com/philip-tsukerman/activation-contexts-a-love-story-5f57f82bccd)
				* TL;DR — Windows loads a version of the Microsoft.Windows.SystemCompatible assembly manifest into every process. Tampering with it lets you inject DLL side-loading opportunities into every process, and to perform COM hijacking without touching the registry. Unfortunately, the manifest could be replaced by another version, possibly killing your persistence by surprise.
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
	* **External Remote Services**
	* **Filesystem**
		* **NTFS**
			* [Pentester’s Windows NTFS Tricks Collection - Rene Freingruber](https://sec-consult.com/en/blog/2018/06/pentesters-windows-ntfs-tricks-collection/)
	* **Hijack Execution Flow**
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
	* **Implant Container Image**
	* **MS Distributed Transaction Coordinator Service**
		* **Articles/Blogposts/Writeups**
			* [Distributed Transaction Coordinator - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms684146(v=vs.85))
			* [The Microsoft Distributed Transaction Coordinator service must run under the NT AUTHORITY\NetworkService Windows account - support.ms](https://support.microsoft.com/en-us/help/903944/the-microsoft-distributed-transaction-coordinator-service-must-run-und)
			* [Shadow Force Uses DLL Hijacking, Targets South Korean Company - Dove Chiu(2015)](https://blog.trendmicro.com/trendlabs-security-intelligence/shadow-force-uses-dll-hijacking-targets-south-korean-company/)
			* [Use msdtc to maintain persistence - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-msdtc-to-maintain-persistence/)
	* **LAPS**
		* **Articles/Blogposts/Writeups**
			* [Mise en place d'une Backdoor LAPS via modification de l'attribut SearchFlags avec DCShadow - Gregory Lucand](https://adds-security.blogspot.com/2018/08/mise-en-place-dune-backdoor-laps-via.html)
			* [Adding a Backdoor to AD in 400 Milliseconds - David Rowe](https://www.secframe.com/blog/persistence-in-400-milliseconds)
			* [LAPS - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/域渗透-利用SYSVOL还原组策略中保存的密码/)
			* [LAPS - liuhaihua](http://www.liuhaihua.cn/archives/179102.html)
	* **Library Files**
		* **101**
			* [Windows libraries - docs.ms](https://docs.microsoft.com/en-us/windows/client-management/windows-libraries)
				* Libraries are virtual containers for users’ content. A library can contain files and folders stored on the local computer or in a remote storage location. In Windows Explorer, users interact with libraries in ways similar to how they would interact with other folders. Libraries are built upon the legacy known folders (such as My Documents, My Pictures, and My Music) that users are familiar with, and these known folders are automatically included in the default libraries and set as the default save location.
		* **Articles/Blogposts/Writeups**
			* [Windows Library Files (.library-ms) - Vault7 Leaks](https://wikileaks.org/ciav7p1/cms/page_13763381.html)
			* [Abusing Windows Library Files for Persistence - F-Secure](https://blog.f-secure.com/abusing-windows-library-files-for-persistence/)
	* **.NET**
		* **Articles/Blogposts/Writeups**
			* [Common Language Runtime Hook for Persistence - Paul Laine](https://www.contextis.com/en/blog/common-language-runtime-hook-for-persistence)
				* This blog post explains how it is possible to execute arbitrary code and maintain access to a Microsoft Windows system by leveraging the Common Language Runtime application domain manager.
			* [CLR-Persistence](https://github.com/3gstudent/CLR-Injection)
				* Use CLR to inject all the .NET apps
			* [Using CLR to maintain Persistence](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-maintain-persistence/)
			* [Common Language Runtime Hook for Persistence - Paul Laine](https://www.contextis.com/en/blog/common-language-runtime-hook-for-persistence#When:10:30:00Z)
			* [SharPersist: Windows Persistence Toolkit in C# - Brett Hawkins](https://www.fireeye.com/blog/threat-research/2019/09/sharpersist-windows-persistence-toolkit.html)
		* **Tools**
			* [SharPersist](https://github.com/fireeye/SharPersist)
				* Windows persistence toolkit written in C#
		* **AppDomain**
			* [Use AppDomainManager to maintain persistence](https://3gstudent.github.io/3gstudent.github.io/Use-AppDomainManager-to-maintain-persistence/)
	* **Netsh Helper DLL**
		* [Persistence – Netsh Helper DLL - NetbiosX](https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/)
	* **Office Applications**
		* **Articles/Blogposts/Writeups**
			* [Use Office to maintain persistence - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/)
			* [Office Persistence on x64 operating system - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/Office-Persistence-on-x64-operating-system/)
			* [Persistence: “the continued or prolonged existence of something” - Dominic Chell](https://medium.com/@dmchell/persistence-the-continued-or-prolonged-existence-of-something-e29ea63e5c9a)
		* **Add-ins**
			* [Add-In Opportunities for Office Persistence - William Knowles](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
		* **Extensibility Features**
			* [Persisting with Microsoft Office: Abusing Extensibility Options - William Knowles](https://labs.mwrinfosecurity.com/assets/BlogFiles/WilliamKnowles-MWR-44con-PersistingWithMicrosoftOffice.pdf)
		* **Office Template Macros**
			* [One Template To Rule 'Em All - Kostas Lintovois](https://labs.f-secure.com/archive/one-template-to-rule-em-all/)
				* Introduction of wePWNize
		* **Outlook Forms**
		* **Outlook Rules**
		* **Outlook Home Page**
		* **Office Test**
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
	* **Pre-OS Boot**
		* **System Firmware**
		* **Component Firmware**
		* **Bootkit**
	* **Registry**
		* [Windows Registry Attacks: Knowledge Is the Best Defense](https://www.redcanary.com/blog/windows-registry-attacks-threat-detection/)
		* [Windows Registry Persistence, Part 1: Introduction, Attack Phases and Windows Services](http://blog.cylance.com/windows-registry-persistence-part-1-introduction-attack-phases-and-windows-services)
		* [Windows Registry Persistence, Part 2: The Run Keys and Search-Order](http://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order)
		* [List of autorun keys / malware persistence Windows registry entries](https://www.peerlyst.com/posts/list-of-autorun-keys-malware-persistence-windows-registry-entries-benjamin-infosec)
		* [How to Evade Detection: Hiding in the Registry - David Lu](https://www.tripwire.com/state-of-security/mitre-framework/evade-detection-hiding-registry/)
		* [Persistence – Registry Run Keys - NetbiosX](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/)
		* [InvisiblePersistence](https://github.com/ewhitehats/InvisiblePersistence)
			* Persisting in the Windows registry "invisibly". Whitepaper and POC
	* **Scheduled Task/Job**
		* **At (Windows)**
			* [Userland Persistence with Scheduled Tasks and COM Handler Hijacking - enigma0x3](https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
		* **Scheduled Task**
			* [Sc](https://technet.microsoft.com/en-us/library/cc754599.aspx)
				* Communicates with the Service Controller and installed services. The SC.exe program provides capabilities similar to those provided in Services in the Control Panel.
			* [schtasks](https://technet.microsoft.com/en-us/library/cc725744.aspx)
			* [Script Task](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task)
				* Persistence Via MSSQL
		
		* **At (Linux)**
		* **Launchd**
		* **Cron**
	* **ScreenSaver**
		* [Persistence – Screensaver - NetbiosX](https://pentestlab.blog/2019/10/09/persistence-screensaver/)	
	* **Services**
			* [Stealthier persistence using new services purposely vulnerable to path interception - Christophe Tafani-Dereeper](https://blog.christophetd.fr/stealthier-persistence-using-new-services-purposely-vulnerable-to-path-interception/)
			* [Persistence – New Service - NetbiosX](https://pentestlab.blog/2019/10/07/persistence-new-service/)
	* **Server Software Component**
		* **IIS**
			* [IIS Raid – Backdooring IIS Using Native Modules - MDSec](https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/)
		* **MS-SQL Server**
			* [Maintaining Persistence via SQL Server – Part 1: Startup Stored Procedures - NETSPI](https://blog.netspi.com/sql-server-persistence-part-1-startup-stored-procedures/)
			* [Script Task - doc.ms](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task?redirectedfrom=MSDN&view=sql-server-2017)
		* **SQL Stored Procedures**
		* **Transport Agent**
		* **Web Shell**
	* **Third-Party Programs**
		* [Persistence with KeePass - Part 1 - James](https://web.archive.org/web/20190816125156/https://medium.com/@two06/persistence-with-keepass-part-1-d2e705326aa6)	
	* **Traffic Signaling**
		* **Port Knocking**
	* **Valid Accounts**
		* **Default Accounts**
		* **Domain Accounts**
		* **Local Accounts**
		* **Cloud Accounts**
	* **VisualStudio**
		* [Using Visual Studio Code Extensions for Persistence - Charley Célice(2020)](https://medium.com/secarmalabs/using-visual-studio-code-extensions-for-persistence-a65c940b7ea6)
	* **WaitFor**
		* [waitfor - docs.ms](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/waitfor)
		* [Persistence – WaitFor - NetbiosX(2020)](https://pentestlab.blog/2020/02/04/persistence-waitfor/)
			* "Waitfor is a Microsoft binary which is typically used to synchronize computers across a network by sending signals. This communication mechanism can be used in a red team operation in order to download and execution arbitrary code and for persistence. The binary is stored in C:\Windows\System32 folder which means that local administrator privileges are required to perform this activity and both hosts (sender and receiver) needs to be on the same network segment. "
	* **WMI**
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
		* **DLL Stuff** <a name="dllstuff"></a>
			* [Creating a Windows DLL with Visual Basic](http://www.windowsdevcenter.com/pub/a/windows/2005/04/26/create_dll.html)
			* [Calling DLL Functions from Visual Basic Applications - msdn](https://msdn.microsoft.com/en-us/library/dt232c9t.aspx)
			* **DLL Hijacking/Plant**
				* **101**
					* [Dynamic-Link Library Search Order - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/Dlls/dynamic-link-library-search-order)
					* [Dynamic-Link Library Hijacking](https://www.exploit-db.com/docs/31687.pdf)
					* [Crash Course in DLL Hijacking](https://blog.fortinet.com/2015/12/10/a-crash-course-in-dll-hijacking)
					* [VB.NET Tutorial - Create a DLL / Class Library](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)
					* [Exploiting DLL Hijacking by DLL Proxying Super Easily](https://github.com/tothi/dll-hijack-by-proxying)
						* This is a tutorial about exploiting DLL Hijack vulnerability without crashing the application. The method used is called DLL Proxying.
					* [Hijacking DLLs in Windows - Wietze(2020)](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)
						* DLL Hijacking is a popular technique for executing malicious payloads. This post lists nearly 300 executables vulnerable to relative path DLL Hijacking on Windows 10 (1909), and shows how with a few lines of VBScript some of the DLL hijacks can be executed with elevated privileges, bypassing UAC.
				* **Articles/Blogposts/Writeups**
					* [Adaptive DLL Hijacking - Nick Landers](https://silentbreaksecurity.com/adaptive-dll-hijacking/)
					* [Windows 10 - Task Scheduler service - Privilege Escalation/Persistence through DLL planting - remoteawesomethoughts.blogspot](https://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html)
					* [DLL Hijacking via URL files - InsertScript](https://insert-script.blogspot.com/2018/05/dll-hijacking-via-url-files.html)
					* [DLL Hijacking - pentestlab.blog(2017)](https://pentestlab.blog/2017/03/27/dll-hijacking/)
					* [Understanding how DLL Hijacking works - Astr0baby(2018)](https://astr0baby.wordpress.com/2018/09/08/understanding-how-dll-hijacking-works/)
					* [DLL Hijacking - libertyshell.com(2019)](https://liberty-shell.com/sec/2019/03/12/dll-hijacking/)
					* [Understanding how DLL Hijacking works - Astr0baby(2018)](https://astr0baby.wordpress.com/2018/09/08/understanding-how-dll-hijacking-works/)
					* [Lateral Movement — SCM and DLL Hijacking Primer - Dwight Hohnstein(2019)](https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992)
					* [Automating DLL Hijack Discovery - Justin Bui(2020)](https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0)
					* [UAC bypass through Trusted Folder abuse - Jean Maes(2020)](https://redteamer.tips/uac-bypass-through-trusted-folder-abuse/)
					* [Windows 10 - Task Scheduler service - Privilege Escalation/Persistence through DLL planting - remoteawesomethoughts.blogspot](https://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html)
						* I was recently busy doing some reverse on an antivirus solution. During this review, I figured out the Windows 10 Task Scheduler service was looking for a missing DLL exposing it to DLL hijacking/planting. It opens for persistence and privilege escalation in case one can write a rogue DLL in a folder pointed by the PATH environment variable. It can also be used as a UAC bypass.
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
			* **DLL Tools**
				* [rattler](https://github.com/sensepost/rattler)
					* Rattler is a tool that automates the identification of DLL's which can be used for DLL preloading attacks.
				* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings)
					* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
				* [Pazuzu](https://github.com/BorjaMerino/Pazuzu)
					* Pazuzu is a Python script that allows you to embed a binary within a precompiled DLL which uses reflective DLL injection. The goal is that you can run your own binary directly from memory. This can be useful in various scenarios.	
				* [Bleak](https://github.com/Akaion/Bleak)
					* A Windows native DLL injection library written in C# that supports several methods of injection.
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
				* [CVE-2020-0796 Windows SMBv3 LPE Exploit POC Analysis - Sung Lin(2020)](https://paper.seebug.org/1165/)
				* [Exploiting SMBGhost (CVE-2020-0796) for a Local Privilege Escalation: Writeup + POC - Zecops(2020)](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/)
				* [CVE-2020-0796 | Windows SMBv3 Client/Server Remote Code Execution Vulnerability - portal.msrc](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796)
				* [I'm SMBGhost, daba dee daba da - Lucas Georges(2020)](https://www.synacktiv.com/en/publications/im-smbghost-daba-dee-daba-da.html)
				* [CVE-2020-0796 Memory Corruption Vulnerability in Windows 10 SMB Server - Yije Wang(2020)](https://www.fortinet.com/blog/threat-research/cve-2020-0796-memory-corruption-vulnerability-in-windows-10-smb-server#.Xndfn0lv150.twitter)
				* [SMBGhost – Analysis of CVE-2020-0796 - Eoin Carroll, Philippe Laulheret, Kevin McGrath, Steve Povolny(2020)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/smbghost-analysis-of-cve-2020-0796/)
				* [微软SMBv3客户端/服务端远程代码执行漏洞（CVE-2020-0796）技术分析](https://blogs.360.cn/post/CVE-2020-0796.html)
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
			* **Articles/Blogposts/Writeups**
				* [Ask and ye shall receive - Impersonating everyday applications for profit - FoxIT](https://www.fox-it.com/en/insights/blogs/blog/phishing-ask-and-ye-shall-receive/)
				* [Phishing for Credentials: If you want it, just ask! - enigma0x3](http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
				* [Phishing Windows Credentials - NetbiosX](https://pentestlab.blog/2020/03/02/phishing-windows-credentials/)
				* [Credentials Collection via CredUIPromptForCredentials - @spottheplanet](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/credentials-collection-via-creduipromptforcredentials)
				* [ICU: A Red Teamer’s Hail Mary - Jean Maes](https://redteamer.tips/icu-a-red-teamers-hail-mary/)
					* [Code](https://github.com/WingsOfDoom/ICU)
			* **Tools**
				* [Invoke-CredentialPhisher](https://github.com/fox-it/Invoke-CredentialPhisher)
					* The first one is a powershell script to send toast notifications on behalf on an (installed) application or the computer itself. The user will be asked to supply credentials once they click on the notification toast. The second one is a Cobalt Strike module to launch the phishing attack on connected beacons.
		* **Logic Bugs**
			* [Introduction to Logical Privilege Escalation on Windows - James Forshaw](https://conference.hitb.org/hitbsecconf2017ams/materials/D2T3%20-%20James%20Forshaw%20-%20Introduction%20to%20Logical%20Privilege%20Escalation%20on%20Windows.pdf)
			* [Windows Logical EoP Workbook](https://docs.google.com/document/d/1qujIzDmFrcFCBeIgMjWDZTLNMCAHChAnKDkHdWYEomM/edit)	
			* [Abusing Token Privileges For EoP](https://github.com/hatRiot/token-priv)
				* This repository contains all code and a Phrack-style paper on research into abusing token privileges for escalation of privilege. Please feel free to ping us with questions, ideas, insults, or bugs.				
			* [awesome_windows_logical_bugs](https://github.com/sailay1996/awesome_windows_logical_bugs)
		* **Named Pipes**
			* [Discovering and Exploiting Named Pipe Security Flaws for Fun and Profit - Blake Watts(2002)](http://www.blakewatts.com/namedpipepaper.html)
			* [Named Pipe Filename Local Privilege Escalation - Securiteam(2003)](https://securiteam.com/windowsntfocus/5bp012kaki/)
			* [Windows Named Pipes & Impersonation - decoder.cloud(2019)](https://decoder.cloud/2019/03/06/windows-named-pipes-impersonation/)
			* [Windows NamedPipes 101 + Privilege Escalation - @spottheplanet](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
			* [Part I: The Fundamentals of Windows Named Pipes - Robert Hawes](https://versprite.com/blog/security-research/microsoft-windows-pipes-intro/)
			* [Part II: Analysis of a Vulnerable Microsoft Windows Named Pipe Application - Robert Hawes](https://versprite.com/blog/security-research/vulnerable-named-pipe-application/)
		* **Privileged File Operation Abuse**
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
				* [From directory deletion to SYSTEM shell - Jonas L(2020)](https://secret.club/2020/04/23/directory-deletion-shell.html)
			* **Talks/Presentations/Videos**
				* [Abusing privileged file operations - Clément Lavoillotte(Troopers19)](https://www.youtube.com/watch?v=xQKtdMO5FuE)
					* [Slides](https://troopers.de/downloads/troopers19/TROOPERS19_AD_Abusing_privileged_file_operations.pdf)
			* **Tools**
				* [UsoDllLoader](https://github.com/itm4n/UsoDllLoader)
					* This PoC shows a technique that can be used to weaponize privileged file write vulnerabilities on Windows. It provides an alternative to the DiagHub DLL loading "exploit" found by James Forshaw (a.k.a. @tiraniddo), which was fixed by Microsoft starting from build version 1903.
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
		* **Privilege Abuse**
			* [Priv2Admin](https://github.com/gtworek/Priv2Admin)
				* Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS. 
		* **Privileged File Operations**
			* **101**
				* [An introduction to privileged file operation abuse on Windows - @clavoillotte(2019)](https://offsec.almond.consulting/intro-to-file-operation-abuse-on-Windows.html)
					* TL;DR This is a (bit long) introduction on how to abuse file operations performed by privileged processes on Windows for local privilege escalation (user to admin/system), and a presentation of available techniques, tools and procedures to exploit these types of bugs.
			* **Articles/Blogposts/Writeups**
				* [CVE-2020–1088 — Yet another arbitrary delete EoP - Søren Fritzbøger(2020)](https://medium.com/csis-techblog/cve-2020-1088-yet-another-arbitrary-delete-eop-a00b97d8c3e2)
		* **Registry Paths/Permissions**
			* [Insecure Registry Permissions - NetbiosX](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
			* [RegSLScan](https://github.com/Dankirk/RegSLScan)
				* This tool scans registery keys under Local Machine (HKLM) and lists out any keys non-admins have access to create symbolic links in.
		* **Services**
			* [The power of backup operators - decoder.cloud](https://decoder.cloud/2018/02/12/the-power-of-backup-operatos/)
				* [Associated Code](https://github.com/decoder-it/BadBackupOperator)
			* [Unquoted Service Path - NetbiosX](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
		* **Service Abuse**
			* **Articles/Blogposts/Writeups**
				* [Give Me Back My Privileges! Please? - itm4n(2019)](https://itm4n.github.io/localservice-privileges/)
			* **Tools**
				* [FullPowers](https://github.com/itm4n/FullPowers)
					* FullPowers is a Proof-of-Concept tool I made for automatically recovering the default privilege set of a service account including SeAssignPrimaryToken and SeImpersonate.
		* **Unquoted Service Paths**
			* **Articles/Blogposts/Writeups**
			* **Tools**
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
			* [DisplayLink USB Graphics Software arbitrary file write Elevation of Privilege - Yannick Méheut(2020)](https://offsec.almond.consulting/displaylink-usb-graphics-arbitrary-file-write-eop.html)
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
		* [[CVE49] Microsoft Windows LNK Remote Code Execution Vulnerability - CVE-2020-1299 - linhlhq from Infiniti Team - VinCSS](https://movaxbx.ru/2020/06/26/microsoft-windows-lnk-remote-code-execution-vulnerability-cve-2020-1299/)
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
		* [Evading Autoruns - Kyle Hanslovan, Chris Bisnett(DerbyCon7)](https://www.youtube.com/watch?v=AEmuhCwFL5I&app=desktop)
			* When it comes to offense, maintaining access to your endpoints is key. For defenders, it's equally important to discover these footholds within your network. During this talk, Kyle and Chris expose several semi-public and private techniques used to evade the most common persistence enumeration tools. Their techniques will explore ways to re-invent the run key, unconventionally abuse search order, and exploit trusted applications. To complement their technical explanations, each bypass includes a live demo and recommendations for detection.
			* [RE: Evading Autoruns PoCs on Windows 10 - Kyle Hanslovan](https://medium.com/@KyleHanslovan/re-evading-autoruns-pocs-on-windows-10-dd810d7e8a3f)
			* [Evading Autoruns - DerbyCon 7.0](https://github.com/huntresslabs/evading-autoruns)
	* **AMSI**<a name="amsi"></a>
		* **101**
			* [AMSI Bypass - Paul Laine](https://www.contextis.com/en/blog/amsi-bypass)
			* [Exploring PowerShell AMSI and Logging Evasion - Adam Chester](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
			* [Developer audience, and sample code - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/dev-audience)
			* [Antimalware Scan Interface (AMSI) functions - docs.ms](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-functions)
			* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - Nikhil Mittal(BHUS16)](https://www.youtube.com/watch?v=7A_rgu3kbvw)
				* [Blogpost](http://www.labofapenetrationtester.com/2016/09/amsi.html)
				* [Paper](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
				* In Windows 10, Microsoft introduced the AntiMalware Scan Interface (AMSI) which is designed to target script-based attacks and malware. Script-based attacks have been lethal for enterprise security and with advent of PowerShell, such attacks have become increasingly common. AMSI targets malicious scripts written in PowerShell, VBScript, JScript etc. and drastically improves detection and blocking rate of malicious scripts. When a piece of code is submitted for execution to the scripting host, AMSI steps in and the code is scanned for malicious content. What makes AMSI effective is, no matter how obfuscated the code is, it needs to be presented to the script host in clear text and unobfuscated. Moreover, since the code is submitted to AMSI just before execution, it doesn't matter if the code came from disk, memory or was entered interactively. AMSI is an open interface and MS says any application will be able to call its APIs. Currently, Windows Defender uses it on Windows 10. Has Microsoft finally killed script-based attacks? What are the ways out? The talk will be full of live demonstrations.
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
			* [Resurrecting an old AMSI Bypass - Philippe Vogler(2020)](https://sensepost.com/blog/2020/resurrecting-an-old-amsi-bypass/)
				* Before the latest Windows Defender update, and possibly with other endpoint security products, regardless of access rights on a host, users can bypass AMSI for PowerShell. Other scripting engines such as jscript or cscript do not suffer from this DLL hijack and directly load AMSI from the System32 folder.
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
				* [Ultimate AppLocker ByPass List](https://github.com/api0cradle/UltimateAppLockerByPassList)
					* "The goal of this repository is to document the most common and known techniques to bypass AppLocker. Since AppLocker can be configured in different ways I maintain a verified list of bypasses (that works against the default AppLocker rules) and a list with possible bypass technique (depending on configuration) or claimed to be a bypass by someone. I also have a list of generic bypass techniques as well as a legacy list of methods to execute through DLLs."
				* [myAPPLockerBypassSummary](https://github.com/0xVIC/myAPPLockerBypassSummary)
					* Simple APPLocker bypass summary based on the extensive work of @api0cradle
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
				* [Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies - sixdub(2014)](https://www.sixdub.net/?p=367)
				* [AppLocker Bypass – File Extensions - pentestlab.blog(2017)](https://pentestlab.blog/2017/06/12/applocker-bypass-file-extensions/)
					* Bypassing AppLocker restrictions usually requires the use of trusted Microsoft binaries that can execute code or weak path rules. However it is possible in a system that it has been configured with default rules and it is allowing the use of command prompt and PowerShell to the users to bypass AppLocker by using payloads with different file extensions.
				* [Bring your own .NET Core Garbage Collector - Paul Laine(2020)](https://www.contextis.com/en/blog/bring-your-own-.net-core-garbage-collector)
					* This blog post explains how it is possible to abuse a legitimate feature of .Net Core, and exploit a directory traversal bug to achieve application whitelisting bypass.
					* [Code](https://github.com/am0nsec/MCGC)
				* [Abusing .NET Core – Evasion - pentestlaboratories.com](https://pentestlaboratories.com/2020/06/23/abusing-net-core-application-whitelisting/)
			* **Tools**
				* [Backdoor-Minimalist.sct](https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302)
					* Applocker bypass
	* **Defender**<a name="defender"></a>
		* **101**
			* [Next-generation protection in Windows 10, Windows Server 2016, and Windows Server 2019 - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/microsoft-defender-antivirus-in-windows-10)
			* [Microsoft Defender Advanced Threat Protection - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/microsoft-defender-advanced-threat-protection)
			* [Microsoft Defender ATP Blog - Microsoft](https://techcommunity.microsoft.com/t5/microsoft-defender-atp/bg-p/MicrosoftDefenderATPBlog)
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
			* [Auditing and Bypassing Windows Defender Application Control - Matt Graeber](https://www.youtube.com/watch?v=GU5OS7UN8nY)
			* [Bypass Windows Exploit Guard ASR - Emeric Nasi(OffensiveCon2020)](https://www.youtube.com/watch?v=YMHsuu3qldE&list=PLYvhPWR_XYJmwgLkZbjoEOnf2I1zkylz8&index=16&t=0s)
				* How to bypass all Microsoft latest "Attack Surface Reduction" rules with malicious Office documents and scripts. The last years, I have been doing some research around Windows security. I liked exploring APT/Redteam techniques and payload used for social engineering and airgap bypass attacks. I am naturally interested into new security features such as ASR. Microsoft introduced Attack Surface Reduction (ASR) as part of Windows defender exploit guard. ASR is composed of a set of configurable rules such as: "Block Office applications from creating child process". While these rules seem effective against common Office and scripts malwares, there are ways to bypass all of them. We will go over each rule related to malicious Office or VB scripts behavior, analyze how It work behind the scene and find a way to bypass it. As example we will take common attack scenario and see how they can be achieved with all rules enforced: Download execute DLL/EXE/script from Office/VBscript; Drop execute embedded DLL/EXE/script from Office/VBscript; Machine takeover with Meterpreter shell from Office/VBscript; Lateral movement/UAC bypass/AMSI bypass/etc.
		* **Tools**
	 		* [Windows Defender Emulator Tools](https://github.com/0xAlexei/WindowsDefenderTools)
				* Tools for instrumenting Windows Defender's mpengine.dll
				* [Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf)
				* [Video](https://www.youtube.com/watch?v=xbu0ARqmZDc)
			* [ExpandDefenderSig.ps1](https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866)
				* Decompresses Windows Defender AV signatures for exploration purposes
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
			* [CQLabs – How UAC bypass methods really work - Adrian Denkiewicz(2020)](https://cqureacademy.com/cqure-labs/cqlabs-how-uac-bypass-methods-really-work-by-adrian-denkiewicz)
				* In this article, we will analyze a couple of knowns, still working, UAC bypasses – how they work, what are the requirements, and potential mitigation techniques. Before we dive into this, we need to briefly explain what UAC is.
			* [Testing UAC on Windows 10 - Ernesto Fernandez](https://www.researchgate.net/publication/319454675_Testing_UAC_on_Windows_10)
				* User Account Control (UAC) is a mechanism implemented in Windows systems from Vista to prevent malicious software from executing with administrative privileges without user consent. However, this mechanism does not provide a secure solution to that problem, since can be easily bypassed in some ways, something we will show by means of different methods such as DLL hijacking, token impersonation or COM interface elevation, also we will show a new method which we have developed based on a previous one. Moreover, this new Proof of Concept has been ported to the Metasploit Framework as a new module, which indeed is the only UAC bypass module that works in the latest Windows 10 build version.
			* [Reading Your Way Around UAC (Part 1)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-1.html)
				* [Reading Your Way Around UAC (Part 2)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-2.html)
				* [Reading Your Way Around UAC (Part 3)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-3.html)
			* [Testing User Account Control (UAC) on  Windows 10 - Ernesto Fernández Provecho](https://www.researchgate.net/publication/319454675_Testing_UAC_on_Windows_10)
			* [More Than a Penetration Test (Microsoft Windows CVE-2019–1082) - Michal Bazyli](https://medium.com/@bazyli.michal/more-than-a-penetration-test-cve-2019-1082-647ba2e59034)	
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
			* [User Account Control & odbcad32.exe - secureyourit.co.uk](https://secureyourit.co.uk/wp/2019/09/18/user-account-control-odbcad32-exe/)
			* [Fileless_UAC_bypass_WSReset](https://github.com/sailay1996/Fileless_UAC_bypass_WSReset)
			* [UAC Bypass or a Story of Three Elevations - xi-tauw(2017)](https://amonitoring.ru/article/uac_bypass_english/)
			* [UAC bypass through Trusted Folder abuse - Jean Maes(2020)](https://redteamer.tips/uac-bypass-through-trusted-folder-abuse/)
		* **Talks & Presentations**
			* [Not a Security Boundary: Bypassing User Account Control - Matt Nelson(Derbycon7)](https://www.youtube.com/watch?v=c8LgqtATAnE&index=21&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
		* **Tools**
			* [UACME](https://github.com/hfiref0x/UACME)
				* Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
			* [DccwBypassUAC](https://github.com/L3cr0f/DccwBypassUAC)
				* This exploit abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. It supports "x86" and "x64" architectures. Moreover, it has been successfully tested on Windows 8.1 9600, Windows 10 14393, Windows 10 15031 and Windows 10 15062.
			* [Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
				* Bypass-UAC provides a framework to perform UAC bypasses based on auto elevating IFileOperation COM object method calls. This is not a new technique, traditionally, this is accomplished by injecting a DLL into "explorer.exe". This is not desirable because injecting into explorer may trigger security alerts and working with unmanaged DLL's makes for an inflexible work-flow. To get around this, Bypass-UAC implements a function which rewrites PowerShell's PEB to give it the appearance of "explorer.exe". This provides the same effect because COM objects exclusively rely on Windows's Process Status API (PSAPI) which reads the process PEB.
* **Credential Access**<a name="wincredac"></a>
	* **101**
		* [An Overview of KB2871997 - msrc-blog.ms](https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/)
			* Increasing complexity of retrieving clear-text creds
		* [Cached and Stored Credentials Technical Overview - docs.ms(2016)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11))
			* Applies To: Windows Vista, Windows Server 2008, Windows 7, Windows 8.1, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2012, Windows 8
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
		* [Extracting credentials from a remote Windows system - Living off the Land - bitsadmin.in(2020)](https://bitsadm.in/blog/extracting-credentials-from-remote-windows-system)
		* [SecretsDump Demystified - Mike Benich(2020)](https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b)
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
	* **DPAPI**
		* [TBAL: an (accidental?) DPAPI Backdoor for local users a.k.a how a convenience feature undermined a security feature - vztekoverflow(2018)](http://vztekoverflow.com/2018/07/31/tbal-dpapi-backdoor/)
			* In this article, we have demonstrated that in some scenarios, the default Windows configuration leads to the SHA‑1 hash of the user’s password being stored to the disk in a way that is retrievable without any further knowledge about the password. We argue that this is an issue for DPAPI, because if the secret necessary for decrypting the master key was to be stored on the disk by design, Microsoft could have kept on using the NTLM hash it uses in domain settings (and supposedly used in the first implementation of DPAPI). We then demonstrated how this attack can be executed using readily available tools.
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
			* [gosecretsdump](https://github.com/C-Sto/gosecretsdump)
				* This is a conversion of the impacket secretsdump module into golang. It's not very good, but it is quite fast. Please let me know if you find bugs, I'll try and fix where I can - bonus points if you can provide sample .dit files for me to bash against.
	* **Internal Monologue**
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
	* **Keylogger**
		* **Articles/Blogpost/Writeups**
			* [Keylogging by Using Windows’ Built-in Mechanisms Only - Paula Januszkiewicz(2020)](https://cqureacademy.com/blog/windows-internals/keylogging)
			* [How to create a keylogger in PowerShell? - Juan Manuel Fernandez](https://www.tarlogic.com/en/blog/how-to-create-keylogger-in-powershell/)
		* **Papers**
			* [You Can Type, but You Can’t Hide: A Stealthy GPU-based Keylogger](http://www.cs.columbia.edu/~mikepo/papers/gpukeylogger.eurosec13.pdf) 
				* Keyloggers are a prominent class of malware that harvests sensitive data by recording any typed in information. Key- logger implementations strive to hide their presence using rootkit-like techniques to evade detection by antivirus and other system protections. In this paper, we present a new approach for implementing a stealthy keylogger: we explore the possibility of leveraging the graphics card as an alterna- tive environment for hosting the operation of a keylogger. The key idea behind our approach is to monitor the system’s keyboard buffer directly from the GPU via DMA, without any hooks or modifications in the kernel’s code and data structures besides the page table. The evaluation of our pro- totype implementation shows that a GPU-based keylogger can effectively record all user keystrokes, store them in the memory space of the GPU, and even analyze the recorded data in-place, with negligible runtime overhead.
		* **Tools**
			* [Puffadder](https://github.com/xp4xbox/Puffader/blob/master/readme.md)
				* Puffader is an opensource, hidden and undetectable keylogger for windows written in Python 2.7 which can also capture screenshots, mouse window clicks and clipboard data.
	* **Local Account**
		* [Win Brute Logon (Proof Of Concept)](https://github.com/DarkCoderSc/win-brute-logon)
			*  Crack any Microsoft Windows users password without any privilege (Guest account included)
	* **Local Phishing**
		* **Articles/Blogposts/Writeups**
			* [Post exploitation trick - Phish users for creds on domains, from their own box](https://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
		* **Tools**
			* [Pickl3](https://github.com/hlldz/pickl3)
				* Pickl3 is Windows active user credential phishing tool. You can execute the Pickl3 and phish the target user credential. 
	* **Logon**
		* [Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
			* The quick lowdown: I wrote a DLL capable of logging the credentials entered at logon for Windows Vista, 7 and future versions which you can download at http://www.leetsys.com/programs/credentialprovider/cp.zip. The credentials are logged to a file located at c:\cplog.txt. Simply copy the dll to the system32 directory and run the included register.reg script to create the necessary registry settings.
	* **Local Files**
		* **Articles/Blogposts/Writeups**
			* [Extracting SSH Private Keys from Windows 10 ssh-agent - ropnop](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)
			* [Stored passwords found all over the place after installing Windows in company networks :( - Win-Fu Official Blog](http://blog.win-fu.com/2017/08/stored-passwords-found-all-over-place.html)
		* **Tools**
			* [windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)
				* PoC code to extract private keys from Windows 10's built in ssh-agent service
	* **Local Security Authority Subsystem Service(LSA & LSASS&)**
		* **101**
			* [Local Security Authority Subsystem Service - Wikipedia](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)
			* [Local Security Authority SubSystem Service - ldapwiki](https://ldapwiki.com/wiki/Local%20Security%20Authority%20Subsystem%20Service)
			* [Security Subsystem Architecture - 2012](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN)
			* [LSA Authentication - docs.ms(2018)](https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication?redirectedfrom=MSDN)
		* **Articles/Blogposts/Writeups**
			* [Dumping LSA Secrets - @spottheplanet(2019)](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets)
			* [Dumping Lsass.exe to Disk Without Mimikatz and Extracting Credentials - @spotheplanet](https://ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
			* [Some ways to dump LSASS.exe - Mark Mo](https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf)
			* [Extract credentials from lsass remotely - hackndo](https://en.hackndo.com/remote-lsass-dump-passwords/)
			* [MiniDumpWriteDump via COM+ Services DLL - modexp](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/)
			* [Bypassing LSA Protection (aka Protected Process Light) without Mimikatz on Windows 10 - RedCursor.com.au(2020)](https://www.redcursor.com.au/blog/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10)
			* [How to Capture a Minidump: Let Me Count the Ways - John Robbins(2020)](https://www.wintellect.com/how-to-capture-a-minidump-let-me-count-the-ways/)
		* **Tools**
			* [Dumpert](https://github.com/outflanknl/Dumpert)
				* Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike, while not touching disk and evading AV/EDR monitored user-mode API calls.
			* [AndrewSpecial](https://github.com/hoangprod/AndrewSpecial)
				* AndrewSpecial, dumping lsass' memory stealthily and bypassing "Cilence" since 2019.
			* [PhysMem2Profit](https://github.com/FSecureLABS/physmem2profit)
				* Physmem2profit can be used to create a minidump of a target host's LSASS process by analysing physical memory remotely. The intention of this research is to propose an alternative approach to credential theft and create a modular framework that can be extended to support other drivers that can access physical memory. Physmem2profit generates a minidump (.dmp) of LSASS that can be further analyzed with Mimikatz. The tool does not require Cobalt Strike but should work fine over beacon with a SOCKS proxy.
				* [Blogpost](https://labs.f-secure.com/blog/rethinking-credential-theft/)
			* [lsassy](https://github.com/hackndo/lsassy)
				* Python library to remotely extract credentials on a set of hosts
				* [Blogpost](https://en.hackndo.com/remote-lsass-dump-passwords/)
			* [SharpMiniDump](https://github.com/b4rtik/SharpMiniDump)
				* Create a minidump of the LSASS process from memory (Windows 10 - Windows Server 2016). The entire process uses: dynamic API calls, direct syscall and Native API unhooking to evade the AV / EDR detection.
			* [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)
				* Tool to bypass LSA Protection (aka Protected Process Light) I’ve noticed there is a common misconception that LSA Protection prevents attacks that leverage SeDebug or Administrative privileges to extract credential material from memory, like Mimikatz. LSA Protection does NOT protect from these attacks, at best it makes them slightly more difficult as an extra step needs to be performed.
			* [Spraykatz](https://github.com/aas-n/spraykatz)
				* Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments. It simply tries to procdump machines and parse dumps remotely in order to avoid detections by antivirus softwares as much as possible.
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
		* **pypykatz**
			* [pypykatz](https://github.com/skelsec/pypykatz)
				* Mimikatz implementation in pure Python
			* [pypykatz_server](https://github.com/skelsec/pypykatz_server)
			* [pypykatz_dn](https://github.com/skelsec/pypykatz_agent_dn)
	* **NTLM**
		* [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge](http://davenport.sourceforge.net/ntlm.html)
		* [Live off the Land and Crack the NTLMSSP Protocol](https://www.mike-gualtieri.com/posts/live-off-the-land-and-crack-the-ntlmssp-protocol)
			* Last month Bleeping Computer published an article about PKTMON.EXE, a little known utility in Windows 10 that provides the ability to sniff and monitor network traffic.  I quickly wondered if it would be feasible to use this utility, and other native tools within Windows, to capture NTLMv2 network authentication handshakes. TL;DR: Yes it is possible and I wrote a Python3 script called NTLMRawUnHide that can extract NTLMv2 password hashes from packet dumps of many formats!
		* [NTLMRawUnhide.py](https://github.com/mlgualtieri/NTLMRawUnHide)
			* NTLMRawUnhide.py is a Python3 script designed to parse network packet capture files and extract NTLMv2 hashes in a crackable format. The tool was developed to extract NTLMv2 hashes from files generated by native Windows binaries like NETSH.EXE and PKTMON.EXE without conversion.
	* **Password Filter DLL**
		* [PasswordStealing -PSBits](https://github.com/gtworek/PSBits/tree/master/PasswordStealing)
			* "Password stealing DLL I wrote around 1999, some time before Active Directory was announced. And of course it still works. First, it was written in 32-bit Delphi (pardon my language) and when it stopped working as everything changed into 64-bit - in (so much simpler when it comes to Win32 API) C, as I did not have 64-bit Delphi. The original implementation was a bit more complex, including broadcasting the changed password over the network etc. but now it works as a demonstration of an idea, so let's keep it as simple as possible. It works everywhere - on local machines for local accounts and on DCs for domain accounts."
		* [Credential Access – Password Filter DLL - NetbiosX](https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/)
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
			* [Spray](https://github.com/Greenwolf/Spray)
				* A Password Spraying tool for Active Directory Credentials by Jacob Wilkin(Greenwolf)
			* [Sharphose](https://github.com/ustayready/SharpHose)
				* SharpHose is a C# password spraying tool designed to be fast, safe, and usable over Cobalt Strike's execute-assembly. It provides a flexible way to interact with Active Directory using domain-joined and non-joined contexts, while also being able to target specific domains and domain controllers. SharpHose takes into consideration the domain password policy, including fine grained password policies, in an attempt to avoid account lockouts. Fine grained password policies are enumerated for the users and groups that that the policy applies to. If the policy applied also to groups, the group users are captured. All enabled domain users are then classified according to their password policies, in order of precedence, and marked as safe or unsafe. The remaining users are filtered against an optional user-supplied exclude list. Besides just spraying, red team operators can view all of the password policies for a domain, all the users affected by the policy, or just view the enabled domain users. Output can be sent directly to the console or to a user-supplied output folder.
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
	* **Wifi(saved)**
		* [Credential Dumping: Wireless - Yashika Dhir(2020)](https://www.hackingarticles.in/credential-dumping-wireless/)
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
		* [Red Team Play-book - Initial Enumeration - HunnicCyber](https://blog.hunniccyber.com/red-team-play-book-initial-enumeration/)
	* **Talks/Presentations/Videos**
		* [Post Exploitation: Striking Gold with Covert Recon - Derek Rook(WWHF19)](https://www.youtube.com/watch?v=04H1s9z0JDo)
			* You're on a covert penetration test focusing on the client's monitoring and alerting capabilities. You've just established a foothold, maybe even elevated to admin, but now what? You want to know more about the internal network but careless packet slinging will get you caught. Join me on a mining expedition where you can't swing your pick axe without striking gold. We'll be mining logs, pilfering connection statistics, and claim jumping process network connections. Without leaving the comfort of your beachhead, you'll be shouting "Eureka!" in no time.
	* **AD**
		* **Articles/Blogposts/Writeups**
			* [Push it, Push it Real Good - harmj0y](http://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
			* [Script to Create an Overview and Full Report of all Group Objects in a Domain - Jeremy Saunders](http://www.jhouseconsulting.com/2015/01/02/script-to-create-an-overview-and-full-report-of-all-group-objects-in-a-domain-1455)
			* [PowerQuinsta - harmj0y](http://www.harmj0y.net/blog/powershell/powerquinsta/)
		* **Tools**
			* [Low Privilege Active Directory Enumeration from a non-Domain Joined Host - matt](https://www.attackdebris.com/?p=470)
	* **AppLocker**
		* **Articles/Blogposts/Writeups**
			* [AppLocker Policy Enumeration in C - ntamonsec.blogspot(2020)](https://ntamonsec.blogspot.com/2020/08/applocker-policy-enumeration-in-c.html)
		* **Tools**
	* **Endpoint Protections**
	* **Files**
		* **Articles/Blogposts/Writeups**
			* [Build a Query to Search the Windows Index from PowerShell - Dr Scripto(2012)](https://devblogs.microsoft.com/scripting/build-a-query-to-search-the-windows-index-from-powershell/)
				* Guest blogger, James O’Neill, discusses using Windows PowerShell to build a query to search the Windows Index.
				* [Hey, Scripting Guy! Weekend Scripter: Using the Windows Search Index to Find Specific Files - Dr Scripto(2010)](https://devblogs.microsoft.com/scripting/hey-scripting-guy-weekend-scripter-using-the-windows-search-index-to-find-specific-files/)
			* [Reading Windows Sticky Notes - two06(2020)](https://blog.two06.info/Reading-Windows-Sticky-Notes/)
				* [Code](https://github.com/two06/SharpStick)
			* [Red Team Enumeration: A corner rarely explored - Mohammed Danish(2020)](https://medium.com/@gamer.skullie/red-team-enumeration-a-corner-rarely-explored-75bfae8d8944)
			* [StickyReader](https://github.com/whitej3rry/StickyReader)
				* Read Sticky Notes from Windows 10
		* **Tools**
			* [Snaffler](https://github.com/SnaffCon/Snaffler/)
				* Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly, but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment).
			* [diskover](https://github.com/shirosaidev/diskover)
				*  File system crawler, disk space usage, file search engine and file system analytics powered by Elasticsearch 
	* **Logs**
		* **Articles/Blogposts/Writeups**
			* [Offensive Event Parsing – Bringing Home Trophies - sixdub](https://www.sixdub.net/?p=315)
	* **Mail**
		* **Articles/Blogposts/Writeups**
			* [Compliance search – a pentesters dream - Oddvar Moe](https://msitpros.com/?p=3678)
		* **Tools**
	* **NetworkCapture**
		* **Articles/Blogposts/Writeups**
			* [Capture a Network Trace without installing anything (& capture a network trace of a reboot) - Chad Duffey(blogs.mdsn)](https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/)
		* **Tools**
	* **Sitrep**
		* **Articles/Blogposts/Writeups**
			* [Windows Driver and Service enumeration with Python](https://cybersyndicates.com/2015/09/windows-driver-and-service-enumeration-with-python/)	
			* [Remotely Enumerate Anti-Virus Configurations - FortyNorthSecurity](https://fortynorthsecurity.com/blog/remotely-enumerate-anti-virus-configurations/)
			* [Get-MpPreference - docs.ms](https://docs.microsoft.com/en-us/powershell/module/defender/get-mppreference?view=win10-ps)
			* [Finding Hidden Treasure on Owned Boxes: Post-Exploitation Enumeration with wmiServSessEnum - RedXORBlue](http://blog.redxorblue.com/2019/08/finding-hidden-treasure-on-owned-boxes.html)
				* TLDR: We can use WMI queries to enumerate accounts configured to run any service on a box (even non-started / disabled), as well as perform live session enumeration.  Info on running the tool is in the bottom section.
			* [Detecting Hypervisor Presence On Windows 10 - Daax Rynd](https://revers.engineering/detecting-hypervisor-presence-on-windows-10/)
			* [Windows information gathering using Powershell: a brief cheatsheet - Andrea Fortuna(2019)](https://www.andreafortuna.org/2019/08/29/windows-information-gathering-with-powershell-a-brief-cheatsheet/)
			* [PowerShell: Getting Windows Defender Status from all Domain Joined Computers (Get-AntiMalwareStatus) - Patrick Gruenauer(2018)](https://sid-500.com/2018/08/27/powershell-getting-windows-defender-status-from-all-domain-joined-computers-get-antimalwarestatus/)
		* **Tools**		
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
		* [hunter](https://github.com/fdiskyou/hunter/)
			*  (l)user hunter using WinAPI calls only
		* [NetRipper](https://github.com/NytroRST/NetRipper)
			* NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.
* **Lateral Movement**<a name="winlater"></a>
	* **Articles/Blogposts/Writeups**
		* [Using Credentials to Own Windows Boxes - Part 1 (from Kali) - ropnop](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
		* [Authenticated Remote Code Execution Methods in Windows](https://www.scriptjunkie.us/2013/02/authenticated-remote-code-execution-methods-in-windows/)
		* [Lateral Movement and Persistence: tactics vs techniques - hexacorn(2018)](https://www.hexacorn.com/blog/2018/10/05/lateral-movement-and-persistence-tactics-vs-techniques/)
		* [Offensive Lateral Movement - Hausec](https://hausec.com/2019/08/12/offensive-lateral-movement/)
		* [Lateral Movement - Riccardo Carrani(2019)](https://riccardoancarani.github.io/2019-10-04-lateral-movement-megaprimer/)
		* [Description of User Account Control and remote restrictions in Windows Vista - support.ms](https://support.microsoft.com/en-us/help/951016/description-of-user-account-control-and-remote-restrictions-in-windows)	
	* **Talks/Presentations/Videos**
		* [The Industrial Revolution of Lateral Movement - Tal Be'ery, Tal Maor(BH USA17)](https://www.blackhat.com/docs/us-17/thursday/us-17-Beery-The-Industrial-Revolution-Of-Lateral-Movement.pdf)
		* [Look what you could be up against soon - FX, Hadez(Offensivecon2020)](https://www.youtube.com/watch?v=fgp0KQNjrMQ)
			* Lateral movement is essential for offensive operations during CNO. Exploiting the inherent trust relationships is what makes spreading within the chewy inside of a network so easy once the crunchy outside is broken. But what if the chewy inside is bitchy and challenges you everywhere you want to go? That's what P3KI is all about: To make the chewy inside more bitchy. Hear about how we intend to make your life harder and why the often dismissed "social engineering" aspect might become essential in cases where you face a network employing P3KI's technology deployed.
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
		* **Tools**
			* [smbexec](https://github.com/pentestgeek/smbexec)
				* A rapid psexec style attack with samba tools
				* [Blogpost that inspired it](http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html)
			* [pth-toolkit I.e Portable pass the hash toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
				* A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
	* **PS-Remoting**
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
	* **Protocol Handler**
		* **Articles/Blogposts/Writeups**
			* [Lateral movement using URL Protocol - Matt harr0ey](https://medium.com/@mattharr0ey/lateral-movement-using-url-protocol-e6f7d2d6cf2e)
		* **Tools**	
			* [PoisonHandler](https://github.com/Mr-Un1k0d3r/PoisonHandler)
				* This technique is registering a protocol handler remotely and invoke it to execute arbitrary code on the remote host. The idea is to simply invoke start handler:// to execute commands and evade detection.
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
		* [Revisiting Remote Desktop Lateral Movement - 0xthirteen(2020)](https://0xthirteen.com/2020/01/21/revisiting-remote-desktop-lateral-movement/)
			* Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
	* **Registry-related**
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [WMIReg](https://github.com/airzero24/WMIReg)
				* This PoC was started from a code snippet of @harmj0y's that I thought was pretty cool. Using the StdRegProv management class through WMI, you are able to read and write to local and remote registry keys. This doesn't seem very special, but the biggest advantage is that remote registry interaction is done through WMI, therefore it does not require the Remote Registry service to be enabled/started on the remote host!
	* **SCM**
		* **Articles/Blogposts/Writeups**
			* [Lateral Movement — SCM and DLL Hijacking Primer - Dwight Hohnstein](https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992)
		* **Tools**
	* **Services**
		* **Articles/Blogposts/Writeups**
			* [Lateral Movement – Services - pentestlab.blog(2020)](https://pentestlab.blog/2020/07/21/lateral-movement-services/)
	* **SMB**
		* **Articles/Blogposts/Writeups**
			* [Lateral movement: A deep look into PsExec - Daniel Munoz(2018)](https://www.contextis.com/en/blog/lateral-movement-a-deep-look-into-psexec)
		* **Tools**
			* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
				* A swiss army knife for pentesting networks 
	* **SSH**
		* **Articles/Blogposts/Writeups**
			* [SSH Command - ssh.com](https://www.ssh.com/ssh/command/)
			* [SSH tunnel - ssh.com](https://www.ssh.com/ssh/tunneling/)
			* [SSH Port Forwarding Example - ssh.com](https://www.ssh.com/ssh/tunneling/example/)
			* [SSH Essentials: Working with SSH Servers, Clients, and Keys - Justin Ellingwood(2014)](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys)
			* [SSH/OpenSSH/PortForwarding - help.ubuntu](https://help.ubuntu.com/community/SSH/OpenSSH/PortForwarding)
	* **WinRM**
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
	* **WMI**
		* **101**
		* **Articles/Blogposts/Writeups**
			* [T1047: WMI for Lateral Movement - @spottheplanet](https://www.ired.team/offensive-security/lateral-movement/t1047-wmi-for-lateral-movement)
			* [Lateral Movement: WMI - Pavandeep Singh(2020)](https://www.hackingarticles.in/lateral-movement-wmi/)
			* [No Win32_Process Needed – Expanding the WMI Lateral Movement Arsenal - Philip Tsukerman](https://www.cybereason.com/blog/no-win32-process-needed-expanding-the-wmi-lateral-movement-arsenal?hs_preview=UbvcDFUZ-5764480077)
			* [Lateral Movement in an Environment with Attack Surface Reduction - Michael Bielenberg(2019)](https://ionize.com.au/lateral-movement-in-an-environment-with-attack-surface-reduction/)
		* **Papers**
			* [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor - Matt Graeber(2015)](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
			* [No Win32_Process Needed – Expanding the WMI Lateral Movement Arsenal - Philip Tsukerman(2018)](https://conference.hitb.org/hitbsecconf2018ams/materials/D2T1%20-%20Philip%20Tsukerman%20-%20Expanding%20Your%20WMI%20Lateral%20Movement%20Arsenal.pdf)
		* **Tools**
			* [WMI Shell Tool](https://github.com/secabstraction/Create-WMIshell)
				* The WMI shell tool that we have developed allows us to execute commands and get their output using only the WMI infrastructure, without any help from other services, like the SMB server. With the wmi-shell tool we can execute commands, upload files and recover Windows passwords remotely using only the WMI service available on port 135.
			* [WMIcmd](https://github.com/nccgroup/WMIcmd)
				* A command shell wrapper using only WMI for Microsoft Windows
	* **WSH**
		* [Lateral Movement using WSHController/WSHRemote objects (IWSHController and IWSHRemote interfaces) - hexacorn(2018)](https://www.hexacorn.com/blog/2018/08/18/lateral-movement-using-wshcontroller-wshremote-objects-iwshcontroller-and-iwshremote-interfaces/)
	* **(Ab)Using 'Legitimate' Applications already installed**
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
* **Exfiltration**
	* **Articles/Blogposts/Writeups**
		* [WMI & PowerShell: An Introduction to Copying Files - FortyNorthSecurity](https://fortynorthsecurity.com/blog/wmi/)










---------------------------
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
* **ClickOnce Applications**<a name="clickonce"></a>
	* [ClickOnce - Wikipedia](https://en.wikipedia.org/wiki/ClickOnce)
	* [ClickOnce security and deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2019)
	* [ClickOnce Deployment for Windows Forms - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/winforms/clickonce-deployment-for-windows-forms)
	* [ClickOnce Applications in Enterprise Environments - Remko Weijnen](https://www.remkoweijnen.nl/blog/2013/08/05/clickonce-applications-in-enterprise-environments/)
		* ClickOnce is a Microsoft technology that enables an end user to install an application from the web without administrative permissions.
	* [Eight Evil Things Microsoft Never Showed You in the ClickOnce Demos (and What You Can Do About Some of Them) - Chris Williams](https://www.codemag.com/Article/0902031/Eight-Evil-Things-Microsoft-Never-Showed-You-in-the-ClickOnce-Demos-and-What-You-Can-Do-About-Some-of-Them)
* **Credential Guard**<a name="credguard"></a>
	* **101**
		* 
* **Code Signing**<a name="codesign"></a>
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
* **(Distributed) Component-Object-Model(COM)**<a name="dcom"></a>
	* **101**
		* [Component Object Model (COM) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal?redirectedfrom=MSDN)
			* COM is a platform-independent, distributed, object-oriented system for creating binary software components that can interact. COM is the foundation technology for Microsoft's OLE (compound documents) and ActiveX (Internet-enabled components) technologies.
		* [[MS-DCOM]: Distributed Component Object Model (DCOM) Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0)
			* Specifies the Distributed Component Object Model (DCOM) Remote Protocol, which exposes application objects via remote procedure calls (RPCs) and consists of a set of extensions layered on the Microsoft Remote Procedure Call Extensions.
	* **Articles/Blogposts/WRiteups**
		* [Exploiting .NET Managed DCOM - James Forshaw](https://googleprojectzero.blogspot.com/2017/04/exploiting-net-managed-dcom.html)
			* One of the more interesting classes of security vulnerabilities are those affecting interoperability technology. This is because these vulnerabilities typically affect any application using the technology, regardless of what the application actually does. Also in many cases they’re difficult for a developer to mitigate outside of not using that technology, something which isn’t always possible. I discovered one such vulnerability class in the Component Object Model (COM) interoperability layers of .NET which make the use of .NET for Distributed COM (DCOM) across privilege boundaries inherently insecure. This blog post will describe a couple of ways this could be abused, first to gain elevated privileges and then as a remote code execution vulnerability.
		* [COM Hijacking – Windows Overlooked Security Vulnerability - Yaniv Assor](https://www.cyberbit.com/blog/endpoint-security/com-hijacking-windows-overlooked-security-vulnerability/)
	* **Papers**
		* [The Dangers of Per-User COM Objects - Jon Larimer](https://www.virusbulletin.com/uploads/pdf/conference_slides/2011/Larimer-VB2011.pdf)
* **DLLs**<a name="dll"></a>
	* **101**
		* [What is a DLL? - support.ms](https://support.microsoft.com/en-us/help/815065/what-is-a-dll)
		* [Dynamic-Link-Library - Wikipedia](https://en.wikipedia.org/wiki/Dynamic-link_library)
		* [DLL Hell - Wikipedia](https://en.wikipedia.org/wiki/DLL_Hell)
	* **Tools**
		* [CMDLL](https://github.com/jfmaes/CMDLL)
			* the most basic DLL ever to pop a cmd.
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
* **Faxes & Printers**<a name="printfax"></a>	
	* **101**
		* [[MS-RPRN]: Print System Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)
		* [[MS-RPRN]: Print System Remote Protocol - msdn.ms](https://msdn.microsoft.com/en-us/library/cc244528.aspx)
	* **Articles/Blogposts/Writeups**
* **Fibers**<a name="fibers"></a>
	* **101**
		* [Fibers - docs.ms](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers)
	* **Articles/Blogposts/Writeups**
* **File Extensions**<a name="fext"></a>
	* [Common file name extensions in Windows - support.ms](https://support.microsoft.com/en-us/help/4479981/windows-10-common-file-name-extensions)
	* [File Types - docs.ms](https://docs.microsoft.com/en-us/windows/win32/shell/fa-file-types)
		* This topic explains how to create new file types and how to associate your app with your file type and other well-defined file types. Files with a shared common file name extension (.doc, .html, and so on) are of the same type. For example, if you create a new text editor, then you can use the existing .txt file type. In other cases, you might need to create a new file type.
	* [The case of the missing file extensions - NCCGroup(2014)](https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2014/may/the-case-of-the-missing-file-extensions/)
* **LNK Files**<a name="LNK"></a>
	* **101**
		* [[MS-SHLLINK]: Shell Link (.LNK) Binary File Format - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)
			* Specifies the Shell Link Binary File Format, which contains information that can be used to access another data object. The Shell Link Binary File Format is the format of Windows files with the extension "LNK".
		* [Windows Shortcut File format specification - liblnk](https://github.com/libyal/liblnk/blob/master/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc)
			* This document is intended as a working document for the Windows Shortcut File (LNK) format specification. Which should allow existing Open Source forensic tooling to be able to process this file type.
	* **Articles/Blogposts/Writeups**
		* [You down with LNK? - Nathan Drier(2012)](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/you-down-with-lnk/)
		* [Analyzing the Windows LNK file attack method - 0xd3xt3r](https://dexters-lab.net/2019/02/16/analyzing-the-windows-lnk-file-attack-method/)
		* [Suspected Sapphire Mushroom (APT-C-12) malicious LNK files - @mattnotmax](https://bitofhex.com/2020/02/10/sapphire-mushroom-lnk-files/)
		* [The Missing LNK — Correlating User Search LNK files - Ashley Frazer](https://www.fireeye.com/blog/threat-research/2020/02/the-missing-lnk-correlating-user-search-lnk-files.html)
		* [Using Shell Links as zero-touch downloaders and to initiate network connections - Jan Kopriva(2020)](https://isc.sans.edu/forums/diary/Using+Shell+Links+as+zerotouch+downloaders+and+to+initiate+network+connections/26276/)
		* [CVE-2020-0729: Remote Code Execution Through .LNK Files - Trend Micro Research Team(2020)](https://www.thezdi.com/blog/2020/3/25/cve-2020-0729-remote-code-execution-through-lnk-files)
* **Logging**<a name="winlog"></a>
	* See [L-SM-TH.md](./L-SM-TH.md)
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
			* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
		* [GENE: Go Evtx sigNature Engine](https://github.com/0xrawsec/gene)
			* The idea behind this project is to provide an efficient and standard way to look into Windows Event Logs (a.k.a EVTX files). For those who are familiar with Yara, it can be seen as a Yara engine but to look for information into Windows Events.
			* [Documentation](https://rawsec.lu/doc/gene/1.6/)
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
		* **Tools**
			* [InsecurePowerShell](https://github.com/cobbr/InsecurePowerShell)
				* InsecurePowershell is a fork of PowerShell Core v6.0.0, with key security features removed.
			* [InsecurePowerShellHost](https://github.com/cobbr/InsecurePowerShellHost)
				* InsecurePowerShellHost is a .NET Core host process for InsecurePowerShell, a version of PowerShell Core with key security features removed.
			* [PowerPick](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)
				* This project focuses on allowing the execution of Powershell functionality without the use of Powershell.exe. Primarily this project uses.NET assemblies/libraries to start execution of the Powershell scripts.
			* [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)
				* Executes PowerShell from an unmanaged process.
			* [PowerShdll](https://github.com/p3nt4/PowerShdll)
				* Run PowerShell with dlls only.
			* [NoPowerShell](https://github.com/bitsadmin/nopowershell)
				* NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used; only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll,main.
			* [A Powerful New Tool: PowerLine - BHIS(2017)](https://www.youtube.com/watch?v=HiAtkLa8FOc)
				* [PowerLine](https://github.com/fullmetalcache/PowerLine)
			* [psfire](https://github.com/curi0usJack/psfire)
				* simple demo of using C# & System.Management.Automation.dll to run powershell code (b64 encoded) without powershell.exe
* **PowerShell Desired State Configuration**<a name="winpsc"></a>
	* **Documentation**
		* [Windows PowerShell Desired State Configuration Overview - docs.ms](https://docs.microsoft.com/en-us/powershell/dsc/overview)
	* [DSCompromised: A Windows DSC Attack Framework - Matt Hastings, Ryan Kazanciyan - BH Asia16](https://www.blackhat.com/docs/asia-16/materials/asia-16-Kazanciyan-DSCompromised-A-Windows-DSC-Attack-Framework.pdf)
	* [DSCompromised](https://github.com/matthastings/DSCompromised)
		* PowerShell framework for managing and infecting systems via Windows Desired State Configuration (DSC) DSC is a built-in feature in Windows Management Framework 4.0 (PowerShell v4) and is installed natively on Windows operating systems beginning with Server 2012 R2 and Windows 8.1.
* **Privileges**
	* [Privilege Constants (Authorization) - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
		* Privileges determine the type of system operations that a user account can perform. An administrator assigns privileges to user and group accounts. Each user's privileges include those granted to the user and to the groups to which the user belongs.
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
* **Windows Remote Management**<a name="winrm"></a>
	* **101**
		* F
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











#### <a name="csharp-stuff">C# & .NET Stuff</a>
* **101**
	* **.NET & .NET Core**
		* [Overview of .NET Framework - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/get-started/overview)
		* [Introduction to .NET Core - docs.ms](https://docs.microsoft.com/en-us/dotnet/core/introduction)
		* [.NET Core CLI overview - docs.ms](https://docs.microsoft.com/en-us/dotnet/core/tools/)
		* [.NET Standard - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/net-standard)
		* [Tour of .NET - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/tour)
			* This article offers a guided tour through some of the key features of the .NET.
		* [.NET architectural components - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/components)
			* A .NET app is developed for and runs in one or more implementations of .NET. Implementations of .NET include the .NET Framework, .NET Core, and Mono. There is an API specification common to all implementations of .NET that's called the .NET Standard. This article gives a brief introduction to each of these concepts.
		* [Common Language Runtime (CLR) overview - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/clr)
		* [AppDomain Class - docs.ms](https://docs.microsoft.com/en-us/dotnet/api/system.appdomain?view=netcore-3.1)
			* Represents an application domain, which is an isolated environment where applications execute. This class cannot be inherited.
		* [.NET Method Internals - Common Intermediate Language (CIL) Basics - @mattifestation(2014)](http://www.exploit-monday.com/2014/07/dotNETMethodInternals.html)
		* [.NET Malware Threat: Internals and Reversing - Alexandre Borges(Defcon2019)](http://www.blackstormsecurity.com/docs/ALEXANDREBORGES_DEFCON_2019.pdf)
		* [What is "managed code"? - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/managed-code)
			* When working with .NET Framework, you will often encounter the term "managed code". This document will explain what this term means and additional information around it.
	* **C#**
		* [A tour of the C# language - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/tour-of-csharp/)
			* C# (pronounced "See Sharp") is a modern, object-oriented, and type-safe programming language. C# has its roots in the C family of languages and will be immediately familiar to C, C++, Java, and JavaScript programmers. This tour provides an overview of the major components of the language in C# 8 and earlier. 
		* [Get started with C# - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/getting-started/)
		* [Inside a C# program - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/)
			* The section discusses the general structure of a C# program, and includes the standard "Hello, World!" example.
	* **Detection**
		* [Interesting DFIR traces of .NET CLR Usage Logs - MenaSec(2019)](https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html)
		* [Hijacking .NET to Defend PowerShell - Amanda Rosseau](https://arxiv.org/pdf/1709.07508.pdf)
			* Abstract—With the rise of attacks using PowerShell in the recent months, there has not been a comprehensive solution for monitoring or prevention. Microsoft recently released the AMSI solution for PowerShell v5, however this can also be bypassed. This paper focuses on repurposing various stealthy runtime .NET hijacking techniques implemented for PowerShell attacks for defensive monitoring of PowerShell. It begins with a brief introduction to .NET and PowerShell, followed by a deeper explanation of various attacker techniques, which is explained from the perspective of the defender, including assembly modification, class and method injection, compiler profiling, and C based function hooking. Of the four attacker techniques that are repurposed for defensive real-time monitoring of PowerShell execution, intermediate language binary modification, JIT hooking, and machine code manipulation provide the best results for stealthy run-time interfaces for PowerShell scripting analysis
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
		* [SharpNado - Teaching an old dog evil tricks using .NET Remoting or WCF to host smarter and dynamic payloads - redxorblue](http://blog.redxorblue.com/2018/12/sharpnado-teaching-old-dog-evil-tricks.html)
			* SharpNado is proof of concept tool that demonstrates how one could use .Net Remoting or Windows Communication Foundation (WCF) to host smarter and dynamic .NET payloads.  SharpNado is not meant to be a full functioning, robust, payload delivery system nor is it anything groundbreaking. It's merely something to get the creative juices flowing on how one could use these technologies or others to create dynamic and hopefully smarter payloads. I have provided a few simple examples of how this could be used to either dynamically execute base64 assemblies in memory or dynamically compile source code and execute it in memory.  This, however, could be expanded upon to include different kinds of stagers, payloads, protocols, etc.
	* **Talks/Presentations/Videos**
		* [.NET Manifesto - Win Friends and Influence the Loader - Casey Smith(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-28-net-manifesto-win-friends-and-influence-the-loader-casey-smith)
			* Everything you never wanted to know about .NET manifests and influencing binary loading. A growing number of security tools, both offensive and defensive rely on the .NET Framework. This talk will focus on a narrow but important aspect. We will cover Application and Machine configuration files, as well as Registration-Free and Side-By-Side Assembly loading. What do all these have in common?Manifests. XML manifest can influence how the Operating System locates and executes binaries. We will explore additional concepts around influencing assembly loads. This talk will provide excellent insight into how these mechanisms work. How they can be subverted, and how they can be instrumented to aid defenders.
		* [Staying # & Bringing Covert Injection Tradecraft to .NET - The Wover, Ruben Boonen(BlueHat IL 2020)](https://www.youtube.com/watch?v=FuxpMXTgV9s&feature=share)
			* As .NET has taken over as the preferred platform for development on Windows, many attackers have chosen to take advantage of its features for post-exploitation tradecraft. Legitimate APIs can be leveraged for nearly every imaginable task, managed code can be loaded and executed from memory with extraordinary ease, and scalable monitoring for suspicious usage of .NET APIs is a problem yet to be solved. However, offensive .NET tools are still hindered by a fundamental weakness: the inability to leverage unmanaged code (such as the Win32/NT APIs) safe from observation by EDR. Managed code must eventually invoke unmanaged code in order to interface with the operating system. It is here that the attacker may be caught in the hooks of any system keen on watching for fundamentally malicious behavior. To expose the depth of tradecraft still unexplored in .NET and highlight the fragility of many existing detections, we will detail the tools we have built for evading these hooks. All of our efforts have been integrated into SharpSploit, a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers. Over the past few months we have added numerous new tools and techniques for loading and executing unmanaged code safely from .NET. Unmanaged APIs may be safely accessed and modules loaded either from memory or from disk in the new DInvoke API, a dynamic replacement for .NET's PInvoke API. It also includes manual mapping, a generic syscall wrapper, a new technique we call Module Overloading, and more. Additionally, we have added a modular process injection API that allows tool developers to build their own injection technique. Simply select an allocation and injection primitive, pass in any options, and execute the result with your preferred payload. This exposes all possible design decisions to the user, and allows for easy adaptation when existing tools fail. In our talk we will focus on explaining the fundamental tradecraft behind these new developments, the challenges and requirements associated with them, and how they can be adapted to suit your needs. Additionally, we will discuss how SharpSploit can be combined with other open-source projects to be integrated into a red team's tooling. As much as possible, we will also discuss how to counter and detect the techniques that we have developed. Finally, we will explain the community-focused development of these projects and how you too can contribute to advance open-source .NET tradecraft
	* **Tools**
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
			* [Shellcode: Loading .NET Assemblies From Memory(2019)](https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/)
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
				* [Shellcode: Loading .NET Assemblies From Memory - modexp](https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/)
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
	* **Binary/Source Obfuscation**
		* [AsStrongAsFuck](https://github.com/Charterino/AsStrongAsFuck)
			* A console obfuscator for .NET assemblies. 
		* [ConfuserEx2](https://github.com/mkaring/ConfuserEx)
			* ConfuserEx 2 is a open-source protector for .NET applications. It is the successor of Confuser project and the ConfuserEx project.
		* [NeoConfuserEx](https://github.com/XenocodeRCE/neo-ConfuserEx)
			* Neo ConfuserEx is the successor of ConfuserEx project, an open source C# obfuscator which uses its own fork of dnlib for assembly manipulation. Neo ConfuserEx handles most of the dotnet app, supports all elligible .NET Frameworks and provide decent obfuscation on your file.
		* [.NET Obfuscator Lists](https://github.com/NotPrab/.NET-Obfuscator)
		* [Lists of .NET Deobfuscator / Unpacker (Open Source)](https://github.com/NotPrab/.NET-Deobfuscator)
		* [MindLated](https://github.com/Sato-Isolated/MindLated)
			* .net obfuscator
	* **Cradles/Runners**
		* [SharpCradle](https://github.com/anthemtotheego/SharpCradle)
			* SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
		* [RunShellcode](https://github.com/zerosum0x0/RunShellcode)
			* Simple GUI program when you just want to run some shellcode.
		* [CreateThread Example](https://github.com/djhohnstein/CSharpCreateThreadExample)
			* C# code to use CreateThread to run position independent code in the running process. This code is provided AS IS, and will not be supported.
		* [CSharp SetThreadContext](https://github.com/djhohnstein/CSharpSetThreadContext)
			*  C# Shellcode Runner to execute shellcode via CreateRemoteThread and SetThreadContext to evade Get-InjectedThread 
	* **MSBuild-related**
		* [Another MSBuild Invocation (February 2020 Edition) - Joe Leon(2020)](https://fortynorthsecurity.com/blog/another-msbuild-bypass-february-2020-edition/)
	* **MS-SQL-related**
		* [Attacking SQL Server CLR Assemblies - Scott Sutherland](https://www.netspi.com/webinars/attacking-sql-server-clr-assemblies-on-demand/)
			* During this webinar we’ll review how to create, import, export, and modify CLR assemblies in SQL Server with the goal of privilege escalation, OS command execution, and persistence. Scott will also share a few PowerUpSQL functions that can be used to execute the CLR attacks on a larger scale in Active Directory environments.
	* **Process Injection/Shellcode Execution**
		* **Articles/Blogposts/Writeups**
			* [Shellcode Execution in .NET using MSIL-based JIT Overwrite - Matt Graeber(2013)](http://www.exploit-monday.com/2013/04/MSILbasedShellcodeExec.html)
		* **Tools**
			* [C# Memory Injection Examples](https://github.com/pwndizzle/c-sharp-memory-injection)
				* A set of scripts that demonstrate how to perform memory injection.
			* [Execute assembly via Meterpreter session](https://github.com/b4rtik/metasploit-execute-assembly)
				* Custom Metasploit post module to executing a .NET Assembly from Meterpreter session 
			* [TikiTorch](https://github.com/rasta-mouse/TikiTorch)
				* TikiTorch was named in homage to CACTUSTORCH by Vincent Yiu. The basic concept of CACTUSTORCH is that it spawns a new process, allocates a region of memory, then uses CreateRemoteThread to run the desired shellcode within that target process. Both the process and shellcode are specified by the user.
				* [TikiTorch - Rastamouse](https://rastamouse.me/blog/tikitorch/)
				* [TikiVader - Rastamouse](https://rastamouse.me/blog/tikivader/)
				* [The Return of Aggressor - Rastamouse](https://rastamouse.me/blog/tikigressor/)
				* [TikiService - Rastamouse](https://rastamouse.me/blog/tikiservice/)
				* [Lighting the path through EDRs using TikiTorch - RhythmStick(2019)](https://www.rythmstick.net/posts/tikitorch/)
			* [MemorySharp](https://github.com/ZenLulz/MemorySharp)
				* MemorySharp is a C# based memory editing library targeting Windows applications, offering various functions to extract and inject data and codes into remote processes to allow interoperability.
			* [ManagedInjection](https://github.com/malcomvetter/ManagedInjection)
				* A proof of concept for dynamically loading .net assemblies at runtime with only a minimal convention pre-knowledge
			* [SharpNeedle](https://github.com/ChadSki/SharpNeedle)
				* A project for properly injecting C# dlls into other processes.
			* [ManagedInjection](https://github.com/malcomvetter/ManagedInjection)
				* A proof of concept for injecting a pre-compiled .net assembly in memory at runtime with zero pre-knowledge of its assembly namespace or type. All that is necessary is a convention for the initial method name which will be instantiated, or just have the assembly initialize via its Constructor for a true "zero knowledge" scenario.
	* **PS in C#**
		* **Articles/Blogposts/Writeups**
			* [Executing PowerShell scripts from C# - doc.ms(2014)](https://docs.microsoft.com/en-us/archive/blogs/kebab/executing-powershell-scripts-from-c)
				* "In today’s post, I will demonstrate the basics of how to execute PowerShell scripts and code from within a C#/.NET applications. I will walk through how to setup your project prerequisites, populate the pipeline with script code and parameters, perform synchronous and asynchronous execution, capture output, and leverage shared namespaces."
			* [Using C# for post-PowerShell attacks - John Bergbom(2018)](https://www.forcepoint.com/blog/x-labs/using-c-post-powershell-attacks)
		* **Tools**
			* [NoPowerShell](https://github.com/bitsadmin/nopowershell)
				* NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used; only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll,main.
			* [p0wnedShell](https://github.com/Cn33liz/p0wnedShell)
				* PowerShell Runspace Post Exploitation Toolkit 
			* [p0wnedLoader](https://github.com/Cn33liz/p0wnedLoader)
			* [Smallp0wnedShell](https://github.com/3gstudent/Smallp0wnedShell)
				* Small modification version of PowerShell Runspace Post Exploitation Toolkit (p0wnedShell)
			* [CScriptShell](https://github.com/Cn33liz/CScriptShell)
			* [Stracciatella](https://github.com/mgeeky/Stracciatella)
				* OpSec-safe Powershell runspace from within C# (aka SharpPick) with AMSI, CLM and Script Block Logging disabled at startup
	* **Reflection**
	    * [Reflection (C#) - docs.ms](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/reflection)
	    	* Reflection provides objects (of type Type) that describe assemblies, modules, and types. You can use reflection to dynamically create an instance of a type, bind the type to an existing object, or get the type from an existing object and invoke its methods or access its fields and properties. If you are using attributes in your code, reflection enables you to access them. For more information, see Attributes.
	    * [How C# Reflection Works With Code Examples - stackify](https://stackify.com/what-is-c-reflection/)
	    * [Reflection in .NET - keesari_anjaiah(2010)](https://www.codeproject.com/Articles/55710/Reflection-in-NET)
	    * [What is Reflection in C#? - geeksforgeeks(2019)](https://www.geeksforgeeks.org/what-is-reflection-in-c-sharp/)
	* **Resource Embedding**
		Single File Executable - https://docs.microsoft.com/en-us/dotnet/core/whats-new/dotnet-core-3-0#single-file-executables
		Assembly Linking - https://docs.microsoft.com/en-us/dotnet/core/whats-new/dotnet-core-3-0#assembly-linking
		https://denhamcoder.net/2018/08/25/embedding-net-assemblies-inside-net-assemblies/
		* [Fody](https://github.com/Fody/Home/#endofbacking)
			* The Home repository is the starting point for people to learn about Fody, the project.
		* [Fody Engine](https://github.com/Fody/Fody)
			* Extensible tool for weaving .net assemblies. Manipulating the IL of an assembly as part of a build requires a significant amount of plumbing code. This plumbing code involves knowledge of both the MSBuild and Visual Studio APIs. Fody attempts to eliminate that plumbing code through an extensible add-in model.
		* [Costura](https://github.com/Fody/Costura)
			* Embed references as resources
	* **Serialization**
		* **Gadget2Jscript**
			* [GadgetToJScript - RastaMouse(2020)](https://rastamouse.me/blog/gadgettojscript/)
				* [Github](https://github.com/rasta-mouse/GadgetToJScript)
			* [GadgetToJScript - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/GadgetToJScript%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)
			* [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript)
				* A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS based scripts. The gadget being used triggers a call to Assembly.Load when deserialized via jscript/vbscript, this means it can be used in the same way to trigger in-memory load of your own shellcode loader at runtime. Lastly, the tool was created mainly for automating WSH scripts weaponization for RT engagements (LT, Persistence, Initial Compromise), the shellcode loader which was used for PoC is removed and replaced by an example assembly implemented in the "TestAssemblyLoader.cs" class for PoC purpose.
			* [GadgetToJScript, Covenant, Donut - 3xpl01tc0d3r](https://3xpl01tc0d3r.blogspot.com/2020/02/gadgettojscript-covenant-donut.html)
		* **Tools**
			* [DotNetDeserializationScanner](https://github.com/leechristensen/DotNetDeserializationScanner)
				* Scans for .NET Deserialization Bugs in .NET Assemblies 
	* **Windows Services**
		* [Using Parameters With InstallUtil - ip3lee](https://diaryofadeveloper.wordpress.com/2012/04/26/using-paramters-with-installutil/)
		* [SharpSC](https://github.com/djhohnstein/SharpSC)
			* Simple .NET assembly to interact with services.
	* **WinAPI Access**
		* **Articles/Blogposts/Writeups**
			* [Offensive P/Invoke: Leveraging the Win32 API from Managed Code - Matt Hand](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d)
			* [Red Team Tactics: Utilizing Syscalls in C# - Prerequisite Knowledge - Jack Halon(2020)](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/)
				* [Part2: Writing The Code](https://jhalon.github.io/utilizing-syscalls-in-csharp-2/)
		* **Tools**
			* [ManagedWindows](https://github.com/zodiacon/ManagedWindows)
				* Managed wrappers around the Windows API and some Native API
			* [SharpCall](https://github.com/jhalon/SharpCall)
				* Simple proof of concept code that allows you to execute direct system calls in C# by utilizing unmanaged code to bypass EDR and API Hooking.
			* [taskkill](https://github.com/malcomvetter/taskkill)
				* This is a reference example for how to call the Windows API to enumerate and kill a process similar to taskkill.exe. This is based on (incomplete) MSDN example code. Proof of concept or pattern only.
			* [DnsCache](https://github.com/malcomvetter/DnsCache)
				* This is a reference example for how to call the Windows API to enumerate cached DNS records in the Windows resolver. Proof of concept or pattern only.
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
	* [SharpExchangePriv](https://github.com/panagioto/SharpExchangePriv)
		* A C# implementation of PrivExchange by `@_dirkjan`. Kudos to @g0ldenGunSec, as I relied on his code.
	* [SharpUp](https://github.com/GhostPack/SharpUp)
		* SharpUp is a C# port of various PowerUp functionality. Currently, only the most common checks have been ported; no weaponization functions have yet been implemented.
	* [Watson](https://github.com/rasta-mouse/Watson)
		* Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
	* [Net-GPPPassword](https://github.com/outflanknl/Net-GPPPassword)
		* .NET/C# implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
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
* **Privilege Escalation**
	* **Active Directory**
		* [Grouper2](https://github.com/l0ss/Grouper2)
			* Find vulnerabilities in AD Group Policy
	* **Registry**
		* [Reg1c1de: Windows Registry Privesc Scanner](https://github.com/deadjakk/reg1c1de)
			* Reg1c1de is a tool that scans specified registry hives and reports on any keys where the user has write permissions In addition, if any registry values are found that contain file paths with certain file extensions and they are writeable, these will be reported as well.
		* [Blogpost](https://deadjakk.github.io/registry_privesc.html)
	* **Services**
		* [SneakyService](https://github.com/malcomvetter/SneakyService)
			* A simple C# windows service implementation that can be used to demonstrate privilege escalation from misconfigured windows services.
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
		* [Dumping Process Memory with Custom C# Code - 3xplo1tcod3r](https://3xpl01tc0d3r.blogspot.com/2019/07/dumping-process-memory-with-custom-c-sharp.html)
		* [SharpDump](https://github.com/GhostPack/SharpDump)
			* SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
		* [ATPMiniDump](https://github.com/b4rtik/ATPMiniDump)
			* Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft.
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
	* **Talks/Presentations/Videos**
		* [Simple Windows Application Whitelisting Evasion - Casey Smith(ShmooCon 2015)](https://www.youtube.com/watch?v=XVuboBH5TYo)
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































---------------------------------------------------------------------------------------------------------
### <a name="powershell-stuff">Powershell Things</a>
* **101**
	* [Why I Choose PowerShell as an Attack Platform - @mattifestation(2012)](http://www.exploit-monday.com/2012/08/Why-I-Choose-PowerShell.html)
	* [The PowerSploit Manifesto - @mattifestation(2015)](http://www.exploit-monday.com/2015/12/the-powersploit-manifesto.html)
	* [PowerShell is Not Special - An Offensive PowerShell Retrospective - @mattifestation(2017)](http://www.exploit-monday.com/2017/01/powershell-is-not-special-offensive.html)
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
	* **Memory & Processes**
		* [Powershell Live-Memory Analysis Tools: Dump-Memory, Dump-Strings, Check-MemoryProtection - @mattifestation(2012)](http://www.exploit-monday.com/2012/03/powershell-live-memory-analysis-tools.html)
		* [Invoke-ProcessScan](https://github.com/vysec/Invoke-ProcessScan)
			* Gives context to a system. Uses EQGRP shadow broker leaked list to give some descriptions to processes.
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
    	* Invoke-ReflectivePEInjection.ps1 - https://github.com/clymb3r/PowerShell/blob/master/Invoke-ReflectivePEInjection/Invoke-ReflectivePEInjection.ps1
			* This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,  or it can reflectively load a DLL in to a remote process.
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
	* **Download Cradles**
	 	* [Dropping Executables with Powershell - @mattifestation(2011)](http://www.exploit-monday.com/2011/09/dropping-executables-with-powershell.html)
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
	* **Reflection**
		* [Use PowerShell to Work with the .NET Framework Classes - devblogs.ms(2010)](https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-the-net-framework-classes/)
		* [PowerShell cmdLet add-type - renenyffenegger.ch](https://renenyffenegger.ch/notes/Windows/PowerShell/command-inventory/noun/type/add/index)
		* [How to do .NET Reflection in PowerShell - Roger Lipscombe(2013)](https://blog.differentpla.net/blog/2013/04/17/how-to-do-net-reflection-in-powershell/)
		* [Using Powershell and Reflection API to invoke methods from .NET Assemblies - Khai Tran(2013)](https://blog.netspi.com/using-powershell-and-reflection-api-to-invoke-methods-from-net-assemblies/)
	* **Reflective DLL Injection**
		* [Reflective DLL Injection with PowerShell - clymb3r(2013)](https://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/)
		* [Invoke-DllInjection.ps1 - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-DllInjection.ps1)
			* Injects a Dll into the process ID of your choosing.
	* **Reflective PE Injection**
		* Invoke-ReflectivePEInjection.ps1 - PowerSploit Invoke-ReflectivePEInjection.ps1)
			* This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,  or it can reflectively load a DLL in to a remote process.
		* [Reflective PE Injection In Windows 10 1909 - HUBBL3(2020)](https://www.bc-security.org/post/reflective-pe-injection-in-windows-10-1909/)
	* **Running Shellcode**
		* [Invoke-Shellcode.ps1 - PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1)
			* Inject shellcode into the process ID of your choosing or within the context of the running PowerShell process.
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
			* [Properly Retrieving Win32 API Error Codes in PowerShell - @mattifestation(2016)](http://www.exploit-monday.com/2016/01/properly-retrieving-win32-api-error.html)
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
			* [Invoke-CradleCrafter: Moar PowerShell obFUsk8tion by Daniel Bohannon](https://www.youtube.com/watch?feature=youtu.be&v=Nn9yJjFGXU0&app=desktop)
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

















---------------------
### <a name="Pivoting">Pivoting & Tunneling</a>
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
			* [Proxyjump, the SSH option you probably never heard of - Khris Tolbert(2020)](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464)
		* **VPN**
			* [How VPN Pivoting Works (with Source Code) - cs](https://blog.cobaltstrike.com/2014/10/14/how-vpn-pivoting-works-with-source-code/)
			* [Universal TUN/TAP device driver. - kernel.org](https://www.kernel.org/pub/linux/kernel/people/marcelo/linux-2.4/Documentation/networking/tuntap.txt)
			* [Tun/Tap interface tutorial - backreference](http://backreference.org/2010/03/26/tuntap-interface-tutorial/)
			* [Responder and Layer 2 Pivots - cplsec](https://ijustwannared.team/2017/05/27/responder-and-layer-2-pivots/)
			* [simpletun](https://github.com/gregnietsky/simpletun)
				* Example program for tap driver VPN
		* **WMIC**
			* [The Grammar of WMIC](https://isc.sans.edu/diary/The+Grammar+of+WMIC/2376)
			* [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
			* [Windows Security Center: Fooling WMI Consumers](https://www.opswat.com/blog/windows-security-center-fooling-wmi-consumers)
	* **Tools**
		* [Socat](http://www.dest-unreach.org/socat/)
			* socat is a relay for bidirectional data transfer between two independent data channels. Each of these data channels may be a file, pipe, device (serial line etc. or a pseudo terminal), a socket (UNIX, IP4, IP6 - raw, UDP, TCP), an SSL socket, proxy CONNECT connection, a file descriptor (stdin etc.), the GNU line editor (readline), a program, or a combination of two of these.  These modes include generation of "listening" sockets, named pipes, and pseudo terminals.
			* [Examples of use](http://www.dest-unreach.org/socat/doc/socat.html#EXAMPLES)
			* [Socat Cheatsheet](http://www.blackbytes.info/2012/07/socat-cheatsheet/)
		* [XFLTReaT](https://github.com/earthquake/XFLTReaT)
			* XFLTReaT tunnelling framework
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
			* [SharpChisel](https://github.com/shantanu561993/SharpChisel)
				* C# Wrapper of Chisel from https://github.com/jpillora/chisel
			* [Crowbar](https://github.com/q3k/crowbar)
				* Crowbar is an EXPERIMENTAL tool that allows you to establish a secure circuit with your existing encrypting TCP endpoints (an OpenVPN setup, an SSH server for forwarding...) when your network connection is limited by a Web proxy that only allows basic port 80 HTTP connectivity.  Crowbar will tunnel TCP connections over an HTTP session using only GET and POST requests. This is in contrast to most tunneling systems that reuse the CONNECT verb. It also provides basic authentication to make sure nobody who stumbles upon the server steals your proxy to order drugs from Silkroad.
			* [A Black Path Toward The Sun(ABPTTS)](https://github.com/nccgroup/ABPTTS)
				* ABPTTS uses a Python client script and a web application server page/package[1] to tunnel TCP traffic over an HTTP/HTTPS connection to a web application server. In other words, anywhere that one could deploy a web shell, one should now be able to establish a full TCP tunnel. This permits making RDP, interactive SSH, Meterpreter, and other connections through the web application server.
			* [pivotnacci](https://github.com/blackarrowsec/pivotnacci)
				* Pivot into the internal network by deploying HTTP agents. Pivotnacci allows you to create a socks server which communicates with HTTP agents
			* [graftcp](https://github.com/hmgle/graftcp)
				* graftcp can redirect the TCP connection made by the given program [application, script, shell, etc.] to SOCKS5 or HTTP proxy.
			* [Tunna](https://github.com/SECFORCE/Tunna)
				* Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments.
		* **HTTP2**
			* [gTunnel](https://github.com/hotnops/gtunnel)
				* A TCP tunneling suite built with golang and gRPC. gTunnel can manage multiple forward and reverse tunnels that are all carried over a single TCP/HTTP2 connection. I wanted to learn a new language, so I picked go and gRPC. Client executables have been tested on windows and linux.
		* **ICMP**
			* [Hans - IP over ICMP - hans](http://code.gerade.org/hans/)
				* [Source](https://sourceforge.net/projects/hanstunnel/files/source/)
				* Hans makes it possible to tunnel IPv4 through ICMP echo packets, so you could call it a ping tunnel. This can be useful when you find yourself in the situation that your Internet access is firewalled, but pings are allowed.
			* [icmptx](https://github.com/jakkarth/icmptx)
				*  ICMPTX is a program that allows a user with root privledges to create a virtual network link between two computers, encapsulating data inside of ICMP packets.
		* **PowerShell**
			* [PowerShellDSCLateralMovement.ps1](https://gist.github.com/mattifestation/bae509f38e46547cf211949991f81092)
		* **RDP**
			* [Socks Over RDP / Socks Over Citrix](https://github.com/nccgroup/SocksOverRDP)
				* This tool adds the capability of a SOCKS proxy to Terminal Services (or Remote Desktop Services) and Citrix (XenApp/XenDesktop). It uses Dynamic Virtual Channel that enables us to communicate over an open RDP/Citrix connection without the need to open a new socket, connection or a port on a firewall.
			* [Socks Over RDP - Balazs Bucsay(2020)](https://research.nccgroup.com/2020/05/06/tool-release-socks-over-rdp/)
		* **SMB**
			* [Piper](https://github.com/p3nt4/Piper)
				* Creates a local or remote port forwarding through named pipes.
			* [flatpipes](https://github.com/dxflatline/flatpipes)
				* A TCP proxy over named pipes. Originally created for maintaining a meterpreter session over 445 for less network alarms.
			* [Invoke-PipeShell](https://github.com/threatexpress/invoke-pipeshell)
				* This script demonstrates a remote command shell running over an SMB Named Pipe. The shell is interactive PowerShell or single PowerShell commands
			* [Invoke-Piper](https://github.com/p3nt4/Invoke-Piper)
				* Forward local or remote tcp ports through SMB pipes.
		* **SSH**
			* [SSHDog](https://github.com/Matir/sshdog)
				* SSHDog is your go-anywhere lightweight SSH server. Written in Go, it aims to be a portable SSH server that you can drop on a system and use for remote access without any additional configuration.	
			* [MeterSSH](https://github.com/trustedsec/meterssh)
				* MeterSSH is a way to take shellcode, inject it into memory then tunnel whatever port you want to over SSH to mask any type of communications as a normal SSH connection. The way it works is by injecting shellcode into memory, then wrapping a port spawned (meterpeter in this case) by the shellcode over SSH back to the attackers machine. Then connecting with meterpreter's listener to localhost will communicate through the SSH proxy, to the victim through the SSH tunnel. All communications are relayed through the SSH tunnel and not through the network.
			* [powermole](https://github.com/yutanicorp/powermolecli)
				* This program will let you perform port forwarding, redirect internet traffic, and transfer files to, and issue commands on, a host without making a direct connection (ie. via one or more intermediate hosts), which would undoubtedly compromise your privacy. This solution can only work when you or your peers own one or more hosts as this program communicates with SSH servers. This program can be viewed as a multi-versatile wrapper around SSH with the ProxyJump directive enabled. Powermole creates automatically a ssh/scp configuration file to enable key-based authentication with the intermediate hosts.
		* **SOCKS/TCP/UDP**
			* [RFC1928: SOCKS Protocol Version 5](https://tools.ietf.org/html/RFC1928)
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
			* [ligolo](https://github.com/sysdream/ligolo)
				* Ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve). It is comparable to Meterpreter with Autoroute + Socks4a, but more stable and faster.
			* [proxychains-windows](https://github.com/shunf4/proxychains-windows)
				* Windows and Cygwin port of proxychains, based on MinHook and DLL Injection
			* [rpivot](https://github.com/klsecservices/rpivot)
				* This tool is Python 2.6-2.7 compatible and has no dependencies beyond the standard library. It has client-server architecture. Just run the client on the machine you want to tunnel the traffic through. Server should be started on pentester's machine and listen to incoming connections from the client.
			* [Secure Socket Funneling](https://github.com/securesocketfunneling/ssf)
				* Secure Socket Funneling (SSF) is a network tool and toolkit. It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS tunnel to a remote computer. SSF is cross platform (Windows, Linux, OSX) and comes as standalone executables.
		* **WMI**
			* [PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)
				* PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement.
				* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)
		* **VNC**
			* [Invoke-Vnc](https://github.com/klsecservices/Invoke-Vnc)
				* Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.
			* [jsmpeg-vnc](https://github.com/phoboslab/jsmpeg-vnc)
				* A low latency, high framerate screen sharing server for Windows and client for browsers






















----------------
### <a name="av">Avoiding/Bypassing AV(Anti-Virus)/UAC/Whitelisting/Sandboxes/Logging/etc - General Evasion Tactics & Techniques</a>

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
	* **Binary/Payload Obfuscation**
		* **Articles/Writeups**		
			* [Building an Obfuscator to Evade Windows Defender - Samuel Wong(2020)](https://www.xanthus.io/post/building-an-obfuscator-to-evade-windows-defender)
			* [Build your first LLVM Obfuscator - polarply(2020)](https://medium.com/@polarply/build-your-first-llvm-obfuscator-80d16583392b)
				* In this post we will briefly present LLVM, discuss popular obfuscation approaches and their shortcomings and build our own epic LLVM-based string obfuscator.
				* [Code](https://github.com/tsarpaul/llvm-string-obfuscator)
		* **Tools**
			* [avcleaner](https://github.com/scrt/avcleaner)
				* C/C++ source obfuscator for antivirus bypass
			* [NET-Obfuscate](https://github.com/BinaryScary/NET-Obfuscate)
				* Obfuscate ECMA CIL (.NET IL) assemblies to evade Windows Defender AMSI. 
	* **Sandbox Detection & Evasion**
		* See also 'Keying'
		* **Articles/Writeups**
			* [Introduction to Sandbox Evasion and AMSI Bypasses - BC-Security(2019)](https://github.com/BC-SECURITY/DEFCON27)
		* **Tools**
			* [CheckPlease](https://github.com/Arvanaghi/CheckPlease)
	* **Windows Event Log Avoidance & Deletion**
		* **Articles/Writeups**
			* [Remove individual lines from Windows XML Event Log (EVTX) files](https://github.com/3gstudent/Eventlogedit-evtx--Evolution)
				* Remove individual lines from Windows XML Event Log (EVTX) files
			* [Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)
			* [Universally Evading Sysmon and ETW - dylan.codes(2020)](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)
			* [Mute Sysmon - Silence Sysmon via event manifest tampering - SecurityJosh(2020)](https://securityjosh.github.io/2020/04/23/Mute-Sysmon.html)
			* [Deletion and Bypass of Windows Logs - 3gstudent](https://3gstudent.github.io/3gstudent.github.io/渗透技巧-Windows日志的删除与绕过/)
			* [Domain Controller Security Logs – how to get at them *without* being a Domain Admin - girlgerms(2016)](https://girl-germs.com/?p=1538)
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
	* **Crypters**
		* [100% evasion - Write a crypter in any language to bypass AV - xentropy(2020)](https://netsec.expert/2020/02/06/write-a-crypter-in-any-language.html)
	* **Keying**
		* **Articles**
			* [Mesh design pattern: hash-and-decrypt - rdist(2007)](https://web.archive.org/web/20200727221946/https://rdist.root.org/2007/04/09/mesh-design-pattern-hash-and-decrypt/)
			* [Bradley, hash-and-decrypt, Gauss ... a brief history of armored malware and malicious crypto - Fred Raynal(2012)](https://blog.quarkslab.com/bradley-hash-and-decrypt-gauss-a-brief-history-of-armored-malware-and-malicious-crypto.html)
			* [Keying Payloads for Scripting Languages - @leoloobeek(2017)](https://adapt-and-attack.com/2017/11/15/keying-payloads-for-scripting-languages/)
		* **Talks/Presentations/Videos**
			* [Context-Keyed Payload Encoding: Fighting The Next Generation of IDS - Dimitris Glynos(AthCon2010)](https://www.youtube.com/watch?v=mHMULvGynSU)
				* [Slides](https://census-labs.com/media/context-keying-slides.pdf)
				* [Paper](http://census.gr/media/context-keying-whitepaper.pdf)
				* Exploit payload encoding allows hiding maliciouspayloads from modern Intrusion Detection Systems (IDS). Although metamorphic and polymorphic encoding allow such payloads to be hidden from signature-based and anomaly-based IDS,these techniques fall short when the payload is being examined by IDS that can trace the execution of malicious code. Context-keyed encodingis a technique that allows the attacker to encrypt the malicious payload in such a way, that it canonly be executed in an environment (context) withspecific characteristics. By selecting an environment characteristic that will not be present during the IDS trace (but will be present on the target host), the attacker may evade detection by advanced IDS. This paper focuses on the current research in context-keyed payload encoding and proposes a novel encoder that surpasses many of the limitations found in its predecessors.
			* [Advanced Payload Strategies: “What is new, what works and what is hoax?”](https://www.troopers.de/events/troopers09/220_advanced_payload_strategies_what_is_new_what_works_and_what_is_hoax/)
				* This talk focuses on the shellcode perspective and it’s evolution. From the simplest {shell}code to the polymorphism to bypass filters and I{D|P}S (which has lots of new ideas, like application-specific decoders, decoders based on architecture-instructions, and many others), passing through syscall proxying and injection, this talk will explain how it works and how effective they are against the new evolving technologies like network code emulation, with live demonstrations. There is long time since the first paper was released about shellcoding. Most of modern text just tries to explain the assembly structure and many new ideas have just been released as code, never been detailed or explained. The talk will try to fix this gap, also showing some new ideas and considering different architectures.
			* [Genetic Malware: Designing Payloads for Specific Targets - Travis Morrow, Josh Pitts(2016)](https://www.youtube.com/watch?v=WI8Y24jTTlw)
				* [Slides](https://raw.githubusercontent.com/Genetic-Malware/Ebowla/master/Eko_2016_Morrow_Pitts_Master.pdf)
				* [Ebowla @ Infiltrate](https://downloads.immunityinc.com/infiltrate-archives/Genetic_Malware_Travis_Morrow_Josh_Pitts.pdf)
			* [Protect Your Payloads Modern Keying Techniques - Leo Loobeek(Derybcon2018)](https://www.youtube.com/watch?v=MHc3XP3XC4I)
				* Our payloads are at risk! Incident responders, threat hunters, and automated software solutions are eager to pick apart your new custom dropper and send you back to square one. One answer to this problem is encrypting your payload with key derivation functions ("keying") which leverages a variety of local and remote resources to build the decryption key. Throughout this talk I will present modern keying techniques and demo some tools to help along the way. I will start with showing how easy it is to discover attacker infrastructure or techniques in the payloads we commonly use every day. I will then quickly review how keying helps and the considerations when generating keyed payloads. Throughout the presentation many practical examples of keying techniques will be provided which can be used for typical pentests or full red team operations. Finally I will introduce KeyServer, a new piece to add to your red team infrastructure which handles advanced HTTP and DNS keying. Using unprotected payloads during ops should be a thing of the past. Let’s regain control of our malicious code and make it harder on defenders! This talk is based on the original research of environmental keying by Josh Pitts and Travis Morrow.
		* **Papers**
			* [Environmental Key Generation towards Clueless Agents - J. Riordan and B. Schneier(1998)](https://www.schneier.com/academic/archives/1998/06/environmental_key_ge.html)
				* In this paper, we introduce a collection of cryptographic key constructions built from environmental data that are resistant to adversarial analysis and deceit. We expound upon their properties and discuss some possible applications; the primary envisioned use of these constructions is in the creation of mobile agents whose analysis does not reveal their exact purpose.
			* [Strong Cryptography Armoured Computer VirusesForbidding Code Analysis: the bradley virusEric Filiol(2004)](https://hal.inria.fr/inria-00070748/document)
				* Imagining what the nature of future viral attacks might look like is the key to successfully protecting against them. This paper discusses how cryptography and key management techniques may definitively checkmate antiviral analysis and mechanisms. We present a generic virus, denoted bradley which protects its code with a very secure, ultra-fast symmetric encryption. Since the main drawback of using encryption in that case lies on the existence of the secret key or information about it within the viral code, we show how to bypass this limitation by using suitable key management techniques. Finally, we show that the complexity of the bradley code analysis is at least as high as that of the cryptanalysis of its underlying encryption algorithm.
			* [Foundations and applications for secure triggers - Ariel Futoransky, Emiliano  Kargieman, Carlos Sarraute, Ariel  Waissbein(2006)](https://dl.acm.org/doi/10.1145/1127345.1127349)
				* Imagine there is certain content we want to maintain private until some particular event occurs, when we want to have it automatically disclosed. Suppose, furthermore, that we want this done in a (possibly) malicious host. Say the confidential content is a piece of code belonging to a computer program that should remain ciphered and then “be triggered” (i.e., deciphered and executed) when the underlying system satisfies a preselected condition, which must remain secret after code inspection. In this work we present different solutions for problems of this sort, using different “declassification” criteria, based on a primitive we call secure triggers. We establish the notion of secure triggers in the universally composable security framework of Canetti [2001] and introduce several examples. Our examples demonstrate that a new sort of obfuscation is possible. Finally, we motivate its use with applications in realistic scenarios.
			* [Context-keyed Payload Encoding: Preventing Payload Disclosure via Context - 	druid@caughq.org(2008)](http://www.uninformed.org/?v=9&a=3)
			* [Malicious cryptography. . . reloaded - Eric Filiol, Fr'ed'eric Raynal(CanSecWest2008)](https://cansecwest.com/csw08/csw08-raynal.pdf)
			* [Context-keyed Payload Encoding:Fighting the Next Generation of IDS - Dimitrios A. Glynos(2010)](http://census.gr/media/context-keying-whitepaper.pdf)
			* [Impeding Automated Malware Analysis with Environment-sensitive Malware - Chengyu Song, Paul Royal, Wenke Lee(2012)](https://www.usenix.org/conference/hotsec12/workshop-program/presentation/song)
				* To solve the scalability problem introduced by the exponential growth of malware, numerous automated malware analysis techniques have been developed. Unfortunately, all of these approaches make previously unaddressed assumptions that manifest as weaknesses to the tenability of the automated malware analysis process. To highlight this concern, we developed two obfuscation techniques that make the successful execution of a malware sample dependent on the unique properties of the original host it infects. To reinforce the potential for malware authors to leverage this type of analysis resistance, we discuss the Flashback botnet’s use of a similar technique to prevent the automated analysis of its samples.
			* [Sleeping Your Way out of theSandbox - Hassan  Mourad(2015)](https://www.sans.org/reading-room/whitepapers/malicious/sleeping-sandbox-35797)
				* In recent years,the security landscape has witnessed the rise of a new breed of malware, Advanced  Persistence  Threat,  or  APT  for  short.  With  all  traditional  security  solutions failing  to  address  this  new  threat,  a  demand  was  created  for  new  solutions  that  are capable of addressing the advanced capabilities of APT. One of the offeredsolutions was file-based  sandboxes,asolution  that  dynamically  analyzes  files  and  judgestheir  threat levelsbased  on  their  behavior  in  an  emulated/virtual  environment.  But  security  is  a  cat and mouse game, and malware authors are always trying to detect/bypass such measures. Some of the common techniques used by malware for sandbox evasionwill be discussed in  this  paper. This  paperwill  also  analyze  how  to  turn somecountermeasuresused  by sandboxes against it. Finally, itwill introduce some new ideas for sandbox evasion along with recommendationsto address them.
			* [Hot Knives Through Butter: Evading File-based Sandboxes - Abhishek Singh, Zheng Bu(2014)](https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/pf/file/fireeye-hot-knives-through-butter.pdf)
		* **Tools**
			* **Metasploit**
				* [Hostname-based Context Keyed Payload Encoder - Metasploit Module](https://github.com/rapid7/metasploit-framework/blob/master//modules/encoders/x64/xor_context.rb)
					* 'Context-Keyed Payload Encoder based on hostname and x64 XOR encoder.'	
			* [EBOWLA](https://github.com/Genetic-Malware/Ebowla)
				* Framework for Making Environmental Keyed Payloads
			* [keyring](https://github.com/leoloobeek/keyring)
				* KeyRing was written to make key derivation functions (keying) more approachable and easier to quickly develop during pentesting and red team operations. Keying is the idea of encrypting your original payload with local and remote resources, so it will only decrypt on the target system or under other situations.
			* [satellite](https://github.com/t94j0/satellite)
				* [Satellite: A Payload and Proxy Service for Red Team Operations - Max Harley](https://posts.specterops.io/satellite-a-payload-and-proxy-service-for-red-team-operations-aa4500d3d970)
				* Satellite is an web payload hosting service which filters requests to ensure the correct target is getting a payload. This can also be a useful service for hosting files that should be only accessed in very specific circumstances.
			* [GoGreen](https://github.com/leoloobeek/GoGreen)
				* This project was created to bring environmental (and HTTP) keying to scripting languages. As its common place to use PowerShell/JScript/VBScript as an initial vector of code execution, as a result of phishing or lateral movement, I see value of the techniques for these languages.
			* [Spotter](https://github.com/matterpreter/spotter)
				* Spotter is a tool to wrap payloads in environmentally-keyed, AES256-encrypted launchers. These keyed launchers provide a way to ensure your payload is running on its intended target, as well as provide a level of protection for the launcher itself.
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
















































------------------------------------------------------------------------------------------------------------------------------------
### <a name="lict"></a>Linux Code Injection
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









































------------------------------------------------------------------------------------------------------------------------------------
### <a name="mict"></a>macOS Code Injection
* **101**
* **General Information**
* **Articles/Blogposts/Writeups**
* **Techniques**
















































---------------------------------------------------------------------------------------------------------------------------------
### <a name="wcit"></a>Windows Code Injection Techniques
* **101**
	* [Process Injection Techniques — Gotta Catch Them All - Itzik Kotler, Amit Klein(BHUSA19)](https://www.youtube.com/watch?v=xewv122qxnk)
		* [Paper](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)	
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
	* **Samples**
		* [ProcessInjection - 3xpl01tc0d3r](https://github.com/3xpl01tc0d3r/ProcessInjection)
		* [injection - theevilbit](https://github.com/theevilbit/injection)
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
* **APC**
	* **101**
		* [Asynchronous Procedure Calls - docs.ms](https://docs.microsoft.com/en-gb/windows/win32/sync/asynchronous-procedure-calls)
		* [Inside NT's Asynchronous Procedure Call - Albert Almeida(2002)](https://www.drdobbs.com/inside-nts-asynchronous-procedure-call/184416590)
		* [APC Series: User APC API - repnz(2020)](https://repnz.github.io/posts/apc/user-apc/)
		* [APC Series: User APC Internals - repnz(2020)](https://repnz.github.io/posts/apc/kernel-user-apc-api/)
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
* **Atom Bombing**
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
* **Breaking BaDDEr**
	* [Windows Process Injection: Breaking BaDDEr - modexp(2019)](https://modexp.wordpress.com/2019/08/09/windows-process-injection-breaking-badder/)
	* [PoC](https://github.com/odzhan/injection/tree/master/dde)
* **Command Line and Environment Variables**
	* [Windows Process Injection: Command Line and Environment Variables - modexp(2020)](https://modexp.wordpress.com/2020/07/31/wpi-cmdline-envar/)
* **Console Window Class**
	* [Windows Process Injection: ConsoleWindowClass - modexp(2018)](https://modexp.wordpress.com/2018/09/12/process-injection-user-data/)
	* [PoC](https://github.com/odzhan/injection/tree/master/conhost)
* **Ctrl Injection**
	* [Ctrl-Inject - Rotem Kerner(2018)](https://web.archive.org/web/20190612183057/https://blog.ensilo.com/ctrl-inject)
    * [PoC](https://github.com/theevilbit/injection/blob/master/Ctrlinject/Ctrlinject/Ctrlinject.cpp)
* **DLL Injection**
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
* **Reflective Dll Injection**
	* **101**
		* [Reflection (computer programming) - Wikipedia](https://en.wikipedia.org/wiki/Reflection_(computer_programming))
		* [HS-P005_ReflectiveDllInjection.pdf - Stephen Fewer(2008)](https://packetstormsecurity.com/files/71410/HS-P005_ReflectiveDllInjection.pdf.html)
			* Whitepaper on reflective DLL injection. Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process. As such the library is responsible for loading itself by implementing a minimal Portable Executable (PE) loader.
		* [Reflective DLL Injection - Stephen Fewer(2008)](https://www.exploit-db.com/docs/english/13007-reflective-dll-injection.pdf)
			* Alternate hosting of paper
		* [Loading a DLL from memory - Joachim Bauch(2010)](https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/)
	* **Info**
		* [Reflective DLL Injection with PowerShell - clymb3r(2013)](https://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/)
		* [Upgrade your DLL to Reflective DLL - Ionut Popescu(2015)](https://securitycafe.ro/2015/02/26/upgrade-your-dll-to-reflective-dll/)
		* [An Improved Reflective DLL Injection Technique - Dan Staples(2015)](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html)
		* [Cross-Architecture Reflective DLL Injection - Dan Staples(2015)](https://disman.tl/2015/03/16/cross-architecture-reflective-dll-inection.html)
		* [ThreadContinue - Reflective DLL Injection Using SetThreadContext() and NtContinue(2017)](https://zerosum0x0.blogspot.com/2017/07/threadcontinue-reflective-injection.html)
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
* **DNS Client API**
	* [Code Execution via surgical callback overwrites (e.g. DNS memory functions) - hexacorn(2019)](http://www.hexacorn.com/blog/2019/06/12/code-execution-via-surgical-callback-overwrites-e-g-dns-memory-functions/)
	* [Windows Process Injection: DNS Client API - modexp(2019)](https://modexp.wordpress.com/2019/08/08/windows-process-injection-dnsapi/)
	* [Poc](https://github.com/odzhan/injection/tree/master/dns)
* **Process Doppelganging**
* **DoubleAgent**
	* [DOUBLEAGENT: Zero-Day Code Injection AND Persistence Technique - Cybellum(2017)](https://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique/)
	* [Masquerading Windows processes like a DoubleAgent. - Philippe Vogler(2020)](https://sensepost.com/blog/2020/masquerading-windows-processes-like-a-doubleagent./)
* **Earlybird Injection**
* **Extra Window Bytes**
	* **101**
		* [Process Injection: Extra Window Memory Injection - MITRE ATT&CK(2020)](https://attack.mitre.org/techniques/T1055/011/)
		* [Windows Process Injection: Extra Window Bytes - modexp(2018)](https://modexp.wordpress.com/2018/08/26/process-injection-ctray/)
	* **Informational**
		* [Win32/Gapz: steps of evolution - Aleksandr Matrosov(2012)](https://www.welivesecurity.com/2012/12/27/win32gapz-steps-of-evolution/)
		* [Through the Window: Creative Code Invocation - Chris Dietrich(2014)](https://www.crowdstrike.com/blog/through-window-creative-code-invocation/)
	* **PoCs**
		* [Poc](https://github.com/odzhan/injection/tree/master/extrabytes)
* **Gargoyle**
* **GhostWriting Injection**
	* **101**
		* [A paradox: Writing to another process without openning it nor actually writing to it - txipi(2007)](http://blog.txipinet.com/2007/04/05/69-a-paradox-writing-to-another-process-without-openning-it-nor-actually-writing-to-it/)
			* A paradox: Writing to another process without openning it nor actually writing to it
	* **Informational**
		* [Using METASM To Avoid Antivirus Detection (Ghost Writing ASM) - Royce Davis(2012)](https://www.pentestgeek.com/penetration-testing/using-metasm-to-avoid-antivirus-detection-ghost-writing-asm)
		* [Ghost Writing METASM - Vanshit Malhotra(2015)](https://screwnomore.wordpress.com/2015/05/26/ghost-writing-metasm/)
	* **Performing**	
	* **PoCs**
		* [GhostWriting](https://github.com/c0de90e7/GhostWriting)
* **Process Hollowing**
* **(Un-)Hooking**
* **Inject-Me**
* **KernelControlTable** - ehhhhhhhhhhh
* **KnownDLLs Cache Poisoning**
* **Mapping Injection**
* **Multiple Provider Router (MPR) DLL and Shell Notifications**
* **NINA**
	* **101**
		* [NINA: x64 Process Injection (NINA: No Injection, No Allocation x64 Process Injection Technique.) - NtRaiseHardError(2020)]
			* [Code](https://github.com/NtRaiseHardError/NINA)
* **NtCreate**
* **.NET/C#**
	* [.NET Internals and Code Injection](https://ntcore.com/files/netint_injection.htm)
		 * This article is the obvious culmination of the previous effort of writing the Rebel.NET application and the first of a two series of articles about the .NET framework internals and the protections available for .NET assemblies. The next article will be about .NET native compiling. As the JIT inner workings haven't been analyzed yet, .NET protections are quite naļf nowadays. This situation will rapidly change as soon as the reverse engineering community will focus its attention on this technology. These two articles are aimed to raise the consiousness about the current state of .NET protections and what is possible to achieve but hasn't been done yet. In particular, the current article about .NET code injection represents, let's say, the present, whereas the next one about .NET native compiling represents the future. What I'm presenting in these two articles is new at the time I'm writing it, but I expect it to become obsolete in less than a year. Of course, this is obvious as I'm moving the first steps out from current .NET protections in the direction of better ones. But this article isn't really about protections: exploring the .NET framework internals can be useful for many purposes. So, talking about protections is just a means to an end.		
* **PE Injection**
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
	* **Detection**
		* See the [Logging, System Monitoring and Threat Hunting](./L-SM-TH.md) Page.
	* **PoCs**
		* [ PE-Inject - DelphiBasics(2010)](http://www.delphibasics.info/home/delphibasicscounterstrikewireleases/pe-inject)
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
		* Invoke-ReflectivePEInjection - PowerSploit https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
			* [Documentation](https://powersploit.readthedocs.io/en/latest/CodeExecution/Invoke-ReflectivePEInjection/
		* Invoke-ReflectivePEInjection.ps1 - empire https://github.com/BC-SECURITY/Empire/blob/master/data/module_source/management/Invoke-ReflectivePEInjection.ps1
* **PowerLoader(Ex)**
	* **101**
		* [PowerLoader Injection – Something truly amazing - malwaretech(2013)](https://www.malwaretech.com/2013/08/powerloader-injection-something-truly.html)
	* **PoC**
		* [PowerLoaderEx](https://github.com/BreakingMalware/PowerLoaderEx)
* **Print Spooler**
* **PROPagate**
* **Service Control Handler**
* **Shatter**
* **Shellcode Injection**
* **Stack Bomber**
* **Thread Execution Hijacking**
* **ThreadLocal Storage Injection**
* **Tooltips/Common Controls**
* **Windows Notification Facility**
* **WinSock Helper Functions(WSHX)**


