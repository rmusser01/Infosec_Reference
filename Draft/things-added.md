




-----------
### ATT&CK
* [Adversary Emulation Plans](https://attack.mitre.org/wiki/Adversary_Emulation_Plans)
	* To showcase the practical use of ATT&CK for offensive operators and defenders, MITRE created Adversary Emulation Plans. These are prototype documents of what can be done with publicly available threat reports and ATT&CK. The purpose of this activity is to allow defenders to more effectively test their networks and defenses by enabling red teams to more actively model adversary behavior, as described by ATT&CK. This is part of a larger process to help more effectively test products and environments, as well as create analytics for ATT&CK behaviors rather than detecting a specific indicator of compromise (IOC) or specific tool.
* [Malicious Installer Plugins - specterops](https://posts.specterops.io/malicious-installer-plugins-6e30991bb529)
* [DPAPI Primer for Pentesters - webstersprodigy](https://webstersprodigy.net/2013/04/05/dpapi-primer-for-pentesters/)
* [net-creds](https://github.com/DanMcInerney/net-creds)
	* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification.

* [PCredz](https://github.com/lgandx/PCredz)
	* This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

https://www.mac4n6.com/blog/2018/3/21/uh-oh-unified-logs-in-high-sierra-1013-show-plaintext-password-for-apfs-encrypted-external-volumes-via-disk-utilityapp

* [Orchard](https://github.com/its-a-feature/Orchard)
	* Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS' JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web.

* [High Sierra’s ‘Secure Kernel Extension Loading’ is Broken - Patrick Wardle](https://www.synack.com/2017/09/08/high-sierras-secure-kernel-extension-loading-is-broken/)

* [NetRipper](https://github.com/NytroRST/NetRipper)
	* NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.

* [Javascript for Automation - Release Notes 10.10 - dev.apple](https://developer.apple.com/library/content/releasenotes/InterapplicationCommunication/RN-JavaScriptForAutomation/Articles/OSX10-10.html)

* [3snake](https://github.com/blendin/3snake)
	* Targeting rooted servers, reads memory from sshd and sudo system calls that handle password based authentication. Doesn't write any memory to the traced processes. Spawns a new process for every sshd and sudo command that is run. Listens for the proc event using netlink sockets to get candidate processes to trace. When it receives an sshd or sudo process ptrace is attached and traces read and write system calls, extracting strings related to password based authentication.

https://github.com/NetSPI/skl
https://sysadminconcombre.blogspot.ca/2018/04/run-system-commands-through-nvidia.html
* [Windows CMD Reference - ms](https://www.microsoft.com/en-us/download/details.aspx?id=56846)





------------
## Anonymity/OpSec/Privacy

* [Understanding & Improving Privacy "Audits" under FTC Orders](https://cyberlaw.stanford.edu/blog/2018/04/understanding-improving-privacy-audits-under-ftc-orders)
	* This new white paper, entitled “Understanding and Improving Privacy ‘Audits’ under FTC Orders,” carefully parses the third-party audits that Google and Facebook are required to conduct under their 2012 Federal Trade Commission consent orders.  Using only publicly available documents, the article contrasts the FTC’s high expectations for the audits with what the FTC actually received (as released to the public in redacted form).   These audits, as a practical matter, are often the only “tooth” in FTC orders to protect consumer privacy.  They are critically important to accomplishing the agency’s privacy mission.  As such, a failure to attend to their robust enforcement can have unintended consequences, and arguably, provide consumers with a false sense of security. The paper shows how the audits are not actually audits as commonly understood.  Instead, because the FTC order language only requires third-party “assessments,” the companies submit reports that are termed “attestations.”  Attestations fundamentally rely on a few vague privacy program aspects that are self-selected by the companies themselves.  While the FTC could reject attestation-type assessments, the agency could also insist the companies bolster certain characteristics of the attestation assessments to make them more effective and replicate audit attributes.  For example, the FTC could require a broader and deeper scope for the assessments.  The agency could also require that assessors evaluate Fair Information Practices, data flows, notice/consent effectiveness, all company privacy assurances, and known order violations.


------------
## Basic Security Info


------------
## BIOS/UEFI/Firmware/Low Level Attacks











------------
## Building a Lab 

* [Invoke-ADLabDeployer](https://github.com/outflanknl/Invoke-ADLabDeployer)
	* Automated deployment of Windows and Active Directory test lab networks. Useful for red and blue teams.
* [ADImporter](https://github.com/curi0usJack/ADImporter)
	* When you need to simulate a real Active Directory with thousands of users you quickly find that creating realistic test accounts is not trivial. Sure enough, you can whip up a quick PowerShell one-liner that creates any number of accounts, but what if you need real first and last names? Real (existing) addresses? Postal codes matching phone area codes? I could go on. The point is that you need two things: input files with names, addresses etc. And script logic that creates user accounts from that data. This blog post provides both.
* [Automated-AD-Setup](https://github.com/OneLogicalMyth/Automated-AD-Setup)
	* A PowerShell script that aims to have a fully configured domain built in under 10 minutes, but also apply security configuration and hardening.
* [OWASP Damn Vulnerabl Web Sockets](https://github.com/interference-security/DVWS)
	* OWASP Damn Vulnerable Web Sockets (DVWS) is a vulnerable web application which works on web sockets for client-server communication. The flow of the application is similar to DVWA. You will find more vulnerabilities than the ones listed in the application.
* [Damn Vulnerable Web App](https://github.com/ethicalhack3r/DVWA)
	* Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and to aid both students & teachers to learn about web application security in a controlled class room environment.
* [Damn Small Vulnerable Web](https://github.com/stamparm/DSVW)
	* Damn Small Vulnerable Web (DSVW) is a deliberately vulnerable web application written in under 100 lines of code, created for educational purposes. It supports majority of (most popular) web application vulnerabilities together with appropriate attacks.


------------
## Car Hacking


------------
## Cheat Sheets
* [Windows CMD Reference - ms](https://www.microsoft.com/en-us/download/details.aspx?id=56846)




------------
## Conferences







------------
## Courses

* [InfosecPosh101](https://github.com/garignack/InfosecPosh101)
	* A repository of Labs and other information for learning how PowerShell can help with infosec

------------
## Cryptography & Timing Attacks (& CryptoCurrencies)

* [Project HashClash](https://marc-stevens.nl/p/hashclash/)
	* Framework for MD5 & SHA-1 Differential Path Construction and Chosen-Prefix Collisions for MD5. It's goal is to further understanding and study of the weaknesses of MD5 and SHA-1. 
* [Hash-based Signatures: An illustrated Primer](https://blog.cryptographyengineering.com/2018/04/07/hash-based-signatures-an-illustrated-primer/)
* [Outsmarting-Smart-Contracts](https://github.com/sneakerhax/Outsmarting-Smart-Contracts)






------------
## CTF




-------------
## Darknets





------------
## Data Analysis/Visualization




-----------------
## Defense

* [Detect Password Spraying With Windows Event Log Correlation](https://www.ziemba.ninja/?p=66)
* [YubiKey-Guide](https://github.com/drduh/YubiKey-Guide)
	* This is a practical guide to using YubiKey as a SmartCard for storing GPG encryption and signing keys.
* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
	* A curated list of awesome Security Hardening techniques for Windows.
* [DCSYNCMonitor](https://github.com/shellster/DCSYNCMonitor)
	* Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.
* [Service Account best practices Part 1: Choosing a Service Account](https://4sysops.com/archives/service-account-best-practices-part-1-choosing-a-service-account/)
	* In this article you will learn the fundamentals of Windows service accounts. Specifically, we discover the options and best practices concerning the selection of a service account for a particular service application.
* [Service Account best practices - Part 2: Least Privilege implementation](https://4sysops.com/archives/service-account-best-practices-part-2-least-privilege-implementation/)
	* In this article you will learn some best-practice suggestions for using service applications according to the IT security rule of least privilege.
* [Best Practice: Securing Windows Service Accounts and Privileged Access – Part 1 - SecurIT360](https://www.securit360.com/blog/best-practice-service-accounts/)
* [Best Practice: Securing Windows Service Accounts and Privileged Access – Part 2 - SecurIT360](https://www.securit360.com/blog/best-practice-service-accounts-p2/)
* [Windows CMD Reference - ms](https://www.microsoft.com/en-us/download/details.aspx?id=56846)
* [The Open Guide to Amazon Web Services](https://github.com/open-guides/og-aws)
	* A lot of information on AWS is already written. Most people learn AWS by reading a blog or a “getting started guide” and referring to the standard AWS references. Nonetheless, trustworthy and practical information and recommendations aren’t easy to come by. AWS’s own documentation is a great but sprawling resource few have time to read fully, and it doesn’t include anything but official facts, so omits experiences of engineers. The information in blogs or Stack Overflow is also not consistently up to date. This guide is by and for engineers who use AWS. It aims to be a useful, living reference that consolidates links, tips, gotchas, and best practices. It arose from discussion and editing over beers by several engineers who have used AWS extensively.
* [WindowsDefenderATP-Hunting-Queries](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries)
	* This repo contains sample queries for Advanced hunting on Windows Defender Advanced Threat Protection. With these sample queries, you can start to experience Advanced hunting, including the types of data that it covers and the query language it supports. You can also explore a variety of attack techniques and how they may be surfaced through Advanced hunting.
* [DrawBridge](https://github.com/landhb/DrawBridge)
	* A layer 4 Single Packet Authentication (SPA) Module, used to conceal TCP ports on public facing machines and add an extra layer of security.
* [OpenPasswordFilter](https://github.com/jephthai/OpenPasswordFilter)
	* An open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords.
* [PE-sieve](https://github.com/hasherezade/pe-sieve)
	* PE-sieve scans a given process, searching for the modules containing in-memory code modifications. When found, it dumps the modified PE.
* [ClrGuard](https://github.com/endgameinc/ClrGuard)
	* ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes. ClrGuard leverages a simple appInit DLL (ClrHook32/64.dll) in order to load into all CLR/.NET processes. From there, it performs an in-line hook of security critical functions. Currently, the only implemented hook is on the native LoadImage() function. When events are observed, they are sent over a named pipe to a monitoring process for further introspection and mitigation decision.
* [Auditing Security Events - WCF - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/auditing-security-events)
* [Windows Security Log Events - ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
* [Hunting-Newly-Registered-Domains](https://github.com/gfek/Hunting-New-Registered-Domains)
	* The hnrd.py is a python utility for finding and analysing potential phishing domains used in phishing campaigns targeting your customers. This utility is written in python (2.7 and 3) and is based on the analysis of the features below by consuming a free daily list provided by the Whoisds site.
* [Powershell Download Cradles - Matthew Green](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)









------------
## Design



------------
## DFIR




------------
## Disclosure





------------
## Documentation/Technical writing

* [Vulnreport](https://github.com/Salesforce/Vulnreport)
	* Vulnreport is a platform for managing penetration tests and generating well-formatted, actionable findings reports without the normal overhead that takes up security engineer's time. The platform is built to support automation at every stage of the process and allow customization for whatever other systems you use as part of your pentesting process.
* [Pocuito](https://github.com/tunnelshade/pocuito)
	* A tiny chrome extension to record and replay your web application proof-of-concepts. Replaying PoCs from bug tracker written steps is a pain most of the time, so just record the poc, distribute and replay it whenever necessary without much hassle.





------------
## Drones




------------
## Embedded Devices/Hardware (Including Printers & PoS & IoS)

* [CPU security bugs caused by speculative execution](https://github.com/marcan/speculation-bugs)
	* This repo is an attempt to collect information on the class of information disclosure vulnerabilities caused by CPU speculative execution that were disclosed on January 3rd, 2018.
* [OWASP Embedded Application Security](https://www.owasp.org/index.php/OWASP_Embedded_Application_Security)
	* [Live Copy](https://scriptingxss.gitbooks.io/embedded-appsec-best-practices/)





------------
## Exfiltration







------------
## Exploit Dev

* [Low Level Exploits - hugh pearse](https://dl.packetstormsecurity.net/papers/presentations/Low-Level-Exploits.pdf)
* [credssp](https://github.com/preempt/credssp)
	* This is a poc code for exploiting CVE-2018-0886. 
* [Getting Cozy with Exploit Development - mallardlabs](https://blog.mallardlabs.com/getting-cozy-with-exploit-development/)



------------
## Forensics 
* [aws_ir](https://github.com/ThreatResponse/aws_ir)
	* Python installable command line utility for mitigation of instance and key compromises.





------------
## Fuzzing/Bug Hunting

* [Vulnerabilities 101 : How to Launch or Improve Your  Vulnerability Research Game - Joshua Drake, Steve Christey Coley](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Drake-Christey-Vulnerabilities-101-UPDATED.pdf)
* [Bug Hunting with Static Code  Analysis - Nick Jones](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-bug-hunting-with-static-code-analysis-bsides-2016.pdf)
* [Quick introduction into SAT/SMT solvers and symbolic execution - Dennis Yurichev](https://yurichev.com/writings/SAT_SMT_draft-EN.pdf)
	* [SAT_SMT_Article](https://github.com/DennisYurichev/SAT_SMT_article)
	* SAT/SMT by example
* [XDiFF](https://github.com/IOActive/XDiFF)
	* XDiFF is an Extended Differential Fuzzing Framework built for finding vulnerabilities in software. It collects as much data as possible from different executions an then tries to infer different potential vulnerabilities based on the different outputs obtained. The fuzzer uses Python and runs on multiple OSs (Linux, Windows, OS X, and Freebsd). Its main goal is to detect issues based on diffential fuzzing aided with the extended capabilities to increase coverage. Still, it will found common vulnerabilities based on hangs and crashes, allowing to attach a memory debugger to the fuzzing sessions.




------------
## Game Hacking
* [Fabien Sanglard's Website](http://fabiensanglard.net/)
* [Nocash PSX Emulator Specifications](http://problemkaputt.de/psx-spx.htm)
* [Introduction to Server Side Emulation - Corilian(2006)](http://cellframework.sourceforge.net/uploads/Introduction%20to%20Server%20Side%20Emulation.pdf)



------------
## Honeypots(It's in Malware)

* [Portspoof](https://drk1wi.github.io/portspoof/)
	*  The Portspoof program primary goal is to enhance your systems security through a set of new camouflage techniques. As a result of applying them your attackers' port scan result will become entirely mangled and to very significant extent meaningless. 
		* Opens all ports, hosts seemingly legitimate services on each.
* [Honeytrap](https://github.com/honeytrap/honeytrap)
	* Honeytrap is an extensible and opensource system for running, monitoring and managing honeypots.




------------
## ICS/SCADA




------------
## Interesting Things/Miscellaneous

* [The XY Problem](http://xyproblem.info/)
	* The XY problem is asking about your attempted solution rather than your actual problem. This leads to enormous amounts of wasted time and energy, both on the part of people asking for help, and on the part of those providing help.
* [The AZ Problem](http://azproblem.info/)
	* This website introduces the AZ Problem: a generalization of the XY Problem. To wit, if we agree that the XY Problem is a problem, than the AZ Problem is a metaproblem. And while the XY Problem is often technical, the AZ Problem is procedural. The AZ Problem is when business requirements are misunderstood or decontextualized. These requirements end up being the root cause of brittle, ill-suited, or frivolous features. An AZ Problem will often give rise to several XY Problems. 
* [scrape-twitter](https://github.com/sebinsua/scrape-twitter)
	* Access Twitter data without an API key









------------
## Lockpicking





------------
## Malware

* [gscript](https://github.com/gen0cide/gscript)
	* Scriptable dynamic runtime execution of malware





------------
## Network Scanning and Attacks

* [Attacks Against Windows PXE Boot Images - Thomas Elling](https://blog.netspi.com/attacks-against-windows-pxe-boot-images/)
* [WSUSpect Proxy](https://github.com/pdjstone/wsuspect-proxy)
	* This is a proof of concept script to inject 'fake' updates into non-SSL WSUS traffic. It is based on the BlackHat USA 2015 presentation, 'WSUSpect – Compromising the Windows Enterprise via Windows Update'
	- White paper: http://www.contextis.com/documents/161/CTX_WSUSpect_White_Paper.pdf
	- Slides: http://www.contextis.com/documents/162/WSUSpect_Presentation.pdf
* [SIET - Smart Install Exploitation Toolkit](https://github.com/Sab0tag3d/SIET)
	* Cisco Smart Install is a plug-and-play configuration and image-management feature that provides zero-touch deployment for new switches. You can ship a switch to a location, place it in the network and power it on with no configuration required on the device. You can easy identify it using nmap: nmap -p 4786 -v 192.168.0.1
* [SMBrute](https://github.com/m4ll0k/SMBrute)
	* SMBrute is a program that can be used to bruteforce username and passwords of servers that are using SMB (Samba).
* [nessusporter](https://github.com/Tw1sm/nessporter)
	* Easily download entire folders of Nessus scans in the format(s) of your choosing. This script uses provided credentials to connect to a Nessus server and store a session token, which is then used for all subsquent requests.
* [SNMP Config File Injection to Shell - digi.ninja](https://digi.ninja/blog/snmp_to_shell.php)
* [Garfield](https://github.com/tunnelshade/garfield)
	* Garfield is and open source framework for scanning and exploiting Distributed Systems. The framework currently being in it's alpha stage and is undergoing rapid development.



------------
## Network/Endpoint Monitoring & Logging & Threat Hunting

* [ The Quieter You Become, the More You’re Able to (H)ELK -  Nate Guagenti, Roberto Rodriquez - BSides Colombus Ohio 2018](https://www.irongeek.com/i.php?page=videos/bsidescolumbus2018/p05-the-quieter-you-become-the-more-youre-able-to-helk-nate-guagenti-roberto-rodriquez)
	* Enabling the correct endpoint logging and centralizing the collection of different data sources has finally become a basic security standard. This allows organizations to not just increase the level of visibility, but to enhance their threat detection. Solutions such as an (Elastic) ELK stack have largely been adopted by small and large organizations for data ingestion, storage and visualization. Although, it might seem that collecting a massive amount of data is all analysts need to do their jobs, there are several challenges for them when faced with large, unstructured and often incomplete/disparate data sets. In addition to the sisyphean task of detecting and responding to adversaries there may be pitfalls with organizational funding, support, and or approval (Government). Although “everyone” is collecting logs and despite the many challenges, we will show you how to make sense of these logs in an efficient and consistent way. Specifically when it comes to Windows Event logs (ie: Sysmon, PowerShell, etc) and the ability to map fields to other logs such as Bro NSM or some other network monitoring/prevention device. This will include different Windows Event log data normalization techniques across the 1,000+ unique Event IDs and its 3,000+ unique fields. Also, proven data normalization techniques such as hashing fields/values for logs such as PowerShell, Scheduled Tasks, Command Line, and more. These implementations will show how it allows an analyst to efficiently “pivot” from an endpoint log to a NSM log or a device configuration change log. However, we will also show how an analyst can make an informed decision without degrading/hindering their investigation as well as to enhance their decision. Whether this is preventing an analyst from excluding keywords that a malicious actor may include as an “evasion” technique or adding additional analysis techniques (ie: graphing).
* [WEBCAST: Tales from the Network Threat Hunting Trenches - BHIS](https://www.blackhillsinfosec.com/webcast-tales-network-threat-hunting-trenches/)
	* In this webcast John walks through a couple of cool things we’ve found useful in some recent network hunt teams. He also shares some of our techniques and tools (like RITA) that we use all the time to work through massive amounts of data. There are lots of awesome websites that can greatly increase the effectiveness of your in network threat hunting.
* [Windows-Hunting](https://github.com/beahunt3r/Windows-Hunting)
	* The Purpose of this repository is to aid windows threat hunters to look for some common artifacts during their day to day operations.
* [process-forest](https://github.com/williballenthin/process-forest)
	* process-forest is a tool that processes Microsoft Windows EVTX event logs that contain process accounting events and reconstructs the historical process heirarchies. That is, it displays the parent-child relationships among programs. When using this tool during an incident response engagement, identifying a reverse shell process quickly leads to the processes launched by the operator, and insight into how it may be maintaining persistence.
* [Places of Interest in Stealing NetNTLM Hashes - osandamalith.com/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [Using Osquery to Detect Reverse Shells on MacOS - Chris Long](https://www.clo.ng/blog/osquery_reverse_shell/)






------------
## OSINT
* [Open Source Intelligence (OSINT) Tools & Resources - osint.link](http://osint.link/)
	* Seems pretty good.


------------
##	OS X






------------
## Passwords

* [Oracle Default Password List](http://www.petefinnigan.com/default/default_password_list.htm)
* [Mentalist](https://github.com/sc0tfree/mentalist)
	* Mentalist is a graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with Hashcat and John the Ripper.
	* [Wiki](https://github.com/sc0tfree/mentalist/wiki)







------------
## Phishing

* [Macro-less Code Exec in MSWord - Sensepost](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - Pwndizzle](https://pwndizzle.blogspot.com.es/2017/03/office-document-macros-ole-actions-dde.html)
* [ReelPhish: A Real-Time Two-Factor Phishing Tool](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html)
* [ReelPhish](https://github.com/fireeye/ReelPhish)
	* Tool page
* [Image-Cache-Logger](https://github.com/kale/image-cache-logger)
	* A simple tool to see when other services/clients like Gmail open an image and test if they are storing it within their cache.
* [Phishing with PowerPoint - BHIS](https://www.blackhillsinfosec.com/phishing-with-powerpoint/)
* [Phishing with Empire - Enigma0x3](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
* [Phishing for “Access” - rvrsh3ll's blog](http://www.rvrsh3ll.net/blog/phishing/phishing-for-access/)
* [Abusing Microsoft Word Features for Phishing: “subDoc”](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/)
* [CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler - Fireeye](https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html)
* [SwiftFilter](https://github.com/SwiftOnSecurity/SwiftFilter)
	* Exchange Transport rules using text matching and Regular Expressions to detect and enable response to basic phishing. Designed to augment EOP in Office 365.
* [Cross-Site Phishing](http://blog.obscuritylabs.com/merging-web-apps-and-red-teams/)





------------
## Physical Security









------------
## Policy & Compliance


* [HIPAA vs Security: Building security into medical purchasing decisions - infosystir](https://infosystir.blogspot.com/2018/01/hipaa-vs-security-building-security.html?m=1)
* [CSIS Critical Security Controls v7.0](https://www.auditscripts.com/free-resources/critical-security-controls/)
* [PCI SSC Cloud  Computing  Guidelines - 4/2018](https://www.pcisecuritystandards.org/pdfs/PCI_SSC_Cloud_Guidelines_v3.pdf)










------------
## Post Exploitation/Privilege Escalation/Pivoting
* [Using Parameters with InstallUtil](https://diaryofadeveloper.wordpress.com/2012/04/26/using-paramters-with-installutil/)
* [Windows Program Automatic Startup Locations(2004) BleepingComputer](https://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)
* [Syringe](https://github.com/securestate/syringe)
	* Syringe is a general purpose DLL and code injection utility for 32 and 64-bit Windows. It is capable of executing raw shellcode as well as injecting shellcode or a DLL directly into running processes.
* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence](https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/)
* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence (Part 2)](https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/)
* [Windows CMD Reference - ms](https://www.microsoft.com/en-us/download/details.aspx?id=56846)
* [DAMP](https://github.com/HarmJ0y/DAMP)
	* This project contains several files that implement host-based security descriptor "backdoors" that facilitate the abuse of various remotely accessible services for arbitrary trustees/security principals.
* [Password spraying using AWS Lambda for IP rotation](https://github.com/ustayready/CredKing)
* [Get-GPTrashFire: Identifiying and Abusing Vulnerable Configuraitons in MS AD Group Policy](https://github.com/l0ss/Get-GPTrashfire/blob/master/Get-GPTrashFire.pdf)
* [Invoke-SocksProxy](https://github.com/p3nt4/Invoke-SocksProxy)
	* Creates a Socks proxy using powershell.
* [Invoke-BSOD](https://github.com/peewpw/Invoke-BSOD)
	* A PowerShell script to induce a Blue Screen of Death (BSOD) without admin privileges. Also enumerates Windows crash dump settings. This is a standalone script, it does not depend on any other files.
* [MimiDbg](https://github.com/giMini/mimiDbg)
	* PowerShell oneliner to retrieve wdigest passwords from the memory
* [redsocks – transparent TCP-to-proxy redirector](https://github.com/darkk/redsocks)
	* This tool allows you to redirect any TCP connection to SOCKS or HTTPS proxy using your firewall, so redirection may be system-wide or network-wide.
* [Tunna](https://github.com/SECFORCE/Tunna)
	* Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments.
* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
* [mimikittenz](https://github.com/putterpanda/mimikittenz/)
	* mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes.
* [CHAOS](https://github.com/tiagorlampert/CHAOS)
	* Windows payload generator in go
* [Bat Armor](https://github.com/klsecservices/bat-armor)
	* Bypass PowerShell execution policy by encoding ps script into bat file.
* [Invoke-Vnc](https://github.com/klsecservices/Invoke-Vnc)
	* Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.
* [Three Simple Disguises for Evading Antivirus - BHIS](https://www.blackhillsinfosec.com/three-simple-disguises-for-evading-antivirus/)

* [LAPS - Part 1 - Rastamouse](https://rastamouse.me/2018/03/laps---part-1/)
	* The purpose of this post, is to put together a more complete end-to-end process for mapping out the LAPS configuration in a domain.
* [LAPS - Part 2 - Rastamouse])(https://rastamouse.me/2018/03/laps---part-2/)
	* In this part, we’ll look at various ways LAPS can be abused for persistence purposes.
* [Escalating Privileges with CylancePROTECT - atredis](https://www.atredis.com/blog/cylance-privilege-escalation-vulnerability)
* [GoFetch](https://github.com/GoFetchAD/GoFetch)
	* GoFetch is a tool to automatically exercise an attack plan generated by the BloodHound application. GoFetch first loads a path of local admin users and computers generated by BloodHound and converts it to its own attack plan format. Once the attack plan is ready, GoFetch advances towards the destination according to plan step by step, by successively applying remote code execution techniques and compromising credentials with Mimikatz.
* [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
	* Cmd.exe Command Obfuscation Generator & Detection Test Harness





------------
## Programming/AppSec
* [SpotBugs](https://github.com/spotbugs/spotbugs)
	* SpotBugs is the spiritual successor of FindBugs, carrying on from the point where it left off with support of its community.
* [Graudit](https://github.com/wireghoul/graudit)
	* Graudit is a simple script and signature sets that allows you to find potential  security flaws in source code using the GNU utility grep. It's comparable to  other static analysis applications like RATS, SWAAT and flaw-finder while  keeping the technical requirements to a minimum and being very flexible.
* [cloc](https://github.com/AlDanial/cloc)
	* cloc counts blank lines, comment lines, and physical lines of source code in many programming languages.
* [Providence](https://github.com/salesforce/Providence
	* Providence is a system for code commit & bug system monitoring. It is deployed within an organization to monitor code commits for security (or other) concerns, via customizable plugins. A plugin performs logic whenever a commit occurs.
* [NodeJsScan](https://github.com/ajinabraham/NodeJsScan)
	* Static security code scanner (SAST) for Node.js applications.
* [Bandit](https://github.com/openstack/bandit)
	* Bandit is a tool designed to find common security issues in Python code. To do this Bandit processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files it generates a report.
* [Python Taint](https://github.com/python-security/pyt)
	* Static analysis of Python web applications based on theoretical foundations (Control flow graphs, fixed point, dataflow analysis)
* [Damn Small Vulnerable Web](https://github.com/stamparm/DSVW)
	* Damn Small Vulnerable Web (DSVW) is a deliberately vulnerable web application written in under 100 lines of code, created for educational purposes. It supports majority of (most popular) web application vulnerabilities together with appropriate attacks.
* [s2n](https://github.com/awslabs/s2n)
	* s2n is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority. It is released and licensed under the Apache License 2.0.
* [Application Security in a DevOps Environment - Lyft](https://eng.lyft.com/application-security-in-a-devops-environment-53092f8a6048)



------------
## Red Team/Adversary Simulation/Pentesting 

* [Powershell Github Shell](https://github.com/zlocal/Powershell-Github-Shell)
* [DogWhisperer - BloodHound Cypher Cheat Sheet (v2)](https://github.com/SadProcessor/Cheats/blob/master/DogWhispererV2.md)
* [Empire API Cheat Sheet](https://github.com/SadProcessor/Cheats/blob/master/EmpireAPI.md)
* [Build Your Own: Plugins in Empire - strikersecurity](https://strikersecurity.com/blog/empire-plugins/)
* [sneaky-creeper](https://github.com/DakotaNelson/sneaky-creeper)
	* Get your APT on using social media as a tool for data exfiltration.
* [go-deliver](https://github.com/0x09AL/go-deliver)
	* Go-deliver is a payload delivery tool coded in Go. This is the first version and other features will be added in the future.
* [DicerosBicornis](https://github.com/maldevel/dicerosbicornis)
	* A stealthy Python based Windows backdoor that uses email as a command and control server.
* [canisrufus](https://github.com/maldevel/canisrufus)
	* A stealthy Python based Windows backdoor that uses Github as a command and control server.
* [Extending BloodHound: Track and Visualize Your Compromise](https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise/)
	* Customizing BloodHound's UI and taking advantage of Custom Queries to document a compromise, find collateral spread of owned nodes, and visualize deltas in privilege gains.
* [Chameleon](https://github.com/mdsecactivebreach/Chameleon)
	* Chameleon is a tool which assists red teams in categorising their infrastructure under arbitrary categories. Currently, the tool supports arbitrary categorisation for Bluecoat, McAfee Trustedsource and IBM X-Force. However, the tool is designed in such a way that additional proxies can be added with ease.
* [WheresMyImplant](https://github.com/0xbadjuju/WheresMyImplant)
	* This WMI provider includes functions to execute commands, payloads, and Empire Agent to maintain a low profile on the host. This is related to the project PowerProvider. PowerProvider provides the deployment methods for the implant.
* [PowerProvider](https://github.com/0xbadjuju/PowerProvider/)
	* PowerProvider: A toolkit to manipulate WMI. Used with WheresMyImplant
* [Internal Red Teams and Insider Knowledge - Tim MalcomVetter](https://medium.com/@malcomvetter/internal-red-teams-and-insider-knowledge-8324555aaf40)
* [Invoke-BSOD](https://github.com/peewpw/Invoke-BSOD)
		* A PowerShell script to induce a Blue Screen of Death (BSOD) without admin privileges. Also enumerates Windows crash dump settings. This is a standalone script, it does not depend on any other files.
* [SneakyCreeper](https://strikersecurity.com/blog/sneaky-creeper-data-exfiltration-overview/)
	* A Framework for Data Exfiltration
	* [Github](https://github.com/DakotaNelson/sneaky-creeper)
* [Metasploit Domain Fronting With Microsoft Azure - chigstuff](https://chigstuff.com/blog/metasploit-domain-fronting-with-microsoft-azure/)
	


------------
## Reverse Engineering
* [A bibliography of papers related to symbolic execution](https://github.com/saswatanand/symexbib)
* [DbgShell](https://github.com/Microsoft/DbgShell)
	* A PowerShell front-end for the Windows debugger engine.
* [BOLO: Reverse Engineering — Part 1 (Basic Programming Concepts) - Daniel Bloom](https://medium.com/bugbountywriteup/bolo-reverse-engineering-part-1-basic-programming-concepts-f88b233c63b7)
* [WhatsApp Web reverse engineered](https://github.com/sigalor/whatsapp-web-reveng)
	* This project intends to provide a complete description and re-implementation of the WhatsApp Web API, which will eventually lead to a custom client. WhatsApp Web internally works using WebSockets; this project does as well.
* [BinDbg](https://github.com/kukfa/bindbg)
	* BinDbg is a Binary Ninja plugin that syncs WinDbg to Binja to create a fusion of dynamic and static analyses. It was primarily written to improve the Windows experience for Binja debugger integrations.





------------
## Rootkits
* [GrayFish rootkit analysis - artemonsecurity](https://artemonsecurity.blogspot.com/2017/05/grayfish-rootkit-analysis.html)
* [EquationDrug rootkit analysis (mstcp32.sys) - artemonsecurity](https://artemonsecurity.blogspot.com/2017/03/equationdrug-rootkit-analysis-mstcp32sys.html)
* [SharknAT&To](https://www.nomotion.net/blog/sharknatto/)
* [Diamorphine](https://github.com/alex91ar/Diamorphine)
	* Diamorphine is a LKM rootkit for Linux Kernels 2.6.x/3.x/4.x originally developed by m0nad and forked by me. This fork hides high CPU usage from tools like top, htop or other commonly used utilities, by hooking the read() syscall and modifying the buffer returning the contents for /proc/stat and /proc/loadavg. The syscall sysinfo() is also hooked, but it's not used by these tools.
* [WindowsRegistryRootkit - Cr4sh](https://github.com/Cr4sh/WindowsRegistryRootkit)
	* Kernel rootkit, that lives inside the Windows registry value data.
* [DdiMon](https://github.com/tandasat/DdiMon)
	* DdiMon is a hypervisor performing inline hooking that is invisible to a guest (ie, any code other than DdiMon) by using extended page table (EPT).  DdiMon is meant to be an educational tool for understanding how to use EPT from a programming perspective for research. To demonstrate it, DdiMon installs the invisible inline hooks on the following device driver interfaces (DDIs) to monitor activities of the Windows built-in kernel patch protection, a.k.a. PatchGuard, and hide certain processes without being detected by PatchGuard.
* [Azazel](https://github.com/chokepoint/azazel)
	* Azazel is a userland rootkit based off of the original LD_PRELOAD technique from Jynx rootkit. It is more robust and has additional features, and focuses heavily around anti-debugging and anti-detection.



------------
## SCADA / Heavy Machinery

* [Robust control system networks: how to achieve reliable control after Stuxnet / Ralph Langner.](https://catalog.princeton.edu/catalog/9908132)
* [Industrial Control Systems Pattern - opensecurityarchitecture.com](http://www.opensecurityarchitecture.org/cms/en/library/patternlandscape/293-draft-sp-023-industrial-control-systems)
* [SCADApedia](https://www.digitalbond.com/wiki)





------------
## Social Engineering





------------
## System Internals

* [Service Account best practices Part 1: Choosing a Service Account](https://4sysops.com/archives/service-account-best-practices-part-1-choosing-a-service-account/)
	* In this article you will learn the fundamentals of Windows service accounts. Specifically, we discover the options and best practices concerning the selection of a service account for a particular service application.
* [Linux Kernel Map](http://www.makelinux.net/kernel_map/)
	* Interactive map of the Linux Kernel
* [Everything You Never Wanted To Know About DLLs](http://blog.omega-prime.co.uk/2011/07/04/everything-you-never-wanted-to-know-about-dlls/)
* [The Security Descriptor Definition Language of Love (Part 1) - technet.ms](https://blogs.technet.microsoft.com/askds/2008/04/18/the-security-descriptor-definition-language-of-love-part-1/)
* [The Security Descriptor Definition Language of Love (Part 2) - technet.ms](https://blogs.technet.microsoft.com/askds/2008/05/07/the-security-descriptor-definition-language-of-love-part-2/)









------------
## Threat Modeling & Analysis



--------------
## UI









------------
## Web

* [TLS Redirection (and Virtual Host Confusion) - GrrDog](https://github.com/GrrrDog/TLS-Redirection)
	* The goal of this document is to raise awareness of a little-known group of attacks, TLS redirection / Virtual Host Confusion, and to bring all the information related to this topic together.
	* 'New' Attack type
* [Network-based Origin Confusion Attacks against HTTPS Virtual Hosting - Antoine Delignat-Lavaud, Karthikeyan Bhargavan](http://antoine.delignat-lavaud.fr/doc/www15.pdf)
* [The BEAST Wins Again: Why TLS Keeps Failing to Protect HTTP - BHUSA14](https://www.blackhat.com/docs/us-14/materials/us-14-Delignat-The-BEAST-Wins-Again-Why-TLS-Keeps-Failing-To-Protect-HTTP.pdf)
* [OWASP Testing Checklist(OTGv4)](https://github.com/tanprathan/OWASP-Testing-Checklist)
	* OWASP based Web Application Security Testing Checklist is an Excel based checklist which helps you to track the status of completed and pending test cases. This checklist is completely based on OWASP Testing Guide v 4. The OWASP Testing Guide includes a “best practice” penetration testing framework which users can implement in their own organizations and a “low level” penetration testing guide that describes techniques for testing most common web application security issues. Moreover, the checklist also contains OWASP Risk Assessment Calculator and Summary Findings template.
* [Brida](https://github.com/federicodotta/Brida)
	* Brida is a Burp Suite Extension that, working as a bridge between Burp Suite and Frida, lets you use and manipulate applications’ own methods while tampering the traffic exchanged between the applications and their back-end services/servers. It supports all platforms supported by Frida (Windows, macOS, Linux, iOS, Android, and QNX)
* [A New Era of SSRF  - Exploiting URL Parser in  Trending Programming Languages! - Orange Tsai- BHUSA17](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
* [Jwt==insecurity? - Ruxcon2018](https://www.slideshare.net/snyff/jwt-insecurity)
* [PHPGGC: PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
	* PHPGGC is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically. When encountering an unserialize on a website you don't have the code of, or simply when trying to build an exploit, this tool allows you to generate the payload without having to go through the tedious steps of finding gadgets and combining them. It can be seen as the equivalent of frohoff's ysoserial, but for PHP. Currently, the tool supports: Doctrine, Guzzle, Laravel, Magento, Monolog, Phalcon, Slim, SwiftMailer, Symfony, Yii and ZendFramework.
* [burp-suite-error-message-checks](https://github.com/ewilded/burp-suite-error-message-checks)
	* Burp Suite extension to passively scan for applications revealing server error messages
* [Browsers Gone Wild - Angelo Prado & Xiaoran Wang - BHAsia2015](https://www.youtube.com/watch?v=nsjCQlEsgW8)
	* In this talk, we will demonstrate and unveil the latest developments on browser specific weaknesses including creative new mechanisms to compromise confidentiality, successfully perform login and history detection, serve mixed content, deliver malicious ghost binaries without a C&C server, exploit cache/timing side channels to extract secrets from third-party domains, and leverage new HTML5 features to carry out more stealthy attacks. This is a practical presentation with live demos that will challenge your knowledge of the Same Origin Policy and push the limits of what is possible with today's web clients.
* [CORS Findings: Another Way to Comprehend - Ryan Leese](https://www.trustedsec.com/2018/04/cors-findings/)
* [Build Simple Restful Api With Python and Flask Part 1 - Mukhammad Ginanjar Azie](https://medium.com/python-pandemonium/build-simple-restful-api-with-python-and-flask-part-1-fae9ff66a706)
* [Introduction to RESTful APIs with Chris Wahl](https://www.youtube.com/watch?v=k00sfolsmp0&index=1&list=PL2rC-8e38bUU7Xa5kBaw0Cceo2NoI4mK-)

* [Cross-Site WebSocket Hijacking (CSWSH)](https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html)
* [How Cross-Site WebSocket Hijacking could lead to full Session Compromise](https://www.notsosecure.com/how-cross-site-websocket-hijacking-could-lead-to-full-session-compromise/)
* [XSS without HTML: Client-Side Template Injection with AngularJS](https://portswigger.net/blog/xss-without-html-client-side-template-injection-with-angularjs)
* [XSS in AngularJS video series (walkthrough) - explaining some AngularJS sandbox bypasses, which resulted in the removal of the sandbox in 1.6](https://www.reddit.com/r/angularjs/comments/557bhr/xss_in_angularjs_video_series_walkthrough/)
* [J2EEScan](https://github.com/ilmila/J2EEScan)
	* J2EEScan is a plugin for Burp Suite Proxy. The goal of this plugin is to improve the test coverage during web application penetration tests on J2EE applications.
* [Exploiting OGNL Injection - mediaservice.net](https://techblog.mediaservice.net/2016/10/exploiting-ognl-injection/)
* [Stop using JWT for sessions, part 2: Why your solution doesn't work - joepie91](http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/)
* [Hacking JSON Web Token (JWT) - Hate_401](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6)
* [On-Site Request Forgery - PortSwigger](http://blog.portswigger.net/2007/05/on-site-request-forgery.html)
* [On-site Request Forgery - cm2.pw](https://blog.cm2.pw/on-site-request-forgery/)
* [JSON Web Token Flowchart](http://cryto.net/%7Ejoepie91/blog/attachments/jwt-flowchart.png)
* [JSON Web Token Security Cheat Sheet](https://assets.pentesterlab.com/jwt_security_cheatsheet/jwt_security_cheatsheet.pdf)
* [JWT4B](https://github.com/mvetsch/JWT4B)
	* JSON Web Tokens (JWT) support for the Burp Interception Proxy. JWT4B will let you manipulate a JWT on the fly, automate common attacks against JWT and decode it for you in the proxy history. JWT4B automagically detects JWTs in the form of 'Authorization Bearer' headers as well as customizable post body parameters.
* [cloudfrunt](https://github.com/MindPointGroup/cloudfrunt)
	* A tool for identifying misconfigured CloudFront domains
* [Imagecreatefromgif-Bypass](https://github.com/JohnHoder/Imagecreatefromgif-Bypass)
	* A simple helper script to find byte sequences present in both of 2 given files. The main purpose of this is to find bytes that remain untouched after being processed with imagecreatefromgif() PHP function from GD-LIB. That is the place where a malicious PHP script can be inserted to achieve some nasty RCE.
* [Enteletaor](https://github.com/cr0hn/enteletaor)
	* Message Queue & Broker Injection tool that implements attacks to Redis, RabbitMQ and ZeroMQ.
* [How to resolve a million domains](https://idea.popcount.org/2013-11-28-how-to-resolve-a-million-domains/)
* [Astra](https://github.com/flipkart-incubator/Astra)
	* REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs. Astra can be used by security engineers or developers as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. Astra can automatically detect and test login & logout (Authentication API), so it's easy for anyone to integrate this into CICD pipeline. Astra can take API collection as an input so this can also be used for testing apis in standalone mode.
* [Cloud Security Suite](https://github.com/SecurityFTW/cs-suite)
	* One stop tool for auditing the security posture of AWS & GCP infrastructure.
* [AWS Security Audit Guidelines - docs.aws](https://docs.aws.amazon.com/general/latest/gr/aws-security-audit-guide.html)
* [CORS Findings: Another Way to Comprehend - Ryan Leese](https://www.trustedsec.com/2018/04/cors-findings/)
* [Exploiting CORS Misconfigurations for Bitcoins and Bounties- James Kettle](http://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
* [Same Origin Policy - dev.mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
* [Same Origin Policy - W3C](https://www.w3.org/Security/wiki/Same_Origin_Policy)
* [Cross-Origin Resource Sharing (CORS) - dev.mozilla](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

Relative Path Overwrite


* [Relative Path Overwrite(RPO) - TheSpanner](http://www.thespanner.co.uk/2014/03/21/rpo/)
* [A few RPO
exploitation techniques - Takeshi Terada](https://www.mbsd.jp/Whitepaper/rpo.pdf)
* [Non-Root-Relative Path Overwrite (RPO) in IIS and .Net applications - soroush.techproject](https://soroush.secproject.com/blog/tag/non-root-relative-path-overwrite/)

Mutation XSS
* [What is mutation XSS (mXSS)? - StackOverflow](https://security.stackexchange.com/questions/46836/what-is-mutation-xss-mxss)
* [How mXSS attacks change everything we believed to know so far - Mario Heiderich - OWASP AppSec EU 2013](https://www.youtube.com/watch?v=Haum9UpIQzU)
* [mXSS - TheSpanner](http://www.thespanner.co.uk/2014/05/06/mxss/)
* [Exploiting the unexploitable with lesser known browser tricks - filedescriptor](https://speakerdeck.com/filedescriptor/exploiting-the-unexploitable-with-lesser-known-browser-tricks)
* [Running Your Instance of Burp Collaborator Server - blog.fabiopires.pt](https://blog.fabiopires.pt/running-your-instance-of-burp-collaborator-server/)
* [Piercing the Veil: Server Side Request Forgery to NIPRNet access](https://web.archive.org/web/20180410080115/https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-171018bca2c3)



------------
## Wireless Stuff

* [Guide to LTE Security - NIST Special Publication 800-187](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-187.pdf)
* [RF-Capture](http://rfcapture.csail.mit.edu/)
	* RF-Capture is a device that captures a human figure through walls and occlusions. It transmits wireless signals and reconstructs a human figure by analyzing the signals' reflections. RF-Capture does not require the person to wear any sensor, and its transmitted power is 10,000 times lower than that of a standard cell-phone.
	* [Paper](http://rfcapture.csail.mit.edu/rfcapture-paper.pdf)
* [Inmarsat-C - Inmarsat](https://www.inmarsat.com/services/safety/inmarsat-c/)
* [Inmarsat-C - Wikipedia](https://en.wikipedia.org/wiki/Inmarsat-C)
* [Very-small-aperture terminal - Wikipedia](https://en.wikipedia.org/wiki/Very-small-aperture_terminal)
* [BGAN](https://www.inmarsat.com/service/bgan/)
* [Broadband Global Area Network - Wikipedia](https://en.wikipedia.org/wiki/Broadband_Global_Area_Network)
* [SwiftBroadband - inmarsat](https://www.inmarsat.com/service-collection/swiftbroadband/)
* [SwiftBroadband - Wikipedia](https://en.wikipedia.org/wiki/SwiftBroadband)
* [FleetBroadband](https://www.inmarsat.com/service/fleetbroadband/)
* [Fleet Broadband - Wikipedia](https://en.wikipedia.org/wiki/FleetBroadband)








### Container Security

* [nsjail](https://github.com/google/nsjail)
	* A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)
* [docker-bench-security](https://github.com/docker/docker-bench-security)
	* The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production.	
* [Controlling access to user namespaces - lwn.net](https://lwn.net/Articles/673597/)
* [Namespaces in operation, part 1: namespaces overview - lwn.net](https://lwn.net/Articles/531114/#series_index)
* [Linux LXC vs FreeBSD jail - Are there any notable differences between LXC (Linux containers) and FreeBSD's jails in terms of security, stability & performance? - unix.StackExchange](https://unix.stackexchange.com/questions/127001/linux-lxc-vs-freebsd-jail)
* [LXC - Wikipedia](https://en.wikipedia.org/wiki/LXC)
* [Process Containers - lwn.net](https://lwn.net/Articles/236038/)
* [cgroups - wikipedia](https://en.wikipedia.org/wiki/Cgroups)
* [Everything you need to know about Jails - bsdnow.tv](http://www.bsdnow.tv/tutorials/jails)
* [Jails - FreeBSD handbook](https://www.freebsd.org/doc/handbook/jails.html)
* [ezjail – Jail administration framework](https://erdgeist.org/arts/software/ezjail/)



https://github.com/alexplaskett/QNXSecurity
https://github.com/scriptingxss/embeddedappsec