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









------------
## Anonymity/OpSec/Privacy


------------
## Basic Security Info
* [Common misconfigurations that lead to a breach - Justin Tharpe](https://www.youtube.com/watch?v=fI3mycr5cPg)
* [Mozilla Enterprise Information Security](https://infosec.mozilla.org/)


------------
## BIOS/UEFI/Firmware/Low Level Attacks











------------
## Building a Lab 

* [Pentesting In The Cloud - primalsecurity](http://www.primalsecurity.net/pentesting-in-the-cloud/)
	* Instantiating a Kali linux on Amazons EC2



------------
## Car Hacking


------------
## Cheat Sheets





------------
## Conferences







------------
## Courses


* [Security_Ninjas_AppSec_Training](https://github.com/opendns/Security_Ninjas_AppSec_Training)
	* OpenDNS application security training program. This hands-on training lab consists of 10 fun real world like hacking exercises, corresponding to each of the OWASP Top 10 vulnerabilities. Hints and solutions are provided along the way. Although the backend for this is written in PHP, vulnerabilities would remain the same across all web based languages, so the training would still be relevant even if you don’t actively code in PHP.



------------
## Cryptography & Timing Attacks (& CryptoCurrencies)

* [TLS 1.3 Implementations](https://github.com/tlswg/tls13-spec/wiki/Implementations)
* [Encryption 101, RSA 001 (The maths behind it) - IoTh1nkN0t](https://0x00sec.org/t/encryption-101-rsa-001-the-maths-behind-it/1921)
* [ROBOT Attack](https://robotattack.org/)
	* ROBOT is the return of a 19-year-old vulnerability that allows performing RSA decryption and signing operations with the private key of a TLS server. In 1998, Daniel Bleichenbacher discovered that the error messages given by SSL servers for errors in the PKCS #1 v1.5 padding allowed an adaptive-chosen ciphertext attack; this attack fully breaks the confidentiality of TLS when used with RSA encryption. We discovered that by using some slight variations this vulnerability can still be used against many HTTPS hosts in today's Internet.
* [Discovering Smart Contract Vulnerabilities with GOATCasino - NCCGroup](https://www.nccgroup.trust/us/our-research/discovering-smart-contract-vulnerabilities-with-goatcasino/?style=Cyber+Security)




------------
## CTF




-------------
## Darknets





------------
## Data Analysis/Visualization

* [NewsDiffs](https://github.com/ecprice/newsdiffs)
	* Automatic scraper that tracks changes in news articles over time.
* [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths)
	* Control paths in Active Directory are an aggregation of "control relations" between entities of the domain (users, computers, groups, GPO, containers, etc.) which can be visualized as graphs (such as above) and whose purpose is to answer questions like "Who can get 'Domain Admins' privileges ?" or "What resources can a user control ?" and even "Who can read the CEO's emails ?".



-----------------
## Defense

* [PPRT](https://github.com/MSAdministrator/PPRT)
	* This module is used to report phishing URLs to their WHOIS/RDAP abuse contact information.
* [Tracking Newly Registered Domains - SANS](https://isc.sans.edu/forums/diary/Tracking+Newly+Registered+Domains/23127/)
* [Domain Password Audit Tool (DPAT)]( )
	* This is a python script that will generate password use statistics from password hashes dumped from a domain controller and a password crack file such as hashcat.potfile generated from the Hashcat tool during password cracking. The report is an HTML report with clickable links.
	* [Tutorial Video & Demo](https://github.com/clr2of8/DPAT)
* [Azure AD and ADFS best practices: Defending against password spray attacks](https://cloudblogs.microsoft.com/enterprisemobility/2018/03/05/azure-ad-and-adfs-best-practices-defending-against-password-spray-attacks/)
* [teleport](https://github.com/gravitational/teleport)
	* Modern SSH server for clusters and teams. 
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer)
	* Investigate malicious Windows logon by visualizing and analyzing Windows event log
* [New feature in Office 2016 can block macros and help prevent infection (2016)](https://cloudblogs.microsoft.com/microsoftsecure/2016/03/22/new-feature-in-office-2016-can-block-macros-and-help-prevent-infection/?source=mmpc)
* [Mercure](https://github.com/synhack/mercure)
	* Mercure is a tool for security managers who want to teach their colleagues about phishing.
* [Respounder](https://github.com/codeexpress/respounder)
	* Respounder sends LLMNR name resolution requests for made-up hostnames that do not exist. In a normal non-adversarial network we do not expect such names to resolve. However, a responder, if present in the network, will resolve such queries and therefore will be forced to reveal itself.
https://www.auditscripts.com/free-resources/critical-security-controls/
* [AWS Lambda - IAM Access Key Disabler](https://github.com/te-papa/aws-key-disabler)
	* The AWS Key disabler is a Lambda Function that disables AWS IAM User Access Keys after a set amount of time in order to reduce the risk associated with old access keys.
* [Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields - docs.ms](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440)
* [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
* [Software Restriction Policies - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies)
	* This topic for the IT professional describes Software Restriction Policies (SRP) in Windows Server 2012 and Windows 8, and provides links to technical information about SRP beginning with Windows Server 2003.
* [Detecting Lateral Movement through Tracking Event Logs - JPCERTCC](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)
* [Detecting Lateral Movements in Windows Infrastructure - CERT-EU](http://cert.europa.eu/static/WhitePapers/CERT-EU_SWP_17-002_Lateral_Movements.pdf)


* [The Evolution of Protected Processes – Part 1: Pass-the-Hash Mitigations in Windows 8.1](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)
* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.crowdstrike.com/blog/evolution-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and/) 
* [Protected Processes Part 3: Windows PKI Internals (Signing Levels, Scenarios, Signers, Root Keys, EKUs & Runtime Signers)](https://www.crowdstrike.com/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)




------------
## Design



------------
## DFIR

* [Margarita Shotgun](https://github.com/ThreatResponse/margaritashotgun)
	* Python Remote Memory Aquisition
* [Basics of Incident Handling - Josh Rickard](https://msadministrator.github.io/presentations/basics-of-incident-handling.html)
https://medium.com/@sroberts/introduction-to-dfir-d35d5de4c180



------------
## Disclosure





------------
## Documentation/Technical writing
* [Pentest/Red Team Offering Documents - mubix](https://drive.google.com/drive/folders/0ByiDshWJ_PnZdnJZQ0h3MWZyRUk)





------------
## Drones




------------
## Embedded Devices/Hardware (Including Printers & PoS & IoS)




------------
## Exfiltration







------------
## Exploit Dev


* [Shellen](https://github.com/merrychap/shellen)
	* Shellen is an interactive shellcoding environment. If you want a handy tool to write shellcodes, then shellen may be your friend. Shellen can also be used as an assembly or disassembly tool. keystone and capstone engines are used for all of shellen's operations. Shellen only works on python3. python2 support may appear in the future.
* [PoC for CVE-2018-0802 And CVE-2017-11882](https://github.com/Ridter/RTF_11882_0802)
* [Linux Vulnerabilities Windows Exploits: Escalating Privileges with WSL - BlueHat IL 2018 - Saar Amar](http://www.bluehatil.com/files/Linux%20Vulnerabilities%2C%20Windows%20Exploits%20-%20Escalating%20Privileges%20with%20WSL.PDF)
	* [Slides](http://www.bluehatil.com/files/Linux%20Vulnerabilities%2C%20Windows%20Exploits%20-%20Escalating%20Privileges%20with%20WSL.PDF)
* [explodingcan](https://github.com/danigargu/explodingcan)
	* An implementation of NSA's ExplodingCan exploit in Python
* [CVE-2017-10271 identification and exploitation. Unauthenticated Weblogic RCE.](https://github.com/c0mmand3rOpSec/CVE-2017-10271)
* [Chimay-Red](https://github.com/BigNerd95/Chimay-Red)
	* Working POC of Mikrotik exploit from Vault 7 CIA Leaks
	* [Writeup](https://github.com/BigNerd95/Chimay-Red/blob/master/docs/ChimayRed.pdf)





------------
## Forensics








------------
## Fuzzing/Bug Hunting

* [Microsoft Patch Analysis for Exploitation - Stephen Sims](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t111-microsoft-patch-analysis-for-exploitation-stephen-sims)
	* Since the early 2000's Microsoft has distributed patches on the second Tuesday of each month. Bad guys, good guys, and many in-between compare the newly released patches to the unpatched version of the files to identify the security fixes. Many organizations take weeks to patch and the faster someone can reverse engineer the patches and get a working exploit written, the more valuable it is as an attack vector. Analysis also allows a researcher to identify common ways that Microsoft fixes bugs which can be used to find 0-days. Microsoft has recently moved to mandatory cumulative patches which introduces complexity in extracting patches for analysis. Join me in this presentation while I demonstrate the analysis of various patches and exploits, as well as the best-known method for modern patch extraction.
* [Fixer](https://github.com/SECFORCE/fixer)
	* Fixer™ is a Python command-line tool which simplifies and enhances FIX security testing by delivering a more customisable and automated Fix fuzzing process.
* [Droid Application Fuzz Framework](https://github.com/ajinabraham/Droid-Application-Fuzz-Framework)
	* Droid Application Fuzz Framework (DAFF) helps you to fuzz Android Browsers and PDF Readers for memory corruption bugs in real android devices. You can use the inbuilt fuzzers or import fuzz files from your own custom fuzzers. DAFF consist of inbuilt fuzzers and crash monitor. It currently supports fuzzing the following applications:
* [bounty-monitor](https://github.com/nashcontrol/bounty-monitor)
	* Leverage certificate transparency live feed to monitor for newly issued subdomain certificates (last 90 days, configurable), for domains participating in bug bounty programs.
* [MFFA - Media Fuzzing Framework for Android (Stagefright fuzzer)](https://github.com/fuzzing/MFFA)
	* The main idea behind this project is to create corrupt but structurally valid media files, direct them to the appropriate software components in Android to be decoded and/or played and monitor the system for potential issues (i.e system crashes) that may lead to exploitable vulnerabilities. Custom developed Python scripts are used to send the malformed data across a distributed infrastructure of Android devices, log the findings and monitor for possible issues, in an automated manner. The actual decoding of the media files on the Android devices is done using the Stagefright command line interface. The results are sorted out, in an attempt to find only the unique issues, using a custom built triage mechanism.






------------
## Game Hacking






------------
## Honeypots

* [honeyLambda](https://github.com/0x4D31/honeyLambda)
	* honeyλ allows you to create and monitor fake HTTP endpoints automatically. You can then place these URL honeytokens in e.g. your inbox, documents, browser history, or embed them as {hidden} links in your web pages (Note: honeybits can be used for spreading breadcrumbs across your systems to lure the attackers toward your traps). Depending on how and where you implement honeytokens, you may detect human attackers, malicious insiders, content scrapers, or bad bots. This application is based on Serverless framework and can be deployed in different cloud providers such as Amazon Web Services (AWS), Microsoft Azure, IBM OpenWhisk or Google Cloud (Only tested on AWS; the main function may need small changes to support other providers). If your cloud provider is AWS, it automatically creates HTTP endpoints using Amazon API Gateway and then starts monitoring the HTTP endpoints using honeyλ Lambda function.
* [Project SPACECRAB](https://bitbucket.org/asecurityteam/spacecrab)
	* Bootstraps an AWS account with everything you need to generate, mangage, and distribute and alert on AWS honey tokens. Made with breakfast roti by the Atlassian security team.

------------
## ICS/SCADA


------------
## Interesting Things/Miscellaneous

* [The Marketing Behind MongoDB](https://www.nemil.com/mongo/3.html)



------------
## Lockpicking





------------
## Malware

* [Noriben - The Portable Sandbox System - ghettoforensics.com](http://www.ghettoforensics.com/2013/04/noriben-your-personal-portable-malware.html)
	* Noriben is a Python-based script that works in conjunction with SysInternals Procmon to automatically collect, analyze, and report on runtime indicators of malware and suspicious system behavior. In a nutshell, it allows you to run your malware, hit a keypress, and get a simple text report of the system's activity after running an attack.
* [Noriben Malware Analysis Sandbox](https://github.com/Rurik/noriben)
	* Noriben is a Python-based script that works in conjunction with Sysinternals Procmon to automatically collect, analyze, and report on runtime indicators of malware. In a nutshell, it allows you to run your malware, hit a keypress, and get a simple text report of the sample's activities. Noriben allows you to not only run malware similar to a sandbox, but to also log system-wide events while you manually run malware in ways particular to making it run. For example, it can listen as you run malware that requires varying command line options, or user interaction. Or, to watch the system as you step through malware in a debugger.
* [metasearch-public](https://github.com/PaulSec/metasearch-public?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=fbefaaabb99249989456a6e322557550&fl=4&uid=150127534&nid=244+276893704)
	* Purpose: stop searching for sample hashes on 10 different sites. This is a simple Python3 Flask application running on port 5000 interacting with various platforms (TBC) and caching the results in a Redis database for faster responses.









------------
## Network Scanning and Attacks

* [How I Identified 93k Domain-Frontable CloudFront Domains](https://www.peew.pw/blog/2018/2/22/how-i-identified-93k-domain-frontable-cloudfront-domains)

* [icebreaker](https://github.com/DanMcInerney/icebreaker/blob/master/README.md)
	* Break the ice with that cute Active Directory environment over there. When you're cold and alone staring in at an Active Directory party but don't possess even a single AD credential to join the fun, this tool's for you. Sequentially automates 5 internal network attacks against Active Directory to deliver you plaintext credentials. Use the --auto option to automatically acquire domain admin privileges after gaining a foothold.
* [IP Cameras Default Passwords Directory](https://ipvm.com/reports/ip-cameras-default-passwords-directory)
* [Gaining Domain Admin from Outside Active Directory - markitzeroday](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
* [Nmap XML Parser Documentation](https://nmap-parser.readthedocs.io/en/latest/)
* [Evasions used by The Shadow Brokers' Tools DanderSpritz and DoublePulsar (Part 2 of 2) - forcepoint](https://blogs.forcepoint.com/security-labs/evasions-used-shadow-brokers-tools-danderspritz-and-doublepulsar-part-2-2)
* [cpscam](https://github.com/codewatchorg/cpscam)
	* Bypass captive portals by impersonating inactive users








------------
## Network/Endpoint Monitoring & Logging & Threat Hunting





------------
## OSINT

* [gitleaks](https://github.com/zricethezav/gitleaks)
	*  Searches full repo history for secrets and keys
IntelTechniques OSINT Flowcharts
* [Email Address](https://inteltechniques.com/data/Email.png)
* [Domain Name](https://inteltechniques.com/data/Domain.png)
* [Real Name](https://inteltechniques.com/data/Real%20Name.png)
* [Telephone #](https://inteltechniques.com/data/Telephone.png)
* [Location](https://inteltechniques.com/data/location.png)
* [User Name](https://inteltechniques.com/data/Username.png)


------------
##	OS X






------------
## Passwords









------------
## Phishing

* [Macro-less Code Exec in MSWord - Sensepost](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - Pwndizzle](https://pwndizzle.blogspot.com.es/2017/03/office-document-macros-ole-actions-dde.html)
* [ReelPhish: A Real-Time Two-Factor Phishing Tool](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html)
* [ReelPhish](https://github.com/fireeye/ReelPhish)
	* Tool page
* [Image-Cache-Logger](https://github.com/kale/image-cache-logger)
	* A simple tool to see when other services/clients like Gmail open an image and test if they are storing it within their cache.


------------
## Physical Security









------------
## Policy & Compliance

https://www.open-scap.org/tools/openscap-base/#documentation
https://cloudsecurityalliance.org/group/cloud-controls-matrix/#_overview
* [FATF blacklist - Wikipedia](https://en.wikipedia.org/wiki/FATF_blacklist)
	* The FATF blacklist was the common shorthand description for the Financial Action Task Force list of "Non-Cooperative Countries or Territories" (NCCTs) issued since 2000, which it perceived to be non-cooperative in the global fight against money laundering and terrorist financing.


------------
## Post Exploitation/Privilege Escalation/Pivoting

* [NetRipper](https://github.com/NytroRST/NetRipper)
	* NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.
* [jsmpeg-vnc](https://github.com/phoboslab/jsmpeg-vnc)
	* A low latency, high framerate screen sharing server for Windows and client for browsers
* [docker-layer2-icc](https://github.com/brthor/docker-layer2-icc)
	* Demonstrating that disabling ICC in docker does not block raw packets between containers.
* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
	* SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. SharpShooter is capable of creating payloads in a variety of formats, including HTA, JS, VBS and WSF. It leverages James Forshaw's DotNetToJavaScript tool to invoke methods from the SharpShooter DotNet serialised object. Payloads can be retrieved using Web or DNS delivery or both; SharpShooter is compatible with the MDSec ActiveBreach PowerDNS project. Alternatively, stageless payloads with embedded shellcode execution can also be generated for the same scripting formats.
* [WsgiDAV](https://github.com/mar10/wsgidav)
	* WsgiDAV is a generic WebDAV server written in Python and based on WSGI.
* [Malicious Installer Plugins - specterops](https://posts.specterops.io/malicious-installer-plugins-6e30991bb529)
* [net-creds](https://github.com/DanMcInerney/net-creds)
	* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification.
* [3snake](https://github.com/blendin/3snake)
	* Targeting rooted servers, reads memory from sshd and sudo system calls that handle password based authentication. Doesn't write any memory to the traced processes. Spawns a new process for every sshd and sudo command that is run. Listens for the proc event using netlink sockets to get candidate processes to trace. When it receives an sshd or sudo process ptrace is attached and traces read and write system calls, extracting strings related to password based authentication.
* [DSCompromised: A Windows DSC Attack Framework - Matt Hastings, Ryan Kazanciyan - BH Asia16](https://www.blackhat.com/docs/asia-16/materials/asia-16-Kazanciyan-DSCompromised-A-Windows-DSC-Attack-Framework.pdf)
* [PowerShellDSCLateralMovement.ps1](https://gist.github.com/mattifestation/bae509f38e46547cf211949991f81092)
* [Passhunt](https://github.com/Viralmaniar/Passhunt/blob/master/README.md)
	* Passhunt is a simple tool for searching of default credentials for network devices, web applications and more. Search through 523 vendors and their 2084 default passwords.
* [Orchard](https://github.com/its-a-feature/Orchard)
	* Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS' JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web.
* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
	* Payload Generation Framework
* [Windows Credential Guard & Mimikatz - nviso](https://blog.nviso.be/2018/01/09/windows-credential-guard-mimikatz/)
* [Pazuzu](https://github.com/BorjaMerino/Pazuzu)
	* Pazuzu is a Python script that allows you to embed a binary within a precompiled DLL which uses reflective DLL injection. The goal is that you can run your own binary directly from memory. This can be useful in various scenarios.	
* [Demiguise](https://github.com/nccgroup/demiguise)
	* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place, and (if you use environmental keying) to avoid it being sandboxed.
* [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
	* Linux privilege escalation auditing tool
* [Windows Privilege Escalation Guide - sploitspren(2018)](https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
	* Nice methodology/walk through of Windows PrivEsc methods and tactics
* [linuxprivchecker.py --- A Linux Privilege Escalation Checker for Python 2.7 and 3.x](https://github.com/oschoudhury/linuxprivchecker)
	* This script is intended to be executed locally on a Linux machine, with a Python version of 2.7 or 3.x, to enumerate basic system info and search for common privilege escalation vectors. Currently at version 2. - Fork of the ever popular scrip that added support for Python3
* [Testing User Account Control (UAC) on  Windows 10 - Ernesto Fernández Provecho](https://www.researchgate.net/publication/319454675_Testing_UAC_on_Windows_10)
* [DPAPI Primer for Pentesters - webstersprodigy](https://webstersprodigy.net/2013/04/05/dpapi-primer-for-pentesters/)
* [Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
	* Great explanation of Process Hollowing
* [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths)
	* Control paths in Active Directory are an aggregation of "control relations" between entities of the domain (users, computers, groups, GPO, containers, etc.) which can be visualized as graphs (such as above) and whose purpose is to answer questions like "Who can get 'Domain Admins' privileges ?" or "What resources can a user control ?" and even "Who can read the CEO's emails ?".
* [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
	* This repository provides a few techniques and scripts regarding the impact of Microsoft Exchange deployment on Active Directory security. This is a side project of [AD-Control-Paths](https://github.com/ANSSI-FR/AD-control-paths), an AD permissions auditing project to which I recently added some Exchange-related modules.
* [systemd (systemd-tmpfiles) < 236 - 'fs.protected_hardlinks=0' Local Privilege Escalation](https://www.exploit-db.com/exploits/43935/)
* [PCredz](https://github.com/lgandx/PCredz)
	* This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
* [DccwBypassUAC](https://github.com/L3cr0f/DccwBypassUAC)
	* This exploit abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. It supports "x86" and "x64" architectures. Moreover, it has been successfully tested on Windows 8.1 9600, Windows 10 14393, Windows 10 15031 and Windows 10 15062. 
* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
	* A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.





------------
## Programming/AppSec
* [Spellbook of Modern Web Dev](https://github.com/dexteryy/spellbook-of-modern-webdev)
	* A Big Picture, Thesaurus, and Taxonomy of Modern JavaScript Web Development
* [JWT Handbook - Auth0](https://auth0.com/resources/ebooks/jwt-handbook)
* [RESTful API Best Practices and Common Pitfalls - Spencer Schneidenbach](https://medium.com/@schneidenbach/restful-api-best-practices-and-common-pitfalls-7a83ba3763b5)
* [White House Web API Standards](https://github.com/WhiteHouse/api-standards)
	* This document provides guidelines and examples for White House Web APIs, encouraging consistency, maintainability, and best practices across applications. White House APIs aim to balance a truly RESTful API interface with a positive developer experience (DX).
* [HTTP API Design Guide](https://github.com/interagent/http-api-design)
	* HTTP API design guide extracted from work on the [Heroku Platform API](https://devcenter.heroku.com/articles/platform-api-reference)
* [Security Guide for Developers](https://github.com/FallibleInc/security-guide-for-developers)





------------
## Red Team/Adversary Simulation/Pentesting 

https://bneg.io/2017/11/06/automated-empire-infrastructure/
https://www.slideshare.net/JeremyJohnson166/advanced-weapons-training-for-the-empire

* [RedTrooperFM - Empire Module Wiki](https://github.com/SadProcessor/Cheats/blob/master/RedTrooperFM.md)
	* A one page Wiki for all your Empire RTFM needs...
* [Red Team Laptop & Infrastructure (pt 1: Architecture) - hon1nbo](https://hackingand.coffee/2018/02/assessment-laptop-architecture/)
* [Aggressor 101: Unleashing Cobalt Strike for Fun and Profit](https://medium.com/@001SPARTaN/aggressor-101-unleashing-cobalt-strike-for-fun-and-profit-879bf22cea31)

* [Introducing the Adversary Resilience Methodology — Part One - specterops](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
* [Introducing the Adversary Resilience Methodology — Part Two](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
* [Red Team Techniques for Evading, Bypassing, and Disabling MS Advanced Threat Protection and Advanced Threat Analytics - Chris Thompson](https://www.youtube.com/watch?v=2HNuzUuVyv0&app=desktop)
	* [Slides](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
	* Windows Defender Advanced Threat Protection is now available for all Blue Teams to utilize within Windows 10 Enterprise and Server 2012/16, which includes detection of post breach tools, tactics and techniques commonly used by Red Teams, as well as behavior analytics. 

* [Demiguise](https://github.com/nccgroup/demiguise)
	* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place, and (if you use environmental keying) to avoid it being sandboxed.
* [powersap - Powershell SAP assessment tool](https://github.com/airbus-seclab/powersap)
	* PowerSAP is a simple powershell re-implementation of popular & effective techniques of all public tools such as Bizploit, Metasploit auxiliary modules, or python scripts available on the Internet. This re-implementation does not contain any new or undisclosed vulnerability.
* [Metta](https://github.com/uber-common/metta)
	* An information security preparedness tool to do adversarial simulation. This project uses Redis/Celery, python, and vagrant with virtualbox to do adversarial simulation. This allows you to test (mostly) your host based instrumentation but may also allow you to test any network based detection and controls depending on how you set up your vagrants. The project parses yaml files with actions and uses celery to queue these actions up and run them one at a time without interaction.

* [google_socks](https://github.com/lukebaggett/google_socks)
	* A proof of concept demonstrating the use of Google Drive for command and control.
* [TTP: Domain Fronting with Metasploit and Meterpreter - beyondbinary](https://beyondbinary.io/articles/domain-fronting-with-metasploit-and-meterpreter/)
* [Alibaba CDN Domain Fronting - Vincent Yiu](https://medium.com/@vysec.private/alibaba-cdn-domain-fronting-1c0754fa0142)
* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
	* SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. SharpShooter is capable of creating payloads in a variety of formats, including HTA, JS, VBS and WSF. It leverages James Forshaw's DotNetToJavaScript tool to invoke methods from the SharpShooter DotNet serialised object. Payloads can be retrieved using Web or DNS delivery or both; SharpShooter is compatible with the MDSec ActiveBreach PowerDNS project. Alternatively, stageless payloads with embedded shellcode execution can also be generated for the same scripting formats.
* [Ares](https://github.com/sweetsoftware/Ares)
	* Ares is a Python Remote Access Tool.
* [demiguise](https://github.com/nccgroup/demiguise)
	* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place, and (if you use environmental keying) to avoid it being sandboxed.





------------
## Reverse Engineering

* [Panopticon](https://github.com/das-labor/panopticon)
	* Panopticon is a cross platform disassembler for reverse engineering written in Rust. It can disassemble AMD64, x86, AVR and MOS 6502 instruction sets and open ELF files. Panopticon comes with Qt GUI for browsing and annotating control flow graphs,

* [linux-re-101](https://github.com/michalmalik/linux-re-101)
	* Cool resource relating to REing linux related things. Structured similar to this reference
* [JavaScript AntiDebugging Tricks - x-c3ll](https://x-c3ll.github.io/posts/javascript-antidebugging/)
* [Reversing Objective-C Binaries With the REobjc Module for IDA Pro - Todd Manning](https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro)
* [oleviewdotnet](https://github.com/tyranid/oleviewdotnet)
	* OleViewDotNet is a .NET 4 application to provide a tool which merges the classic SDK tools OleView and Test Container into one application. It allows you to find COM objects through a number of different views (e.g. by CLSID, by ProgID, by server executable), enumerate interfaces on the object and then create an instance and invoke methods. It also has a basic container to attack ActiveX objects to so you can see the display output while manipulating the data. 




------------
## Rootkits

https://github.com/chokepoint/azazel






------------
## SCADA / Heavy Machinery





------------
## Social Engineering





------------
## System Internals

* [About Dynamic Data Exchange - msdn.ms](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774%28v=vs.85%29.aspx)
* [Windows Data Protection - msdn.ms](https://msdn.microsoft.com/en-us/library/ms995355.aspx)
* [Dynamic Data Exchange - msdn.ms](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648711(v=vs.85).aspx)
	* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML).



------------
## Threat Modeling & Analysis

* [Escaping the Hamster Wheel of Pain - Risk Management is Where the Confusion Is](http://www.markerbench.com/blog/2005/05/04/Escaping-the-Hamster-Wheel-of-Pain/)


--------------
## UI









------------
## Web


https://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks/15-Keep_pokinCanJS_for_examplescript_srcjquery203minjsscriptscript

* [CloudTracker](https://github.com/duo-labs/cloudtracker)
	* CloudTracker helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.
	* [Blogpost](https://duo.com/blog/introducing-cloudtracker-an-aws-cloudtrail-log-analyzer)
* [Amazon Inspector](https://aws.amazon.com/inspector/)
	* Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS. Amazon Inspector automatically assesses applications for vulnerabilities or deviations from best practices. After performing an assessment, Amazon Inspector produces a detailed list of security findings prioritized by level of severity. These findings can be reviewed directly or as part of detailed assessment reports which are available via the Amazon Inspector console or API.
* [aws_pwn](https://github.com/dagrz/aws_pwn)
	* This is a collection of horribly written scripts for performing various tasks related to penetration testing AWS. Please don't be sad if it doesn't work for you. It might be that AWS has changed since a given tool was written or it might be that the code sux. Either way, please feel free to contribute. Most of this junk was written by Daniel Grzelak but there's been plenty of contributions, most notably Mike Fuller.
* [Practical tips for defending web applications - Zane Lackey - devops Amsterdam 2017](https://www.youtube.com/watch?v=Mae2iXUA7a4)
	* [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Lackey-Practical%20Tips-for-Defending-Web-Applications-in-the-Age-of-DevOps.pdf)
* [XSStrike](https://github.com/UltimateHackers/XSStrike)
	* XSStrike is an advanced XSS detection and exploitation suite. 
* [I Forgot Your Password: Randomness Attacks Against PHP Applications - George Argyros, Aggelos Kiayia](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.360.4033&rep=rep1&type=pdf)
	* We provide a number of practical techniques and algorithms for exploiting randomness vulnerabilities in PHP applications.We focus on the predictability of password reset tokens and demonstrate how an attacker can take over user accounts in a web application via predicting or algorithmically derandomizing the PHP core randomness generators. While our techniques are designed for the PHP language, the principles behind our techniques and our algorithms are independent of PHP and can readily apply to any system that utilizes weak randomness generators or low entropy sources. Our results include: algorithms that reduce the entropy of time variables, identifying and exploiting vulnera- bilities of the PHP system that enable the recovery or reconstruction of PRNG seeds, an experimental analysis of the Hastad-Shamir framework for breaking truncated linear variables, an optimized online Gaussian solver for large sparse linear systems, and an algorithm for recovering the state of the Mersenne twister generator from any level of truncation.  We demonstrate the gravity of our attacks via a number of case studies. Specifically, we show that a number of current widely used web applications can be broken using our tech- niques including Mediawiki, Joomla, Gallery, osCommerce and others.
* [Exploiting Script Injection Flaws in ReactJS Apps](https://medium.com/dailyjs/exploiting-script-injection-flaws-in-reactjs-883fb1fe36c1)
* [mustache-security(2013)](https://code.google.com/archive/p/mustache-security/)
	* This place will host a collection of security tips and tricks for JavaScript MVC frameworks and templating libraries.
	* [Wikis](https://code.google.com/archive/p/mustache-security/wikis)
* [A penetration tester’s guide to sub-domain enumeration - appseco](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
* [Fuzzing JSON Web Services - Simple guide how to fuzz JSON web services properly - secapps](https://secapps.com/blog/2018/03/fuzzing-json-web-services)
* [Exploiting Script Injection Flaws in ReactJS Apps - Bernhard Mueller](https://medium.com/dailyjs/exploiting-script-injection-flaws-in-reactjs-883fb1fe36c1)
* [Web Filter External Enumeration Tool (WebFEET)](https://github.com/nccgroup/WebFEET)
	* WebFEET is a web application for the drive-by enumeration of web security proxies and policies. See associated [white paper](https://www.nccgroup.com/media/481438/whitepaper-ben-web-filt.pdf) (Drive-by enumeration of web filtering solutions)
* [repokid](https://github.com/Netflix/repokid)
	* AWS Least Privilege for Distributed, High-Velocity Deployment
* [Testing stateful web application workflows - András Veres-Szentkirályi](https://www.youtube.com/watch?v=xiTFKigyncg)
[JSON Web Token - Wikipedia](https://en.wikipedia.org/wiki/JSON_Web_Token)
[Introduction to JSON Web Tokens](https://jwt.io/introduction/) 
[c-jwt-cracker ](https://github.com/brendan-rius/c-jwt-cracker)
* [Azurite - Azurite Explorer and Azurite Visualizer](https://github.com/mwrlabs/Azurite)
	* consists of two helper scripts: Azurite Explorer and Azurite Visualizer. The scripts are used to collect, passively, verbose information of the main components within a deployment to be reviewed offline, and visulise the assosiation between the resources using an interactive representation. One of the main features of the visual representation is to provide a quick way to identify insecure Network Security Groups (NSGs) in a subnet or Virtual Machine configuration.
* [CTFR](https://github.com/UnaPibaGeek/ctfr)
	* Do you miss AXFR technique? This tool allows to get the subdomains from a HTTPS website in a few seconds. How it works? CTFR does not use neither dictionary attack nor brute-force, it just abuses of Certificate Transparency logs.
* [Request form for performing Pentesting on AWS Infrastructure](https://aws.amazon.com/premiumsupport/knowledge-center/penetration-testing/)
https://www.owasp.org/images/b/bf/OWASP_Stammtisch_Frankfurt_WAF_Profiling_and_Evasion.pdf 
https://www.sunnyhoi.com/guide-identifying-bypassing-wafs/ 
* [JoomlaVS](https://github.com/rastating/joomlavs)
	* JoomlaVS is a Ruby application that can help automate assessing how vulnerable a Joomla installation is to exploitation. It supports basic finger printing and can scan for vulnerabilities in components, modules and templates as well as vulnerabilities that exist within Joomla itself.
* [XSS bypass strtoupper & htmlspecialchars](https://security.stackexchange.com/questions/145716/xss-bypass-strtoupper-htmlspecialchars)
* [Is htmlspecialchars enough to prevent an SQL injection on a variable enclosed in single quotes? - StackOverflow](https://stackoverflow.com/questions/22116934/is-htmlspecialchars-enough-to-prevent-an-sql-injection-on-a-variable-enclosed-in)
* [Google Cloud Security Scanner](https://cloud.google.com/security-scanner/)
	* Cloud Security Scanner is a web security scanner for common vulnerabilities in Google App Engine applications. It can automatically scan and detect four common vulnerabilities, including cross-site-scripting (XSS), Flash injection, mixed content (HTTP in HTTPS), and outdated/insecure libraries. It enables early identification and delivers very low false positive rates. You can easily setup, run, schedule, and manage security scans and it is free for Google Cloud Platform users.
* [Pivoting in Amazon Clouds](https://andresriancho.github.io/nimbostratus/pivoting-in-amazon-clouds.pdf)
* [Nimbostratus](https://github.com/andresriancho/nimbostratus)
	* Tools for fingerprinting and exploiting Amazon cloud infrastructures
* [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
* [Pivoting in Amazon Clouds - Andres Riancho - BHUSA14](https://www.youtube.com/watch?v=2NF4LjjwoZw)
	* "From no access at all, to the company Amazon's root account, this talk will teach attendees about the components used in cloud applications like: EC2, SQS, IAM, RDS, meta-data, user-data, Celery; and how misconfigurations in each can be abused to gain access to operating systems, database information, application source code, and Amazon's services through its API. The talk will follow a knowledgeable intruder from the first second after identifying a vulnerability in a cloud-deployed Web application and all the steps he takes to reach the root account for the Amazon user. Except for the initial vulnerability, a classic remote file included in a Web application which grants access to the front-end EC2 instance, all the other vulnerabilities and weaknesses exploited by this intruder are going to be cloud-specific.
* [htcap](https://github.com/segment-srl/htcap)
	* htcap is a web application scanner able to crawl single page application (SPA) in a recursive manner by intercepting ajax calls and DOM changes. Htcap is not just another vulnerability scanner since it's focused mainly on the crawling process and uses external tools to discover vulnerabilities. It's designed to be a tool for both manual and automated penetration test of modern web applications.
* [Microsoft Azure: Penetration Testing - Official Documentation](https://docs.microsoft.com/en-us/azure/security/azure-security-pen-testing)
* [Beginner’s Guide to API(REST) security](https://introvertmac.wordpress.com/2015/09/09/beginners-guide-to-apirest-security/)
* [Continuous Security - In the DevOps World - Julien Vehent](https://jvehent.github.io/continuous-security-talk/#/)
* [Bumpster](https://github.com/markclayton/bumpster)
	* The Unofficial Burp Extension for DNSDumpster.com. You simply supply a domain name and it returns a ton of DNS information and basically lays out the external network topology. 
* [Brute Forcing HS256 is Possible: The Importance of Using Strong Keys in Signing JWTs](https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/)
* [Introducing CFire: Evading CloudFlare Security Protections - rhinosecuritylabs](https://rhinosecuritylabs.com/cloud-security/cloudflare-bypassing-cloud-security/)
* [CloudFire](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/cfire)
	* This project focuses on discovering potential IP's leaking from behind cloud-proxied services, e.g. Cloudflare. Although there are many ways to tackle this task, we are focusing right now on CrimeFlare database lookups, search engine scraping and other enumeration techniques.
* [Cross-Origin Resource Sharing (CORS) - Mozilla Dev Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
* [Practical tips for defending web  applications in the age of agile/DevOps - Zane Lackey](https://www.blackhat.com/docs/us-17/thursday/us-17-Lackey-Practical%20Tips-for-Defending-Web-Applications-in-the-Age-of-DevOps.pdf)
* [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
* [RESTful API Best Practices and Common Pitfalls - Spencer Schneidenbach](https://medium.com/@schneidenbach/restful-api-best-practices-and-common-pitfalls-7a83ba3763b5)
* [What is MIME Sniffing? - keycdn.com](https://www.keycdn.com/support/what-is-mime-sniffing/)
* [Risky sniffing - MIME sniffing in Internet Explorer enables cross-site scripting attacks - h-online.com(2009)](http://www.h-online.com/security/features/Risky-MIME-sniffing-in-Internet-Explorer-746229.html)
* [Content Sniffing - Wikipedia](https://en.wikipedia.org/wiki/Content_sniffing)
	* Content sniffing, also known as media type sniffing or MIME sniffing, is the practice of inspecting the content of a byte stream to attempt to deduce the file format of the data within it. 
* [MS07-034 - Yosuke Hasegawa](https://web.archive.org/web/20160609171311/http://openmya.hacker.jp/hasegawa/security/ms07-034.txt)
* [What is “X-Content-Type-Options=nosniff”?](https://stackoverflow.com/questions/18337630/what-is-x-content-type-options-nosniff)
* [Content hosting for the modern web - Google](https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html)
* [Is it safe to serve any user uploaded file under only white-listed MIME content types? - StackOverflow](https://security.stackexchange.com/questions/11756/is-it-safe-to-serve-any-user-uploaded-file-under-only-white-listed-mime-content)
* [Guidelines for Setting Security Headers - Isaac Dawson](https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers)
* [HTTP Strict Transport Security - cio.gov](https://https.cio.gov/hsts/)
* [From hacked client to 0day discovery - infoteam](https://security.infoteam.ch/en/blog/posts/from-hacked-client-to-0day-discovery.html)
	* PHP equivalency check failure writeup
* [OWASP Mutillidae II](https://sourceforge.net/projects/mutillidae/)
	* OWASP Mutillidae II is a free, open source, deliberately vulnerable web-application providing a target for web-security enthusiast. Mutillidae can be installed on Linux and Windows using LAMP, WAMP, and XAMMP. It is pre-installed on SamuraiWTF and OWASP BWA. The existing version can be updated on these platforms. With dozens of vulnerabilities and hints to help the user; this is an easy-to-use web hacking environment designed for labs, security enthusiast, classrooms, CTF, and vulnerability assessment tool targets. Mutillidae has been used in graduate security courses, corporate web sec training courses, and as an "assess the assessor" target for vulnerability assessment software.





------------
## Wireless Stuff

* [LTEInspector : A Systematic Approach for Adversarial Testing of 4G LTE](http://wp.internetsociety.org/ndss/wp-content/uploads/sites/25/2018/02/ndss2018_02A-3_Hussain_paper.pdf)
	* In this paper, we investigate the security and privacy of the three critical procedures of the 4G LTE protocol (i.e., attach, detach, and paging), and in the process, uncover potential design flaws of the protocol and unsafe practices employed by the stakeholders. For exposing vulnerabilities, we propose a model-based testing approach LTEInspector which lazily combines a symbolic model checker and a cryptographic protocol verifier in the symbolic attacker model. Using LTEInspector, we have uncovered 10 new attacks along with 9 prior attacks, cate- gorized into three abstract classes (i.e., security, user privacy, and disruption of service), in the three procedures of 4G LTE. Notable among our findings is the authentication relay attack that enables an adversary to spoof the location of a legitimate user to the core network without possessing appropriate credentials. To ensure that the exposed attacks pose real threats and are indeed realizable in practice, we have validated 8 of the 10 new attacks and their accompanying adversarial assumptions through experimentation in a real testbed



### Container Security

* [nsjail](https://github.com/google/nsjail)
	* A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)
* [docker-bench-security](https://github.com/docker/docker-bench-security)
	* The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production.	