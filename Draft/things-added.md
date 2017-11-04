


-------------
### ATT&CK

[Koadic](https://github.com/zerosum0x0/koadic)
* Koadic, or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript), with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.

[Abusing Webhooks for Command and Control - Dimitry Snezhkov - BSides LV 2017](https://www.youtube.com/watch?v=TmLoTrJuung)

[changeme - A default credential scanner.](https://github.com/ztgrace/changeme)
* changeme picks up where commercial scanners leave off. It focuses on detecting default and backdoor credentials and not necessarily common credentials. It's default mode is to scan HTTP default credentials, but has support for other credentials. changeme is designed to be simple to add new credentials without having to write any code or modules. changeme keeps credential data separate from code. All credentials are stored in yaml files so they can be both easily read by humans and processed by changeme. Credential files can be created by using the ./changeme.py --mkcred tool and answering a few questions. changeme supports the http/https, mssql, mysql, postgres, ssh, ssh w/key, snmp, mongodb and ftp protocols. Use ./changeme.py --dump to output all of the currently available credentials.

[Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.

[DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)
* [Slides](https://github.com/TryCatchHCF/DumpsterFire/raw/master/CactusCon_2017_Presentation/DumpsterFire_CactusCon_2017_Slides.pdf)
* The DumpsterFire Toolset is a modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations. Turn paper tabletop exercises into controlled "live fire" range events. Build event sequences ("narratives") to simulate realistic scenarios and generate corresponding network and filesystem artifacts.

[Hammerspoon - Staggeringly powerful OS X desktop automation with Lua](https://github.com/Hammerspoon/hammerspoon)
* This is a tool for powerful automation of OS X. At its core, Hammerspoon is just a bridge between the operating system and a Lua scripting engine. What gives Hammerspoon its power is a set of extensions that expose specific pieces of system functionality, to the user. With these, you can write Lua scripts to control many aspects of your OS X environment.


















------------
## Anonymity/Privacy


[Mobile Phone Data lookup](https://medium.com/@philipn/want-to-see-something-crazy-open-this-link-on-your-phone-with-wifi-turned-off-9e0adb00d024)



[Debian-Privacy-Server-Guide](https://github.com/drduh/Debian-Privacy-Server-Guide)
* This is a step-by-step guide to configuring and managing a domain, remote server and hosted services, such as VPN, a private and obfuscated Tor bridge, and encrypted chat, using the Debian GNU/Linux operating system and other free software.


[David Goulet - Deep Dive Into Tor Onion Services](https://www.youtube.com/watch?v=AkoyCLAXVsc)

[Winning and Quitting the Privacy Game What it REALLY takes to have True Privacy in the 21st Century - Derbycon 7](https://www.youtube.com/watch?v=bxQSu06yuZc)

[Reminder: Oh, Won't You Please Shut Up?](https://www.popehat.com/2011/12/01/reminder-oh-wont-you-please-shut-up/)

[Managing Pseudonyms with Compartmentalization: Identity Management of Personas](https://www.alienvault.com/blogs/security-essentials/managing-pseudonyms-with-compartmentalization-identity-management-of-personas)





------------
## Attacking/Defending Android






------------
## Basic Security Info



------------
## BIOS/UEFI

[Replace your exploit-ridden  firmware with a Linux kernel](https://schd.ws/hosted_files/osseu17/84/Replace%20UEFI%20with%20Linux.pdf)

[The UEFI Firm(ware Rootkits: Myths and Reality - BH Asia 2017](https://www.youtube.com/watch?v=P3yMXspLzoY&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=28)






------------
## Building a Lab 

[DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)
* [Slides](https://github.com/TryCatchHCF/DumpsterFire/raw/master/CactusCon_2017_Presentation/DumpsterFire_CactusCon_2017_Slides.pdf)
* The DumpsterFire Toolset is a modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations. Turn paper tabletop exercises into controlled "live fire" range events. Build event sequences ("narratives") to simulate realistic scenarios and generate corresponding network and filesystem artifacts.


------------
## Car Hacking



------------
## Conferences







------------
## Courses






------------
## CTF








------------
## Crypto


[ROCA: Vulnerable RSA generation (CVE-2017-15361)](https://crocs.fi.muni.cz/public/papers/rsa_ccs17)
*  A newly discovered vulnerability in generation of RSA keys used by a software library adopted in cryptographic smartcards, security tokens and other secure hardware chips manufactured by Infineon Technologies AG allows for a practical factorization attack, in which the attacker computes the private part of an RSA key. The attack is feasible for commonly used key lengths, including 1024 and 2048 bits, and affects chips manufactured as early as 2012, that are now commonplace. Assess your keys now with the provided offline and online detection tools and contact your vendor if you are affected. Major vendors including Microsoft, Google, HP, Lenovo, Fujitsu already released the software updates and guidelines for a mitigation. Full details including the factorization method will be released in 2 weeks at the ACM CCS conference as 'The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli' (ROCA) research paper. 



[roca - ROCA detection tool](https://github.com/crocs-muni/roca)
* ROCA: Infineon RSA vulnerability
 
[ROCA Vulnerability Test Suite - keychest](https://keychest.net/roca)

[KeyTester - Roca - Cryptosense](https://keytester.cryptosense.com/)
* Test your RSA Keys

[A Stick Figure Guide to the Advanced Encryption Standard (AES)](http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html)

[Faux Disk Encryption: Realities of Secure Storage On Mobile Devices - NCC Group](https://www.blackhat.com/docs/us-15/materials/us-15-Mayer-Faux-Disk-Encryption-Realities-Of-Secure-Storage-On-Mobile-Devices-wp.pdf)






------------
## Crypto Currencies




------------
## Data Analysis/Visualization





------------
## Design





------------
## Disclosure




------------
## Documentation/Technical writing




------------
## Embedded Devices/Hardware (Including Printers & PoS)

[Secure Tokin’ & Doobiekeys: How to roll your own counterfeit hardware security devices - @securelyfitz, @r00tkillah](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-r00killah-and-securelyfitz-Secure-Tokin-and-Doobiekeys.pdf)

[Pwn2Win 2017 - Shift Register](http://blog.dragonsector.pl/2017/10/pwn2win-2017-shift-register.html)

[When IoT Attacks: Hacking A Linux-Powered Rifle ](https://www.blackhat.com/docs/us-15/materials/us-15-Sandvik-When-IoT-Attacks-Hacking-A-Linux-Powered-Rifle.pdf)






















------------
## Exfiltration





------------
## Exploit Dev


[MS17-010: EternalBlue’s Large Non-Paged Pool Overflow in SRV Driver - blog.trendmicro](http://blog.trendmicro.com/trendlabs-security-intelligence/ms17-010-eternalblue/)

[MS17-010 worawit](https://github.com/worawit/MS17-010)



------------
## Forensics


[int0x80 (of Dual Core) -- Anti-Forensics for the Louise - Derbycon](https://www.youtube.com/watch?v=-HK1JHR7LIM	)

[Commercial Spyware - Detecting the Undetectable](https://www.blackhat.com/docs/us-15/materials/us-15-Dalman-Commercial-Spyware-Detecting-The-Undetectable-wp.pdf)









------------
## Fuzzing/Bug Hunting

[GitHub for Bug Bounty Hunters](https://gist.github.com/EdOverflow/922549f610b258f459b219a32f92d10b)

[Secure Code Review - OpenSecurityTraining.info](http://opensecuritytraining.info/SecureCodeReview.html)

[High-Level Approaches for Finding Vulnerabilities](http://jackson.thuraisamy.me/finding-vulnerabilities.html)

[Hacking Virtual Appliances - DerbyconV](https://www.irongeek.com/i.php?page=videos/derbycon5/fix-me08-hacking-virtual-appliances-jeremy-brown)
* Virtual Appliances have become very prevalent these days as virtualization is ubiquitous and hypervisors commonplace. More and more of the major vendors are providing literally virtual clones for many of their once physical-only products. Like IoT and the CAN bus, it's early in the game and vendors are late as usual. One thing that it catching these vendors off guard is the huge additional attack surface, ripe with vulnerabilities, added in the process. Also, many vendors see software appliances as an opportunity for the customer to easily evaluate the product before buying the physical one, making these editions more accessible and debuggable by utilizing features of the platform on which it runs. During this talk, I will provide real case studies for various vulnerabilities created by mistakes that many of the major players made when shipping their appliances. You'll learn how to find these bugs yourself and how the vendors went about fixing them, if at all. By the end of this talk, you should have a firm grasp of how one goes about getting remotes on these appliances.














------------
## Game Hacking

[Reverse engineering a Gameboy ROM with radare2](https://www.megabeets.net/reverse-engineering-a-gameboy-rom-with-radare2/)

[TruePlay - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/mt808781(v=vs.85).aspx)

[Valve Anti-Cheat Untrusted Bans (VAC) CSGO](http://dev.cra0kalo.com/?p=521)















------------
## Honeypots



		
------------
## ICS/SCADA






------------
## Interesting Things


[The Aviation Herald](https://avherald.com/)

[NTSB Aviation Accident Database & Synopses](https://www.ntsb.gov/_layouts/ntsb.aviation/index.aspx)

[autojump - a faster way to navigate your filesystem](https://github.com/wting/autojump)
* autojump is a faster way to navigate your filesystem. It works by maintaining a database of the directories you use the most from the command line.

[OSX for Hackers (Mavericks/Yosemite)](https://gist.github.com/matthewmueller/e22d9840f9ea2fee4716)

[Human Trafficking in the Digital Age](https://www.irongeek.com/i.php?page=videos/derbycon4/t516-human-trafficking-in-the-digital-age-chris-jenks)

[What Colour are your bits?](http://ansuz.sooke.bc.ca/entry/23)


[ThreatPinch Lookup](https://github.com/cloudtracer/ThreatPinchLookup)
* ThreatPinch Lookup creates informational tooltips when hovering oven an item of interest on any website. It helps speed up security investigations by automatically providing relevant information upon hovering over any IPv4 address, MD5 hash, SHA2 hash, and CVE title. It’s designed to be completely customizable and work with any rest API.







------------
## Lockpicking





------------
## Malware

[Windows’ PsSetLoadImageNotifyRoutine Callbacks: the Good, the Bad and the Unclear (Part 2)](https://breakingmalware.com/documentation/windows-pssetloadimagenotifyroutine-callbacks-good-bad-unclear-part-2/)

[ZitMo NoM - Derbycon2014](https://www.irongeek.com/i.php?page=videos/derbycon4/t520-zitmo-nom-david-schwartzberg)
* A world without malware is ideal but unlikely. Many of us would prefer *not* to install another layer of protection on their already resource constrained handheld mobile device. Alternatively, Android malware detection sans anti-virus installation has become a reality. Learn about how it’s possible to detect mobile malware using simple text messages with ZitMo NoM. ZeuS in the mobile, known as ZitMo, is infamous for intercepting SMS transmissions then redirecting them to a Command & Control in order steal banking and personal information. Research with SMS transmissions directed at mobile malware has resulted in the ability to detect ZitMo’s presence without anti,virus applications installed. Turning their own tools against them makes this even more of a rewarding endeavor. We are looking for malware researchers to contribute to the continued development of this open tool. The presentation will include the research, the infrastructure and a demonstration of ZitMo NoM. Live malware will be used during this presentation, assuming we get it to behave.

[Manalyze - static analyzer for PE files](https://github.com/JusticeRage/Manalyze)
* Manalyze was written in C++ for Windows and Linux and is released under the terms of the GPLv3 license. It is a robust parser for PE files with a flexible plugin architecture which allows users to statically analyze files in-depth.




------------
## Mainframes





------------
## Network Scanning and Attacks

[changeme - A default credential scanner.](https://github.com/ztgrace/changeme)
* changeme picks up where commercial scanners leave off. It focuses on detecting default and backdoor credentials and not necessarily common credentials. It's default mode is to scan HTTP default credentials, but has support for other credentials. changeme is designed to be simple to add new credentials without having to write any code or modules. changeme keeps credential data separate from code. All credentials are stored in yaml files so they can be both easily read by humans and processed by changeme. Credential files can be created by using the ./changeme.py --mkcred tool and answering a few questions. changeme supports the http/https, mssql, mysql, postgres, ssh, ssh w/key, snmp, mongodb and ftp protocols. Use ./changeme.py --dump to output all of the currently available credentials.

[Fire Away Sinking the Next Gen Firewall Russell Butturini - Derbycon6](https://www.youtube.com/watch?v=Qpty_f0Eu7Y)

[NTLMssp-Extract](https://github.com/sinnaj-r/NTLMssp-Extract)
* A small Python-Script to extract NetNTLMv2 Hashes from NTMLssp-HTTP-Authentications, which were captured in a pcap.

[ntlmRelayToEWS](https://github.com/Arno0x/NtlmRelayToEWS)
* ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS). It spawns an SMBListener on port 445 and an HTTPListener on port 80, waiting for incoming connection from the victim. Once the victim connects to one of the listeners, an NTLM negociation occurs and is relayed to the target EWS server.










------------
## Network Monitoring & Logging


[Automating large-scale memory forensics](https://medium.com/@henrikjohansen/automating-large-scale-memory-forensics-fdc302dc3383)

[PowerShellMethodAuditor](https://github.com/zacbrown/PowerShellMethodAuditor)


------------
## OSINT

[6 Actionable Web Scraping Hacks for White Hat Marketers](http://ytcomments.klostermann.ca/)

[BuzzSumo](http://buzzsumo.com/)

[us-info](http://www.us-info.com/en/usa)
*  Search for a company/person in United States of America 

[waybackpack](https://github.com/jsvine/waybackpack)
* Download the entire Wayback Machine archive for a given URL.

[LinkedInt: A LinkedIn scraper for reconnaissance during adversary simulation](https://github.com/mdsecactivebreach/LinkedInt)







------------
##	OS X






------------
## Password Cracking

[Cracking Corporate Passwords – Exploiting Password Policy Weaknesses - Minga / Rick Redman Derbycon 2013](https://www.irongeek.com/i.php?page=videos/derbycon3/1301-cracking-corporate-passwords-exploiting-password-policy-weaknesses-minga-rick-redman)






------------
## Phishing/SE

[Exploiting Office native functionality: Word DDE edition](https://www.securityforrealpeople.com/2017/10/exploiting-office-native-functionality.html)


[Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.

[Outlook and Exchange for the Bad Guys Nick Landers - Derbycon6](https://www.youtube.com/watch?v=cVhc9VOK5MY)

[morphHTA - Morphing Cobalt Strike's evil.HTA](https://github.com/vysec/morphHTA)

[Malicious Outlook Rules - Nick Landers](https://silentbreaksecurity.com/malicious-outlook-rules/)




















------------
## Physical Security

[zoneminder](https://www.zoneminder.com/)
* A full-featured, open source, state-of-the-art video surveillance software system.












------------
## Policy

[SP 800-115: Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/publications/detail/sp/800-115/final)
* The purpose of this document is to assist organizations in planning and conducting technical information security tests and examinations, analyzing findings, and developing mitigation strategies. The guide provides practical recommendations for designing, implementing, and maintaining technical information security test and examination processes and procedures. These can be used for several purposes, such as finding vulnerabilities in a system or network and verifying compliance with a policy or other requirements. The guide is not intended to present a comprehensive information security testing and examination program but rather an overview of key elements of technical security testing and examination, with an emphasis on specific technical techniques, the benefits and limitations of each, and recommendations for their use. 


[Information Security Risk Assessment Guidelines - mass.gov](http://www.mass.gov/anf/research-and-tech/cyber-security/security-for-state-employees/risk-assessment/risk-assessment-guideline.html)

[An Overview of Threat and Risk Assessment](https://www.sans.org/reading-room/whitepapers/auditing/overview-threat-risk-assessment-76)


[Security Assessment Guidelines for Financial Institutions](https://www.sans.org/reading-room/whitepapers/auditing/security-assessment-guidelines-financial-institutions-993)





------------
## Post Exploitation/Privilege Escalation


[Breaking out of secured Python environments](http://tomforb.es/breaking-out-of-secured-python-environments)


[Windows Privilege Escalation -  Riyaz Walikar](https://www.slideshare.net/riyazwalikar/windows-privilege-escalation)

[Koadic](https://github.com/zerosum0x0/koadic)
* Koadic, or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript), with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.

[Seth](https://github.com/SySS-Research/Seth)
* Seth is a tool written in Python and Bash to MitM RDP connections by attempting to downgrade the connection in order to extract clear text credentials. It was developed to raise awareness and educate about the importance of properly configured RDP connections in the context of pentests, workshops or talks. The author is Adrian Vollmer (SySS GmbH).


[ps1-toolkit](https://github.com/vysec/ps1-toolkit)
* This is a set of PowerShell scripts that are used by many penetration testers released by multiple leading professionals. This is simply a collection of scripts that are prepared and obfuscated to reduce level of detectability and to slow down incident response from understanding the actions performed by an attacker.

[ANGRYPUPPY](https://github.com/vysec/ANGRYPUPPY)
* Bloodhound Attack Path Execution for Cobalt Strike

[VMware Escape Exploit](https://github.com/unamer/vmware_escape)
* VMware Escape Exploit before VMware WorkStation 12.5.5

[Whitelist Evasion revisited](https://khr0x40sh.wordpress.com/2015/05/27/whitelist-evasion-revisited/)











------------
## Programming:

[Diving deep into Python – the not-so-obvious language parts](http://sebastianraschka.com/Articles/2014_deep_python.html)

[Alamofire](https://github.com/Alamofire/Alamofire)
* Alamofire is an HTTP networking library written in Swift.









------------
## RE

[Hacking travel routers  like it’s 1999](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Mikhail-Sosonkin-Hacking-Travel-Routers-Like-1999.pdf)




------------
## Red Team/Pentesting

[10 Red Teaming Lessons Learned over 20 Years](https://redteamjournal.com/2015/10/10-red-teaming-lessons-learned-over-20-years/)

[Red Team - Wikipedia](https://en.m.wikipedia.org/wiki/Red_team)

[Reflections from a Red Team Leader - Susan Craig](http://usacac.army.mil/CAC2/MilitaryReview/Archives/English/MilitaryReview_20070430_art011.pdf)

[Cyber Red Team ing  Organis ational ,  technical and  legal  implications  in a  military context - NATO](https://ccdcoe.org/sites/default/files/multimedia/pdf/Cyber_Red_Team.pdf)

[A Short Introduction to Red Teaming - Dr. Mark Mateski](https://redteamjournal.com/papers/A%20Short%20Introduction%20to%20Red%20Teaming%20(1dot0).pdf)

[Red Teaming Guide - UK Ministry of Defense](https://www.gov.uk/government/uploads/system/uploads/attachment_data/file/142533/20130301_red_teaming_ed2.pdf)

[Red Team Handbook(2012) - University of Foreign Military And Cultural studies](http://www.au.af.mil/au/awc/awcgate/army/ufmcs_red_team_handbook_apr2012.pdf)

[The Applied Critical Thinking Handbook(2015) - University of Foreign Military And Cultural studies](http://usacac.army.mil/sites/default/files/documents/ufmcs/The_Applied_Critical_Thinking_Handbook_v7.0.pdf)

[Red Teaming of Advanced Information Assurance Concepts - Bradley Wood, Ruth Duggan](http://cs.uccs.edu/~gsc/pub/master/sjelinek/doc/research/red.pdf)

[A GUIDE TO RED TEAMING - NATO](http://www.act.nato.int/images/stories/events/2011/cde/rr_ukdcdc.pdf)

[Goodbye OODA Loop](http://armedforcesjournal.com/goodbye-ooda-loop/)

[Full Contact Recon int0x80 of Dual Core savant - Derbycon7](https://www.youtube.com/watch?v=XBqmvpzrNfs)

[Red Teams - Facebook Experiences Writeup - Ryan McGeehan](https://medium.com/starting-up-security/red-teams-6faa8d95f602)

[Red Teaming: Using Cutting-Edge Threat Simulation to Harden the Microsoft Enterprise Cloud](https://azure.microsoft.com/en-us/blog/red-teaming-using-cutting-edge-threat-simulation-to-harden-the-microsoft-enterprise-cloud/)

[Penetration Testing Trends John Strand - Derbycon6](https://www.youtube.com/watch?v=QyxdUe1iMNk)

[Preparing for the War of the Future in the Wake of Defeat: The Evolution of German Strategic Thought, 1919 - 1935 - Mark Shannon](https://www.ciaonet.org/attachments/25573/uploads)

[TRADITIONS IN MILITARY-STRATEGIC THOUGHT IN GERMANY AND THE PROBLEM OF DETERRENCE - 1989 - Detlef Bald](http://www.mgfa.de/html/einsatzunterstuetzung/downloads/ap018englisch.pdf?PHPSESSID=931748af0e86616800373655acaf2902)

[Target Analysis - Wikipedia](https://en.wikipedia.org/wiki/Target_analysis)

[Center of Gravity Analysis - Dale C. Eikmeier](http://www.au.af.mil/au/awc/awcgate/milreview/eikmeier.pdf)
* Center of Gravity: A system's source of power to act.

[A Tradecraft Primer: Structured Analytic Techniques for Improving Intelligence Analysis - USGov 2009](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/Tradecraft%20Primer-apr09.pdf)

[Force Protection and Suicide Bombers: The Necessity for Two Types of Canadian Military Red Teams](http://www.journal.forces.gc.ca/vol12/no4/page35-eng.asp)

[Red team versus blue team: How to run an effective simulation - CSOonline](https://www.csoonline.com/article/2122440/disaster-recovery/emergency-preparedness-red-team-versus-blue-team-how-to-run-an-effective-simulation.html)

[Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.

[Red teaming - A Short Introduction (1.0) June 2009 - Mark Mateski](https://redteamjournal.com/papers/A%20Short%20Introduction%20to%20Red%20Teaming%20(1dot0).pdf)

[Red Teaming and the Adversarial Mindset: Have a Plan, Backup Plan and Escape Plan - ITS](https://www.itstactical.com/digicom/security/red-teaming-and-the-adversarial-mindset-have-a-plan-backup-plan-and-escape-plan/)

[Modeling and Simulation of Red Teaming - Part 1: Why Red Team M&S? - Michael J Skroch](https://redteamjournal.com/wp-content/uploads/2009/12/msrt0.3-2nov2009-sand2009-7215J.pdf)

[Moving Forward with Computational Red Teaming - Scott Wheeler - Australian DoD](http://www.dtic.mil/dtic/tr/fulltext/u2/a569437.pdf)

[LinkedInt: A LinkedIn scraper for reconnaissance during adversary simulation](https://github.com/mdsecactivebreach/LinkedInt)

[DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)
* [Slides](https://github.com/TryCatchHCF/DumpsterFire/raw/master/CactusCon_2017_Presentation/DumpsterFire_CactusCon_2017_Slides.pdf)
* The DumpsterFire Toolset is a modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations. Turn paper tabletop exercises into controlled "live fire" range events. Build event sequences ("narratives") to simulate realistic scenarios and generate corresponding network and filesystem artifacts.





























------------
## Rootkits







------------
## SCADA


[Adventures in Attacking Wind Farm Control Networks - Jason Stagg](https://www.blackhat.com/docs/us-17/wednesday/us-17-Staggs-Adventures-In-Attacking-Wind-Farm-Control-Networks.pdf)

[Rocking the pocket book: Hacking chemical plants for competition and extortion](https://www.youtube.com/watch?v=lsY3bkMI-90)




------------
## Social Engineering

[So you wanna be a Social Engineer Christopher Hadnagy - Derbycon 7](https://www.youtube.com/watch?v=RGnzf66-a4A)

As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.





------------
## System Internals

[Authenticode - MSDN](https://msdn.microsoft.com/en-us/library/ms537359(v=vs.85).aspx)
* Microsoft Authenticode, which is based on industry standards, allows developers to include information about themselves and their code with their programs through the use of digital signatures. 
[Security Configuration Wizard](https://technet.microsoft.com/en-us/library/cc754997(v=ws.11).aspx)
* The Security Configuration Wizard (SCW) guides you through the process of creating, editing, applying, or rolling back a security policy. A security policy that you create with SCW is an .xml file that, when applied, configures services, network security, specific registry values, and audit policy. SCW is a role-based tool: you can use it to create a policy that enables services, firewall rules, and settings that are required for a selected server to perform specific roles, such as a file server, a print server, or a domain controller.








------------
## Threat Modeling & Analysis




------------
## Threat Hunting

[Hunting Lateral Movement for Fun and Profit Mauricio Velazco - Derbycon7](https://www.youtube.com/watch?v=hVTkkkM9XDg)

[ThreatHunter-Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook)
* A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns.



------------
## Web: 

[Code Reuse Attacks in PHP: Automated POP Chain Generation](https://www.syssec.rub.de/media/emma/veroeffentlichungen/2014/09/10/POPChainGeneration-CCS14.pdf)
* In  this  paper, we study code reuse attacks in the con- text of PHP-based web applications. We analyze how PHP object injection (POI) vulnerabilities  can  be exploited via property-oriented programming (POP) and perform a systematic analysis of available gadgets in common PHP applications. Furthermore, we introduce an automated approach to statically detect  POI  vulnerabilities  in  object-oriented PHP code. Our approach is also capable of generating POP chains in an automated way. We implemented a prototype of the proposed approach and evaluated it with 10 well-known applications. Overall, we detected 30 new POI vulnerabilities and 28 new gadget chains

[Property Oriented Programming - Applied to Ruby](https://slides.com/benmurphy/property-oriented-programming/fullscreen#/)

[Utilizing Code Reuse/ROP in PHP Application Exploits - BH 2010](https://www.owasp.org/images/9/9e/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)

[POP-Exploit](https://github.com/enddo/POP-Exploit)
* Research into Property Oriented Programming about php applications.

[PHP Autoload Invalid Classname Injection](https://hakre.wordpress.com/2013/02/10/php-autoload-invalid-classname-injection/)


[Autoloading Classes](http://www.php.net/language.oop5.autoload)

[serialize - php](http://us3.php.net/serialize)

[unserialize - php](https://secure.php.net/unserialize)

[The ReflectionClass class](https://secure.php.net/ReflectionClass)

[PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection)

[Automating Web Apps Input fuzzing via Burp Macros](http://blog.securelayer7.net/automating-web-apps-input-fuzzing-via-burp-macros/)

[ Race conditions on the web ](https://www.josipfranjkovic.com/blog/race-conditions-on-web)

[Practical Race Condition Vulnerabilities in Web Applications](https://defuse.ca/race-conditions-in-web-applications.htm)

[Race condition exploit](https://github.com/andresriancho/race-condition-exploit)
* Tool to help with the exploitation of web application race conditions

[Hunting in the Dark - Blind XXE](https://blog.zsec.uk/blind-xxe-learning/)

[SSRF (Server Side Request Forgery) testing resources](https://github.com/cujanovic/SSRF-Testing/)

[Security Implications of DTD Attacks Against a Wide Range of XML Parsers](https://www.nds.rub.de/media/nds/arbeiten/2015/11/04/spaeth-dtd_attacks.pdf)

[ABUSING CERTIFICATE TRANSPARENCY OR HOW TO HACK WEB APPLICATIONS BEFORE INSTALLATION - Hanno Bock](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Hanno-Boeck-Abusing-Certificate-Transparency-Logs.pdf)

[Web Application testing approach and cheating to win Jim McMurry Lee Neely Chelle Clements - Derbycon7](https://www.youtube.com/watch?v=Z8ZAv_EN-9M) 

[Pentesting Django and Rails](https://es.slideshare.net/levigross/pentesting-django-and-rails)

[MongoDB Pentesting for Absolute Beginners](https://github.com/nixawk/pentest-wiki/blob/master/2.Vulnerability-Assessment/Database-Assessment/mongodb/MongoDB%20Pentesting%20for%20Absolute%20Beginners.pdf)

[Stealing Amazon EC2 Keys via an XSS Vulnerability](https://ionize.com.au/stealing-amazon-ec2-keys-via-xss-vulnerability/)

[Abusing Webhooks for Command and Control - Dimitry Snezhkov - BSides LV 2017](https://www.youtube.com/watch?v=TmLoTrJuung)
* [octohook](https://github.com/dsnezhkov/octohook)

[Popular Approaches to Preventing Code Injection Attacks are Dangerously Wrong - AppSecUSA 2017](https://www.youtube.com/watch?v=GjK0bB4K2zA&app=desktop)

[Exploiting Continuous Integration (CI) and Automated Build Systems - spaceb0x](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-spaceB0x-Exploiting-Continuous-Integration.pdf)

[Spaghetti - Web Application Security Scanner](https://github.com/m4ll0k/Spaghetti)
* Spaghetti is an Open Source web application scanner, it is designed to find various default and insecure files, configurations, and misconfigurations. Spaghetti is built on python2.7 and can run on any platform which has a Python environment.

[cider - Continuous Integration and Deployment Exploiter](https://github.com/spaceB0x/cider)
* CIDER is a framework written in node js that aims to harness the functions necessary for exploiting Continuous Integration (CI) systems and their related infrastructure and build chain (eg. Travis-CI, Drone, Circle-CI). Most of the exploits in CIDER exploit CI build systems through open GitHub repositories via malicious Pull Requests. It is built modularly to encourage contributions, so more exploits, attack surfaces, and build chain services will be integrated in the future.

[Rotten Apple](https://github.com/claudijd/rotten_apple)
* A tool for testing continuous integration (CI) or continuous delivery (CD) system security

[Comma Separated Vulnerabilities](https://www.contextis.com/blog/comma-separated-vulnerabilities)





















------------
## Wireless Stuff
[]()

[Small Tweaks do Not Help: Differential Power Analysis of MILENAGE Implementations in 3G/4G USIM Cards](https://www.blackhat.com/docs/us-15/materials/us-15-Yu-Cloning-3G-4G-SIM-Cards-With-A-PC-And-An-Oscilloscope-Lessons-Learned-In-Physical-Security-wp.pdf)