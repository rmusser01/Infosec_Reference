* Merging Physical with lockpicking



[Loading a DLL from memory](https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/)

[Measure Boot Performance with the Windows Assessment and Deployment Toolkit](https://blogs.technet.microsoft.com/mspfe/2012/09/19/measure-boot-performance-with-the-windows-assessment-and-deployment-toolkit/)

[Evaluate Fast Startup Using the Assessment Toolkit](https://docs.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-1)

[DELTA: SDN SECURITY EVALUATION FRAMEWORK](https://github.com/OpenNetworkingFoundation/DELTA)
* DELTA is a penetration testing framework that regenerates known attack scenarios for diverse test cases. This framework also provides the capability of discovering unknown security problems in SDN by employing a fuzzing technique.

[From MS08 067 To EternalBlue by Denis Isakov - BSides Manchester2017](https://www.youtube.com/watch?v=LZ_G6RdqrHA&index=13&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)

[Whitelist Evasion revisited](https://khr0x40sh.wordpress.com/2015/05/27/whitelist-evasion-revisited/)

[Untethered initroot (USENIX WOOT '17)](https://alephsecurity.com/2017/08/30/untethered-initroot/)

[Reading Your Way Around UAC (Part 1)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-1.html)
* [Reading Your Way Around UAC (Part 2)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-2.html)
* [Reading Your Way Around UAC (Part 3)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-3.html)

[Decrypting IIS Passwords to Break Out of the DMZ: Part 1 ](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/)
* [Decrypting IIS Passwords to Break Out of the DMZ: Part 2](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/)


[PHP ](https://github.com/phan/phan)


-------------
### ATT&CK

[Windows Operating System Archaeology](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology)
* Given at BSides Nashville 2017. The modern Windows Operating System carries with it an incredible amount of legacy code. The Component Object Model (COM) has left a lasting impact on Windows. This technology is far from dead as it continues to be the foundation for many aspects of the Windows Operating System. You can find hundreds of COM Classes defined by CLSID (COM Class Identifiers). Do you know what they do? This talk seeks to expose tactics long forgotten by the modern defender. We seek to bring to light artifacts in the Windows OS that can be used for persistence. We will present novel tactics for persistence using only the registry and COM objects.




------------
## Anonymity


[You Are Being Tracked: How License Plate Readers Are Being Used to Record Americans' Movements - ACLU](https://www.aclu.org/other/you-are-being-tracked-how-license-plate-readers-are-being-used-record-americans-movements?redirect=technology-and-liberty/you-are-being-tracked-how-license-plate-readers-are-being-used-record)







------------
## Attacking/Defending Android

[Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)







------------
## Basic Security Info



------------
## BIOS/UEFI

[Disabling Intel ME 11 via undocumented mode - ptsecurity](http://blog.ptsecurity.com/2017/08/disabling-intel-me.html)




------------
## Building a Lab 





------------
## Car Hacking

[An Introduction to the CAN Bus: How to Programmatically Control a Car: Hacking the Voyage Ford Fusion to Change A/C Temperature](https://news.voyage.auto/an-introduction-to-the-can-bus-how-to-programmatically-control-a-car-f1b18be4f377)



------------
## Conferences

[HITB GSEC materials](http://gsec.hitb.org/materials/)

[Infosec Cons](https://infocon.org/cons/?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=568393f9b22840fab308295ebdf5608a&uid=150127534&nid=244+289476616)



------------
## Courses






------------
## CTF








------------
## Crypto

[Quick'n easy gpg cheatsheet](http://irtfweb.ifa.hawaii.edu/%7Elockhart/gpg/)

[Hunting For Vulnerabilities In Signal - Markus Vervier - HITB 2017 AMS](https://www.youtube.com/watch?v=2n9HmllVftA)
* Signal is the most trusted secure messaging and secure voice application, recommended by Edward Snowden and the Grugq. And indeed Signal uses strong cryptography, relies on a solid system architecture, and you’ve never heard of any vulnerability in its code base. That’s what this talk is about: hunting for vulnerabilities in Signal. We will present vulnerabilities found in the Signal Android client, in the underlying Java libsignal library, and in example usage of the C libsignal library. Our demos will show how these can be used to crash Signal remotely, to bypass the MAC authentication for certain attached files, and to trigger memory corruption bugs. Combined with vulnerabilities in the Android system it is even possible to remotely brick certain Android devices. We will demonstrate how to initiate a permanent boot loop via a single Signal message. We will also describe the general architecture of Signal, its attack surface, the tools you can use to analyze it, and the general threat model for secure mobile communication apps.

[SSL/TLS and PKI History ](https://www.feistyduck.com/ssl-tls-and-pki-history/)
*  A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem. Based on Bulletproof SSL and TLS, by Ivan Ristić.

[Automated Padding Oracle Attacks with PadBuster](https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html)

[PadBuster v0.3 and the .NET Padding Oracle Attack](https://blog.gdssecurity.com/labs/2010/10/4/padbuster-v03-and-the-net-padding-oracle-attack.html)

[Hyper-encryption - Wikipedia](https://en.wikipedia.org/wiki/Hyper-encryption)

[sheep-wolf](https://github.com/silentsignal/sheep-wolf/)
* Some security tools still stick to MD5 when identifying malware samples years after practical collisions were shown against the algorithm. This can be exploited by first showing these tools a harmless sample (Sheep) and then a malicious one (Wolf) that have the same MD5 hash. Please use this code to test if the security products in your reach use MD5 internally to fingerprint binaries and share your results by issuing a pull request updating the contents of results/!


[pypadbuster](https://github.com/escbar/pypadbuster)
* A Python version of PadBuster.pl by Gotham Digital Security (GDSSecurity on Github)

[padex](https://github.com/szdavid92/padex)
* The goal of this challenge is to find a flag contained in an encrypted message. A decryption oracle and the encrypted message is provided. The student should write an application that cracks the cyphertext by abusing the oracle which is vulnerable to the padding attack.






------------
## Crypto Currencies
[Blockchain Graveyard](https://magoo.github.io/Blockchain-Graveyard/)
* These cryptocurrency institutions have suffered intrusions resulting in stolen financials, or shutdown of the product. Nearly all closed down afterward. 






------------
## Data Analysis/Visualization

[Scriptorium-LE](https://github.com/imifos/Scriptorium-LE/)
* A Linux machine state enumeration, data visualisation and analysis tool.




------------
## Design





------------
## Disclosure




------------
## Documentation/Technical writing




------------
## Embedded Devices/Hardware (Including Printers & PoS)

[umap](https://github.com/nccgroup/umap) 
* The USB host security assessment tool

[PRET](https://github.com/RUB-NDS/PRET)
* PRET is a new tool for printer security testing developed in the scope of a Master's Thesis at Ruhr University Bochum. It connects to a device via network or USB and exploits the features of a given printer language. Currently PostScript, PJL and PCL are supported which are spoken by most laser printers. This allows cool stuff like capturing or manipulating print jobs, accessing the printer's file system and memory or even causing physical damage to the device. All attacks are documented in detail in the Hacking Printers Wiki.

[Attacking *multifunction* printers and getting creds from them](http://www.irongeek.com/i.php?page=videos/bsidescleveland2014/plunder-pillage-and-print-the-art-of-leverage-multifunction-printers-during-penetration-testing-deral-heiland)




------------
## Exfiltration


[Bridging the Air Gap Data Exfiltration from Air Gap Networks - DS15](https://www.youtube.com/watch?v=bThJEX4l_Ks)

[Covert Timing Channels Based on HTTP Cache Headers](https://www.youtube.com/watch?v=DOAG3mtz7H4)

[In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HITB16](https://www.youtube.com/watch?v=T6PscV43C0w)





------------
## Exploit Dev

[Offset-DB](http://offset-db.com/)
*  This website provide you a list of useful offset that you can use for your exploit.

[Write your first driver - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/writing-your-first-driver)

[ROP Emporium](https://ropemporium.com/)
* Learn return-oriented programming through a series of challenges designed to teach ROP techniques in isolation, with minimal reverse-engineering and bug-hunting.

[shellnoob](https://github.com/reyammer/shellnoob)
* A shellcode writing toolkit

[nt!_SEP_TOKEN_PRIVILEGES - Single Write EoP Protect - Kyriakos 'kyREcon' Economou](http://anti-reversing.com/Downloads/Sec_Research/ntoskrnl_v10.0.15063_nt!_SEP_TOKEN_PRIVILEGES-Single_Write_EoP_Protect.pdf)
* TL;DR: Abusing enabled token privileges through a kernel exploit to gain EoP it won't be enough anymore as from NT kernel version 10.0.15063 are 'checked' against the privileges present in the token of the calling process. So you will need two writes

[Shellcodes database for study cases](http://shell-storm.org/shellcode/)

[Sharks in the Pool :: Mixed Object Exploitation in the Windows Kernel PoolSharks in the Pool :: Mixed Object Exploitation in the Windows Kernel Pool](http://srcincite.io/blog/2017/09/06/sharks-in-the-pool-mixed-object-exploitation-in-the-windows-kernel-pool.html)


[UniByAv](https://github.com/Mr-Un1k0d3r/UniByAv)
* UniByAv is a simple obfuscator that take raw shellcode and generate executable that are Anti-Virus friendly. The obfuscation routine is purely writtend in assembly to remain pretty short and efficient. In a nutshell the application generate a 32 bits xor key and brute force the key at run time then perform the decryption of the actually shellcode.


[Hijacking Arbitrary .NET Application Control Flow](https://www.tophertimzen.com/resources/grayStorm/HijackingArbitraryDotnetApplicationControlFlow.pdf)
* This paper describes the use of Reflection in .NET and how it can be utilized to change the control flow of an arbitrary application at runtime. A tool, Gray Storm, will be introduced that can be injected into an AppDomain and used to control the executing assembly instructions after just-in-time compilation.


[Dissecting Veil-Evasion Powershell Payloads and Converting to a Bind Shell](http://threat.tevora.com/dissecting-veil-evasion-powershell-payloads-and-converting-to-a-bind-shell/)

[Analysing the NULL SecurityDescriptor kernel exploitation mitigation in the latest Windows 10 v1607 Build 14393](https://labs.nettitude.com/blog/analysing-the-null-securitydescriptor-kernel-exploitation-mitigation-in-the-latest-windows-10-v1607-build-14393/)

[Loading and Debugging Windows Kernel Shellcodes with Windbg. Debugging DoublePulsar Shellcode.](https://vallejo.cc/2017/06/23/loading-and-debugging-windows-kernel-shellcodes-with-windbg-debugging-doublepulsar-shellcode/)

[Example of a DLL Hijack Exploit - Winamp 5.581](https://www.exploit-db.com/exploits/14789/)

[Cisco ASA Episode 3: A Journey In Analysing Heaps by Cedric Halbronn - BSides Manchester2017](https://www.youtube.com/watch?v=ADYdToi6Wn0&index=21&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)




------------
## Forensics

[dotNET_WinDBG](https://github.com/Cisco-Talos/dotNET_WinDBG)
* This python script is designed to automate .NET analysis with WinDBG. It can be used to analyse a PowerShell script or to unpack a binary packed using a .NET packer.

[Unravelling .NET with the Help of WinDBG - TALOS](http://blog.talosintelligence.com/2017/07/unravelling-net-with-help-of-windbg.html)
* This article describes:
  * How to analyse PowerShell scripts by inserting a breakpoint in the .NET API.
  * How to easily create a script to automatically unpack .NET samples following analysis of the packer logic.

[Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi)

[Happy DPAPI!](http://blog.digital-forensics.it/2015/01/happy-dpapi.html)

------------
## Fuzzing

[Introduction to Custom Protocol Fuzzing](https://www.youtube.com/watch?v=ieatSJ7ViBw)





------------
## Game Hacking





------------
## Honeypots

[Honeypot Farming: Setup Modern Honey Network](https://medium.com/@theroxyd/honeypot-farming-setup-mhn-f07d241fcac6)



------------
## ICS/SCADA

[Modbus Stager: Using PLCs as a payload/shellcode distribution system](http://www.shelliscoming.com/2016/12/modbus-stager-using-plcs-as.html)





------------
## Interesting Things

[Money Makes Money: How To Buy An ATM And What You Can Do With It by Leigh Ann Galloway - BSides Manchester2017](https://www.youtube.com/watch?v=0HbLQAGS6no&index=8&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)

[Digital Show & Tell - xiph.org](https://xiph.org/video/vid2.shtml)
	* Continuing the "firehose" tradition of maximum information density, Xiph.Org's second video on digital media explores multiple facets of digital audio signals and how they really behave in the real world. 

[what3words](https://what3words.com/about/)
* what3words provides a precise and incredibly simple way to talk about location. We have divided the world into a grid of 3m x 3m squares and assigned each one a unique 3 word address.

[(In)Outsider Trading – Hacking stocks using public information and (influence) - Robert Len - BSides CapeTown16](https://www.youtube.com/watch?v=sfHeguTEkuE)
*  This talk will take a look at how inadvertently leaked technical information from businesses, can be used to successfully trade stocks. This results in making huge profits. We look at different methods of influencing the stock market, such as DDOS attacks (at critical time periods) and simple techniques such as Phish-baiting CEO’s to acquire sensitive, relevant information that can be applied in the real world to make massive gains in profit. We will also take a look at historic trends. How previous hacks, breaches and DDOS attacks have affected stock prices and investor confidence over time. Specific reference will be made towards listed South African companies (Or a particular listed SA company) and a POC will hopefully be completed by the presentation date. 

[netman](https://github.com/iadgov/netman)
* A userland network manager with monitoring and limiting capabilities for macOS.

[netfil](https://github.com/iadgov/netfil)
* A kernel network manager with monitoring and limiting capabilities for macOS.

[Windows Firewall Control - Managing Windows Firewall is now easier than ever](https://www.binisoft.org/wfc.php)

[pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html)
* pngcheck verifies the integrity of PNG, JNG and MNG files (by checking the internal 32-bit CRCs [checksums] and decompressing the image data); it can optionally dump almost all of the chunk-level information in the image in human-readable form. For example, it can be used to print the basic statistics about an image (dimensions, bit depth, etc.); to list the color and transparency info in its palette (assuming it has one); or to extract the embedded text annotations. This is a command-line program with batch capabilities.










------------
## Lockpicking





------------
## Malware

[TIPS FOR REVERSE - ENGINEERING MALICIOUS CODE - Lenny Zeltser](https://zeltser.com/media/docs/reverse-engineering-malicious-code-tips.pdf)

[AVLeak: Fingerprinting Antivirus Emulators Through Black-Box Testing](https://www.usenix.org/system/files/conference/woot16/woot16-paper-blackthorne_update.pdf)

[malboxes](https://github.com/GoSecure/malboxes)
* Builds malware analysis Windows VMs so that you don't have to.

[Malvertising: Under The Hood by Chris Boyd - BSides Manchester2017](https://www.youtube.com/watch?v=VESvOsr91_M&index=1&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)






------------
## Mainframes





------------
## Network Scanning and Attacks


[reGeorg](https://github.com/sensepost/reGeorg)
* The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.

[Adding your protocol to Masscan](http://blog.erratasec.com/2014/11/adding-protocols-to-masscan.html)

[Davoset](https://github.com/MustLive/DAVOSET) 
* DAVOSET - it is console (command line) tool for conducting DDoS attacks on the sites via Abuse of Functionality and XML External Entities vulnerabilities at other sites.

[Too Many Cooks; Exploiting the Internet of Tr-069](http://mis.fortunecook.ie/) 

[Ever wanted to scan the internet in a few hours?](http://blog.erratasec.com/2013/10/faq-from-where-can-i-scan-internet.html)

[device-pharmer](https://github.com/DanMcInerney/device-pharmer)
* Opens 1K+ IPs or Shodan search results and attempts to login 

[Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)

[SSL & TLS Penetration Testing [Definitive Guide]](https://www.aptive.co.uk/blog/tls-ssl-security-testing/)

[OpenSSH User Enumeration Time-Based Attack](http://seclists.org/fulldisclosure/2013/Jul/88)

[testssl.sh](https://github.com/drwetter/testssl.sh)
* testssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.

[ SSL/TLS and PKI History ](https://www.feistyduck.com/ssl-tls-and-pki-history/)
*  A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem. Based on Bulletproof SSL and TLS, by Ivan Ristić.

[Collection of Symantec Endpoint Protection Vulnerabilities + some exploits](http://codewhitesec.blogspot.nl/2015/07/symantec-endpoint-protection.html)

[DNS Cache Snooping or Snooping the Cache for Fun and Profit - Luis Grangeia](http://cs.unc.edu/~fabian/course_papers/cache_snooping.pdf)


[Outgoing port tester - http://letmeoutofyour.net/](http://letmeoutofyour.net/)

[Outgoing port tester - portquiz.net](http://portquiz.net/)
*  This server listens on all TCP ports, allowing you to test any outbound TCP port. 

[Enteletaor](https://github.com/cr0hn/enteletaor)
* Message Queue & Broker Injection tool that implements attacks to Redis, RabbitMQ and ZeroMQ.

[NfSpy](https://github.com/bonsaiviking/NfSpy)
* NfSpy is a Python library for automating the falsification of NFS credentials when mounting an NFS share.

[nsec3map](https://github.com/anonion0/nsec3map)
* a tool to enumerate the resource records of a DNS zone using its DNSSEC NSEC or NSEC3 chain


[HatCloud](https://github.com/HatBashBR/HatCloud)
* HatCloud build in Ruby. It makes bypass in CloudFlare for discover real IP. This can be useful if you need test your server and website. Testing your protection against Ddos (Denial of Service) or Dos. CloudFlare is services and distributed domain name server services, sitting between the visitor and the Cloudflare user's hosting provider, acting as a reverse proxy for websites. Your network protects, speeds up and improves availability for a website or the mobile application with a DNS change.


[Cisc0wn - Cisco SNMP Script](https://github.com/nccgroup/cisco-SNMP-enumeration)
* Automated Cisco SNMP Enumeration, Brute Force, Configuration Download and Password Cracking

[DNS Reference Information - technet](https://technet.microsoft.com/en-us/library/dd197499(v=ws.10).aspx)

[DNS Records: an Introduction](https://www.linode.com/docs/networking/dns/dns-records-an-introduction)


[dnsftp](https://github.com/breenmachine/dnsftp)
* Client/Server scripts to transfer files over DNS. Client scripts are small and only use native tools on the host OS.

[tcpovericmp](https://github.com/Maksadbek/tcpovericmp)
* TCP implementation over ICMP protocol to bypass firewalls

[icmptunnel](https://github.com/DhavalKapil/icmptunnel)
* Transparently tunnel your IP traffic through ICMP echo and reply packets. 

[IPv6 - Playing with IPv6 for fun and profit](https://github.com/zbetcheckin/IPv6)




------------
## Network | Monitoring & Logging

[Introduction to Windows Event Forwarding](https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4)

[Monitoring what matters – Windows Event Forwarding for everyone (even if you already have a SIEM.)](https://blogs.technet.microsoft.com/jepayne/2015/11/23/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem/)



------------
## OSINT


[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
* AWSBucketDump is a tool to quickly enumerate AWS S3 buckets to look for loot. It's similar to a subdomain bruteforcer but is made specifically for S3 buckets and also has some extra features that allow you to grep for delicious files as well as download interesting files if you're not afraid to quickly fill up your hard drive.


[NATO Open Source Intelligence Handbook](http://www.oss.net/dynamaster/file_archive/030201/ca5fb66734f540fbb4f8f6ef759b258c/NATO%20OSINT%20Handbook%20v1.2%20%2d%20Jan%202002.pdf)


------------
##	OS X






------------
## Password Cracking

[Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists)
* Wordlists sorted by probability originally created for password generation and testing



------------
## Phishing/SE


[Outlook and Exchange for the Bad Guys Nick Landers](https://www.youtube.com/watch?v=cVhc9VOK5MY)

[Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)

[Microsoft Support and Recovery Assistant for Office 365](https://testconnectivity.microsoft.com/)

[Exchange Versions, Builds & Dates](https://eightwone.com/references/versions-builds-dates/)





------------
## Physical Security


[Door Control Systems: An Examination of Lines of Attack](https://www.nccgroup.com/en/blog/2013/09/door-control-systems-an-examination-of-lines-of-attack/)

[Hacking things by touching them - armadillo](https://www.armadillophone.com/blog/2017/08/27/hacking-things-by-touching-them)

[Home Insecurity: No Alarms, False Alarms, and SIGINT](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20presentations/Logan%20Lamb/DEFCON-22-Logan-Lamb-HOME-INSECURITY-NO-ALARMS-FALSE-ALARMS-AND-SIGINT-WP.pdf)


[Let's get physical: Breaking home security systems & bypassing controls - Black Hat USA 2013](https://www.youtube.com/watch?v=O4ya3z-PCQs)

[Tamper resistance and  hardware security](https://www.cl.cam.ac.uk/~sps32/PartII_030214.pd)

|||||||||||||||||||||||||

[Physical Security - Everything That's Wrong With Your Typical Door - Deviant Ollam - SANS Webcast](https://www.youtube.com/watch?v=raBMFqZRB0s&t=&feature=youtu.be&app=desktop)

[Safe to Armed in Seconds - Deviant Ollam - DEF CON 19](https://www.youtube.com/watch?v=3SVMT_zNlgA)

[What Does The Perfect Door Or Padlock Look Like? - Deviant Ollam - BruCON 0x08](https://www.youtube.com/watch?v=4skSBwBBI-s)

["Lockpicking in Real Life versus on the Screen" - The Eleventh HOPE (2016)](https://www.youtube.com/watch?v=mjBSocgMCPU)
* We all know that Hollywood has a difficult time portraying hackers accurately. This quirk often extends to the realm of showing lockpicking in movies and on TV. But sometimes, a film gets it really right! This talk is both an introduction to lockpicking (in case you still need to learn) as well as a walk through some of the best - and some of the worst - scenes of lockpicking that have ever been seen by movie and TV audiences. Learn about how to be a better lockpicker and a better filmmaker... all at the same time!

[Lockpicking, Safecracking, & More by Deviant Ollam & renderman at ShmooCon 3](https://www.youtube.com/watch?v=WTgUVhjts2U)
* For the first time on the same stage together at ShmooCon, renderman and i give a funny and informative presentation about lockpicking using much of my traditional material as well as a whole load of new content that my favorite Canadian demonstrates. In addition to his all-around general badassery, renderman even opened up a locked safe on stage... one that he had never seen before and was simply given by an audience member. That took fucking balls.

[!$@$Lockpicking & Physical security - Deviant Ollam - Best lockpicking course abc tutorial diy](https://www.youtube.com/watch?v=j6WCe-4XQ3Q)

[The Search for the Perfect Door - Deviant Ollam - Shakacon](https://www.youtube.com/watch?v=4YYvBLAF4T8)
* You have spent lots of money on a high-grade, pick-resistant, ANSI-rated lock for your door. Your vendor has assured you how it will resist attack and how difficult it would be for someone to copy your key. Maybe they’re right. But… the bulk of attacks that both penetration testers and also criminals attempt against doors have little or nothing to do with the lock itself! This talk will be a hard-hitting exploration (full of photo and video examples) of the ways in which your door — the most fundamental part of your physical security — can possibly be thwarted by someone attempting illicit entry. The scary problems will be immediately followed by simple solutions that are instantly implementable and usually very within-budget. You, too, can have a near-perfect door… if you’re willing to learn and understand the problems that all doors tend to have. 

[This Key is Your Key, This Key is My Key - Howard Payne & Deviant Ollam](https://www.youtube.com/watch?v=a9b9IYqsb_U)

[I'll Let Myself In Tactics of Physical Pentesters - Deviant Ollam -B-sides Orlando 2017](https://www.youtube.com/watch?v=Rctzi66kCX4)

[Mastering Master Keys - Deviant Ollam - HOPE Number 9](https://www.youtube.com/watch?v=aVPSaKLKHd4)

[Ways your alarm system can fail - abak Javadi Keith Howell](https://www.youtube.com/watch?v=g4-B7d3ZQUA)

[Alarmed About Your Alarm System Yet - Keith Howell, Babak Javadi](https://www.youtube.com/watch?v=5rnkhqEj_Po)

[Electronic Locks - are really secure?!](https://www.youtube.com/watch?v=ZK0MfE7o4HU)
* Many people are familiar with the ways in which mechanical locks can be attacked, compromised, and bypassed. Indeed, the hands-on workshops and the availability of pick tools at the Lockpick Village is an enduring part of the fun at DeepSec and other popular security conferences around the world. Often, attendees will ask questions like, "So, this is really great... but what if someone is using an electronic lock? How hard is it to open the door, then?" Unfortunately, due to time and space constraints, our answer is typically, "Well... that's a very complicated question. Sometimes they're good, and sometimes they're weak." We often promise greater detail another day, another time... but until now that time has not come. Finally now, however, TOOOL will describe some of the most popular electronic locks and show examples of how they can sometimes be attacked. 

[Distinguishing Lockpicks: Raking vs Lifting vs Jiggling and More - Deviant Ollam](https://www.youtube.com/watch?v=e07VRxJ01Fs)

[Hacking Wireless Home Security Systems by Eric Escobar - BSides Manchester2017](https://www.youtube.com/watch?v=kERUpg5YMis&index=12&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)
















------------
## Policy

[NIST Cybersecurity Practice Guide, Securing Wireless Infusion Pumps in Healthcare Delivery Organizations](https://nccoe.nist.gov/projects/use-cases/medical-devices)
* [SP 1800-8a: Executive Summary](https://nccoe.nist.gov/publication/draft/1800-8/VolA/)
* [SP 1800-8b: Approach, Architecture, and Security Characteristics ](https://nccoe.nist.gov/publication/draft/1800-8/VolB/)
* [SP 1800-8c: How-To Guides](https://nccoe.nist.gov/publication/draft/1800-8/VolC/)

[IT Law Wiki](http://itlaw.wikia.com/wiki/The_IT_Law_Wiki))



------------
## Post Exploitation/Privilege Escalation

[VirtualBox Detection Via WQL Queries](http://waleedassar.blogspot.com/)

[chw00t: chroot escape tool](https://github.com/earthquake/chw00t)

[Breaking Out of a Chroot Jail Using PERL](http://pentestmonkey.net/blog/chroot-breakout-perl)

[ssh environment - circumvention of restricted shells](http://www.opennet.ru/base/netsoft/1025195882_355.txt.html)

[avepoc](https://github.com/govolution/avepoc)
* some pocs for antivirus evasion

[CC_Checker](https://github.com/NetSPI/PS_CC_Checker)
* CC_Checker cracks credit card hashes with PowerShell.

[SearchForCC](https://github.com/eelsivart/SearchForCC)
* A collection of open source/common tools/scripts to perform a system memory dump and/or process memory dump on Windows-based PoS systems and search for unencrypted credit card track data.

[Post Exploitation Persistence With Application Shims (Intro)](http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/)

[RemoteRecon](https://github.com/xorrior/RemoteRecon)
* RemoteRecon provides the ability to execute post-exploitation capabilities against a remote host, without having to expose your complete toolkit/agent. Often times as operator's we need to compromise a host, just so we can keylog or screenshot (or some other miniscule task) against a person/host of interest. Why should you have to push over beacon, empire, innuendo, meterpreter, or a custom RAT to the target? This increases the footprint that you have in the target environment, exposes functionality in your agent, and most likely your C2 infrastructure. An alternative would be to deploy a secondary agent to targets of interest and collect intelligence. Then store this data for retrieval at your discretion. If these compromised endpoints are discovered by IR teams, you lose those endpoints and the information you've collected, but nothing more. Below is a visual representation of how I imagine an adversary would utilize this.

[PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)
* PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement.
* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)

[RunMe.c](https://gist.github.com/hugsy/e5c4ce99cd7821744f95)
* Trick to run arbitrary command when code execution policy is enforced (i.e. AppLocker or equivalent). Works on Win98 (lol) and up - tested on 7/8

[Escaping a Python sandbox with a memory corruption bug](https://hackernoon.com/python-sandbox-escape-via-a-memory-corruption-bug-19dde4d5fea5)

[Empire without PowerShell.exe](https://bneg.io/2017/07/26/empire-without-powershell-exe/)

[Triple-Fetch-Kernel-Creds](https://github.com/coffeebreakerz/Tripple-Fetch-Kernel-Creds)
* Attempt to steal kernelcredentials from launchd + task_t pointer (Based on: CVE-2017-7047)

[Breaking out of secured Python environments](http://tomforb.es/breaking-out-of-secured-python-environments)

[UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell/tree/master)

[rundll32 lockdown testing goodness](https://www.attackdebris.com/?p=143)

[Requiem For An Admin, Walter Legowski (@SadProcessor) - BSides Amsterdam 2017](https://www.youtube.com/watch?v=uMg18TvLAcE&index=3&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
* Orchestrating BloodHound and Empire for Automated AD Post-Exploitation. Lateral Movement and Privilege Escalation are two of the main steps in the Active Directory attacker kill- chain. Applying the 'assume breach' mentality, more and more companies are asking for red-teaming type of assessments, and security researcher have therefor developed a wide range of open-source tools to assist them during these engagements. Out of these, two have quickly gained a solid reputation: PowerShell Empire and BloodHound (Both by @Harmj0y & ex-ATD Crew). In this Session, I will be presenting DogStrike, a new tool (PowerShell Modules) made to interface Empire & BloodHound, allowing penetration testers to merge their Empire infrastructure into the bloodhound graph database. Doing so allows the operator to request a bloodhound path that is 'Agent Aware', and makes it possible to automate the entire kill chain, from initial foothold to DA - or any desired part of an attacker's routine. Presentation will be demo-driven. Code for the module will be made public after the presentation. Automation of Active Directory post-exploitation is going to happen sooner than you might think. (Other tools are being released with the same goal*). Is it a good thing? Is it a bad thing? If I do not run out of time, I would like to finish the presentation by opening the discussion with the audience and see what the consequences of automated post- exploitation could mean, from the red, the blue or any other point of view... *: DeathStar by @Byt3Bl33d3r | GoFetch by @TalTheMaor.




------------
## Programming:


[How to find 56 potential vulnerabilities in FreeBSD code in one evening](https://www.viva64.com/en/b/0496/)

[Static analysis tools for PHP](https://github.com/exakat/php-static-analysis-tools)
* A reviewed list of useful PHP static analysis tools

[x86 Call/Return Protocol](http://pages.cs.wisc.edu/~remzi/Classes/354/Fall2012/Handouts/Handout-CallReturn.pdf)

[Diving deep into Python – the not-so-obvious language parts](http://sebastianraschka.com/Articles/2014_deep_python.html)

[C Right-Left Rule](http://ieng9.ucsd.edu/~cs30x/rt_lt.rule.html)

[PEP: 551 Title: Security transparency in the Python runtime Version](https://github.com/python/peps/blob/cd795ec53c939e5b40808bb9d7a80c428c85dd52/pep-0551.rst)

[Build an API under 30 lines of code with Python and Flask](https://impythonist.wordpress.com/2015/07/12/build-an-api-under-30-lines-of-code-with-python-and-flask/)	

[.Net The Managed Heap and Garbage Collection in the CLR](https://www.microsoftpressstore.com/articles/article.aspx?p=2224054)

[Nmap (XML) Parser documentation](https://nmap-parser.readthedocs.io/en/latest/)

[The little book about OS development](https://littleosbook.github.io/)

[How to Make a Computer Operating System in C++](https://github.com/SamyPesse/How-to-Make-a-Computer-Operating-System)

[Deobfuscating Python Bytecode](https://www.fireeye.com/blog/threat-research/2016/05/deobfuscating_python.html)

[.NET serialiception](https://blog.scrt.ch/2016/05/12/net-serialiception/)


------------
## Policy and Compliance



------------
## RE

[Windows for Reverse Engineers](http://www.cse.tkk.fi/fi/opinnot/T-110.6220/2014_Reverse_Engineering_Malware_AND_Mobile_Platform_Security_AND_Software_Security/luennot-files/T1106220.pdf)

[Reversing GO binaries like a pro](https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/	)

[Detecting debuggers by abusing a bad assumption within Windows](http://www.triplefault.io/2017/08/detecting-debuggers-by-abusing-bad.html)


[Flipping Bits and Opening Doors: Reverse Engineering the Linear Wireless Security DX Protocol](https://duo.com/blog/flipping-bits-and-opening-doors-reverse-engineering-the-linear-wireless-security-dx-protocol)

[Reverse Engineering of Proprietary Protocols, Tools and Techniques - Rob Savoye - FOSDEM 2009 ](https://www.youtube.com/watch?v=t3s-mG5yUjY)
* This talk is about reverse engineering a proprietary network protocol, and then creating my own implementation. The talk will cover the tools used to take binary data apart, capture the data, and techniques I use for decoding unknown formats. The protocol covered is the RTMP protocol used by Adobe flash, and this new implementation is part of the Gnash project.

[Jailbreaks and Pirate Tractors: Reverse Engineering Do’s and Don’ts](https://www.youtube.com/watch?v=8_mMTVsOM6Y)

[Multiple vulnerabilities found in the Dlink DWR-932B (backdoor, backdoor accounts, weak WPS, RCE ...)](https://pierrekim.github.io/blog/2016-09-28-dlink-dwr-932b-lte-routers-vulnerabilities.html)


[funcap - IDA Pro script to add some useful runtime info to static analysis.](https://github.com/deresz/funcap)
* This script records function calls (and returns) across an executable using IDA debugger API, along with all the arguments passed. It dumps the info to a text file, and also inserts it into IDA's inline comments. This way, static analysis that usually follows the behavioral runtime analysis when analyzing malware, can be directly fed with runtime info such as decrypted strings returned in function's arguments. In author's opinion this allows to understand the program's logic way faster than starting the "zero-knowledge" reversing. Quick understanding of a malware sample code was precisely the motivation to write this script and the author has been using it succesfully at his $DAYJOB. It is best to see the examples with screenshots to see how it works (see below). It must be noted that the script has been designed with many misconceptions, errors and bad design decisions (see issues and funcap.py code) as I was learning when coding but it has one advantage - it kind of works :) Current architectures supported are x86, amd64 and arm.

[Ponce](https://github.com/illera88/Ponce)
* Ponce (pronounced [ 'poN θe ] pon-they ) is an IDA Pro plugin that provides users the ability to perform taint analysis and symbolic execution over binaries in an easy and intuitive fashion. With Ponce you are one click away from getting all the power from cutting edge symbolic execution. Entirely written in C/C++.

[IDASkins](https://github.com/zyantific/IDASkins)
* Advanced skinning plugin for IDA Pro

[idaConsonance](https://github.com/eugeii/ida-consonance)
* Consonance, a dark color theme for IDA.


[SWFRETools](https://github.com/sporst/SWFREtools)
* The SWFRETools are a collection of tools built for vulnerability analysis of the Adobe Flash player and for malware analysis of malicious SWF files. The tools are partly written in Java and partly in Python and are licensed under the GPL 2.0 license.


[Reflexil](https://github.com/sailro/Reflexil)
* Reflexil is an assembly editor and runs as a plug-in for Red Gate's Reflector, ILSpy and Telerik's JustDecompile. Reflexil is using Mono.Cecil, written by Jb Evain and is able to manipulate IL code and save the modified assemblies to disk. Reflexil also supports C#/VB.NET code injection.

[de4dot](https://github.com/0xd4d/de4dot)
* de4dot is an open source (GPLv3) .NET deobfuscator and unpacker written in C#. It will try its best to restore a packed and obfuscated assembly to almost the original assembly. Most of the obfuscation can be completely restored (eg. string encryption), but symbol renaming is impossible to restore since the original names aren't (usually) part of the obfuscated assembly.

[BsidesLV ProvingGrounds17 - Introduction to Reversing and Pwning - David Weinman](https://www.youtube.com/watch?v=4rjWlOvbz7U&app=desktop)
* 

[Reversing C++ programs with IDA pro and Hex-rays](https://blog.0xbadc0de.be/archives/67)

[How to Identify Virtual Table Functions with IDA Pro and the VTBL Plugin](https://www.youtube.com/watch?v=XHW9Akb4KLI&app=desktop)

[vtbl-ida-pro-plugin](https://github.com/nektra/vtbl-ida-pro-plugin)
* Identifying Virtual Table Functions using VTBL IDA Pro Plugin + Deviare Hooking Engine

[Fun combining anti-debugging and anti-disassembly tricks](http://blog.sevagas.com/?Fun-combining-anti-debugging-and)

[python-uncompyle6](https://github.com/rocky/python-uncompyle6)
* A Python cross-version decompiler

[Decompyle++](https://github.com/zrax/pycdc)
* C++ python bytecode disassembler and decompiler

[Python Decompiler](https://github.com/alex/python-decompiler)
* This project aims to create a comprehensive decompiler for CPython bytecode (likely works with PyPy as well, and any other Python implementation that uses CPython's bytecode)


[PyInstaller Extractor](https://sourceforge.net/p/pyinstallerextractor/tickets/5/)
* Extract contents of a Windows executable file created by pyinstaller 

[Easy Python Decompiler](https://sourceforge.net/projects/easypythondecompiler/)
* Python 1.0 - 3.4 bytecode decompiler 










------------
## Red Team/Pentesting

[A  Year In The Red by Dominic Chell and Vincent Yiu - BSides Manchester2017](https://www.youtube.com/watch?v=-FQgWGktYtw&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP&index=23)

[Data Sound Modulation POC](https://github.com/iiamit/data-sound-poc)

[Goodbye Data, Hello Exfiltration - Itzik Kotler](https://www.youtube.com/watch?v=GwaIvm2HJKc)
* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
* [Slides](http://www.ikotler.org/GoodbyeDataHelloExfiltration_BSidesORL.pdf)

[Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)
* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.

[In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)
* In this session, we will reveal and demonstrate perfect exfiltration via indirect covert channels (i.e. the communicating parties don’t directly exchange network packets). This is a family of techniques to exfiltrate data (low throughput) from an enterprise in a manner indistinguishable from genuine traffic. Using HTTP and exploiting a byproduct of how some websites choose to cache their pages, we will demonstrate how data can be leaked without raising any suspicion. These techniques are designed to overcome even perfect knowledge and analysis of the enterprise network traffic.

[Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)

[A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)
* Covert channels are used for the secret transfer of information. Encryption only protects communication from being decoded by unauthorised parties, whereas covert channels aim to hide the very existence of the communication. Initially, covert channels were identified as a security threat on monolithic systems i.e. mainframes. More recently focus has shifted towards covert channels in computer network protocols. The huge amount of data and vast number of different protocols in the Internet seems ideal as a high-bandwidth vehicle for covert communication. This article is a survey of the existing techniques for creating covert channels in widely deployed network and application protocols. We also give an overview of common methods for their detection, elimination, and capacity limitation, required to improve security in future computer networks. 

[Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)
* [Covert Timing Channels Based on HTTP Cache Headers - Paper](scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)

[P4wnP1](https://github.com/mame82/P4wnP1)
* P4wnP1 is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W.

[PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)
* PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement.
* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)

[Building A Successful Internal Adversarial Simulation Team - C. Gates & C. Nickerson - BruCON 0x08](https://www.youtube.com/watch?v=Q5Fu6AvXi_A&list=PLtb1FJdVWjUfCe1Vcj67PG5Px8u1VY3YD&index=1)

[AIX for Penetration Testers 2017 thevivi.net](https://thevivi.net/2017/03/19/aix-for-penetration-testers/)

[How To Bypass Email Gateways Using Common Payloads by Neil Lines - BSides Manchester2017](https://www.youtube.com/watch?v=eZxWDCetqkE&index=11&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)




------------
## Rootkits




------------
## SCADA


[Different Type of SCADA](http://scadastrangelove.blogspot.com/2014/10/different-type-of-scada.html)

[SCADA Strangelove or: How I Learned to Start Worrying and Love Nuclear Plants](https://www.youtube.com/watch?v=o2r7jbwTv6w)
* Modern civilization unconditionally depends on information systems. It is paradoxical but true that ICS/SCADA systems are the most insecure systems in the world. From network to application, SCADA is full of configuration issues and vulnerabilities. During our report, we will demonstrate how to obtain full access to a plant via:
* a sniffer and a packet generator; FTP and Telnet; Metasploit and oslq; a webserver and a browser; 
* About 20 new vulnerabilities in common SCADA systems including Simatic WinCC will be revealed.

[Introduction to Attacking ICS/SCADA Systems for Penetration Testers -GDS Sec](http://blog.gdssecurity.com/labs/2017/5/17/introduction-to-attacking-icsscada-systems-for-penetration-t.html)

[SCADAPASS](https://github.com/scadastrangelove/SCADAPASS)
* SCADA StrangeLove Default/Hardcoded Passwords List 

[smod - MODBUS Penetration Testing Framework](https://github.com/enddo/smod)
* #smod smod is a modular framework with every kind of diagnostic and offensive feature you could need in order to pentest modbus protocol. It is a full Modbus protocol implementation using Python and Scapy. This software could be run on Linux/OSX under python 2.7.x.









------------
## Social Engineering




------------
## System Internals

[Process Security and Access Rights - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx)

[OpenProcessToken function - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295%28v=vs.85%29.aspx)

[Linux Kernel Security Subsystem Wiki](https://kernsec.org/wiki/index.php/Main_Page)
* This is the Linux kernel security subsystem wiki, a resource for developers and users. 

[Symbols and Symbol Files - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols-and-symbol-files)

[Symbol Files - docs ms](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)

[microsoft-pdb](https://github.com/Microsoft/microsoft-pdb)
* This repo contains information from Microsoft about the PDB (Program Database) Symbol File format.

[Public and Private Symbols - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/public-and-private-symbols)

[How to Inspect the Content of a Program Database (PDB) File](https://www.codeproject.com/Articles/37456/How-To-Inspect-the-Content-of-a-Program-Database-P)

[microsoft-pdb](https://github.com/Microsoft/microsoft-pdb)
* This repo contains information from Microsoft about the PDB (Program Database) Symbol File format.

[Symbol Files](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)
* Normally, debugging information is stored in a symbol file separate from the executable. The implementation of this debugging information has changed over the years, and the following documentation will provide guidance regarding these various implementations .



------------
## Threat Modeling & Analysis


[Global Adversarial Capability Modeling](https://www.youtube.com/watch?v=56T3JN09SrY#t=41)


------------
## Threat Hunting

[Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK - Part I (Event ID 7)](https://cyberwardog.blogspot.de/2017/03/chronicles-of-threat-hunter-hunting-for.html)


------------
## Web: 

[Unrestricted File Upload Security Testing - Aptive](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)

[JSShell](https://github.com/Den1al/JSShell/)
* An interactive multi-user web based JS shell written in Python with Flask (for server side) and of course Javascript and HTML (client side). It was initially created to debug remote esoteric browsers during tests and research. I'm aware of other purposes this tool might serve, use it at your own responsibility and risk.

[STUN IP Address requests for WebRTC](https://github.com/diafygi/webrtc-ips)

[Use google bots to perform SQL injections on websites](http://blog.sucuri.net/2013/11/google-bots-doing-sql-injection-attacks.html)

[JSRat-Py](https://github.com/Hood3dRob1n/JSRat-Py) 
* implementation of JSRat.ps1 in Python so you can now run the attack server from any OS instead of being limited to a Windows OS with Powershell enabled

[ParrotNG](https://github.com/ikkisoft/ParrotNG)
* ParrotNG is a tool capable of identifying Adobe Flex applications (SWF) vulnerable to CVE-2011-2461 

[The old is new, again. CVE-2011-2461 is back!](https://www.slideshare.net/ikkisoft/the-old-is-new-again-cve20112461-is-back)
* As a part of an ongoing investigation on Adobe Flash SOP bypass techniques, we identified a vulnerability affecting old releases of the Adobe Flex SDK compiler. Further investigation traced the issue back to a well known vulnerability (CVE20112461), already patched by Adobe. Old vulnerability, let's move on? Not this time. CVE20112461 is a very interesting bug. As long as the SWF file was compiled with a vulnerable Flex SDK, attackers can still use this vulnerability against the latest web browsers and Flash plugin. Even with the most recent updates, vulnerable Flex applications hosted on your domain can be exploited. In this presentation, we will disclose the details of this vulnerability (Adobe has never released all technicalities) and we will discuss how we conducted a large scale analysis on popular websites, resulting in the identification of numerous Alexa Top 50 sites vulnerable to this bug. Finally, we will also release a custom tool and a Burp plugin capable of detecting vulnerable SWF applications. 

[ParrotNG - burp plugin](https://portswigger.net/bappstore/bapps/details/f99325340a404c67a8de2ce593824e0e)

[SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd)

[Php Codz Hacking](https://github.com/80vul/phpcodz)
* Writeups of specific PHP vulns

[deblaze](http://blog.dornea.nu/2015/06/22/decode-adobe-flex-amf-protocol/)
* Performs method enumeration and interrogation against flash remoting end points.


[DB2 SQL injection cheat sheet](https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)


[xssValidator](https://github.com/nVisium/xssValidator)
* This is a burp intruder extender that is designed for automation and validation of XSS vulnerabilities. 

[PwnBack](https://github.com/k4ch0w/PwnBack)
* Burp Extender plugin that generates a sitemap of a website using Wayback Machine

[sonar.js](https://thehackerblog.com/sonar-a-framework-for-scanning-and-exploiting-internal-hosts-with-a-webpage/)
* A Framework for Scanning and Exploiting Internal Hosts With a Webpage


[Decode Adobe Flex AMF protocol](http://blog.dornea.nu/2015/06/22/decode-adobe-flex-amf-protocol/)

[Reverse shell on a Node.js application](https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/)

[Automating Web Apps Input fuzzing via Burp Macros](http://blog.securelayer7.net/automating-web-apps-input-fuzzing-via-burp-macros/)

Advanced Flash Vulnerabilities in Youtube Writeups Series
* [Advanced Flash Vulnerabilities in Youtube – Part 1](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-1/)
* [Advanced Flash Vulnerabilities in Youtube – Part 2](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-2/)
* [Advanced Flash Vulnerabilities in Youtube – Part 3](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-3/)

[dirsearch](https://github.com/maurosoria/dirsearch)
* dirsearch is a simple command line tool designed to brute force directories and files in websites.

[Browser Security White Paper - Cure53](https://browser-security.x41-dsec.de/X41-Browser-Security-White-Paper.pdf)

[Penetration Testing AWS Storage: Kicking the S3 Bucket](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/)

[G-Jacking AppEngine-based applications - HITB2014](https://conference.hitb.org/hitbsecconf2014ams/materials/D2T1-G-Jacking-AppEngine-based-Applications.pdf)

[Reverse shell on a Node.js application](https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/)

[Unrestricted File Upload Testing](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)

[Object MetaInformation](https://www.w3.org/Protocols/HTTP/Object_Headers.html#public)

[DOM Based Angular Sandbox Escapes by Gareth Heyes - BSides Manchester2017](https://www.youtube.com/watch?v=jlSI5aVTEIg&index=16&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)






------------
## Wireless Stuff


[Honey, I'm Home!! Hacking Z-Wave Home Automation Systems - video](https://www.youtube.com/watch?v=KYaEQhvodc8)
* [Slides - PDF](https://cybergibbons.com/wp-content/uploads/2014/11/honeyimhome-131001042426-phpapp01.pdf)


[An Auditing Tool for Wi-Fi or Wired Ethernet Connections - Matthew Sullivan](https://www.cookiecadger.com/wp-content/uploads/Cookie%20Cadger.pdf)