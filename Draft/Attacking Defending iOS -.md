## Attacking & Defending iOS






#### TOC
[Cull](#cull)
[Hardening Guides](#harden)
[Techniques](#tech)
[Training & Tutorials](#train)
[Security Testing Methodologies](#test)
[General Research Papers](#research)
[Reverse Engineering](#re)
[Jailbreaking](#jail)


#### <a name="cull">Cull</a>

| Title     | Link |
| -------- | ------------------------ |
| **iOS 678 Security - A Study in Fail** | https://www.syscan.org/index.php/download/get/bec31d45168aa331fc01f84451e11186/SyScan15%20Stefan%20Esser%20-%20iOS%20678%20Security%20-%20A%20Study%20in%20Fail.pdf
| **Jailbreak Stories - Cyril Cattiaux(pod2g) - WWJC 2014** | https://www.youtube.com/watch?v=OBFLTb-AY38
| **Mobile self-defense - Karsten Nohl** | https://www.youtube.com/watch?v=GeCkO0fWWqc
| **Pentesting iOS Applications - Pentester Academy - Paid Course** - This course focuses on the iOS platform and application security and is ideal for pentesters, researchers and the casual iOS enthusiast who would like to dive deep and understand how to analyze and systematically audit applications on this platform using a variety of bleeding edge tools and techniques. | http://www.pentesteracademy.com/course?id=2

[Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)

* Redo formatting
#### End Cull

### General

[Hacking Your Way Up The Mobile Stack](http://vimeo.com/51270090)

[iOS Application Security Review Methodology](http://research.aurainfosec.io/ios-application-security-review-methodology/#snapshot)
* aurainfosec

[Secure iOS application development](https://github.com/felixgr/secure-ios-app-dev)
* This guide is a collection of the most common vulnerabilities found in iOS applications. The focus is on vulnerabilities in the applications’ code and only marginally covers general iOS system security, Darwin security, C/ObjC/C++ memory safety, or high-level application security. Nevertheless, hopefully the guide can serve as training material to iOS app developers that want to make sure that they ship a more secure app. Also, iOS security reviewers can use it as a reference during assessments.

[needle](https://github.com/mwrlabs/needle)
* Needle is an open source, modular framework to streamline the process of conducting security assessments of iOS apps.



### <a name="harden">List of Hardening Guides for iOS</a>

| Title     | Link |
| -------- | ------------------------ |
| **Excellent forum post detailing general security practices** | https://forum.raymond.cc/threads/hardening-apple-ios-iphone-ipad-ipod.37451/
| **Apple’s white paper on their security mechanisms built into iOS** | https://images.apple.com/ipad/business/docs/iOS_Security_Feb14.pdf)
|  **University of Texas’s Checklist/Guide to securing iOS** | https://wikis.utexas.edu/display/ISO/Apple+iOS+Hardening+Checklist
| **Center for Internet Security Guide to securing iOS 7** | https://benchmarks.cisecurity.org/tools2/iphone/CIS_Apple_iOS_7_Benchmark_v1.1.0.pdf
| **Australian Signals Intel Guide to securing iOS 7** | http://www.asd.gov.au/publications/iOS7_Hardening_Guide.pdf
| **Excellent forum post detailing general security practices** | https://forum.raymond.cc/threads/hardening-apple-ios-iphone-ipad-ipod.37451/
| **Guide to hardening iOS with the goal of privacy** | http://cydia.radare.org/sec/

### <a name="vuln">Vulnerabilities/Exploits</a>

[List of iOS Exploits](http://theiphonewiki.com/wiki/Category:Exploits)


### <a name="tech">Techniques</a>
| Title     | Link |
| -------- | ------------------------ |


### <a name="train">Training & Tutorials</a>

[iOSRE](https://github.com/kpwn/iOSRE)
* The aim of this project is to provide useful and updated tools and knowledge on iOS reverse engineering and exploitation. This is an ongoing effort, and still in a very new stage.

[OWASP iOS crackme tutorial: Solved with Frida](https://www.nowsecure.com/blog/2017/04/27/owasp-ios-crackme-tutorial-frida/)


| Title     | Link |
| -------- | ------------------------ |
| **Bypassing SSL Cert Pinning in iOS** | http://chargen.matasano.com/chargen/2015/1/6/bypassing-openssl-certificate-pinning-in-ios-apps.html
| **Learning iOS Application Security - 34 part series - damnvulnerableiosapp** | http://damnvulnerableiosapp.com/#learn
| **iOS app designed to be vulnerable in specific ways to teach security testing of iOS applications.
| **Damn Vulnerable iOS App - Getting Started** | http://damnvulnerableiosapp.com/2013/12/get-started/
| **OWASP iGOAT** - “iGoat is a safe environment where iOS developers can learn about the major security pitfalls they face as well as how to avoid them. It is made up of a series of lessons that each teach a single (but vital) security lesson.” | https://www.owasp.org/index.php/OWASP_iGoat_Project
	








### <a name="test">iOS Security Testing Methodologies/Tools</a>

| Title     | Link |
| -------- | ------------------------ |
| **iPwn Apps: Pentesting iOS Applications - SANS** | https://www.sans.org/reading-room/whitepapers/testing/ipwn-apps-pentesting-ios-applications-34577

| **iOS Application Security Testing Cheat Sheet** | https://www.owasp.org/index.php/IOS_Application_Security_Testing_Cheat_Sheet
| **idb** - idb is a tool to simplify some common tasks for iOS pentesting and research. It is still a work in progress but already provides a bunch of (hopefully) useful commands. The goal was to provide all (or most) functionality for both, iDevices and the iOS simulator. For this, a lot is abstracted internally to make it work transparently for both environments. Although recently the focus has been more on supporting devices. | https://github.com/dmayer/idb
| **idb project page** | http://cysec.org/blog/2014/01/23/idb-ios-research-slash-pentesting-tool/)
| **idb - iOS Blackbox Pentesting - Daniel A Meyer** | http://matasano.com/research/Introducing_idb_-_Simplified_Blackbox_iOS_App_Pentesting.pdf
| **idb github page** | https://github.com/dmayer/idb

[needle](https://github.com/mwrlabs/needle)
* Needle is an open source, modular framework to streamline the process of conducting security assessments of iOS apps.






### <a name="papers">General Research Papers</a>
| Title     | Link |
| -------- | ------------------------ |

[Write-up for alloc8: untethered bootrom exploit for iPhone 3GS](https://github.com/axi0mX/alloc8)









### <a name="re">Reverse Engineering</a>
| Title     | Link |
| -------- | ------------------------ |
| **IODIDE - The IOS Debugger and Integrated Disassembler Environment** | https://github.com/nccgroup/IODIDE
| **Clutch** - Fast iOS executable dumper | https://github.com/KJCracks/Clutch
| **MEMSCAN - Dump iPhone app RAM** - A Cigital consultant – Grant Douglas, recently created a utility called MEMSCAN which enables users to dump the memory contents of a given iPhone app. Dumping the memory contents of a process proves to be a useful technique in identifying keys and credentials in memory. Using the utility, users are able to recover keys or secrets that are statically protected within the application but are less protected at runtime. Users can also use the utility to verify that keys and credentials are appropriately disposed of after use. | http://www.cigital.com/justice-league-blog/2015/02/18/memscan-defined/
| **MEMSCAN - A memory scanning tool which uses mach_vm* to either dump memory or look for a specific sequence of bytes. | https://github.com/hexploitable/MEMSCAN
| **IOS Reverse Engineering toolkit** | https://github.com/S3Jensen/iRET











### <a name="jail">Jailbreaking</a>
| Title     | Link |
| -------- | ------------------------ |
| **Guide to hardening iOS with the goal of privacy** | http://cydia.radare.org/sec/
| **IPhoneDevWiki** - “Our goal is to share the sum of all human[1] knowledge about jailbroken iOS development. In other words, this is a collection of documentation written by developers to help each other write extensions (tweaks) for jailbroken iOS, and you're invited to learn from it and contribute to it too.”| http://iphonedevwiki.net/index.php/Main_Page 
| The iPhone Wiki** - The iPhone Wiki is an unofficial wiki dedicated to collecting, storing and providing information on the internals of Apple's amazing iDevices. We hope to pass this information on to the next generation of hackers so that they can go forth into their forebears' footsteps and break the ridiculous bonds Apple has put on their amazing mobile devices. | http://theiphonewiki.com/wiki/Main_Page 
| **OWASP Jailbreaking Cheat Sheet** | https://www.owasp.org/index.php/Mobile_Jailbreaking_Cheat_Sheet

[ipwndfu](https://github.com/axi0mX/ipwndfu)
* open-source jailbreaking tool for older iOS devices






### <a name="dev">iOS Development</a>
| Title     | Link |
| -------- | ------------------------ |
| **imas** - Defense for your iOS app - for developers | https://project-imas.github.io/



### Tools

[Idb](https://github.com/dmayer/idb)
* idb is a tool to simplify some common tasks for iOS pentesting and research


### Writeups

[Write-up for alloc8: untethered bootrom exploit for iPhone 3GS](https://github.com/axi0mX/alloc8)