# Embedded Device Security

## Table of Contents
<!-- nav:toc:start -->
- [Drone security](#ref-embedded-1)
- [General](#ref-embedded-2)
  - [101](#ref-embedded-3)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-4)
  - [Circuit Boards](#ref-embedded-5)
  - [Educational/Informative](#ref-embedded-6)
  - [Resources/Reference](#ref-embedded-7)
  - [Tools](#ref-embedded-8)
  - [Miscellaneous](#ref-embedded-9)
- [Attacking Routers(Firmware)](#ref-embedded-10)
  - [101](#ref-embedded-11)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-12)
  - [Tools](#ref-embedded-13)
- [Cable Modem Hacking](#ref-embedded-14)
  - [101](#ref-embedded-15)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-16)
  - [Tools](#ref-embedded-17)
  - [Miscellaneous](#ref-embedded-18)
- [Credit Cards](#ref-embedded-19)
  - [101](#ref-embedded-20)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-21)
  - [Tools](#ref-embedded-22)
- [esp8266 H/W related](#ref-embedded-23)
- [Flash Memory](#ref-embedded-24)
  - [101](#ref-embedded-25)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-26)
  - [General](#ref-embedded-27)
  - [Tools](#ref-embedded-28)
  - [Miscellaneous](#ref-embedded-29)
- [Firmware(Non-Specific)](#ref-embedded-30)
  - [101](#ref-embedded-31)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-32)
  - [General](#ref-embedded-33)
  - [Tools](#ref-embedded-34)
  - [Miscellaneous](#ref-embedded-35)
- [Internet of Things (IoT)](#ref-embedded-36)
  - [101](#ref-embedded-37)
  - [Articles, Blogposts & Writeups](#ref-embedded-38)
  - [Talks & Presentations](#ref-embedded-39)
  - [Educational/Informative](#ref-embedded-40)
  - [Tools](#ref-embedded-41)
  - [Papers](#ref-embedded-42)
- [JTAG](#ref-embedded-43)
  - [101](#ref-embedded-44)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-45)
  - [Tools](#ref-embedded-46)
  - [Miscellaneous](#ref-embedded-47)
- [Medical Devices](#ref-embedded-48)
  - [101](#ref-embedded-49)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-50)
  - [General](#ref-embedded-51)
  - [Talks & Presentations](#ref-embedded-52)
  - [Tools](#ref-embedded-53)
  - [Miscellaneous](#ref-embedded-54)
- [Miscellaneous Devices](#ref-embedded-55)
- [Lightning/Thunderbolt](#ref-embedded-56)
  - [101](#ref-embedded-57)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-58)
  - [General](#ref-embedded-59)
  - [Tools](#ref-embedded-60)
  - [Miscellaneous](#ref-embedded-61)
- [PCI](#ref-embedded-62)
  - [101](#ref-embedded-63)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-64)
  - [General](#ref-embedded-65)
  - [Tools](#ref-embedded-66)
  - [Miscellaneous](#ref-embedded-67)
- [Printers](#ref-embedded-68)
- [Smart TVs/Monitors](#ref-embedded-69)
  - [101](#ref-embedded-70)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-71)
  - [General](#ref-embedded-72)
  - [Tools](#ref-embedded-73)
  - [Miscellaneous](#ref-embedded-74)
- [SPI(Serial Peripheral Interface Bus)](#ref-embedded-75)
  - [101](#ref-embedded-76)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-77)
  - [General](#ref-embedded-78)
  - [Tools](#ref-embedded-79)
  - [Miscellaneous](#ref-embedded-80)
- [SD Cards](#ref-embedded-81)
  - [101](#ref-embedded-82)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-83)
  - [General](#ref-embedded-84)
  - [Tools](#ref-embedded-85)
  - [Miscellaneous](#ref-embedded-86)
- [PCB Related](#ref-embedded-87)
- [Point-of-Sale](#ref-embedded-88)
  - [101](#ref-embedded-89)
  - [Articles & Writeups](#ref-embedded-90)
  - [Talks & Presentations](#ref-embedded-91)
  - [Papers](#ref-embedded-92)
  - [Tools](#ref-embedded-93)
  - [Miscellaneous](#ref-embedded-94)
- [Secure Tokens](#ref-embedded-95)
  - [101](#ref-embedded-96)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-97)
  - [General](#ref-embedded-98)
  - [Tools](#ref-embedded-99)
  - [Miscellaneous](#ref-embedded-100)
- [USB](#ref-embedded-101)
  - [101](#ref-embedded-102)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-103)
  - [Educational/Informative](#ref-embedded-104)
  - [Tools](#ref-embedded-105)
  - [Miscellaneous](#ref-embedded-106)
  - [BadUSB](#ref-embedded-107)
  - [USB Device/Class Info](#ref-embedded-108)
- [SIM Cards](#ref-embedded-109)
  - [101](#ref-embedded-110)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-111)
  - [Tools](#ref-embedded-112)
  - [Miscellaneous](#ref-embedded-113)
- [Smartcards](#ref-embedded-114)
  - [101](#ref-embedded-115)
  - [Articles/Papers/Talks/Writeups](#ref-embedded-116)
  - [Tools](#ref-embedded-117)
  - [Miscellaneous](#ref-embedded-118)
  - [Chameleon Mini](#ref-embedded-119)
- [Voting Machines](#ref-embedded-120)
- [Specific Attacks](#ref-embedded-121)
  - [Fault Attacks](#ref-embedded-122)
  - [Glitch Attacks](#ref-embedded-123)
  - [Traffic Injection](#ref-embedded-124)
- [Unsorted resources](#ref-embedded-125)
<!-- nav:toc:end -->

## <a id="ref-embedded-1"></a>Drone security

* [ArduPilot](http://ardupilot.org/ardupilot/index.html)
* [Knocking my neighbors kids cruddy drone offline - DefCon 23 Robinson and Mitchell](https://www.youtube.com/watch?v=5CzURm7OpAA)
* [Game of Drones - Brown,Latimer - Defcon25](https://www.youtube.com/watch?v=iG7hUE2BZZo)
    * We’ve taken a MythBusters-style approach to testing the effectiveness of a variety of drone defense solutions, pitting them against our DangerDrone. Videos demonstrating the results should be almost as fun for you to watch as they were for us to produce. Expect to witness epic aerial battles against an assortment of drone defense types
* [DUMLRacer](https://github.com/CunningLogic/DUMLRacer)
    * Root Exploit for DJI Drones and Controllers (up to and including v01.04.0100)

---------------------

## <a id="ref-embedded-2"></a><a id="general" name="general"></a>General

### <a id="ref-embedded-3"></a>101

* [Embedded System - Wikipedia](https://en.wikipedia.org/wiki/Embedded_system)
* [Hardware Security and Trust/ECE 4451/5451: Introduction to Hardware Security and Trust](https://www.engr.uconn.edu/~tehrani/teaching/hst/)
* [Hardware Hacking for Software People](http://dontstuffbeansupyournose.com/2011/08/25/hardware-hacking-for-software-people/)
* [I2C - Inter-Integrated Circuit](https://en.wikipedia.org/wiki/I%C2%B2C)
* [Display Data Channel](https://en.wikipedia.org/wiki/Display_Data_Channel)
* [UART - Universal asynchronous receiver/transmitter](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver/transmitter)

### <a id="ref-embedded-4"></a>Articles/Papers/Talks/Writeups

* [Infecting the Embedded Supply Chain - somersetrecon](https://www.somersetrecon.com/blog/2018/7/27/infecting-the-embedded-supply-chain)
* [Exploiting Qualcomm EDL Programmers (1): Gaining Access & PBL Internals](https://alephsecurity.com/2018/01/22/qualcomm-edl-1/)
* [Using the Shikra to Attack Embedded Systems: Getting Started - xipiter](https://www.xipiter.com/musings/using-the-shikra-to-attack-embedded-systems-getting-started)

### <a id="ref-embedded-5"></a>Circuit Boards

* [Deconstructing the Circuit Board Sandwich DEF CON 22 - Joe Grand aka Kingpin](https://www.youtube.com/watch?v=O8FQZIPkgZM)

### <a id="ref-embedded-6"></a>Educational/Informative

* [OWASP Embedded Application Security](https://www.owasp.org/index.php/OWASP_Embedded_Application_Security)
    * [Live Copy](https://scriptingxss.gitbooks.io/embedded-appsec-best-practices//)
* [Hardware Hacking - Nicolas Collins](http://www.nicolascollins.com/texts/originalhackingmanual.pdf)
* [Reversing and Exploiting Embedded Devices: The Software Stack (Part 1)](https://p16.praetorian.com/blog/reversing-and-exploiting-embedded-devices-part-1-the-software-stack)
* [Common methods of H/W hacking](https://www.sparkfun.com/news/1314)
* [Hardware Hacking Videos](http://vimeo.com/album/1632121)
* [Hardware Hacking the Easyware Way](http://www.irongeek.com/i.php?page=videos/derbycon6/417-hardware-hacking-the-easyware-way-brian-fehrman)
    * Interested in hardware hacking but not quite sure where to start? Does the thought of soldering thrill you (or scare you)? Come check out this talk to see just how easy it is to jump into this exciting field of research! Many people and companies use similar models of hardware. Unlike software, these devices rarely receive security updates. Sometimes, used devices are sold without clearing the configurations and important data is left behind. After this talk, you will know how to find hidden interfaces on these devices, start searching for vulnerabilities and sensitive information, and have irresistible urges to go home and tear apart all your old networking equipment. Did we mention...live demo?
* [Methodologies for Hacking Embedded Security Appliances](https://media.blackhat.com/us-13/US-13-Bathurst-Methodologies-for-Hacking-Embdded-Security-Appliances-Slides.pdf)
* [Hardware Backdooring is Practical -Jonathan Brossard](https://www.youtube.com/watch?v=umBruM-wFUw)
* [Infecting the Embedded Supply Chain - Somerset Recon](https://www.somersetrecon.com/blog/2018/7/27/infecting-the-embedded-supply-chain)

### <a id="ref-embedded-7"></a>Resources/Reference

* [FCC ID Lookup](http://transition.fcc.gov/oet/ea/fccid/)
    * Lookup devices according to FCC ID

### <a id="ref-embedded-8"></a>Tools

* [Logic Pirate](http://dangerousprototypes.com/docs/Logic_Pirate)
    * The Logic Pirate is an inexpensive, yet capable open source logic analyzer. It is designed to support the SUMP logic analyzer protocol. Costs $30. Recommended to me by those who use it.
    * [Blog Post about it](http://dangerousprototypes.com/2014/04/15/new-prototype-logic-pirate-8-channel-256k-sample-60msps-logic-analyzer/)
* [Debug Probes - J-Link and J-Trace](https://www.segger.com/jlink-debug-probes.html)
* [Hardware reverse engineering tools (Olivier Thomas)  - REcon 2013](https://www.youtube.com/watch?v=o77GTR8RovM)
    * [Gettting in with the Proxmark3 & ProxBrute](https://www.trustwave.com/Resources/SpiderLabs-Blog/Getting-in-with-the-Proxmark-3-and-ProxBrute/)
* [Metasploit Hardware Brdige](https://community.rapid7.com/community/transpo-security/blog/2017/02/02/exiting-the-matrix)
    * [Hardware Bridge API](http://opengarages.org/hwbridge/)
* [NSA Playset](http://www.nsaplayset.org/)
    * In the coming months and beyond, we will release a series of dead simple, easy to use tools to enable the next generation of security researchers.  We, the security community have learned a lot in the past couple decades, yet the general public is still ill equipped to deal with real threats that face them every day, and ill informed as to what is possible. Inspired by the NSA ANT catalog, we hope the NSA Playset will make cutting edge security tools more accessible, easier to understand, and harder to forget.  Now you can play along with the NSA!
* [Anti-Evil Maid](http://theinvisiblethings.blogspot.com/2011/09/anti-evil-maid.html?m=1)

### <a id="ref-embedded-9"></a>Miscellaneous

    * NFC - See wireless section
* [Project bdp](http://www.malcolmstagg.com/bdp-s390.html)
    * This is a project to modify the Sony Blu-ray BDP firmware. It started out with only the BDP-S390, but has branched out to include other players and a variety of goals, including removing Cinavia and obtaining Region-Free.
* [Learn how to send an SMS text message in Python by pushing a button on your Arduino!](http://juliahgrace.com/intro-hardware-hacking-arduino.html)
* [U-Boot -- the Universal Boot Loader](http://www.denx.de/wiki/U-Boot)
    * Very popular on embedded devices open source bootloader for linux
    * [Manual/Documentation](http://www.denx.de/wiki/DULG/Manual)
* [Probe comparison - sigrok.org](https://sigrok.org/wiki/Probe_comparison)

---------------------------

## <a id="ref-embedded-10"></a><a id="routers" name="routers"></a>Attacking Routers(Firmware)

### <a id="ref-embedded-11"></a>101

* [Unpacking Firmware images from cable modems](http://w00tsec.blogspot.com.br/2013/11/unpacking-firmware-images-from-cable.html)

### <a id="ref-embedded-12"></a>Articles/Papers/Talks/Writeups

* [Hacking the D-Link DIR-890L](http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/)
* [Multiple Vulnerabilities in BHU WiFi “uRouter”](http://blog.ioactive.com/2016/08/multiple-vulnerabilities-in-bhu-wifi.html)
* [From Zero to ZeroDay Journey: Router Hacking (WRT54GL Linksys Case)](http://www.defensecode.com/whitepapers/From_Zero_To_ZeroDay_Network_Devices_Exploitation.txt)
* [Rooting the MikroTik routers (SHA2017)](https://www.youtube.com/watch?v=KZWGD9fWIcM)
    * In this talk I describe my journey into reverse engineering parts of MikroTik system to gain access to hardware features and the shell behind the RouterOS that has no “ls”.
* [From 0-day to exploit – Buffer overflow in Belkin N750 (CVE-2014-1635)](https://labs.integrity.pt/articles/from-0-day-to-exploit-buffer-overflow-in-belkin-n750-cve-2014-1635/)
* [Firmware Exploitation with JEB: Part 1](https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-1/)

### <a id="ref-embedded-13"></a>Tools

* [Router Post-Exploitation Framework](https://github.com/mncoppola/rpef)
    * Abstracts and expedites the process of backdooring stock firmware images for consumer/SOHO routers.

---------------------------

## <a id="ref-embedded-14"></a><a id="modem" name="modem"></a>Cable Modem Hacking

### <a id="ref-embedded-15"></a>101

* [Cable Modem - Wikipedia](https://en.wikipedia.org/wiki/Cable_modem)
* [Data Over Cable Service Interface Specification (DOCSIS) - Wikipedia](https://en.wikipedia.org/wiki/DOCSIS)

### <a id="ref-embedded-16"></a>Articles/Papers/Talks/Writeups

* [Docsis hacking](https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-self.pdf)
    * [Video](https://www.youtube.com/watch?v=tEg09zSsfQo)
* [Hacking Docsis for fun and profit](https://www.defcon.org/images/defcon-18/dc-18-presentations/Blake-bitemytaco/DEFCON-18-Blake-bitemytaco-Hacking-DOCSIS.pdf)
    * [Video](https://www.youtube.com/watch?v=aaaJ86K-ovE)
* [Hacking DOCSIS: Or how to get free internet - Chaosmaster - Easterhegg 2017](https://www.youtube.com/watch?v=wFnfYElMGe0)
    * In German
* [Modem Cloning for Fun (but NOT for profit!) - Yifan Lu](https://yifan.lu/2017/04/02/modem-cloning-for-fun-but-not-for-profit/)
* [Hacking cable modems the later years - Bernardo Rodrigues - NullByte 2016](https://www.slideshare.net/nullbytecon/nullbyte-2015-hackingcablemodemsthelateryears)
* [ Beyond your cable modem: How not to do DOCSIS networks - Alexander Graf](https://media.ccc.de/v/32c3-7133-beyond_your_cable_modem#video)

### <a id="ref-embedded-17"></a>Tools

* [Keykeriki v2.0](http://www.remote-exploit.org/articles/keykeriki_v2_0__8211_2_4ghz/index.html)
    * Hardware to attack wireless keyboards and other such things

### <a id="ref-embedded-18"></a>Miscellaneous

-----------------------

## <a id="ref-embedded-19"></a><a id="cc" name="cc"></a>Credit Cards

### <a id="ref-embedded-20"></a>101

### <a id="ref-embedded-21"></a>Articles/Papers/Talks/Writeups

* [Cloning Credit Cards: A combined pre-play and downgrade attack on EMV Contactless](https://0b4af6cdc2f0c5998459-c0245c5c937c5dedcca3f1764ecc9b2f.ssl.cf2.rackcdn.com/12055-woot13-roland.pdf)
* [How to Hack a Contactless Payment System](https://hackfu.mwrinfosecurity.com/hackfu-blog/params/post/465447/how-to-hack-a-contactless-payment-system.html)

### <a id="ref-embedded-22"></a>Tools

* [MagSpoof - credit card/magstripe spoofer](https://github.com/samyk/magspoof)

---------------

## <a id="ref-embedded-23"></a>esp8266 H/W related

* [esp8266 wiki](https://github.com/esp8266/esp8266-wiki)

---------------------------

## <a id="ref-embedded-24"></a><a id="flash" name="flash"></a>Flash Memory

### <a id="ref-embedded-25"></a>101

* [Flash Memory - Wikipedia](https://en.wikipedia.org/wiki/Flash_memory)

### <a id="ref-embedded-26"></a>Articles/Papers/Talks/Writeups

* [Reverse Engineering Flash Memory for Fun and Benefit - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)
* [Vulnerabilities in MLC NAND Flash Memory Programming: Experimental Analysis, Exploits, and Mitigation Techniques](https://pdfs.semanticscholar.org/b9bc/a3c9f531002854af48de121cdcc8e0520c7f.pdf)
* [Reverse Engineering: Reverse Engineering Flash Memory for Fun and Benefit - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)

### <a id="ref-embedded-27"></a>General

### <a id="ref-embedded-28"></a>Tools

### <a id="ref-embedded-29"></a>Miscellaneous

--------------------------

## <a id="ref-embedded-30"></a><a id="firmware" name="firmware"></a>Firmware(Non-Specific)

### <a id="ref-embedded-31"></a>101

* Check the BIOS/UEFI page as well.
* Check out the RE page too.
* [Reverse Engineering Firmware Primer - SecurityWeekly](https://wiki.securityweekly.com/Reverse_Engineering_Firmware_Primer)

### <a id="ref-embedded-32"></a>Articles/Papers/Talks/Writeups

* [Lost your "secure" HDD PIN? We can help!](https://syscall.eu/pdf/2016-Lenoir_Rigo-HDD_PIN-paper.pdf)
* [Analyzing and Running binaries from Firmware Images - Part 1](http://w00tsec.blogspot.com.br/2013/09/analyzing-and-running-binaries-from.html)

### <a id="ref-embedded-33"></a>General

* [Damn Vulnerable Router Firmware (DVRF) v0.5](https://github.com/b1ack0wl/DVRF)
    * The goal of this project is to simulate a real world environment to help people learn about other CPU architectures outside of the x86_64 space. This project is also for those who are curious about embedded research, but don't want to invest a lot of money.

### <a id="ref-embedded-34"></a>Tools

* [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
    * FAT is a toolkit built in order to help security researchers analyze and identify vulnerabilities in IoT and embedded device firmware. 
* [dfu-programmer](https://github.com/dfu-programmer/dfu-programmer)
    * dfu-programmer is an implementation of the Device Firmware Upgrade class USB driver that enables firmware upgrades for various USB enabled (with the correct bootloader) Atmel chips.  This program was created because the Atmel "FLIP" program for flashing devices does not support flashing via USB on Linux, and because standard DFU loaders do not work for Atmel's chips.

### <a id="ref-embedded-35"></a>Miscellaneous

* [Firmware Forensics: Diffs, Timelines, ELFs and Backdoors](http://w00tsec.blogspot.com/2015/02/firmware-forensics-diffs-timelines-elfs.html)
* [Firmwalker](https://github.com/craigz28/firmwalker)
    * A simple bash script for searching the extracted or mounted firmware file system. It will search through the extracted or mounted firmware file system for things of interest
* [Disk Genie - SpritesMods](http://spritesmods.com/?art=diskgenie)

---------------------------

## <a id="ref-embedded-36"></a><a id="iot" name="iot"></a>Internet of Things (IoT)

### <a id="ref-embedded-37"></a>101

* [A Primer on IoT Security Research](https://community.rapid7.com/community/infosec/blog/2015/03/10/iot-security-research-whats-it-take)

### <a id="ref-embedded-38"></a>Articles, Blogposts & Writeups

* [Smart Parking Meters](http://uninformed.org/?v=all&a=6&t=sumry)
    * Security through obscurity is unfortunately much more common than people think: many interfaces are built on the premise that since they are a "closed system" they can ignore standard security practices. This paper will demonstrate how parking meter smart cards implement their protocol and will point out some weaknesses in their design that open the doors to the system. It will also present schematics and code that you can use to perform these basic techniques for auditing almost any type of blackblox secure memory card.
* [Smart Nest Thermostat A Smart Spy in Your Home](https://www.youtube.com/watch?v=UFQ9AYMee_Q)
* [A Survey of Various Methods for Analyzing the Amazon Echo](https://vanderpot.com/Clinton_Cook_Paper.pdf)
* Hacking the Dropcam series
    * [Part 1 - Dropcam Comms](http://blog.includesecurity.com/2014/03/Reverse-Engineering-Dropcam-Communications.html)
    * [Part 2 - Rooting the Dropcam](http://blog.includesecurity.com/2014/04/reverse-engineering-dropcam-rooting-the-device.html)
    * [Part 3 - Dropcam Lua Bytecode](http://blog.includesecurity.com/2014/08/Reverse-Engineering-Dropcam-Lua-Bytecode.html)
* [When IoT Attacks: Hacking A Linux-Powered Rifle ](https://www.blackhat.com/docs/us-15/materials/us-15-Sandvik-When-IoT-Attacks-Hacking-A-Linux-Powered-Rifle.pdf)

### <a id="ref-embedded-39"></a>Talks & Presentations

* [When IoT Research Matters - Mark Loveless - Derbycon2017](https://www.youtube.com/watch?v=abkb5-F7BfA)
    * Most IoT research involves low hanging fruit and kitchen appliances. But what happens when the tech you are researching is changing a niche industry, or creating one? This involves a little deeper dive. This talk illustrates some basic concepts and includes some tips on how to make that dive slightly deeper, with examples of hacking tool usage, going above and beyond with a vendor during disclosure, and creating realistic attack scenarios without coming across as mere stunt hacking.
* [IoT Security: Executing an Effective Security Testing Process  - Deral Heiland - Derbycon2017](https://www.irongeek.com/i.php?page=videos/derbycon7/t403-iot-security-executing-an-effective-security-testing-process-deral-heiland)
    * With IoT expected to top 20 billion connected devices by the end of the decade. A focused effort is critical if we plan to be successfully securing our new IoT driven world. One of the primary necessities to meet this goal is to develop sound methods for identification, and mitigation of security vulnerabilities within IoT products. As an IoT security researcher and consultant, I regularly conduct IoT security testing. Within my testing methodologies I leverage a holistic approach that focuses on the entire ecosystem of an IoT solution, including: hardware, mobile, and cloud environments allowing for a more through evaluation of a solutions security issues. During this presentation attendees will learn about the ecosystem structure of IoT and security implication of the interconnected components as I guide the audience through several research projects focused on security testing of an IoT technology. Using live demonstration I will show real-world security vulnerability examples identified within each segment of an IoT ecosystem 
* [Backdooring the Frontdoor - Jmaxxz - DEF CON 24](https://www.youtube.com/watch?v=MMB1CkZi6t4&feature=youtu.be)
    * As our homes become smarter and more connected we come up with new ways of reasoning about our privacy and security. Vendors promise security, but provide little technical information to back up their claims. Further complicating the matter, many of these devices are closed systems which can be difficult to assess. This talk will explore the validity of claims made by one smart lock manufacturer about the security of their product. The entire solution will be deconstructed and examined all the way from web services to the lock itself. By exploiting multiple vulnerabilities Jmaxxz will demonstrate not only how to backdoor a front door, but also how to utilize these same techniques to protect your privacy.

### <a id="ref-embedded-40"></a>Educational/Informative

* [Security of Things: An Implementers’ Guide to Cyber-Security for Internet of Things Devices and Beyond - NCC Group](https://www.nccgroup.com/media/481272/2014-04-09_-_security_of_things_-_an_implementers_guide_to_cyber_security_for_internet_of_things_devices_and_beyond-2.pdf)
* [Ian Douglas - Creating an Internet of Private Things](https://www.youtube.com/watch?v=4W8SkujOXi4&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=8)
    * The next big market push is to have the cool IoT device that’s connected to the internet. As we’ve seen from the Mirai and Switcher hacks, it’s important to embed the appropriate safeguards so that devices are not open to attack. When selecting device components there are things that should be checked for, and when you’re doing the coding and workflows, there are other things that need to be taken in to account. Although security and privacy are close cousins, they’re also different. This talk will be centered around some best security and privacy practices as well as some common errors that should be avoided.

### <a id="ref-embedded-41"></a>Tools

### <a id="ref-embedded-42"></a>Papers

---------------

## <a id="ref-embedded-43"></a><a id="jtag" name="jtag"></a>JTAG

### <a id="ref-embedded-44"></a>101

* [JTAG - Wikipedia](https://en.wikipedia.org/wiki/JTAG)
* [What is JTAG and how can I make use of it? - xjtag.com](https://www.xjtag.com/about-jtag/what-is-jtag/)
* [What is JTAG? - corelis.com](https://www.corelis.com/education/tutorials/jtag-tutorial/what-is-jtag/)

### <a id="ref-embedded-45"></a>Articles/Papers/Talks/Writeups

### <a id="ref-embedded-46"></a>Tools

* [JTAGulator](http://www.grandideastudio.com/portfolio/jtagulator/)
    * JTAGulator is an open source hardware tool that assists in identifying OCD connections from test points, vias, or component pads on a target device.

### <a id="ref-embedded-47"></a>Miscellaneous

-------------------

## <a id="ref-embedded-48"></a><a id="medical" name="medical"></a>Medical Devices

### <a id="ref-embedded-49"></a>101

### <a id="ref-embedded-50"></a>Articles/Papers/Talks/Writeups

* [Insulin Pumps, Decapped chips and Software Defined Radios - Pete Schwamb](https://blog.usejournal.com/insulin-pumps-decapped-chips-and-software-defined-radios-1be50f121d05)

### <a id="ref-embedded-51"></a>General

* [FDA.gov Medical Devices Page](https://www.fda.gov/Medicaldevices/default.htm)

### <a id="ref-embedded-52"></a>Talks & Presentations

* [Anatomy of a Medical Device Hack- Doctors vs. Hackers in a Clinical Simulation Cage Match - Joshua Corman & Christian Dameff MD MS & Jeff Tully MD & Beau Woods(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t316-anatomy-of-a-medical-device-hack-doctors-vs-hackers-in-a-clinical-simulation-cage-match-joshua-corman-christian-dameff-md-ms-jeff-tully-md-beau-woods)
    * In the near future, a crisis unfolds at a hospital: patients on automated drug infusion machines overdose, hacked insulin pumps lead to car crashes, and internal defibrillators flatline weakened hearts. Clinical staff are unprepared and ill equipped to treat these complications, as they are all unaware of the true culprits behind the crisis. A state of emergency is declared, the public demands answers, and policymakers scramble to preserve national trust. This was the scenario that played out in first-of-their-kind clinical simulations carried out in June, and the results were scary yet unsurprising: health care cybersecurity is in critical condition. It’s been a long four years since the guiding ideals and message of The Cavalry was tempered from the forge that was the first Hacker Constitutional Congress (hosted in these very halls at DerbyCon 3). The battle continues to ensure that technologies capable of impacting public safety and human life remain worthy of our trust, and no battlefield looms larger than the healthcare space. Despite important steps toward change- from the Hippocratic Oath for Connected Medical Devices to the just-published Health Care Industry Cybersecurity Task Force Report- recent events remind us that the dual pillars of healthcare technology- patient facing medical devices and the infrastructure that supports clinical practice- remain as vulnerable and exposed as ever. Join Josh Corman and Beau Woods of I am The Cavalry as they team up with Christian Dameff, MD, and Jeff Tully, MD- two “white coat hackers” working to save patient lives at the bedside- to share lessons learned from the world’s first ever clinical simulations of patients threatened by hacked medical devices. By bringing the technical work done by security researchers you know and love to life and demonstrating the profound impact to patient physiology from compromised devices, these life-like simulations provide a powerful avenue to engage with stakeholder groups including clinicians and policymakers, and may represent the new standard for hackers looking to demonstrate the true impact and importance of their biomedical work.

### <a id="ref-embedded-53"></a>Tools

### <a id="ref-embedded-54"></a>Miscellaneous

------------------------

## <a id="ref-embedded-55"></a><a id="misc-devices" name="misc-devices"></a>Miscellaneous Devices

* [dustcloud](https://github.com/dgiese/dustcloud)
    * Xiaomi Vacuum Robot Reverse Engineering and Hacking
* [Xiaomi Dafang hacks](https://github.com/EliasKotlyar/Xiaomi-Dafang-Hacks)
    * This repository is a collection of information & software for the Xiaomi Dafang Camera
* [xiaomi-sensors-hacks](https://github.com/PischeDev/xiaomi-sensors-hacks)
    * collection of xiaomi/aqara sensors hacks/modifications

---------------------------

## <a id="ref-embedded-56"></a><a id="lightning" name="lightning"></a>Lightning/Thunderbolt

### <a id="ref-embedded-57"></a>101

### <a id="ref-embedded-58"></a>Articles/Papers/Talks/Writeups

* [Apple Lightning Reverse Engineered](http://ramtin-amin.fr/#tristar)

### <a id="ref-embedded-59"></a>General

### <a id="ref-embedded-60"></a>Tools

* [ThunderGate](http://thundergate.io/)
    * ThunderGate is a collection of tools for the manipulation of Tigon3 Gigabit Ethernet controllers, with special emphasis on the Broadcom NetLink 57762, such as is found in Apple Thunderbolt Gigabit Ethernet adapters.

### <a id="ref-embedded-61"></a>Miscellaneous

---------------------------

## <a id="ref-embedded-62"></a><a id="pci" name="pci"></a>PCI

### <a id="ref-embedded-63"></a>101

### <a id="ref-embedded-64"></a>Articles/Papers/Talks/Writeups

* [Stupid PCIe Tricks featuring NSA Playset: PCIe](https://www.youtube.com/watch?v=Zwz61uVxiM0)

### <a id="ref-embedded-65"></a>General

### <a id="ref-embedded-66"></a>Tools

* [Inception](https://github.com/carmaa/inception)
    * Inception is a physical memory manipulation and hacking tool exploiting PCI-based DMA. The tool can attack over FireWire, Thunderbolt, ExpressCard, PC Card and any other PCI/PCIe interfaces. Inception aims to provide a relatively quick, stable and easy way of performing intrusive and non-intrusive memory hacks against live computers using DMA.
* [PCILeech](https://github.com/ufrisk/pcileech)
    * The PCILeech use the USB3380 chip in order to read from and write to the memory of a target system. This is achieved by using DMA over PCI Express. No drivers are needed on the target system. The USB3380 is only able to read 4GB of memory natively, but is able to read all memory if a kernel module (KMD) is first inserted into the target system kernel. Reading 8GB of memory from the target system take around one (1) minute. The PCILeech hardware is connected with USB3 to a controlling computer running the PCILeech program. PCILeech is also capable of inserting a wide range of kernel modules into the targeted kernels - allowing for pulling and pushing files, remove the logon password requirement, loading unsigned drivers, executing code and spawn system shells. The software is written in visual studio and runs on Windows 7/Windows 10. Supported target systems are currently the x64 versions of: Linux, FreeBSD, macOS and Windows.

### <a id="ref-embedded-67"></a>Miscellaneous

----------------------

## <a id="ref-embedded-68"></a><a id="printers" name="printers"></a>Printers

See 'Printers' Section in Network Attacks & Scanning

------------------

## <a id="ref-embedded-69"></a><a id="smart" name="smart"></a>Smart TVs/Monitors

### <a id="ref-embedded-70"></a>101

### <a id="ref-embedded-71"></a>Articles/Papers/Talks/Writeups

* [Smart TV Security - #1984 in 21 st century](https://cansecwest.com/slides/2013/SmartTV%20Security.pdf)
    * This talk is more about security bugs and rootkits than about firmware for TVs. This talk more covers rootkits than security bugs and exploitation thereof, as they’re not different to traditional techniques. This talk is about general security issues of all Smart TV vendors.
* [MonitorDarkly](https://github.com/RedBalloonShenanigans/MonitorDarkly)
    * This repo contains the exploit for the Dell 2410U monitor. It contains utilities for communicating with and executing code on the device. The research presented here was done in order to highlight the lack of security in "modern" on-screen-display controllers. Please check out our Recon 0xA presentation (included) for a detailed description of our research findings and process.

### <a id="ref-embedded-72"></a>General

### <a id="ref-embedded-73"></a>Tools

### <a id="ref-embedded-74"></a>Miscellaneous

---------------

## <a id="ref-embedded-75"></a><a id="spi" name="spi"></a>SPI(Serial Peripheral Interface Bus)

### <a id="ref-embedded-76"></a>101

* [Serial Peripheral Interface Bus - Wikipedia](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface_Bus)
* [SPI](https://trmm.net/SPI_flash)

### <a id="ref-embedded-77"></a>Articles/Papers/Talks/Writeups

### <a id="ref-embedded-78"></a>General

### <a id="ref-embedded-79"></a>Tools

### <a id="ref-embedded-80"></a>Miscellaneous

---------------------------

## <a id="ref-embedded-81"></a><a id="sdcard" name="sdcard"></a>SD Cards

### <a id="ref-embedded-82"></a>101

### <a id="ref-embedded-83"></a>Articles/Papers/Talks/Writeups

* [The Exploration and Exploitation of an SD Memory Card](https://www.youtube.com/watch?v=Tj-zI8Tl218)
    * This talk demonstrates a method for reverse engineering and loading code into the microcontroller within a SD memory card.

### <a id="ref-embedded-84"></a>General

### <a id="ref-embedded-85"></a>Tools

### <a id="ref-embedded-86"></a>Miscellaneous

-------------

## <a id="ref-embedded-87"></a><a id="pcb" name="pcb"></a>PCB Related

* [PCB-RE: Tools & Techniques](https://www.amazon.com/dp/1979331383)

------------------------------

## <a id="ref-embedded-88"></a><a id="pos" name="pos"></a>Point-of-Sale

### <a id="ref-embedded-89"></a>101

### <a id="ref-embedded-90"></a>Articles & Writeups

### <a id="ref-embedded-91"></a>Talks & Presentations

* [Chip & PIN is Definitely Broken - Defcon 19](https://www.youtube.com/watch?v=JABJlvrZWbY)
* [Jackson Thuraisamy & Jason Tran - Hacking POS PoS Systems](https://www.youtube.com/watch?v=-n7oJqmTUCo) 
* [Pwning the POS! - Nick Douglas - Notacon11](https://www.irongeek.com/i.php?page=videos/notacon11/pwning-the-pos-mick-douglas)
    * Everybody’s talking about the Target breach. However, there’s lots wrong with the retail space… and it’s been this way for quite some time! Focusing on Point of Sale (POS) systems this talk will show you how to exploit friendly the POS ecosystem really is, and how you can help fix things.
* [Pandora's Cash Box - The Ghost under your POS - RECON2015](https://recon.cx/2015/slides/recon2015-17-nitay-artenstein-shift-reduce-Pandora-s-Cash-Box-The-Ghost-Under-Your-POS.pdf)
* [Retail Store/POS Penetration Testing - Daniel Brown - Derbycon2017](https://www.irongeek.com/i.php?page=videos/derbycon7/s10-retail-storepos-penetration-testing-daniel-brown)
    * Penetration Testing a retail/POS environment. The methods companies are using to try and protect them, methods of bypassing security implementations, and how they tie into a companies overall security.

### <a id="ref-embedded-92"></a>Papers

### <a id="ref-embedded-93"></a>Tools

### <a id="ref-embedded-94"></a>Miscellaneous

------------------

## <a id="ref-embedded-95"></a><a id="tokens" name="tokens"></a>Secure Tokens

### <a id="ref-embedded-96"></a>101

### <a id="ref-embedded-97"></a>Articles/Papers/Talks/Writeups

* [Secure Tokin’ & Doobiekeys: How to roll your own counterfeit hardware security devices - @securelyfitz, @r00tkillah](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-r00killah-and-securelyfitz-Secure-Tokin-and-Doobiekeys.pdf)

### <a id="ref-embedded-98"></a>General

### <a id="ref-embedded-99"></a>Tools

### <a id="ref-embedded-100"></a>Miscellaneous

---------------------------

## <a id="ref-embedded-101"></a><a id="usb" name="usb"></a>USB

### <a id="ref-embedded-102"></a>101

* [USB in a Nutshell](http://www.beyondlogic.org/usbnutshell/usb1.shtml)
    * Great explanation of the USB standard in depth

### <a id="ref-embedded-103"></a>Articles/Papers/Talks/Writeups

* **Attacking**
    * [USB Attacks Need Physical Access Right? Not Any More… by Andy Davis](https://www.youtube.com/watch?v=90MIjgh5ESU)
        * This project's goal is to turn PS2303-based USB flash drive into a cheap USB 3.0 development platform (i.e. fast USB 3.0 to FPGA bridge).
    * [Multiplexed Wired Attack Surfaces - Michael Ossmann & Kos - Toorcon15](https://www.youtube.com/watch?v=4QB79921Nlw)
        * Manufacturers of mobile devices often multiplex several wired interfaces onto a single connector. Some of these interfaces, probably intended for test and development, are still enabled when the devices ship. We'll show you how you can get a shell on a popular mobile phone via its USB port without using a USB connection and we will release an open source tool for exploring multiplexed wired interfaces.
    * [DRIVE IT YOURSELF: USB CAR](http://www.linuxvoice.com/drive-it-yourself-usb-car-6/)
        * Reversing USB and writing USB Drivers for an RC car.
    * [Introduction to USB and Fuzzing - Matt DuHarte - Defcon23](https://www.youtube.com/watch?v=KWOTXypBt4E)
    * [Lowering the USB Fuzzing Barrier by Transparent Two-Way Emulation](https://www.usenix.org/system/files/conference/woot14/woot14-vantonder.pdf)
        * Abstract: Increased focus on the Universal Serial Bus (USB) attack surface of devices has recently resulted in a number of new vulnerabilities. Much of this advance has been aided by the advent of hardware-based USB emulation techniques. However, existing tools and methods are far from ideal, requiring a significant investment of time, money, and effort. In this work, we present a USB testing framework that improves significantly over existing methods in providing a cost-effective and flexible way to read and modify USB communication. Amongst other benefits, the framework enables man-in-the-middle fuzz testing between a host and peripheral. We achieve this by performing two-way emulation using inexpensive bespoke USB testing hardware, thereby delivering capa-bilities of a USB analyzer at a tenth of the cost. Mutational fuzzing is applied during live communication between a host and peripheral, yielding new security-relevant bugs. Lastly, we comment on the potential of the framework to improve current exploitation techniques on the USB channel.
    * [USB For All - Defcon 22 - Jesse Michael and Mickey Shkatov](https://www.youtube.com/watch?v=7HnQnpJwr-c)
        * USB is used in almost every computing device produced in recent years. In addition to well-known usages like keyboard, mouse, and mass storage, a much wider range of capabilities exist such as Device Firmware Update, USB On-The-Go, debug over USB, and more. What actually happens on the wire? Is there interesting data we can observe or inject into these operations that we can take advantage of? In this talk, we will present an overview of USB and its corresponding attack surface. We will demonstrate different tools and methods that can be used to monitor and abuse USB for malicious purposes.
    * [Implementing an USB Host Driver Fuzzer - Daniel Mende - Troopers14](https://www.youtube.com/watch?v=h777lF6xjs4)
    * [Attacking secure USB keys, behind the scene](https://www.j-michel.org/blog/2018/01/16/attacking-secure-usb-keys-behind-the-scene)
    * [Attacking encrypted USB keys the hard(ware) way - Jean-Michel Picod, Rémi Audebert, Elie Bursztein -BHUSA 17](https://elie.net/talk/attacking-encrypted-usb-keys-the-hardware-way)
        * In this talk, we will present our methodology to assess "secure" USB devices both from the software and the hardware perspectives. We will demonstrate how this methodology works in practice via a set of case-studies. We will demonstrate some of the practical attacks we found during our audit so you will learn what type of vulnerability to look for and how to exploit them. Armed with this knowledge and our tools, you will be able to evaluate the security of the USB device of your choice.
    * [Here's a List of 29 Different Types of USB Attacks - BleepingComputer](https://www.bleepingcomputer.com/news/security/heres-a-list-of-29-different-types-of-usb-attacks/)
    * [5 Things to Do Now: the USB/JTAG/IME Exploit - ci.security](https://ci.security/news/article/5-things-to-do-now-the-usb-jtag-ime-exploit)
* **Understanding**
    * [USB Device Drivers: A Stepping Stone into your Kernel](https://www.youtube.com/watch?v=HQWFHskIY2)
        * [Slides])(www.jodeit.org/research/DeepSec2009_USB_Device_Drivers.pdf)

### <a id="ref-embedded-104"></a>Educational/Informative

* [USBProxy](https://github.com/dominicgs/USBProxy)
    * A USB man in the middle device using USB On-The-Go, libUSB and gadgetFS 
* [Attacks via physical access to USB (DMA…?)](https://security.stackexchange.com/questions/118854/attacks-via-physical-access-to-usb-dma)
* [Can a connected USB device read all data from the USB bus?](https://security.stackexchange.com/questions/37927/can-a-connected-usb-device-read-all-data-from-the-usb-bus?rq=1)
* [Defending Against Malicious USB Firmware with GoodUSB - Dave Tian, Adam Bates, Kevin Butler](https://cise.ufl.edu/~butler/pubs/acsac15.pdf)
* [Defending Against Malicious USB Firmware with GoodUSB - davejintian.org](https://davejingtian.org/2015/12/03/defending-against-malicious-usb-firmware-with-goodusb/)

### <a id="ref-embedded-105"></a>Tools

* [WHID Injector: an USB-Rubberducky/BadUSB on Steroids](https://whid-injector.blogspot.lt/2017/04/whid-injector-how-to-bring-hid-attacks.html)
* [umap](https://github.com/nccgroup/umap) 
    * The USB host security assessment tool
* [NSA USB Playset - ShmooCon201](https://www.youtube.com/watch?v=eTDBFpLYcGA)
* [Phison PS2303 (PS2251-03) framework](https://bitbucket.org/flowswitch/phison)

### <a id="ref-embedded-106"></a>Miscellaneous

* [Vendors, Disclosure, and a bit of WebUSB Madness - Markus Vervier](https://pwnaccelerator.github.io/2018/webusb-yubico-disclosure.html)

### <a id="ref-embedded-107"></a>BadUSB

* [Slides](https://srlabs.de/blog/wp-content/uploads/2014/11/SRLabs-BadUSB-Pacsec-v2.pdf)
* [Video](https://www.youtube.com/watch?v=nuruzFqMgIw)
* [Code - Psychson](https://github.com/adamcaudill/Psychson) 
* [Media Transfer Protocol and USB device Research](http://nicoleibrahim.com/part-1-mtp-and-ptp-usb-device-research/)

### <a id="ref-embedded-108"></a>USB Device/Class Info

* [USB Device Class Specifications - Official Site](http://www.usb.org/developers/docs/devclass_docs/)
    * These specifications recommend design targets for classes of devices. For HID related information, please go to the [HID web page.](http://www.usb.org/developers/docs/docs/hidpage/)
* [Universal Serial Bus Device Class Specification for Device Firmware Upgrade Version 1.1 Aug 5, 2004](http://www.usb.org/developers/docs/devclass_docs/DFU_1.1.pdf)
* [Identifiers for USB Devices - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-for-usb-devices)

---------------------------

## <a id="ref-embedded-109"></a><a id="sim" name="sim"></a>SIM Cards

### <a id="ref-embedded-110"></a>101

### <a id="ref-embedded-111"></a>Articles/Papers/Talks/Writeups

* [Rooting SIM cards](https://www.youtube.com/watch?v=BR0yWjQYnhQ)
* [The Secret Life of SIM Cards - Karl Koscher/Eric Butler](https://www.youtube.com/watch?v=_-nxemBCcmU)
* [Hacking a USB Modem & SIM](http://blog.ptsecurity.com/2014/12/4g-security-hacking-usb-modem-and-sim.html)

### <a id="ref-embedded-112"></a>Tools

### <a id="ref-embedded-113"></a>Miscellaneous

---------------------------

## <a id="ref-embedded-114"></a><a id="smartcard" name="smartcard"></a>Smartcards

### <a id="ref-embedded-115"></a>101

* [ISO/IEC 7816](https://en.wikipedia.org/wiki/ISO/IEC_7816)
* [ISO/IEC 15693](https://en.wikipedia.org/wiki/ISO/IEC_15693)
* [ISO/IEC 14443](https://en.wikipedia.org/wiki/ISO/IEC_14443)
* [Introduction to Smart Card Security](http://resources.infosecinstitute.com/introduction-smartcard-security/)

### <a id="ref-embedded-116"></a>Articles/Papers/Talks/Writeups

* [How can I do that? Intro to hardware hacking with an RFID badge reader - Kevin Bong](http://www.irongeek.com/i.php?page=videos/derbycon3/3303-how-can-i-do-that-intro-to-hardware-hacking-with-an-rfid-badge-reader-kevin-bong)
* [An analysis of the vulnerabilities introduced with Java Card 3 Connected Edition](http://www.ma.rhul.ac.uk/static/techrep/2013/MA-2013-04.pdf)
* [Outsmarting smartcards](http://gerhard.dekoninggans.nl/documents/publications/dekoninggans.phd.thesis.pdf)
* [Deconstructing a secure processor - Christopher Tarnovsky](https://www.youtube.com/watch?v=w7PT0nrK2BE)
    * From start to finish, we will walk through how a current generation smartcard was successfully compromised. The talk will discuss everything that was required in the order the events took place. We will cram several months into an hour! PS- The talk will be very technical mixed hardware and software (60% hardware, 40% software).

### <a id="ref-embedded-117"></a>Tools

### <a id="ref-embedded-118"></a>Miscellaneous

### <a id="ref-embedded-119"></a>Chameleon Mini

* [Chameleon: A Versatile Emulator for Contactless Smartcards - Paper](https://www.ei.rub.de/media/crypto/veroeffentlichungen/2011/11/16/chameleon.pdf)
* [Milking the Digital Cash Cow [29c3] Video Presentation](https://www.youtube.com/watch?v=Y1o2ST03O8I)
* [ChameleonMini Hardware](https://github.com/emsec/ChameleonMini/wiki)

-----------------

## <a id="ref-embedded-120"></a><a id="voting" name="voting"></a>Voting Machines

* [Hacking Voting Machines at DEF CON 25](https://blog.horner.tj/post/hacking-voting-machines-def-con-25)
* [dc25-votingvillage-report - notes from participants](https://github.com/josephlhall/dc25-votingvillage-report/blob/master/notes-from-folks-redact.md)
* [dc25-votingvillage-report](https://github.com/josephlhall/dc25-votingvillage-report)
    * A report to synthesize findings from the Defcon 25 Voting Machine Hacking Village

--------------------------------

## <a id="ref-embedded-121"></a>Specific Attacks

* [Introduction to Trusted Execution  Environments - Steven J. Murdoch](https://www.cl.cam.ac.uk/~sjm217/talks/rhul14tee.pdf)

### <a id="ref-embedded-122"></a>Fault Attacks

* [The Sorcerer’s Apprentice Guide to Fault Attacks](https://eprint.iacr.org/2004/100.pdf)
    * The effect of faults on electronic systems has been studied since the 1970s when it was noticed that radioactive particles caused errors in chips. This led to further research on the effect of charged particles on silicon, motivated by the aerospace industry who was becoming concerned about the effect of faults in airborne electronic systems. Since then various mechanisms for fault creation and propagation have been discovered and researched. This paper covers the various methods that can be used to induce faults in semiconductors and exploit such errors maliciously. Several examples of attacks stemming from the exploiting of faults are explained. Finally a series of countermeasures to thwart these attacks are described.

### <a id="ref-embedded-123"></a>Glitch Attacks

* [Introduction to Glitch Attacks](https://wiki.newae.com/Tutorial_A2_Introduction_to_Glitch_Attacks_(including_Glitch_Explorer))
    * This advanced tutorial will demonstrate clock glitch attacks using the ChipWhisperer system. This will introduce you to many required features of the ChipWhisperer system when it comes to glitching. This will be built on in later tutorials to generate voltage glitching attacks, or when you wish to attack other targets. 
* [Glitching for n00bs - A journey to coax out chips' inner seccrets](http://media.ccc.de/browse/congress/2014/31c3_-_6499_-_en_-_saal_2_-_201412271715_-_glitching_for_n00bs_-_exide.html#video)
    * Despite claims of its obsolescence, electrical glitching can be a viable attack vector against some ICs. This presentation chronicles a quest to learn what types of electrical transients can be introduced into an integrated circuit to cause a variety of circuit faults advantageous to an reverser. Several hardware platforms were constructed during the quest to aid in research, including old-skool & solderless breadboards, photo-etched & professional PCBs, FPGAs, and cheap & dirty homemade logic analyzers. The strengths and weaknesses of the various approaches will be discussed.

### <a id="ref-embedded-124"></a>Traffic Injection

* [Perimeter-Crossing Buses: a New Attack Surface for Embedded Systems](http://www.cs.dartmouth.edu/~sws/pubs/bgjss12.pdf)
    * Abstract: This paper maps out the bus-facing attack surface of a modern operating system, and demonstrates that effective and effcient injection of traffc into the buses is real and easily a ordable. Further, it presents a simple and inexpensive hardware tool for the job, outlining the architectural and computation-theoretic challenges to creating a defensive OS/driver architecture comparable to that which has been achieved for network stacks.

---------------------------------

## <a id="ref-embedded-125"></a><a id="sort" name="sort"></a>Unsorted resources

* **Fingerprint readers**
    * [Breaking apple touchID cheaply](http://www.ccc.de/en/updates/2013/ccc-breaks-apple-touchid)
* **TPM**
    * [Attackin the TPM part 2](https://www.youtube.com/watch?v=h-hohCfo4LA)

http://www.sp3ctr3.me/hardware-security-resources/
https://github.com/yadox666/The-Hackers-Hardware-Toolkit/

* [nRF24L01+ sniffer - part 1 - Yveaux](https://yveaux.blogspot.com/2014/07/nrf24l01-sniffer-part-1.html)

* [Code used in the Great Drone Duel of 2016](https://github.com/marcnewlin/drone-duel)
    * At ToorCamp 2016, an unknown Chinese benefactor provided all participants with Cheerson CX-10A quadcopters. Coincidentally, Michael Ossmann and Dominic Spill gave a talk about hacking those very same quadcopters, and as part of their talk, they released a protocol specification which formalized the packet format used by the drones. Following the only logical path that made sense at the time, we challenged them to a duel at high noon. Using Python, nRF24LU1+ dongles (running Marc's nRF24LU1+ firmware), and an IntimidationAntenna(tm), we hacked together some code to either fly their drones far, far away, or bring them crashing to the ground. The code has been alpha tested against giant fishing nets with mixed results.
* [How To Set Up A Drone Vulnerability Testing Lab - Sanders Walters](https://medium.com/@swalters/how-to-set-up-a-drone-vulnerability-testing-lab-db8f7c762663#.9nxqcjnqw)

* [JTAG Explained (finally!): Why "IoT", Software Security Engineers, and Manufacturers Should Car - senr.io]
https://www.attify-store.com/

* [Hardware Stuff for Software People By Stephen Ridley(REcon2011)](https://archive.org/details/HardwareStuffForSoftwarePeople)
    * This talk will be an introduction to doing "hardware stuff" stuff, for people accustomed to plying their trade against software. I will discuss how to build tools (and use existing tools) to sniff/spy on a variety of hardware communications channels from UART Serial (the kind in your computer) to the very ubiquitous SPI/I2C serial busses used in virtual everything (from EEPROM in your portable DVD player to the HDMI/VGA cables between your computer and monitor). I will demonstrate how these simple hardware taps can be used to begin reverse engineering, spoofing, and fuzzing in places where (as a software person) you might not have previously felt comfortable. I will be bringing along a number of custom hardware and software tools (used specifically for these purposes) as well as a mock lab environment for demonstrations. Other than these practical skills, I am new to this "hardware stuff" so please don't expect a "embedded-JTag-SCADA-mobile" buzzword soliloquy. I'll just be sharing some stories and showing some neat hardware and software I've recently found useful.

* [PentestHardware](https://github.com/unprovable/PentestHardware)
    * "Kinda useful notes collated together publicly"

* [Embedded Devices Security and Firmware Reverse Engineering - Jonas Zaddach, Andrei Costin(BH13USA)](https://media.blackhat.com/us-13/US-13-Zaddach-Workshop-on-Embedded-Devices-Security-and-Firmware-Reverse-Engineering-WP.pdf)
    * This workshop aims at presenting a quick-start at how to inspect firmwares and a hands-on presentation with exercises on real firmwares from a security analysis standpoint.

* [Hardware and Firmware Security Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance)
    * This repository provides content for aiding DoD administrators in verifying systems have applied and enabled mitigations for hardware and firmware vulnerabilities such as side-channel and UEFI vulnerabilities. The repository is a companion to NSA Cybersecurity Advisories such as Vulnerabilities Affecting Modern Processors. This repository is updated as new information, research, strategies, and guidance are developed.

* [Inception: System-wide Security Testing of Real-World Embedded Systems Software](https://inception-framework.github.io/inception/)
http://s3.eurecom.fr/docs/usenixsec18_corteggiani.pdf

* [ESP32/ESP8266 Wi-Fi Attacks](https://github.com/Matheus-Garbelini/esp32_esp8266_attacks)

* [UBoot to Root - Deral Heiland(OISF19)](https://www.youtube.com/watch?v=Yn1mN1ySwQc&feature=share)

* [Are We Really Safe? - Bypassing Access Control Systems - Dennis Maldonado(Defcon23)](https://www.youtube.com/watch?v=-cZ7eDV2n5Y)
    * The world relies on access control systems to ensure that secured areas are only accessible to authorized users. Usually, a keypad is the only thing stopping an unauthorized person from accessing the private space behind it. There are many types of access control systems from stand-alone keypads to telephony access control. In this talk, Dennis will be going over how and where access control systems are used. Dennis will walk through and demonstrate the tips and tricks used in bypassing common access control systems. This presentation will include attack methods of all nature including physical attacks, RFID, wireless, telephony, network, and more.
* [Firmware analysis Basic Approach - Veerababu Penugonda](http://www.iotpentest.com/2019/02/firmware-analysis-basic-approach.html)

* [The Ninja Recon Technique for IoT Pentesting - attify](https://blog.attify.com/how-to-iot-pentesting/)

* [Extracting Firmware from Microcontrollers' Onboard Flash Memory, Part 1: Atmel Microcontrollers - Deral Heiland](https://blog.rapid7.com/2019/04/16/extracting-firmware-from-microcontrollers-onboard-flash-memory-part-1-atmel-microcontrollers/)
* [Extracting Firmware from Microcontrollers' Onboard Flash Memory, Part 2: Nordic RF Microcontrollers - Deral Heiland](https://blog.rapid7.com/2019/04/23/extracting-firmware-from-microcontrollers-onboard-flash-memory-part-2-nordic-rf-microcontrollers/)
* [Extracting Firmware from Microcontrollers' Onboard Flash Memory, Part 3: Microchip PIC Microcontrollers - Deral Heiland](https://blog.rapid7.com/2019/04/30/extracting-firmware-from-microcontrollers-onboard-flash-memory-part-3-microchip-pic-microcontrollers/)

* [Building your own JTAG, ISP, & Chip Off Lab - Jack Farley](http://www.farleyforensics.com/2019/04/25/have-you-ever-wanted-to-get-started-with-jtag-isp-chip-off-extractions-but-never-knew-what-you-needed-to-get-started/)

* [Reverse-engineering Broadcom wireless chipsets - Hugues Anguelkov](https://blog.quarkslab.com/reverse-engineering-broadcom-wireless-chipsets.html)

* [From 0 to Infinity - Guy](https://docs.google.com/presentation/d/19A1JWyOTueZvD8AksqCxtxriNJJgj0vPdq3cNTwndf4/mobilepresent#slide=id.g35506ef05e_0_0)

Drone hacking
* [DeviationTX with NRF24L01 module, the universal drone remote control - dronegarageblog.wordpress](https://dronegarageblog.wordpress.com/2016/06/07/deviationtx-with-nrf24l01-module-the-universal-drone-remote/)
* [How To Set Up A Drone Vulnerability Testing Lab - Sander Walters](https://medium.com/@swalters/how-to-set-up-a-drone-vulnerability-testing-lab-db8f7c762663)
* [How to hack IP camera in toy drone - u/pj530i](https://www.reddit.com/r/HowToHack/comments/4512il/how_to_hack_ip_camera_in_toy_drone/)
* [ PHD VI: How They Stole Our Drone ](http://blog.ptsecurity.com/2016/06/phd-vi-how-they-stole-our-drone.html)
* [Code used in the Great Drone Duel of 2016](https://github.com/marcnewlin/drone-duel)
    * "At ToorCamp 2016, an unknown Chinese benefactor provided all participants with Cheerson CX-10A quadcopters. Coincidentally, Michael Ossmann and Dominic Spill gave a talk about hacking those very same quadcopters, and as part of their talk, they released a protocol specification which formalized the packet format used by the drones. Following the only logical path that made sense at the time, [we challenged them](https://twitter.com/marcnewlin/status/741401358465519616) to a duel at high noon.""
* [nRF24L01+ sniffer - part 1 - Yveaux](https://yveaux.blogspot.com/2014/07/nrf24l01-sniffer-part-1.html)
* [GPS Spoofing Of UAV - YUAN Jian](https://www.syscan360.org/slides/2015_EN_GPSSpoofingofUav_YuanJian.pdf)
* [DEVIATIONTX WITH NRF24L01 MODULE, THE UNIVERSAL DRONE REMOTE CONTROL. - garagedrone](https://dronegarageblog.wordpress.com/2016/06/07/deviationtx-with-nrf24l01-module-the-universal-drone-remote/)
https://github.com/phodal/awesome-iot
https://github.com/V33RU/IoTSecurity101
* [Hardware Hacking for the Masses (and you!) - BusesCanFly(LevelUp 0x05)](https://www.youtube.com/watch?v=95vRsoGG9dc&list=PLIK9nm3mu-S4vjC0EGZVEK3WAKwT3rAFy&index=2&t=0s)
    * Custom summary: Intro(ish)-level talk for getting started/introduced to HardwareHacking. Good stuff.
    * [Slides](https://github.com/BusesCanFly/HardwareHackingForTheMasses/blob/master/HardwareHackingForTheMasses.pdf)
