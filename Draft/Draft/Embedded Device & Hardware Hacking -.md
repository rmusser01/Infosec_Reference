##Embedded Device Security

https://en.wikipedia.org/wiki/Embedded_system


ToC
Cull
Attacking Routers
Cable Modem Hacking
Educational
Flash Memory
Internet of Things
General Tools(S/W & H/W)
General Hardware Hacking
Miscellaneous
PCI
PenTest Dropboxes
Teensy/Rubberducky Style Attack Tools
SD Cards
Tutorials/Walkthroughs/Write-ups
USB
SmartCards
Papers





###General

[NSA Playset](http://www.nsaplayset.org/)
* In the coming months and beyond, we will release a series of dead simple, easy to use tools to enable the next generation of security researchers.  We, the security community have learned a lot in the past couple decades, yet the general public is still ill equipped to deal with real threats that face them every day, and ill informed as to what is possible. Inspired by the NSA ANT catalog, we hope the NSA Playset will make cutting edge security tools more accessible, easier to understand, and harder to forget.  Now you can play along with the NSA!




###Cull

[Chip & PIN is Definitely Broken - Defcon 19](https://www.youtube.com/watch?v=JABJlvrZWbY)

Chameleon Mini 
* [Chameleon: A Versatile Emulator for Contactless Smartcards - Paper](https://www.ei.rub.de/media/crypto/veroeffentlichungen/2011/11/16/chameleon.pdf)
* [Milking the Digital Cash Cow [29c3] Video Presentation](https://www.youtube.com/watch?v=Y1o2ST03O8I)
* [ChameleonMini Hardware](https://github.com/emsec/ChameleonMini/wiki)



[Introduction to Trusted Execution  Environments - Steven J. Murdoch](https://www.cl.cam.ac.uk/~sjm217/talks/rhul14tee.pdf)
[U-Boot -- the Universal Boot Loader](http://www.denx.de/wiki/U-Boot)
* Very popular on embedded devices open source bootloader for linux
* [Manual/Documentation](http://www.denx.de/wiki/DULG/Manual)

[Anti-Evil Maid](http://theinvisiblethings.blogspot.com/2011/09/anti-evil-maid.html?m=1)


[Adapting Software Fault Isolation to Contemporary CPU Architectures](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/35649.pdf)
* Software Fault Isolation (SFI) is an effective approach to sandboxing binary code of questionable provenance, an interesting use case for native plugins in a Web browser. We present software fault isolation schemes for ARM and x86-64 that provide control-flow and memory integrity with average performance overhead of under 5% on ARM and 7% on x86-64. We believe these are the best known SFI implementations for these architectures, with significantly lower overhead than previous systems for similar architectures. Our experience suggests that these SFI implementations benefit from instruction-level parallelism, and have particularly small impact for work- loads that are data memory-bound, both properties that tend to reduce the impact of our SFI systems for future CPU implementations.








http://greatscottgadgets.com/infiltrate2013/

http://blog.ptsecurity.com/2014/12/4g-security-hacking-usb-modem-and-sim.html







###Attacking Routers

TR-069


[I Hunt TR-069 Admins - Pwning ISPs Like a Boss - Defcon 22](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20video%20and%20slides/DEF%20CON%2022%20Hacking%20Conference%20Presentation%20By%20Shahar%20Tal%20-%20I%20Hunt%20TR%20-%20069%20Admins%20-%20Pwning%20ISPs%20Like%20a%20Boss%20-%20Video%20and%20Slides.m4v)
* [Related to TR-069](http://blog.3slabs.com/2012/12/a-brief-survey-of-cwmp-security.html)

[Router Post-Exploitation Framework](https://github.com/mncoppola/rpef
* Abstracts and expedites the process of backdooring stock firmware images for consumer/SOHO routers.

[ASUS Router infosvr UDP Broadcast root Command Execution](https://github.com/jduck/asus-cmd)

[Unpacking Firmware images from cable modems](http://w00tsec.blogspot.com.br/2013/11/unpacking-firmware-images-from-cable.html0

[From 0-day to exploit – Buffer overflow in Belkin N750 (CVE-2014-1635)](https://labs.integrity.pt/articles/from-0-day-to-exploit-buffer-overflow-in-belkin-n750-cve-2014-1635/)

[Hacking the D-Link DIR-890L](http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/)



###Cable Modem Hacking

[Docsis hacking](https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-self.pdf)
[Hacking Docsis for fun and profit](https://www.defcon.org/images/defcon-18/dc-18-presentations/Blake-bitemytaco/DEFCON-18-Blake-bitemytaco-Hacking-DOCSIS.pdf)

[Keykeriki v2.0](http://www.remote-exploit.org/articles/keykeriki_v2_0__8211_2_4ghz/index.html)
* Hardware to attack wireless keyboards and other such things




###Educational
[Hardware Hacking for Software People](http://dontstuffbeansupyournose.com/2011/08/25/hardware-hacking-for-software-people/)

[Glitching for n00bs - A journey to coax out chips' inner seccrets](http://media.ccc.de/browse/congress/2014/31c3_-_6499_-_en_-_saal_2_-_201412271715_-_glitching_for_n00bs_-_exide.html#video)
* Despite claims of its obsolescence, electrical glitching can be a viable attack vector against some ICs. This presentation chronicles a quest to learn what types of electrical transients can be introduced into an integrated circuit to cause a variety of circuit faults advantageous to an reverser. Several hardware platforms were constructed during the quest to aid in research, including old-skool & solderless breadboards, photo-etched & professional PCBs, FPGAs, and cheap & dirty homemade logic analyzers. The strengths and weaknesses of the various approaches will be discussed.

[Hardware Hacking Videos](http://vimeo.com/album/1632121)

[Serial Peripheral Interface Bus](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface_Bus)

[I2C - Inter-Integrated Circuit](https://en.wikipedia.org/wiki/I%C2%B2C)

[Display Data Channel](https://en.wikipedia.org/wiki/Display_Data_Channel)

[UART - Universal asynchronous receiver/transmitter](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver/transmitter)

[Hardware Hacking - Nicolas Collins](http://www.nicolascollins.com/texts/originalhackingmanual.pdf)

[Common methods of H/W hacking](https://www.sparkfun.com/news/1314)





###Flash Memory
[Reverse Engineering Flash Memory for Fun and Benefit - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)



###Internet of Things
[Smart Nest Thermostat A Smart Spy in Your Home](https://www.youtube.com/watch?v=UFQ9AYMee_Q)

[A Primer on IoT Security Research](https://community.rapid7.com/community/infosec/blog/2015/03/10/iot-security-research-whats-it-take)

[Security of Things: An Implementers’ Guide to Cyber-Security for Internet of Things Devices and Beyond - NCC Group](https://www.nccgroup.com/media/481272/2014-04-09_-_security_of_things_-_an_implementers_guide_to_cyber_security_for_internet_of_things_devices_and_beyond-2.pdf)






###General Tools(Software & Hardware)

[FCC ID Lookup](http://transition.fcc.gov/oet/ea/fccid/)
* Lookup devices according to FCC ID

[Logic Pirate](http://dangerousprototypes.com/docs/Logic_Pirate)
* The Logic Pirate is an inexpensive, yet capable open source logic analyzer. It is designed to support the SUMP logic analyzer protocol. Costs $30. Recommended to me by those who use it.
* [Blog Post about it](http://dangerousprototypes.com/2014/04/15/new-prototype-logic-pirate-8-channel-256k-sample-60msps-logic-analyzer/)

[JTAGulator](http://www.grandideastudio.com/portfolio/jtagulator/)
* JTAGulator is an open source hardware tool that assists in identifying OCD connections from test points, vias, or component pads on a target device.


###General Hardware Hacking

[Door Control Systems: An Examination of Lines of Attack](https://www.nccgroup.com/en/blog/2013/09/door-control-systems-an-examination-of-lines-of-attack/)

[ChipWhisperer](http://www.newae.com/chipwhisperer)
* ChipWhisperer is the first ever open-source solution that provides a complete toolchain for research and analysis of embedded hardware security. Side Channel Power Analysis, Clock Glitching, VCC Glitching, and more are all possible with this unique tool.

[Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)

[Deconstructing the Circuit Board Sandwich DEF CON 22 - Joe Grand aka Kingpin](https://www.youtube.com/watch?v=O8FQZIPkgZM)

[The Sorcerer’s Apprentice Guide to Fault Attacks](https://eprint.iacr.org/2004/100.pdf)
* The effect of faults on electronic systems has been studied since the 1970s when it was noticed that radioactive particles caused errors in chips. This led to further research on the effect of charged particles on silicon, motivated by the aerospace industry who was becoming concerned about the effect of faults in airborne electronic systems. Since then various mechanisms for fault creation and propagation have been discovered and researched. This paper covers the various methods that can be used to induce faults in semiconductors and exploit such errors maliciously. Several examples of attacks stemming from the exploiting of faults are explained. Finally a series of countermeasures to thwart these attacks are described.

[A Survey of Remote Automotive Attack Surfaces  - Black Hat USA 2014](https://www.youtube.com/watch?v=mNhFGJVq2HE)

[Smart Parking Meters](http://uninformed.org/?v=all&a=6&t=sumry)
* Security through obscurity is unfortunately much more common than people think: many interfaces are built on the premise that since they are a "closed system" they can ignore standard security practices. This paper will demonstrate how parking meter smart cards implement their protocol and will point out some weaknesses in their design that open the doors to the system. It will also present schematics and code that you can use to perform these basic techniques for auditing almost any type of blackblox secure memory card. 


###Miscellaneous

[Project bdp](http://www.malcolmstagg.com/bdp-s390.html)
* This is a project to modify the Sony Blu-ray BDP firmware. It started out with only the BDP-S390, but has branched out to include other players and a variety of goals, including removing Cinavia and obtaining Region-Free.


[Learn how to send an SMS text message in Python by pushing a button on your Arduino!](http://juliahgrace.com/intro-hardware-hacking-arduino.html)




###PCI


[Inception](https://github.com/carmaa/inception)
* Inception is a physical memory manipulation and hacking tool exploiting PCI-based DMA. The tool can attack over FireWire, Thunderbolt, ExpressCard, PC Card and any other PCI/PCIe interfaces. Inception aims to provide a relatively quick, stable and easy way of performing intrusive and non-intrusive memory hacks against live computers using DMA.
[Stupid PCIe Tricks featuring NSA Playset: PCIe](https://www.youtube.com/watch?v=Zwz61uVxiM0)



###Pentesting Drop Boxes
Minipwner


Pineapple


R00tabaga

Raspi
http://crushbeercrushcode.org/2013/03/developing-the-rogue-pi/
http://www.instructables.com/id/MyLittlePwny-Make-a-self-powered-pentesting-box-/
https://github.com/pwnieexpress/raspberry_pwn


###Teensy/Rubbery Ducky Style Attacks/Etc


[USB teensy attack set OSX](http://samy.pl/usbdriveby/)

[Paensy](https://github.com/Ozuru/Paensy)
* Paensy is a combination of the word payload and Teensy - Paensy is an attacker-oriented library written for the development of Teensy devices. Paensy simplifies mundane tasks and allows an easier platform for scripting.
* [Blogpost](http://malware.cat/?p=89)






###SD Cards
[The Exploration and Exploitation of an SD Memory Card](https://www.youtube.com/watch?v=Tj-zI8Tl218)
* This talk demonstrates a method for reverse engineering and loading code into the microcontroller within a SD memory card.



###Tutorials/Walkthroughs/Write-ups

[Methodologies for Hacking Embedded Security Appliances](https://media.blackhat.com/us-13/US-13-Bathurst-Methodologies-for-Hacking-Embdded-Security-Appliances-Slides.pdf)

[Reversing D-Links WPS pin algorithm](http://www.devttys0.com/2014/10/reversing-d-links-wps-pin-algorithm/)

[Firmware Forensics: Diffs, Timelines, ELFs and Backdoors](http://w00tsec.blogspot.com/2015/02/firmware-forensics-diffs-timelines-elfs.html)

[Disk Genie - SpritesMods](http://spritesmods.com/?art=diskgenie)

[DRIVE IT YOURSELF: USB CAR](http://www.linuxvoice.com/drive-it-yourself-usb-car-6/)
* Reversing USB and writing USB Drivers for an RC car.



###USB
[USB in a Nutshell](http://www.beyondlogic.org/usbnutshell/usb1.shtml)
* Great explanation of the USB standard in depth

[USB Device Drivers: A Stepping Stone into your Kernel](https://www.youtube.com/watch?v=HQWFHskIY2)
* [Slides])(www.jodeit.org/research/DeepSec2009_USB_Device_Drivers.pdf)

[Lowering the USB Fuzzing Barrier by Transparent Two-Way Emulation](https://www.usenix.org/system/files/conference/woot14/woot14-vantonder.pdf)
* Abstract: Increased focus on the Universal Serial Bus (USB) attack surface of devices has recently resulted in a number of new vulnerabilities. Much of this advance has been aided by the advent of hardware-based USB emulation techniques. However, existing tools and methods are far from ideal, requiring a significant investment of time, money, and effort. In this work, we present a USB testing framework that improves significantly over existing methods in providing a cost-effective and flexible way to read and modify USB communication. Amongst other benefits, the framework enables man-in-the-middle fuzz testing between a host and peripheral. We achieve this by performing two-way emulation using inexpensive bespoke USB testing hardware, thereby delivering capa-bilities of a USB analyzer at a tenth of the cost. Mutational fuzzing is applied during live communication between a host and peripheral, yielding new security-relevant bugs. Lastly, we comment on the potential of the framework to improve current exploitation techniques on the USB channel.


[USB For All - Defcon 22 - Jesse Michael and Mickey Shkatov])(https://www.youtube.com/watch?v=7HnQnpJwr-c)
* USB is used in almost every computing device produced in recent years. In addition to well-known usages like keyboard, mouse, and mass storage, a much wider range of capabilities exist such as Device Firmware Update, USB On-The-Go, debug over USB, and more. What actually happens on the wire? Is there interesting data we can observe or inject into these operations that we can take advantage of? In this talk, we will present an overview of USB and its corresponding attack surface. We will demonstrate different tools and methods that can be used to monitor and abuse USB for malicious purposes.


BadUSB
[Slides](https://srlabs.de/blog/wp-content/uploads/2014/11/SRLabs-BadUSB-Pacsec-v2.pdf)
[Video](https://www.youtube.com/watch?v=nuruzFqMgIw)
[Code - Psychson](https://github.com/adamcaudill/Psychson) 
[Media Transfer Protocol and USB device Research](http://nicoleibrahim.com/part-1-mtp-and-ptp-usb-device-research/)


[USB Device Class Specifications - Official Site](http://www.usb.org/developers/docs/devclass_docs/)
* These specifications recommend design targets for classes of devices. For HID related information, please go to the [HID web page.](http://www.usb.org/developers/docs/docs/hidpage/)

[Universal Serial Bus Device Class Specification for Device Firmware Upgrade Version 1.1 Aug 5, 2004](http://www.usb.org/developers/docs/devclass_docs/DFU_1.1.pdf)

[USB Attacks Need Physical Access Right? Not Any More… by Andy Davis](https://www.youtube.com/watch?v=90MIjgh5ESU)

[Phison PS2303 (PS2251-03) framework](https://bitbucket.org/flowswitch/phison)
* This project's goal is to turn PS2303-based USB flash drive into a cheap USB 3.0 development platform (i.e. fast USB 3.0 to FPGA bridge).


###SIM Cards
[Rooting SIM cards](https://www.youtube.com/watch?v=BR0yWjQYnhQ)






###Smartcards

[An analysis of the vulnerabilities introduced with Java Card 3 Connected Edition](http://www.ma.rhul.ac.uk/static/techrep/2013/MA-2013-04.pdf)

[Introduction to Smart Card Security](http://resources.infosecinstitute.com/introduction-smartcard-security/)



###Papers

[Stealthy Dopant-Level Hardware Trojans](Hardware level trojans http://sharps.org/wp-content/uploads/BECKER-CHES.pdf)
* Abstract: In this paper we propose an extremely stealthy approach for implement- ing hardware Trojans below the gate level, and we evaluate their impact on the security of the target device. Instead of adding additional cir- cuitry to the target design, we insert our hardware Trojans by changing the dopant polarity of existing transistors. Since the modi ed circuit ap- pears legitimate on all wiring layers (including all metal and polysilicon), our family of Trojans is resistant to most detection techniques, includ- ing ne-grain optical inspection and checking against \golden chips". We demonstrate the e ectiveness of our approach by inserting Trojans into two designs | a digital post-processing derived from Intel's cryp- tographically secure RNG design used in the Ivy Bridge processors and a side-channel resistant SBox implementation | and by exploring their detectability and their e ects on security.

[Perimeter-Crossing Buses: a New Attack Surface for
Embedded Systems](http://www.cs.dartmouth.edu/~sws/pubs/bgjss12.pdf)
* Abstract: This paper maps out the bus-facing attack surface of a modern operating system, and demonstrates that e ective and ecient injection of trac into the buses is real and easily a ordable. Further, it presents a simple and inexpen-sive hardware tool for the job, outlining the architectural and computation-theoretic challenges to creating a defensive OS/driver architecture comparable to that which has been achieved for network stacks.

[Implementation and Implications of a Stealth Hard-Drive Backdoor](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf) 
* Modern workstations and servers implicitly trust hard disks to act as well-behaved block devices. This paper analyzes the catastrophic loss of security that occurs when hard disks are not trustworthy. First, we show that it is possible to compromise the firmware of a commercial o-the-shelf hard drive, by resorting only to public information and reverse engineering. Using such a compromised firmware, we present a stealth rootkit that replaces arbitrary blocks from the disk while they are written, providing a data replacement back- door . The measured performance overhead of the compromised disk drive is less than 1% compared with a normal, non-malicious disk drive. We then demonstrate that a re- mote attacker can even establish a communication channel with a compromised disk to infiltrate commands and to ex-filtrate data. In our example, this channel is established over the Internet to an unmodified web server that relies on the compromised drive for its storage, passing through the original webserver, database server, database storage engine, filesystem driver, and block device driver. Additional experiments, performed in an emulated disk-drive environment, could automatically extract sensitive data such as /etc/shadow (or a secret key le) in less than a minute. This paper claims that the diffculty of implementing such an at- tack is not limited to the area of government cyber-warfare; rather, it is well within the reach of moderately funded criminals, botnet herders and academic researchers.

[Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors](https://www.ece.cmu.edu/~safari/pubs/kim-isca14.pdf)
* Abstract. Memory isolation is a key property of a reliable and secure computing system — an access to one memory ad- dress should not have unintended side e ects on data stored in other addresses. However, as DRAM process technology scales down to smaller dimensions, it becomes more di  cult to prevent DRAM cells from electrically interacting with each other. In this paper, we expose the vulnerability of commodity DRAM chips to disturbance errors. By reading from the same address in DRAM, we show that it is possible to corrupt data in nearby addresses. More specifically, activating the same row in DRAM corrupts data in nearby rows. We demonstrate this phenomenon on Intel and AMD systems using a malicious program that generates many DRAM accesses. We induce errors in most DRAM modules (110 out of 129) from three major DRAM manufacturers. From this we conclude that many deployed systems are likely to be at risk. We identify the root cause of disturbance errors as the repeated toggling of a DRAM row’s wordline, which stresses inter-cell coupling e ects that accelerate charge leakage from nearby rows. We provide an extensive characterization study of disturbance errors and their behavior using an FPGA-based testing plat- form. Among our key findings, we show that (i) it takes as few as 139K accesses to induce an error and (ii) up to one in every 1.7K cells is susceptible to errors. After examining var- ious potential ways of addressing the problem, we propose a low-overhead solution to prevent the errors.
























