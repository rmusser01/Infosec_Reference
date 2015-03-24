##Low Level Attacks/Firmware/BIOS/UEFI

[Timeline of Low level software and hardware attack papers](http://timeglider.com/timeline/5ca2daa6078caaf4)





BIOS/UEFI Firmware
Writeups




###Cull



http://www.legbacore.com/Research.html

http://www.legbacore.com/Research.html

http://www.stoned-vienna.com/11111

https://www.blackhat.com/presentations/bh-usa-09/KLEISSNER/BHUSA09-Kleissner-StonedBootkit-SLIDES.pdf

http://forums.mydigitallife.info/forums/34-MDL-Projects-and-Applications


http://forums.mydigitallife.info/forums/25-BIOS-Mods

https://01.org/linux-uefi-validation/overview

[Technical Overview of Windows UEFI Startup Process](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)



[Hacking Measured Boot and UEFI - Defcon20](https://www.youtube.com/watch?v=oiqcog1sk2E)
*  There's been a lot buzz about UEFI Secure Booting, and the ability of hardware and software manufacturers to lock out third-party loaders (and rootkits). Even the NSA has been advocating the adoption of measured boot and hardware-based integrity checks. But what does this trend mean to the open source and hacker communities? In this talk I'll demonstrate measured boot in action. I'll also be releasing my new Measured Boot Tool which allows you to view Trusted Platform Module (TPM) boot data and identify risks such as unsigned early-boot drivers. And, I'll demonstrate how measured boot is used for remote device authentication.  Finally, I'll discuss weaknesses in the system (hint: bootstrapping trust is still hard), what this technology means to the consumerization trend in IT, and what software and services gaps exist in this space for aspiring entrepreneurs.

[BIOS Chronomancy: Fixing the Core Root of Trust for Measurement - BlackHat 2013](https://www.youtube.com/watch?v=NbYZ4UCN9GY)



###Firmware Analysis

[An Introduction to Firmware Analysis[30c3]](https://www.youtube.com/watch?v=kvfP7StmFxY)
* This talk gives an introduction to firmware analysis: It starts with how to retrieve the binary, e.g. get a plain file from manufacturer, extract it from an executable or memory device, or even sniff it out of an update process or internal CPU memory, which can be really tricky. After that it introduces the necessary tools, gives tips on how to detect the processor architecture, and explains some more advanced analysis techniques, including how to figure out the offsets where the firmware is loaded to, and how to start the investigation.


Reverse Engineering Router Firmware walk through
* [Part 1](http://www.secforce.com/blog/2014/04/reverse-engineer-router-firmware-part-1/)
* [Part 2](http://www.secforce.com/blog/2014/07/reverse-engineer-router-firmware-part-2/)


[Firmware Modifcation kit](https://code.google.com/p/firmware-mod-kit/)
* This kit is a collection of scripts and utilities to extract and rebuild linux based firmware images.



[Binwalk](https://github.com/devttys0/binwalk)
Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.

[Analyzing and Running binaries from Firmware Images - Part 1](http://w00tsec.blogspot.com.br/2013/09/analyzing-and-running-binaries-from.html
)
[SIMET Box Firmware Analysis: Embedded Device Hacking & Forensics](http://w00tsec.blogspot.com.br/2013/08/simet-box-firmware-analysis-embedded.html)



[hwlat_detector: A system hardware latency detector -Linux Kernel Module](http://ftp.dei.uc.pt/pub/linux/kernel/people/jcm/hwlat_detector/hwlat-detector-1.0.0.patch)
* This patch introduces a new hardware latency detector module that can be used
to detect high hardware-induced latencies within the system. It was originally
written for use in the RT kernel, but has wider applications.


[Attacking Intel ® Trusted Execution Technology Rafal Wojtczuk and Joanna Rutkowska](https://www.blackhat.com/presentations/bh-dc-09/Wojtczuk_Rutkowska/BlackHat-DC-09-Rutkowska-Attacking-Intel-TXT-slides.pdf)



http://forums.mydigitallife.info/forums/25-BIOS-Mods



[System Management Mode Hack Using SMM for "Other Purposes](http://phrack.org/issues/65/7.html)
* The research provided in this paper describes in details how to reverse engineer and modify System Management Interrupt (SMI) handlers in the BIOS system firmware and how to implement and detect SMM keystroke logger. This work also presents proof of concept code of SMM keystroke logger that uses I/O Trap based keystroke interception and a code for detection of such keystroke logger.



[A Real SMM Rootkit: Reversing and Hooking BIOS SMI Handlers - Filip Wecherowski](http://phrack.org/issues/66/11.html#article)
* The research provided in this paper describes in details how to reverse engineer and modify System Management Interrupt (SMI) handlers in the BIOS system firmware and how to implement and detect SMM keystroke logger. This work also presents proof of concept code of SMM keystroke logger that uses I/O Trap based keystroke interception and a code for detection of such keystroke logger.

[Exploiting UEFI boot script table vulnerability](http://blog.cr4.sh/2015/02/exploiting-uefi-boot-script-table.html)

[Attacking UEFI Boot Script](https://frab.cccv.de/system/attachments/2566/original/venamis_whitepaper.pdf)
* Abstract—UEFI Boot Script is a data structure interpreted by UEFI firmware during S3 resume. We show that on many systems, an attacker with ring0 privileges can alter this data structure. As a result, by forcing S3 suspend/resume cycle, an attacker can run arbitrary code on a platform that is not yet fully locked. The consequences include ability to overwrite the flash storage and take control over SMM.


[BIOS Chronomancy: Fixing the Core Root of Trust for Measurement - BlackHat 2013](https://www.youtube.com/watch?v=NbYZ4UCN9GY)


[WindSLIC SLIC injectors](https://github.com/untermensch/WindSLIC)
* includes UEFI, NTFS, bootmgr SLIC injectors and installers.


[ UEFI Firmware Parser](https://github.com/theopolis/uefi-firmware-parser)
* The UEFI firmware parser is a simple module and set of scripts for parsing, extracting, and recreating UEFI firmware volumes. This includes parsing modules for BIOS, OptionROM, Intel ME and other formats too. Please use the example scripts for parsing tutorials.


Professor’s page:
http://www.cl.cam.ac.uk/~sps32/

Grab links for his papers








[Implementation and Implications of a Stealth Hard-Drive Backdoor](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf) 
* Modern workstations and servers implicitly trust hard disks to act as well-behaved block devices. This paper analyzes the catastrophic loss of security that occurs when hard disks are not trustworthy. First, we show that it is possible to compromise the firmware of a commercial o-the-shelf hard drive, by resorting only to public information and reverse engineering. Using such a compromised firmware, we present a stealth rootkit that replaces arbitrary blocks from the disk while they are written, providing a data replacement back- door . The measured performance overhead of the compromised disk drive is less than 1% compared with a normal, non-malicious disk drive. We then demonstrate that a re- mote attacker can even establish a communication channel with a compromised disk to infiltrate commands and to ex-filtrate data. In our example, this channel is established over the Internet to an unmodified web server that relies on the compromised drive for its storage, passing through the original webserver, database server, database storage engine, filesystem driver, and block device driver. Additional experiments, performed in an emulated disk-drive environment, could automatically extract sensitive data such as /etc/shadow (or a secret key le) in less than a minute. This paper claims that the diffculty of implementing such an at- tack is not limited to the area of government cyber-warfare; rather, it is well within the reach of moderately funded criminals, botnet herders and academic researchers.

[Attackin the TPM part 2](https://www.youtube.com/watch?v=h-hohCfo4LA)

[Attacking “secure” chips](https://www.youtube.com/watch?v=w7PT0nrK2BE)



###Tools: 
[Psychson](https://github.com/adamcaudill/Psychson)




Phison 2251-03 (2303) Custom Firmware & Existing Firmware Patches (BadUSB) 



###Defending Against Hardware Attacks


[Anti-Evil Maid](http://theinvisiblethings.blogspot.com/2011/09/anti-evil-maid.html?m=1)

###USB

[USB in a Nutshell](http://www.beyondlogic.org/usbnutshell/usb1.shtml)
* Great explanation of the USB standard in depth

[Psychson](https://github.com/adamcaudill/Psychson)

[USB Device Drivers: A Stepping Stone into your Kernel](https://www.youtube.com/watch?v=HQWFHskIY2)
* [Slides])(www.jodeit.org/research/DeepSec2009_USB_Device_Drivers.pdf)

[Lowering the USB Fuzzing Barrier by Transparent Two-Way Emulation](https://www.usenix.org/system/files/conference/woot14/woot14-vantonder.pdf)
* Abstract: Increased focus on the Universal Serial Bus (USB) attack surface of devices has recently resulted in a number of new vulnerabilities. Much of this advance has been aided by the advent of hardware-based USB emulation techniques. However, existing tools and methods are far from ideal, requiring a significant investment of time, money, and effort. In this work, we present a USB testing framework that improves significantly over existing methods in providing a cost-effective and flexible way to read and modify USB communication. Amongst other benefits, the framework enables man-in-the-middle fuzz testing between a host and peripheral. We achieve this by performing two-way emulation using inexpensive bespoke USB testing hardware, thereby delivering capa-bilities of a USB analyzer at a tenth of the cost. Mutational fuzzing is applied during live communication between a host and peripheral, yielding new security-relevant bugs. Lastly, we comment on the potential of the framework to improve current exploitation techniques on the USB channel.


###SD Cards
[The Exploration and Exploitation of an SD Memory Card](https://www.youtube.com/watch?v=Tj-zI8Tl218)
* This talk demonstrates a method for reverse engineering and loading code into the microcontroller within a SD memory card.




###Computer Hardware Attack Writeups

[Perimeter-Crossing Buses: a New Attack Surface for
Embedded Systems](http://www.cs.dartmouth.edu/~sws/pubs/bgjss12.pdf)
* Abstract: This paper maps out the bus-facing attack surface of a modern operating system, and demonstrates that e ective and ecient injection of trac into the buses is real and easily a ordable. Further, it presents a simple and inexpen-sive hardware tool for the job, outlining the architectural and computation-theoretic challenges to creating a defensive OS/driver architecture comparable to that which has been achieved for network stacks.

[Breaking apple touchID cheaply](http://www.ccc.de/en/updates/2013/ccc-breaks-apple-touchid)

[Keykeriki v2.0](http://www.remote-exploit.org/articles/keykeriki_v2_0__8211_2_4ghz/index.html)
* Hardware to attack wireless keyboards and other such things

[Stealthy Dopant-Level Hardware Trojans](Hardware level trojans http://sharps.org/wp-content/uploads/BECKER-CHES.pdf)
* Abstract: In this paper we propose an extremely stealthy approach for implement- ing hardware Trojans below the gate level, and we evaluate their impact on the security of the target device. Instead of adding additional cir- cuitry to the target design, we insert our hardware Trojans by changing the dopant polarity of existing transistors. Since the modi ed circuit ap- pears legitimate on all wiring layers (including all metal and polysilicon), our family of Trojans is resistant to most detection techniques, includ- ing ne-grain optical inspection and checking against \golden chips". We demonstrate the e ectiveness of our approach by inserting Trojans into two designs | a digital post-processing derived from Intel's cryp- tographically secure RNG design used in the Ivy Bridge processors and a side-channel resistant SBox implementation | and by exploring their detectability and their e ects on security.
