##Low Level Attacks/Firmware/BIOS/UEFI

[Timeline of Low level software and hardware attack papers](http://timeglider.com/timeline/5ca2daa6078caaf4)





BIOS/UEFI Firmware
Writeups




###Cull

[Exploiting UEFI boot script table vulnerability](http://blog.cr4.sh/2015/02/exploiting-uefi-boot-script-table.html)

[20 Ways Past Secure Boot - Job de Haas - Troopers14](https://www.youtube.com/watch?v=74SzIe9qiM8)

[Intel ME (Manageability engine) Huffman algorithm](http://io.smashthestack.org/me/)

[CHIPSEC module that exploits UEFI boot script table vulnerability](https://github.com/Cr4sh/UEFI_boot_script_expl)

[Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)

[Understanding AMT, UEFI BIOS and Secure boot relationships](https://communities.intel.com/community/itpeernetwork/vproexpert/blog/2013/08/11/understanding-amt-uefi-bios-and-secure-boot-relationships)


[Debug Agent Based UEFI Debugging](https://software.intel.com/en-us/articles/xdb-agent-based-uefi-debug)
* The Intel® System Debugger now supports non-JTAG based debug of UEFI BIOS, this requires the use of a target-side debug agent and a USB or serial connection to the debug agent.  This article takes you through the steps necessary and the the debug methodology used bey the Intel® System Debugger to use this method to supplement the pure JTAG based UEFI debug method it also supports

[Official UEFI Site - Specs](http://www.uefi.org/specsandtesttools)

[UEFI - OSDev Wiki](http://wiki.osdev.org/UEFI)


[Easily create UEFI applications using Visual Studio 2013 ](http://pete.akeo.ie/2015/01/easily-create-uefi-applications-using.html)

[Extensible Firmware Interface (EFI) and Unified EFI (UEFI)](http://www.intel.com/content/www/us/en/architecture-and-technology/unified-extensible-firmware-interface/efi-homepage-general-technology.html)


[Windows UEFI startup – A technical overview](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)
* Through this analysis paper we’ll give a look at Windows 8 (and 8.1) UEFI startup mechanisms and we’ll try to understand their relationship with the underlying hardware platform.


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







[Hardware Backdooring is Practical -Jonathan Brossard - Defcon20](https://www.youtube.com/watch?v=umBruM-wFUw)


[Attackin the TPM part 2](https://www.youtube.com/watch?v=h-hohCfo4LA)

[Attacking “secure” chips](https://www.youtube.com/watch?v=w7PT0nrK2BE)



[Breaking apple touchID cheaply](http://www.ccc.de/en/updates/2013/ccc-breaks-apple-touchid)

