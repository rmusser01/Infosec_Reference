
## Low Level Attacks/Firmware/BIOS/UEFI

[Timeline of Low level software and hardware attack papers](http://timeglider.com/timeline/5ca2daa6078caaf4)



TOC
* [General](#general)
* [BIOS/UEFI Firmware Analysis](#firmware)
* [Exploitation](#exploit)
* [Tools](#tools)
* [Writeups](#writeups)





#### Cull
http://www.stoned-vienna.com/

[ Hyper-V backdoor for UEFI](https://gist.github.com/Cr4sh/55a54e7f3c113316efd2d66457df68dd)

[Advice for writing a Bootloader? - reddit](https://www.reddit.com/r/lowlevel/comments/30toah/advices_for_a_bootloader/)
#### End Cull



## <a name="general">General</a>
| Title | Link |
| -------- | ------------------------ |
| **Official UEFI Site - Specs** | http://www.uefi.org/specsandtesttools
| **UEFI - OSDev Wiki** | http://wiki.osdev.org/UEFI
| **Technical Overview of Windows UEFI Startup Process** | http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/
| **Understanding AMT, UEFI BIOS and Secure boot relationships** | https://communities.intel.com/community/itpeernetwork/vproexpert/blog/2013/08/11/understanding-amt-uefi-bios-and-secure-boot-relationships
| **Windows UEFI startup – A technical overview]** - Through this analysis paper we’ll give a look at Windows 8 (and 8.1) UEFI startup mechanisms and we’ll try to understand their relationship with the underlying hardware platform.| http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/
| **Extensible Firmware Interface (EFI) and Unified EFI (UEFI)** | http://www.intel.com/content/www/us/en/architecture-and-technology/unified-extensible-firmware-interface/efi-homepage-general-technology.html
| **Intel ME (Manageability engine) Huffman algorithm]** | http://io.smashthestack.org/me/

[Introduction to UEFI](http://x86asm.net/articles/introduction-to-uefi/)

[UEFI Programming - First Steps](http://x86asm.net/articles/uefi-programming-first-steps/)

[Dr Sergei Skorobogatov - Researcher in hardware based attacks, good stuff](https://www.cl.cam.ac.uk/~sps32/)

[UEFI Programming - First Steps](http://x86asm.net/articles/uefi-programming-first-steps/)

[LEGBACORE Research/Publicatoins](http://www.legbacore.com/Research.html)

[What is Intel Mangement Engine?](http://me.bios.io/ME:About)





## Talks & Presentations
| Title | Link |
| -------- | ------------------------ |
| **BIOS Chronomancy: Fixing the Core Root of Trust for Measurement - BlackHat 2013** | https://www.youtube.com/watch?v=NbYZ4UCN9GY
| **Hacking Measured Boot and UEFI - Defcon20** - There's been a lot buzz about UEFI Secure Booting, and the ability of hardware and software manufacturers to lock out third-party loaders (and rootkits). Even the NSA has been advocating the adoption of measured boot and hardware-based integrity checks. But what does this trend mean to the open source and hacker communities? In this talk I'll demonstrate measured boot in action. I'll also be releasing my new Measured Boot Tool which allows you to view Trusted Platform Module (TPM) boot data and identify risks such as unsigned early-boot drivers. And, I'll demonstrate how measured boot is used for remote device authentication. Finally, I'll discuss weaknesses in the system (hint: bootstrapping trust is still hard), what this technology means to the consumerization trend in IT, and what software and services gaps exist in this space for aspiring entrepreneurs.| https://www.youtube.com/watch?v=oiqcog1sk2E
| **Hardware Backdooring is Practical -Jonathan Brossard** | https://www.youtube.com/watch?v=umBruM-wFUw
| **Attacking “secure” chips** | https://www.youtube.com/watch?v=w7PT0nrK2BE
| **Attackin the TPM part 2https://www.youtube.com/watch?v=h-hohCfo4LA
| **Breaking apple touchID cheaply** | http://www.ccc.de/en/updates/2013/ccc-breaks-apple-touchid)

[Attacks on UEFI Security - Rafal Wojtczuk&Corey Kallenberg(https://bromiumlabs.files.wordpress.com/2015/01/attacksonuefi_slides.pdf)

[The Empire Strikes Back Apple – how your Mac firmware security is completely broken](https://reverse.put.as/2015/05/29/the-empire-strikes-back-apple-how-your-mac-firmware-security-is-completely-broken/)
* Writeup on compromise of UEFI on apple hardware.

[Bootkit Threats: In Depth Reverse Engineering & Defense- Eugene Rodionov&Aleksandr Matrosov](https://www.eset.com/fileadmin/Images/US/Docs/Business/presentations/conference_papers/REcon2012.pdf)

[Attacks on UEFI security, inspired by Darth Venamis's misery and Speed Racer](https://media.ccc.de/browse/congress/2014/31c3_-_6129_-_en_-_saal_2_-_201412282030_-_attacks_on_uefi_security_inspired_by_darth_venamis_s_misery_and_speed_racer_-_rafal_wojtczuk_-_corey_kallenberg.html#video)
* On modern Intel based computers there exists two powerful and protected code regions: the UEFI firmware and System Management Mode (SMM). UEFI is the replacement for conventional BIOS and has the responsibility of initializing the platform. SMM is a powerful mode of execution on Intel CPUs that is even more privileged than a hypervisor. Because of their powerful positions, SMM and UEFI are protected by a variety of hardware mechanisms. In this talk, Rafal Wojtczuk and Corey Kallenberg team up to disclose several prevalent vulnerabilities that result in SMM runtime breakin as well as arbitrary reflash of the UEFI firmware. 

[Attacking and Defending BIOS in 2015](http://www.intelsecurity.com/advanced-threat-research/content/AttackingAndDefendingBIOS-RECon2015.pdf)

[CansecWest2016 Getting Physical: Extreme Abuse of Intel Based Paging Systems](https://github.com/n3k/CansecWest2016_Getting_Physical_Extreme_Abuse_of_Intel_Based_Paging_Systems)

[Stoned Bootkit - BH USA09](https://www.blackhat.com/presentations/bh-usa-09/KLEISSNER/BHUSA09-Kleissner-StonedBootkit-SLIDES.pdf)

[Attacking Intel BIOS - BHUSA09](https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf)

[#root via SMS: 4G access level security assessment](https://conference.hitb.org/hitbsecconf2015ams/materials/D1T1%20-%20T.%20Yunusov%20K.%20Nesterov%20-%20Bootkit%20via%20SMS.pdf)

[Using Intel TXT to Attack BIOSes](https://vimeo.com/117156508)


## Firmware Analysis
| Title | Link |
| -------- | ------------------------ |
| **An Introduction to Firmware Analysis[30c3]** - This talk gives an introduction to firmware analysis: It starts with how to retrieve the binary, e.g. get a plain file from manufacturer, extract it from an executable or memory device, or even sniff it out of an update process or internal CPU memory, which can be really tricky. After that it introduces the necessary tools, gives tips on how to detect the processor architecture, and explains some more advanced analysis techniques, including how to figure out the offsets where the firmware is loaded to, and how to start the investigation. | https://www.youtube.com/watch?v=kvfP7StmFxY
| **Analyzing and Running binaries from Firmware Images - Part 1** | http://w00tsec.blogspot.com.br/2013/09/analyzing-and-running-binaries-from.html
| **Binwalk** - Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images. | https://github.com/devttys0/binwalk
| **SIMET Box Firmware Analysis: Embedded Device Hacking & Forensics** | http://w00tsec.blogspot.com.br/2013/08/simet-box-firmware-analysis-embedded.html
| **hw0lat_detector: A system hardware latency detector -Linux Kernel Module** - This patch introduces a new hardware latency detector module that can be used to detect high hardware-induced latencies within the system. It was originally written for use in the RT kernel, but has wider applications.| http://ftp.dei.uc.pt/pub/linux/kernel/people/jcm/hwlat_detector/hwlat-detector-1.0.0.patch

Reverse Engineering Router Firmware walk through
* [Part 1](http://www.secforce.com/blog/2014/04/reverse-engineer-router-firmware-part-1/)
* [Part 2](http://www.secforce.com/blog/2014/07/reverse-engineer-router-firmware-part-2/)

[Debug Methodology Under UEFI](http://www.uefi.org/sites/default/files/resources/UEFI_Plugfest_2011Q4_P8_PHX.pdf)

[Reverse Engineering UEFI Firmware](https://jbeekman.nl/blog/2015/03/reverse-engineering-uefi-firmware/)

[Intel® System Studio – UEFI BIOS Debugging](https://software.intel.com/en-us/articles/intel-system-studio-2014-uefi-bios-debugging)

[Debug SPI BIOS after Power Up Sequence](https://software.intel.com/en-us/articles/debug-spi-bios-after-power-up-sequence)

[me-tools](https://github.com/skochinsky/me-tools)
* Tools for working with Intel ME














## Exploitation
| Title | Link |
| -------- | ------------------------ |
| **CHIPSEC module that exploits UEFI boot script table vulnerability** | https://github.com/Cr4sh/UEFI_boot_script_expl
| **System Management Mode Hack Using SMM for "Other Purposes** - The research provided in this paper describes in details how to reverse engineer and modify System Management Interrupt (SMI) handlers in the BIOS system firmware and how to implement and detect SMM keystroke logger. This work also presents proof of concept code of SMM keystroke logger that uses I/O Trap based keystroke interception and a code for detection of such keystroke logger. | http://phrack.org/issues/65/7.html)
| **A Real SMM Rootkit: Reversing and Hooking BIOS SMI Handlers - Filip Wecherowski** - The research provided in this paper describes in details how to reverse engineer and modify System Management Interrupt (SMI) handlers in the BIOS system firmware and how to implement and detect SMM keystroke logger. This work also presents proof of concept code of SMM keystroke logger that uses I/O Trap based keystroke interception and a code for detection of such keystroke logger. | http://phrack.org/issues/66/11.html#article
| **Exploiting UEFI boot script table vulnerability** | http://blog.cr4.sh/2015/02/exploiting-uefi-boot-script-table.html
| **Attacking Intel ® Trusted Execution Technology Rafal Wojtczuk and Joanna Rutkowska** | https://www.blackhat.com/presentations/bh-dc-09/Wojtczuk_Rutkowska/BlackHat-DC-09-Rutkowska-Attacking-Intel-TXT-slides.pdf
| **Attacking UEFI Boot Script** - Abstract—UEFI Boot Script is a data structure interpreted by UEFI firmware during S3 resume. We show that on many systems, an attacker with ring0 privileges can alter this data structure. As a result, by forcing S3 suspend/resume cycle, an attacker can run arbitrary code on a platform that is not yet fully locked. The consequences include ability to overwrite the flash storage and take control over SMM.| https://frab.cccv.de/system/attachments/2566/original/venamis_whitepaper.pdf
| **Breaking IPMI/BMC** | http://fish2.com/ipmi/how-to-break-stuff.html
| **20 Ways Past Secure Boot - Job de Haas - Troopers14** | https://www.youtube.com/watch?v=74SzIe9qiM8

[Building reliable SMM backdoor for UEFI based platforms](http://blog.cr4.sh/2015/07/building-reliable-smm-backdoor-for-uefi.html)

[ThinkPwn](https://github.com/Cr4sh/ThinkPwn)
* Lenovo ThinkPad System Management Mode arbitrary code execution exploit

[From SMM to userland in a few bytes](https://scumjr.github.io/2016/01/10/from-smm-to-userland-in-a-few-bytes/)

[Getting Physical: Extreme abuse of Intel based Paging Systems - Part 1](https://blog.coresecurity.com/2016/05/10/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-1/)






## Tools
| | |
| -------- | ------------------------ |
| **WindSLIC SLIC injectors** - includes UEFI, NTFS, bootmgr SLIC injectors and installers. | https://github.com/untermensch/WindSLIC
| **UEFI Firmware Parser** - The UEFI firmware parser is a simple module and set of scripts for parsing, extracting, and recreating UEFI firmware volumes. This includes parsing modules for BIOS, OptionROM, Intel ME and other formats too. Please use the example scripts for parsing tutorials. | https://github.com/theopolis/uefi-firmware-parser
| **Firmware Modifcation kit** - This kit is a collection of scripts and utilities to extract and rebuild linux based firmware images.| https://code.google.com/p/firmware-mod-kit/
| **Debug Agent Based UEFI Debugging** - The Intel® System Debugger now supports non-JTAG based debug of UEFI BIOS, this requires the use of a target-side debug agent and a USB or serial connection to the debug agent. This article takes you through the steps necessary and the the debug methodology used bey the Intel® System Debugger to use this method to supplement the pure JTAG based UEFI debug method it also supports | https://software.intel.com/en-us/articles/xdb-agent-based-uefi-debug

[ida-uefiutils](https://github.com/snare/ida-efiutils/)
* Some scripts for IDA Pro to assist with reverse engineering EFI binaries 

[VisualUEFI](https://github.com/ionescu007/VisualUefi)
* A project for allowing EDK-II Development with Visual Studio

[UDKToolbox](https://github.com/smwikipedia/UDKToolbox)
* An toolbox to help adopt Visual Studio for UEFI development.





## Papers & Writeups
| Title | Link |
| -------- | ------------------------ |
| **Security Evaluation of Intel's Active Management Technology** | http://people.kth.se/~maguire/DEGREE-PROJECT-REPORTS/100402-Vassilios_Ververis-with-cover.pdf
| **Easily create UEFI applications using Visual Studio 2013* | http://pete.akeo.ie/2015/01/easily-create-uefi-applications-using.html


[SMM Rootkits:A New Breed of OS Independent Malware](http://www.eecs.ucf.edu/~czou/research/SMM-Rootkits-Securecom08.pdf)
* The emergence of hardware virtualization technology has led to the development of OS independent malware such as the Virtual Machine based rootkits (VMBRs). In this paper, we draw attention to a different but related threat that exists on many commodity systems in operation today: The System Management Mode based rootkit (SMBR). System Management Mode (SMM) is a relatively obscure mode on Intel processors used for low-level hardware control. It has its own private memory space and execution environment which is generally invisible to code running outside (e.g., the Operating System). Furthermore, SMM code is completely non-preemptible, lacks any concept of privilege level, and is immune to memory protection mechanisms. These features make it a potentially attractive home for stealthy rootkits. In this paper, we present our development of a proof of concept SMM rootkit. In it, we explore the potential of System Management Mode for malicious use by implementing a chipset level keylogger and a network backdoor capable of directly interacting with the network card to send logged keystrokes to a remote machine via UDP. The rootkit hides its memory footprint and requires no changes to the existing Operating System. It is compared and contrasted with VMBRs. Finally, techniques to defend against these threats are explored. By taking an offensive perspective we hope to help security researchers better understand the depth and scope of the problems posed by an emerging class of OS independent malware. 

[How to develop your own Boot Loader](https://www.codeproject.com/Articles/36907/How-to-develop-your-own-Boot-Loader)


### Other
[Notes on Intel Microcode Updates](http://hireme.geek.nz/Intel_x86_NSA_Microcode_Updates.pdf)

[BIOS Mods - mydigitallife](https://forums.mydigitallife.net/forums/bios-mods.25/)

[MDL Projects and Applications](https://forums.mydigitallife.net/forums/mdl-projects-and-applications.34/)

[Advice for writing a Bootloader? - reddit](https://www.reddit.com/r/lowlevel/comments/30toah/advices_for_a_bootloader/)