
# Low Level Attacks/Firmware/BIOS/UEFI





TOC
* [General](#general)
* [Exploitation](#exploit)
* [Firmware Analysis](#firmware)
* [Talks & Presentations](#talks)
* [Tools](#tools)
* [Papers & Writeups](#papers)
* [Other](#other)





#### Sort
http://www.stoned-vienna.com/

* [How to hack a disabled computer or run code in Intel ME](http://blog.ptsecurity.ru/2018/01/intel-me.html)
* [Intel Q3’17 ME 11.x, SPS 4.0, and TXE 3.0 Security Review Cumulative Update](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00086&languageid=en-fr)

#### End Sort




----------------
### What is This Stuff?
* [Official UEFI Site - Specs](http://www.uefi.org/specsandtesttools)
* [UEFI - OSDev Wiki](http://wiki.osdev.org/UEFI)
* [Extensible Firmware Interface (EFI) and Unified EFI (UEFI)](http://www.intel.com/content/www/us/en/architecture-and-technology/unified-extensible-firmware-interface/efi-homepage-general-technology.html)
* [Understanding AMT, UEFI BIOS and Secure boot relationships](https://communities.intel.com/community/itpeernetwork/vproexpert/blog/2013/08/11/understanding-amt-uefi-bios-and-secure-boot-relationships)
* [Introduction to UEFI](http://x86asm.net/articles/introduction-to-uefi/)
* [What is Intel Mangement Engine?](http://me.bios.io/ME:About)



-----------------
### <a name="general">General</a>
* [Timeline of Low level software and hardware attack papers](http://timeglider.com/timeline/5ca2daa6078caaf4)
* [Technical Overview of Windows UEFI Startup Process](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)
* [Windows UEFI startup – A technical overview](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)
	* Through this analysis paper we’ll give a look at Windows 8 (and 8.1) UEFI startup mechanisms and we’ll try to understand their relationship with the underlying hardware platform.
* [Intel ME (Manageability engine) Huffman algorithm](http://io.smashthestack.org/me/)
* [LEGBACORE Research/Publicatoins](http://www.legbacore.com/Research.html)
* [Dr Sergei Skorobogatov - Researcher in hardware based attacks, good stuff](https://www.cl.cam.ac.uk/~sps32/)
* [Disabling Intel ME 11 via undocumented mode - ptsecurity](http://blog.ptsecurity.com/2017/08/disabling-intel-me.html)
* [Advanced Threat Research - Intel](http://www.intelsecurity.com/advanced-threat-research/index.html)



-----------------
## <a name="exploit"></a>Exploitation
* [CHIPSEC module that exploits UEFI boot script table vulnerability](https://github.com/Cr4sh/UEFI_boot_script_expl)
[System Management Mode Hack Using SMM for "Other Purposes](http://phrack.org/issues/65/7.html))
	* The research provided in this paper describes in details how to reverse engineer and modify System Management Interrupt (SMI) handlers in the BIOS system firmware and how to implement and detect SMM keystroke logger. This work also presents proof of concept code of SMM keystroke logger that uses I/O Trap based keystroke interception and a code for detection of such keystroke logger.
* [A Real SMM Rootkit: Reversing and Hooking BIOS SMI Handlers - Filip Wecherowski](http://phrack.org/issues/66/11.html#article)
	* The research provided in this paper describes in details how to reverse engineer and modify System Management Interrupt (SMI) handlers in the BIOS system firmware and how to implement and detect SMM keystroke logger. This work also presents proof of concept code of SMM keystroke logger that uses I/O Trap based keystroke interception and a code for detection of such keystroke logger.
* [Exploiting UEFI boot script table vulnerability](http://blog.cr4.sh/2015/02/exploiting-uefi-boot-script-table.html)
* [Attacking Intel ® Trusted Execution Technology Rafal Wojtczuk and Joanna Rutkowska](https://www.blackhat.com/presentations/bh-dc-09/Wojtczuk_Rutkowska/BlackHat-DC-09-Rutkowska-Attacking-Intel-TXT-slides.pdf)
* [Attacking UEFI Boot Script](https://frab.cccv.de/system/attachments/2566/original/venamis_whitepaper.pdf)
	* Abstract—UEFI Boot Script is a data structure interpreted by UEFI firmware during S3 resume. We show that on many systems, an attacker with ring0 privileges can alter this data structure. As a result, by forcing S3 suspend/resume cycle, an attacker can run arbitrary code on a platform that is not yet fully locked. The consequences include ability to overwrite the flash storage and take control over SMM.
* [Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)
* [20 Ways Past Secure Boot - Job de Haas - Troopers14](https://www.youtube.com/watch?v=74SzIe9qiM8)
* [Building reliable SMM backdoor for UEFI based platforms](http://blog.cr4.sh/2015/07/building-reliable-smm-backdoor-for-uefi.html)
* [ThinkPwn](https://github.com/Cr4sh/ThinkPwn)
	* Lenovo ThinkPad System Management Mode arbitrary code execution exploit
* [From SMM to userland in a few bytes](https://scumjr.github.io/2016/01/10/from-smm-to-userland-in-a-few-bytes/)
* [Getting Physical: Extreme abuse of Intel based Paging Systems - Part 1](https://blog.coresecurity.com/2016/05/10/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-1/)
* [I Boot when U-Boot, Bernardo Maia Rodrigues (@bernardomr) & Vincent Ruijter (`@_evict`)](https://www.youtube.com/watch?v=2-Y4X81QHys&index=11&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
* [Extreme Privelege Escalataion on Windows8 UEFI Systems](https://www.youtube.com/watch?v=UJp_rMwdyyI)
	* [Slides](https://www.blackhat.com/docs/us-14/materials/us-14-Kallenberg-Extreme-Privilege-Escalation-On-Windows8-UEFI-Systems.pdf)
	* Summary by stormehh from reddit: In this whitepaper (and accompanying Defcon/Blackhat presentations), the authors demonstrate vulnerabilities in the UEFI "Runtime Service" interface accessible by a privileged userland process on Windows 8. This paper steps through the exploitation process in great detail and demonstrates the ability to obtain code execution in SMM and maintain persistence by means of overwriting SPI flash


------------------------
### <a name="firmware"></a>Firmware Analysis
* [An Introduction to Firmware Analysis[30c3](https://www.youtube.com/watch?v=kvfP7StmFxY)
	* This talk gives an introduction to firmware analysis: It starts with how to retrieve the binary, e.g. get a plain file from manufacturer, extract it from an executable or memory device, or even sniff it out of an update process or internal CPU memory, which can be really tricky. After that it introduces the necessary tools, gives tips on how to detect the processor architecture, and explains some more advanced analysis techniques, including how to figure out the offsets where the firmware is loaded to, and how to start the investigation.
* [Analyzing and Running binaries from Firmware Images - Part 1](http://w00tsec.blogspot.com.br/2013/09/analyzing-and-running-binaries-from.html)
* [Binwalk](https://github.com/devttys0/binwalk)
	* Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
* [SIMET Box Firmware Analysis: Embedded Device Hacking & Forensics](http://w00tsec.blogspot.com.br/2013/08/simet-box-firmware-analysis-embedded.html)
* [hw0lat_detector](http://ftp.dei.uc.pt/pub/linux/kernel/people/jcm/hwlat_detector/hwlat-detector-1.0.0.patch)
	* A system hardware latency detector Linux Kernel Module. This patch introduces a new hardware latency detector module that can be used to detect high hardware-induced latencies within the system. It was originally written for use in the RT kernel, but has wider applications.
Reverse Engineering Router Firmware walk through

* Reverse Engineering Router Firmware Writeup - secforce
	* [Part 1](http://www.secforce.com/blog/2014/04/reverse-engineer-router-firmware-part-1/)
	* [Part 2](http://www.secforce.com/blog/2014/07/reverse-engineer-router-firmware-part-2/)
* [Debug Methodology Under UEFI](http://www.uefi.org/sites/default/files/resources/UEFI_Plugfest_2011Q4_P8_PHX.pdf)
* [Reverse Engineering UEFI Firmware](https://jbeekman.nl/blog/2015/03/reverse-engineering-uefi-firmware/)
* [Intel® System Studio – UEFI BIOS Debugging](https://software.intel.com/en-us/articles/intel-system-studio-2014-uefi-bios-debugging)
* [Debug SPI BIOS after Power Up Sequence](https://software.intel.com/en-us/articles/debug-spi-bios-after-power-up-sequence)
* [me-tools](https://github.com/skochinsky/me-tools)
	* Tools for working with Intel ME



------------------------
### Meltdown & Spectre
* [Meltdown and Spectre - Vulnerabilities in modern computers leak passwords and sensitive data.](https://meltdown.help/)
	* Meltdown and Spectre exploit critical vulnerabilities in modern processors. These hardware vulnerabilities allow programs to steal data which is currently processed on the computer. While programs are typically not permitted to read data from other programs, a malicious program can exploit Meltdown and Spectre to get hold of secrets stored in the memory of other running programs. This might include your passwords stored in a password manager or browser, your personal photos, emails, instant messages and even business-critical documents. Meltdown and Spectre work on personal computers, mobile devices, and in the cloud. Depending on the cloud provider's infrastructure, it might be possible to steal data from other customers.
* [Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)
* **Meltdown**
	* [Meltdown](https://meltdownattack.com/meltdown.pdf)
		* The security of computer systems fundamentally relies on memory isolation, e.g., kernel address ranges are marked as non-accessible and are protected from user access. In this paper, we present Meltdown. Meltdown exploits side effects of out-of-order execution on modern processors to read arbitrary kernel-memory locations including personal data and passwords. Out-of-order execution is an indispensable performance feature and present in a wide range of modern processors. The attack is independent of the operating system, and it does not rely on any software vulnerabilities. Meltdown breaks all security assumptions given by address space isolation as well as paravirtualized environments and, thus, every security mechanism building upon this foundation. On affected systems, Meltdown enables an adversary to read memory of other processes or virtual machines in the cloud without any permissions or privileges, affecting millions of customers and virtually every user of a personal computer. We show that the KAISER defense mechanism for KASLR [8] has the important (but inadvertent) side effect of impeding Meltdown. We stress that KAISER must be deployed immediately to prevent large-scale exploitation of this severe information leakage
	* [Meltdown Proof-of-Concept](https://github.com/IAIK/meltdown)
		* This repository contains several applications, demonstrating the Meltdown bug. For technical information about the bug, refer to the paper:
			* Meltdown by Lipp, Schwarz, Gruss, Prescher, Haas, Mangard, Kocher, Genkin, Yarom, and Hamburg
		* The applications in this repository are built with libkdump, a library we developed for the paper. This library simplifies exploitation of the bug by automatically adapting to certain properties of the environment.
* **Spectre**
	* [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf)
		* Modern processors use branch prediction and speculative execution to maximize performance. For example, if the destination of a branch depends on a memory value that is in the process of being read, CPUs will try guess the destination and attempt to execute ahead. When the memory value finally arrives, the CPU either discards or commits the speculative computation. Speculative logic is unfaithful in how it executes,can access to the victim’s memory and registers, and can perform operations with measurable side effects. Spectre attacks involve inducing a victim to speculatively perform  operations that would not occur during correct program execution and which leak the victim’s confidential information via a side channel to the adversary. This paper describes practical attacks that combine methodology from side channel attacks, fault  attacks, and return-oriented programming that can read arbitrary memory from the victim’s process. More broadly, the paper shows that speculative execution implementations violate the security assumptions underpinning numerous software security mechanisms, including operating system process separation, static analysis, containerization, just-in-time (JIT) compilation, and countermeasures to cache timing/side-channel attacks. These attacks repre- sent a serious threat to actual systems, since vulnerable speculative execution capabilities are found in microprocessors from Intel, AMD, and ARM that are used in billions of devices. While  makeshift processor-specific countermeasures are possible in some cases, sound solutions will require fixes to processor designs as well as updates to instruction set architectures (ISAs) to give hardware architects and software developers a common understanding as to what computation state CPU implementations are (and are not) permitted to leak.
	* [spec_poc_arm](https://github.com/lgeek/spec_poc_arm)
		* PoC code implementing variant 3a of the Meltdown attack for AArch64. This allows reading all (potentially excluding registers whose read has side effects - not verified) system registers from user mode, including those which should only be accessible from the EL1 (kernel), EL2 (hypervisor) and EL3 (secure monitor) modes.
	* [SpectrePoC](https://github.com/crozone/SpectrePoC)
		* Proof of concept code for the Spectre CPU exploit.
	* [spectre-attack](https://github.com/Eugnis/spectre-attack)
		* Example of using revealed "Spectre" exploit (CVE-2017-5753 and CVE-2017-5715)





----------------------
### <a name="programming"></a>Programming
* [UEFI Programming - First Steps](http://x86asm.net/articles/uefi-programming-first-steps/)







-----------------
### <a name="talks"></a>Talks & Presentations
* [BIOS Chronomancy: Fixing the Core Root of Trust for Measurement - BlackHat 2013](https://www.youtube.com/watch?v=NbYZ4UCN9GY)
* [Hacking Measured Boot and UEFI - Defcon20](https://www.youtube.com/watch?v=oiqcog1sk2E)
	* There's been a lot buzz about UEFI Secure Booting, and the ability of hardware and software manufacturers to lock out third-party loaders (and rootkits). Even the NSA has been advocating the adoption of measured boot and hardware-based integrity checks. But what does this trend mean to the open source and hacker communities? In this talk I'll demonstrate measured boot in action. I'll also be releasing my new Measured Boot Tool which allows you to view Trusted Platform Module (TPM) boot data and identify risks such as unsigned early-boot drivers. And, I'll demonstrate how measured boot is used for remote device authentication. Finally, I'll discuss weaknesses in the system (hint: bootstrapping trust is still hard), what this technology means to the consumerization trend in IT, and what software and services gaps exist in this space for aspiring entrepreneurs.
* [Hardware Backdooring is Practical -Jonathan Brossard](https://www.youtube.com/watch?v=umBruM-wFUw)
* [Attacking “secure” chips](https://www.youtube.com/watch?v=w7PT0nrK2BE)
* [Attackin the TPM part 2](https://www.youtube.com/watch?v=h-hohCfo4LA)
* [Breaking apple touchID cheaply](http://www.ccc.de/en/updates/2013/ccc-breaks-apple-touchid)
* [Attacks on UEFI Security - Rafal Wojtczuk&Corey Kallenberg](https://bromiumlabs.files.wordpress.com/2015/01/attacksonuefi_slides.pdf)
* [The Empire Strikes Back Apple – how your Mac firmware security is completely broken](https://reverse.put.as/2015/05/29/the-empire-strikes-back-apple-how-your-mac-firmware-security-is-completely-broken/)
	* Writeup on compromise of UEFI on apple hardware.
* [Bootkit Threats: In Depth Reverse Engineering & Defense- Eugene Rodionov&Aleksandr Matrosov](https://www.eset.com/fileadmin/Images/US/Docs/Business/presentations/conference_papers/REcon2012.pdf)
* [Attacks on UEFI security, inspired by Darth Venamis's misery and Speed Racer](https://media.ccc.de/browse/congress/2014/31c3_-_6129_-_en_-_saal_2_-_201412282030_-_attacks_on_uefi_security_inspired_by_darth_venamis_s_misery_and_speed_racer_-_rafal_wojtczuk_-_corey_kallenberg.html#video)
	* On modern Intel based computers there exists two powerful and protected code regions: the UEFI firmware and System Management Mode (SMM). UEFI is the replacement for conventional BIOS and has the responsibility of initializing the platform. SMM is a powerful mode of execution on Intel CPUs that is even more privileged than a hypervisor. Because of their powerful positions, SMM and UEFI are protected by a variety of hardware mechanisms. In this talk, Rafal Wojtczuk and Corey Kallenberg team up to disclose several prevalent vulnerabilities that result in SMM runtime breakin as well as arbitrary reflash of the UEFI firmware. 
* [Attacking and Defending BIOS in 2015](http://www.intelsecurity.com/advanced-threat-research/content/AttackingAndDefendingBIOS-RECon2015.pdf)
* [CansecWest2016 Getting Physical: Extreme Abuse of Intel Based Paging Systems](https://github.com/n3k/CansecWest2016_Getting_Physical_Extreme_Abuse_of_Intel_Based_Paging_Systems)
* [Stoned Bootkit - BH USA09](https://www.blackhat.com/presentations/bh-usa-09/KLEISSNER/BHUSA09-Kleissner-StonedBootkit-SLIDES.pdf)
* [Attacking Intel BIOS - BHUSA09](https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf)
* [#root via SMS: 4G access level security assessment](https://conference.hitb.org/hitbsecconf2015ams/materials/D1T1%20-%20T.%20Yunusov%20K.%20Nesterov%20-%20Bootkit%20via%20SMS.pdf)
* [Using Intel TXT to Attack BIOSes](https://vimeo.com/117156508)
* [Detecting BadBIOS, Evil Maids, Bootkits and Other Firmware Malware - Paul English and Lee Fisher](https://archive.org/details/seagl-2017)
	* For attackers, platform firmware is the new Software. Most systems include hundreds of firmwares - UEFI or BIOS, PCIe expansion ROMs, USB controller drivers, storage controller host and disk/SSD drivers. Firmware-level hosted malware, bare-metal or virtualized, is nearly invisible to normal security detection tools, has full control of your system, and can often continue running even when the system is "powered off". Security Firms (eg, "Hacking Team" sell UEFI 0days to the highest bidder), and government agencies include firmware-level malware (eg, Wikileak'ed Vault7 CIA EFI malware). Defenders need to catch-up, and learn to defend their systems against firmware-level malware. In this presentation, we'll cover the NIST SP (147,147b,155,193) secure firmware guidance, for citizens, rather than vendors/enterprises. We'll discuss the problem of firmware-level malware, and cover some open source tools (FlashROM, CHIPSEC, etc.) to help detect malware on your system. We'll be discussing a new open source tool we've just released to help make it easier for you to do this check. You'll also get a nice paper tri-fold copy of our CHIPSEC Quick Reference for Sysadmins [note: we're all sysadmins for our own personal systems(!)], and some scary looking BadBIOS stickers for your laptop.
* [Detecting BadBIOS, Evil Maids, Bootkits, and Other Firmware Malware](https://ia600805.us.archive.org/7/items/seagl-2017/seagl-2017.pdf)


--------------------
### <a name="tools"></a>Tools
* [WindSLIC SLIC injectors](https://github.com/untermensch/WindSLIC)
	* includes UEFI, NTFS, bootmgr SLIC injectors and installers.
* [UEFI Firmware Parser](https://github.com/theopolis/uefi-firmware-parser)
	* The UEFI firmware parser is a simple module and set of scripts for parsing, extracting, and recreating UEFI firmware volumes. This includes parsing modules for BIOS, OptionROM, Intel ME and other formats too. Please use the example scripts for parsing tutorials.
* [Firmware Modifcation kit](https://code.google.com/p/firmware-mod-kit/)
	* This kit is a collection of scripts and utilities to extract and rebuild linux based firmware images.
* [Debug Agent Based UEFI Debugging](https://software.intel.com/en-us/articles/xdb-agent-based-uefi-debug)
	* The Intel® System Debugger now supports non-JTAG based debug of UEFI BIOS, this requires the use of a target-side debug agent and a USB or serial connection to the debug agent. This article takes you through the steps necessary and the the debug methodology used bey the Intel® System Debugger to use this method to supplement the pure JTAG based UEFI debug method it also supports
* [ida-uefiutils](https://github.com/snare/ida-efiutils/)
	* Some scripts for IDA Pro to assist with reverse engineering EFI binaries 
* [VisualUEFI](https://github.com/ionescu007/VisualUefi)
	* A project for allowing EDK-II Development with Visual Studio
* [UDKToolbox](https://github.com/smwikipedia/UDKToolbox)
	* An toolbox to help adopt Visual Studio for UEFI development.
* [Hyper-V backdoor for UEFI](https://gist.github.com/Cr4sh/55a54e7f3c113316efd2d66457df68dd)
* [UEFITool](https://github.com/LongSoft/UEFITool)
	* UEFITool is a cross-platform C++/Qt program for parsing, extracting and modifying UEFI firmware images. It supports parsing of full BIOS images starting with the flash descriptor or any binary files containing UEFI volumes.




-----------------------
### <a name="papers"></a>Papers & Writeups
* [Security Evaluation of Intel's Active Management Technology](http://people.kth.se/~maguire/DEGREE-PROJECT-REPORTS/100402-Vassilios_Ververis-with-cover.pdf)
* [Easily create UEFI applications using Visual Studio 2013](http://pete.akeo.ie/2015/01/easily-create-uefi-applications-using.html]
* [SMM Rootkits:A New Breed of OS Independent Malware](http://www.eecs.ucf.edu/~czou/research/SMM-Rootkits-Securecom08.pdf)
	* The emergence of hardware virtualization technology has led to the development of OS independent malware such as the Virtual Machine based rootkits (VMBRs). In this paper, we draw attention to a different but related threat that exists on many commodity systems in operation today: The System Management Mode based rootkit (SMBR). System Management Mode (SMM) is a relatively obscure mode on Intel processors used for low-level hardware control. It has its own private memory space and execution environment which is generally invisible to code running outside (e.g., the Operating System). Furthermore, SMM code is completely non-preemptible, lacks any concept of privilege level, and is immune to memory protection mechanisms. These features make it a potentially attractive home for stealthy rootkits. In this paper, we present our development of a proof of concept SMM rootkit. In it, we explore the potential of System Management Mode for malicious use by implementing a chipset level keylogger and a network backdoor capable of directly interacting with the network card to send logged keystrokes to a remote machine via UDP. The rootkit hides its memory footprint and requires no changes to the existing Operating System. It is compared and contrasted with VMBRs. Finally, techniques to defend against these threats are explored. By taking an offensive perspective we hope to help security researchers better understand the depth and scope of the problems posed by an emerging class of OS independent malware. 
* [How to develop your own Boot Loader](https://www.codeproject.com/Articles/36907/How-to-develop-your-own-Boot-Loader)
* [Disabling Intel ME 11 via undocumented mode - ptsecurity](http://blog.ptsecurity.com/2017/08/disabling-intel-me.html)




-------------
### <a name="other"></a>Other
* [Notes on Intel Microcode Updates](http://hireme.geek.nz/Intel_x86_NSA_Microcode_Updates.pdf)
* [BIOS Mods - mydigitallife](https://forums.mydigitallife.net/forums/bios-mods.25/)
* [MDL Projects and Applications](https://forums.mydigitallife.net/forums/mdl-projects-and-applications.34/)
* [Advice for writing a Bootloader? - reddit](https://www.reddit.com/r/lowlevel/comments/30toah/advices_for_a_bootloader/)


