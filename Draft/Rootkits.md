# Rootkits

----------------------------------
## Table of Contents
- [101](#101)
- [Platforms](#platforms)
	- [Android](#android)
	- [FreeBSD](#freebsd)
	- [Linux](#linux)
	- [OS X](#osx)
	- [UEFI](#uefi)
	- [Windows](#windows)
- [Defense Against/Identification of](#defense)
- [Educational](#educational)
- [Samples](#samples)



-----------------
## Rootkits
* **101**
* **General Information**
	* [Introducing Ring -3 Rootkits](http://invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf)
	* [Rise of the dual architecture usermode rootkit](http://www.malwaretech.com/2013/06/rise-of-dual-architecture-usermode.html)
	* [Pitfalls of virtual machine introspection on modern hardware](https://www.acsac.org/2014/workshops/mmf/Tamas%20Lengyel-Pitfalls%20of%20virtual%20machine%20introspection%20on%20modern%20hardware.pdf)
	* [Thunderstrike](https://trmm.net/EFI)
		* Thunderstrike is the name for a class of Apple EFI firmware security vulnerabilities that allow malicious software or Thunderbolt devices to flash untrusted code to the boot ROM and propagate via shared devices.
	* [SharknAT&To](https://www.nomotion.net/blog/sharknatto/)
* **Platforms**<a name="platforms"></a>
	* **Android**<a name="android"></a>
		* [Android Rootkit](https://github.com/hiteshd/Android-Rootkit)
		* [Advanced Bootkit Techniques on Android](http://www.syscan360.org/slides/2014_EN_AdvancedBootkitTechniquesOnAndroid_ChenZhangqiShendi.pdf)
		* [Android platform based linux kernel rootkit - dong-hoon you](http://www.phrack.org/issues/68/6.html)
	* **FreeBSD**<a name="freebsd"></a>
		* [FreeBSD Rootkits: A first step into Kernel Analysis #0 (Fundamentals)](https://www.youtube.com/watch?v=MbEhTkfuz3U)
	* **Linux**<a name="linux"></a>
		* **Educational**
			* [BoutiqueKit: Playing WarGames with Expensive Rootkits and Malware- Defcon 21](https://www.youtube.com/watch?v=gKUleWyfut0)
			* [Kernel Rootkit Experiences - stealth](http://phrack.org/issues/61/14.html)
			* [How to Write Your Own Linux Kernel Module with a Simple Example - thegeekstuff.com](https://www.thegeekstuff.com/2013/07/write-linux-kernel-module/)
			* [Writing a Linux character Device Driver - appusajeev.wordpress](https://appusajeev.wordpress.com/2011/06/18/writing-a-linux-character-device-driver/)
			* [Linux Kernel: System call hooking example - StackOverflow](https://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example)
		* **Examples**
			* [Suterusu](https://github.com/mncoppola/suterusu)
				* An LKM rootkit targeting Linux 2.6/3.x on x86(\_64), and ARM
			* [DragonKing Rootkit](https://github.com/mgrube/DragonKing)
				* This is an open source rootkit created for a class taught on Rootkit Design. This rootkit hides by hooking the system call table and using an agent to do interactive manipulation in userland.
			* [Diamorphine](https://github.com/alex91ar/Diamorphine)
				* Diamorphine is a LKM rootkit for Linux Kernels 2.6.x/3.x/4.x originally developed by m0nad and forked by me. This fork hides high CPU usage from tools like top, htop or other commonly used utilities, by hooking the read() syscall and modifying the buffer returning the contents for /proc/stat and /proc/loadavg. The syscall sysinfo() is also hooked, but it's not used by these tools.
		* **Writeups**
			* [Linux on-the-fly kernel patching without LKM - sd, devik](http://phrack.org/issues/58/7.html)
			* [Analyzing the Jynx rootkit and the LD-Preload technique](http://volatility-labs.blogspot.com/2012/09/movp-24-analyzing-jynx-rootkit-and.html)
				* In this post I will analyze the Jynx rootkit using Volatility’s new Linux features.
			* [Smart TV Security - #1984 in 21 st century](https://cansecwest.com/slides/2013/SmartTV%20Security.pdf)
				* This talk is more about security bugs and rootkits than about firmware for TVs. This talk more covers rootkits than security bugs and exploitation thereof, as they’re not different to traditional techniques. This talk is about general security issues of all Smart TV vendors.
		* **Tools**
		* **Shadow Walker**
			* [Shadow Walker - Raising the Bar for Rootkit detection - BH 2005](https://www.blackhat.com/presentations/bh-jp-05/bh-jp-05-sparks-butler.pdf)
			* [TLB Synchronization (Split TLB)](http://uninformed.org/index.cgi?v=6&a=1&p=21)
			* [Slides - MoRE Shadow Walker : TLB - splitting on Modern x86](https://www.blackhat.com/docs/us-14/materials/us-14-Torrey-MoRE-Shadow-Walker-The-Progression-Of-TLB-Splitting-On-x86-WP.pdf)
				* MoRE, or Measurement of Running Executables, was a DARPA Cyber Fast Track effort to study the feasibility of utilizi ng x86 translation look - aside buffer (TLB) splitting techniques for realizing periodic measurements of running and dynamically changing applications. It built upon PaX, which used TLB splitting to emulate the no - execute bit and Shadow Walker, a memory hidi ng rootkit ; both designed for earlier processor architectures. MoRE and MoRE Shadow Walker are a defensive TLB splitting system and a prototype memory hiding rootkit for the current Intel i - series processors respectively – demonstrating the evolution of th e x86 architecture and how its complexity allows software to effect the apparent hardware architecture.
			* [Video - MoRE Shadow Walker : TLB - splitting on Modern x86](https://www.youtube.com/watch?v=XU1uNGZ7HnY)
				* This presentation provides a cohesive overview of the work performed by AIS, Inc. on the DARPA CFT MoRE effort. MoRE was a 4-month effort which examined the feasibility of utilizing TLB splitting as a mechanism for periodic measurement of dynamically changing binaries. The effort created a proof-of-concept system to split the TLB for target applications, allowing dynamic applications to be measured and can detect code corruption with low performance overhead.
			* [Measurement of Running Executables](http://vimeo.com/81335517)
	* **OS X**<a name="osx"></a>
		* [Crafting Mac OS Rootkits](https://www.zdziarski.com/blog/wp-content/uploads/2017/02/Crafting-macOS-Root-Kits.pdf)
		* [Masochist](https://github.com/squiffy/Masochist)
			* Masochist is a framework for creating XNU based rootkits. Very useful in OS X and iOS security research.
		* [Revisiting Mac OS X Kernel Rootkits - fG! <phrack@put.as>-](http://phrack.org/issues/69/7.html)
	* **UEFI**<a name="UEFI"></a>
		* [LoJax: First UEFI rootkit found in the wild, courtesy of the Sednit group - ESET](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/)
		* [LOJAX: First UEFI rootkit found in the wild, courtesy of the Sednit group](https://www.welivesecurity.com/wp-content/uploads/2018/09/ESET-LoJax.pdf)
	* **Windows**<a name="windows"></a>
		* **Educational**
			* [NTIllusion: A portable Win32 userland rootkit - Kdm](http://phrack.org/issues/62/12.html)
			* [KernelMode Rootkits: Part 1, SSDT hooks - adlice](https://www.adlice.com/kernelmode-rootkits-part-1-ssdt-hooks/)
			* [KernelMode Rootkits: Part 2, IRP hooks - adlice](https://www.adlice.com/kernelmode-rootkits-part-2-irp-hooks/)
			* [KernelMode Rootkits: Part 3, kernel filters- adlice](https://www.adlice.com/kernelmode-rootkits-part-3-kernel-filters/)
			* [Program Develop: Windows Rootkits]()
				* [Part 1](http://www.programdevelop.com/5408113/)
				* [Part 2](http://www.programdevelop.com/5409574/)
				* [Part 3](http://www.programdevelop.com/5408212/)
			* [Stealth hooking : Another way to subvert the Windows kernel - mxatone and ivanlef0u](http://phrack.org/issues/65/4.html#article)
			* [A Catalog of Windows Local Kernel-mode Backdoors](http://uninformed.org/?v=all&a=35&t=sumry)
				* This paper presents a detailed catalog of techniques that can be used to create local kernel-mode backdoors on Windows. These techniques include function trampolines, descriptor table hooks, model-specific register hooks, page table modifications, as well as others that have not previously been described. The majority of these techniques have been publicly known far in advance of this paper. However, at the time of this writing, there appears to be no detailed single point of reference for many of them. The intention of this paper is to provide a solid understanding on the subject of local kernel-mode backdoors. This understanding is necessary in order to encourage the thoughtful discussion of potential countermeasures and perceived advancements. In the vein of countermeasures, some additional thoughts are given to the common misconception that PatchGuard, in its current design, can be used to prevent kernel-mode rootkits.
			* [Raising The Bar For Windows Rootkit Detection - Phrack](http://www.phrack.org/issues/63/8.html)
			* [Concepts for the Steal the Windows Rootkit (The Chameleon Project)Joanna Rutkowska2003](http://repo.hackerzvoice.net/depot_madchat/vxdevl/avtech/Concepts%20for%20the%20Stealth%20Windows%20Rootkit%20%28The%20Chameleon%20Project%29.pdf)
			* [futo](http://uninformed.org/?v=all&a=17&t=sumry)
				* Since the introduction of FU, the rootkit world has moved away from implementing system hooks to hide their presence. Because of this change in offense, a new defense had to be developed. The new algorithms used by rootkit detectors, such as BlackLight, attempt to find what the rootkit is hiding instead of simply detecting the presence of the rootkit's hooks. This paper will discuss an algorithm that is used by both Blacklight and IceSword to detect hidden processes. This paper will also document current weaknesses in the rootkit detection field and introduce a more complete stealth technique implemented as a prototype in FUTo.
		* **Examples**
			* [WindowsRegistryRootkit - Cr4sh](https://github.com/Cr4sh/WindowsRegistryRootkit)
				* Kernel rootkit, that lives inside the Windows registry value data.
			* [DdiMon](https://github.com/tandasat/DdiMon)
				* DdiMon is a hypervisor performing inline hooking that is invisible to a guest (ie, any code other than DdiMon) by using extended page table (EPT).  DdiMon is meant to be an educational tool for understanding how to use EPT from a programming perspective for research. To demonstrate it, DdiMon installs the invisible inline hooks on the following device driver interfaces (DDIs) to monitor activities of the Windows built-in kernel patch protection, a.k.a. PatchGuard, and hide certain processes without being detected by PatchGuard.
			* [HookPasswordChange](https://github.com/clymb3r/Misc-Windows-Hacking/tree/master/HookPasswordChange/HookPasswordChange)
		* **Writeups**
			* [Komodia Rootkit Writeupn](https://gist.github.com/Wack0/f865ef369eb8c23ee028)
				* Komodia rootkit findings by @TheWack0lian
				* [Talk at CCC31](https://www.youtube.com/watch?v=5BrdX7VdOr0)
			* [Using Kernel Rootkits to conceal infected MBR](http://www.malwaretech.com/2015/01/using-kernel-rootkits-to-conceal.html)
				* [FakeMBR](https://github.com/MalwareTech/FakeMBR/)
			* [EquationDrug rootkit analysis (mstcp32.sys) - artemonsecurity](https://artemonsecurity.blogspot.com/2017/03/equationdrug-rootkit-analysis-mstcp32sys.html)
			* [GrayFish rootkit analysis - artemonsecurity](https://artemonsecurity.blogspot.com/2017/05/grayfish-rootkit-analysis.html)
* **Defense Against/Identifying**<a name="defense"></a>
	* [Killing Rootkits](http://blog.ioactive.com/2014/09/killing-rootkit.html)
	* [Killing the Rootkit - Shane Macaulay](http://blog.ioactive.com/2014/09/killing-rootkit.html)
		* Cross-platform, cross-architecture DKOM detection
	* [Driver security checklist - docs.ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist?platform=hootsuite)	
		* This article provides a driver security checklist for driver developers to help reduce the risk of drivers being compromised.
	* [Tyton](https://github.com/nbulischeck/tyton)
		* Linux Kernel-Mode Rootkit Hunter for 4.4.0-31+.
		* [Homepage](https://nbulischeck.github.io/tyton/)
* **Interesting Things**
	* [From Kernel to VM](https://www.youtube.com/watch?v=FSw8Ff1SFLM)
		* Description from stormeh on reddit(https://www.reddit.com/r/rootkit/comments/25hsc4/jacob_i_torrey_from_kernel_to_vmm/): Although it's not directly a lecture about rootkit development, the topics discussed are very much of interest: hardware virtualization, page table and TLB manipulation, hypervisors and privilege levels below ring 0, etc. The speaker does also go on to mention how prior rootkits such as Blue Pill and Shadow Walker leveraged these features, as well as defensive technologies such as PaX. 
		* [Slides](http://jacobtorrey.com/VMMLecture.pdf)
	* [Demon](https://github.com/x0r1/Demon)
		* GPU keylogger PoC by Team Jellyfish
	* [WIN_JELLY](https://github.com/x0r1/WIN_JELLY)
		* Windows GPU RAT PoC by Team Jellyfish. Project demonstrates persistent executable code storage in gpu that later can be mapped back to userspace after reboot. The sole purpose why we titled this concept that of a trojan is due to what it's capable of. Simply use this code to hide your own basically; we aren't responsible.	
* **Samples**<a name="samples"></a>
	* **GPU**
		* [GPU rootkit PoC by Team Jellyfish](https://github.com/x0r1/jellyfish)
	* **Android**
	* **FreeBSD**
	* **Linux**
		* [Vlany](https://github.com/mempodippy/vlany)
			* vlany is a Linux LD_PRELOAD rootkit.
		* [Azazel](https://github.com/chokepoint/azazel)
			* Azazel is a userland rootkit based off of the original LD_PRELOAD technique from Jynx rootkit. It is more robust and has additional features, and focuses heavily around anti-debugging and anti-detection.
	* **OS X**
	* **Physical**
		* [Implementation and Implications of a Stealth Hard-Drive Backdoor](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf) 
			* Modern workstations and servers implicitly trust hard disks to act as well-behaved block devices. This paper analyzes the catastrophic loss of security that occurs when hard disks are not trustworthy. First, we show that it is possible to compromise the firmware of a commercial over-the-shelf hard drive, by resorting only to public information and reverse engineering. Using such a compromised firmware, we present a stealth rootkit that replaces arbitrary blocks from the disk while they are written, providing a data replacement back- door . The measured performance overhead of the compromised disk drive is less than 1% compared with a normal, non-malicious disk drive. We then demonstrate that a re- mote attacker can even establish a communication channel with a compromised disk to infiltrate commands and to ex-filtrate data. In our example, this channel is established over the Internet to an unmodified web server that relies on the compromised drive for its storage, passing through the original webserver, database server, database storage engine, filesystem driver, and block device driver. Additional experiments, performed in an emulated disk-drive environment, could automatically extract sensitive data such as /etc/shadow (or a secret key file) in less than a minute. This paper claims that the diffculty of implementing such an at- tack is not limited to the area of government cyber-warfare; rather, it is well within the reach of moderately funded criminals, botnet herders and academic researchers.
	* **VM**
	* **Windows**
		* [HORSE PILL](https://github.com/r00tkillah/HORSEPILL)
			* Horse Pill is a PoC of a ramdisk based containerizing root kit. It resides inside the initrd, and prior to the actual init running, it puts it into a mount and pid namespace that allows it to run covert processes and covert storage. This also allows it run covert networking systems, such as dns tunnels.
		* [WindowsRegistryRootkit](https://github.com/Cr4sh/WindowsRegistryRootkit)
			* Kernel rootkit, that lives inside the Windows registry value data. By Oleksiuk Dmytro (aka Cr4sh) 
			* Rootkit uses the zero day vulnerability in win32k.sys (buffer overflow in function win32k!bInitializeEUDC()) to get the execution at the OS startup.


-----------------
#### Sort
* [WoW64 internals...re-discovering Heaven's Gate on ARM - wbenny](https://wbenny.github.io/2018/11/04/wow64-internals.html)
* [5 Days To Virtualization: A Series On Hypervisor Development - Daax Rynd](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
* [Day 2: Entering VMX Operation, Explaining Implementation Requirements - Daax Rynd](https://revers.engineering/day-2-entering-vmx-operation/)
* [Superseding Driver Altitude Checks On Windows - Daax Rynd](https://revers.engineering/superseding-driver-altitude-checks-on-windows/)
* [System call dispatching on Windows ARM64 - Bruce Dang](https://gracefulbits.com/2018/07/26/system-call-dispatching-for-windows-on-arm64/)
* [Find which process is using the microphone, from a kernel-mode driver - Bruce Dang](https://gracefulbits.com/2018/08/13/find-which-process-is-using-the-microphone-from-a-kernel-mode-driver/)
* [Windows Notification Facility: Peeling the Onion of the Most Undocumented Kernel Attack Surface Yet - Gabrielle Viala, Alex Ionescu](https://www.youtube.com/watch?v=MybmgE95weo)

* [WindowsD](https://github.com/katlogic/WindowsD)
	* Disable DSE and WinTcb (without breaking DRM)
* [Windows Rootkit Development Python prototyping to kernel level - RJ McDown, Joshua Theimer(Derbycon2017)](https://www.youtube.com/watch?v=Ul8uPvlOsug&index=43&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)

* [DSEFix](https://github.com/hfiref0x/DSEFix)
	* Windows x64 Driver Signature Enforcement Overrider
* [Some fun with vintage bugs and driver signing enforcement - kat.lua](http://kat.lua.cz/posts/Some_fun_with_vintage_bugs_and_driver_signing_enforcement/#more)
* [r77 Rootkit](https://github.com/bytecode77/r77-rootkit)
	* This work in progress ring 3 rootkit hides processes, files and directories from applications in user mode. Future implementation on modules, registry, services and possibly other entities is planned.