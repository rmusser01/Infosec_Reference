# Rootkits





## Table of Contents

* [Cull](#cull)
* [Developing](#dev)
* [Identifying/Defending Against](#id)
* [Talks/Videos](#talks)
* [Writeups](#writeups)
* [Papers](#papers)
* [Tools](#tools)


### Sort

[Homesite](https://trmm.net/EFI)

[Talk at CCC31](https://www.youtube.com/watch?v=5BrdX7VdOr0)

* [FreeBSD Rootkits: A first step into Kernel Analysis #0 (Fundamentals)](https://www.youtube.com/watch?v=MbEhTkfuz3U)
* [Vlany](https://github.com/mempodippy/vlany)
	* vlany is a Linux LD_PRELOAD rootkit.
* [Demon](https://github.com/x0r1/Demon)
	* GPU keylogger PoC by Team Jellyfish
* [WIN_JELLY](https://github.com/x0r1/WIN_JELLY)
	* Windows GPU RAT PoC by Team Jellyfish. Project demonstrates persistent executable code storage in gpu that later can be mapped back to userspace after reboot. The sole purpose why we titled this concept that of a trojan is due to what it's capable of. Simply use this code to hide your own basically; we aren't responsible.

* [KernelMode Rootkits: Part 1, SSDT hooks - adlice](https://www.adlice.com/kernelmode-rootkits-part-1-ssdt-hooks/)
* [KernelMode Rootkits: Part 2, IRP hooks - adlice](https://www.adlice.com/kernelmode-rootkits-part-2-irp-hooks/)
* [KernelMode Rootkits: Part 3, kernel filters- adlice](https://www.adlice.com/kernelmode-rootkits-part-3-kernel-filters/)

* [HookPasswordChange](https://github.com/clymb3r/Misc-Windows-Hacking/tree/master/HookPasswordChange/HookPasswordChange)

##### End Sort







-----------------
### <a name="dev">Developing</a>
* [Android Rootkit](https://github.com/hiteshd/Android-Rootkit)
* [Masochist](https://github.com/squiffy/Masochist)
	* Masochist is a framework for creating XNU based rootkits. Very useful in OS X and iOS security research.
* [Using Kernel Rootkits to conceal infected MBR](https://github.com/MalwareTech/FakeMBR/)
* [Hypervisor](https://github.com/ainfosec/more)
* [Suterusu](https://github.com/mncoppola/suterusu)
* Windows Rootkits(excellent writeup/introduction to windows rootkits)
	* [Part 1](http://www.programdevelop.com/5408113/)
	* [Part 2](http://www.programdevelop.com/5409574/)
	* [Part 3](http://www.programdevelop.com/5408212/)
* [Crafting Mac OS Rootkits](https://www.zdziarski.com/blog/wp-content/uploads/2017/02/Crafting-macOS-Root-Kits.pdf)
* [WindowsRegistryRootkit](https://github.com/Cr4sh/WindowsRegistryRootkit)
	* Kernel rootkit, that lives inside the Windows registry value data. By Oleksiuk Dmytro (aka Cr4sh) 
	* Rootkit uses the zero day vulnerability in win32k.sys (buffer overflow in function win32k!bInitializeEUDC()) to get the execution at the OS startup.



-----------------
### <a name="id">Identifiying/Defending Against</a>
* [Killing Rootkits](http://blog.ioactive.com/2014/09/killing-rootkit.html)





-----------------
###<a name="talks">Talks/Videos</a>
* [BoutiqueKit: Playing WarGames with Expensive Rootkits and Malware- Defcon 21](https://www.youtube.com/watch?v=gKUleWyfut0)
* [Persistent, Stealthy, Remote-controlled Dedicated Hardware Malware [30c3]](https://www.youtube.com/watch?v=Ck8bIjAUJgE)
* [Intel Management Engine Secrets by Igor Skochinsky](https://www.youtube.com/watch?v=Y2_-VXz9E-w)
* [MoRE Shadow Walker : TLB - splitting on Modern x86](https://www.youtube.com/watch?v=XU1uNGZ7HnY)
	* This presentation provides a cohesive overview of the work performed by AIS, Inc. on the DARPA CFT MoRE effort. MoRE was a 4-month effort which examined the feasibility of utilizing TLB splitting as a mechanism for periodic measurement of dynamically changing binaries. The effort created a proof-of-concept system to split the TLB for target applications, allowing dynamic applications to be measured and can detect code corruption with low performance overhead.
* [How Many Million BIOSes Would you Like to Infect?](http://conference.hitb.org/hitbsecconf2015ams/sessions/how-many-million-bioses-would-you-like-to-infect/)
	* This talk is going to be all about how the automation of BIOS vulnerability exploitation and leveraging of built-in capabilities can yield highly portable UEFI firmware malware. And how millions of systems will be vulnerable for years, because no one cares enough to patch the BIOS bugs we’ve found.  So you think you’re doing OPSEC right, right? You’re going to crazy lengths to protect yourself, reinstalling your main OS every month, or using a privacy-conscious live DVD like TAILS. Guess what? BIOS malware doesn’t care! BIOS malware doesn’t give a shit
* [Measurement of Running Executables](http://vimeo.com/81335517)
* [From Kernel to VM](https://www.youtube.com/watch?v=FSw8Ff1SFLM)
	* Description from stormeh on reddit(https://www.reddit.com/r/rootkit/comments/25hsc4/jacob_i_torrey_from_kernel_to_vmm/): Although it's not directly a lecture about rootkit development, the topics discussed are very much of interest: hardware virtualization, page table and TLB manipulation, hypervisors and privilege levels below ring 0, etc. The speaker does also go on to mention how prior rootkits such as Blue Pill and Shadow Walker leveraged these features, as well as defensive technologies such as PaX. 
	* [Slides](http://jacobtorrey.com/VMMLecture.pdf)
* [All Your Boot Are Belong To Us - Intel Security](https://cansecwest.com/slides/2014/AllYourBoot_csw14-intel-final.pdf)
* [Concepts for the Steal the Windows Rootkit (The Chameleon Project)Joanna Rutkowska2003](http://repo.hackerzvoice.net/depot_madchat/vxdevl/avtech/Concepts%20for%20the%20Stealth%20Windows%20Rootkit%20%28The%20Chameleon%20Project%29.pdf)\




-----------------
###<a name="writeups">Writeups</a>
* [Shadow Walker - Raising the Bar for Rootkit detection - BH 2005](https://www.blackhat.com/presentations/bh-jp-05/bh-jp-05-sparks-butler.pdf)
* [Rise of the dual architecture usermode rootkit](http://www.malwaretech.com/2013/06/rise-of-dual-architecture-usermode.html)
* [Killing the Rootkit - Shane Macaulay](http://blog.ioactive.com/2014/09/killing-rootkit.html)
	* Cross-platform, cross-architecture DKOM detection
* [Raising The Bar For Windows Rootkit Detection - Phrack](http://www.phrack.org/issues/63/8.html)
* [TLB Synchronization (Split TLB)](http://uninformed.org/index.cgi?v=6&a=1&p=21)
* [Komodia Rootkit Writeupn](https://gist.github.com/Wack0/f865ef369eb8c23ee028)
	* Komodia rootkit findings by @TheWack0lian
* [Using Kernel Rootkits to conceal infected MBR](http://www.malwaretech.com/2015/01/using-kernel-rootkits-to-conceal.html)
* [MoRE Shadow Walker : TLB - splitting on Modern x86](https://www.blackhat.com/docs/us-14/materials/us-14-Torrey-MoRE-Shadow-Walker-The-Progression-Of-TLB-Splitting-On-x86-WP.pdf)
	* MoRE, or Measurement of Running Executables, was a DARPA Cyber Fast Track effort to study the feasibility of utilizi ng x86 translation look - aside buffer (TLB) splitting techniques for realizing periodic measurements of running and dynamically changing applications. It built upon PaX, which used TLB splitting to emulate the no - execute bit and Shadow Walker, a memory hidi ng rootkit ; both designed for earlier processor architectures. MoRE and MoRE Shadow Walker are a defensive TLB splitting system and a prototype memory hiding rootkit for the current Intel i - series processors respectively – demonstrating the evolution of th e x86 architecture and how its complexity allows software to effect the apparent hardware architecture.
* [Smart TV Security - #1984 in 21 st century](https://cansecwest.com/slides/2013/SmartTV%20Security.pdf)
	* This talk is more about security bugs and rootkits than about firmware for TVs. This talk more covers rootkits than security bugs and exploitation thereof, as they’re not different to traditional techniques. This talk is about general security issues of all Smart TV vendors.
* [Advanced Bootkit Techniques on Android](http://www.syscan360.org/slides/2014_EN_AdvancedBootkitTechniquesOnAndroid_ChenZhangqiShendi.pdf)
* [Analyzing the Jynx rootkit and the LD-Preload technique](http://volatility-labs.blogspot.com/2012/09/movp-24-analyzing-jynx-rootkit-and.html)
	* In this post I will analyze the Jynx rootkit using Volatility’s new Linux features.
* [A Real SMM Rootkit: Reversing and Hooking BIOS SMI Handlers - Filip Wecherowski](http://phrack.org/issues/66/11.html#article)
	* The research provided in this paper describes in details how to reverse engineer and modify System Management Interrupt (SMI) handlers in the BIOS system firmware and how to implement and detect SMM keystroke logger. This work also presents proof of concept code of SMM keystroke logger that uses I/O Trap based keystroke interception and a code for detection of such keystroke logger.
* [Revisiting Mac OS X Kernel Rootkits - fG! <phrack@put.as>-](http://phrack.org/issues/69/7.html)
* [Android platform based linux kernel rootkit - dong-hoon you](http://www.phrack.org/issues/68/6.html)
* [Stealth hooking : Another way to subvert the Windows kernel - mxatone and ivanlef0u](http://phrack.org/issues/65/4.html#article)
* [Kernel Rootkit Experiences - stealth](http://phrack.org/issues/61/14.html)
* [NTIllusion: A portable Win32 userland rootkit - Kdm](http://phrack.org/issues/62/12.html)
* [Linux on-the-fly kernel patching without LKM - sd, devik](http://phrack.org/issues/58/7.html)







-----------------
### <a name="papers">Papers</a>
* [A Catalog of Windows Local Kernel-mode Backdoors](http://uninformed.org/?v=all&a=35&t=sumry)
	* This paper presents a detailed catalog of techniques that can be used to create local kernel-mode backdoors on Windows. These techniques include function trampolines, descriptor table hooks, model-specific register hooks, page table modifications, as well as others that have not previously been described. The majority of these techniques have been publicly known far in advance of this paper. However, at the time of this writing, there appears to be no detailed single point of reference for many of them. The intention of this paper is to provide a solid understanding on the subject of local kernel-mode backdoors. This understanding is necessary in order to encourage the thoughtful discussion of potential countermeasures and perceived advancements. In the vein of countermeasures, some additional thoughts are given to the common misconception that PatchGuard, in its current design, can be used to prevent kernel-mode rootkits.
* [Implementation and Implications of a Stealth Hard-Drive Backdoor](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf) 
	* Modern workstations and servers implicitly trust hard disks to act as well-behaved block devices. This paper analyzes the catastrophic loss of security that occurs when hard disks are not trustworthy. First, we show that it is possible to compromise the firmware of a commercial over-the-shelf hard drive, by resorting only to public information and reverse engineering. Using such a compromised firmware, we present a stealth rootkit that replaces arbitrary blocks from the disk while they are written, providing a data replacement back- door . The measured performance overhead of the compromised disk drive is less than 1% compared with a normal, non-malicious disk drive. We then demonstrate that a re- mote attacker can even establish a communication channel with a compromised disk to infiltrate commands and to ex-filtrate data. In our example, this channel is established over the Internet to an unmodified web server that relies on the compromised drive for its storage, passing through the original webserver, database server, database storage engine, filesystem driver, and block device driver. Additional experiments, performed in an emulated disk-drive environment, could automatically extract sensitive data such as /etc/shadow (or a secret key file) in less than a minute. This paper claims that the diffculty of implementing such an at- tack is not limited to the area of government cyber-warfare; rather, it is well within the reach of moderately funded criminals, botnet herders and academic researchers.
* [futo](http://uninformed.org/?v=all&a=17&t=sumry)
	* Since the introduction of FU, the rootkit world has moved away from implementing system hooks to hide their presence. Because of this change in offense, a new defense had to be developed. The new algorithms used by rootkit detectors, such as BlackLight, attempt to find what the rootkit is hiding instead of simply detecting the presence of the rootkit's hooks. This paper will discuss an algorithm that is used by both Blacklight and IceSword to detect hidden processes. This paper will also document current weaknesses in the rootkit detection field and introduce a more complete stealth technique implemented as a prototype in FUTo. 
* [Introducing Ring -3 Rootkits](http://invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf)
* [Pitfalls of virtual machine introspection on modern hardware](https://www.acsac.org/2014/workshops/mmf/Tamas%20Lengyel-Pitfalls%20of%20virtual%20machine%20introspection%20on%20modern%20hardware.pdf)
* [Security Evaluation of Intel's Active Management Technology](http://people.kth.se/~maguire/DEGREE-PROJECT-REPORTS/100402-Vassilios_Ververis-with-cover.pdf)


### <a name="tools"></a>Tools
* [DragonKing Rootkit](https://github.com/mgrube/DragonKing)
	* This is an open source rootkit created for a class taught on Rootkit Design. This rootkit hides by hooking the system call table and using an agent to do interactive manipulation in userland.
* [GPU rootkit PoC by Team Jellyfish](https://github.com/x0r1/jellyfish)









