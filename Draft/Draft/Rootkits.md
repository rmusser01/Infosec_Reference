##Rootkits



###Cull

[Shadow Walker - Raising the Bar for Rootkit detection - BH 2005](https://www.blackhat.com/presentations/bh-jp-05/bh-jp-05-sparks-butler.pdf)

[MoRE Shadow Walker : TLB - splitting on Modern x86](https://www.blackhat.com/docs/us-14/materials/us-14-Torrey-MoRE-Shadow-Walker-The-Progression-Of-TLB-Splitting-On-x86-WP.pdf)
* MoRE, or Measurement of Running Executables, was a DARPA Cyber Fast Track effort to study the feasibility of utilizi ng x86 translation look - aside buffer (TLB) splitting techniques for realizing periodic measurements of running and dynamically changing applications. It built upon PaX, which used TLB splitting to emulate the no - execute bit and Shadow Walker, a memory hidi ng rootkit ; both designed for earlier processor architectures. MoRE and MoRE Shadow Walker are a defensive TLB splitting system and a prototype memory hiding rootkit for the current Intel i - series processors respectively – demonstrating the evolution of th e x86 architecture and how its complexity allows software to effect the apparent hardware architecture.
* [Video Presentation at BlackHat](https://www.youtube.com/watch?v=XU1uNGZ7HnY)

[Masochist](https://github.com/squiffy/Masochist)
* Masochist is a framework for creating XNU based rootkits. Very useful in OS X and iOS security research.


[Suterusu](https://github.com/mncoppola/suterusu)
[Android Rootkit](https://github.com/hiteshd/Android-Rootkit)
An LKM rootkit targeting Linux 2.6/3.x on x86(_64), and ARM 
[Komodia Rootkit Writeupn](https://gist.github.com/Wack0/f865ef369eb8c23ee028)
* Komodia rootkit findings by @TheWack0lian

[Killing Rootkits](http://blog.ioactive.com/2014/09/killing-rootkit.html)

Defeating Sniffers and Intrustion Detection Systems - Horizon, 12/25/1998
Armouring the ELF: Binary Encryption on the UNIX Platform - grugq, scut, 12/28/2001
Runtime Process Infection - anonymous, 07/28/2002
Polymorphic Shellcode Engine Using Spectrum Analysis - theo detristan et al, 08/13/2003
Next-generation Runtime Binary Encryption using On-demand Function Extraction - Zeljko Vrba, 08/01/2005
Stealth Hooking: Another Way to Subvert the Windows Kernel - mxatone, ivanlef0u, 04/11/2008
Mystifying the Debugger for Ultimate Stealthness - halfdead, 04/11/2008
Binary Mangling with Radare - pancake, 06/11/2009

[Advanced Bootkit Techniques on Android](http://www.syscan360.org/slides/2014_EN_AdvancedBootkitTechniquesOnAndroid_ChenZhangqiShendi.pdf)

[Using Kernel Rootkits to conceal infected MBR](http://www.malwaretech.com/2015/01/using-kernel-rootkits-to-conceal.html)
* [Code](https://github.com/MalwareTech/FakeMBR/)

[From Kernel to VM](https://www.youtube.com/watch?v=FSw8Ff1SFLM)

* Description from stormeh on reddit(https://www.reddit.com/r/rootkit/comments/25hsc4/jacob_i_torrey_from_kernel_to_vmm/): Although it's not directly a lecture about rootkit development, the topics discussed are very much of interest: hardware virtualization, page table and TLB manipulation, hypervisors and privilege levels below ring 0, etc. The speaker does also go on to mention how prior rootkits such as Blue Pill and Shadow Walker leveraged these features, as well as defensive technologies such as PaX. 
* [Slides](http://jacobtorrey.com/VMMLecture.pdf)
* [Hypervisor code](https://github.com/ainfosec/more)
[Measurement of Running Executables](http://vimeo.com/81335517)
* This presentation provides a cohesive overview of the work performed by AIS, Inc. on the DARPA CFT MoRE effort. MoRE was a 4-month effort which examined the feasibility of utilizing TLB splitting as a mechanism for periodic measurement of dynamically changing binaries. The effort created a proof-of-concept system to split the TLB for target applications, allowing dynamic applications to be measured and can detect code corruption with low performance overhead.
[TLB Synchronization (Split TLB)](http://uninformed.org/index.cgi?v=6&a=1&p=21)

[MoRE Shadow Walker: The Progression Of TLB Splitting On x86](https://www.blackhat.com/docs/us-14/materials/us-14-Torrey-MoRE-Shadow-Walker-The-Progression-Of-TLB-Splitting-On-x86-WP.pdf)

[Raising The Bar For Windows Rootkit Detection - Phrack](http://www.phrack.org/issues/63/8.html)

http://www.phrack.com/papers/revisiting-mac-os-x-kernel-rootkits.html

http://www.phrack.org/issues/68/6.html

http://phrack.org/issues/65/4.html#article

http://phrack.org/issues/61/14.html

http://phrack.org/issues/58/7.html
http://phrack.org/issues/62/12.html

Thunderstrike is the name for the Apple EFI firmware security vulnerability that allows a malicious Thunderbolt device to flash untrusted code to the boot ROM
[Homesite](https://trmm.net/EFI)
[Talk at CCC31](https://www.youtube.com/watch?v=5BrdX7VdOr0)





###Writeups
[Rise of the dual architecture usermode rootkit](http://www.malwaretech.com/2013/06/rise-of-dual-architecture-usermode.html)
[Killing the Rootkit - Shane Macaulay](http://blog.ioactive.com/2014/09/killing-rootkit.html)
* Cross-platform, cross-architecture DKOM detection


###Videos
[Persistent, Stealthy, Remote-controlled Dedicated Hardware Malware [30c3]](https://www.youtube.com/watch?v=Ck8bIjAUJgE)

[Intel Management Engine Secrets by Igor Skochinsky](https://www.youtube.com/watch?v=Y2_-VXz9E-w)









