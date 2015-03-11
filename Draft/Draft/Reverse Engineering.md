##Reverse Engineering


###Cull

[Introduction to Reverse Engineering Win32 Applications](http://uninformed.org/?v=all&a=7&t=sumry)
* During the course of this paper the reader will be (re)introduced to many concepts and tools essential to understanding and controlling native Win32 applications through the eyes of Windows Debugger (WinDBG). Throughout, WinMine will be utilized as a vehicle to deliver and demonstrate the functionality provided by WinDBG and how this functionality can be harnessed to aid the reader in reverse engineering native Win32 applications. Topics covered include an introductory look at IA-32 assembly, register significance, memory protection, stack usage, various WinDBG commands, call stacks, endianness, and portions of the Windows API. Knowledge gleaned will be used to develop an application designed to reveal and/or remove bombs from the WinMine playing grid. 




[Inside Blizzard: Battle.net](http://uninformed.org/?v=all&a=8&t=sumry)
* This paper intends to describe a variety of the problems Blizzard Entertainment has encountered from a practical standpoint through their implementation of the large-scale online game matchmaking and chat service, Battle.net. The paper provides some background historical information into the design and purpose of Battle.net and continues on to discuss a variety of flaws that have been observed in the implementation of the system. Readers should come away with a better understanding of problems that can be easily introduced in designing a matchmaking/chat system to operate on such a large scale in addition to some of the serious security-related consequences of not performing proper parameter validation of untrusted clients. 

[Bypassing PatchGuard on Windows x64](http://uninformed.org/?v=all&a=14&t=sumry)
* The version of the Windows kernel that runs on the x64 platform has introduced a new feature, nicknamed PatchGuard, that is intended to prevent both malicious software and third-party vendors from modifying certain critical operating system structures. These structures include things like specific system images, the SSDT, the IDT, the GDT, and certain critical processor MSRs. This feature is intended to ensure kernel stability by preventing uncondoned behavior, such as hooking. However, it also has the side effect of preventing legitimate products from working properly. For that reason, this paper will serve as an in-depth analysis of PatchGuard's inner workings with an eye toward techniques that can be used to bypass it. Possible solutions will also be proposed for the bypass techniques that are suggested. 

[Subverting PatchGuard Version 2](http://uninformed.org/?v=all&a=28&t=sumry)
* Windows Vista x64 and recently hotfixed versions of the Windows Server 2003 x64 kernel contain an updated version of Microsoft's kernel-mode patch prevention technology known as PatchGuard. This new version of PatchGuard improves on the previous version in several ways, primarily dealing with attempts to increase the difficulty of bypassing PatchGuard from the perspective of an independent software vendor (ISV) deploying a driver that patches the kernel. The feature-set of PatchGuard version 2 is otherwise quite similar to PatchGuard version 1; the SSDT, IDT/GDT, various MSRs, and several kernel global function pointer variables (as well as kernel code) are guarded against unauthorized modification. This paper proposes several methods that can be used to bypass PatchGuard version 2 completely. Potential solutions to these bypass techniques are also suggested. Additionally, this paper describes a mechanism by which PatchGuard version 2 can be subverted to run custom code in place of PatchGuard's system integrity checking code, all while leaving no traces of any kernel patching or custom kernel drivers loaded in the system after PatchGuard has been subverted. This is particularly interesting from the perspective of using PatchGuard's defenses to hide kernel mode code, a goal that is (in many respects) completely contrary to what PatchGuard is designed to do. 


[PatchGuard Reloaded: A Brief Analysis of PatchGuard Version 3](http://uninformed.org/?v=all&a=38&t=sumry)
* Since the publication of previous bypass or circumvention techniques for Kernel Patch Protection (otherwise known as "PatchGuard"), Microsoft has continued to refine their patch protection system in an attempt to foil known bypass mechanisms. With the release of Windows Server 2008 Beta 3, and later a full-blown distribution of PatchGuard to Windows Vista and Windows Server 2003 via Windows Update, Microsoft has introduced the next generation of PatchGuard to the general public ("PatchGuard 3"). As with previous updates to PatchGuard, version three represents a set of incremental changes that are designed to address perceived weaknesses and known bypass vectors in earlier versions. Additionally, PatchGuard 3 expands the set of kernel variables that are protected from unauthorized modification, eliminating several mechanisms that might be used to circumvent PatchGuard while co-existing (as opposed to disabling) it. This article describes some of the changes that have been made in PatchGuard 3. This article also proposes several new techniques that can be used to circumvent PatchGuard's defenses. Countermeasures for these techniques are also discussed. 

[Improving Automated Analysis of Windows x64 Binaries](http://uninformed.org/?v=all&a=18&t=sumry)
* As Windows x64 becomes a more prominent platform, it will become necessary to develop techniques that improve the binary analysis process. In particular, automated techniques that can be performed prior to doing code or data flow analysis can be useful in getting a better understanding for how a binary operates. To that point, this paper gives a brief explanation of some of the changes that have been made to support Windows x64 binaries. From there, a few basic techniques are illustrated that can be used to improve the process of identifying functions, annotating their stack frames, and describing their exception handler relationships. Source code to an example IDA plugin is also included that shows how these techniques can be implemented. 

[An Objective Analysis of the Lockdown Protection System for Battle.net ](http://uninformed.org/?v=all&a=40&t=sumry)
* Near the end of 2006, Blizzard deployed the first major update to the version check and client software authentication system used to verify the authenticity of clients connecting to Battle.net using the binary game client protocol. This system had been in use since just after the release of the original Diablo game and the public launch of Battle.net. The new authentication module (Lockdown) introduced a variety of mechanisms designed to raise the bar with respect to spoofing a game client when logging on to Battle.net. In addition, the new authentication module also introduced run-time integrity checks of client binaries in memory. This is meant to provide simple detection of many client modifications (often labeled "hacks") that patch game code in-memory in order to modify game behavior. The Lockdown authentication module also introduced some anti-debugging techniques that are designed to make it more difficult to reverse engineer the module. In addition, several checks that are designed to make it difficult to simply load and run the Blizzard Lockdown module from the context of an unauthorized, non-Blizzard-game process. After all, if an attacker can simply load and run the Lockdown module in his or her own process, it becomes trivially easy to spoof the game client logon process, or to allow a modified game client to log on to Battle.net successfully. However, like any protection mechanism, the new Lockdown module is not without its flaws, some of which are discussed in detail in this paper. 

[Real-time Steganography with RTP](http://uninformed.org/?v=all&a=36&t=sumry)
* Real-time Transfer Protocol (RTP) is used by nearly all Voice-over-IP systems to provide the audio channel for calls. As such, it provides ample opportunity for the creation of a covert communication channel due to its very nature. While use of steganographic techniques with various audio cover-medium has been extensively researched, most applications of such have been limited to audio cover-medium of a static nature such as WAV or MP3 file audio data. This paper details a common technique for the use of steganography with audio data cover-medium, outlines the problem issues that arise when attempting to use such techniques to establish a full-duplex communications channel within audio data transmitted via an unreliable streaming protocol, and documents solutions to these problems. An implementation of the ideas discussed entitled SteganRTP is included in the reference materials. 

[Locreate: An Anagram for Relocate ](http://uninformed.org/?v=all&a=30&t=sumry)
* This paper presents a proof of concept executable packer that does not use any custom code to unpack binaries at execution time. This is different from typical packers which generally rely on packed executables containing code that is used to perform the inverse of the packing operation at runtime. Instead of depending on custom code, the technique described in this paper uses documented behavior of the dynamic loader as a mechanism for performing the unpacking operation. This difference can make binaries packed using this technique more difficult to signature and analyze, but only when presented to an untrained eye. The description of this technique is meant to be an example of a fun thought exercise and not as some sort of revolutionary packer. In fact, it's been used in the virus world many years prior to this paper. 

[Using dual-mappings to evade automated unpackers ](http://uninformed.org/?v=all&a=44&t=sumry)
* Automated unpackers such as Renovo, Saffron, and Pandora's Bochs attempt to dynamically unpack executables by detecting the execution of code from regions of virtual memory that have been written to. While this is an elegant method of detecting dynamic code execution, it is possible to evade these unpackers by dual-mapping physical pages to two distinct virtual address regions where one region is used as an editable mapping and the second region is used as an executable mapping. In this way, the editable mapping is written to during the unpacking process and the executable mapping is used to execute the unpacked code dynamically. This effectively evades automated unpackers which rely on detecting the execution of code from virtual addresses that have been written to. 






























Reverse Engineering - Wikipedia
https://en.wikipedia.org/wiki/Reverse_engineering


[Introduction to Reverse Engineering Software](http://althing.cs.dartmouth.edu/local/www.acm.uiuc.edu/sigmil/RevEng/)
* This book is an attempt to provide an introduction to reverse engineering software under both Linux and Microsoft Windows©. Since reverse engineering is under legal fire, the authors figure the best response is to make the knowledge widespread. The idea is that since discussing specific reverse engineering feats is now illegal in many cases, we should then discuss general approaches, so that it is within every motivated user's ability to obtain information locked inside the black box. Furthermore, interoperability issues with closed-source proprietary systems are just plain annoying, and something needs to be done to educate more open source developers as to how to implement this functionality in their software. 




[OpenRCE Anti Reverse Engineering Techniques Database](http://www.openrce.org/reference_library/anti_reversing)


[Analyzing and Running binaries from Firmware Images - Part 1](http://w00tsec.blogspot.com.br/2013/09/analyzing-and-running-binaries-from.html
)
[SIMET Box Firmware Analysis: Embedded Device Hacking & Forensics](http://w00tsec.blogspot.com.br/2013/08/simet-box-firmware-analysis-embedded.html)



[APK Studio - Android Reverse Engineering](https://apkstudio.codeplex.com/)
* APK Studio is an IDE for decompiling/editing & then recompiling of android application binaries. Unlike initial release being Windows exclusive & also didn't support frameworks, this one is completely re-written using QT for cross-platform support. You can now have multiple frameworks installed & pick a particular one on a per project basis.

[Apple Lightning Reverse Engineered](http://ramtin-amin.fr/#tristar)


High Level view of what Reverse Engineering is

Link: http://www.program-transformation.org/Transform/DecompilationAndReverseEngineering


Anti Reverse Engineering:
http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide


What is Reverse Engineering? See the following link:
http://www.program-transformation.org/Transform/DecompilationAndReverseEngineering

Guides & Tutorials


Wikis


Reference Guides




Starting from Scratch?
Check out: http://www.reddit.com/r/ReverseEngineering/comments/smf4u/reverser_wanting_to_develop_mathematically/
And : 

Windows Anti-Debugging Reference
	From: http://www.symantec.com/connect/articles/windows-anti-debug-reference
This paper classifies and presents several anti-debugging techniques used on Windows NT-based operating systems. Anti-debugging techniques are ways for a program to detect if it runs under control of a debugger. They are used by commercial executable protectors, packers and malicious software, to prevent or slow-down the process of reverse-engineering. We'll suppose the program is analyzed under a ring3 debugger, such as OllyDbg on Windows platforms. The paper is aimed towards reverse-engineers and malware analysts. Note that we will talk purely about generic anti-debugging and anti-tracing techniques. Specific debugger detection, such as window or processes enumeration, registry scanning, etc. will not be addressed here.

Cryptoshark
	From: https://github.com/frida/cryptoshark
Interactive code tracer for reverse-engineering proprietary software 