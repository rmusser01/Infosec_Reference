

##Reverse Engineering

Reverse Engineering - Wikipedia
https://en.wikipedia.org/wiki/Reverse_engineering


[Introduction to Reverse Engineering Software](http://althing.cs.dartmouth.edu/local/www.acm.uiuc.edu/sigmil/RevEng/)
* This book is an attempt to provide an introduction to reverse engineering software under both Linux and Microsoft Windows©. Since reverse engineering is under legal fire, the authors figure the best response is to make the knowledge widespread. The idea is that since discussing specific reverse engineering feats is now illegal in many cases, we should then discuss general approaches, so that it is within every motivated user's ability to obtain information locked inside the black box. Furthermore, interoperability issues with closed-source proprietary systems are just plain annoying, and something needs to be done to educate more open source developers as to how to implement this functionality in their software. 


TOC
Intro
Cull

ida plugins




###Cull


Add Section for Ida plugins
Ida pomidor plugin
Ida sploiter plugin


[Memalyze: Dynamic Analysis of Memory Access Behavior in Software](http://uninformed.org/?v=all&a=31&t=sumry)
* This paper describes strategies for dynamically analyzing an application's memory access behavior. These strategies make it possible to detect when a read or write is about to occur at a given location in memory while an application is executing. An application's memory access behavior can provide additional insight into its behavior. For example, it may be able to provide an idea of how data propagates throughout the address space. Three individual strategies which can be used to intercept memory accesses are described in this paper. Each strategy makes use of a unique method of intercepting memory accesses. These methods include the use of Dynamic Binary Instrumentation (DBI), x86 hardware paging features, and x86 segmentation features. A detailed description of the design and implementation of these strategies for 32-bit versions of Windows is given. Potential uses for these analysis techniques are described in detail. 



[TAMPER (Tamper And Monitoring Protection Engineering Research)](http://www.cl.cam.ac.uk/research/security/tamper/)
* In the TAMPER Lab, we study existing security products, document how they have been penetrated in the past, develop new attack techniques, and try to forecast how newly available technologies will make it easier to bypass hardware security mechanisms. We then develop and evaluate new countermeasures and assist industrial designers in staying ahead of the game, most of all by giving them an advanced understanding of which attack techniques are most dangerous. We are especially interested in protection systems for mass-market applications, and in forensic applications. 

[IDA Python - Ero Carrera](http://www.offensivecomputing.net/papers/IDAPythonIntro.pdf)
* IDAPython is an extension for IDA , the Interactive Disassembler . It brings the power and convenience of Python scripting to aid in the analysis of binaries. This article will cover some basic usage and provide examples to get interested individuals started. W e will walk through practical examples ranging from iterating through functions, segments and instructions to data mining the binaries, collecting references and analyzing their structure.


[PEview](http://wjradburn.com/software/)
* PEview provides a quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files. This PE/COFF file viewer displays header, section, directory, import table, export table, and resource information within EXE, DLL, OBJ, LIB, DBG, and other file types.


[Reverse Engineering: Reverse Engineering Flash Memory for Fun and Benefit  - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)

[Hardware reverse engineering tools (Olivier Thomas)  - REcon 2013](https://www.youtube.com/watch?v=o77GTR8RovM)

[Reverse](https://github.com/joelpx/reverse)
* Reverse engineering for x86 binaries (elf-format). Generate a more readable code (pseudo-C) with colored syntax. Warning, the project is still in development, use it at your own risks. This tool try to disassemble one function (by default main). The address of the function, or its symbol, can be passed by argument.

[Reversing Monkey](http://cheeky4n6monkey.blogspot.com/2015/02/reversing-monkey.html?m=1)
* When trying to recover/carve deleted data, some reverse engineering of the file format may be required. Without knowing how the data is stored, we cannot recover the data of interest - be it timestamps, messages, images, video or another type of data. This quick blog post is intended to give some basic tips that have been observed during monkey's latest travels into reverse engineering of file formats. It was done partly as a memory aid/thinking exercise but hopefully other monkeys will find it useful. This post assumes there's no obfuscation/encryption applied to the file and it does not cover reverse engineering malware exes (which is another kettle of bananas).  - Great post/write-up


[xnippet](https://github.com/isislab/xnippet)
* xnippet is a tool that lets you load code snippets or isolated functions (no matter the operating system they came from), pass parameters to it in several formats (signed decimal, string, unsigned hexadecimal...), hook other functions called by the snippet and analyze the result. The tool is written in a way that will let me improve it in a future, defining new calling conventions and output argument pointers.

[Reverse Engineering: Reverse Engineering Flash Memory for Fun and Benefit - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)




[SATCOM Terminals Hacking by Air, Sea, and Land - Black Hat USA 2014](https://www.youtube.com/watch?v=tRHDuT__GoM)



https://github.com/droidsec/droidsec.github.io/wiki/Android-Crackmes

[How to RE data files?](https://www.reddit.com/r/ReverseEngineering/comments/l8ac0/how_to_re_data_files/)
* Good read over.

[Introduction to Reverse Engineering Win32 Applications](http://uninformed.org/?v=all&a=7&t=sumry)
* During the course of this paper the reader will be (re)introduced to many concepts and tools essential to understanding and controlling native Win32 applications through the eyes of Windows Debugger (WinDBG). Throughout, WinMine will be utilized as a vehicle to deliver and demonstrate the functionality provided by WinDBG and how this functionality can be harnessed to aid the reader in reverse engineering native Win32 applications. Topics covered include an introductory look at IA-32 assembly, register significance, memory protection, stack usage, various WinDBG commands, call stacks, endianness, and portions of the Windows API. Knowledge gleaned will be used to develop an application designed to reveal and/or remove bombs from the WinMine playing grid. 

[Reverse Engineering Mac OS X](http://reverse.put.as/papers/)
* Excellent source of papers from 2003-2013 all with a focus on reversing either iOS or OS X.


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

[An Objective Analysis of the Lockdown Protection System for Battle.net](http://uninformed.org/?v=all&a=40&t=sumry)
* Near the end of 2006, Blizzard deployed the first major update to the version check and client software authentication system used to verify the authenticity of clients connecting to Battle.net using the binary game client protocol. This system had been in use since just after the release of the original Diablo game and the public launch of Battle.net. The new authentication module (Lockdown) introduced a variety of mechanisms designed to raise the bar with respect to spoofing a game client when logging on to Battle.net. In addition, the new authentication module also introduced run-time integrity checks of client binaries in memory. This is meant to provide simple detection of many client modifications (often labeled "hacks") that patch game code in-memory in order to modify game behavior. The Lockdown authentication module also introduced some anti-debugging techniques that are designed to make it more difficult to reverse engineer the module. In addition, several checks that are designed to make it difficult to simply load and run the Blizzard Lockdown module from the context of an unauthorized, non-Blizzard-game process. After all, if an attacker can simply load and run the Lockdown module in his or her own process, it becomes trivially easy to spoof the game client logon process, or to allow a modified game client to log on to Battle.net successfully. However, like any protection mechanism, the new Lockdown module is not without its flaws, some of which are discussed in detail in this paper. 

[Real-time Steganography with RTP](http://uninformed.org/?v=all&a=36&t=sumry)
* Real-time Transfer Protocol (RTP) is used by nearly all Voice-over-IP systems to provide the audio channel for calls. As such, it provides ample opportunity for the creation of a covert communication channel due to its very nature. While use of steganographic techniques with various audio cover-medium has been extensively researched, most applications of such have been limited to audio cover-medium of a static nature such as WAV or MP3 file audio data. This paper details a common technique for the use of steganography with audio data cover-medium, outlines the problem issues that arise when attempting to use such techniques to establish a full-duplex communications channel within audio data transmitted via an unreliable streaming protocol, and documents solutions to these problems. An implementation of the ideas discussed entitled SteganRTP is included in the reference materials. 

[Locreate: An Anagram for Relocate ](http://uninformed.org/?v=all&a=30&t=sumry)
* This paper presents a proof of concept executable packer that does not use any custom code to unpack binaries at execution time. This is different from typical packers which generally rely on packed executables containing code that is used to perform the inverse of the packing operation at runtime. Instead of depending on custom code, the technique described in this paper uses documented behavior of the dynamic loader as a mechanism for performing the unpacking operation. This difference can make binaries packed using this technique more difficult to signature and analyze, but only when presented to an untrained eye. The description of this technique is meant to be an example of a fun thought exercise and not as some sort of revolutionary packer. In fact, it's been used in the virus world many years prior to this paper. 

[Using dual-mappings to evade automated unpackers ](http://uninformed.org/?v=all&a=44&t=sumry)
* Automated unpackers such as Renovo, Saffron, and Pandora's Bochs attempt to dynamically unpack executables by detecting the execution of code from regions of virtual memory that have been written to. While this is an elegant method of detecting dynamic code execution, it is possible to evade these unpackers by dual-mapping physical pages to two distinct virtual address regions where one region is used as an editable mapping and the second region is used as an executable mapping. In this way, the editable mapping is written to during the unpacking process and the executable mapping is used to execute the unpacked code dynamically. This effectively evades automated unpackers which rely on detecting the execution of code from virtual addresses that have been written to. 


[Android Reverse Engineering Defenses](https://bluebox.com/wp-content/uploads/2013/05/AndroidREnDefenses201305.pdf)



###Tools


###General Tools/Multiplatform





###Linux Specific Tools




###Windows Specific Tools






[readelf](https://sourceware.org/binutils/docs/binutils/readelf.html)
* Unix Tool



[Rdis](https://github.com/endeav0r/rdis)
* Rdis is a Binary Analysis Tool for Linux.


[Statically Linked Library Detector](https://github.com/arvinddoraiswamy/slid)


[Open Source Windows x86/x64 Debugger](http://x64dbg.com/)

[PortEx](https://github.com/katjahahn/PortEx)
* PortEx is a Java library for static malware analysis of Portable Executable files. Its focus is on PE malformation robustness, and anomaly detection. PortEx is written in Java and Scala, and targeted at Java applications.


[binwally](https://github.com/bmaia/binwally)
* Binary and Directory tree comparison tool using the Fuzzy Hashing concept (ssdeep)
* [Using binwally - a directory tree diff tool](http://w00tsec.blogspot.com/2013/12/binwally-directory-tree-diff-tool-using.html)
[BitBlaze](http://bitblaze.cs.berkeley.edu/)
* The BitBlaze project aims to design and develop a powerful binary analysis platform and employ the platform in order to (1) analyze and develop novel COTS protection and diagnostic mechanisms and (2) analyze, understand, and develop defenses against malicious code. The BitBlaze project also strives to open new application areas of binary analysis, which provides sound and effective solutions to applications beyond software security and malicious code defense, such as protocol reverse engineering and fingerprint generation. 

[SpyStudio](http://www.nektra.com/products/spystudio-api-monitor/)
* SpyStudio shows and interprets calls, displaying the results in a structured way which is easy for any IT professional to understand. SpyStudio can show registry keys and files that an application uses, COM objects and Windows the application has created, and errors and exceptions.

[API Monitor](http://www.rohitab.com/apimonitor)
* API Monitor is a free software that lets you monitor and control API calls made by applications and services. Its a powerful tool for seeing how applications and services work or for tracking down problems that you have in your own applications.


[Equip: python bytecode instrumentation](https://github.com/neuroo/equip)
* equip is a small library that helps with Python bytecode instrumentation. Its API is designed to be small and flexible to enable a wide range of possible instrumentations. The instrumentation is designed around the injection of bytecode inside the bytecode of the program to be instrumented. However, the developer does not need to know anything about the Python bytecode since the injected code is Python source.


[Firmware Modifcation kit](https://code.google.com/p/firmware-mod-kit/)
* This kit is a collection of scripts and utilities to extract and rebuild linux based firmware images.


[Binwalk](https://github.com/devttys0/binwalk)
* Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.


PEStudio
PEStudio is a unique tool that performs the static investigation of 32-bit and 64-bit executable. 



Malicious executable often attempts to hide its malicious behavior and to evade detection. In doing so, it generally presents anomalies and suspicious patterns. The goal of PEStudio is to detect these anomalies, provide indicators and score the executable being analyzed. Since the executable file being analyzed is never started, you can inspect any unknown or malicious executable with no risk. 
http://www.winitor.com/

[DotPeek](http://www.jetbrains.com/decompiler/features/)
* dotPeek is a .NET decompiler that has several handy features. I haven’t used it much, and don’t do much in .NET so I can’t say if its a good one, only that I’ve had success in using it.

[Microsoft Message Analyzer])http://www.microsoft.com/en-us/download/details.aspx?id=40308)
* Microsoft Message Analyzer is a new tool for capturing, displaying, and analyzing protocol messaging traffic and other system messages. Message Analyzer also enables you to import, aggregate, and analyze data from log and trace files. It is the successor to Microsoft Network Monitor 3.4 and a key component in the Protocol Engineering Framework (PEF) that was created by Microsoft for the improvement of protocol design, development, documentation, testing, and support. With Message Analyzer, you can choose to capture data live or load archived message collections from multiple data sources simultaneously.


[API Monitor](http://www.rohitab.com/apimonitor)
* API Monitor is a free software that lets you monitor and control API calls made by applications and services. Its a powerful tool for seeing how applications and services work or for tracking down problems that you have in your own applications.

[Static binary analysis tool](https://github.com/bdcht/amoco)
* Amoco is a python package dedicated to the (static) analysis of binaries.
* Worth a check on the Github


[Python RE tools list](http://pythonarsenal.erpscan.com/)



[Frida](http://www.frida.re/docs/home/)
* Inject JS into native apps



[Procyon - Java Decompiler](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler)

[PortEx](https://github.com/katjahahn/PortEx)
* PortEx is a Java library for static malware analysis of Portable Executable files. Its focus is on PE malformation robustness, and anomaly detection. PortEx is written in Java and Scala, and targeted at Java applications.

[Xmount](https://www.pinguin.lu/xmount)
* What is xmount? xmount allows you to convert on-the-fly between multiple input and output harddisk image types. xmount creates a virtual file system using FUSE (Filesystem in Userspace) that contains a virtual representation of the input image. The virtual representation can be in raw DD, DMG, VHD, VirtualBox's virtual disk file format or in VmWare's VMDK file format. Input images can be raw DD, EWF (Expert Witness Compression Format) or AFF (Advanced Forensic Format) files. In addition, xmount also supports virtual write access to the output files that is redirected to a cache file. This makes it possible to boot acquired harddisk images using QEMU, KVM, VirtualBox, VmWare or alike.




[STOKE](https://github.com/eschkufz/stoke-release)
* STOKE is a stochastic optimizer for the x86_64 instruction set. STOKE uses random search to explore the extremely high-dimensional space of all possible program transformations. Although any one random transformation is unlikely to produce a code sequence that is both correct and an improvement over the original, the repeated application of millions of transformations is sufficient to produce novel and non-obvious code sequences that have been shown to outperform the code produced by general-purpose and domain-specific compilers, and in some cases expert hand-written code.


[Intro to x86 calling conventions](http://codearcana.com/posts/2013/05/21/a-brief-introduction-to-x86-calling-conventions.html)



[Theorem prover, symbolic execution and practical reverse-engineering](https://doar-e.github.io/presentations/securityday2015/SecDay-Lille-2015-Axel-0vercl0k-Souchet.html#/)






###File Formats

[Tour of Win32 Executable format](http://msdn.microsoft.com/en-us/magazine/ms809762.aspx)






###Anti-Reverse Engineering Techniques & Countermeasures

[Anti-RE A collection of Anti-Reverse Engineering Techniques](http://pnx.tf/files/spring7_antire_plohmann_kannen.pdf)

[simpliFiRE.AntiRE - An Executable Collection of Anti-Reversing Techniques](https://bitbucket.org/fkie_cd_dare/simplifire.antire)
* AntiRE is a collection of such anti analysis approaches, gathered from various sources like Peter Ferrie's The "Ultimate" Anti-Debugging Reference and Ange Albertini's corkami. While these techniques by themselves are nothing new, we believe that the integration of these tests in a single, executable file provides a comprehensive overview on these, suitable for directly studying their behaviour in a harmless context without additional efforts. AntiRE includes different techniques to detect or circumvent debuggers, fool execution tracing, and disable memory dumping. Furthermore, it can detect the presence of different virtualization environments and gives examples of techniques used to twarth static analysis.

	
[Medusa](https://github.com/wisk/medusa)
* Medusa is a disassembler designed to be both modular and interactive. It runs on Windows and Linux, it should be the same on OSX. This project is organized as a library. To disassemble a file you have to use medusa_dummy or qMedusa. wxMedusa and pydusa are not available anymore.

[x86 opcode structure and instruction overview](http://pnx.tf/files/x86_opcode_structure_and_instruction_overview.pdf)

[ALPHA3[(https://code.google.com/p/alpha3/)
* ALPHA3 is a tool for transforming any x86 machine code into 100% alphanumeric code with similar functionality. It works by encoding the original code into alphanumeric data and combining this data with a decoder, which is a piece of x86 machine code written specifically to be 100% alphanumeric. When run, the decoder converts the data back to the original code, after which it is executed.


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





###Firmware Analysis

[An Introduction to Firmware Analysis[30c3]](https://www.youtube.com/watch?v=kvfP7StmFxY)
* This talk gives an introduction to firmware analysis: It starts with how to retrieve the binary, e.g. get a plain file from manufacturer, extract it from an executable or memory device, or even sniff it out of an update process or internal CPU memory, which can be really tricky. After that it introduces the necessary tools, gives tips on how to detect the processor architecture, and explains some more advanced analysis techniques, including how to figure out the offsets where the firmware is loaded to, and how to start the investigation.


Reverse Engineering Router Firmware walk through
* [Part 1](http://www.secforce.com/blog/2014/04/reverse-engineer-router-firmware-part-1/)
* [Part 2](http://www.secforce.com/blog/2014/07/reverse-engineer-router-firmware-part-2/)

###Guides & Tutorials



###Protocol Analysis & Related

* [Netzob](http://www.netzob.org/)
* Originaly, the development of Netzob has been initiated to support security auditors and evaluators in their activities of modeling and simulating undocumented protocols. The tool has then been extended to allow smart fuzzing of unknown protocol. 
[Netzob Documentation](http://netzob.readthedocs.org/en/latest/overview/index.html) 



###Writeups

[A Technical Analysis of CVE 2014-1776](http://blog.fortinet.com/post/a-technical-analysis-of-cve-2014-1776)



[Somfy Smoove Origin RTS Protocol](https://pushstack.wordpress.com/somfy-rts-protocol/)
* This document describes the Somfy RTS protocol as used by the “Somfy Smoove Origin RTS”. Most information in this document is based on passive observation of the data send by the Smoove Origin RTS remote, and thus can be inaccurate or incorrect!

[ Reverse Engineering The eQSO Protocol](https://gist.github.com/anonymous/7a9d713e61ba990a3a17)
* Today I reverse engineered the eQSO protocol. If you didn't know, eQSO is a small program that allows radio amateurs to talk to each other online. Sadly this program isn't as popular as it used to be (Well, neither is the radio).

[You can ring my bell! Adventures in sub-GHz RF land…](http://adamsblog.aperturelabs.com/2013/03/you-can-ring-my-bell-adventures-in-sub.html)


Reverse engineering walk htrouhg; guy rev eng alarm system from shelf to replay
https://www.reddit.com/r/ReverseEngineering/comments/1hb7oy/a_series_about_basics_of_hardware_reverse/
Part 1: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-system-part-1/
Part 2: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-2/
Part 3: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-3/
Part 4: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-4/
Part 5: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-5/
Part 6: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-6/
Part 7: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-7/
Part 8: http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-8/

###Papers

[Byteweight: Learning to Recognize Functions in Binary Code](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-bao.pdf)

[Reverse Engineering Qualcomm Baseband](http://events.ccc.de/congress/2011/Fahrplan/attachments/2022_11-ccc-qcombbdbg.pdf)

[The Art of Unpacking - Paper](https://www.blackhat.com/presentations/bh-usa-07/Yason/Whitepaper/bh-usa-07-yason-WP.pdf)
* Abstract: The main purpose of this paper is to present anti-reversing techniques employed by 
executable packers/protectors and also discusses techniques and publicly available tools that 
can be used to bypass or disable this protections. This information will allow researchers, 
especially, malcode analysts to identify these techniques when utilized by packed malicious 
code, and then be able decide the next move when these anti-reversing techniques impede 
successful analysis. As a secondary purpose, the information presented can also be used by 
researchers that are planning to add some level of protection in their software by slowing 
down reversers from analyzing their protected code, but of course, nothing will stop a skilled, 
informed, and determined reverser



[Paper on Manual unpacking of UPX packed executable using Ollydbg and Importrec](http://www.iosrjournals.org/iosr-jce/papers/Vol16-issue1/Version-1/L016117177.pdf)







###Wikis & Useful Sites
[FCC ID Lookup](http://transition.fcc.gov/oet/ea/fccid/)
* Lookup devices according to FCC ID





###Reference Guides



###Talks & Videos

[Cyber Necromancy - Reverse engineering dead protocols - Defcamp 2014 ](https://www.youtube.com/watch?v=G0v2FO2Ru0w&index=6&list=PLnwq8gv9MEKgSryzYIFhpmCcqnVzdUWfH)



###Windows Specific
[Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it’s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What’s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."



###Hardware Focused Reverse Engineering

[Reverse Engineering Intels Management Engine](http://recon.cx/2014/slides/Recon%202014%20Skochinsky.pdf) 
* On every intel chip core2duo and newer

[ChipWhisperer](http://www.newae.com/chipwhisperer)
* ChipWhisperer is the first ever open-source solution that provides a complete toolchain for research and analysis of embedded hardware security. Side Channel Power Analysis, Clock Glitching, VCC Glitching, and more are all possible with this unique tool.

####Hacking the Dropcam series
	[Part 1 - Dropcam Comms](http://blog.includesecurity.com/2014/03/Reverse-Engineering-Dropcam-Communications.html)
	[Part 2 - Rooting the Dropcam](http://blog.includesecurity.com/2014/04/reverse-engineering-dropcam-rooting-the-device.html)
	[Part 3 - Dropcam Lua Bytecode](http://blog.includesecurity.com/2014/08/Reverse-Engineering-Dropcam-Lua-Bytecode.html)




Starting from Scratch?
Check out: http://www.reddit.com/r/ReverseEngineering/comments/smf4u/reverser_wanting_to_develop_mathematically/
And : 

Windows Anti-Debugging Reference
	From: http://www.symantec.com/connect/articles/windows-anti-debug-reference
This paper classifies and presents several anti-debugging techniques used on Windows NT-based operating systems. Anti-debugging techniques are ways for a program to detect if it runs under control of a debugger. They are used by commercial executable protectors, packers and malicious software, to prevent or slow-down the process of reverse-engineering. We'll suppose the program is analyzed under a ring3 debugger, such as OllyDbg on Windows platforms. The paper is aimed towards reverse-engineers and malware analysts. Note that we will talk purely about generic anti-debugging and anti-tracing techniques. Specific debugger detection, such as window or processes enumeration, registry scanning, etc. will not be addressed here.

Cryptoshark
	From: https://github.com/frida/cryptoshark
Interactive code tracer for reverse-engineering proprietary software 