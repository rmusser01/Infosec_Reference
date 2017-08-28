

## Reverse Engineering



TOC
Intro
To be sorted

* [Frameworks](#frameworks)
* [Debuggers & Related Techniques](#dbg)
* [Decompilers](#decom)
* [Comparison Tools](#ct)
* [Tools](#tools)
	..* [Linux Specific Tools](#lt)
	..* [Windows Specific Tools](#wt)
	..* [Programming Libraries](#pl)
* [Anti-Reverse Engineering & Countermeasure](#ar)
* [Guides & Tutorials](#guides)
* [Hardware Reverse Engineering](#hre)
* [Protocol Analysis](#pa)
* [Write-ups](#writeups)
* [Talks & Videos](#talks)
* [Papers](#papers)
* [Wikis & Useful Sites](#wikis)





### To be sorted


[Hyper-V debugging for beginners](http://hvinternals.blogspot.com/2015/10/hyper-v-debugging-for-beginners.html?m=1)

[Software Hooking methods reveiw(2016)]((https://www.blackhat.com/docs/us-16/materials/us-16-Yavo-Captain-Hook-Pirating-AVs-To-Bypass-Exploit-Mitigations-wp.pdf)

[Deviare v2.0](http://whiteboard.nektra.com/deviare-v-2-0)
* The Deviare API has been developed to intercept any API calls, letting you get control of the flow of execution of any application.

[Reverse History Part Two – Research](http://jakob.engbloms.se/archives/1554)

[SpyStudio Tutorials](http://whiteboard.nektra.com/spystudio-2-0-quickstart)


[PPEE(puppy)](https://www.mzrst.com/#top)
* Professional PE file Explorer for reversers, malware researchers and those who want to statically inspect PE files in more details. Free and fast.

[bingrep](https://github.com/m4b/bingrep)
* Greps through binaries from various OSs and architectures, and colors them. 

http://stunnix.com/prod/cxxo/

[asar](https://github.com/electron/asar)
*  Simple extensive tar-like archive format with indexing

https://speakerdeck.com/patrickwardle/defcon-2016-i-got-99-problems-but-little-snitch-aint-one

https://www.hex-rays.com/products/ida/tech/flirt/in_depth.shtml 


http://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/ 

 mammon_'s tales to his grandson - https://mammon.github.io/tales/

http://fileformats.archiveteam.org/wiki/PNG

[Bug Hunting for the Man on the Street]()
* Finding and discovering bugs has to be one of the most special times in a security researchers life (until you realise that crash you've been searching for and finally found is not actually exploitable). But the process of searching, discovery, understanding and of course some very much needed trial and error, many would say are rewarding and fulfilling themselves (I would of course, prefer to have my exploit cherry on the top)! So this talk will detail some of the aspects required to hunt down and find these coveted security vulnerabilities and bugs and some approaches that have proven to be invaluable (and some not so much). Of course bug hunting principle need to produce bugs so as the cherry there will be a virtual box exploit and Barracuda networks 0 day exploit discussed and demon


[Universal Extractor](http://www.legroom.net/software/uniextract)
* Universal Extractor is a program designed to decompress and extract files from any type of archive or installer, such as ZIP or RAR files, self-extracting EXE files, application installers, etc

[Unicorn-Engine](http://www.unicorn-engine.org/)
* Unicorn is a lightweight multi-platform, multi-architecture CPU emulator framework.

[Reversing Prince Harming’s Kiss of Death]( https://reverse.put.as/2015/07/01/reversing-prince-harmings-kiss-of-death/)

https://objective-see.com/

[Bytecode Club - RE Forum](https://the.bytecode.club/)



[Blackbone](https://github.com/DarthTon/Blackbone)
* Windows memory hacking library

[Binacle](https://github.com/ANSSI-FR/Binacle)
* Indexation "full-bin" of binary files


[Microsoft.Diagnostics.Runtime.dll(CLR MD)](https://github.com/Microsoft/clrmd)
* Microsoft.Diagnostics.Runtime.dll (nicknamed "CLR MD") is a process and crash dump introspection library. This allows you to write tools and debugger plugins which can do thing similar to SOS and PSSCOR.

[Getting Started with CLR MD](https://github.com/Microsoft/clrmd/blob/master/Documentation/GettingStarted.md)

[Reverse Engineering IoT Devices](https://iayanpahwa.github.io/Reverse-Engineering-IoT-Devices/)

[radare2 as an alternative to gdb-peda](https://monosource.github.io/2016/10/radare2-peda)

[jefferson](https://github.com/sviehb/jefferson)
* JFFS2 filesystem extraction tool

[Reverse Engineering Firmware Primer](https://wiki.securityweekly.com/Reverse_Engineering_Firmware_Primer)

[Hacking Linksys E4200v2 firmware](https://blog.bramp.net/post/2012/01/24/hacking-linksys-e4200v2-firmware/)

[Defeating ioli with radare2](https://dustri.org/b/defeating-ioli-with-radare2.html)

[Gynvael’s Mission 11 (en): Python bytecode reverse-engineering](https://chriswarrick.com/blog/2017/08/03/gynvaels-mission-11-en-python-bytecode-reverse-engineering/)




### End sort





### General



[radare2 cheat sheet](https://github.com/pwntester/cheatsheets/blob/master/radare2.md)

[Introduction to Reverse Engineering Software - Dartmouth](http://althing.cs.dartmouth.edu/local/www.acm.uiuc.edu/sigmil/RevEng/)

[CSCI 4974 / 6974 Hardware Reverse Engineering](http://security.cs.rpi.edu/courses/hwre-spring2014/)

[Reverse Engineering - Wikipedia](https://en.wikipedia.org/wiki/Reverse_engineering)

[High Level view of what Reverse Engineering is](http://www.program-transformation.org/Transform/DecompilationAndReverseEngineering)

[What is Reverse Engineering?](http://www.program-transformation.org/Transform/DecompilationAndReverseEngineering)

[Introduction to Reverse Engineering Software](http://althing.cs.dartmouth.edu/local/www.acm.uiuc.edu/sigmil/RevEng/)
* This book is an attempt to provide an introduction to reverse engineering software under both Linux and Microsoft Windows©. Since reverse engineering is under legal fire, the authors figure the best response is to make the knowledge widespread. The idea is that since discussing specific reverse engineering feats is now illegal in many cases, we should then discuss general approaches, so that it is within every motivated user's ability to obtain information locked inside the black box. Furthermore, interoperability issues with closed-source proprietary systems are just plain annoying, and something needs to be done to educate more open source developers as to how to implement this functionality in their software. 

[Starting from Scratch?](http://www.reddit.com/r/ReverseEngineering/comments/smf4u/reverser_wanting_to_develop_mathematically/)

[Symbolic execution timeline](https://github.com/enzet/symbolic-execution)
* Diagram highlights some major tools and ideas of pure symbolic execution, dynamic symbolic execution (concolic) as well as related ideas of model checking, SAT/SMT solving, black-box fuzzing, taint data tracking, and other dynamic analysis techniques.





### Things that are interesting/don't fit elsewhere

[SyntaxHighlighter](http://alexgorbatchev.com/SyntaxHighlighter/)
* SyntaxHighlighter is a fully functional self-contained code syntax highlighter developed in JavaScript. To get an idea of what SyntaxHighlighter is capable of, have a look at the demo page.

[linguist](https://github.com/github/linguist)
*  Language Savant. If your repository's language is being reported incorrectly, send us a pull request!

[Ohcount - Ohloh's source code line counter.](https://github.com/blackducksoftware/ohcount)

[Detecting programming language from a snippet](https://stackoverflow.com/questions/475033/detecting-programming-language-from-a-snippet)




### <a name="general">General Research/Stuff</a>
[TAMPER (Tamper And Monitoring Protection Engineering Research)](http://www.cl.cam.ac.uk/research/security/tamper/)
* In the TAMPER Lab, we study existing security products, document how they have been penetrated in the past, develop new attack techniques, and try to forecast how newly available technologies will make it easier to bypass hardware security mechanisms. We then develop and evaluate new countermeasures and assist industrial designers in staying ahead of the game, most of all by giving them an advanced understanding of which attack techniques are most dangerous. We are especially interested in protection systems for mass-market applications, and in forensic applications. 

[Tour of Win32 Executable format](http://msdn.microsoft.com/en-us/magazine/ms809762.aspx)

[Theorem prover, symbolic execution and practical reverse-engineering](https://doar-e.github.io/presentations/securityday2015/SecDay-Lille-2015-Axel-0vercl0k-Souchet.html#/)


 [PE File Format Graphs](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html?view=mosaic)

[Encyclopedia of Graphics File Formats](http://fileformats.archiveteam.org/wiki/Encyclopedia_of_Graphics_File_Formats)








### <a name="tools">Tools</a>
Will sort to static/dynamic/OS specific

[Frida](http://www.frida.re/docs/home/)
* Inject JS into native apps

[Dependency Walker](http://www.dependencywalker.com/)
*  Dependency Walker is a free utility that scans any 32-bit or 64-bit Windows module (exe, dll, ocx, sys, etc.) and builds a hierarchical tree diagram of all dependent modules. For each module found, it lists all the functions that are exported by that module, and which of those functions are actually being called by other modules. Another view displays the minimum set of required files, along with detailed information about each file including a full path to the file, base address, version numbers, machine type, debug information, and more.

[Rdis](https://github.com/endeav0r/rdis)
* Rdis is a Binary Analysis Tool for Linux.

[Python RE tools list](http://pythonarsenal.erpscan.com/)

[Statically Linked Library Detector](https://github.com/arvinddoraiswamy/slid)

[Bindead - static binary binary analysis tool](https://bitbucket.org/mihaila/bindead/wiki/Home)
* Bindead is an analyzer for executable machine code. It features a disassembler that translates machine code bits into an assembler like language (RREIL) that in turn is then analyzed by the static analysis component using abstract interpretation. 

[Static binary analysis tool](https://github.com/bdcht/amoco)
* Amoco is a python package dedicated to the (static) analysis of binaries.
* Worth a check on the Github

[Binwalk](https://github.com/devttys0/binwalk)
Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.

[Cryptoshark](https://github.com/frida/cryptoshark)
* Interactive code tracer for reverse-engineering proprietary software 

[Pip3line, the Swiss army knife of byte manipulation](https://nccgroup.github.io/pip3line/index.html) 
* Pip3line is a raw bytes manipulation utility, able to apply well known and less well known transformations from anywhere to anywhere (almost).

[Instruments - OS X system analysis](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/Introduction/Introduction.html)
* Instruments is a performance-analysis and testing tool for dynamically tracing and profiling OS X and iOS code. It is a flexible and powerful tool that lets you track a process, collect data, and examine the collected data. In this way, Instruments helps you understand the behavior of both user apps and the operating system.

Reversing iOS/OS X http://newosxbook.com/forum/viewforum.php?f=8

[Construct2](https://github.com/construct/construct)
* Construct is a powerful declarative parser (and builder) for binary data.  Instead of writing imperative code to parse a piece of data, you declaratively define a data structure that describes your data. As this data structure is not code, you can use it in one direction to parse data into Pythonic objects, and in the other direction, convert ("build") objects into binary data.

[Deviare2](https://github.com/nektra/deviare2)
* Deviare is a professional hooking engine for instrumenting arbitrary Win32 functions, COM objects, and functions which symbols are located in program databases (PDBs). It can intercept unmanaged code in 32-bit and 64-bit applications. It is implemented as a COM component, so it can be integrated with all the programming languages which support COM, such as C/C++, VB, C#, Delphi, and Python.

[PolyHook - x86/x64 Hooking Library](https://github.com/stevemk14ebr/PolyHook)
* Provides abstract C++ 11 interface for various hooking methods
* [Technical Writeup](https://www.codeproject.com/articles/1100579/polyhook-the-cplusplus-x-x-hooking-library)

[EasyHook](https://easyhook.github.io/)
* EasyHook makes it possible to extend (via hooking) unmanaged code APIs with pure managed functions, from within a fully managed environment on 32- or 64-bit Windows XP SP2, Windows Vista x64, Windows Server 2008 x64, Windows 7, Windows 8.1, and Windows 10.

[python-oletools](https://github.com/decalage2/oletools)
* python-oletools is a package of python tools to analyze Microsoft OLE2 files (also called Structured Storage, Compound File Binary Format or Compound Document File Format), such as Microsoft Office documents or Outlook messages, mainly for malware analysis, forensics and debugging. It is based on the olefile parser. See http://www.decalage.info/python/oletools for more info.

[Fibratus](https://github.com/rabbitstack/fibratus)
* Fibratus is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, file system I/O, registry, network activity, DLL loading/unloading and much more. Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, set kernel event filters or run the lightweight Python modules called filaments. You can use filaments to extend Fibratus with your own arsenal of tools.













#### Binary Visualization Tools
[binglide](https://github.com/wapiflapi/binglide)
* binglide is a visual reverse engineering tool. It is designed to offer a quick overview of the different data types that are present in a file. This tool does not know about any particular file format, everything is done using the same analysis working on the data. This means it works even if headers are missing or corrupted or if the file format is unknown.

[binvis.io](http://binvis.io/#/)
* visual analysis of binary files

[cantor.dust](https://sites.google.com/site/xxcantorxdustxx/home)
* a powerful, dynamic, interactive binary visualization tool








#### <a name="frameworks"Frameworks</a>

[angr](http://angr.io/)
* angr is a python framework for analyzing binaries. It focuses on both static and dynamic symbolic ("concolic") analysis, making it applicable to a variety of tasks.

Radare2 - unix-like reverse engineering framework and commandline tools ](http://www.radare.org/y/?p=features)
* Informally goal is to be best RE software framework
* [Github](https://github.com/radare/radare2)
* [Radare2 Book(free)](https://maijin.github.io/radare2book/index.html)
* [Radare2 Documentation](http://www.radare.org/y/?p=documentation)
* [ Reverse engineering embedded software using Radare2 - Talk/Tutorial](https://www.youtube.com/watch?v=R3sGlzXfEkU)
* [Notes and Demos for above video](https://github.com/pastcompute/lca2015-radare2-tutorial)

[BitBlaze](http://bitblaze.cs.berkeley.edu/)
* The BitBlaze project aims to design and develop a powerful binary analysis platform and employ the platform in order to (1) analyze and develop novel COTS protection and diagnostic mechanisms and (2) analyze, understand, and develop defenses against malicious code. The BitBlaze project also strives to open new application areas of binary analysis, which provides sound and effective solutions to applications beyond software security and malicious code defense, such as protocol reverse engineering and fingerprint generation. 

[Platform for Architecture-Neutral Dynamic Analysis](https://github.com/moyix/panda)

[BitBlaze](http://bitblaze.cs.berkeley.edu/)
* The BitBlaze project aims to design and develop a powerful binary analysis platform and employ the platform in order to (1) analyze and develop novel COTS protection and diagnostic mechanisms and (2) analyze, understand, and develop defenses against malicious code. The BitBlaze project also strives to open new application areas of binary analysis, which provides sound and effective solutions to applications beyond software security and malicious code defense, such as protocol reverse engineering and fingerprint generation. 

[BARF-Project](https://github.com/programa-stic/barf-project)
* BARF : A multiplatform open source Binary Analysis and Reverse engineering Framework 
* Presentation: Barfing Gadgets - Ekoparty 2014](https://github.com/programa-stic/barf-project/raw/master/documentation/presentations/barfing-gadgets.ekoparty2014.es.pdf)






#### <a name="dbg">Debuggers</a>

[OllyDbg](http://www.ollydbg.de/)
* OllyDbg is a 32-bit assembler level analysing debugger for Microsoft® Windows®. Emphasis on binary code analysis makes it particularly useful in cases where source is unavailable.
* [OllyDbg Tricks for Exploit Development](http://resources.infosecinstitute.com/in-depth-seh-exploit-writing-tutorial-using-ollydbg/)

[GDB - GNU Debugger](https://www.gnu.org/software/gdb/)
* GDB, the GNU Project debugger, allows you to see what is going on `inside' another program while it executes -- or what another program was doing at the moment it crashed. 

[PEDA](https://github.com/longld/peda)
* PEDA - Python Exploit Development Assistance for GDB 

[gdbgui](https://github.com/cs01/gdbgui)
* A modern, browser-based frontend to gdb (gnu debugger). Add breakpoints, view stack traces, and more in C, C++, Go, and Rust. Simply run gdbgui from the terminal and a new tab will open in your browser.

[GEF - GDB Enhanced Features](https://github.com/hugsy/gef)
* GEF is aimed to be used mostly by exploiters and reverse-engineers. It provides additional features to GDB using the Python API to assist during the process of dynamic analysis or exploit development.
* Why not PEDA?
* Yes!! Why not?! PEDA is a fantastic tool to do the same, but is only to be used for x86-32 or x86-64. On the other hand, GEF supports all the architecture supported by GDB (x86, ARM, MIPS, PowerPC, SPARC, and so on).
* [Docs](https://gef.readthedocs.org/en/latest/)

[WinDbg](https://msdn.microsoft.com/en-us/library/windows/hardware/ff551063%28v=vs.85%29.aspx)
*[Excellent Resource Site](http://www.windbg.org/)
*[Crash Dump Analysis Poster](http://www.dumpanalysis.org/CDAPoster.html)

* [Getting Started with WinDbg (User-Mode)](https://msdn.microsoft.com/en-us/library/windows/hardware/dn745911%28v=vs.85%29.aspx)
* [Getting Started with WinDbg (Kernel-Mode)](https://msdn.microsoft.com/en-us/library/windows/hardware/dn745912%28v=vs.85%29.aspx)

[WinAppDbg](http://winappdbg.sourceforge.net/)
* The WinAppDbg python module allows developers to quickly code instrumentation scripts in Python under a Windows environment.  It uses ctypes to wrap many Win32 API calls related to debugging, and provides a powerful abstraction layer to manipulate threads, libraries and processes, attach your script as a debugger, trace execution, hook API calls, handle events in your debugee and set breakpoints of different kinds (code, hardware and memory). Additionally it has no native code at all, making it easier to maintain or modify than other debuggers on Windows.  The intended audience are QA engineers and software security auditors wishing to test or fuzz Windows applications with quickly coded Python scripts. Several ready to use tools are shipped and can be used for this purposes.  Current features also include disassembling x86/x64 native code, debugging multiple processes simultaneously and produce a detailed log of application crashes, useful for fuzzing and automated testing.

[REhints MEX - WinDBG addons](https://github.com/REhints/WinDbg/tree/master/MEX)

[Open Source Windows x86/x64 Debugger](http://x64dbg.com/)

[xnippet](https://github.com/isislab/xnippet)
* xnippet is a tool that lets you load code snippets or isolated functions (no matter the operating system they came from), pass parameters to it in several formats (signed decimal, string, unsigned hexadecimal...), hook other functions called by the snippet and analyze the result. The tool is written in a way that will let me improve it in a future, defining new calling conventions and output argument pointers.

[HyperDbg](https://github.com/rmusser01/hyperdbg/)
* HyperDbg is a kernel debugger that leverages hardware-assisted virtualization. More precisely, HyperDbg is based on a minimalistic hypervisor that is installed while the system runs. Compared to traditional kernel debuggers (e.g., WinDbg, SoftIce, Rasta R0 Debugger) HyperDbg is completely transparent to the kernel and can be used to debug kernel code without the need of serial (or USB) cables. For example, HyperDbg allows to single step the execution of the kernel, even when the kernel is executing exception and interrupt handlers. Compared to traditional virtual machine based debuggers (e.g., the VMware builtin debugger), HyperDbg does not require the kernel to be run as a guest of a virtual machine, although it is as powerful. 
* [Paper](http://roberto.greyhats.it/pubs/ase10.pdf)

[Voltro](https://github.com/snare/voltron)
* Voltron is an extensible debugger UI toolkit written in Python. It aims to improve the user experience of various debuggers (LLDB, GDB, VDB and WinDbg) by enabling the attachment of utility views that can retrieve and display data from the debugger host. By running these views in other TTYs, you can build a customised debugger user interface to suit your needs.

[#Fldbg](https://github.com/offensive-security/fldbg)
* #Fldbg, a Pykd script to debug FlashPlayer



##### Debugging Writeups/Papers

[BugNet: Continuously Recording Program Execution for Deterministic Replay Debugging](https://cseweb.ucsd.edu/~calder/papers/ISCA-05-BugNet.pdf)

[Back to the Future: Omniscient Debugging](https://pleiad.cl/papers/2009/pothierTanter-software2009.pdf) 

[A REVIEW OF REVERSE DEBUGGING - Jakob Engblom (2012?)](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.338.3420&rep=rep1&type=pdf)

[Binary Hooking Problems](http://www.ragestorm.net/blogs/?p=348)









#### <a name="decom">Decompilers & Disassemblers</a>

[Procyon - Java Decompiler](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler)

[IDA](https://www.hex-rays.com/products/ida/)
* IDA Pro combines an interactive, programmable, multi-processor
disassembler coupled to a local and remote debugger and augmented by a complete plugin
programming environment.
* [Overview & Tutorials](https://www.hex-rays.com/products/ida/debugger/index.shtml)
* Ida Plugins
	* [Ida Sploiter](https://thesprawl.org/projects/ida-sploiter/)
	* IDA Sploiter is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool. Some of the plugin's features include a powerful ROP gadgets search engine, semantic gadget analysis and filtering, interactive ROP chain builder, stack pivot analysis, writable function pointer search, cyclic memory pattern generation and offset analysis, detection of bad characters and memory holes, and many others.
	* [Ida Pomidor](https://thesprawl.org/projects/ida-pomidor/)
	* IDA Pomidor is a fun and simple plugin for the Hex-Ray's IDA Pro disassembler that will help you retain concentration and productivity during long reversing sessions. 

[fREedom](capstone based disassembler for extracting to binnavi )
* fREedom is a primitive attempt to provide an IDA Pro independent means of extracting disassembly information from executables for use with binnavi (https://github.com/google/binnavi).

[Hopper](http://www.hopperapp.com/)
* Hopper is a reverse engineering tool for OS X and Linux, that lets you disassemble, decompile and debug your 32/64bits Intel Mac, Linux, Windows and iOS executables!

[Reverse](https://github.com/joelpx/reverse)
* Reverse engineering for x86 binaries (elf-format). Generate a more readable code (pseudo-C) with colored syntax. Warning, the project is still in development, use it at your own risks. This tool will try to disassemble one function (by default main). The address of the function, or its symbol, can be passed by argument.




##### IDA specific Stuff

[BAP-IDA](https://github.com/BinaryAnalysisPlatform/bap-ida-python)
* This package provides the necessary IDAPython scripts required for interoperatibility between BAP and IDA Pro. It also provides many useful feature additions to IDA, by leveraging power from BAP.

[Kam1n0-Plugin-IDA-Pro](https://github.com/McGill-DMaS/Kam1n0-Plugin-IDA-Pro)
* Kam1n0 is a scalable system that supports assembly code clone search. It allows a user to first index a (large) collection of binaries, and then search for the code clones of a given target function or binary file. Kam1n0 tries to solve the efficient subgraph search problem (i.e. graph isomorphism problem) for assembly functions. Given a target function (the middle one in the figure below) it can identity the cloned subgraphs among other functions in the repository (the ones on the left and the right as shown below). Kam1n0 supports rich comment format and has an IDA Pro plug-in to use its indexing and searching capabilities via IDA Pro. 

[FLARE-Ida](https://github.com/fireeye/flare-ida)
* This repository contains a collection of IDA Pro scripts and plugins used by the FireEye Labs Advanced Reverse Engineering (FLARE) team.

[TiGa's Video Tutorial Series on IDA Pro](http://woodmann.com/TiGa/idaseries.html)

[IDA PLUG-IN WRITING IN C/C++](http://www.binarypool.com/idapluginwriting/idapw.pdf)

[toolbag](https://github.com/aaronportnoy/toolbag)
 * The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler. 

[A list of IDA Plugins](https://github.com/onethawt/idaplugins-list)

[Dynamic IDA Enrichment (aka. DIE)](https://github.com/ynvb/DIE)
* DIE is an IDA python plugin designed to enrich IDA`s static analysis with dynamic data. This is done using the IDA Debugger API, by placing breakpoints in key locations and saving the current system context once those breakpoints are hit.

[virusbattle-ida-plugin](https://github.com/moghimi/virusbattle-ida-plugin)
* The plugin is an integration of Virus Battle API to the well known IDA Disassembler. Virusbattle is a web service that analyses malware and other binaries with a variety of advanced static and dynamic analyses.

[HexRaysCodeXplorer](https://github.com/REhints/HexRaysCodeXplorer)
* Hex-Rays Decompiler plugin for better code navigation in RE process of C++ applications or code reconstruction of modern malware as Stuxnet, Flame, Equation

[NRS](https://github.com/isra17/nrs)
* NRS is a set of Python librairies used to unpack and analysis NSIS installer's data. It also feature an IDA plugin used to disassembly the NSIS Script of an installer











#### <a name="ct">Comparison Tools</a>s

[binwally](https://github.com/bmaia/binwally)
* Binary and Directory tree comparison tool using the Fuzzy Hashing concept (ssdeep)
* [Using binwally - a directory tree diff tool](http://w00tsec.blogspot.com/2013/12/binwally-directory-tree-diff-tool-using.html)














#### <a name="lt">Linux Specific Tools</a>

[readelf](https://sourceware.org/binutils/docs/binutils/readelf.html)
* Unix Tool

[Rdis](https://github.com/endeav0r/rdis)
* Rdis is a Binary Analysis Tool for Linux.

[Statically Linked Library Detector](https://github.com/arvinddoraiswamy/slid)










#### <a name="wt">Windows Specific Tools</a>

[PEview](http://wjradburn.com/software/)
* PEview provides a quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files. This PE/COFF file viewer displays header, section, directory, import table, export table, and resource information within EXE, DLL, OBJ, LIB, DBG, and other file types.


[SpyStudio](http://www.nektra.com/products/spystudio-api-monitor/)
* SpyStudio shows and interprets calls, displaying the results in a structured way which is easy for any IT professional to understand. SpyStudio can show registry keys and files that an application uses, COM objects and Windows the application has created, and errors and exceptions.

[PEStudio](http://www.winitor.com/)
* pestudio is a tool that performs the static analysis of 32-bit and 64-bit Windows executable files.  Malicious executable attempts to hide its malicious intents and to evade detection. In doing so, it generally presents anomalies and suspicious patterns. The goal of pestudio is to detect these anomalies, provide indicators and score the executable being analyzed. Since the executable file being analyzed is never started, you can inspect any unknown or malicious executable with no risk. 

[DotPeek](http://www.jetbrains.com/decompiler/features/)
* dotPeek is a .NET decompiler that has several handy features. I haven’t used it much, and don’t do much in .NET so I can’t say if its a good one, only that I’ve had success in using it.

[API Monitor](http://www.rohitab.com/apimonitor)
* API Monitor is a free software that lets you monitor and control API calls made by applications and services. Its a powerful tool for seeing how applications and services work or for tracking down problems that you have in your own applications.

[Microsoft Message Analyzer])http://www.microsoft.com/en-us/download/details.aspx?id=40308)
* Microsoft Message Analyzer is a new tool for capturing, displaying, and analyzing protocol messaging traffic and other system messages. Message Analyzer also enables you to import, aggregate, and analyze data from log and trace files. It is the successor to Microsoft Network Monitor 3.4 and a key component in the Protocol Engineering Framework (PEF) that was created by Microsoft for the improvement of protocol design, development, documentation, testing, and support. With Message Analyzer, you can choose to capture data live or load archived message collections from multiple data sources simultaneously.





#### <a name="pl">Programming Libraries</a>


[openreil](https://github.com/Cr4sh/openreil)
* Open source library that implements translator and tools for REIL (Reverse Engineering Intermediate Language)]


[PortEx](https://github.com/katjahahn/PortEx)
* PortEx is a Java library for static malware analysis of Portable Executable files. Its focus is on PE malformation robustness, and anomaly detection. PortEx is written in Java and Scala, and targeted at Java applications.

[Equip: python bytecode instrumentation](https://github.com/neuroo/equip)
* equip is a small library that helps with Python bytecode instrumentation. Its API is designed to be small and flexible to enable a wide range of possible instrumentations. The instrumentation is designed around the injection of bytecode inside the bytecode of the program to be instrumented. However, the developer does not need to know anything about the Python bytecode since the injected code is Python source.


[Medusa](https://github.com/wisk/medusa)
* Medusa is a disassembler designed to be both modular and interactive. It runs on Windows and Linux, it should be the same on OSX. This project is organized as a library. To disassemble a file you have to use medusa_dummy or qMedusa. wxMedusa and pydusa are not available anymore.
[IDA Python - Ero Carrera](http://www.offensivecomputing.net/papers/IDAPythonIntro.pdf)
* IDAPython is an extension for IDA , the Interactive Disassembler . It brings the power and convenience of Python scripting to aid in the analysis of binaries. This article will cover some basic usage and provide examples to get interested individuals started. W e will walk through practical examples ranging from iterating through functions, segments and instructions to data mining the binaries, collecting references and analyzing their structure.











### <a name="are">Anti-Reverse Engineering Techniques & Countermeasures</a>

[Anti-RE A collection of Anti-Reverse Engineering Techniques](http://pnx.tf/files/spring7_antire_plohmann_kannen.pdf)

[simpliFiRE.AntiRE - An Executable Collection of Anti-Reversing Techniques](https://bitbucket.org/fkie_cd_dare/simplifire.antire)
* AntiRE is a collection of such anti analysis approaches, gathered from various sources like Peter Ferrie's The "Ultimate" Anti-Debugging Reference and Ange Albertini's corkami. While these techniques by themselves are nothing new, we believe that the integration of these tests in a single, executable file provides a comprehensive overview on these, suitable for directly studying their behaviour in a harmless context without additional efforts. AntiRE includes different techniques to detect or circumvent debuggers, fool execution tracing, and disable memory dumping. Furthermore, it can detect the presence of different virtualization environments and gives examples of techniques used to twarth static analysis.

[Anti Reverse Engineering](http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide)
	
[ALPHA3[(https://code.google.com/p/alpha3/)
* ALPHA3 is a tool for transforming any x86 machine code into 100% alphanumeric code with similar functionality. It works by encoding the original code into alphanumeric data and combining this data with a decoder, which is a piece of x86 machine code written specifically to be 100% alphanumeric. When run, the decoder converts the data back to the original code, after which it is executed.


[OpenRCE Anti Reverse Engineering Techniques Database](http://www.openrce.org/reference_library/anti_reversing)

[Windows Anti-Debugging Reference](http://www.symantec.com/connect/articles/windows-anti-debug-reference)
* This paper classifies and presents several anti-debugging techniques used on Windows NT-based operating systems. Anti-debugging techniques are ways for a program to detect if it runs under control of a debugger. They are used by commercial executable protectors, packers and malicious software, to prevent or slow-down the process of reverse-engineering. We'll suppose the program is analyzed under a ring3 debugger, such as OllyDbg on Windows platforms. The paper is aimed towards reverse-engineers and malware analysts. Note that we will talk purely about generic anti-debugging and anti-tracing techniques. Specific debugger detection, such as window or processes enumeration, registry scanning, etc. will not be addressed here

[Android Reverse Engineering Defenses](https://bluebox.com/wp-content/uploads/2013/05/AndroidREnDefenses201305.pdf)







### <a name="guide">Guides & Tutorials</a>
[How to RE data files?](https://www.reddit.com/r/ReverseEngineering/comments/l8ac0/how_to_re_data_files/)
* Good read over.

[Reversing Monkey](http://cheeky4n6monkey.blogspot.com/2015/02/reversing-monkey.html?m=1)
* When trying to recover/carve deleted data, some reverse engineering of the file format may be required. Without knowing how the data is stored, we cannot recover the data of interest - be it timestamps, messages, images, video or another type of data. This quick blog post is intended to give some basic tips that have been observed during monkey's latest travels into reverse engineering of file formats. It was done partly as a memory aid/thinking exercise but hopefully other monkeys will find it useful. This post assumes there's no obfuscation/encryption applied to the file and it does not cover reverse engineering malware exes (which is another kettle of bananas).  - Great post/write-up

[Microsoft Patch Analysis for Exploitation](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t111-microsoft-patch-analysis-for-exploitation-stephen-sims)
* Since the early 2000's Microsoft has distributed patches on the second Tuesday of each month. Bad guys, good guys, and many in-between compare the newly released patches to the unpatched version of the files to identify the security fixes. Many organizations take weeks to patch and the faster someone can reverse engineer the patches and get a working exploit written, the more valuable it is as an attack vector. Analysis also allows a researcher to identify common ways that Microsoft fixes bugs which can be used to find 0-days. Microsoft has recently moved to mandatory cumulative patches which introduces complexity in extracting patches for analysis. Join me in this presentation while I demonstrate the analysis of various patches and exploits, as well as the best-known method for modern patch extraction.













### <a name="hre">Hardware Reverse Engineering</a>
[Apple Lightning Reverse Engineered](http://ramtin-amin.fr/#tristar)

[Reverse Engineering Intels Management Engine](http://recon.cx/2014/slides/Recon%202014%20Skochinsky.pdf) 
* On every intel chip core2duo and newer

[ChipWhisperer](http://www.newae.com/chipwhisperer)
* ChipWhisperer is the first ever open-source solution that provides a complete toolchain for research and analysis of embedded hardware security. Side Channel Power Analysis, Clock Glitching, VCC Glitching, and more are all possible with this unique tool.

Hacking the Dropcam series
* [Part 1 - Dropcam Comms](http://blog.includesecurity.com/2014/03/Reverse-Engineering-Dropcam-Communications.html)
* [Part 2 - Rooting the Dropcam](http://blog.includesecurity.com/2014/04/reverse-engineering-dropcam-rooting-the-device.html)
* [Part 3 - Dropcam Lua Bytecode](http://blog.includesecurity.com/2014/08/Reverse-Engineering-Dropcam-Lua-Bytecode.html)

[Hardware reverse engineering tools (Olivier Thomas)  - REcon 2013](https://www.youtube.com/watch?v=o77GTR8RovM)

[Reverse Engineering: Reverse Engineering Flash Memory for Fun and Benefit - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)










### <a name="pa">Protocol Analysis & Related</a>
[Netzob](http://www.netzob.org/)
* Originaly, the development of Netzob has been initiated to support security auditors and evaluators in their activities of modeling and simulating undocumented protocols. The tool has then been extended to allow smart fuzzing of unknown protocol. 
* [Netzob Documentation](http://netzob.readthedocs.org/en/latest/overview/index.html)
 





### <a name="writeups">Writeups</a>
[Reverse engineering radio weather station](http://blog.atx.name/reverse-engineering-radio-weather-station/)
[Introduction to Reverse Engineering Win32 Applications](http://uninformed.org/?v=all&a=7&t=sumry)
* During the course of this paper the reader will be (re)introduced to many concepts and tools essential to understanding and controlling native Win32 applications through the eyes of Windows Debugger (WinDBG). Throughout, WinMine will be utilized as a vehicle to deliver and demonstrate the functionality provided by WinDBG and how this functionality can be harnessed to aid the reader in reverse engineering native Win32 applications. Topics covered include an introductory look at IA-32 assembly, register significance, memory protection, stack usage, various WinDBG commands, call stacks, endianness, and portions of the Windows API. Knowledge gleaned will be used to develop an application designed to reveal and/or remove bombs from the WinMine playing grid. 

[Somfy Smoove Origin RTS Protocol](https://pushstack.wordpress.com/somfy-rts-protocol/)
* This document describes the Somfy RTS protocol as used by the “Somfy Smoove Origin RTS”. Most information in this document is based on passive observation of the data send by the Smoove Origin RTS remote, and thus can be inaccurate or incorrect!

[ Reverse Engineering The eQSO Protocol](https://gist.github.com/anonymous/7a9d713e61ba990a3a17)
* Today I reverse engineered the eQSO protocol. If you didn't know, eQSO is a small program that allows radio amateurs to talk to each other online. Sadly this program isn't as popular as it used to be (Well, neither is the radio).

[You can ring my bell! Adventures in sub-GHz RF land…](http://adamsblog.aperturelabs.com/2013/03/you-can-ring-my-bell-adventures-in-sub.html)

[Reverse Engineering Windows AFD.sys](https://recon.cx/2015/slides/recon2015-20-steven-vittitoe-Reverse-Engineering-Windows-AFD-sys.pdf)


[Reverse engineering walk thrrouhg; guy rev eng alarm system from shelf to replay]()
https://www.reddit.com/r/ReverseEngineering/comments/1hb7oy/a_series_about_basics_of_hardware_reverse/)
* [Part 1:](http://cybergibbons.com/uncategorized/)reverse-engineering-a-wireless-burglar-alarm-system-part-1/

* [Part 2:](http://cybergibbons.com/uncategorized/)reverse-engineering-a-wireless-burglar-alarm-part-2/)

* [Part 3:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-3/)

* [Part 4:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-4/)

* [Part 5:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-5/)

* [Part 6:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-6/)

* [Part 7:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-7/)

* [Part 8:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-8/)

* [Blackbox Reversing an Electric Skateboard Wireless Protocol ](https://blog.lacklustre.net/posts/Blackbox_Reversing_an_Electric_Skateboard_Wireless_Protocol/)

[The Empire Strikes Back Apple – how your Mac firmware security is completely broken](https://reverse.put.as/2015/05/29/the-empire-strikes-back-apple-how-your-mac-firmware-security-is-completely-broken/)

[A Brief Examination of Hacking Team’s Crypter: core-packer.](http://ethanheilman.tumblr.com/post/128708937890/a-brief-examination-of-hacking-teams-crypter)

[Blackbox Reversing an Electric Skateboard Wireless Protocol ](https://blog.lacklustre.net/posts/Blackbox_Reversing_an_Electric_Skateboard_Wireless_Protocol/)

[Getting access to your own Fitbit data](https://www.cs.ru.nl/bachelorscripties/2016/Maarten_Schellevis___4142616___Getting_access_to_your_own_Fitbit_data.pdf)
* his study investigates the possibility of getting direct access to one’s own data, as recorded by a Fitbit Charge HR activity tracker, without going through the Fitbit servers. We captured the firmware image of the Fitbit Charge HR during a firmware update. By analyzing this firmware image we were able to reverse-engineer the cryptographic primitives used by the Fitbit Charge HR activity tracker and recover the authentication  protocol. We obtained the cryptographic key that is used in the authentication protocol from the Fitbit Android application. We located a backdoor in version 18.102 of the firmware by comparing it with the latest version of the firmware (18.122). In the latest version of the firmware the backdoor was removed. This backdoor was used to extract the device specific encryption key from the memory of the tracker. While we have not implemented this last step in practice, the device specific encryption key can be used by a Fitbit Charge HR user to obtain his/her fitness data directly from the device.

[Make Confide great again? No, we cannot](http://blog.quarkslab.com/make-confide-great-again-no-we-cannot.html)
* RE'ing an electron based "secure communications" app

[Reverse Engineering a 433MHz Motorised Blind RF Protocol](https://nickwhyte.com/post/2017/reversing-433mhz-raex-motorised-rf-blinds/)

[IDAnt-wanna](https://github.com/strazzere/IDAnt-wanna)
* ELF header abuse


### <a name="talks">Talks & Videos</a>
[The Three Billion Dollar App - Vladimir Wolstencroft -Troopers14](https://www.youtube.com/watch?v=5Duc-uUFzoU)
* Talk about reverse engineering SnapChat and Wickr Messaging apps.

[Cyber Necromancy - Reverse engineering dead protocols - Defcamp 2014 ](https://www.youtube.com/watch?v=G0v2FO2Ru0w&index=6&list=PLnwq8gv9MEKgSryzYIFhpmCcqnVzdUWfH)

[Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it’s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What’s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."

[Reverse Engineering Flash Memory for Fun and Benefit - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)

[SATCOM Terminals Hacking by Air, Sea, and Land - Black Hat USA 2014](https://www.youtube.com/watch?v=tRHDuT__GoM)

[Advanced PDF Tricks - Ange Albertini, Kurt Pfeifle - Troopers1](https://www.youtube.com/watch?v=k9g9jZdjRcE)
* This session is NOT about analyzing exploits but about learning to manipulate PDF contents. Among others:hide/reveal information; remove/add watermark;  just suck less about the format. It's an extended session (2 hours) to leave the audience time to try by themselves actively. The slides' PDF is entirely hand-written to explain clearly each fact, so the presentation slides themselves will be the study materials.

[The Best Campfire Tales that Reverse Engineers Tell - Travis Goodspeed with Sergey Bratus](https://www.youtube.com/watch?v=l39OVRDvN9w)

















### <a name="papers">Papers</a>

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

[Inside Blizzard: Battle.net](http://uninformed.org/?v=all&a=8&t=sumry)
* This paper intends to describe a variety of the problems Blizzard Entertainment has encountered from a practical standpoint through their implementation of the large-scale online game matchmaking and chat service, Battle.net. The paper provides some background historical information into the design and purpose of Battle.net and continues on to discuss a variety of flaws that have been observed in the implementation of the system. Readers should come away with a better understanding of problems that can be easily introduced in designing a matchmaking/chat system to operate on such a large scale in addition to some of the serious security-related consequences of not performing proper parameter validation of untrusted clients. 

[Paper on Manual unpacking of UPX packed executable using Ollydbg and Importrec](http://www.iosrjournals.org/iosr-jce/papers/Vol16-issue1/Version-1/L016117177.pdf)

[Memalyze: Dynamic Analysis of Memory Access Behavior in Software](http://uninformed.org/?v=all&a=31&t=sumry)
* This paper describes strategies for dynamically analyzing an application's memory access behavior. These strategies make it possible to detect when a read or write is about to occur at a given location in memory while an application is executing. An application's memory access behavior can provide additional insight into its behavior. For example, it may be able to provide an idea of how data propagates throughout the address space. Three individual strategies which can be used to intercept memory accesses are described in this paper. Each strategy makes use of a unique method of intercepting memory accesses. These methods include the use of Dynamic Binary Instrumentation (DBI), x86 hardware paging features, and x86 segmentation features. A detailed description of the design and implementation of these strategies for 32-bit versions of Windows is given. Potential uses for these analysis techniques are described in detail. 

[An Objective Analysis of the Lockdown Protection System for Battle.net](http://uninformed.org/?v=all&a=40&t=sumry)
* Near the end of 2006, Blizzard deployed the first major update to the version check and client software authentication system used to verify the authenticity of clients connecting to Battle.net using the binary game client protocol. This system had been in use since just after the release of the original Diablo game and the public launch of Battle.net. The new authentication module (Lockdown) introduced a variety of mechanisms designed to raise the bar with respect to spoofing a game client when logging on to Battle.net. In addition, the new authentication module also introduced run-time integrity checks of client binaries in memory. This is meant to provide simple detection of many client modifications (often labeled "hacks") that patch game code in-memory in order to modify game behavior. The Lockdown authentication module also introduced some anti-debugging techniques that are designed to make it more difficult to reverse engineer the module. In addition, several checks that are designed to make it difficult to simply load and run the Blizzard Lockdown module from the context of an unauthorized, non-Blizzard-game process. After all, if an attacker can simply load and run the Lockdown module in his or her own process, it becomes trivially easy to spoof the game client logon process, or to allow a modified game client to log on to Battle.net successfully. However, like any protection mechanism, the new Lockdown module is not without its flaws, some of which are discussed in detail in this paper.

[Improving Automated Analysis of Windows x64 Binaries](http://uninformed.org/?v=all&a=18&t=sumry)
* As Windows x64 becomes a more prominent platform, it will become necessary to develop techniques that improve the binary analysis process. In particular, automated techniques that can be performed prior to doing code or data flow analysis can be useful in getting a better understanding for how a binary operates. To that point, this paper gives a brief explanation of some of the changes that have been made to support Windows x64 binaries. From there, a few basic techniques are illustrated that can be used to improve the process of identifying functions, annotating their stack frames, and describing their exception handler relationships. Source code to an example IDA plugin is also included that shows how these techniques can be implemented. 

[Reverse Engineering Mac OS X](http://reverse.put.as/papers/)
* Excellent source of papers from 2003-2013 all with a focus on reversing either iOS or OS X.

[A Practical-Time Attack on the A5/3 Cryptosystem Used in Third Generation GSM Telephony](https://eprint.iacr.org/2010/013)
* Abstract: The privacy of most GSM phone conversations is currently protected by the 20+ years old A5/1 and A5/2 stream ciphers, which were repeatedly shown to be cryptographically weak. They will soon be replaced in third generation networks by a new A5/3 block cipher called KASUMI, which is a modified version of the MISTY cryptosystem. In this paper we describe a new type of attack called a sandwich attack, and use it to construct a simple distinguisher for 7 of the 8 rounds of KASUMI with an amazingly high probability of $2^{ -14}$. By using this distinguisher and analyzing the single remaining round, we can derive the complete 128 bit key of the full KASUMI by using only 4 related keys, $2^{26}$ data, $2^{30}$ bytes of memory, and $2^{32}$ time. These complexities are so small that we have actually simulated the attack in less than two hours on a single PC, and experimentally verified its correctness and complexity. Interestingly, neither our technique nor any other published attack can break MISTY in less than the $2^{128}$ complexity of exhaustive search, which indicates that the changes made by the GSM Association in moving from MISTY to KASUMI resulted in a much weaker cryptosystem.

[How to Grow a TREE from CBASS - Interactive Binary Analysis for  Security Professionals](https://media.blackhat.com/us-13/US-13-Li-How-to-Grow-a-TREE-Slides.pdf)






### <a name="wikis">Wikis & Useful Sites</a>
[FCC ID Lookup](http://transition.fcc.gov/oet/ea/fccid/)
* Lookup devices according to FCC ID

[x86 opcode structure and instruction overview](http://pnx.tf/files/x86_opcode_structure_and_instruction_overview.pdf)





*
