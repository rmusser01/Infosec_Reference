# Reverse Engineering

## Table of Contents
* [Frameworks](#frameworks)
* [Debuggers & Related Techniques](#dbg)
* [Decompilers](#decom)
* [Comparison Tools](#ct)
* [Tools](#tools)
	* [Linux Specific Tools](#lt)
	* [Windows Specific Tools](#wt)
	* [Programming Libraries](#pl)
* [Anti-Reverse Engineering & Countermeasure](#ar)
* [Guides & Tutorials](#guides)
* [Hardware Reverse Engineering](#hre)
* [Protocol Analysis](#pa)
* [Write-ups](#writeups)
* [Talks & Videos](#talks)
* [Papers](#papers)
* [Wikis & Useful Sites](#wikis)

http://ropgadget.com/posts/pebwalk.html


https://github.com/TakahiroHaruyama/ida_haru/tree/master/bindiff

https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/
http://kakaroto.homelinux.net/2017/11/introduction-to-reverse-engineering-and-assembly/
https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/june/advanced-frida-witchcraft-turning-an-android-application-into-a-voodoo-doll/
* [Using WPP and TraceLoggingTracing to Facilitate Dynamic and Static Windows RE - Matt Graeber](https://drive.google.com/file/d/1wtQXVdvJmhG7ba99pq3BZq_Fyf6E3F71/view)

RE
https://fkie-cad.github.io/FACT_core/
https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool
https://dyninst.org/
https://drmemory.org/strace_for_windows.html
https://www.frida.re/
http://dynamorio.org/
https://arxiv.org/pdf/1901.01161.pdf

* https://github.com/JusticeRage/Manalyze
* https://bordplate.no/blog/en/post/debugging-a-windows-service/
https://doc.dustri.org/reverse/Brian%20Pak%20-%20Effective%20Patch%20Analysis%20for%20Microsoft%20Updates%20-%20Power%20of%20Community%20-%202016.11.pdf

* [How to break PDF Signatures](https://www.pdf-insecurity.org/)
	* [Technical Writeup](https://www.pdf-insecurity.org/signature/signature.html)
* **ToDo**
	* A proper ToC
	* Sort bottom section
https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/
https://ezequieltbh.me/posts/2019/05/love-is-in-the-air-reverse-engineering-a-shitty-drone/
* [Advanced Portable Executable File Analyzer](https://github.com/blacknbunny/peanalyzer)
	* Advanced Portable Executable File Analyzer And Disassembler 32 & 64 Bit

* [Debugging with Symbols - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/DxTechArts/debugging-with-symbols)
https://secrary.com/Random/unexported/

PDF
http://joxeankoret.com/blog/2010/02/21/analyzing-pdf-exploits-with-pyew/
https://blog.didierstevens.com/2008/10/30/pdf-parserpy/
http://blog.9bplus.com/
http://blog.9bplus.com/scoring-pdfs-based-on-malicious-filter/
http://honeynet.org/node/1304
https://itsjack.cc/blog/2017/08/analysingdetecting-malicious-pdfs-primer/
https://securityoversimplicity.wordpress.com/2017/09/28/not-all-she-wrote-part-1-rigged-pdfs/
https://digital-forensics.sans.org/blog/2009/12/14/pdf-malware-analysis/
https://blog.didierstevens.com/programs/pdf-tools/
https://blog.didierstevens.com/2009/03/31/pdfid/
https://www.cs.unm.edu/~eschulte/data/bed.pdf

--------------
### General
* **101**
	* [Reverse Engineering - Wikipedia](https://en.wikipedia.org/wiki/Reverse_engineering)
	* [High Level view of what Reverse Engineering is](http://www.program-transformation.org/Transform/DecompilationAndReverseEngineering)
	* [What is Reverse Engineering?](http://www.program-transformation.org/Transform/DecompilationAndReverseEngineering)
* **Articles/Blogposts**
	* [Starting from Scratch?](http://www.reddit.com/r/ReverseEngineering/comments/smf4u/reverser_wanting_to_develop_mathematically/)
* **Educational**
	* [Reverse Engineering Reference Manual (beta)](https://github.com/yellowbyte/reverse-engineering-reference-manual)
		*  collage of reverse engineering topics that I find interesting - yellowbyte
	* [Introduction to Reverse Engineering Software - Dartmouth](http://althing.cs.dartmouth.edu/local/www.acm.uiuc.edu/sigmil/RevEng/)
	* [CSCI 4974 / 6974 Hardware Reverse Engineering](http://security.cs.rpi.edu/courses/hwre-spring2014/)
	* [Introduction to Reverse Engineering Software](http://althing.cs.dartmouth.edu/local/www.acm.uiuc.edu/sigmil/RevEng/)
		* This book is an attempt to provide an introduction to reverse engineering software under both Linux and Microsoft Windows©. Since reverse engineering is under legal fire, the authors figure the best response is to make the knowledge widespread. The idea is that since discussing specific reverse engineering feats is now illegal in many cases, we should then discuss general approaches, so that it is within every motivated user's ability to obtain information locked inside the black box. Furthermore, interoperability issues with closed-source proprietary systems are just plain annoying, and something needs to be done to educate more open source developers as to how to implement this functionality in their software. 
	* [Reverse History Part Two – Research](http://jakob.engbloms.se/archives/1554)
	* [mammon_'s tales to his grandson](https://mammon.github.io/tales/)
	* [Reversing Prince Harming’s Kiss of Death]( https://reverse.put.as/2015/07/01/reversing-prince-harmings-kiss-of-death/)
	* [Jailbreaks and Pirate Tractors: Reverse Engineering Do’s and Don’ts](https://www.youtube.com/watch?v=8_mMTVsOM6Y)
* **Timelines**
	* [Symbolic execution timeline](https://github.com/enzet/symbolic-execution)
		* Diagram highlights some major tools and ideas of pure symbolic execution, dynamic symbolic execution (concolic) as well as related ideas of model checking, SAT/SMT solving, black-box fuzzing, taint data tracking, and other dynamic analysis techniques.
* **Videos**
	* [The Best Campfire Tales that Reverse Engineers Tell - Travis Goodspeed with Sergey Bratus](https://www.youtube.com/watch?v=l39OVRDvN9w)
	* [Jailbreaks and Pirate Tractors: Reverse Engineering Do’s and Don’ts](https://www.youtube.com/watch?v=8_mMTVsOM6Y)
	* [Introduction to Reversing and Pwning - David Weinman - BsidesLV ProvingGrounds17](https://www.youtube.com/watch?v=4rjWlOvbz7U&app=desktop)
* **Things that Don't fit elsewhere**
	* **Code Tools**
		* [SyntaxHighlighter](http://alexgorbatchev.com/SyntaxHighlighter/)
			* SyntaxHighlighter is a fully functional self-contained code syntax highlighter developed in JavaScript. To get an idea of what SyntaxHighlighter is capable of, have a look at the demo page.
		* [linguist](https://github.com/github/linguist)
			* Language Savant. If your repository's language is being reported incorrectly, send us a pull request!
		* [Ohcount - Ohloh's source code line counter.](https://github.com/blackducksoftware/ohcount)
		* [Detecting programming language from a snippet](https://stackoverflow.com/questions/475033/detecting-programming-language-from-a-snippet)
	* **Comparison Tools**
		* [binwally](https://github.com/bmaia/binwally)
			* Binary and Directory tree comparison tool using the Fuzzy Hashing concept (ssdeep)
		* [Using binwally - a directory tree diff tool](http://w00tsec.blogspot.com/2013/12/binwally-directory-tree-diff-tool-using.html)
		* [Diaphora](https://github.com/joxeankoret/diaphora)
			* Diaphora (`διαφορά`, Greek for 'difference') is a program diffing plugin for IDA Pro and Radare2, similar to Zynamics Bindiff or the FOSS counterparts DarunGrim, TurboDiff, etc... It was released during SyScan 2015. It works with IDA Pro 6.9, 6.95 and 7.0. In batch mode, it supports Radare2 too (check this fork). In the future, adding support for Binary Ninja is also planned.
	* **References**
		* [FCC ID Lookup](http://transition.fcc.gov/oet/ea/fccid/)
			* Lookup devices according to FCC ID
		* [x86 opcode structure and instruction overview](http://pnx.tf/files/x86_opcode_structure_and_instruction_overview.pdf)
		* [ARMwiki - hehyrick.co.uk](https://www.heyrick.co.uk/armwiki/Category:Introduction)
			* ARM processor wiki
* **General Research/Stuff**
	* [TAMPER (Tamper And Monitoring Protection Engineering Research)](http://www.cl.cam.ac.uk/research/security/tamper/)
		* In the TAMPER Lab, we study existing security products, document how they have been penetrated in the past, develop new attack techniques, and try to forecast how newly available technologies will make it easier to bypass hardware security mechanisms. We then develop and evaluate new countermeasures and assist industrial designers in staying ahead of the game, most of all by giving them an advanced understanding of which attack techniques are most dangerous. We are especially interested in protection systems for mass-market applications, and in forensic applications. 
* **General Tools**<a name="tools"></a>
	* **Binary Visualization Tools**
		* [binglide](https://github.com/wapiflapi/binglide)
			* binglide is a visual reverse engineering tool. It is designed to offer a quick overview of the different data types that are present in a file. This tool does not know about any particular file format, everything is done using the same analysis working on the data. This means it works even if headers are missing or corrupted or if the file format is unknown.
		* [binvis.io](http://binvis.io/#/)
			* visual analysis of binary files
		* [cantor.dust](https://sites.google.com/site/xxcantorxdustxx/home)
			* a powerful, dynamic, interactive binary visualization tool
	* **General**
		* [Binwalk](https://github.com/devttys0/binwalk)
			* Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
		* [Pip3line, the Swiss army knife of byte manipulation](https://nccgroup.github.io/pip3line/index.html) 
			* Pip3line is a raw bytes manipulation utility, able to apply well known and less well known transformations from anywhere to anywhere (almost).
		* [Frida](http://www.frida.re/docs/home/)
			* Inject JS into native apps
		* [Binacle](https://github.com/ANSSI-FR/Binacle)
			* Indexation "full-bin" of binary files
		* [Construct2](https://github.com/construct/construct)
			* Construct is a powerful declarative parser (and builder) for binary data. Instead of writing imperative code to parse a piece of data, you declaratively define a data structure that describes your data. As this data structure is not code, you can use it in one direction to parse data into Pythonic objects, and in the other direction, convert ("build") objects into binary data.
	* **De/Obfuscators/Unpackers**
		* [de4dot](https://github.com/0xd4d/de4dot)
			* de4dot is an open source (GPLv3) .NET deobfuscator and unpacker written in C#. It will try its best to restore a packed and obfuscated assembly to almost the original assembly. Most of the obfuscation can be completely restored (eg. string encryption), but symbol renaming is impossible to restore since the original names aren't (usually) part of the obfuscated assembly.
		* [Universal Extractor](http://www.legroom.net/software/uniextract)
			* Universal Extractor is a program designed to decompress and extract files from any type of archive or installer, such as ZIP or RAR files, self-extracting EXE files, application installers, etc
		* [Stunnix C/C++ Obfuscator](http://stunnix.com/prod/cxxo/)
		* [asar](https://github.com/electron/asar)
			* Simple extensive tar-like archive format with indexing
	* **ELF/Related Tools**
		* [Rdis](https://github.com/endeav0r/rdis)
			* Rdis is a Binary Analysis Tool for Linux.
		* [readelf](https://sourceware.org/binutils/docs/binutils/readelf.html)
			* Unix Tool
	* **Emulators**
		* [Unicorn-Engine](http://www.unicorn-engine.org/)
			* Unicorn is a lightweight multi-platform, multi-architecture CPU emulator framework.
		* [pegasus - Windbg extension DLL for emulation](https://github.com/0a777h/pegasus)
			* Windbg emulation plugin 
	* **Packers**
		* [UPX - the Ultimate Packer for eXecutables](https://github.com/upx/upx)
			* UPX is an advanced executable file compressor. UPX will typically reduce the file size of programs and DLLs by around 50%-70%, thus reducing disk space, network load times, download times and other distribution and storage costs.
	* **PE32/Related Tools**
		* [Dependency Walker](http://www.dependencywalker.com/)
			* Dependency Walker is a free utility that scans any 32-bit or 64-bit Windows module (exe, dll, ocx, sys, etc.) and builds a hierarchical tree diagram of all dependent modules. For each module found, it lists all the functions that are exported by that module, and which of those functions are actually being called by other modules. Another view displays the minimum set of required files, along with detailed information about each file including a full path to the file, base address, version numbers, machine type, debug information, and more.
		* [PPEE(puppy)](https://www.mzrst.com/#top)
			* Professional PE file Explorer for reversers, malware researchers and those who want to statically inspect PE files in more details. Free and fast.
		* [PEStudio](http://www.winitor.com/)
			* pestudio is a tool that performs the static analysis of 32-bit and 64-bit Windows executable files.  Malicious executable attempts to hide its malicious intents and to evade detection. In doing so, it generally presents anomalies and suspicious patterns. The goal of pestudio is to detect these anomalies, provide indicators and score the executable being analyzed. Since the executable file being analyzed is never started, you can inspect any unknown or malicious executable with no risk. 
		* [PEview](http://wjradburn.com/software/)
			* PEview provides a quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files. This PE/COFF file viewer displays header, section, directory, import table, export table, and resource information within EXE, DLL, OBJ, LIB, DBG, and other file types.
	* **OLE**
		* [python-oletools](https://github.com/decalage2/oletools)
			* python-oletools is a package of python tools to analyze Microsoft OLE2 files (also called Structured Storage, Compound File Binary Format or Compound Document File Format), such as Microsoft Office documents or Outlook messages, mainly for malware analysis, forensics and debugging. It is based on the olefile parser. See http://www.decalage.info/python/oletools for more info.
	* **Searching Through Binaries**
 		* [bingrep](https://github.com/m4b/bingrep)
			* Greps through binaries from various OSs and architectures, and colors them. 
	* **Static Analysis Tools**
		* [Bindead - static binary binary analysis tool](https://bitbucket.org/mihaila/bindead/wiki/Home)
			* Bindead is an analyzer for executable machine code. It features a disassembler that translates machine code bits into an assembler like language (RREIL) that in turn is then analyzed by the static analysis component using abstract interpretation. 
		* [Static binary analysis tool](https://github.com/bdcht/amoco)
			* Amoco is a python package dedicated to the (static) analysis of binaries. Worth a check on the Github
		* [Statically Linked Library Detector](https://github.com/arvinddoraiswamy/slid)
	* **OS X**
		* [Instruments - OS X system analysis](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/Introduction/Introduction.html)
			* Instruments is a performance-analysis and testing tool for dynamically tracing and profiling OS X and iOS code. It is a flexible and powerful tool that lets you track a process, collect data, and examine the collected data. In this way, Instruments helps you understand the behavior of both user apps and the operating system.
		* [Reversing iOS/OS X](http://newosxbook.com/forum/viewforum.php?f=8)
	* **Linux**
		* [Statically Linked Library Detector](https://github.com/arvinddoraiswamy/slid)
		* [Rdis](https://github.com/endeav0r/rdis)
			* Rdis is a Binary Analysis Tool for Linux.
	* **Windows**
		* [PolyHook - x86/x64 Hooking Library](https://github.com/stevemk14ebr/PolyHook)
			* Provides abstract C++ 11 interface for various hooking methods
		* [EasyHook](https://easyhook.github.io/)
			* EasyHook makes it possible to extend (via hooking) unmanaged code APIs with pure managed functions, from within a fully managed environment on 32- or 64-bit Windows XP SP2, Windows Vista x64, Windows Server 2008 x64, Windows 7, Windows 8.1, and Windows 10.
		* [Microsoft Message Analyzer](http://www.microsoft.com/en-us/download/details.aspx?id=40308)
			* Microsoft Message Analyzer is a new tool for capturing, displaying, and analyzing protocol messaging traffic and other system messages. Message Analyzer also enables you to import, aggregate, and analyze data from log and trace files. It is the successor to Microsoft Network Monitor 3.4 and a key component in the Protocol Engineering Framework (PEF) that was created by Microsoft for the improvement of protocol design, development, documentation, testing, and support. With Message Analyzer, you can choose to capture data live or load archived message collections from multiple data sources simultaneously.
		* [API Monitor](http://www.rohitab.com/apimonitor)
			* API Monitor is a free software that lets you monitor and control API calls made by applications and services. Its a powerful tool for seeing how applications and services work or for tracking down problems that you have in your own applications.
		* [SpyStudio](http://www.nektra.com/products/spystudio-api-monitor/)
			* SpyStudio shows and interprets calls, displaying the results in a structured way which is easy for any IT professional to understand. SpyStudio can show registry keys and files that an application uses, COM objects and Windows the application has created, and errors and exceptions.
			* [SpyStudio Tutorials](http://whiteboard.nektra.com/spystudio-2-0-quickstart)
		* [Fibratus](https://github.com/rabbitstack/fibratus)
			* Fibratus is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, file system I/O, registry, network activity, DLL loading/unloading and much more. Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, set kernel event filters or run the lightweight Python modules called filaments. You can use filaments to extend Fibratus with your own arsenal of tools.
		* [Deviare2](https://github.com/nektra/Deviare2)
			* Deviare is a professional hooking engine for instrumenting arbitrary Win32 functions, COM objects, and functions whose symbols are located in program databases (PDBs). It can intercept unmanaged code in 32-bit and 64-bit applications. It is implemented as a COM component, so it can be integrated with all the programming languages which support COM, such as C/C++, VB, C#, Delphi, and Python.
		* [Deviare In-Proc](https://github.com/nektra/Deviare-InProc)
			* Deviare In-Proc is a code interception engine for Microsoft Windows® developed by Nektra Advanced Computing. This library is at the core of our Deviare v2.0 and SpyStudio Application Monitor technologies. Deviare is an alternative to Microsoft Detours® but with a dual license distribution. The library is coded in C++ and provides all the facilities required to instrument binary libraries during runtime. It includes support for both 32 and 64 bit applications and it implements the interception verifying different situations that can crash the process. If you need to intercept any Win32 functions or any other code, this library makes it easier than ever. Unlike the rest of the libraries, Deviare In-Proc provides a safe mechanism to implement multi-threaded application API hooking. When an application is running, more than one thread can be executing the code being intercepted. Deviare In-Proc provides safe hooking even in this scenario.		
* **Debuggers**<a name="dbg"></a> 
	* **All platforms**
		* [Voltron](https://github.com/snare/voltron)
			* Voltron is an extensible debugger UI toolkit written in Python. It aims to improve the user experience of various debuggers (LLDB, GDB, VDB and WinDbg) by enabling the attachment of utility views that can retrieve and display data from the debugger host. By running these views in other TTYs, you can build a customised debugger user interface to suit your needs.
		* [GDB - GNU Debugger](https://www.gnu.org/software/gdb/)
			* GDB, the GNU Project debugger, allows you to see what is going on 'inside' another program while it executes -- or what another program was doing at the moment it crashed. 
		* **GDB Addons**
			* [PEDA](https://github.com/longld/peda)
				* PEDA - Python Exploit Development Assistance for GDB 		
			* [gdbgui](https://github.com/cs01/gdbgui)
				* A modern, browser-based frontend to gdb (gnu debugger). Add breakpoints, view stack traces, and more in C, C++, Go, and Rust. Simply run gdbgui from the terminal and a new tab will open in your browser.
			* [GEF - GDB Enhanced Features](https://github.com/hugsy/gef)
				* GEF is aimed to be used mostly by exploiters and reverse-engineers. It provides additional features to GDB using the Python API to assist during the process of dynamic analysis or exploit development. Why not PEDA? Yes!! Why not?! PEDA is a fantastic tool to do the same, but is only to be used for x86-32 or x86-64. On the other hand, GEF supports all the architecture supported by GDB (x86, ARM, MIPS, PowerPC, SPARC, and so on).
				* [Docs](https://gef.readthedocs.org/en/latest/)
		* [edb](https://github.com/eteran/edb-debugger)
			* edb is a cross platform x86/x86-64 debugger. It was inspired by Ollydbg, but aims to function on x86 and x86-64 as well as multiple OS's. Linux is the only officially supported platform at the moment, but FreeBSD, OpenBSD, OSX and Windows ports are underway with varying degrees of functionality.
		* [LLDB](https://lldb.llvm.org/)
			* LLDB is a next generation, high-performance debugger. It is built as a set of reusable components which highly leverage existing libraries in the larger LLVM Project, such as the Clang expression parser and LLVM disassembler. LLDB is the default debugger in Xcode on Mac OS X and supports debugging C, Objective-C and C++ on the desktop and iOS devices and simulator.
	* **Linux**
		* [PulseDBG](https://github.com/honorarybot/PulseDBG)
			* Hypervisor-based debugger
		* [xnippet](https://github.com/isislab/xnippet)
			* xnippet is a tool that lets you load code snippets or isolated functions (no matter the operating system they came from), pass parameters to it in several formats (signed decimal, string, unsigned hexadecimal...), hook other functions called by the snippet and analyze the result. The tool is written in a way that will let me improve it in a future, defining new calling conventions and output argument pointers.
	* **OS X**	
	* **Windows**
		* [OllyDbg](http://www.ollydbg.de/)
			* OllyDbg is a 32-bit assembler level analysing debugger for Microsoft® Windows®. Emphasis on binary code analysis makes it particularly useful in cases where source is unavailable.
			* [OllyDbg Tricks for Exploit Development](http://resources.infosecinstitute.com/in-depth-seh-exploit-writing-tutorial-using-ollydbg/)
		* **WindDbg**
			* [WinDbg](https://msdn.microsoft.com/en-us/library/windows/hardware/ff551063%28v=vs.85%29.aspx)
				* [Excellent Resource Site](http://www.windbg.org/)
				* [Crash Dump Analysis Poster](http://www.dumpanalysis.org/CDAPoster.html)
				* [Getting Started with WinDbg (User-Mode)](https://msdn.microsoft.com/en-us/library/windows/hardware/dn745911%28v=vs.85%29.aspx)
				* [Getting Started with WinDbg (Kernel-Mode)](https://msdn.microsoft.com/en-us/library/windows/hardware/dn745912%28v=vs.85%29.aspx)
				* [REhints MEX - WinDBG addons](https://github.com/REhints/WinDbg/tree/master/MEX)
			* [pykd](https://pypi.python.org/pypi/pykd)
				* python windbg extension
			* [WinAppDbg](http://winappdbg.sourceforge.net/)
				* The WinAppDbg python module allows developers to quickly code instrumentation scripts in Python under a Windows environment.  It uses ctypes to wrap many Win32 API calls related to debugging, and provides a powerful abstraction layer to manipulate threads, libraries and processes, attach your script as a debugger, trace execution, hook API calls, handle events in your debugee and set breakpoints of different kinds (code, hardware and memory). Additionally it has no native code at all, making it easier to maintain or modify than other debuggers on Windows.  The intended audience are QA engineers and software security auditors wishing to test or fuzz Windows applications with quickly coded Python scripts. Several ready to use tools are shipped and can be used for this purposes.  Current features also include disassembling x86/x64 native code, debugging multiple processes simultaneously and produce a detailed log of application crashes, useful for fuzzing and automated testing.
			* [Getting Started with WinDbg part 1](http://blog.opensecurityresearch.com/2013/12/getting-started-with-windbg-part-1.html)
			* [An Introduction to Debugging the Windows Kernel with WinDbg](http://www.contextis.com/resources/blog/introduction-debugging-windows-kernel-windbg/)
			* [DbgShell](https://github.com/Microsoft/DbgShell)
				* A PowerShell front-end for the Windows debugger engine.
		* [Open Source Windows x86/x64 Debugger](http://x64dbg.com/)
		* [HyperDbg](https://github.com/rmusser01/hyperdbg/)
			* HyperDbg is a kernel debugger that leverages hardware-assisted virtualization. More precisely, HyperDbg is based on a minimalistic hypervisor that is installed while the system runs. Compared to traditional kernel debuggers (e.g., WinDbg, SoftIce, Rasta R0 Debugger) HyperDbg is completely transparent to the kernel and can be used to debug kernel code without the need of serial (or USB) cables. For example, HyperDbg allows to single step the execution of the kernel, even when the kernel is executing exception and interrupt handlers. Compared to traditional virtual machine based debuggers (e.g., the VMware builtin debugger), HyperDbg does not require the kernel to be run as a guest of a virtual machine, although it is as powerful. 
			* [Paper](http://roberto.greyhats.it/pubs/ase10.pdf)
	* **Debugging Writeups/Papers**
		* [BugNet: Continuously Recording Program Execution for Deterministic Replay Debugging](https://cseweb.ucsd.edu/~calder/papers/ISCA-05-BugNet.pdf)
		* [Back to the Future: Omniscient Debugging](https://pleiad.cl/papers/2009/pothierTanter-software2009.pdf) 
		* [A REVIEW OF REVERSE DEBUGGING - Jakob Engblom (2012?)](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.338.3420&rep=rep1&type=pdf)
		* [Binary Hooking Problems](http://www.ragestorm.net/blogs/?p=348)
		* [Hyper-V debugging for beginners](http://hvinternals.blogspot.com/2015/10/hyper-v-debugging-for-beginners.html?m=1)
		* [GCC gOlogy: studying the impact of optimizations on debugging - Alexandre Oliva](https://www.fsfla.org/~lxoliva/writeups/gOlogy/gOlogy.txt)
* **Decompilers & Disassemblers**<a name="decom"></a>
	* **General**
		* [IDA](https://www.hex-rays.com/products/ida/)
			* IDA Pro combines an interactive, programmable, multi-processor disassembler coupled to a local and remote debugger and augmented by a complete plugin programming environment.
			* [Overview & Tutorials](https://www.hex-rays.com/products/ida/debugger/index.shtml)
		* [fREedom](capstone based disassembler for extracting to binnavi )
			* fREedom is a primitive attempt to provide an IDA Pro independent means of extracting disassembly information from executables for use with binnavi (https://github.com/google/binnavi).
		* [Hopper](http://www.hopperapp.com/)
			* Hopper is a reverse engineering tool for OS X and Linux, that lets you disassemble, decompile and debug your 32/64bits Intel Mac, Linux, Windows and iOS executables!
		* [Reverse](https://github.com/joelpx/reverse)
			* Reverse engineering for x86 binaries (elf-format). Generate a more readable code (pseudo-C) with colored syntax. Warning, the project is still in development, use it at your own risks. This tool will try to disassemble one function (by default main). The address of the function, or its symbol, can be passed by argument.
		* [Medusa](https://github.com/wisk/medusa)
			* Medusa is a disassembler designed to be both modular and interactive. It runs on Windows and Linux, it should be the same on OSX. This project is organized as a library. To disassemble a file you have to use medusa_dummy or qMedusa. wxMedusa and pydusa are not available anymore.
		* [PLASMA](https://github.com/plasma-disassembler/plasma)
			* PLASMA is an interactive disassembler. It can generate a more readable assembly (pseudo code) with colored syntax. You can write scripts with the available Python api (see an example below). The project is still in big development.
		* [Snowman decompiler](https://github.com/yegord/snowman)
			* [Snowman](http://derevenets.com/) is a native code to C/C++ decompiler, supporting x86, AMD64, and ARM architectures. You can use it as a [standalone GUI application](https://github.com/yegord/snowman/blob/master/src/snowman), a [command-line tool](https://github.com/yegord/snowman/blob/master/src/nocode), an [IDA plug-in](https://github.com/yegord/snowman/blob/master/src/ida-plugin), a [radare2 plug-in](https://github.com/radare/radare2-pm/blob/master/db/r2snow), an [x64dbg plug-in](https://github.com/x64dbg/snowman), or a [library](https://github.com/yegord/snowman/blob/master/src/nc). Snowman is free software.
		* [Panopticon](https://github.com/das-labor/panopticon)
			* Panopticon is a cross platform disassembler for reverse engineering written in Rust. It can disassemble AMD64, x86, AVR and MOS 6502 instruction sets and open ELF files. Panopticon comes with Qt GUI for browsing and annotating control flow graphs,
		* [BinaryNinja](https://binary.ninja/)
			* [BinDbg](https://github.com/kukfa/bindbg)
				* BinDbg is a Binary Ninja plugin that syncs WinDbg to Binja to create a fusion of dynamic and static analyses. It was primarily written to improve the Windows experience for Binja debugger integrations.
	* **Java**
		* [Procyon - Java Decompiler](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler)
			* [Luyten](https://github.com/deathmarine/Luyten)
				* Java Decompiler Gui for Procyon
		* [JavaSnoop](https://www.aspectsecurity.com/tools/javasnoop)
			* A tool that lets you intercept methods, alter data and otherwise test the security of Java applications on your computer.
		* [Blackhat - 2010 JavaSnoop: How to hack anything written in Java](https://www.youtube.com/watch?v=ipuSmbxBxKw)
		* [JavaSnoop – Debugging Java applications](https://www.securityartwork.es/2013/02/20/javasnoop-debugging-java-applications/)
		* [Krakatau](https://github.com/Storyyeller/Krakatau)
			* Java decompiler, assembler, and disassembler
		* [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer)
			* Bytecode Viewer is an Advanced Lightweight Java Bytecode Viewer, GUI Java Decompiler, GUI Bytecode Editor, GUI Smali, GUI Baksmali, GUI APK Editor, GUI Dex Editor, GUI APK Decompiler, GUI DEX Decompiler, GUI Procyon Java Decompiler, GUI Krakatau, GUI CFR Java Decompiler, GUI FernFlower Java Decompiler, GUI DEX2Jar, GUI Jar2DEX, GUI Jar-Jar, Hex Viewer, Code Searcher, Debugger and more. It's written completely in Java, and it's open sourced. It's currently being maintained and developed by Konloch.
	* **.NET**
		* [DotPeek](http://www.jetbrains.com/decompiler/features/)
			* dotPeek is a .NET decompiler that has several handy features.
		* [dnSpy](https://github.com/0xd4d/dnSpy)
			* dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available.
		* [ILSpy](https://github.com/icsharpcode/ILSpy)
			* ILSpy is the open-source .NET assembly browser and decompiler.
		* [Shed](https://github.com/enkomio/shed)
			* Shed is an application that allow to inspect the .NET runtime of a program in order to extract useful information. It can be used to inspect malicious applications in order to have a first general overview of which information are stored once that the malware is executed.
		* [dotNET_WinDBG](https://github.com/Cisco-Talos/dotNET_WinDBG)
			* This python script is designed to automate .NET analysis with WinDBG. It can be used to analyse a PowerShell script or to unpack a binary packed using a .NET packer.
		* [Unravelling .NET with the Help of WinDBG - TALOS](http://blog.talosintelligence.com/2017/07/unravelling-net-with-help-of-windbg.html)
			* This article describes: How to analyse PowerShell scripts by inserting a breakpoint in the .NET API; How to easily create a script to automatically unpack .NET samples following analysis of the packer logic.
	* **IDA specific Stuff**
		* IDA Extensions
			* [BAP-IDA](https://github.com/BinaryAnalysisPlatform/bap-ida-python)
				* This package provides the necessary IDAPython scripts required for interoperatibility between BAP and IDA Pro. It also provides many useful feature additions to IDA, by leveraging power from BAP.
			* [funcap - IDA Pro script to add some useful runtime info to static analysis.](https://github.com/deresz/funcap)
				* This script records function calls (and returns) across an executable using IDA debugger API, along with all the arguments passed. It dumps the info to a text file, and also inserts it into IDA's inline comments. This way, static analysis that usually follows the behavioral runtime analysis when analyzing malware, can be directly fed with runtime info such as decrypted strings returned in function's arguments. In author's opinion this allows to understand the program's logic way faster than starting the "zero-knowledge" reversing. Quick understanding of a malware sample code was precisely the motivation to write this script and the author has been using it succesfully at his $DAYJOB. It is best to see the examples with screenshots to see how it works (see below). It must be noted that the script has been designed with many misconceptions, errors and bad design decisions (see issues and funcap.py code) as I was learning when coding but it has one advantage - it kind of works :) Current architectures supported are x86, amd64 and arm.
			[IDAPython Embedded Toolkit](https://github.com/maddiestone/IDAPythonEmbeddedToolkit)
				* IDAPython is a way to script different actions in the IDA Pro disassembler with Python. This repository of scripts automates many different processes necessary when analyzing the firmware running on microcontroller and microprocessor CPUs. The scripts are written to be easily modified to run on a variety of architectures. Read the instructions in the header of each script to determine what ought to be modified for each architecture.
		* **IDA Plugins**
			* [A list of IDA Plugins](https://github.com/onethawt/idaplugins-list)
			* [IDA Python - Ero Carrera](http://www.offensivecomputing.net/papers/IDAPythonIntro.pdf)
				* IDAPython is an extension for IDA , the Interactive Disassembler . It brings the power and convenience of Python scripting to aid in the analysis of binaries. This article will cover some basic usage and provide examples to get interested individuals started. W e will walk through practical examples ranging from iterating through functions, segments and instructions to data mining the binaries, collecting references and analyzing their structure.
			* [Kam1n0-Plugin-IDA-Pro](https://github.com/McGill-DMaS/Kam1n0-Plugin-IDA-Pro)
				* Kam1n0 is a scalable system that supports assembly code clone search. It allows a user to first index a (large) collection of binaries, and then search for the code clones of a given target function or binary file. Kam1n0 tries to solve the efficient subgraph search problem (i.e. graph isomorphism problem) for assembly functions. Given a target function (the middle one in the figure below) it can identity the cloned subgraphs among other functions in the repository (the ones on the left and the right as shown below). Kam1n0 supports rich comment format and has an IDA Pro plug-in to use its indexing and searching capabilities via IDA Pro. 
			* [FLARE-Ida](https://github.com/fireeye/flare-ida)
				* This repository contains a collection of IDA Pro scripts and plugins used by the FireEye Labs Advanced Reverse Engineering (FLARE) team.
			* [toolbag](https://github.com/aaronportnoy/toolbag)
				* The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler. 
			* [Dynamic IDA Enrichment (aka. DIE)](https://github.com/ynvb/DIE)
				* DIE is an IDA python plugin designed to enrich IDA's static analysis with dynamic data. This is done using the IDA Debugger API, by placing breakpoints in key locations and saving the current system context once those breakpoints are hit.
			* [HexRaysCodeXplorer](https://github.com/REhints/HexRaysCodeXplorer)
				* Hex-Rays Decompiler plugin for better code navigation in RE process of C++ applications or code reconstruction of modern malware as Stuxnet, Flame, Equation	
			* [Ida Pomidor](https://thesprawl.org/projects/ida-pomidor/)
				* IDA Pomidor is a fun and simple plugin for the Hex-Ray's IDA Pro disassembler that will help you retain concentration and productivity during long reversing sessions.
			* [idaConsonance](https://github.com/eugeii/ida-consonance)
				* Consonance, a dark color theme for IDA.
			* [Lighthouse - Code Coverage Explorer for IDA Pro](https://github.com/gaasedelen/lighthouse)
				* Lighthouse is a code coverage plugin for IDA Pro. The plugin leverages IDA as a platform to map, explore, and visualize externally collected code coverage data when symbols or source may not be available for a given binary.
			* [NRS](https://github.com/isra17/nrs)
				* NRS is a set of Python librairies used to unpack and analysis NSIS installer's data. It also feature an IDA plugin used to disassembly the NSIS Script of an installer
			* [Ponce](https://github.com/illera88/Ponce)
				* Ponce (pronounced [ 'poN θe ] pon-they ) is an IDA Pro plugin that provides users the ability to perform taint analysis and symbolic execution over binaries in an easy and intuitive fashion. With Ponce you are one click away from getting all the power from cutting edge symbolic execution. Entirely written in C/C++.
			* [IDASkins](https://github.com/zyantific/IDASkins)
				* Advanced skinning plugin for IDA Pro
			* [Ida Sploiter](https://thesprawl.org/projects/ida-sploiter/)
				* IDA Sploiter is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool. Some of the plugin's features include a powerful ROP gadgets search engine, semantic gadget analysis and filtering, interactive ROP chain builder, stack pivot analysis, writable function pointer search, cyclic memory pattern generation and offset analysis, detection of bad characters and memory holes, and many others.
			* [vtbl-ida-pro-plugin](https://github.com/nektra/vtbl-ida-pro-plugin)
				* Identifying Virtual Table Functions using VTBL IDA Pro Plugin + Deviare Hooking Engine
			* [virusbattle-ida-plugin](https://github.com/moghimi/virusbattle-ida-plugin)
				* The plugin is an integration of Virus Battle API to the well known IDA Disassembler. Virusbattle is a web service that analyses malware and other binaries with a variety of advanced static and dynamic analyses.
			* [ida-batch_decompile](https://github.com/tintinweb/ida-batch_decompile)
				* IDA Batch Decompile is a plugin for Hex-Ray's IDA Pro that adds the ability to batch decompile multiple files and their imports with additional annotations (xref, stack var size) to the pseudocode .c file
			* [IdaRef](https://github.com/nologic/idaref)
				* IDA Pro Full Instruction Reference Plugin - It's like auto-comments but useful.
			* [YaCo])(https://github.com/DGA-MI-SSI/YaCo)
				* YaCo is an Hex-Rays IDA plugin. When enabled, multiple users can work simultaneously on the same binary. Any modification done by any user is synchronized through git version control.
			* [HexRaysPyTools](https://github.com/igogo-x86/HexRaysPyTools/blob/master/readme.md)
				* The plugin assists in the creation of classes/structures and detection of virtual tables. It also facilitates transforming decompiler output faster and allows to do some stuff which is otherwise impossible.
		* **IDA Tutorials/Help**
			* [TiGa's Video Tutorial Series on IDA Pro](http://woodmann.com/TiGa/idaseries.html)
			* [IDA PLUG-IN WRITING IN C/C++](http://www.binarypool.com/idapluginwriting/idapw.pdf)
			* [How to Identify Virtual Table Functions with IDA Pro and the VTBL Plugin](https://www.youtube.com/watch?v=XHW9Akb4KLI&app=desktop)
			* [Reversing C++ programs with IDA pro and Hex-rays](https://blog.0xbadc0de.be/archives/67)
			* [IDAPython The Wonder Woman of Embedded Device Reversing Maddie Stone - Derbycon7](https://www.youtube.com/watch?v=HRwfRrmPAHI&index=2&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
			* [IDA FLIRT In Depth](https://www.hex-rays.com/products/ida/tech/flirt/in_depth.shtml)
* **File Formats**<a name="formats"></a>
	* [Encyclopedia of Graphics File Formats](http://fileformats.archiveteam.org/wiki/Encyclopedia_of_Graphics_File_Formats)
	* [PE File Format Graphs](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html?view=mosaic)
	* [PNG File Format](http://fileformats.archiveteam.org/wiki/PNG)
	* [Tour of Win32 Executable format](http://msdn.microsoft.com/en-us/magazine/ms809762.aspx)
* **Flash Player** <a name="flash"></a>
	* [#Fldbg](https://github.com/offensive-security/fldbg)
		* #Fldbg, a Pykd script to debug FlashPlayer
	* [SWFRETools](https://github.com/sporst/SWFREtools)
		* The SWFRETools are a collection of tools built for vulnerability analysis of the Adobe Flash player and for malware analysis of malicious SWF files. The tools are partly written in Java and partly in Python and are licensed under the GPL 2.0 license.
* **Frameworks**<a name="frameworks"></a>
	* [angr](http://angr.io/)
		* angr is a python framework for analyzing binaries. It focuses on both static and dynamic symbolic ("concolic") analysis, making it applicable to a variety of tasks.
	* Radare2 - unix-like reverse engineering framework and commandline tools ](http://www.radare.org/y/?p=features)
		* Informally goal is to be best RE software framework
		* [Github](https://github.com/radare/radare2)
		* [Radare2 Book(free)](https://maijin.github.io/radare2book/index.html)
		* [Radare2 Documentation](http://www.radare.org/y/?p=documentation)
		* [Reverse engineering embedded software using Radare2 - Talk/Tutorial](https://www.youtube.com/watch?v=R3sGlzXfEkU)
		* [Notes and Demos for above video](https://github.com/pastcompute/lca2015-radare2-tutorial)
		* [radare2 cheat sheet](https://github.com/pwntester/cheatsheets/blob/master/radare2.md)
		* [radare2 as an alternative to gdb-peda](https://monosource.github.io/2016/10/radare2-peda)
		* [Radare2 in 0x1E minutes](https://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/)
		* [cutter](https://github.com/radareorg/cutter)
			* A Qt and C++ GUI for radare2 reverse engineering framework
	* [BitBlaze](http://bitblaze.cs.berkeley.edu/)
		* The BitBlaze project aims to design and develop a powerful binary analysis platform and employ the platform in order to (1) analyze and develop novel COTS protection and diagnostic mechanisms and (2) analyze, understand, and develop defenses against malicious code. The BitBlaze project also strives to open new application areas of binary analysis, which provides sound and effective solutions to applications beyond software security and malicious code defense, such as protocol reverse engineering and fingerprint generation. 
	* [Platform for Architecture-Neutral Dynamic Analysis](https://github.com/moyix/panda)
	* [BARF-Project](https://github.com/programa-stic/barf-project)
		* BARF : A multiplatform open source Binary Analysis and Reverse engineering Framework 
		* [Presentation: Barfing Gadgets - Ekoparty 2014](https://github.com/programa-stic/barf-project/raw/master/documentation/presentations/barfing-gadgets.ekoparty2014.es.pdf)
* **Programming Language Specifics/Libraries** <a name="pl"></a>
	* **Libraries**
		* [openreil](https://github.com/Cr4sh/openreil)
			* Open source library that implements translator and tools for REIL (Reverse Engineering Intermediate Language)
	* **Go**
		* [Reversing GO binaries like a pro](https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/)
	* **Java**
		* [PortEx](https://github.com/katjahahn/PortEx)
			* PortEx is a Java library for static malware analysis of Portable Executable files. Its focus is on PE malformation robustness, and anomaly detection. PortEx is written in Java and Scala, and targeted at Java applications.
	* **Python** 
		* **Bytecode**
			* [Gynvael’s Mission 11 (en): Python bytecode reverse-engineering](https://chriswarrick.com/blog/2017/08/03/gynvaels-mission-11-en-python-bytecode-reverse-engineering/)
			* [Deobfuscating Python Bytecode](https://www.fireeye.com/blog/threat-research/2016/05/deobfuscating_python.html)
			* [Equip: python bytecode instrumentation](https://github.com/neuroo/equip)
				* equip is a small library that helps with Python bytecode instrumentation. Its API is designed to be small and flexible to enable a wide range of possible instrumentations. The instrumentation is designed around the injection of bytecode inside the bytecode of the program to be instrumented. However, the developer does not need to know anything about the Python bytecode since the injected code is Python source.
		* **Decompilation**
			* [python-uncompyle6](https://github.com/rocky/python-uncompyle6)
				* A native Python cross-version Decompiler and Fragment Decompiler. The successor to decompyle, uncompyle, and uncompyle2.
			* [Decompyle++](https://github.com/zrax/pycdc)
				* C++ python bytecode disassembler and decompiler
			* [Python Decompiler](https://github.com/alex/python-decompiler)
				* This project aims to create a comprehensive decompiler for CPython bytecode (likely works with PyPy as well, and any other Python implementation that uses CPython's bytecode)
			* [PyInstaller Extractor](https://sourceforge.net/p/pyinstallerextractor/tickets/5/)
				* Extract contents of a Windows executable file created by pyinstaller 
			* [Easy Python Decompiler](https://sourceforge.net/projects/easypythondecompiler/)
				* Python 1.0 - 3.4 bytecode decompiler 
		* **General**
			* [Python RE tools list](http://pythonarsenal.erpscan.com/)	
* **Anti-Reverse Engineering Techniques & Countermeasures** <a name="are"></a>
	* **Talks**
		* [Trolling reverse_engineers with math - frank^2 - part.mov](https://www.youtube.com/watch?v=y124L75ZKAc)
	* **Techniques**
		* [The “Ultimate”Anti-Debugging Reference - Peter Ferrie 2011/4](http://pferrie.host22.com/papers/antidebug.pdf)
		* [Android Reverse Engineering Defenses](https://bluebox.com/wp-content/uploads/2013/05/AndroidREnDefenses201305.pdf)
		* [Anti-RE A collection of Anti-Reverse Engineering Techniques](http://pnx.tf/files/spring7_antire_plohmann_kannen.pdf)
		* [Anti Reverse Engineering](http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide)
		* [Fun combining anti-debugging and anti-disassembly tricks](http://blog.sevagas.com/?Fun-combining-anti-debugging-and)
		* [simpliFiRE.AntiRE - An Executable Collection of Anti-Reversing Techniques](https://bitbucket.org/fkie_cd_dare/simplifire.antire)
			* AntiRE is a collection of such anti analysis approaches, gathered from various sources like Peter Ferrie's The "Ultimate" Anti-Debugging Reference and Ange Albertini's corkami. While these techniques by themselves are nothing new, we believe that the integration of these tests in a single, executable file provides a comprehensive overview on these, suitable for directly studying their behaviour in a harmless context without additional efforts. AntiRE includes different techniques to detect or circumvent debuggers, fool execution tracing, and disable memory dumping. Furthermore, it can detect the presence of different virtualization environments and gives examples of techniques used to twarth static analysis.
		* [OpenRCE Anti Reverse Engineering Techniques Database](http://www.openrce.org/reference_library/anti_reversing)
		* [Windows Anti-Debugging Reference](http://www.symantec.com/connect/articles/windows-anti-debug-reference)
			* This paper classifies and presents several anti-debugging techniques used on Windows NT-based operating systems. Anti-debugging techniques are ways for a program to detect if it runs under control of a debugger. They are used by commercial executable protectors, packers and malicious software, to prevent or slow-down the process of reverse-engineering. We'll suppose the program is analyzed under a ring3 debugger, such as OllyDbg on Windows platforms. The paper is aimed towards reverse-engineers and malware analysts. Note that we will talk purely about generic anti-debugging and anti-tracing techniques. Specific debugger detection, such as window or processes enumeration, registry scanning, etc. will not be addressed here
		* [Windows Anti-Debug techniques - OpenProcess filtering](https://blog.xpnsec.com/anti-debug-openprocess/)
		* [Detecting debuggers by abusing a bad assumption within Windows](http://www.triplefault.io/2017/08/detecting-debuggers-by-abusing-bad.html)
		* [Dangers of the Decompiler - A Sampling of Anti-Decompilation Techniques](https://blog.ret2.io/2017/11/16/dangers-of-the-decompiler/)
		* [JavaScript AntiDebugging Tricks - x-c3ll](https://x-c3ll.github.io/posts/javascript-antidebugging/)
	* **Tools**
		* [ALPHA3](https://code.google.com/p/alpha3/)
			* ALPHA3 is a tool for transforming any x86 machine code into 100% alphanumeric code with similar functionality. It works by encoding the original code into alphanumeric data and combining this data with a decoder, which is a piece of x86 machine code written specifically to be 100% alphanumeric. When run, the decoder converts the data back to the original code, after which it is executed.
		* [reductio [ad absurdum]](https://github.com/xoreaxeaxeax/reductio)
			* an exploration of code homeomorphism: all programs can be reduced to the same instruction stream.
		* [REpsych - Psychological Warfare in Reverse Engineering](https://github.com/xoreaxeaxeax/REpsych/blob/master/README.md)
			* The REpsych toolset is a proof-of-concept illustrating the generation of images through a program's control flow graph (CFG).
		* [IDAnt-wanna](https://github.com/strazzere/IDAnt-wanna)
			* ELF header abuse
		* [makin](https://github.com/secrary/makin)
			* makin - reveal anti-debugging tricks
* **Hardware Reverse Engineering**<a name="hre"></a>
	* See 'Embedded Devices & Hardware Hacking'
* **.NET Related** <a name="net"></a>
	* [Getting Started with CLR MD](https://github.com/Microsoft/clrmd/blob/master/Documentation/GettingStarted.md)
	* [Microsoft.Diagnostics.Runtime.dll(CLR MD)](https://github.com/Microsoft/clrmd)
		* Microsoft.Diagnostics.Runtime.dll (nicknamed "CLR MD") is a process and crash dump introspection library. This allows you to write tools and debugger plugins which can do thing similar to SOS and PSSCOR.
	* [Reflexil](https://github.com/sailro/Reflexil)
		* Reflexil is an assembly editor and runs as a plug-in for Red Gate's Reflector, ILSpy and Telerik's JustDecompile. Reflexil is using Mono.Cecil, written by Jb Evain and is able to manipulate IL code and save the modified assemblies to disk. Reflexil also supports C#/VB.NET code injection
* **Writeups**<a name="writeups"></a>
	* **101s**
		* [Defeating ioli with radare2](https://dustri.org/b/defeating-ioli-with-radare2.html)
	* **Binary & Code Analysis**
		* [Byteweight: Learning to Recognize Functions in Binary Code](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-bao.pdf)
		* [Memalyze: Dynamic Analysis of Memory Access Behavior in Software](http://uninformed.org/?v=all&a=31&t=sumry)
			* This paper describes strategies for dynamically analyzing an application's memory access behavior. These strategies make it possible to detect when a read or write is about to occur at a given location in memory while an application is executing. An application's memory access behavior can provide additional insight into its behavior. For example, it may be able to provide an idea of how data propagates throughout the address space. Three individual strategies which can be used to intercept memory accesses are described in this paper. Each strategy makes use of a unique method of intercepting memory accesses. These methods include the use of Dynamic Binary Instrumentation (DBI), x86 hardware paging features, and x86 segmentation features. A detailed description of the design and implementation of these strategies for 32-bit versions of Windows is given. Potential uses for these analysis techniques are described in detail.
		* [How to Grow a TREE from CBASS - Interactive Binary Analysis for  Security Professionals](https://media.blackhat.com/us-13/US-13-Li-How-to-Grow-a-TREE-Slides.pdf)
	* **File Formats**
		* [Reversing Monkey](http://cheeky4n6monkey.blogspot.com/2015/02/reversing-monkey.html?m=1)
			* When trying to recover/carve deleted data, some reverse engineering of the file format may be required. Without knowing how the data is stored, we cannot recover the data of interest - be it timestamps, messages, images, video or another type of data. This quick blog post is intended to give some basic tips that have been observed during monkey's latest travels into reverse engineering of file formats. It was done partly as a memory aid/thinking exercise but hopefully other monkeys will find it useful. This post assumes there's no obfuscation/encryption applied to the file and it does not cover reverse engineering malware exes (which is another kettle of bananas).
		* [How to RE data files?](https://www.reddit.com/r/ReverseEngineering/comments/l8ac0/how_to_re_data_files/)
	* **Firmware**
		* [Reverse Engineering Firmware Primer](https://wiki.securityweekly.com/Reverse_Engineering_Firmware_Primer)
		* [The Empire Strikes Back Apple – how your Mac firmware security is completely broken](https://reverse.put.as/2015/05/29/the-empire-strikes-back-apple-how-your-mac-firmware-security-is-completely-broken/)
		* [Hacking Linksys E4200v2 firmware](https://blog.bramp.net/post/2012/01/24/hacking-linksys-e4200v2-firmware/)
		* [Multiple vulnerabilities found in the Dlink DWR-932B (backdoor, backdoor accounts, weak WPS, RCE ...)](https://pierrekim.github.io/blog/2016-09-28-dlink-dwr-932b-lte-routers-vulnerabilities.html)
		* [Reverse Engineering Qualcomm Baseband](http://events.ccc.de/congress/2011/Fahrplan/attachments/2022_11-ccc-qcombbdbg.pdf)
	* **General**
		* [Reverse Engineering Flash Memory for Fun and Benefit - BlackHat 2014](https://www.youtube.com/watch?v=E8BSnS4-Kpw)
		* [Getting access to your own Fitbit data](https://www.cs.ru.nl/bachelorscripties/2016/Maarten_Schellevis___4142616___Getting_access_to_your_own_Fitbit_data.pdf)
			* This study investigates the possibility of getting direct access to one’s own data, as recorded by a Fitbit Charge HR activity tracker, without going through the Fitbit servers. We captured the firmware image of the Fitbit Charge HR during a firmware update. By analyzing this firmware image we were able to reverse-engineer the cryptographic primitives used by the Fitbit Charge HR activity tracker and recover the authentication  protocol. We obtained the cryptographic key that is used in the authentication protocol from the Fitbit Android application. We located a backdoor in version 18.102 of the firmware by comparing it with the latest version of the firmware (18.122). In the latest version of the firmware the backdoor was removed. This backdoor was used to extract the device specific encryption key from the memory of the tracker. While we have not implemented this last step in practice, the device specific encryption key can be used by a Fitbit Charge HR user to obtain his/her fitness data directly from the device.
		* [Screwdriving. Locating and exploiting smart adult toys](https://www.pentestpartners.com/security-blog/screwdriving-locating-and-exploiting-smart-adult-toys/)
		* [Hacking travel routers  like it’s 1999](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Mikhail-Sosonkin-Hacking-Travel-Routers-Like-1999.pdf)
		* [Reverse Engineering IoT Devices](https://iayanpahwa.github.io/Reverse-Engineering-IoT-Devices/)
		* [How I Reverse Engineered and Exploited a Smart Massager](https://medium.com/@arunmag/how-i-reverse-engineered-and-exploited-a-smart-massager-ee7c9f21bf33)
		* [Make Confide great again? No, we cannot](http://blog.quarkslab.com/make-confide-great-again-no-we-cannot.html)
			* RE'ing an electron based "secure communications" app
		* [The Three Billion Dollar App - Vladimir Wolstencroft -Troopers14](https://www.youtube.com/watch?v=5Duc-uUFzoU)
			* Talk about reverse engineering SnapChat and Wickr Messaging apps.
		* [A Practical-Time Attack on the A5/3 Cryptosystem Used in Third Generation GSM Telephony](https://eprint.iacr.org/2010/013)
			* Abstract: The privacy of most GSM phone conversations is currently protected by the 20+ years old A5/1 and A5/2 stream ciphers, which were repeatedly shown to be cryptographically weak. They will soon be replaced in third generation networks by a new A5/3 block cipher called KASUMI, which is a modified version of the MISTY cryptosystem. In this paper we describe a new type of attack called a sandwich attack, and use it to construct a simple distinguisher for 7 of the 8 rounds of KASUMI with an amazingly high probability of $2^{ -14}$. By using this distinguisher and analyzing the single remaining round, we can derive the complete 128 bit key of the full KASUMI by using only 4 related keys, $2^{26}$ data, $2^{30}$ bytes of memory, and $2^{32}$ time. These complexities are so small that we have actually simulated the attack in less than two hours on a single PC, and experimentally verified its correctness and complexity. Interestingly, neither our technique nor any other published attack can break MISTY in less than the $2^{128}$ complexity of exhaustive search, which indicates that the changes made by the GSM Association in moving from MISTY to KASUMI resulted in a much weaker cryptosystem.
		* [Reverse engineering HID iClass Master keys](https://blog.kchung.co/reverse-engineering-hid-iclass-master-keys/)
		* [Reversing EVM bytecode with radare2](https://blog.positive.com/reversing-evm-bytecode-with-radare2-ab77247e5e53)
		* [WhatsApp Web reverse engineered](https://github.com/sigalor/whatsapp-web-reveng)
			* This project intends to provide a complete description and re-implementation of the WhatsApp Web API, which will eventually lead to a custom client. WhatsApp Web internally works using WebSockets; this project does as well.
	* **OS X**
		* [Reverse Engineering Mac OS X](http://reverse.put.as/papers/)
			* Excellent source of papers from 2003-2013 all with a focus on reversing either iOS or OS X.
		* [osx & ios re 101](https://github.com/michalmalik/osx-re-101)
	* **Packers**
		* [A Brief Examination of Hacking Team’s Crypter: core-packer.](http://ethanheilman.tumblr.com/post/128708937890/a-brief-examination-of-hacking-teams-crypter)
		* [The Art of Unpacking - Paper](https://www.blackhat.com/presentations/bh-usa-07/Yason/Whitepaper/bh-usa-07-yason-WP.pdf)
			* Abstract: The main purpose of this paper is to present anti-reversing techniques employed by executable packers/protectors and also discusses techniques and publicly available tools that can be used to bypass or disable this protections. This information will allow researchers, especially, malcode analysts to identify these techniques when utilized by packed malicious code, and then be able decide the next move when these anti-reversing techniques impede successful analysis. As a secondary purpose, the information presented can also be used by researchers that are planning to add some level of protection in their software by slowing down reversers from analyzing their protected code, but of course, nothing will stop a skilled, informed, and determined reverser
		* [Paper on Manual unpacking of UPX packed executable using Ollydbg and Importrec](http://www.iosrjournals.org/iosr-jce/papers/Vol16-issue1/Version-1/L016117177.pdf)
	* **PDFs**
		* [Advanced PDF Tricks - Ange Albertini, Kurt Pfeifle - Troopers1](https://www.youtube.com/watch?v=k9g9jZdjRcE)
			* This session is NOT about analyzing exploits but about learning to manipulate PDF contents. Among others:hide/reveal information; remove/add watermark;  just suck less about the format. It's an extended session (2 hours) to leave the audience time to try by themselves actively. The slides' PDF is entirely hand-written to explain clearly each fact, so the presentation slides themselves will be the study materials.
	* **Process Hookinng**
		* [Software Hooking methods reveiw(2016)]((https://www.blackhat.com/docs/us-16/materials/us-16-Yavo-Captain-Hook-Pirating-AVs-To-Bypass-Exploit-Mitigations-wp.pdf)
		* [PolyHook](https://www.codeproject.com/articles/1100579/polyhook-the-cplusplus-x-x-hooking-library)
	* **Protocols**
		* [Somfy Smoove Origin RTS Protocol](https://pushstack.wordpress.com/somfy-rts-protocol/)
			* This document describes the Somfy RTS protocol as used by the “Somfy Smoove Origin RTS”. Most information in this document is based on passive observation of the data send by the Smoove Origin RTS remote, and thus can be inaccurate or incorrect!
		* [Reverse Engineering The eQSO Protocol](https://gist.github.com/anonymous/7a9d713e61ba990a3a17)
			* Today I reverse engineered the eQSO protocol. If you didn't know, eQSO is a small program that allows radio amateurs to talk to each other online. Sadly this program isn't as popular as it used to be (Well, neither is the radio).
		* [Cyber Necromancy - Reverse engineering dead protocols - Defcamp 2014 ](https://www.youtube.com/watch?v=G0v2FO2Ru0w&index=6&list=PLnwq8gv9MEKgSryzYIFhpmCcqnVzdUWfH)
		* [Reverse Engineering of Proprietary Protocols, Tools and Techniques - Rob Savoye - FOSDEM 2009 ](https://www.youtube.com/watch?v=t3s-mG5yUjY)
			* This talk is about reverse engineering a proprietary network protocol, and then creating my own implementation. The talk will cover the tools used to take binary data apart, capture the data, and techniques I use for decoding unknown formats. The protocol covered is the RTMP protocol used by Adobe flash, and this new implementation is part of the Gnash project.
		* [Netzob](http://www.netzob.org/)
			* Originaly, the development of Netzob has been initiated to support security auditors and evaluators in their activities of modeling and simulating undocumented protocols. The tool has then been extended to allow smart fuzzing of unknown protocol. 
			* [Netzob Documentation](http://netzob.readthedocs.org/en/latest/overview/index.html)
	* **Satellites**
		* [SATCOM Terminals Hacking by Air, Sea, and Land - Black Hat USA 2014](https://www.youtube.com/watch?v=tRHDuT__GoM)
	* **Windows**
		* [Windows for Reverse Engineers](http://www.cse.tkk.fi/fi/opinnot/T-110.6220/2014_Reverse_Engineering_Malware_AND_Mobile_Platform_Security_AND_Software_Security/luennot-files/T1106220.pdf)
		* [Introduction to Reverse Engineering Win32 Applications](http://uninformed.org/?v=all&a=7&t=sumry)
			* During the course of this paper the reader will be (re)introduced to many concepts and tools essential to understanding and controlling native Win32 applications through the eyes of Windows Debugger (WinDBG). Throughout, WinMine will be utilized as a vehicle to deliver and demonstrate the functionality provided by WinDBG and how this functionality can be harnessed to aid the reader in reverse engineering native Win32 applications. Topics covered include an introductory look at IA-32 assembly, register significance, memory protection, stack usage, various WinDBG commands, call stacks, endianness, and portions of the Windows API. Knowledge gleaned will be used to develop an application designed to reveal and/or remove bombs from the WinMine playing grid. 
		* [Reverse Engineering Windows AFD.sys](https://recon.cx/2015/slides/recon2015-20-steven-vittitoe-Reverse-Engineering-Windows-AFD-sys.pdf)
		* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
			* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it’s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What’s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."
		* [Improving Automated Analysis of Windows x64 Binaries](http://uninformed.org/?v=all&a=18&t=sumry)
			* As Windows x64 becomes a more prominent platform, it will become necessary to develop techniques that improve the binary analysis process. In particular, automated techniques that can be performed prior to doing code or data flow analysis can be useful in getting a better understanding for how a binary operates. To that point, this paper gives a brief explanation of some of the changes that have been made to support Windows x64 binaries. From there, a few basic techniques are illustrated that can be used to improve the process of identifying functions, annotating their stack frames, and describing their exception handler relationships. Source code to an example IDA plugin is also included that shows how these techniques can be implemented. 
		* [Microsoft Patch Analysis for Exploitation](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t111-microsoft-patch-analysis-for-exploitation-stephen-sims)
			* Since the early 2000's Microsoft has distributed patches on the second Tuesday of each month. Bad guys, good guys, and many in-between compare the newly released patches to the unpatched version of the files to identify the security fixes. Many organizations take weeks to patch and the faster someone can reverse engineer the patches and get a working exploit written, the more valuable it is as an attack vector. Analysis also allows a researcher to identify common ways that Microsoft fixes bugs which can be used to find 0-days. Microsoft has recently moved to mandatory cumulative patches which introduces complexity in extracting patches for analysis. Join me in this presentation while I demonstrate the analysis of various patches and exploits, as well as the best-known method for modern patch extraction.
	* **Wireless**
		* [Reverse engineering radio weather station](http://blog.atx.name/reverse-engineering-radio-weather-station/)
		* [You can ring my bell! Adventures in sub-GHz RF land…](http://adamsblog.aperturelabs.com/2013/03/you-can-ring-my-bell-adventures-in-sub.html)
		* [Reverse engineering walk through; guy REs alarm system from shelf to replay](https://www.reddit.com/r/ReverseEngineering/comments/1hb7oy/a_series_about_basics_of_hardware_reverse/)
			* [Part 1:](http://cybergibbons.com/uncategorized/)reverse-engineering-a-wireless-burglar-alarm-system-part-1/
			* [Part 2:](http://cybergibbons.com/uncategorized/)reverse-engineering-a-wireless-burglar-alarm-part-2/)
			* [Part 3:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-3/)
			* [Part 4:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-4/)
			* [Part 5:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-5/)
			* [Part 6:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-6/)
			* [Part 7:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-7/)
			* [Part 8:](http://cybergibbons.com/uncategorized/reverse-engineering-a-wireless-burglar-alarm-part-8/)
		* [Blackbox Reversing an Electric Skateboard Wireless Protocol ](https://blog.lacklustre.net/posts/Blackbox_Reversing_an_Electric_Skateboard_Wireless_Protocol/)
		* [Reverse Engineering a 433MHz Motorised Blind RF Protocol](https://nickwhyte.com/post/2017/reversing-433mhz-raex-motorised-rf-blinds/)
		* [Flipping Bits and Opening Doors: Reverse Engineering the Linear Wireless Security DX Protocol](https://duo.com/blog/flipping-bits-and-opening-doors-reverse-engineering-the-linear-wireless-security-dx-protocol)
		* [Dissecting Industrial Wireless Implementations - DEF CON 25](https://github.com/voteblake/DIWI)



#### Sort
* [State of the art of network protocol reverse engineering tools](https://hal.inria.fr/hal-01496958/document)

* [linux-re-101](https://github.com/michalmalik/linux-re-101)
	* Cool resource relating to REing linux related things. Structured similar to this reference

* [Reversing Objective-C Binaries With the REobjc Module for IDA Pro - Todd Manning](https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro)
* [oleviewdotnet](https://github.com/tyranid/oleviewdotnet)
	* OleViewDotNet is a .NET 4 application to provide a tool which merges the classic SDK tools OleView and Test Container into one application. It allows you to find COM objects through a number of different views (e.g. by CLSID, by ProgID, by server executable), enumerate interfaces on the object and then create an instance and invoke methods. It also has a basic container to attack ActiveX objects to so you can see the display output while manipulating the data. 

* [Cryptoshark](https://github.com/frida/cryptoshark)
	* Interactive code tracer for reverse-engineering proprietary software 

* [Hide data inside pointers](http://arjunsreedharan.org/post/105266490272/hide-data-inside-pointers)
* [BinCAT](https://github.com/airbus-seclab/bincat)
	* BinCAT is a static Binary Code Analysis Toolkit, designed to help reverse engineers, directly from IDA.
* [Record and Replay Debugging with Firefox](https://developer.mozilla.org/en-US/docs/Mozilla/Debugging/Record_and_Replay_Debugging_Firefox)
* [rr](https://github.com/mozilla/rr)
	* rr is a lightweight tool for recording and replaying execution of applications (trees of processes and threads). More information about the project, including instructions on how to install, run, and build rr, is at http://rr-project.org.w

* [What are the methods to find hooked functions and APIs?](https://security.stackexchange.com/questions/17904/what-are-the-methods-to-find-hooked-functions-and-apis)

* [Taking a Snapshot and Viewing Processes - msdn.ms](https://msdn.microsoft.com/library/windows/desktop/ms686701.aspx)

* **QEMU**
	* [PyREBox](https://github.com/Cisco-Talos/pyrebox)
		* PyREBox is a Python scriptable Reverse Engineering sandbox. It is based on QEMU, and its goal is to aid reverse engineering by providing dynamic analysis and debugging capabilities from a different perspective. PyREBox allows to inspect a running QEMU VM, modify its memory or registers, and to instrument its execution, by creating simple scripts in python to automate any kind of analysis. QEMU (when working as a whole-system-emulator) emulates a complete system (CPU, memory, devices...). By using VMI techniques, it does not require to perform any modification into the guest operating system, as it transparently retrieves information from its memory at run-time.




* **Binary Instrumentation**
	* [Dynamic Binary Instrumentation Primer - rui - deniable.org ](http://deniable.org/reversing/binary-instrumentation)
		* "Dynamic Binary Instrumentation (DBI) is a method of analyzing the behavior of a binary application at runtime through the injection of instrumentation code" - Uninformed 2007


* [Etnaviv](https://github.com/etnaviv/etna_viv)
	* Project Etnaviv is an open source user-space driver for the Vivante GCxxx series of embedded GPUs. This repository contains reverse-engineering and debugging tools, and rnndb register documentation. It is not necessary to use this repository when building the driver.
Android
* [Tracing arbitrary Methods and Function calls on Android and iOS](https://techblog.mediaservice.net/2017/09/tracing-arbitrary-methods-and-function-calls-on-android-and-ios/)
	* [code](https://github.com/0xdea/frida-scripts)
* [Offensive & Defensive Android Reverse Engineering](https://github.com/rednaga/training/tree/master/DEFCON23)
	* Thinking like an attacker, you will learn to identify juicy Android targets, reverse engineer them, find vulnerabilities, and write exploits. We will deep dive into reverse engineering Android frameworks, applications, services, and boot loaders with the end goal of rooting devices. Approaching from a defensive perspective, we will learn quickly triage applications to determine maliciousness, exploits, and weaknesses. After learning triage skills, we will deep dive into malicious code along while dealing with packers, obfuscators, and anti-reversing techniques. Between the offensive and defensive aspects of this class, you should walk away with the fundamentals of reverse engineering and a strong understanding of how to further develop your skills for mobile platforms.
* [ARMwiki - hehyrick.co.uk](https://www.heyrick.co.uk/armwiki/Category:Introduction)
	* ARM processor wiki

	```
https://github.com/Wenzel/r2vmi
https://github.com/giMini/mimiDbg
https://github.com/samyk/frisky
https://hshrzd.wordpress.com/how-to-start/
http://www.hexacorn.com/blog/2018/04/14/how-to-become-the-best-malware-analyst-e-v-e-r/
https://github.com/yellowbyte/reverse-engineering-reference-manual
https://hex-rays.com/contests/2017/index.shtml
https://www.endgame.com/blog/technical-blog/introduction-windows-kernel-debugging
http://jamie-wong.com/post/reverse-engineering-instruments-file-format/
http://deniable.org/reversing/binary-instrumentation
http://terminus.rewolf.pl/terminus/
```
Symbolic Execution
	* [Theorem prover, symbolic execution and practical reverse-engineering](https://doar-e.github.io/presentations/securityday2015/SecDay-Lille-2015-Axel-0vercl0k-Souchet.html#/)
	* [A bibliography of papers related to symbolic execution](https://github.com/saswatanand/symexbib)

* [BOLO: Reverse Engineering — Part 1 (Basic Programming Concepts) - Daniel Bloom](https://medium.com/bugbountywriteup/bolo-reverse-engineering-part-1-basic-programming-concepts-f88b233c63b7)