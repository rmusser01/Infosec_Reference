## System Internals of Windows; OS X; Linux; ARM

### TOC

* [General Internals](#general)
* [Windows Internals](#winternals)
* Windows 
* [Kerberos / Related](#kerberos)
* [Linux Internals](#linux)
* [Windows Reference](#windowsref)
* [Linux Reference](#linuxref)
* [OS X Reference](#osx)
* [ARM Reference](#ARM)



##### To Do:
* Fix ToC so its accurate
*	Split sections into reference material and writeup material(quick vs long reference)
* Further categorize sections (network vs memory vs exploit mitigations vs feature)


#### Sort

[Waitfor - tehcnet](https://technet.microsoft.com/en-us/library/cc731613(v=ws.11).aspx?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&iid=22f4306f9238443891cea105281cfd3f&uid=150127534&nid=244+289476616)

[Authentication Registry Keys - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374737(v=vs.85).aspx)
* When it installs a network provider, your application should create the registry keys and values described in this topic. These keys and values provide information to the MPR about the network providers installed on the system. The MPR checks these keys when it starts and loads the network provider DLLs that it finds.

[](http://archive.msdn.microsoft.com/ShellRevealed/Release/ProjectReleases.aspx?ReleaseId=2871)

[BCDEdit /dbgsettings - msdn](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542187(v=vs.85).aspx)

[windows-syscall-table](https://github.com/tinysec/windows-syscall-table)
* windows syscall table from xp ~ 10 rs2

[Debugging Functions - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679303.aspx)

#### End Sort


---------------------
## <a name="general">General Internals</a>
[C Function Call Conventions and the Stack](https://archive.is/o2nD5)

[The Anatomy of an Executable](https://github.com/mewrev/dissection)

[What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)

[Linux kernel development(walkthrough)](https://github.com/0xAX/linux-insides/blob/master/Misc/contribute.md)

[Event log explanations for various systems(not just windows)](http://eventopedia.cloudapp.net/Events/?/Operating+System)

[duartes.org - internals](http://duartes.org/gustavo/blog/category/internals/)

[The little book about OS development](https://littleosbook.github.io/)

[How to Make a Computer Operating System in C++](https://github.com/SamyPesse/How-to-Make-a-Computer-Operating-System)

---------------------
## <a name="winref">Windows Reference</a>

### <a name="Winternals">Windows Internals</a>

[theForger's Win32 API Programming Tutorial](http://www.winprog.org/tutorial/)

[x86 Disassembly/Windows Executable Files - WikiBooks](https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files)

[WinAPIs for Hackers](https://www.bnxnet.com/wp-content/uploads/2015/01/WinAPIs_for_hackers.pdf)

[About Atom Tables](https://msdn.microsoft.com/en-us/library/windows/desktop/ms649053(v=vs.85).aspx)

[GlobalGetAtomName function](https://msdn.microsoft.com/en-us/library/windows/desktop/ms649063(v=vs.85).aspx)

[windows-operating-system-archaeology](https://github.com/subTee/windows-operating-system-archaeology)
* subTee stuff

[BATTLE OF SKM AND IUM - How Windows 10 rewrites OS Architecture - Alex Ionescu](http://www.alex-ionescu.com/blackhat2015.pdf)

[RtlEncryptMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa387693(v=vs.85).aspx)

[RtlDecryptMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa387692(v=vs.85).aspx)



---------------------
#### Access Control

[Mandatory Integrity Control](https://msdn.microsoft.com/en-gb/library/windows/desktop/bb648648(v=vs.85).aspx)

[Windows Access Control Demystified](http://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=E1A09F166B29C17D2CD38C70A02576E4?doi=10.1.1.88.1930&rep=rep1&type=pdf)

---------------------
##### App Containers
[Demystifying AppContainers in Windows 8 (Part I)](https://blog.nextxpert.com/2013/01/31/demystifying-appcontainers-in-windows-8-part-i/)

[AppContainer Isolation](https://msdn.microsoft.com/en-us/library/windows/desktop/mt595898(v=vs.85).aspx)



#### Credential Provider

[Credential Providers in Windows 10 - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/mt158211(v=vs.85).aspx)

[ICredentialProvider interface - msdn](https://msdn.microsoft.com/en-us/library/bb776042(v=vs.85).aspx)
* Exposes methods used in the setup and manipulation of a credential provider. All credential providers must implement this interface.


[Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))

[Winlogon and Credential Providers](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648647(v=vs.85).aspx)
* Winlogon is the Windows module that performs interactive logon for a logon session. Winlogon behavior can be customized by implementing and registering a Credential Provider.

[Registering Network Providers and Credential Managers - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379389(v=vs.85).aspx)

[V2 Credential Provider Sample - code.msdn](https://code.msdn.microsoft.com/windowsapps/V2-Credential-Provider-7549a730)
* Demonstrates how to build a v2 credential provider that makes use of the new capabilities introduced to credential provider framework in Windows 8 and Windows 8.1.

[Custom Credential Provider for Password Reset - blogs.technet](https://blogs.technet.microsoft.com/aho/2009/11/14/custom-credential-provider-for-password-reset/)

[Starting to build your own Credential Provider](https://blogs.msmvps.com/alunj/2011/02/21/starting-to-build-your-own-credential-provider/)
* If you’re starting to work on a Credential Provider (CredProv or CP, for short) for Windows Vista, Windows Server 2008, Windows Server 2008 R2 or Windows 7, there are a few steps I would strongly recommend you take, because it will make life easier for you.



---------------------
#### Documentation

[AppInit_DLLs in Windows 7 and Windows Server 2008 R2](https://msdn.microsoft.com/en-us/library/windows/desktop/dd744762(v=vs.85).aspx)

[Antimalware Scan Interface Reference](https://msdn.microsoft.com/en-us/library/windows/desktop/dn889588(v=vs.85).aspx)

[Minimal COM object registration](https://blogs.msdn.microsoft.com/larryosterman/2006/01/05/minimal-com-object-registration/)

[Windows Data Protection](https://msdn.microsoft.com/en-us/library/ms995355.aspx)

[The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)





---------------------
##### Exploit Mitigations
[Compiler Security Checks In Depth - MSDN Library](https://msdn.microsoft.com/library/aa290051.aspx)

[A Crash Course on the Depths of Win32™ Structured Exception Handling](https://www.microsoft.com/msj/0197/exception/exception.aspx)

[Antimalware Scan Interface Reference](https://msdn.microsoft.com/en-us/library/windows/desktop/dn889588)
* prevents certain kinds of powershell attacks

[Compiler Security Checks In Depth - MSDN Library](https://msdn.microsoft.com/library/aa290051.aspx)





---------------------
##### Memory

[Pushing the Limits of Windows: Virtual Memory](http://blogs.technet.com/b/markrussinovich/archive/2008/11/17/3155406.aspx)

[Memory Translation and Segmentation](http://duartes.org/gustavo/blog/post/memory-translation-and-segmentation/)

[Exploring Windows virtual memory management](http://www.triplefault.io/2017/08/exploring-windows-virtual-memory.html)




---------------------
##### Networking

[WinHTTP](https://msdn.microsoft.com/en-us/library/windows/desktop/aa382925%28v=vs.85%29.aspx)

[WinINet](https://msdn.microsoft.com/en-us/library/windows/desktop/aa383630%28v=vs.85%29.aspx)

[WinINet vs WinHTTP](https://msdn.microsoft.com/en-us/library/windows/desktop/hh227298%28v=vs.85%29.aspx)





---------------------
##### PE32/Processes/Threads/etc
[About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)

[PE File Format Graphs](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html?view=mosaic)

[Peering Inside the PE: A Tour of the Win32 Portable Executable File Format](https://msdn.microsoft.com/en-us/library/ms809762.aspx?utm_content=buffer4588c&utm_medium=social&utm_source=twitter.com&utm_campaign=buffer)

[TechNet Library: About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)

[A Crash Course on the Depths of Win32™ Structured Exception Handling](https://www.microsoft.com/msj/0197/exception/exception.aspx)

[What is a DLL?](https://support.microsoft.com/en-us/help/815065/what-is-a-dll)
* This article describes what a dynamic link library (DLL) is and the various issues that may occur when you use DLLs.  Then, this article describes some advanced issues that you should consider when you develop your own DLLs. In describing what a DLL is, this article describes dynamic linking methods, DLL dependencies, DLL entry points, exporting DLL functions, and DLL troubleshooting tools.

[Run-Time Dynamic Linking](https://msdn.microsoft.com/en-us/library/ms685090.aspx)

[Thread Local Storage](https://msdn.microsoft.com/en-us/library/ms686749.aspx)

[Windows 8 BOot](http://technet.microsoft.com/en-US/windows/dn168167.aspx)

[PEB32 and PEB64 in one definition](http://blog.rewolf.pl/blog/?p=294)

[Evolution of Process Environment Block (PEB)](http://blog.rewolf.pl/blog/?p=573)

[VirtualAlloc function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx)

[Processes, Threads, and Jobs in the Windows Operating System](https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=2)




---------------------
##### Registry

[What registry entries are needed to register a COM object.](https://blogs.msdn.microsoft.com/larryosterman/2006/01/11/what-registry-entries-are-needed-to-register-a-com-object/)


--------------
### Symbol Files
[Process Security and Access Rights - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx)

[OpenProcessToken function - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295%28v=vs.85%29.aspx)

[Symbols and Symbol Files - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols-and-symbol-files)

[Symbol Files - docs ms](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)

[microsoft-pdb](https://github.com/Microsoft/microsoft-pdb)
* This repo contains information from Microsoft about the PDB (Program Database) Symbol File format.

[Public and Private Symbols - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/public-and-private-symbols)

[How to Inspect the Content of a Program Database (PDB) File](https://www.codeproject.com/Articles/37456/How-To-Inspect-the-Content-of-a-Program-Database-P)

[microsoft-pdb](https://github.com/Microsoft/microsoft-pdb)
* This repo contains information from Microsoft about the PDB (Program Database) Symbol File format.

[Symbol Files](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)
* Normally, debugging information is stored in a symbol file separate from the executable. The implementation of this debugging information has changed over the years, and the following documentation will provide guidance regarding these various implementations .





---------------------
##### System Features

[Windows - Application Shims](https://technet.microsoft.com/en-us/library/dd837644%28v=ws.10%29.aspx)

[Application Compatibility in Windows](https://technet.microsoft.com/en-us/windows/jj863248)

[Windows - Application Shims](https://technet.microsoft.com/en-us/library/dd837644%28v=ws.10%29.aspx)

[LSA Authentication](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326%28v=vs.85%29.aspx)
* LSA Authentication describes the parts of the Local Security Authority (LSA) that applications can use to authenticate and log users on to the local system. It also describes how to create and call authentication packages and security packages.

[Windows - Named Pipes](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365590%28v=vs.85%29.aspx)





---------------------
#### Writeups

[Preventing the Exploitation of Structured Exception Handler (SEH) Overwrites with SEHOP](https://blogs.technet.microsoft.com/srd/2009/02/02/preventing-the-exploitation-of-structured-exception-handler-seh-overwrites-with-sehop/)

[PEB Structure 32/64 pdf](http://blog.rewolf.pl/blog/wp-content/uploads/2013/03/PEB_Evolution.pdf)

[Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)

[Intercepting System Calls on x86_64 Windows](http://jbremer.org/intercepting-system-calls-on-x86_64-windows/)

[Introduction to Windows Kernel Security](http://blog.cmpxchg8b.com/2013/05/introduction-to-windows-kernel-security.html)

[Technical Overview of Windows UEFI Startup Process](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)

[Windows 8 ASLR Explained](http://blog.ptsecurity.com/2012/12/windows-8-aslr-internals.html)

[Know your Windows Processes or Die Trying](https://sysforensics.org/2014/01/know-your-windows-processes.html)
* Excellent quick reference on Windows proccesses with a focus on Win7. Good resource.


[Windows Program Automatic Startup Locations](http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)

[Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)

[Inside the Windows Vista Kernel: Part 1](http://technet.microsoft.com/en-us/magazine/2007.02.vistakernel.aspx)

[How Control Flow Guard Drastically Caused Windows 8.1 Address Space and Behavior Changes](http://www.alex-ionescu.com/?p=246)

[Windows Filtering Platform: Persistent state under the hood](http://blog.quarkslab.com/windows-filtering-platform-persistent-state-under-the-hood.html)

[Hyper-V debugging for beginner](https://hvinternals.blogspot.fr/2015/10/hyper-v-debugging-for-beginners.html)

[Hyper-V internals](https://hvinternals.blogspot.fr/2015/10/hyper-v-internals.html)

[Windows Operating System Archaeology](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology)

[Understanding Windows at a deeper level - Sessions, Window Stations, and Desktops](https://brianbondy.com/blog/100/understanding-windows-at-a-deeper-level-sessions-window-stations-and-desktops)

[MS "reg" commandreference](http://www.computerhope.com/reg.htm)

[Introduction to ADS: Alternate Data Streams](https://hshrzd.wordpress.com/2016/03/19/introduction-to-ads-alternate-data-streams/)

[Detecting stealthier cross-process injection techniques with Windows Defender ATP: Process hollowing and atom bombing](https://blogs.technet.microsoft.com/mmpc/2017/07/12/detecting-stealthier-cross-process-injection-techniques-with-windows-defender-atp-process-hollowing-and-atom-bombing/)

[Unkillable Processes](https://blogs.technet.microsoft.com/markrussinovich/2005/08/17/unkillable-processes/)

[Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)

[Advanced Desktop Application Sandboxing via AppContainer](https://www.malwaretech.com/2015/09/advanced-desktop-application-sandboxing.html)






---------------------
#### Presentations & Talks

[Windows 8 Security and ARM](http://2012.ruxconbreakpoint.com/assets/Uploads/bpx/alex-breakpoint2012.pdf)

[How Do Windows NT System Calls REALLY Work?](http://www.codeguru.com/cpp/w-p/system/devicedriverdevelopment/article.php/c8035/How-Do-Windows-NT-System-Calls-REALLY-Work.htm)

[WinPrefetchView v1.25](http://www.nirsoft.net/utils/win_prefetch_view.html)
* Each time that you run an application in your system, a Prefetch file which contains information about the files loaded by the application is created by Windows operating system. The information in the Prefetch file is used for optimizing the loading time of the application in the next time that you run it. 
WinPrefetchView is a small utility that reads the Prefetch files stored in your system and display the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot. 

[Windows 8 Security and ARM](http://2012.ruxconbreakpoint.com/assets/Uploads/bpx/alex-breakpoint2012.pdf)

[License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)

[Utilizing SysInternal Tools for IT Pros](http://www.microsoftvirtualacademy.com/training-courses/utilizing-sysinternals-tools-for-it-pros#fbid=1IKsqgyvnWp)

[License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)














---------------------
### Active Directory

[Active Directory Architecture](https://technet.microsoft.com/en-us/library/bb727030.aspx)

[AD Local Domain groups, Global groups and Universal groups.](https://ss64.com/nt/syntax-groups.html)

[Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths)
*  Active Directory Control Paths auditing and graphing tools 




---------------------
#### <a name="kerberos">Kerberos Related</a>
[Kerberos Delegation, SPNs and More...](https://www.coresecurity.com/blog/kerberos-delegation-spns-and-more)

[Article Explaining what the KRBTGT account in AD is](http://windowsitpro.com/security/q-what-krbtgt-account-used-active-directory-ad-environment)




---------------------
### <a name="linux">Linux General</a>

[Introduction to Linux - Machtelt Garrels](http://www.tldp.org/LDP/intro-linux/html/intro-linux.html)
* Excellent doc covering every aspect of linux. Deserves at least 1 skim through.

[Linux Documentation Project](http://www.tldp.org/)
* The Linux Documentation Project is working towards developing free, high quality documentation for the Linux operating system. The overall goal of the LDP is to collaborate in all of the issues of Linux documentation.

[Bash Guide for Beginners](http://www.tldp.org/LDP/Bash-Beginners-Guide/html/Bash-Beginners-Guide.html)

[pagexec - GRSEC](https://pax.grsecurity.net/docs/pageexec.txt)


---------------------
### <a name="linux">Linux Internals</a>

[linux-insides](https://www.gitbook.com/book/0xax/linux-insides/details)
* A series of posts about the linux kernel. The goal is simple - to share my modest knowledge about the internals of the linux kernel and help people who are interested in the linux kernel, and other low-level subject matter.

[Introduction to Linux - Machtelt Garrels](http://www.tldp.org/LDP/intro-linux/html/intro-linux.html)
* Excellent doc covering every aspect of linux. Deserves at least 1 skim through.

[Linux Kernel Security Subsystem Wiki](https://kernsec.org/wiki/index.php/Main_Page)
* This is the Linux kernel security subsystem wiki, a resource for developers and users. 


---------------------
#### Compilers/Exploit Mitigations

[Linkers and Loaders - Book](http://www.iecc.com/linker/)
* These are the manuscript chapters for my Linkers and Loaders, published by Morgan-Kaufman. See the book's web site for ordering information. 
* All chapters are online for free at the above site.

[Linker and Libraries](http://docs.oracle.com/cd/E19457-01/801-6737/801-6737.pdf)




---------------------
#### Drivers

[Linux Device Drivers book](http://www.makelinux.net/ldd3/)


---------------------
#### FileSystems

* Linux Filesystem infographic
* [Part 1](http://i.imgur.com/EU6ga.jpg)
* [Part 2](http://i.imgur.com/S5Ds2.jpg)


---------------------
#### Kernel

[Linux Kernel Explanation/Walk through](http://www.faqs.org/docs/Linux-HOWTO/KernelAnalysis-HOWTO.html)

[Kernel booting process](https://github.com/0xAX/linux-insides/tree/master/Booting)
* This chapter describes linux kernel booting process.

[How the Kernel manages Memory - Linux](http://duartes.org/gustavo/blog/post/how-the-kernel-manages-your-memory/)








---------------------
#### Memory

[Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

[Memory Management: Paging](https://www.cs.rutgers.edu/~pxk/416/notes/09a-paging.html)

[Anatomy of a program in memory](http://duartes.org/gustavo/blog/post/anatomy-of-a-program-in-memory/) 
* Writeup on the structure of program memory in Linux.

[Understanding !PTE - Non-PAE and X64](http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx?Redirected=true)

[Linux GLibC Stack Canary Values](https://xorl.wordpress.com/2010/10/14/linux-glibc-stack-canary-values/)

[Stack Smashing Protector](http://wiki.osdev.org/Stack_Smashing_Protector)

[Memory Translation and Segmentation](http://duartes.org/gustavo/blog/post/memory-translation-and-segmentation/)



---------------------
#### Process Structure/Syscalls

[FlexSC: Flexible System Call Scheduling with Exception-Less System Calls](https://www.cs.cmu.edu/~chensm/Big_Data_reading_group/papers/flexsc-osdi10.pdf)

[List of Linux/i386 system calls](http://asm.sourceforge.net/syscall.html)

[Linux Syscall Table](http://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html)
* Complete listing of all Linux Syscalls



---------------------
#### ELF

[The 101 of ELF Binaries on Linux: Understanding and Analysis](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)

[Understanding the ELF](https://medium.com/@MrJamesFisher/understanding-the-elf-4bd60daac571)

[ELF Format](http://www.skyfree.org/linux/references/ELF_Format.pdf)



---------------------
#### X 

[X Window System Explained](https://magcius.github.io/xplain/article/index.html)


[Foreign LINUX](https://github.com/wishstudio/flinux)
* Foreign LINUX is a dynamic binary translator and a Linux system call interface emulator for the Windows platform. It is capable of running unmodified Linux binaries on Windows without any drivers or modifications to the system. This provides another way of running Linux applications under Windows in constrast to Cygwin and other tools.


















---------------------
### <a name="ARM">ARM References</a>



[A Detailed Analysis of Contemporary ARM and x86 Architectures](http://research.cs.wisc.edu/vertical/papers/2013/isa-power-struggles-tr.pdf)
* RISC vs. CISC wars raged in the 1980s when chip area andprocessor design complexity were the primary constraints anddesktops and servers exclusively dominated the computing land-scape. Today, energy and power are the primary design con-straints and the computing landscape is significantly different:growth in tablets and smartphones running ARM (a RISC ISA)is surpassing that of desktops and laptops running x86 (a CISCISA). Further, the traditionally low-power ARM ISA is enter-ing the high-performance server market, while the traditionallyhigh-performance x86 ISA is entering the mobile low-power de-vice market. Thus, the question of whether ISA plays an intrinsicrole in performance or energy efficiency is becoming important,and we seek to answer this question through a detailed mea-surement based study on real hardware running real applica-tions. We analyze measurements on the ARM Cortex-A8 andCortex-A9 and Intel Atom and Sandybridge i7 microprocessorsover workloads spanning mobile, desktop, and server comput-ing. Our methodical investigation demonstrates the role of ISAin modern microprocessors’ performance and energy efficiency.We find that ARM and x86 processors are simply engineeringdesign points optimized for different levels of performance, andthere is nothing fundamentally more energy efficient in one ISAclass or the other. The ISA being RISC or CISC seems irrelevant.

[ARM Documentation](http://infocenter.arm.com/help/index.jsp?noscript=1)




---------------------
### <a name="osx">OS X Internals</a>

[Instruments - OS X system analysis](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/Introduction/Introduction.html)
* Instruments is a performance-analysis and testing tool for dynamically tracing and profiling OS X and iOS code. It is a flexible and powerful tool that lets you track a process, collect data, and examine the collected data. In this way, Instruments helps you understand the behavior of both user apps and the operating system.






---------------------
### Other 
[Intel SGX Explained](https://eprint.iacr.org/2016/086.pdf)
* This paper analyzes Intel SGX, based on the 3 pa- pers [ 14 , 78 , 137 ] that introduced it, on the Intel Software Developer’s Manual [ 100 ] (which supersedes the SGX manuals [ 94 , 98 ]), on an ISCA 2015 tutorial [ 102 ], and on two patents [ 108 , 136 ]. We use the papers, reference manuals, and tutorial as primary data sources, and only draw on the patents to fill in missing information. This  paper’s  contributions  are  a  summary  of  the Intel-specific architectural and micro-architectural details needed to understand SGX, a detailed and structured pre- sentation of the publicly available information on SGX, a series of intelligent guesses about some important but undocumented aspects of SGX, and an analysis of SGX’s security properties.