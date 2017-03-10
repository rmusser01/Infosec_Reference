##System Internals of Windows; OS X; Linux; ARM

TOC
CULL

* [General Internals](#general)
* [Windows Internals](#winternals)
* [Linux Internals](#linux)
* [Windows Reference](#windowsref)
* [Linux Reference](#linuxref)
* [OS X Reference](#osx)
* [ARM Reference](#ARM)



To Do:
*	Clear Cull List
*	Split sections into reference material and writeup material(quick vs long reference)

CULL


http://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/?utm_content=buffere95dc&utm_medium=social&utm_source=twitter.com&utm_campaign=buffer


http://duartes.org/gustavo/blog/post/memory-translation-and-segmentation/ 

http://duartes.org/gustavo/blog/category/internals/

https://www.bnxnet.com/wp-content/uploads/2015/01/WinAPIs_for_hackers.pdf


https://xorl.wordpress.com/2010/10/14/linux-glibc-stack-canary-values/

https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

https://hshrzd.wordpress.com/2016/03/19/introduction-to-ads-alternate-data-streams/ 


https://tribalchicken.com.au/technical/recovering-bitlocker-keys-on-windows-8-1-and-10/ 


[Intel SGX Explained](https://eprint.iacr.org/2016/086.pdf)
* This paper analyzes Intel SGX, based on the 3 pa- pers [ 14 , 78 , 137 ] that introduced it, on the Intel Software Developer’s Manual [ 100 ] (which supersedes the SGX manuals [ 94 , 98 ]), on an ISCA 2015 tutorial [ 102 ], and on two patents [ 108 , 136 ]. We use the papers, reference manuals, and tutorial as primary data sources, and only draw on the patents to fill in missing information. This  paper’s  contributions  are  a  summary  of  the Intel-specific architectural and micro-architectural details needed to understand SGX, a detailed and structured pre- sentation of the publicly available information on SGX, a series of intelligent guesses about some important but undocumented aspects of SGX, and an analysis of SGX’s security properties.

[MS "reg" command] reference(http://www.computerhope.com/reg.htm)

[Event log explanations for various systems(not just windows)](http://eventopedia.cloudapp.net/Events/?/Operating+System)

[Hyper-V debugging for beginners[(https://hvinternals.blogspot.fr/2015/10/hyper-v-debugging-for-beginners.html)

[Hyper-V internals](https://hvinternals.blogspot.fr/2015/10/hyper-v-internals.html)




http://blogs.technet.com/b/markrussinovich/archive/2008/11/17/3155406.aspx



###<a name="general">General Internals</a>
[C Function Call Conventions and the Stack](https://archive.is/o2nD5)

[The Anatomy of an Executable](https://github.com/mewrev/dissection)

[What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)

[Linux kernel development(walkthrough)](https://github.com/0xAX/linux-insides/blob/master/Misc/contribute.md)



###<a name="winref">Windows Reference</a>

###<a name="Winternals">Windows Internals</a>

[theForger's Win32 API Programming Tutorial](http://www.winprog.org/tutorial/)

[About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)

[Windows - Application Shims](https://technet.microsoft.com/en-us/library/dd837644%28v=ws.10%29.aspx)

[A Crash Course on the Depths of Win32™ Structured Exception Handling](https://www.microsoft.com/msj/0197/exception/exception.aspx)

[Compiler Security Checks In Depth - MSDN Library](https://msdn.microsoft.com/library/aa290051.aspx)

[LSA Authentication](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326%28v=vs.85%29.aspx)
* LSA Authentication describes the parts of the Local Security Authority (LSA) that applications can use to authenticate and log users on to the local system. It also describes how to create and call authentication packages and security packages.

[Preventing the Exploitation of Structured Exception Handler (SEH) Overwrites with SEHOP](https://blogs.technet.microsoft.com/srd/2009/02/02/preventing-the-exploitation-of-structured-exception-handler-seh-overwrites-with-sehop/)

[Peering Inside the PE: A Tour of the Win32 Portable Executable File Format](https://msdn.microsoft.com/en-us/library/ms809762.aspx?utm_content=buffer4588c&utm_medium=social&utm_source=twitter.com&utm_campaign=buffer)

[PEB Structure 32/64 pdf](http://blog.rewolf.pl/blog/wp-content/uploads/2013/03/PEB_Evolution.pdf)

[TechNet Library: About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)

[WinHTTP](https://msdn.microsoft.com/en-us/library/windows/desktop/aa382925%28v=vs.85%29.aspx)

[WinINet](https://msdn.microsoft.com/en-us/library/windows/desktop/aa383630%28v=vs.85%29.aspx)

[WinINet vs WinHTTP](https://msdn.microsoft.com/en-us/library/windows/desktop/hh227298%28v=vs.85%29.aspx)

[Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)

[pagexec - GRSEC](https://pax.grsecurity.net/docs/pageexec.txt)

[How Do Windows NT System Calls REALLY Work?](http://www.codeguru.com/cpp/w-p/system/devicedriverdevelopment/article.php/c8035/How-Do-Windows-NT-System-Calls-REALLY-Work.htm)

[Windows 8 Security and ARM](http://2012.ruxconbreakpoint.com/assets/Uploads/bpx/alex-breakpoint2012.pdf)

[Intercepting System Calls on x86_64 Windows](http://jbremer.org/intercepting-system-calls-on-x86_64-windows/)

[Application Compatibility in Windows](https://technet.microsoft.com/en-us/windows/jj863248)

[Introduction to Windows Kernel Security](http://blog.cmpxchg8b.com/2013/05/introduction-to-windows-kernel-security.html)

[Technical Overview of Windows UEFI Startup Process](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)

[Windows 8 BOot](http://technet.microsoft.com/en-US/windows/dn168167.aspx)

[Windows 8 ASLR Explained](http://blog.ptsecurity.com/2012/12/windows-8-aslr-internals.html)

[Inside the Windows Vista Kernel: Part 1](http://technet.microsoft.com/en-us/magazine/2007.02.vistakernel.aspx)

[How Control Flow Guard Drastically Caused Windows 8.1 Address Space and Behavior Changes](http://www.alex-ionescu.com/?p=246)

[Pushing the Limits of Windows: Virtual Memory](http://blogs.technet.com/b/markrussinovich/archive/2008/11/17/3155406.aspx)

[WinPrefetchView v1.25](http://www.nirsoft.net/utils/win_prefetch_view.html)
* Each time that you run an application in your system, a Prefetch file which contains information about the files loaded by the application is created by Windows operating system. The information in the Prefetch file is used for optimizing the loading time of the application in the next time that you run it. 
WinPrefetchView is a small utility that reads the Prefetch files stored in your system and display the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot. 

[Windows 8 Security and ARM](http://2012.ruxconbreakpoint.com/assets/Uploads/bpx/alex-breakpoint2012.pdf)

[Windows - Named Pipes](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365590%28v=vs.85%29.aspx)

[License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)

[PE File Format Graphs](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html?view=mosaic)

[Know your Windows Processes or Die Trying](https://sysforensics.org/2014/01/know-your-windows-processes.html)
* Excellent quick reference on Windows proccesses with a focus on Win7. Good resource.

[Windows Program Automatic Startup Locations](http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)

[PE File Format Graphs](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html?view=mosaic)

[Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610]

[Utilizing SysInternal Tools for IT Pros](http://www.microsoftvirtualacademy.com/training-courses/utilizing-sysinternals-tools-for-it-pros#fbid=1IKsqgyvnWp)

[License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)







###<a name="linux">Linux General</a>

###<a name="linux">Linux Internals</a>
[linux-insides](https://www.gitbook.com/book/0xax/linux-insides/details)
* A series of posts about the linux kernel. The goal is simple - to share my modest knowledge about the internals of the linux kernel and help people who are interested in the linux kernel, and other low-level subject matter.

[Introduction to Linux - Machtelt Garrels](http://www.tldp.org/LDP/intro-linux/html/intro-linux.html)
* Excellent doc covering every aspect of linux. Deserves at least 1 skim through.

[Bash Guide for Beginners](http://www.tldp.org/LDP/Bash-Beginners-Guide/html/Bash-Beginners-Guide.html)

[Linux Documentation Project](http://www.tldp.org/)
* The Linux Documentation Project is working towards developing free, high quality documentation for the Linux operating system. The overall goal of the LDP is to collaborate in all of the issues of Linux documentation.
##System Internals of Windows; OS X; Linux


[FlexSC: Flexible System Call Scheduling with Exception-Less System Calls](https://www.cs.cmu.edu/~chensm/Big_Data_reading_group/papers/flexsc-osdi10.pdf)

[List of Linux/i386 system calls](http://asm.sourceforge.net/syscall.html)

[Linux Syscall Table](http://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html)
* Complete listing of all Linux Syscalls

[Linux Kernel Explanation/Walk through](http://www.faqs.org/docs/Linux-HOWTO/KernelAnalysis-HOWTO.html)

[Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

[Kernel booting process](https://github.com/0xAX/linux-insides/tree/master/Booting)
* This chapter describes linux kernel booting process.

[Memory Management: Paging](https://www.cs.rutgers.edu/~pxk/416/notes/09a-paging.html)

[Linux Device Drivers book](http://www.makelinux.net/ldd3/)
[X Window System Explained](https://magcius.github.io/xplain/article/index.html)

[Understanding the ELF](https://medium.com/@MrJamesFisher/understanding-the-elf-4bd60daac571)
[Linkers and Loaders - Book](http://www.iecc.com/linker/)
* These are the manuscript chapters for my Linkers and Loaders, published by Morgan-Kaufman. See the book's web site for ordering information. 
* All chapters are online for free at the above site.

[ELF Format](http://www.skyfree.org/linux/references/ELF_Format.pdf)
[Linker and Libraries](http://docs.oracle.com/cd/E19457-01/801-6737/801-6737.pdf)

Linux Filesystem infographic
* [Part 1](http://i.imgur.com/EU6ga.jpg)
* [Part 2](http://i.imgur.com/S5Ds2.jpg)

[Anatomy of a program in memory](http://duartes.org/gustavo/blog/post/anatomy-of-a-program-in-memory/) 
* Writeup on the structure of program memory in Linux.

[How the Kernel manages Memory - Linux](http://duartes.org/gustavo/blog/post/how-the-kernel-manages-your-memory/)

[Linux Documentation Project](http://www.tldp.org/)

[linux-insides](https://www.gitbook.com/book/0xax/linux-insides/details)
* A series of posts about the linux kernel and its insides.  The goal is simple - to share my modest knowledge about the internals of the linux kernel and help people who are interested in the linux kernel, and other low-level subject matter.

[List of Linux/i386 system calls](http://asm.sourceforge.net/syscall.html)

[Linux Syscall Table](http://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html)
* Complete listing of all Linux Syscalls

[Memory Management: Paging](https://www.cs.rutgers.edu/~pxk/416/notes/09a-paging.html)

[Linux Device Drivers book](http://www.makelinux.net/ldd3/)
[X Window System Explained](https://magcius.github.io/xplain/article/index.html)

[Understanding the ELF](https://medium.com/@MrJamesFisher/understanding-the-elf-4bd60daac571)
[Linkers and Loaders - Book](http://www.iecc.com/linker/)
* These are the manuscript chapters for my Linkers and Loaders, published by Morgan-Kaufman. See the book's web site for ordering information. 
* All chapters are online for free at the above site.

[ELF Format](http://www.skyfree.org/linux/references/ELF_Format.pdf)
[Linker and Libraries](http://docs.oracle.com/cd/E19457-01/801-6737/801-6737.pdf)

Linux Filesystem infographic
* [Part 1](http://i.imgur.com/EU6ga.jpg)
* [Part 2](http://i.imgur.com/S5Ds2.jpg)

[Anatomy of a program in memory](http://duartes.org/gustavo/blog/post/anatomy-of-a-program-in-memory/) 
* Writeup on the structure of program memory in Linux.

[How the Kernel manages Memory - Linux](http://duartes.org/gustavo/blog/post/how-the-kernel-manages-your-memory/)

[Linux Documentation Project](http://www.tldp.org/)

[Linux Kernel Explanation/Walk through](http://www.faqs.org/docs/Linux-HOWTO/KernelAnalysis-HOWTO.html)

[Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

[Understanding !PTE - Non-PAE and X64](http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx?Redirected=true

[linux-insides](https://www.gitbook.com/book/0xax/linux-insides/details)
* A series of posts about the linux kernel. The goal is simple - to share my modest knowledge about the internals of the linux kernel and help people who are interested in the linux kernel, and other low-level subject matter.

[linux-internals](https://github.com/0xAX/linux-insides)
* A series of posts about the linux kernel and its insides.  The goal is simple - to share my modest knowledge about the internals of the linux kernel and help people who are interested in the linux kernel, and other low-level subject matter.

[Introduction to Linux - Machtelt Garrels](http://www.tldp.org/LDP/intro-linux/html/intro-linux.html)
* Excellent doc covering every aspect of linux. Deserves at least 1 skim through.

[Bash Guide for Beginners](http://www.tldp.org/LDP/Bash-Beginners-Guide/html/Bash-Beginners-Guide.html)

[Linux Documentation Project](http://www.tldp.org/)
* The Linux Documentation Project is working towards developing free, high quality documentation for the Linux operating system. The overall goal of the LDP is to collaborate in all of the issues of Linux documentation.

[Foreign LINUX](https://github.com/wishstudio/flinux)
* Foreign LINUX is a dynamic binary translator and a Linux system call interface emulator for the Windows platform. It is capable of running unmodified Linux binaries on Windows without any drivers or modifications to the system. This provides another way of running Linux applications under Windows in constrast to Cygwin and other tools.

[Linux Kernel Explanation/Walk through](http://www.faqs.org/docs/Linux-HOWTO/KernelAnalysis-HOWTO.html)






###<a name="ARM">ARM References</a>



[A Detailed Analysis of Contemporary ARM and x86 Architectures](http://research.cs.wisc.edu/vertical/papers/2013/isa-power-struggles-tr.pdf)
* RISC vs. CISC wars raged in the 1980s when chip area andprocessor design complexity were the primary constraints anddesktops and servers exclusively dominated the computing land-scape. Today, energy and power are the primary design con-straints and the computing landscape is significantly different:growth in tablets and smartphones running ARM (a RISC ISA)is surpassing that of desktops and laptops running x86 (a CISCISA). Further, the traditionally low-power ARM ISA is enter-ing the high-performance server market, while the traditionallyhigh-performance x86 ISA is entering the mobile low-power de-vice market. Thus, the question of whether ISA plays an intrinsicrole in performance or energy efficiency is becoming important,and we seek to answer this question through a detailed mea-surement based study on real hardware running real applica-tions. We analyze measurements on the ARM Cortex-A8 andCortex-A9 and Intel Atom and Sandybridge i7 microprocessorsover workloads spanning mobile, desktop, and server comput-ing. Our methodical investigation demonstrates the role of ISAin modern microprocessors’ performance and energy efficiency.We find that ARM and x86 processors are simply engineeringdesign points optimized for different levels of performance, andthere is nothing fundamentally more energy efficient in one ISAclass or the other. The ISA being RISC or CISC seems irrelevant.



[ARM Documentation](http://infocenter.arm.com/help/index.jsp?noscript=1)





###<a name="osx">OS X Internals</a>

[Instruments - OS X system analysis](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/Introduction/Introduction.html)
* Instruments is a performance-analysis and testing tool for dynamically tracing and profiling OS X and iOS code. It is a flexible and powerful tool that lets you track a process, collect data, and examine the collected data. In this way, Instruments helps you understand the behavior of both user apps and the operating system.







