# System Internals of Windows; OS X; Linux; ARM

----------------------------------------------------------------------
## Table of Contents
- [General Internals](#general)
- [Linux Internals](#linux)
	- [Linux General](#lgen)
	- [Linux Internals](#linternals)
	- [Boot Process](#lboot)
	- [Drivers](#ldrivers)
	- [ELF](#lelf)
	- [Exploit Mitigations](#lex)
	- [FileSystems](#lfs)
	- [Kernel](#lkernel)
	- [Memory](#lmem)
		- [Out-of-Memory(OOM) Killer](#loom)
	- [Processes](#lproc)
	- [Syscalls](#lps)
	- [X Window System](#lx)
- [macOS Internals](#macos)
	- [Kernel Extensions(KEXTs)](#kexts)
- [Windows Internals](#winternals)
	- [Access Control](#wac)
	- [Accounts](#wacs)
	- [Active Directory](#wad)
	- [Advanced Threat Protection(ATP)](#watp)
	- [Alternate Data Streams](#wads)
	- [Anti-Malware Scan Interface](#wamsi)
	- [Windows Native API](#winapi)
	- [App Containers](#waptain)
	- [Application Shims](#wapshim)
	- [Authentication](#wauth)
		- [Digest Authentication](#wdig)
	- [Authenticode](#wauthentic)
	- [AutoStart Locations](#wauto)
	- [Callbacks](#wcall)
	- [(Distributed) Component Object Model](#wcom)
	- [Credential Storage](#wcreds)
	- [Credential Provider](#wcredsp)
	- [Dynamic Data Exchange](#wdde)
	- [Device Guard](#wdg)
	- [DLLs](#wdll)
	- [DNS](#wdns)
	- [Exchange Web Services](#wews)
	- [Exploit Mitigations](#wem)
	- [File Formats](#wff)
	- [Guarded Fabric/Shielded VMs](#wgf)
	- [Handles](#whandles)
	- [HTML Applications](#whta)
	- [Hyper-V](#whyperv)
	- [Isolated User Mode](#wium)
	- [Kerberos](#wkerb)
	- [Kernel](#wkern)
	- [Lightweight Directory Access Protocol](#wldap)
	- [Linux Subsystem](#wls)
	- [Local Security Authority](#wlsa)
	- [Logon](#wlogon)
	- [Memory](#wmem)
	- [Named Pipes](#wnamed)
	- [Netlogon](#wnetlog)
	- [Networking](#winnet)
	- [NTLM](#wntlm)
	- [PE Loader & Execution Environment](#wpenv)
	- [Powershell](#wps)
	- [Printing](#wprint)
	- [Processes/Threads](#wproc)
	- [Prefetch](#wprefetch)
	- [Registry](#wreg)
	- [Remote Desktop](#wrdp)
	- [User Rights](#wur)
	- [RPC](#wrpc)
	- [Sandboxing](#wsb)
	- [Scripting Host](#wsh)
	- [Security Descriptor Definition Language](#wsddl)
	- [Security Support Providers](#wssp)
	- [Services](#wservice)
	- [Service Accounts](#wserva)
	- [Server Message Block(SMB)](#wsmb)
	- [Subsystems](#wsub)
	- [Symbol Files](#wsymbol)
	- [Syscalls](#wsyscall)
	- [Tokens](#wtokens)
	- [User Account Control(UAC)](#wuac)
	- [Volume Shadow Copy Service](#wvss)
	- [Windows Filtering Platform](#wfp)
	- [Windows Communication Foundation](#wcf)- [Linux Reference](#linuxref)
- [ARM Reference](#ARM)
- [Kerberos / Related](#kerberos)
----------------------------------------------------------------------





##### To Do:
* Fix ToC so its accurate
* Split sections into reference material and writeup material(quick vs long reference)
* Further categorize sections (network vs memory vs exploit mitigations vs feature)


------------------------------------------------------------------------------------------------------------------------------
## <a name="general">General OS Agnostic Internals</a>
* **Building an OS**
	* [The little book about OS development](https://littleosbook.github.io/)
	* [How to Make a Computer Operating System in C++](https://github.com/SamyPesse/How-to-Make-a-Computer-Operating-System)
* **Boot Process**
* **File Systems**
* **Memory**
	* Paging
		* [Introduction to Paging - Philipp Oppermann](https://os.phil-opp.com/paging-introduction/)
* **Processes**
* **Unsorted Stuff**
	* [C Function Call Conventions and the Stack](https://archive.is/o2nD5)
	* [What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)
	* [Event log explanations for various systems(not just windows)](http://eventopedia.cloudapp.net/Events/?/Operating+System)
	* [duartes.org - internals](http://duartes.org/gustavo/blog/category/internals/)
------------------------------------------------------------------------------------------------------------------------------







------------------------------------------------------------------------------------------------------------------------------
### <a name="linux">Linux Internals</a>
* **Linux General**<a name="lgen"></a>
	* [Introduction to Linux - Machtelt Garrels](http://www.tldp.org/LDP/intro-linux/html/intro-linux.html)
		* Excellent doc covering every aspect of linux. Deserves at least 1 skim through.
	* [Linux Documentation Project](http://www.tldp.org/)
		* The Linux Documentation Project is working towards developing free, high quality documentation for the Linux operating system. The overall goal of the LDP is to collaborate in all of the issues of Linux documentation.
	* [Bash Guide for Beginners](http://www.tldp.org/LDP/Bash-Beginners-Guide/html/Bash-Beginners-Guide.html)
	* [pagexec - GRSEC](https://pax.grsecurity.net/docs/pageexec.txt)
* **Linux Internals**<a name="linternals"></a>
	* **101**
	* **Info**
	* [linux-insides](https://www.gitbook.com/book/0xax/linux-insides/details)
		* A series of posts about the linux kernel. The goal is simple - to share my modest knowledge about the internals of the linux kernel and help people who are interested in the linux kernel, and other low-level subject matter.
	* [Introduction to Linux - Machtelt Garrels](http://www.tldp.org/LDP/intro-linux/html/intro-linux.html)
		* Excellent doc covering every aspect of linux. Deserves at least 1 skim through.
	* [Linux Kernel Security Subsystem Wiki](https://kernsec.org/wiki/index.php/Main_Page)
		* This is the Linux kernel security subsystem wiki, a resource for developers and users. 
	* **Compilers/Exploit Mitigations**
		* [Linkers and Loaders - Book](http://www.iecc.com/linker/)
			* These are the manuscript chapters for my Linkers and Loaders, published by Morgan-Kaufman. See the book's web site for ordering information. 
			* All chapters are online for free at the above site.
	* [Linker and Libraries](http://docs.oracle.com/cd/E19457-01/801-6737/801-6737.pdf)
* **Boot Process**<a name="lboot"></a>
	* **101**
		* [Kernel booting process](https://github.com/0xAX/linux-insides/tree/master/Booting)
			* This chapter describes linux kernel booting process.
	* **Info**
* **Drivers**<a name="ldrivers"></a>
	* **101**
	* **Info**
		* [Linux Device Drivers book](http://www.makelinux.net/ldd3/)
* **ELF**<a name="lelf"></a>
	* **101**
		* [The 101 of ELF Binaries on Linux: Understanding and Analysis](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)
		* [ELF Format](http://www.skyfree.org/linux/references/ELF_Format.pdf)
		* [The ELF Object File Format by Dissection - Eric Youngdale(1995)](https://www.linuxjournal.com/article/1060)
	* **Info**
		* [Understanding the ELF](https://medium.com/@MrJamesFisher/understanding-the-elf-4bd60daac571)
		* [The Anatomy of an Executable - mewmew](https://github.com/mewrev/dissection)
			* The dissection of a simple "hello world" ELF binary.
* **Exploit Mitigations**<a name="lex"></a>
	* **101**
		* [Linux GLibC Stack Canary Values](https://xorl.wordpress.com/2010/10/14/linux-glibc-stack-canary-values/)
		* [Stack Smashing Protector](http://wiki.osdev.org/Stack_Smashing_Protector)
	* **Info**
* **FileSystems**<a name="lfs"></a>
	* **101**
	* **Info**
		* Linux Filesystem infographic
			* [Part 1](http://i.imgur.com/EU6ga.jpg)
			* [Part 2](http://i.imgur.com/S5Ds2.jpg)
* **Kernel**<a name="lkernel"></a>
	* **101**
	* **Info**
		* [Linux Kernel Explanation/Walk through](http://www.faqs.org/docs/Linux-HOWTO/KernelAnalysis-HOWTO.html)
			* [Linux Kernel Map](http://www.makelinux.net/kernel_map/)
			* Interactive map of the Linux Kernel
		* [Linux kernel development(walkthrough)](https://github.com/0xAX/linux-insides/blob/master/Misc/contribute.md)
* **Memory**<a name="lmem"></a>
	* **101**
		* [How the Kernel manages Memory - Linux](http://duartes.org/gustavo/blog/post/how-the-kernel-manages-your-memory/)
		* [Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
		* [Memory Management: Paging](https://www.cs.rutgers.edu/~pxk/416/notes/09a-paging.html)
		* [Anatomy of a program in memory](http://duartes.org/gustavo/blog/post/anatomy-of-a-program-in-memory/) 
			* Writeup on the structure of program memory in Linux.
		* [Understanding !PTE - Non-PAE and X64](http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx?Redirected=true)
	* **Info**
		* [Memory Translation and Segmentation](http://duartes.org/gustavo/blog/post/memory-translation-and-segmentation/)
	* **Out-of-Memory(OOM) Killer**<a name="loom"></a>
		* [Taming the OOM killer - Goldwyn Rodrigues](https://lwn.net/Articles/317814/)
		* [OOM_Killer - linux-mm.org](https://linux-mm.org/OOM_Killer)
		* [How does the OOM killer decide which process to kill first? - stackexchange](https://unix.stackexchange.com/questions/153585/how-does-the-oom-killer-decide-which-process-to-kill-first)
		* [OOM - Linux kernel user's and administrator's guide](https://static.lwn.net/kerneldoc/admin-guide/mm/concepts.html)
			* [How to diagnose causes of oom-killer killing processes - Stackexchange](https://serverfault.com/questions/134669/how-to-diagnose-causes-of-oom-killer-killing-processes)
		* [Linux Kernel limits - eloquence.marxmeier](http://eloquence.marxmeier.com/sdb/html/linux_limits.html)
			* This document provides an overview of the default Linux Kernel limits (kernel parameter) and where they are defined.
		* [The OOM killer may be called even when there is still plenty of memory available - bl0g.krunch.be](http://bl0rg.krunch.be/oom-frag.html)
		* [How to Configure the Linux Out-of-Memory Killer - Robert Chase](https://www.oracle.com/technical-resources/articles/it-infrastructure/dev-oom-killer.html)
* **Processes**<a name="lproc"></a>
	* **101**
	* **Info**
		* [Killing a process and all of its descendants - Igor Sarcevic](http://morningcoffee.io/killing-a-process-and-all-of-its-descendants.html)
		* [UNIX one-liner to kill a hanging Firefox process - Vasudev Ram](https://jugad2.blogspot.com/2008/09/unix-one-liner-to-kill-hanging-firefox.html?m=1)
* **Syscalls**<a name="lps"></a>
	* **101**
	* **Info**
		* [FlexSC: Flexible System Call Scheduling with Exception-Less System Calls](https://www.cs.cmu.edu/~chensm/Big_Data_reading_group/papers/flexsc-osdi10.pdf)
		* [List of Linux/i386 system calls](http://asm.sourceforge.net/syscall.html)
		* [Linux Syscall Table](http://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html)
			* Complete listing of all Linux Syscalls
* **X Window System**<a name="lx"></a> 
	* [X Window System Explained](https://magcius.github.io/xplain/article/index.html)
	* [Foreign LINUX](https://github.com/wishstudio/flinux)
		* Foreign LINUX is a dynamic binary translator and a Linux system call interface emulator for the Windows platform. It is capable of running unmodified Linux binaries on Windows without any drivers or modifications to the system. This provides another way of running Linux applications under Windows in constrast to Cygwin and other tools.
------------------------------------------------------------------------------------------------------------------------------





















------------------------------------------------------------------------------------------------------------------------------
### <a name="macos">OS X Internals</a>
* **Kernel Extensions(KEXTs)**<a name="kexts"></a>
	* [Kernel Extension Overview - developer.apple](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html)
* **Tools**
	* [Instruments - OS X system analysis](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/Introduction/Introduction.html)
		* Instruments is a performance-analysis and testing tool for dynamically tracing and profiling OS X and iOS code. It is a flexible and powerful tool that lets you track a process, collect data, and examine the collected data. In this way, Instruments helps you understand the behavior of both user apps and the operating system.
------------------------------------------------------------------------------------------------------------------------------




















------------------------------------------------------------------------------------------------------------------------------
### <a name="Winternals">Windows Internals</a>
* [Windows IT professional documentation - MS](https://github.com/MicrosoftDocs/windows-itpro-docs)
* **Windows Internals**
	* [theForger's Win32 API Programming Tutorial](http://www.winprog.org/tutorial/)
	* [x86 Disassembly/Windows Executable Files - WikiBooks](https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files)
	* [WinAPIs for Hackers](https://www.bnxnet.com/wp-content/uploads/2015/01/WinAPIs_for_hackers.pdf)
	* [About Atom Tables](https://msdn.microsoft.com/en-us/library/windows/desktop/ms649053(v=vs.85).aspx)
	* [GlobalGetAtomName function](https://msdn.microsoft.com/en-us/library/windows/desktop/ms649063(v=vs.85).aspx)
	* [windows-operating-system-archaeology](https://github.com/subTee/windows-operating-system-archaeology)
		* subTee stuff
	* [BATTLE OF SKM AND IUM - How Windows 10 rewrites OS Architecture - Alex Ionescu](http://www.alex-ionescu.com/blackhat2015.pdf)
	* [RtlEncryptMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa387693(v=vs.85).aspx)
	* [RtlDecryptMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa387692(v=vs.85).aspx)
* **Unsorted**
	* [Waitfor - technet.ms](https://technet.microsoft.com/en-us/library/cc731613(v=ws.11).aspx?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&iid=22f4306f9238443891cea105281cfd3f&uid=150127534&nid=244+289476616)
	* [Windows Data Protection - msdn.ms](https://msdn.microsoft.com/en-us/library/ms995355.aspx)
	* [Elevate through ShellExecute - msdn](https://blogs.msdn.microsoft.com/vistacompatteam/2006/09/25/elevate-through-shellexecute/)
	* [Securing Privileged Access](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access)
	* [Windows Operating System Archaeology](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology)
* **Access Control**<a name="wac"></a>
	* **101**
		* [Mandatory Integrity Control](https://msdn.microsoft.com/en-gb/library/windows/desktop/bb648648(v=vs.85).aspx)
	* **Info**
		* [Windows Access Control Demystified](http://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=E1A09F166B29C17D2CD38C70A02576E4?doi=10.1.1.88.1930&rep=rep1&type=pdf)
* **Accounts**<a name="wacs"></a>
	* **101**
		* [AD Accounts - docs.ms](https://technet.microsoft.com/itpro/windows/keep-secure/active-directory-accounts)
		* [AD Security Groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)
		* [Microsoft Accounts - docs.ms](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/microsoft-accounts)
		* [Service Accounts - docs.ms](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts)
		* [Special Identities - docs.ms](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/special-identities)
		* [Group Managed Service Accounts Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
		* [Managed Service Accounts - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd378925(v=ws.10))
		* [Getting Started with Group Managed Service Accounts - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts)
		* [Managed Service Accounts - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd378925(v=ws.10))
		* [Managed Service Accounts - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff641731(v=ws.10))
		* [Service Accounts Step-by-Step Guide - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd548356(v=ws.10))
	* **Info**
		* AD Accounts
		* Microsoft Accounts
		* Services Accounts
		* Managed Service Accounts
		* Group Managed Service Accounts
* **Active Directory**<a name="wad"></a>
	* **101**
		* [Active Directory Architecture](https://technet.microsoft.com/en-us/library/bb727030.aspx)
		* [AD Local Domain groups, Global groups and Universal groups.](https://ss64.com/nt/syntax-groups.html)
		* [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths)
			*  Active Directory Control Paths auditing and graphing tools 
		* [[MS-ADTS]: Active Directory Technical Specification](https://msdn.microsoft.com/en-us/library/cc223122.aspx)
			* Specifies the core functionality of Active Directory. Active Directory extends and provides variations of the Lightweight Directory Access Protocol (LDAP).
		* [How the Data Store Works - technet.ms](https://technet.microsoft.com/en-us/library/cc772829%28v=ws.10%29.aspx)
		* [KCC and Topology Generation - technet.ms](https://technet.microsoft.com/en-us/library/cc961781.aspx?f=255&MSPPError=-2147217396)
			* The KCC is a built-in process that runs on all domain controllers. It is a dynamic-link library that modifies data in the local directory in response to systemwide changes, which are made known to the KCC by changes to the data within Active Directory. The KCC generates and maintains the replication topology for replication within sites and between sites.
		* [How Domain and Forest Trusts Work - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10))
	* **Info**
	* **Group Policy**
		* [Group Policy - Wikipedia](https://en.wikipedia.org/wiki/Group_Policy)
* **Advanced Threat Protection(ATP)**<a name="watp"></a>
	* **101**
		* [Windows Defender Advanced Threat Protection - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/windows-defender-advanced-threat-protection)
	* **Info**
		* [Windows Defender ATP data storage and privacy - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/data-storage-privacy-windows-defender-advanced-threat-protection)
			* This document explains the data storage and privacy details related to Windows Defender ATP
* **Alternate Data Streams**<a name="wads"></a>
	* **101**
		* [NTFS Alternate Data Streams - winitor](https://www.winitor.com/pdf/NtfsAlternateDataStreams.pdf)
		* [Introduction to ADS: Alternate Data Streams](https://hshrzd.wordpress.com/2016/03/19/introduction-to-ads-alternate-data-streams/)
	* **Info**
		* [Kurt Seifried Security Advisory 003 (KSSA-003)](https://seifried.org/security/advisories/kssa-003.html)
* **Anti-Malware Scan Interface**<a name="wamsi"></a>
	* **101**
		* [Antimalware Scan Interface Reference](https://msdn.microsoft.com/en-us/library/windows/desktop/dn889588(v=vs.85).aspx)
	* **Info**
* **Windows Native API**<a name="winapi"></a>
	* **101**
	* **Info**
		* [Windows API Index](https://docs.microsoft.com/en-us/windows/desktop/apiindex/windows-api-list)
			* The following is a list of the reference content for the Windows application programming interface (API) for desktop and server applications.
		* [Windows-Hacks](https://github.com/LazoCoder/Windows-Hacks)
			* Creative and unusual things that can be done with the Windows API.
* **App Containers**<a name="waptain"></a>
	* **101**
		* [AppContainer Isolation](https://msdn.microsoft.com/en-us/library/windows/desktop/mt595898(v=vs.85).aspx)
	* **Info**
		* [Demystifying AppContainers in Windows 8 (Part I)](https://blog.nextxpert.com/2013/01/31/demystifying-appcontainers-in-windows-8-part-i/)

* **Application Shims**<a name="wapshim"></a>
	* **101**
		* [Application Shims](https://technet.microsoft.com/en-us/library/dd837644%28v=ws.10%29.aspx)		
	* **Info**
* **Authentication**<a name="wauth"></a>
	* **101**
		* [Windows Authentication Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview)
		* [Windows Authentication Architecture - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-architecture)
		* [Windows Authentication Technical Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-technical-overview)
		* [Group Policy Settings Used in Windows Authentication - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/group-policy-settings-used-in-windows-authentication)
		* [Windows Logon and Authentication Technical Overview(Win10) - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/group-policy-settings-used-in-windows-authentication)
		* [Windows Logon and Authentication Technical Overview(Server08R2) - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dn169017(v=ws.10))
	* **Digest Authentication**<a name="wdig"></a>
		* [What is Digest Authentication? - technet.ms](https://technet.microsoft.com/en-us/library/cc778868%28v=ws.10%29.aspx)
* **Authenticode**<a name="wauthentic"></a>
	* **101**
		* [Authenticode - MSDN](https://msdn.microsoft.com/en-us/library/ms537359(v=vs.85).aspx)
			* Microsoft Authenticode, which is based on industry standards, allows developers to include information about themselves and their code with their programs through the use of digital signatures. 
	* **Info**
* **AutoStart Locations**<a name="wauto"></a>
	* **101**
	* **Info**
		* [Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)
		* [Windows Program Automatic Startup Locations](http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)
* **Boot Process**<a name="wboot"></a>
	* **101**
		* [BCDEdit /dbgsettings - msdn](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542187(v=vs.85).aspx)
	* **Info**
		* [Technical Overview of Windows UEFI Startup Process](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)
* **Callbacks**<a name="wcall"></a>
* **(Distributed) Component Object Model**<a name="wcom"></a>
	* **101**
		* [The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)
		* [COM Fundamentals - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/com/com-fundamentals)
		* [[MS-DCOM]: Distributed Component Object Model (DCOM) Remote Protocol - msdn.ms](https://msdn.microsoft.com/en-us/library/cc226801.aspx)
		* [DCOM Overview - active-undelete.com](http://active-undelete.com/dcom-overview.htm)
	* **Info**
		* [Minimal COM object registration](https://blogs.msdn.microsoft.com/larryosterman/2006/01/05/minimal-com-object-registration/)
		* [The COM Library - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/the-com-library)
		* [Security in COM - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/security-in-com)
		* [Scripting(COM) - thrysoee.dk](https://web.archive.org/web/20160826221656/http://thrysoee.dk:80/InsideCOM+/ch05e.htm)
		* [Active Directory Service Interfaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)		
		* [CLSID Key - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/com/clsid-key-hklm)
			* A CLSID is a globally unique identifier that identifies a COM class object. If your server or container allows linking to its embedded objects, you need to register a CLSID for each supported class of objects.
			* The CLSID key contains information used by the default COM handler to return information about a class when it is in the running state.
		* [What registry entries are needed to register a COM object.](https://blogs.msdn.microsoft.com/larryosterman/2006/01/11/what-registry-entries-are-needed-to-register-a-com-object/)
* **Credential Storage**<a name="wcreds"></a>
	* **101**
		* [Cached and Stored Credentials Technical Overview(2016) - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11))
	* **Info**
		* [ReVaulting! Decryption and opportunities - Francesco Picasso](https://www.slideshare.net/realitynet/revaulting-decryption-and-opportunities)
			* Windows credentials manager stores users’ credentials in special folders called vaults. Being able to access such credentials could be truly useful during a digital investigation for example, to gain access to other protected systems. Moreover, if data is in the cloud, there is the need to have the proper tokens to access it. This presentation will describe vaults’ internals and how they can be decrypted; the related Python Open Source code will be made publicly available. During the session, credentials and vaults coming from Windows 7, Windows 8.1 and Windows 10 will be decrypted, focusing on particular cases of interest. Finally, the presentation will address the challenges coming from Windows Phone, such as getting system-users’ passwords and obtaining users’ ActiveSync tokens.
* **Credential Provider**<a name="wcredsp"></a>
	* **101**
		* [Credential Providers in Windows 10 - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/mt158211(v=vs.85).aspx)
		* [ICredentialProvider interface - msdn](https://msdn.microsoft.com/en-us/library/bb776042(v=vs.85).aspx)
			* Exposes methods used in the setup and manipulation of a credential provider. All credential providers must implement this interface.
		* [Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))
		* [Winlogon and Credential Providers](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648647(v=vs.85).aspx)
			* Winlogon is the Windows module that performs interactive logon for a logon session. Winlogon behavior can be customized by implementing and registering a Credential Provider.
	* **Info**
		* [Registering Network Providers and Credential Managers - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379389(v=vs.85).aspx)
		* [V2 Credential Provider Sample - code.msdn](https://code.msdn.microsoft.com/windowsapps/V2-Credential-Provider-7549a730)
			* Demonstrates how to build a v2 credential provider that makes use of the new capabilities introduced to credential provider framework in Windows 8 and Windows 8.1.
		* [Custom Credential Provider for Password Reset - blogs.technet](https://blogs.technet.microsoft.com/aho/2009/11/14/custom-credential-provider-for-password-reset/)
		* [Starting to build your own Credential Provider](https://blogs.msmvps.com/alunj/2011/02/21/starting-to-build-your-own-credential-provider/)
			* If you’re starting to work on a Credential Provider (CredProv or CP, for short) for Windows Vista, Windows Server 2008, Windows Server 2008 R2 or Windows 7, there are a few steps I would strongly recommend you take, because it will make life easier for you.
* **Dynamic Data Exchange**<a name="wdde"></a>
	* **101**
		* [About Dynamic Data Exchange - msdn.ms](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774%28v=vs.85%29.aspx)
	* **Info**
		* [Dynamic Data Exchange - msdn.ms](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648711(v=vs.85).aspx)
			* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML).
* **Device Guard**<a name="wdg"></a>
	* **101**
		* [Introduction to Windows Defender Device Guard: virtualization-based security and Windows Defender Application Control - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control)
	* **Info**
* **DLLs**<a name="wdll"></a>
	* **101**
		* [Dynamic-Link Library Security - docs.ms(2018)](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security?redirectedfrom=MSDN)
	* **Info**
		* [Everything You Never Wanted To Know About DLLs](http://blog.omega-prime.co.uk/2011/07/04/everything-you-never-wanted-to-know-about-dlls/)
		* [Everything You Ever Wanted to Know about DLLs” - James McNellis(CppCon 2017)](https://www.youtube.com/watch?v=JPQWQfDhICA)
			* [Slides](https://github.com/CppCon/CppCon2017/blob/master/Presentations/Everything%20You%20Ever%20Wanted%20to%20Know%20about%20DLLs/Everything%20You%20Ever%20Wanted%20to%20Know%20about%20DLLs%20-%20James%20McNellis%20-%20CppCon%202017.pdf)
			* If you build software for Windows, you use DLLs, and it’s likely that you may build DLLs of your own. DLLs are the primary mechanism for packaging and encapsulating code on the Windows platform. But have you ever stopped to think about how DLLs work? What goes into a DLL when you build it, what happens when you link your program with a DLL, or how do DLLs get located and loaded at runtime? Many of us build and use DLLs without fully understanding them. In this session, we’ll give an in-depth introduction to DLLs and how they work.  We’ll begin by looking at what’s in a DLL—the kinds of things a DLL can contain and the basic data structures that are used—and the benefits and drawbacks of packaging code in a DLL. We’ll look at how DLLs are loaded, including the details of how the loader locates DLLs and maps them into the process; how dependencies are resolved among DLLs; and DLL lifetime and how DLLs get unloaded. We’ll also look at how DLLs get built, including what makes DLLs “special,” what goes into an import library, and how the linker uses import libraries. Finally, we’ll look at several other miscellaneous topics, including how DLLs interact with threads and thread-local storage, and mechanisms for solving or mitigating the dreaded “DLL hell.” 
* **DNS**<a name="wdns"></a>
	* **101**
		* [[MS-DNSP]: Domain Name Service (DNS) Server Management Protocol - docs.ms(2019)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)
			* Specifies the Domain Name Service (DNS) Server Management Protocol, which defines the RPC interfaces that provide methods for remotely accessing and administering a DNS server. It is a client and server protocol based on RPC that is used in the configuration, management, and monitoring of a DNS server.
	* **Info**
* **Exchange Web Services**<a name="wews"></a>
	* **101**
		* [Exchange Web Services Overview - TechEd](https://www.youtube.com/watch?v=wOQMJhrp6GQ)
	* **Info**
		* [Start using web services in Exchange - msdn 2017](https://msdn.microsoft.com/en-us/library/office/jj900168(v=exchg.150).aspx)
* **Exploit Mitigations**<a name="wex"></a>
	* **101**
		* [Compiler Security Checks In Depth - MSDN Library](https://msdn.microsoft.com/library/aa290051.aspx)
		* [A Crash Course on the Depths of Win32™ Structured Exception Handling](https://www.microsoft.com/msj/0197/exception/exception.aspx)
		* [Antimalware Scan Interface Reference](https://msdn.microsoft.com/en-us/library/windows/desktop/dn889588)
			* prevents certain kinds of powershell attacks
	* **Info**
		* [Preventing the Exploitation of Structured Exception Handler (SEH) Overwrites with SEHOP](https://blogs.technet.microsoft.com/srd/2009/02/02/preventing-the-exploitation-of-structured-exception-handler-seh-overwrites-with-sehop/)
		* [Windows 8 ASLR Explained](http://blog.ptsecurity.com/2012/12/windows-8-aslr-internals.html)
		* [How Control Flow Guard Drastically Caused Windows 8.1 Address Space and Behavior Changes](http://www.alex-ionescu.com/?p=246)
* **File Formats**<a name="wff"></a>
	* **Misc**
		* [[MS-CFB]: Compound File Binary File Format - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b)
			* Specifies the Compound File Binary File Format, a general-purpose file format that provides a file-system-like structure within a file for the storage of arbitrary, application-specific streams of data.
	* **PE File Structure**
		* [PEB Structure 32/64 pdf](http://blog.rewolf.pl/blog/wp-content/uploads/2013/03/PEB_Evolution.pdf)
		* [PE File Format Graphs](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html?view=mosaic)
		* [Peering Inside the PE: A Tour of the Win32 Portable Executable File Format](https://msdn.microsoft.com/en-us/library/ms809762.aspx?utm_content=buffer4588c&utm_medium=social&utm_source=twitter.com&utm_campaign=buffer)
* **Guarded Fabric/Shielded VMs**<a name="wgf"></a>
	* **101**
		* [Guarded fabric and shielded VMs](https://docs.microsoft.com/en-us/windows-server/virtualization/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms-top-node)
	* **Info**
* **HTML Applications**<a name="whta"></a>
	* **101**
		* [HTML Applications - msdn](https://msdn.microsoft.com/en-us/library/ms536471(VS.85).aspx)
			* HTML Applications (HTAs) are full-fledged applications. These applications are trusted and display only the menus, icons, toolbars, and title information that the Web developer creates. In short, HTAs pack all the power of Windows Internet Explorer—its object model, performance, rendering power, protocol support, and channel–download technology—without enforcing the strict security model and user interface of the browser. HTAs can be created using the HTML and Dynamic HTML (DHTML) that you already know.
	* **Info**
* **Hyper-V**<a name="whyperv"></a>
	* **101**
		* [Hyper-V internals](https://hvinternals.blogspot.fr/2015/10/hyper-v-internals.html)
	* **Info**
		* [Hyper-V debugging for beginner](https://hvinternals.blogspot.fr/2015/10/hyper-v-debugging-for-beginners.html)
* **Isolated User Mode**<a name="wium"></a>
	* **101**
		* [Isolated User Mode in Windows 10 with Dave Probert](https://channel9.msdn.com/Blogs/Seth-Juarez/Isolated-User-Mode-in-Windows-10-with-Dave-Probert)
		* [Isolated User Mode Processes and Features in Windows 10 with Logan Gabriel](https://channel9.msdn.com/Blogs/Seth-Juarez/Isolated-User-Mode-Processes-and-Features-in-Windows-10-with-Logan-Gabriel)
	* **Info**
		* [Battle Of SKM And IUM How Windows 10 Rewrites OS Architecture - Alex Ionescu - BHUSA2015](https://www.youtube.com/watch?v=LqaWIn4y26E&index=15&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7)
			* [Slides](http://www.alex-ionescu.com/blackhat2015.pdf)
* **Kerberos**<a name="wkerb"></a>
	* **101**
		* [Kerberos Authentication Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
		* [Kerberos (I): How does Kerberos work? – Theory - Eloy Perez](https://www.tarlogic.com/en/blog/how-kerberos-works/)
		* [Explain like I’m 5: Kerberos - Lynn Roots](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
	* **Info**
		* [Kerberos Delegation, SPNs and More...](https://www.coresecurity.com/blog/kerberos-delegation-spns-and-more)
		* [Article Explaining what the KRBTGT account in AD is](http://windowsitpro.com/security/q-what-krbtgt-account-used-active-directory-ad-environment)
* **Kernel(general)**<a name="wkern"></a>
	* **101**
		* [Introduction to Windows Kernel Security](http://blog.cmpxchg8b.com/2013/05/introduction-to-windows-kernel-security.html)
	* **Callbacks**
	* **Handles**
	* **Objects**
	* **Info**
		* [Inside the Windows Vista Kernel: Part 1](http://technet.microsoft.com/en-us/magazine/2007.02.vistakernel.aspx)
* **Lightweight Directory Access Protocol**<a name="wldap"></a>
	* **101**
		* [Lightweight Directory Access Protocol (v3) - RFC 2251](https://www.ietf.org/rfc/rfc2251.txt)
	* **Info**
* **Local Security Authority**<a name="wlsa"></a>
	* **101**
		* [LSA Authentication](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326%28v=vs.85%29.aspx)
			* LSA Authentication describes the parts of the Local Security Authority (LSA) that applications can use to authenticate and log users on to the local system. It also describes how to create and call authentication packages and security packages.
	* **Info**
* **Logon**<a name="wlogon"></a>
	* **101**
		* [Windows Logon Scenarios - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-logon-scenarios)
	* **Info**
		* [Fantastic Windows Logon types and Where to Find Credentials in Them - Chirag Salva, Anas Jamal(2021)](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
* **Memory**<a name="wmem"></a>
	* **101**
	* **Info**
		* [Pushing the Limits of Windows: Virtual Memory](http://blogs.technet.com/b/markrussinovich/archive/2008/11/17/3155406.aspx)
		* [Memory Translation and Segmentation](http://duartes.org/gustavo/blog/post/memory-translation-and-segmentation/)
		* [Exploring Windows virtual memory management](http://www.triplefault.io/2017/08/exploring-windows-virtual-memory.html)
* **MS Office**
	* **101**
	* **Info**
		* [Introducing the Office (2007) Open XML File Formats - docs.ms](https://docs.microsoft.com/en-us/previous-versions/office/developer/office-2007/aa338205(v=office.12)#office2007aboutnewfileformat_structureoftheofficexmlformats)
* **Named Pipes**<a name="wnamed"></a>
	* **101**
		* [Named Pipes](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365590(v=vs.85).aspx)
		* [CreateNamedPipe function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365150(v=vs.85).aspx)
		* [CreateFile function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx)
		* ReadFile function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx)
		* [WriteFile function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx)
		* [How to create an anonymous pipe that gives access to everyone](https://support.microsoft.com/en-us/help/813414/how-to-create-an-anonymous-pipe-that-gives-access-to-everyone)
	* **Info**
* **Netlogon**<a name="wnetlog"></a>
	* **101**
		* [Netlogon - technet.ms](https://technet.microsoft.com/fr-fr/library/cc962284.aspx)
	* **Info**
* **Networking**<a name="winnet"></a>
	* **101**
		* [WinHTTP - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa382925%28v=vs.85%29.aspx)
		* [WinINet - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa383630%28v=vs.85%29.aspx)
	* **Info**
		* [WinINet vs WinHTTP](https://msdn.microsoft.com/en-us/library/windows/desktop/hh227298%28v=vs.85%29.aspx)
* **NTLM**<a name="wntlm"></a>
	* **101**
		* [Microsoft NTLM - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378749%28v=vs.85%29.aspx)
		* [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge.net](http://davenport.sourceforge.net/ntlm.html)
	* **Info**
* **PE Loader & Execution Environment**<a name="wpenv"></a>
	* **101**
	* **Info**
		* [PEB32 and PEB64 in one definition](http://blog.rewolf.pl/blog/?p=294)
		* [Evolution of Process Environment Block (PEB)](http://blog.rewolf.pl/blog/?p=573)
	* [PE-Runtime-Data-Structures](https://github.com/JeremyBlackthorne/PE-Runtime-Data-Structures)
		* "Originally posted by me in 2013: http://uncomputable.blogspot.com/2013/08/pe-runtime-data-structures-v1.html, just migrating it to a better home. This is a diagram of PE runtime data structures created using WinDbg and OmniGraffle. I have included jpg and PDF versions in the repository. I was inspired by Ero Carrera's [1](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html) diagrams and Corkami [2](https://code.google.com/p/corkami/). I made this diagram because I was teaching myself Windows data structures and was unsatisfied with what was out there. The information for these structures was obtained from WinDbg and Windows Internals 6 by Russinovich, Solomon, and Ionescu [Windows Internals]."
* **Powershell**<a name="wps"></a>
	* **101**
		* [PowerShell - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-6)
		* [Understanding the Windows PowerShell Pipeline - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/fundamental/understanding-the-windows-powershell-pipeline?view=powershell-5.1)
		* [PowerShell Language Modes - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-5.1)
    * **Constrained-Language Mode**
	    * [PowerShell Constrained Language Mode - devblogs.ms](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
	* **Logging**
		* [About Eventlogs(PowerShell) - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1)
		* [Script Tracing and Logging - docs.ms](https://docs.microsoft.com/en-us/powershell/wmf/whats-new/script-logging)
* **Printing**<a name="wprint"></a>
	* **101**
		* [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://msdn.microsoft.com/en-us/library/cc245476.aspx)
		* Specifies the Security Account Manager (SAM) Remote Protocol (Client-to-Server), which supports printing and spooling operations that are synchronous between client and server.
		* [[MS-RPRN]: Print System Remote Protocol - docs.ms](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
	* **Info**
* **Processes & Threads**<a name="wproc"></a>
	* **101**<a name="wproc101"></a>
		* [About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)
		* [TechNet Library: About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)
		* [Processes, Threads, and Jobs in the Windows Operating System](https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=2)
		* [Process Security and Access Rights - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx)
	* **Info**
		* [Know your Windows Processes or Die Trying](https://sysforensics.org/2014/01/know-your-windows-processes.html)
			* Excellent quick reference on Windows proccesses with a focus on Win7. Good resource.
		* [Run-Time Dynamic Linking](https://msdn.microsoft.com/en-us/library/ms685090.aspx)
		* [Windows 8 Boot](http://technet.microsoft.com/en-US/windows/dn168167.aspx)
		* [VirtualAlloc function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx)
		* [SetProcessMitigationPolicy function - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
			* Sets a mitigation policy for the calling process. Mitigation policies enable a process to harden itself against various types of attacks.
		* [GetProcessMitigationPolicy function - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy)
			* Retrieves mitigation policy settings for the calling process.			
		* [OpenProcessToken function - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295%28v=vs.85%29.aspx)
	* **DLL**<a name="pdll"></a>
		* [What is a DLL?](https://support.microsoft.com/en-us/help/815065/what-is-a-dll)
			* This article describes what a dynamic link library (DLL) is and the various issues that may occur when you use DLLs.  Then, this article describes some advanced issues that you should consider when you develop your own DLLs. In describing what a DLL is, this article describes dynamic linking methods, DLL dependencies, DLL entry points, exporting DLL functions, and DLL troubleshooting tools.
	* **Fibers**<a name="pfiber"></a>
		* [Fibers - docs.ms](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers)
		* [Using Fibers](https://docs.microsoft.com/en-us/windows/win32/procthread/using-fibers)
	* **Protected Processes**<a name="ppl"></a>
		* [Unkillable Processes](https://blogs.technet.microsoft.com/markrussinovich/2005/08/17/unkillable-processes/)
		* [The Evolution of Protected Processes Part 1: Pass-the-Hash Mitigations in Windows 8.1 - Alex Ionescu](http://www.alex-ionescu.com/?p=97)
		* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services - Alex Ionescu](http://ww.alex-ionescu.com/?p=116)
		* [Protected Processes Part 3 : Windows PKI Internals (Signing Levels, Scenarios, Root Keys, EKUs & Runtime Signers) - Alex Ionescu](http://www.alex-ionescu.com/?p=146)
	* **Thread Local Storage**<a name="wtls"></a>
		* [Thread Local Storage](https://msdn.microsoft.com/en-us/library/ms686749.aspx)
		* [Thread-local storage - Wikipedia](https://en.wikipedia.org/wiki/Thread-local_storage)
	* **Exception Handling**<a name="weh"></a>
		* [A Crash Course on the Depths of Win32™ Structured Exception Handling](https://www.microsoft.com/msj/0197/exception/exception.aspx)
* **Prefetch**<a name="wprefetch"></a>
	* **101**
	* **Info**
		* [WinPrefetchView v1.25](http://www.nirsoft.net/utils/win_prefetch_view.html)
			* Each time that you run an application in your system, a Prefetch file which contains information about the files loaded by the application is created by Windows operating system. The information in the Prefetch file is used for optimizing the loading time of the application in the next time that you run it. WinPrefetchView is a small utility that reads the Prefetch files stored in your system and display the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot. 
* **Registry**<a name="wreg"></a>
	* **101**
	* **Info**
* **Remote Desktop**<a name="wrdp"></a>
	* **101**
		* [Remote Desktop Services virtual channels - docs.ms](https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-virtual-channels)
	* **Info**
	* **Tools**
		* [UniversalDVC](https://github.com/earthquake/UniversalDVC)
			* Universal Dynamic Virtual Channel connector for Remote Desktop Services
* **User Rights**<a name="wur"></a>
	* **101**
		* [User Rights Assignment(Win10) - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)
	* **Info**
* **RPC**<a name="wrpc"></a>
	* **101**
		* [RPC Components - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/Rpc/microsoft-rpc-components)
		* [Remote Procedure Call - IBM Knowledgebase](https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.progcomc/ch8_rpc.htm)
		* [Remote Procedure Calls (RPC) - users.cs.cf.ac.uk](https://users.cs.cf.ac.uk/Dave.Marshall/C/node33.html)
		* [Remote Procedure Call (RPC) - cio-wiki.org](https://cio-wiki.org/wiki/Remote_Procedure_Call_(RPC))
		* [Remote Procedure Call - Wikipedia](https://en.wikipedia.org/wiki/Remote_procedure_call)
	* **Info**
		* [How RPC Works - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc738291(v=ws.10))
		* [What is RPC and why is it so important?(windows) - StackOverflow](https://superuser.com/questions/616098/what-is-rpc-and-why-is-it-so-important)
		* [Remote Procedure Calls - Paul Krzyzanowski](https://www.cs.rutgers.edu/~pxk/417/notes/08-rpc.html)
* **Sandboxing**<a name="wsb"></a>
	* **101**
	* **Info**
		* [Advanced Desktop Application Sandboxing via AppContainer](https://www.malwaretech.com/2015/09/advanced-desktop-application-sandboxing.html)
		* [Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)
* **Scripting Host**<a name="wsh"></a>
	* **101**
		* [wscript - docs.ms](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wscript)
			* Windows Script Host provides an environment in which users can execute scripts in a variety of languages that use a variety of object models to perform tasks.
	* **Info**
* **Security Descriptor Definition Language**<a name="wsddl"></a>
	* **101**
	* **Info**
		* [The Security Descriptor Definition Language of Love (Part 1) - technet.ms](https://blogs.technet.microsoft.com/askds/2008/04/18/the-security-descriptor-definition-language-of-love-part-1/)
		* [The Security Descriptor Definition Language of Love (Part 2) - technet.ms](https://blogs.technet.microsoft.com/askds/2008/05/07/the-security-descriptor-definition-language-of-love-part-2/)
		* [SECURITY_DESCRIPTOR_CONTROL - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control?redirectedfrom=MSDN)
			* The SECURITY_DESCRIPTOR_CONTROL data type is a set of bit flags that qualify the meaning of a security descriptor or its components. Each security descriptor has a Control member that stores the SECURITY_DESCRIPTOR_CONTROL bits.
* **Security Support Providers**<a name="wssp"></a>
	* **101**
		* [Security Support Provider Interface Architecture - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture)	
	* **Info**
		* [SSP Packages Provided by Microsoft - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/ssp-packages-provided-by-microsoft)
		* [Secure Channel - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/secure-channel)
			* Secure Channel, also known as Schannel, is a security support provider (SSP) that contains a set of security protocols that provide identity authentication and secure, private communication through encryption. Schannel is primarily used for Internet applications that require secure Hypertext Transfer Protocol (HTTP) communications.
		* [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge.net](http://davenport.sourceforge.net/ntlm.html)
		* [Microsoft Digest SSP - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/microsoft-digest-ssp)
			* Microsoft Digest is a security support provider (SSP) that implements the Digest Access protocol, a lightweight authentication protocol for parties involved in Hypertext Transfer Protocol (HTTP) or Simple Authentication Security Layer (SASL) based communications. Microsoft Digest provides a simple challenge response mechanism for authenticating clients. This SSP is intended for use by client/server applications using HTTP or SASL based communications.
* **Services**<a name="wservice"></a>
	* **101**
	* **Info**	
		* [Creating a service using sc.exe](https://support.microsoft.com/en-us/help/251192/how-to-create-a-windows-service-by-using-sc-exe)
		* [Services: Windows 10 Services(ss64)](https://ss64.com/nt/syntax-services.html)
			* A list of the default services in Windows 10 (build 1903).
	* **Service Accounts**<a name="wserva"></a>
		* **101**
		* **Info**
			* [Service Account best practices Part 1: Choosing a Service Account](https://4sysops.com/archives/service-account-best-practices-part-1-choosing-a-service-account/)
				* In this article you will learn the fundamentals of Windows service accounts. Specifically, we discover the options and best practices concerning the selection of a service account for a particular service application.
* **Server Message Block(SMB)**<a name="wsmb"></a>
	* **101**
		* [Server Message Block Overview - msdn.ms](https://msdn.microsoft.com/fr-fr/library/hh831795%28v=ws.11%29.aspx)
	* **Info**
* **Sessions**<a name="wsesh"></a>
	* **101**
		* [Server Message Block Overview - msdn.ms](https://msdn.microsoft.com/fr-fr/library/hh831795%28v=ws.11%29.aspx)
	* **Info**
		* [Understanding Windows at a deeper level - Sessions, Window Stations, and Desktops](https://brianbondy.com/blog/100/understanding-windows-at-a-deeper-level-sessions-window-stations-and-desktops)
* **Subsystems**<a name="wsub"></a>
	* **Linux Subsystem**<a name="wls"></a>
		* **101**
			* [Learn About Windows Console & Windows Subsystem For Linux (WSL) - devblogs.ms](https://devblogs.microsoft.com/commandline/learn-about-windows-console-and-windows-subsystem-for-linux-wsl/)
		* **Info**
	* **Security**
		* **101**
			* [Security Subsystem Architecture - docs.ms(2012)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN)
		* **Info**
* **Symbol Files**<a name="wsymbol"></a>
	* **101**
		* [Symbols and Symbol Files - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols-and-symbol-files)
		* [Symbol Files - docs ms](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)

	* **Info**
		* [microsoft-pdb](https://github.com/Microsoft/microsoft-pdb)
			* This repo contains information from Microsoft about the PDB (Program Database) Symbol File format.
		* [Public and Private Symbols - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/public-and-private-symbols)
		* [How to Inspect the Content of a Program Database (PDB) File](https://www.codeproject.com/Articles/37456/How-To-Inspect-the-Content-of-a-Program-Database-P)
		* [Symbol Files](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)
			* Normally, debugging information is stored in a symbol file separate from the executable. The implementation of this debugging information has changed over the years, and the following documentation will provide guidance regarding these various implementations .
* **Syscalls**<a name="wsyscall"></a>
	* **101**
	* **Info**
		* [windows-syscall-table](https://github.com/tinysec/windows-syscall-table)
			* windows syscall table from xp ~ 10 rs2
		* [How Do Windows NT System Calls REALLY Work?](http://www.codeguru.com/cpp/w-p/system/devicedriverdevelopment/article.php/c8035/How-Do-Windows-NT-System-Calls-REALLY-Work.htm)
		* [Debugging Functions - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679303.aspx)
		* [Intercepting System Calls on x86_64 Windows](http://jbremer.org/intercepting-system-calls-on-x86_64-windows/)
* **Tokens**<a name="wtokens"></a>
	* **101**
	* **Info**
	* **API Calls**
		* [DuplicateTokenEx function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex?redirectedfrom=MSDN)
			* The DuplicateTokenEx function creates a new access token that duplicates an existing token. This function can create either a primary token or an impersonation token.
		* [ImpersonateLoggedOnUser function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser?redirectedfrom=MSDN)
			* The ImpersonateLoggedOnUser function lets the calling thread impersonate the security context of a logged-on user. The user is represented by a token handle.
		* [SetThreadToken function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken?redirectedfrom=MSDN)
			* The SetThreadToken function assigns an impersonation token to a thread. The function can also cause a thread to stop using an impersonation token.
		* [CreateProcessWithTokenW function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw?redirectedfrom=MSDN)
			* Creates a new process and its primary thread. The new process runs in the security context of the specified token. It can optionally load the user profile for the specified user.
		* [OpenProcess function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess?redirectedfrom=MSDN)
			* Opens an existing local process object.
		* [OpenProcessToken function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken?redirectedfrom=MSDN)
			* The OpenProcessToken function opens the access token associated with a process.
		* [OpenThread function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread?redirectedfrom=MSDN)
			* Opens an existing thread object.
		* [OpenThreadToken function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken?redirectedfrom=MSDN)
			* The OpenThreadToken function opens the access token associated with a thread.
		* [GetTokenInformation function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation?redirectedfrom=MSDN)
			* The GetTokenInformation function retrieves a specified type of information about an access token. The calling process must have appropriate access rights to obtain the information.
* **User Account Control(UAC)**<a name="wuac"></a>
	* **101**
		* [User Account Control - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/user-account-control)
		* [Inside Windows Vista User Account Control - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc138019(v=msdn.10)?redirectedfrom=MSDN)
		* [Inside Windows 7 User Account Control - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/dd822916(v=msdn.10)?redirectedfrom=MSDN)
		* [User Account Control: Inside Windows 7 User Account Control - Mark Russinovich](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/dd822916(v=msdn.10))
	* **Info**	
		* [Protecting Windows Networks – UAC - dfirblog.wordpress.com](https://dfirblog.wordpress.com/2015/10/24/protecting-windows-networks-uac/) 
		* User Account Control - Steven Sinofsky(blogs.msdn)](https://blogs.msdn.microsoft.com/e7/2008/10/08/user-account-control/)
		* [User Account Control Step-by-Step Guide - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc709691(v=ws.10))
* **Volume Shadow Copy Service**<a name="wvss"></a>
	* **101**
		* [About the Volume Shadow Copy Service - docs.ms](https://docs.microsoft.com/en-us/windows/win32/vss/about-the-volume-shadow-copy-service)
	* **Info**
* **Windows Filtering Platform**<a name="wfp"></a>
	* **101**
	* **Info**
		* [Windows Filtering Platform: Persistent state under the hood](http://blog.quarkslab.com/windows-filtering-platform-persistent-state-under-the-hood.html)
* **Windows Communication Foundation**<a name="wcf"></a>
	* **101**
		* [Windows Communication Foundation - Guide to the Documentation - docs.ms]
		* [What Is Windows Communication Foundation](https://docs.microsoft.com/en-us/dotnet/framework/wcf/whats-wcf)
			* Windows Communication Foundation (WCF) is a framework for building service-oriented applications. Using WCF, you can send data as asynchronous messages from one service endpoint to another. A service endpoint can be part of a continuously available service hosted by IIS, or it can be a service hosted in an application. An endpoint can be a client of a service that requests data from a service endpoint. The messages can be as simple as a single character or word sent as XML, or as complex as a stream of binary data.
		* [Fundamental Windows Communication Foundation Concepts](https://docs.microsoft.com/en-us/dotnet/framework/wcf/fundamental-concepts)
			*  WCF is a runtime and a set of APIs for creating systems that send messages between services and clients. The same infrastructure and APIs are used to create applications that communicate with other applications on the same computer system or on a system that resides in another company and is accessed over the Internet.
		* [Windows Communication Foundation Architecture Architecture Graphic](https://docs.microsoft.com/en-us/dotnet/framework/wcf/architecture)
	* **Info**
------------------------------------------------------------------------------------------------------------------------------








------------------------------------------------------------------------------------------------------------------------------
### <a name="ARM">ARM References</a>
* [A Detailed Analysis of Contemporary ARM and x86 Architectures](http://research.cs.wisc.edu/vertical/papers/2013/isa-power-struggles-tr.pdf)
	* RISC vs. CISC wars raged in the 1980s when chip area andprocessor design complexity were the primary constraints anddesktops and servers exclusively dominated the computing land-scape. Today, energy and power are the primary design con-straints and the computing landscape is significantly different:growth in tablets and smartphones running ARM (a RISC ISA)is surpassing that of desktops and laptops running x86 (a CISCISA). Further, the traditionally low-power ARM ISA is enter-ing the high-performance server market, while the traditionallyhigh-performance x86 ISA is entering the mobile low-power de-vice market. Thus, the question of whether ISA plays an intrinsicrole in performance or energy efficiency is becoming important,and we seek to answer this question through a detailed mea-surement based study on real hardware running real applica-tions. We analyze measurements on the ARM Cortex-A8 andCortex-A9 and Intel Atom and Sandybridge i7 microprocessorsover workloads spanning mobile, desktop, and server comput-ing. Our methodical investigation demonstrates the role of ISAin modern microprocessors’ performance and energy efficiency.We find that ARM and x86 processors are simply engineeringdesign points optimized for different levels of performance, andthere is nothing fundamentally more energy efficient in one ISAclass or the other. The ISA being RISC or CISC seems irrelevant.
* [ARM Documentation](http://infocenter.arm.com/help/index.jsp?noscript=1)
* [Windows 8 Security and ARM](http://2012.ruxconbreakpoint.com/assets/Uploads/bpx/alex-breakpoint2012.pdf)
------------------------------------------------------------------------------------------------------------------------------




------------------------------------------------------------------------------------------------------------------------------
### Other 
* [Intel SGX Explained](https://eprint.iacr.org/2016/086.pdf)
	* This paper analyzes Intel SGX, based on the 3 pa- pers [ 14 , 78 , 137 ] that introduced it, on the Intel Software Developer’s Manual [ 100 ] (which supersedes the SGX manuals [ 94 , 98 ]), on an ISCA 2015 tutorial [ 102 ], and on two patents [ 108 , 136 ]. We use the papers, reference manuals, and tutorial as primary data sources, and only draw on the patents to fill in missing information. This  paper’s  contributions  are  a  summary  of  the Intel-specific architectural and micro-architectural details needed to understand SGX, a detailed and structured pre- sentation of the publicly available information on SGX, a series of intelligent guesses about some important but undocumented aspects of SGX, and an analysis of SGX’s security properties.



------------------------------------------------------------------------------------------------------------------------------
##### Emojis/Fonts/Encoding
* [Introducing Character Sets and Encodings - W3C](https://www.w3.org/International/getting-started/characters)
* [An Introduction to Writing Systems & Unicode](https://r12a.github.io/scripts/tutorial/)
* [Tifinagh - Wikipedia](https://en.m.wikipedia.org/wiki/Tifinagh)
* [Core Text - apple](https://developer.apple.com/documentation/coretext)
* [Full Emoji List - Unicode.org](https://unicode.org/emoji/charts/full-emoji-list.html)
* [List of XML and HTML character entity references - Wikipedia](https://en.m.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references)
* [Ambiguous ampersands](https://mathiasbynens.be/notes/ambiguous-ampersands)
* [Everything You Need To Know About Emoji 🍭](https://www.smashingmagazine.com/2016/11/character-sets-encoding-emoji/)
* [Emoji and Pictographs - FAQ - unicode.org](https://unicode.org/faq/emoji_dingbats.html)
* [Unicode® Emoji](https://www.unicode.org/emoji/)
	* This page provides information about Unicode emoji and their development. 
* [Emojipedia](https://emojipedia.org/)
	* Emoji Meanings
------------------------------------------------------------------------------------------------------------------------------



#### To be Sorted
