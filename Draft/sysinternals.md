
# System Internals of Windows; OS X; Linux; ARM

## Table of Contents

* [General Internals](#general)
* [Windows Internals](#winternals)
* [Kerberos / Related](#kerberos)
* [Linux Internals](#linux)
* [Windows Reference](#windowsref)
* [Linux Reference](#linuxref)
* [OS X Reference](#osx)
* [ARM Reference](#ARM)





##### To Do:

* Fix ToC so its accurate
* Split sections into reference material and writeup material(quick vs long reference)
* Further categorize sections (network vs memory vs exploit mitigations vs feature)

---------------------
## <a name="general">General Internals</a>
* [C Function Call Conventions and the Stack](https://archive.is/o2nD5)
* [The Anatomy of an Executable](https://github.com/mewrev/dissection)
* [What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)
* [Linux kernel development(walkthrough)](https://github.com/0xAX/linux-insides/blob/master/Misc/contribute.md)
* [Event log explanations for various systems(not just windows)](http://eventopedia.cloudapp.net/Events/?/Operating+System)
* [duartes.org - internals](http://duartes.org/gustavo/blog/category/internals/)
* [The little book about OS development](https://littleosbook.github.io/)
* [How to Make a Computer Operating System in C++](https://github.com/SamyPesse/How-to-Make-a-Computer-Operating-System)
* [Introduction to Paging - Philipp Oppermann](https://os.phil-opp.com/paging-introduction/)

---------------------
## <a name="winref">Windows Reference</a>

### <a name="Winternals">Windows Internals</a>
* [Windows IT professional documentation](https://github.com/MicrosoftDocs/windows-itpro-docs)
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
* **Access Control**
	* [Mandatory Integrity Control](https://msdn.microsoft.com/en-gb/library/windows/desktop/bb648648(v=vs.85).aspx)
	* [Windows Access Control Demystified](http://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=E1A09F166B29C17D2CD38C70A02576E4?doi=10.1.1.88.1930&rep=rep1&type=pdf)
* **Accounts**
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
* **Active Directory**
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
* **Advanced Threat Protection(ATP)**
	* [Windows Defender Advanced Threat Protection - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/windows-defender-advanced-threat-protection)
	* [Windows Defender ATP data storage and privacy - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/data-storage-privacy-windows-defender-advanced-threat-protection)
		* This document explains the data storage and privacy details related to Windows Defender ATP
* **Alternate Data Streams**
	* [Kurt Seifried Security Advisory 003 (KSSA-003)](https://seifried.org/security/advisories/kssa-003.html)
	* [NTFS Alternate Data Streams - winitor](https://www.winitor.com/pdf/NtfsAlternateDataStreams.pdf)
* **Anti-Malware Scan Interface**
	* [Antimalware Scan Interface Reference](https://msdn.microsoft.com/en-us/library/windows/desktop/dn889588(v=vs.85).aspx)
* **API**
	* [Windows API Index](https://docs.microsoft.com/en-us/windows/desktop/apiindex/windows-api-list)
		* The following is a list of the reference content for the Windows application programming interface (API) for desktop and server applications.
* **App Containers**
	* [Demystifying AppContainers in Windows 8 (Part I)](https://blog.nextxpert.com/2013/01/31/demystifying-appcontainers-in-windows-8-part-i/)
	* [AppContainer Isolation](https://msdn.microsoft.com/en-us/library/windows/desktop/mt595898(v=vs.85).aspx)
* **Application Shims**
	* [Application Shims](https://technet.microsoft.com/en-us/library/dd837644%28v=ws.10%29.aspx)
* **Authentication**
Windows Authentication
	* [Windows Authentication Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview)
	* [Windows Authentication Architecture - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-architecture)
	* [Windows Authentication Technical Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-technical-overview)
	* [Group Policy Settings Used in Windows Authentication - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/group-policy-settings-used-in-windows-authentication)
	* [Windows Logon and Authentication Technical Overview(Win10) - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/group-policy-settings-used-in-windows-authentication)
	* [Windows Logon and Authentication Technical Overview(Server08R2) - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dn169017(v=ws.10))
* **Authenticode**
	* [Authenticode - MSDN](https://msdn.microsoft.com/en-us/library/ms537359(v=vs.85).aspx)
		* Microsoft Authenticode, which is based on industry standards, allows developers to include information about themselves and their code with their programs through the use of digital signatures. 
* **AutoStart Locations**
	* [Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)
	* [Windows Program Automatic Startup Locations](http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)
* **(Distributed) Component Object Model**
	* [The Component Object Model](https://msdn.microsoft.com/library/ms694363.aspx)
	* [Minimal COM object registration](https://blogs.msdn.microsoft.com/larryosterman/2006/01/05/minimal-com-object-registration/)
	* [CLSID Key - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/com/clsid-key-hklm)
		* A CLSID is a globally unique identifier that identifies a COM class object. If your server or container allows linking to its embedded objects, you need to register a CLSID for each supported class of objects.
		* The CLSID key contains information used by the default COM handler to return information about a class when it is in the running state.
	* [COM Fundamentals - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/com/com-fundamentals)
	* [The COM Library - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/the-com-library)
	* [Security in COM - docs.ms](https://docs.microsoft.com/en-us/windows/win32/com/security-in-com)
	* [Scripting(COM) - thrysoee.dk](https://web.archive.org/web/20160826221656/http://thrysoee.dk:80/InsideCOM+/ch05e.htm)
	* [[MS-DCOM]: Distributed Component Object Model (DCOM) Remote Protocol - msdn.ms](https://msdn.microsoft.com/en-us/library/cc226801.aspx)
	* [DCOM Overview - active-undelete.com](http://active-undelete.com/dcom-overview.htm)
	* [Active Directory Service Interfaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)
* **Credential Provider**
	* [Credential Providers in Windows 10 - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/mt158211(v=vs.85).aspx)
	* [ICredentialProvider interface - msdn](https://msdn.microsoft.com/en-us/library/bb776042(v=vs.85).aspx)
		* Exposes methods used in the setup and manipulation of a credential provider. All credential providers must implement this interface.
	* [Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))
	* [Winlogon and Credential Providers](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648647(v=vs.85).aspx)
		* Winlogon is the Windows module that performs interactive logon for a logon session. Winlogon behavior can be customized by implementing and registering a Credential Provider.
	* [Registering Network Providers and Credential Managers - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379389(v=vs.85).aspx)
	* [V2 Credential Provider Sample - code.msdn](https://code.msdn.microsoft.com/windowsapps/V2-Credential-Provider-7549a730)
		* Demonstrates how to build a v2 credential provider that makes use of the new capabilities introduced to credential provider framework in Windows 8 and Windows 8.1.
	* [Custom Credential Provider for Password Reset - blogs.technet](https://blogs.technet.microsoft.com/aho/2009/11/14/custom-credential-provider-for-password-reset/)
	* [Starting to build your own Credential Provider](https://blogs.msmvps.com/alunj/2011/02/21/starting-to-build-your-own-credential-provider/)
		* If you’re starting to work on a Credential Provider (CredProv or CP, for short) for Windows Vista, Windows Server 2008, Windows Server 2008 R2 or Windows 7, there are a few steps I would strongly recommend you take, because it will make life easier for you.
* **Device Guard**
	* [Introduction to Windows Defender Device Guard: virtualization-based security and Windows Defender Application Control - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control)
* **Digest Authentication**
	* [What is Digest Authentication? - technet.ms](https://technet.microsoft.com/en-us/library/cc778868%28v=ws.10%29.aspx)
* **DLLs**
	* [Everything You Never Wanted To Know About DLLs](http://blog.omega-prime.co.uk/2011/07/04/everything-you-never-wanted-to-know-about-dlls/)
* **Dynamic Data Exchange**
	* [Dynamic Data Exchange - msdn.ms](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648711(v=vs.85).aspx)
		* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML).
	* [About Dynamic Data Exchange - msdn.ms](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774%28v=vs.85%29.aspx)
* **Exchange Web Services**
	* [Start using web services in Exchange - msdn 2017](https://msdn.microsoft.com/en-us/library/office/jj900168(v=exchg.150).aspx)
	* [Exchange Web Services Overview - TechEd](https://www.youtube.com/watch?v=wOQMJhrp6GQ)
* **Exploit Mitigations**
	* [Compiler Security Checks In Depth - MSDN Library](https://msdn.microsoft.com/library/aa290051.aspx)
	* [A Crash Course on the Depths of Win32™ Structured Exception Handling](https://www.microsoft.com/msj/0197/exception/exception.aspx)
	* [Antimalware Scan Interface Reference](https://msdn.microsoft.com/en-us/library/windows/desktop/dn889588)
		* prevents certain kinds of powershell attacks
	* [Compiler Security Checks In Depth - MSDN Library](https://msdn.microsoft.com/library/aa290051.aspx)
* **File Formats**
	* [[MS-CFB]: Compound File Binary File Format - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b)
		* Specifies the Compound File Binary File Format, a general-purpose file format that provides a file-system-like structure within a file for the storage of arbitrary, application-specific streams of data.
* **Group Policy**
	* [Group Policy - Wikipedia](https://en.wikipedia.org/wiki/Group_Policy)
* **Guarded Fabric/Shielded VMs**
	* [Guarded fabric and shielded VMs](https://docs.microsoft.com/en-us/windows-server/virtualization/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms-top-node)
* **HTML Applications**
	* [HTML Applications - msdn](https://msdn.microsoft.com/en-us/library/ms536471(VS.85).aspx)
		* HTML Applications (HTAs) are full-fledged applications. These applications are trusted and display only the menus, icons, toolbars, and title information that the Web developer creates. In short, HTAs pack all the power of Windows Internet Explorer—its object model, performance, rendering power, protocol support, and channel–download technology—without enforcing the strict security model and user interface of the browser. HTAs can be created using the HTML and Dynamic HTML (DHTML) that you already know.
* **Isolated User Mode**
	* [Battle Of SKM And IUM How Windows 10 Rewrites OS Architecture - Alex Ionescu - BHUSA2015](https://www.youtube.com/watch?v=LqaWIn4y26E&index=15&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7)
		* [Slides](http://www.alex-ionescu.com/blackhat2015.pdf)
	* [Isolated User Mode in Windows 10 with Dave Probert](https://channel9.msdn.com/Blogs/Seth-Juarez/Isolated-User-Mode-in-Windows-10-with-Dave-Probert)
	* [Isolated User Mode Processes and Features in Windows 10 with Logan Gabriel](https://channel9.msdn.com/Blogs/Seth-Juarez/Isolated-User-Mode-Processes-and-Features-in-Windows-10-with-Logan-Gabriel)
* **Kerberos**
	* [Kerberos Delegation, SPNs and More...](https://www.coresecurity.com/blog/kerberos-delegation-spns-and-more)
	* [Article Explaining what the KRBTGT account in AD is](http://windowsitpro.com/security/q-what-krbtgt-account-used-active-directory-ad-environment)
	* [Kerberos Authentication Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
	* [Kerberos (I): How does Kerberos work? – Theory - Eloy Perez](https://www.tarlogic.com/en/blog/how-kerberos-works/)
	* [Explain like I’m 5: Kerberos - Lynn Roots](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* **Kernel**
	* [Inside the Windows Vista Kernel: Part 1](http://technet.microsoft.com/en-us/magazine/2007.02.vistakernel.aspx)
* **Lightweight Directory Access Protocol**
	* [Lightweight Directory Access Protocol (v3) - RFC 2251](https://www.ietf.org/rfc/rfc2251.txt)
* **Linux Subsystem**
	* [Learn About Windows Console & Windows Subsystem For Linux (WSL) - devblogs.ms](https://devblogs.microsoft.com/commandline/learn-about-windows-console-and-windows-subsystem-for-linux-wsl/)
* **Local Security Authority**
	* [LSA Authentication](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326%28v=vs.85%29.aspx)
		* LSA Authentication describes the parts of the Local Security Authority (LSA) that applications can use to authenticate and log users on to the local system. It also describes how to create and call authentication packages and security packages.
* **Logon**
	* [Windows Logon Scenarios - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-logon-scenarios)
* **Memory**
	* [Pushing the Limits of Windows: Virtual Memory](http://blogs.technet.com/b/markrussinovich/archive/2008/11/17/3155406.aspx)
	* [Memory Translation and Segmentation](http://duartes.org/gustavo/blog/post/memory-translation-and-segmentation/)
	* [Exploring Windows virtual memory management](http://www.triplefault.io/2017/08/exploring-windows-virtual-memory.html)
* **MS Office**
	* [Introducing the Office (2007) Open XML File Formats - docs.ms](https://docs.microsoft.com/en-us/previous-versions/office/developer/office-2007/aa338205(v=office.12)#office2007aboutnewfileformat_structureoftheofficexmlformats)
* **Named Pipes**
	* [Named Pipes](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365590(v=vs.85).aspx)
	* [CreateNamedPipe function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365150(v=vs.85).aspx)
	* [CreateFile function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx)
	* ReadFile function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx)
	* [WriteFile function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx)
	* [How to create an anonymous pipe that gives access to everyone](https://support.microsoft.com/en-us/help/813414/how-to-create-an-anonymous-pipe-that-gives-access-to-everyone)
* **Netlogon**
	* [Netlogon - technet.ms](https://technet.microsoft.com/fr-fr/library/cc962284.aspx)
* **Networking**
	* [WinHTTP](https://msdn.microsoft.com/en-us/library/windows/desktop/aa382925%28v=vs.85%29.aspx)
	* [WinINet](https://msdn.microsoft.com/en-us/library/windows/desktop/aa383630%28v=vs.85%29.aspx)
	* [WinINet vs WinHTTP](https://msdn.microsoft.com/en-us/library/windows/desktop/hh227298%28v=vs.85%29.aspx)
* **NTLM**
	* [Microsoft NTLM - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378749%28v=vs.85%29.aspx)
	* [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge.net](http://davenport.sourceforge.net/ntlm.html)
* **PE File Structure**
	* [PEB Structure 32/64 pdf](http://blog.rewolf.pl/blog/wp-content/uploads/2013/03/PEB_Evolution.pdf)
	* [PE File Format Graphs](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html?view=mosaic)
	* [Peering Inside the PE: A Tour of the Win32 Portable Executable File Format](https://msdn.microsoft.com/en-us/library/ms809762.aspx?utm_content=buffer4588c&utm_medium=social&utm_source=twitter.com&utm_campaign=buffer)
	* [PEB32 and PEB64 in one definition](http://blog.rewolf.pl/blog/?p=294)
	* [Evolution of Process Environment Block (PEB)](http://blog.rewolf.pl/blog/?p=573)
* **Powershell**
	* [Understanding the Windows PowerShell Pipeline - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/fundamental/understanding-the-windows-powershell-pipeline?view=powershell-5.1)
	* [PowerShell Language Modes - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-5.1)
	* [PowerShell - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-6)
    * **Constrained-Language Mode**
	    * [PowerShell Constrained Language Mode - devblogs.ms](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
	* **Logging**
		* [About Eventlogs(PowerShell) - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1)
		* [Script Tracing and Logging - docs.ms](https://docs.microsoft.com/en-us/powershell/wmf/whats-new/script-logging)
* **Printing**
	* [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://msdn.microsoft.com/en-us/library/cc245476.aspx)
		* Specifies the Security Account Manager (SAM) Remote Protocol (Client-to-Server), which supports printing and spooling operations that are synchronous between client and server.
	* [[MS-RPRN]: Print System Remote Protocol - docs.ms](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* **Processes/Threads**
	* [About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)
	* [TechNet Library: About Processes and Threads](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917%28v=vs.85%29.aspx)
	* [Processes, Threads, and Jobs in the Windows Operating System](https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=2)
	* [Know your Windows Processes or Die Trying](https://sysforensics.org/2014/01/know-your-windows-processes.html)
		* Excellent quick reference on Windows proccesses with a focus on Win7. Good resource.
	* **DLL**
		* [What is a DLL?](https://support.microsoft.com/en-us/help/815065/what-is-a-dll)
			* This article describes what a dynamic link library (DLL) is and the various issues that may occur when you use DLLs.  Then, this article describes some advanced issues that you should consider when you develop your own DLLs. In describing what a DLL is, this article describes dynamic linking methods, DLL dependencies, DLL entry points, exporting DLL functions, and DLL troubleshooting tools.
	* **Fibers**
		* [Fibers - docs.ms](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers)
		* [Using Fibers](https://docs.microsoft.com/en-us/windows/win32/procthread/using-fibers)
	* **Protected Processes**
		* [Unkillable Processes](https://blogs.technet.microsoft.com/markrussinovich/2005/08/17/unkillable-processes/)
		* [The Evolution of Protected Processes Part 1: Pass-the-Hash Mitigations in Windows 8.1 - Alex Ionescu](http://www.alex-ionescu.com/?p=97)
		* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services - Alex Ionescu](http://ww.alex-ionescu.com/?p=116)
		* [Protected Processes Part 3 : Windows PKI Internals (Signing Levels, Scenarios, Root Keys, EKUs & Runtime Signers) - Alex Ionescu](http://www.alex-ionescu.com/?p=146)
	* **Thread Local Storage**
		* [Thread Local Storage](https://msdn.microsoft.com/en-us/library/ms686749.aspx)
		* [Thread-local storage - Wikipedia](https://en.wikipedia.org/wiki/Thread-local_storage)
	* **Exception Handling**
		* [A Crash Course on the Depths of Win32™ Structured Exception Handling](https://www.microsoft.com/msj/0197/exception/exception.aspx)
	* [Run-Time Dynamic Linking](https://msdn.microsoft.com/en-us/library/ms685090.aspx)
	* [Windows 8 Boot](http://technet.microsoft.com/en-US/windows/dn168167.aspx)
	* [VirtualAlloc function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx)
	* [SetProcessMitigationPolicy function - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
		* Sets a mitigation policy for the calling process. Mitigation policies enable a process to harden itself against various types of attacks.
	* [GetProcessMitigationPolicy function - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy)
		* Retrieves mitigation policy settings for the calling process.
	* [PE-Runtime-Data-Structures](https://github.com/JeremyBlackthorne/PE-Runtime-Data-Structures)
		* Originally posted by me in 2013: http://uncomputable.blogspot.com/2013/08/pe-runtime-data-structures-v1.html, just migrating it to a better home.  This is a diagram of PE runtime data structures created using WinDbg and OmniGraffle. I have included jpg and PDF versions in the repository.  I was inspired by Ero Carrera's [1](http://blog.dkbza.org/2012/08/pe-file-format-graphs.html) diagrams and Corkami [2](https://code.google.com/p/corkami/). I made this diagram because I was teaching myself Windows data structures and was unsatisfied with what was out there. The information for these structures was obtained from WinDbg and Windows Internals 6 by Russinovich, Solomon, and Ionescu [Windows Internals].
* **Prefetch**
	* [WinPrefetchView v1.25](http://www.nirsoft.net/utils/win_prefetch_view.html)
		* Each time that you run an application in your system, a Prefetch file which contains information about the files loaded by the application is created by Windows operating system. The information in the Prefetch file is used for optimizing the loading time of the application in the next time that you run it. WinPrefetchView is a small utility that reads the Prefetch files stored in your system and display the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot. 
* **Registry**
	* [What registry entries are needed to register a COM object.](https://blogs.msdn.microsoft.com/larryosterman/2006/01/11/what-registry-entries-are-needed-to-register-a-com-object/)
	* [Authentication Registry Keys - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374737(v=vs.85).aspx)
		* When it installs a network provider, your application should create the registry keys and values described in this topic. These keys and values provide information to the MPR about the network providers installed on the system. The MPR checks these keys when it starts and loads the network provider DLLs that it finds.
* **RPC**
	* [Remote Procedure Call - IBM Knowledgebase](https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.progcomc/ch8_rpc.htm)
	* [Remote Procedure Calls (RPC) - users.cs.cf.ac.uk](https://users.cs.cf.ac.uk/Dave.Marshall/C/node33.html)
	* [Remote Procedure Call (RPC) - cio-wiki.org](https://cio-wiki.org/wiki/Remote_Procedure_Call_(RPC))
	* [Remote Procedure Call - Wikipedia](https://en.wikipedia.org/wiki/Remote_procedure_call)
	* [Remote Procedure Calls - Paul Krzyzanowski](https://www.cs.rutgers.edu/~pxk/417/notes/08-rpc.html)
	* [What is RPC and why is it so important?(windows) - StackOverflow](https://superuser.com/questions/616098/what-is-rpc-and-why-is-it-so-important)
	* [How RPC Works - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc738291(v=ws.10))
	* [RPC Components - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/Rpc/microsoft-rpc-components)
* **Sandboxing**
	* [Advanced Desktop Application Sandboxing via AppContainer](https://www.malwaretech.com/2015/09/advanced-desktop-application-sandboxing.html)
	* [Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)
* **Scripting Host**
	* [wscript - docs.ms](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wscript)
		* Windows Script Host provides an environment in which users can execute scripts in a variety of languages that use a variety of object models to perform tasks.
* **Security Descriptor Definition Language**
	* [The Security Descriptor Definition Language of Love (Part 1) - technet.ms](https://blogs.technet.microsoft.com/askds/2008/04/18/the-security-descriptor-definition-language-of-love-part-1/)
	* [The Security Descriptor Definition Language of Love (Part 2) - technet.ms](https://blogs.technet.microsoft.com/askds/2008/05/07/the-security-descriptor-definition-language-of-love-part-2/)
* [SECURITY_DESCRIPTOR_CONTROL - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control?redirectedfrom=MSDN)
		* The SECURITY_DESCRIPTOR_CONTROL data type is a set of bit flags that qualify the meaning of a security descriptor or its components. Each security descriptor has a Control member that stores the SECURITY_DESCRIPTOR_CONTROL bits.
* **Security Support Providers**
	* [Security Support Provider Interface Architecture - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture)
	* [SSP Packages Provided by Microsoft - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/ssp-packages-provided-by-microsoft)
	* [Secure Channel - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/secure-channel)
		* Secure Channel, also known as Schannel, is a security support provider (SSP) that contains a set of security protocols that provide identity authentication and secure, private communication through encryption. Schannel is primarily used for Internet applications that require secure Hypertext Transfer Protocol (HTTP) communications.
	* [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge.net](http://davenport.sourceforge.net/ntlm.html)
	* [Microsoft Digest SSP - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/microsoft-digest-ssp)
		* Microsoft Digest is a security support provider (SSP) that implements the Digest Access protocol, a lightweight authentication protocol for parties involved in Hypertext Transfer Protocol (HTTP) or Simple Authentication Security Layer (SASL) based communications. Microsoft Digest provides a simple challenge response mechanism for authenticating clients. This SSP is intended for use by client/server applications using HTTP or SASL based communications.
* **Services**
	* [Creating a service using sc.exe](https://support.microsoft.com/en-us/help/251192/how-to-create-a-windows-service-by-using-sc-exe)
* **Service Accounts**
	* [Service Account best practices Part 1: Choosing a Service Account](https://4sysops.com/archives/service-account-best-practices-part-1-choosing-a-service-account/)
		* In this article you will learn the fundamentals of Windows service accounts. Specifically, we discover the options and best practices concerning the selection of a service account for a particular service application.
* **Server Message Block(SMB)**
	* [Server Message Block Overview - msdn.ms](https://msdn.microsoft.com/fr-fr/library/hh831795%28v=ws.11%29.aspx)
* **Symbol Files**
	* [Process Security and Access Rights - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx)
	* [OpenProcessToken function - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295%28v=vs.85%29.aspx)
	* [Symbols and Symbol Files - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols-and-symbol-files)
	* [Symbol Files - docs ms](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)
	* [microsoft-pdb](https://github.com/Microsoft/microsoft-pdb)
		* This repo contains information from Microsoft about the PDB (Program Database) Symbol File format.
	* [Public and Private Symbols - docs ms](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/public-and-private-symbols)
	* [How to Inspect the Content of a Program Database (PDB) File](https://www.codeproject.com/Articles/37456/How-To-Inspect-the-Content-of-a-Program-Database-P)
	* [microsoft-pdb](https://github.com/Microsoft/microsoft-pdb)
		* This repo contains information from Microsoft about the PDB (Program Database) Symbol File format.
	* [Symbol Files](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363368(v=vs.85).aspx)
		* Normally, debugging information is stored in a symbol file separate from the executable. The implementation of this debugging information has changed over the years, and the following documentation will provide guidance regarding these various implementations .
* **Syscalls**
	* [windows-syscall-table](https://github.com/tinysec/windows-syscall-table)
		* windows syscall table from xp ~ 10 rs2
	* [How Do Windows NT System Calls REALLY Work?](http://www.codeguru.com/cpp/w-p/system/devicedriverdevelopment/article.php/c8035/How-Do-Windows-NT-System-Calls-REALLY-Work.htm)
	* [Debugging Functions - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679303.aspx)
	* [Intercepting System Calls on x86_64 Windows](http://jbremer.org/intercepting-system-calls-on-x86_64-windows/)
* **User Account Control(UAC)**
	* [Protecting Windows Networks – UAC - dfirblog.wordpress.com](https://dfirblog.wordpress.com/2015/10/24/protecting-windows-networks-uac/) 
	* User Account Control - Steven Sinofsky(blogs.msdn)](https://blogs.msdn.microsoft.com/e7/2008/10/08/user-account-control/)
	* [Inside Windows Vista User Account Control - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc138019(v=msdn.10)?redirectedfrom=MSDN)
	* [Inside Windows 7 User Account Control - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/dd822916(v=msdn.10)?redirectedfrom=MSDN)
	* [User Account Control - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secauthz/user-account-control)
	* [User Account Control Step-by-Step Guide - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc709691(v=ws.10))
	* [User Account Control: Inside Windows 7 User Account Control - Mark Russinovich](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/dd822916(v=msdn.10))
* **Volume Shadow Copy Service**
	* [About the Volume Shadow Copy Service - docs.ms](https://docs.microsoft.com/en-us/windows/win32/vss/about-the-volume-shadow-copy-service)
* **Windows Filtering Platform**
	* [Windows Filtering Platform: Persistent state under the hood](http://blog.quarkslab.com/windows-filtering-platform-persistent-state-under-the-hood.html)
* **Windows Communication Foundation**
	* [Windows Communication Foundation - Guide to the Documentation - docs.ms]
	* [What Is Windows Communication Foundation](https://docs.microsoft.com/en-us/dotnet/framework/wcf/whats-wcf)
		* Windows Communication Foundation (WCF) is a framework for building service-oriented applications. Using WCF, you can send data as asynchronous messages from one service endpoint to another. A service endpoint can be part of a continuously available service hosted by IIS, or it can be a service hosted in an application. An endpoint can be a client of a service that requests data from a service endpoint. The messages can be as simple as a single character or word sent as XML, or as complex as a stream of binary data.
	* [Fundamental Windows Communication Foundation Concepts](https://docs.microsoft.com/en-us/dotnet/framework/wcf/fundamental-concepts)
		*  WCF is a runtime and a set of APIs for creating systems that send messages between services and clients. The same infrastructure and APIs are used to create applications that communicate with other applications on the same computer system or on a system that resides in another company and is accessed over the Internet.
	* [Windows Communication Foundation Architecture Architecture Graphic](https://docs.microsoft.com/en-us/dotnet/framework/wcf/architecture)

---------------------
#### Writeups
* **Exploit Prevention/Mitigation/Hardening**
	* [Preventing the Exploitation of Structured Exception Handler (SEH) Overwrites with SEHOP](https://blogs.technet.microsoft.com/srd/2009/02/02/preventing-the-exploitation-of-structured-exception-handler-seh-overwrites-with-sehop/)
	* [Windows 8 ASLR Explained](http://blog.ptsecurity.com/2012/12/windows-8-aslr-internals.html)
	* [Introduction to Windows Kernel Security](http://blog.cmpxchg8b.com/2013/05/introduction-to-windows-kernel-security.html)
	* [How Control Flow Guard Drastically Caused Windows 8.1 Address Space and Behavior Changes](http://www.alex-ionescu.com/?p=246)
	* [Technical Overview of Windows UEFI Startup Process](http://news.saferbytes.it/analisi/2013/10/windows-uefi-startup-a-technical-overview/)
	* [Detecting stealthier cross-process injection techniques with Windows Defender ATP: Process hollowing and atom bombing](https://blogs.technet.microsoft.com/mmpc/2017/07/12/detecting-stealthier-cross-process-injection-techniques-with-windows-defender-atp-process-hollowing-and-atom-bombing/)
	
* [Hyper-V internals](https://hvinternals.blogspot.fr/2015/10/hyper-v-internals.html)
	* [Hyper-V debugging for beginner](https://hvinternals.blogspot.fr/2015/10/hyper-v-debugging-for-beginners.html)
	* [Windows Operating System Archaeology](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology)
	* [Understanding Windows at a deeper level - Sessions, Window Stations, and Desktops](https://brianbondy.com/blog/100/understanding-windows-at-a-deeper-level-sessions-window-stations-and-desktops)
	* [Introduction to ADS: Alternate Data Streams](https://hshrzd.wordpress.com/2016/03/19/introduction-to-ads-alternate-data-streams/)
	* [Creative and unusual things that can be done with the Windows API.](https://github.com/LazoCoder/Windows-Hacks)



---------------------
### <a name="linux">Linux General</a>
* [Introduction to Linux - Machtelt Garrels](http://www.tldp.org/LDP/intro-linux/html/intro-linux.html)
	* Excellent doc covering every aspect of linux. Deserves at least 1 skim through.
* [Linux Documentation Project](http://www.tldp.org/)
	* The Linux Documentation Project is working towards developing free, high quality documentation for the Linux operating system. The overall goal of the LDP is to collaborate in all of the issues of Linux documentation.
* [Bash Guide for Beginners](http://www.tldp.org/LDP/Bash-Beginners-Guide/html/Bash-Beginners-Guide.html)
* [pagexec - GRSEC](https://pax.grsecurity.net/docs/pageexec.txt)


---------------------
### <a name="linux">Linux Internals</a>
* **Linux Internals**
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
* **Drivers**
	* [Linux Device Drivers book](http://www.makelinux.net/ldd3/)
* **ELF**
	* [The 101 of ELF Binaries on Linux: Understanding and Analysis](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)
	* [Understanding the ELF](https://medium.com/@MrJamesFisher/understanding-the-elf-4bd60daac571)
	* [ELF Format](http://www.skyfree.org/linux/references/ELF_Format.pdf)
* **FileSystems**
	* Linux Filesystem infographic
		* [Part 1](http://i.imgur.com/EU6ga.jpg)
		* [Part 2](http://i.imgur.com/S5Ds2.jpg)
* **Kernel**
	* [Linux Kernel Explanation/Walk through](http://www.faqs.org/docs/Linux-HOWTO/KernelAnalysis-HOWTO.html)
	* [Kernel booting process](https://github.com/0xAX/linux-insides/tree/master/Booting)
		* This chapter describes linux kernel booting process.
	* [How the Kernel manages Memory - Linux](http://duartes.org/gustavo/blog/post/how-the-kernel-manages-your-memory/)
	* [Linux Kernel Map](http://www.makelinux.net/kernel_map/)
		* Interactive map of the Linux Kernel
* **Memory**
	* [Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
	* [Memory Management: Paging](https://www.cs.rutgers.edu/~pxk/416/notes/09a-paging.html)
	* [Anatomy of a program in memory](http://duartes.org/gustavo/blog/post/anatomy-of-a-program-in-memory/) 
		* Writeup on the structure of program memory in Linux.
	* [Understanding !PTE - Non-PAE and X64](http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx?Redirected=true)
	* [Linux GLibC Stack Canary Values](https://xorl.wordpress.com/2010/10/14/linux-glibc-stack-canary-values/)
	* [Stack Smashing Protector](http://wiki.osdev.org/Stack_Smashing_Protector)
	* [Memory Translation and Segmentation](http://duartes.org/gustavo/blog/post/memory-translation-and-segmentation/)
* **Out-of-Memory(OOM) Killer**
	* [Taming the OOM killer - Goldwyn Rodrigues](https://lwn.net/Articles/317814/)
	* [OOM_Killer - linux-mm.org](https://linux-mm.org/OOM_Killer)
	* [How does the OOM killer decide which process to kill first? - stackexchange](https://unix.stackexchange.com/questions/153585/how-does-the-oom-killer-decide-which-process-to-kill-first)
	* [OOM - Linux kernel user's and administrator's guide](https://static.lwn.net/kerneldoc/admin-guide/mm/concepts.html)
		* [How to diagnose causes of oom-killer killing processes - Stackexchange](https://serverfault.com/questions/134669/how-to-diagnose-causes-of-oom-killer-killing-processes)
	* [Linux Kernel limits - eloquence.marxmeier](http://eloquence.marxmeier.com/sdb/html/linux_limits.html)
		* This document provides an overview of the default Linux Kernel limits (kernel parameter) and where they are defined.
	* [The OOM killer may be called even when there is still plenty of memory available - bl0g.krunch.be](http://bl0rg.krunch.be/oom-frag.html)
	* [How to Configure the Linux Out-of-Memory Killer - Robert Chase](https://www.oracle.com/technical-resources/articles/it-infrastructure/dev-oom-killer.html)
* **Process Structure/Syscalls**
	* [FlexSC: Flexible System Call Scheduling with Exception-Less System Calls](https://www.cs.cmu.edu/~chensm/Big_Data_reading_group/papers/flexsc-osdi10.pdf)
	* [List of Linux/i386 system calls](http://asm.sourceforge.net/syscall.html)
	* [Linux Syscall Table](http://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html)
		* Complete listing of all Linux Syscalls
	* [Killing a process and all of its descendants - Igor Sarcevic](http://morningcoffee.io/killing-a-process-and-all-of-its-descendants.html)
	* [UNIX one-liner to kill a hanging Firefox process - Vasudev Ram](https://jugad2.blogspot.com/2008/09/unix-one-liner-to-kill-hanging-firefox.html?m=1)
* **X** 
	* [X Window System Explained](https://magcius.github.io/xplain/article/index.html)
	* [Foreign LINUX](https://github.com/wishstudio/flinux)
		* Foreign LINUX is a dynamic binary translator and a Linux system call interface emulator for the Windows platform. It is capable of running unmodified Linux binaries on Windows without any drivers or modifications to the system. This provides another way of running Linux applications under Windows in constrast to Cygwin and other tools.


---------------------
### <a name="ARM">ARM References</a>
* [A Detailed Analysis of Contemporary ARM and x86 Architectures](http://research.cs.wisc.edu/vertical/papers/2013/isa-power-struggles-tr.pdf)
	* RISC vs. CISC wars raged in the 1980s when chip area andprocessor design complexity were the primary constraints anddesktops and servers exclusively dominated the computing land-scape. Today, energy and power are the primary design con-straints and the computing landscape is significantly different:growth in tablets and smartphones running ARM (a RISC ISA)is surpassing that of desktops and laptops running x86 (a CISCISA). Further, the traditionally low-power ARM ISA is enter-ing the high-performance server market, while the traditionallyhigh-performance x86 ISA is entering the mobile low-power de-vice market. Thus, the question of whether ISA plays an intrinsicrole in performance or energy efficiency is becoming important,and we seek to answer this question through a detailed mea-surement based study on real hardware running real applica-tions. We analyze measurements on the ARM Cortex-A8 andCortex-A9 and Intel Atom and Sandybridge i7 microprocessorsover workloads spanning mobile, desktop, and server comput-ing. Our methodical investigation demonstrates the role of ISAin modern microprocessors’ performance and energy efficiency.We find that ARM and x86 processors are simply engineeringdesign points optimized for different levels of performance, andthere is nothing fundamentally more energy efficient in one ISAclass or the other. The ISA being RISC or CISC seems irrelevant.
* [ARM Documentation](http://infocenter.arm.com/help/index.jsp?noscript=1)
* [Windows 8 Security and ARM](http://2012.ruxconbreakpoint.com/assets/Uploads/bpx/alex-breakpoint2012.pdf)


---------------------
### <a name="osx">OS X Internals</a>

* **Kernel Extensions**
	* [Kernel Extension Overview - developer.apple](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html)
* **Tools**
	* [Instruments - OS X system analysis](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/Introduction/Introduction.html)
		* Instruments is a performance-analysis and testing tool for dynamically tracing and profiling OS X and iOS code. It is a flexible and powerful tool that lets you track a process, collect data, and examine the collected data. In this way, Instruments helps you understand the behavior of both user apps and the operating system.

---------------------
### Other 
* [Intel SGX Explained](https://eprint.iacr.org/2016/086.pdf)
	* This paper analyzes Intel SGX, based on the 3 pa- pers [ 14 , 78 , 137 ] that introduced it, on the Intel Software Developer’s Manual [ 100 ] (which supersedes the SGX manuals [ 94 , 98 ]), on an ISCA 2015 tutorial [ 102 ], and on two patents [ 108 , 136 ]. We use the papers, reference manuals, and tutorial as primary data sources, and only draw on the patents to fill in missing information. This  paper’s  contributions  are  a  summary  of  the Intel-specific architectural and micro-architectural details needed to understand SGX, a detailed and structured pre- sentation of the publicly available information on SGX, a series of intelligent guesses about some important but undocumented aspects of SGX, and an analysis of SGX’s security properties.



--------------------
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




#### To be Sorted

* [Windows 8 Security and ARM](http://2012.ruxconbreakpoint.com/assets/Uploads/bpx/alex-breakpoint2012.pdf)
* [BCDEdit /dbgsettings - msdn](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542187(v=vs.85).aspx)
	* [AppInit_DLLs in Windows 7 and Windows Server 2008 R2](https://msdn.microsoft.com/en-us/library/windows/desktop/dd744762(v=vs.85).aspx)
	* [Windows Data Protection](https://msdn.microsoft.com/en-us/library/ms995355.aspx)
	* [Application Compatibility in Windows](https://technet.microsoft.com/en-us/windows/jj863248)
	* [Hard Links and Junctions - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365006(v=vs.85).aspx)
	* [Security Configuration Wizard](https://technet.microsoft.com/en-us/library/cc754997(v=ws.11).aspx)
		* The Security Configuration Wizard (SCW) guides you through the process of creating, editing, applying, or rolling back a security policy. A security policy that you create with SCW is an .xml file that, when applied, configures services, network security, specific registry values, and audit policy. SCW is a role-based tool: you can use it to create a policy that enables services, firewall rules, and settings that are required for a selected server to perform specific roles, such as a file server, a print server, or a domain controller.
* [Executing Macros From a DOCX With Remote Template Injection - redxorblue.com](http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html)
* [LM, NTLM, Net-NTLMv2, oh my! - Peter Gombos](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4)
* [ Microsoft Office – NTLM Hashes via Frameset - netbiosX](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
* [SMB/HTTP Auth Capture via SCF File - mubix](https://room362.com/post/2016/smb-http-auth-capture-via-scf/)
* [Places of Interest in Stealing NetNTLM Hashes - Osanda Malith](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [Microsoft Word – UNC Path Injection with Image Linking - Thomas Elling](https://blog.netspi.com/microsoft-word-unc-path-injection-image-linking/)

https://googleprojectzero.blogspot.com/2019/08/down-rabbit-hole.html
https://web.archive.org/web/20060904080018/http://security.tombom.co.uk/shatter.html

* [The 68 things the CLR does before executing a single line of your code - Matt Warren](https://web.archive.org/web/20170614215931/http://mattwarren.org:80/2017/02/07/The-68-things-the-CLR-does-before-executing-a-single-line-of-your-code/)
* [CLR Configuration Knobs - dotnet/coreclr](https://github.com/dotnet/coreclr/blob/master/Documentation/project-docs/clr-configuration-knobs.md)
	* There are two primary ways to configure runtime behavior: CoreCLR hosts can pass in key-value string pairs during runtime initialization, or users can set special variables in the environment or registry. Today, the set of configuration options that can be set via the former method is relatively small, but moving forward, we expect to add more options there. Each set of options is described below.

* [The Windows Research Kernel AKA WRK](https://github.com/Zer0Mem0ry/ntoskrnl)
	* Is a part of the source code of the actual windows NT Kernel. WRK is designed for academic uses and research, by no means it can be used for commercial purposes.
* [chcp](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/chcp)
	* Changes the active console code page. If used without parameters, chcp displays the number of the active console code page.

* [NUMA Support - docs.ms](https://docs.microsoft.com/en-us/windows/win32/procthread/numa-support)

* [Standard ECMA-335 Common Language Infrastructure (CLI) 6th ed- ECMA](https://www.ecma-international.org/publications/standards/Ecma-335.htm)

* [What are the undocumented features and limitations of the Windows FINDSTR command? - StackOverflow](https://stackoverflow.com/questions/8844868/what-are-the-undocumented-features-and-limitations-of-the-windows-findstr-comman)

* [Kerberos.NET](https://github.com/SteveSyfuhs/Kerberos.NET)
https://xinu.cs.purdue.edu/
https://github.com/mit-pdos/xv6-public
http://pages.cs.wisc.edu/~remzi/OSTEP/
http://man7.org/tlpi/
https://wiki.osdev.org/Expanded_Main_Page
https://www.haiku-os.org/
https://devblogs.microsoft.com/commandline/learn-about-windows-console-and-windows-subsystem-for-linux-wsl/
https://j00ru.vexillium.org/syscalls/nt/64/
http://arno.org/arnotify/2006/10/on-the-origins-of-ds_store/
https://0day.work/parsing-the-ds_store-file-format/
https://en.internetwache.org/scanning-the-alexa-top-1m-for-ds-store-files-12-03-2018/
https://www.vergiliusproject.com/

https://docs.microsoft.com/en-us/virtualization/windowscontainers/about/
https://stackoverflow.com/questions/17935873/malloc-fails-when-there-is-still-plenty-of-swap-left
http://www.adrc.com/ckr/windows_bootup_process.html
https://social.technet.microsoft.com/wiki/contents/articles/11341.windows-7-the-boot-process-explained.aspx
http://www.codemachine.com/article_kernelstruct.html



