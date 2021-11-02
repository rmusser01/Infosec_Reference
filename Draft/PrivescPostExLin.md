# Linux Privilege Escalation & Post-Exploitation

----------------------------------------------------------------------
## Table of Contents
- [101](#lin101)
- [Linux Code Injection Techniques](#lcit)
- [Living_off_The_Land](#lolbins-lin)

- [Linux Post Exploitation](#linpost)
	- [Execution](#linexec)
	- [Persistence](#linpersist)
	- [Privilege Escalation](#linprivesc)
	- [Defense Evasion](#lindefe)
	- [Credential Access](#lincredac)
	- [Discovery](#lindisco)
	- [Lateral Movement](#linlat)
	- [Collection](#lincollect)
	- [Linux Defense Evasion](#lindefev)
	- 
- [Linux Specific Technologies](#lintech)
	- 
----------------------------------------------------------------------


























-----------------------------------------------------------------------------------------------------------------------------------
### <a name="linpost">Post-Exploitation Linux</a>
* **101**
	* [More on Using Bash's Built-in /dev/tcp File (TCP/IP)](http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip)
	* [Bash Brace Expansion Cleverness - Jon Oberhide](https://jon.oberheide.org/blog/2008/09/04/bash-brace-expansion-cleverness/)
	* [Basic Linux Privilege Escalation - g0tmi1k](http://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
		* Not so much a script as a resource, g0tmi1k’s blog post here has led to so many privilege escalations on Linux system’s it’s not funny. Would definitely recommend trying out everything on this post for enumerating systems.
* **Discovery**<a name="lindisco"></a>
	* **Articles/Blogposts/Writeups**
		* [Data Collection with Python on Linux Systems - Ogunal(2020)](https://en.ogunal.com/data-collection-with-python-on-linux-system/)
	* **Account Discovery**
	* **Browser Bookmark Discovery**
	* **File and Directory Discovery**
	* **Network Service Scanning**
		* **Articles/Blogposts/Writeups**
			* [Finding DNS servers provided by DHCP using network manager on Linux -ilostmynotes.blogspot ](https://ilostmynotes.blogspot.com/2019/03/finding-dns-servers-provided-by-dhcp.html)
		* **Tools**
			* [Baboossh](https://github.com/cybiere/baboossh)
				* BabooSSH allows you, from a simple SSH connection to a compromised host, to quickly gather info on other SSH endpoints to pivot and compromise them.
	* **Network Sniffing**
	* **Password Policy Discovery**
	* **Permission Groups Discovery**
	* **Process Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**		
			* [pspy](https://github.com/DominicBreuker/pspy)
				* pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute.  The tool gathers the info from procfs scans. Inotify watchers placed on selected parts of the file system trigger these scans to catch short-lived processes.
	* **Remote System Discovery**
		* [nullinux](https://github.com/m8r0wn/nullinux)
			* nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. If no username and password are provided, nullinux will attempt to connect to the target using an SMB null session. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation.This program assumes Python 2.7, and the smbclient package is installed on the machine. Run the setup.sh script to check if these packages are installed.
	* **Software Discovery**
	* **System Information Discovery**
		* [LinEnum](https://github.com/rebootuser/LinEnum)
	* **System Network Configuration Discovery**
 	* **System Network Connections Discovery**
 	* **System Owner/User Discovery**
* **Execution**<a name="linexec"></a>
	* **Articles/Blogposts/Writeups**
	* **Tools**
	* **LoLBins**
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [GTFOBins](https://gtfobins.github.io/#)
				* GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. The project collects legitimate functions of Unix binaries that can be abused to break out of restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks. 
			* [GTFOPlus](https://github.com/yuudev/gtfoplus)
		    	* GTFOPlus is a helper script that relies on the GTFOBins repo to identify standard Linux binaries that could assist with privilege escalation.
	* **Command and Scripting Interpreter**
		* **Bash**
			* **Tools**
				* [Orc](https://github.com/zMarch/Orc)
					* Orc is a post-exploitation framework for Linux written in Bash
	* **Exploitation for Client Execution**
	* **Inter-Process Communication**
	* **Native API**
		* **Articles/Blogposts/Writeups**	
			* [needle - Linux x86 run-time process manipulation(paper)](http://hick.org/code/skape/papers/needle.txt)
			* [In-Memory-Only ELF Execution (Without tmpfs) - Stuart](https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html)
		* **Tools**
			* [msf-elf-in-memory-execution](https://github.com/fbkcs/msf-elf-in-memory-execution)
				* Post module for Metasploit to execute ELF in memory
	* **Scheduled Task/Job**
		* **At**
		* **Launchd**
		* **Cron**
	* **Shared Modules**
	* **Software Deployment Tools**
	* **System Services**
		* **Launchctl**
		* **Service Execution**
	* **User Execution**
		* **Malicious Link**
		* **Malicious File**
			* **Articles/Blogposts/Writeups**	
				* [Introducing tmpnix - an alternative to static binaries for post exploitation - shiftordie.de](https://shiftordie.de/blog/2019/02/05/introducing-tmpnix-an-alternative-to-static-binaries-for-post-exploitation/)
				* [A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux - muppetlabs](http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html)
				* [No one expect command execution!](http://0x90909090.blogspot.fr/2015/07/no-one-expect-command-execution.html)
					* Command execution through native utilities
	* **Payloads**
		* **Tools**
			* [fireELF](https://github.com/rek7/fireELF)
				* fireELF is a opensource fileless linux malware framework thats crossplatform and allows users to easily create and manage payloads. By default is comes with 'memfd_create' which is a new way to run linux elf executables completely from memory, without having the binary touch the harddrive.
* **Persistence**<a name="linpersist"></a>
	* **Account Manipulation**
		* **Additional Azure Service Principal Credentials**
		* **Exchange Email Delegate Permissions**
		* **Add Office 365 Global Administrator Role**
		* **SSH Authorized Keys**
	* **BITS Jobs**
	* **Boot or Logon Autostart Execution**
		* **Registry Run Keys / Startup Folder**
		* **Authentication Package**
		* **Time Providers**
		* **Winlogon Helper DLL**
		* **Security Support Provider**
		* **Kernel Modules and Extensions**
		* **Re-opened Applications**
		* **LSASS Driver**
		* **Shortcut Modification**
		* **Port Monitors**
		* **Plist Modification**
	* **Boot or Logon Initialization Scripts**
		* **Logon Script (Windows)**
		* **Logon Script (Mac)**
		* **Network Logon Script**
		* **Rc.common**
		* **Startup Items**
		* **Browser Extensions**
	* **Browser Extensions**
	* **Compromise Client Software Binary**
		* **Tools**
			* [Debinject](https://github.com/UndeadSec/Debinject)
				* Inject malicious code into .debs	
	* **Create Account**
		* **Local Account**
		* **Domain Account**
		* **Cloud Account**
	* **Create or Modify System Process**
		* **Launch Agent**
		* **Systemd Service**
		* **Windows Service**
		* **Launch Daemon**
	* **Event Triggered Execution**
		* **Change Default File Association**
		* **Screensaver**
		* **Windows Management Instrumentation Event Subscription**
		* **.bash_profile and .bashrc**
		* **Trap**
		* **LC_LOAD_DYLIB Addition**
		* **Netsh Helper DLL**
		* **Accessibility Features**
		* **AppCert DLLs**
		* **AppInit DLLs**
		* **Application Shimming**
		* **Image File Execution Options Injection**
		* **PowerShell Profile**
		* **Emond**
		* **Component Object Model Hijacking**
	* **External Remote Services**
	* **Hijack Execution Flow**
		* **Services File Permissions Weakness**
		* **Executable Installer File Permissions Weakness**
		* **Services Registry Permissions Weakness**
		* **Path Interception by Unquoted Path**
		* **Path Interception by PATH Environment Variable**
		* **Path Interception by Search Order Hijacking**
		* **DLL Search Order Hijacking**
		* **DLL Side-Loading**
		* **LD_PRELOAD**
		* **Dylib Hijacking**
		* **COR_PROFILER**
		* **Implant Container Image**
	* **Implant Container Image**
	* **Office Application Startup**
		* **Add-ins**
		* **Office Template Macros**
		* **Outlook Forms**
		* **Outlook Rules**
		* **Outlook Home Page**
		* **Office Test**
	* **Pre-OS Boot**
		* **System Firmware**
		* **Component Firmware**
		* **Bootkit**
	* **Scheduled Task/Job**
		* **At (Windows)**
		* **Scheduled Task**
		* **At (Linux)**
		* **Launchd**
		* **Cron**
	* **Server Software Component**
		* **SQL Stored Procedures**
		* **Transport Agent**
		* **Web Shell**
	* **Traffic Signaling**
		* **Port Knocking**
	* **Valid Accounts**
		* **Default Accounts**
		* **Domain Accounts**
		* **Local Accounts**
		* **Cloud Accounts**
* **Privilege Escalation**<a name="linprivesc"></a>
	* **101**
		* [Basic Linux Privilege Escalation - g0tm1lk](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
		* [Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
		* [AllTheThings - Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#checklists)
	* **Articles/Blogposts/Writeups**
		* [How I did not get a shell - NCCGroup](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/how-i-did-not-get-a-shell/)
		* [Linux: VMA use-after-free via buggy vmacache_flush_all() fastpath - projectzero](https://bugs.chromium.org/p/project-zero/issues/detail?id=1664)
		* [Attack and Defend: Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
		* [Abusing PackageKit on Fedora/CentOS for fun & profit (from wheel to root). - sysdream.com](https://sysdream.com/news/lab/2020-05-25-abusing-packagekit-on-fedora-centos-for-fun-profit-from-wheel-to-root/)
	* **Exploits**
		* **Docker**
		* **Dirty COW**
			* [DirtyCow.ninja](https://dirtycow.ninja/)
		* **Huge Dirty COW**
			* [“Huge Dirty COW” (CVE-2017–1000405) The incomplete Dirty COW patch - Eylon Ben Yaakov](https://medium.com/bindecy/huge-dirty-cow-cve-2017-1000405-110eca132de0)
			* [HugeDirtyCow PoC](https://github.com/bindecy/HugeDirtyCowPOC)
				* A POC for the Huge Dirty Cow vulnerability (CVE-2017-1000405)
		* **dirty_sock**
		* [dirty_sock - Linux privilege escalation exploit via snapd (CVE-2019-7304)](https://github.com/initstring/dirty_sock)
			* In January 2019, current versions of Ubuntu Linux were found to be vulnerable to local privilege escalation due to a bug in the snapd API. This repository contains the original exploit POC, which is being made available for research and education. For a detailed walkthrough of the vulnerability and the exploit, please refer to the blog posting here.
			* [Linux Privilege Escalation via snapd (dirty_sock exploit)](https://initblog.com/2019/dirty-sock/)
		* **Kernel-based**
		* **Miscellaneous Software**
			* [Vim/Neovim Arbitrary Code Execution via Modelines - CVE-2019-12735](https://github.com/numirias/security/blob/master/doc/2019-06-04_ace-vim-neovim.md)
				* Vim before 8.1.1365 and Neovim before 0.3.6 are vulnerable to arbitrary code execution via modelines by opening a specially crafted text file.
			* [[0day] [exploit] Compromising a Linux desktop using... 6502 processor opcodes on the NES?! - scarybeastsecurity](https://scarybeastsecurity.blogspot.com/2016/11/0day-exploit-compromising-linux-desktop.html)
				*  A vulnerability and a separate logic error exist in the gstreamer 0.10.x player for NSF music files. Combined, they allow for very reliable exploitation and the bypass of 64-bit ASLR, DEP, etc. The reliability is provided by the presence of a turing complete “scripting” inside a music player. NSF files are music files from the Nintendo Entertainment System. Curious? Read on...
			* [systemd (systemd-tmpfiles) < 236 - 'fs.protected_hardlinks=0' Local Privilege Escalation](https://www.exploit-db.com/exploits/43935/)
	* **Techniques**
		* **Container-based**
			* [Using the docker command to root the host (totally not a security issue)](http://reventlov.com/advisories/using-the-docker-command-to-root-the-host)
				* It is possible to do a few more things more with docker besides working with containers, such as creating a root shell on the host, overwriting system configuration files, reading restricted stuff, etc.
			* [Linux Privilege Escalation via LXD & Hijacked UNIX Socket Credentials - Chris Moberly](https://shenaniganslabs.io/2019/05/21/LXD-LPE.html)
		* **Capabilities**
			* [An Interesting Privilege Escalation vector (getcap/setcap) - nxnjz](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)
			* [Linux Privilege Escalation using Capabilities - Raj Chandel](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)
		* **Cron jobs**
			* [Linux Privilege Escalation by Exploiting Cronjobs - Raj Chandel](https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/)
			* [Linux Privilege Escalation by Exploiting Cronjobs - ArmourInfoSec](https://www.armourinfosec.com/linux-privilege-escalation-by-exploiting-cronjobs/)
			* [Day 40: Privilege Escalation (Linux) by Modifying Shadow File for the Easy Win - int0x33](https://medium.com/@int0x33/day-40-privilege-escalation-linux-by-modifying-shadow-file-for-the-easy-win-aff61c1c14ed)
		 * **Exploitation for Privilege Escalation**
		* **GTFOBins**
		* **NFS**
			* [Linux Privilege Escalation using weak NFS permissions - Haider Mahmood](https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/)
			* [Linux Privilege Escalation using Misconfigured NFS - Raj Chandel](https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/)
			* [NFS weak permissions(Linux Privilege Escalation) - Touhid Shaikh](https://touhidshaikh.com/blog/?p=788)
			* [NFS, no_root_squash and SUID - Basic NFS Security - fullyautolinux](https://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html)
			* [A tale of a lesser known NFS privesc - gquere](https://www.errno.fr/nfs_privesc)
			* [NFS - myexperiments.io](https://myexperiments.io/linux-privilege-escalation.html#vii-network-file-system)
		* **PATH**
			* [Abusing users with '.' in their PATH: - gimboyd](http://www.dankalia.com/tutor/01005/0100501004.htm)
		 * **Process Injection**
		 	* **Shared Libraries**
		 * **Setuid and Setgid**
			* [SUID - myexperiments.io](https://myexperiments.io/linux-privilege-escalation.html#vi-file-permission)
			* [SUID Executables - NetbiosX](https://pentestlab.blog/category/privilege-escalation/)
			* **Tools**
				* [SUID3NUM](https://github.com/Anon-Exploiter/SUID3NUM)
					* A standalone python script which utilizes python's built-in modules to find SUID bins, separate default bins from custom bins, cross-match those with bins in GTFO Bin's repository & auto-exploit those, all with colors! ( ͡ʘ ͜ʖ ͡ʘ)
		 * **Sudo**
			* [Dangerous Sudoers Entries – Series, 5 parts](https://blog.compass-security.com/2012/10/dangerous-sudoer-entries-part-1-command-execution/)
			* [sudo - myexperiments.io](https://myexperiments.io/linux-privilege-escalation.html#v-sudo)
		 * **Sudo Caching**
		 * **Valid Accounts**
		 * **Web Shell**
		* **Wildcards**
			* [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)
			* [wildpwn](https://github.com/localh0t/wildpwn)
		* **Writable Files**
			* [uptux](https://github.com/initstring/uptux)
				* Linux privilege escalation checks (systemd, dbus, socket fun, etc)
	* **Solaris**
		* [uid=0 is deprecated: A trick unix-privesc-check doesn’t yet know - TMB](https://labs.portcullis.co.uk/blog/uid0-is-deprecated-a-trick-unix-privesc-check-doesnt-yet-know/)
		* [dtappgather-poc.sh](https://github.com/HackerFantastic/Public/blob/master/exploits/dtappgather-poc.sh)
			* Exploit PoC reverse engineered from EXTREMEPARR which provides local root on Solaris 7 - 11 (x86 & SPARC). Uses a environment variable of setuid binary dtappgather to manipulate file permissions and create a user owned directory anywhere on the system (as root). Can then add a shared object to locale folder and run setuid binaries with an untrusted library file.
	* **Talks/Videos**
		* [Chw00t: Breaking Unixes’ Chroot Solutions](https://www.youtube.com/watch?v=1A7yJxh-fyc)
	* **Tools**
		* [LinEnum](http://www.rebootuser.com/?p=1758)
			* This tool is great at running through a heap of things you should check on a Linux system in the post exploit process. This include file permissions, cron jobs if visible, weak credentials etc. The first thing I run on a newly compromised system.
		* [Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)
			* Linux Exploit Suggester; based on operating system release number.  This program run without arguments will perform a 'uname -r' to grab the Linux Operating Systems release version, and return a suggestive list of possible exploits. Nothing fancy, so a patched/back-ported patch may fool this script.  Additionally possible to provide '-k' flag to manually enter the Kernel Version/Operating System Release Version.
		* [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
			* Linux privilege escalation auditing tool
		* [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
			* Next-Generation Linux Kernel Exploit Suggester 
		* [LinuxPrivChecker](http://www.securitysift.com/download/linuxprivchecker.py)
			* This is a great tool for once again checking a lot of standard things like file permissions etc. The real gem of this script is the recommended privilege escalation exploits given at the conclusion of the sc
			* [Github](https://github.com/oschoudhury/linuxprivchecker)
		* [Unix Privilege Escalation Checker](https://code.google.com/p/unix-privesc-check/)
			* Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases). It is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed). It can run either as a normal user or as root (obviously it does a better job when running as root because it can read more files).
		* [EvilAbigail](https://github.com/GDSSecurity/EvilAbigail/blob/master/README.md)
			* Initrd encrypted root fs attack
		* [kernelpop](https://github.com/spencerdodd/kernelpop)
			* kernel privilege escalation enumeration and exploitation framework
		* [GTFOPlus](https://github.com/netspooky/gtfoplus)
			* GTFOPlus is a helper script that relies on the GTFOBins repo to identify standard Linux binaries that could assist with privilege escalation.
* **Defense Evasion**<a name="lindefe"></a>
	* **Binary Padding**
	* **Clear Command History**
	* **Compile After Delivery**
	* **Connection Proxy**
	* **Disabling Security Tools**
	* **Endpoint Detection Response(EDR)**
		* [Zombie Ant Farm: A Kit For Playing Hide and Seek with Linux EDRs.](https://github.com/dsnezhkov/zombieant/)
			* Zombie Ant Farm: Primitives and Offensive Tooling for Linux EDR evasion.
	* **Execution Guardrails**
* **Credential Access**<a name="lincredac"></a>
	* **Bash History**
		* **Articles/Blogposts**
		* **Tools**
	* **Brute Force**
		* **Articles/Blogposts**
		* **Tools**
	* **Credential Dumping**
		* **Articles/Blogposts**
			* [Where 2 Worlds Collide: Bringing Mimikatz et al to UNIX - Tim(-Wadha) Brown](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Wadhwa-Brown-Where-2-Worlds-Collide-Bringing-Mimikatz-et-al-to-UNIX.pdf)
			    * What this talk is about: Why a domain joined UNIX box matters to Enterprise Admins; How AD based trust relationships on UNIX boxes are abused; How UNIX admins can help mitigate the worst side effects;
			* [linikatz](https://github.com/CiscoCXSecurity/linikatz)
				* This repository contains all of the scripts and source code for "Where 2 Worlds Collide: Bringing Mimikatz et al to UNIX". In addition to the main linikatz.sh script, this also includes auditd policies, John the Ripper rules, Metasploit post-exploitation modules and fuzzers. More will follow in due course.
			* [Kerberos Credential Thiever (GNU/Linux) - Ronan Loftus, Arne Zismer](https://www.delaat.net/rp/2016-2017/p97/report.pdf)
				* Kerberos is an authentication protocol that aims to reduce the amount of sensitive data that needs to be sent across a network with lots of network resources that require authentication.  This reduces the risk of having authentication data stolen by an attacker.  Network Attached Storage devices, big data processing applications like Hadoop, databases and web servers commonly run on GNU/Linux machines that are integrated in a Kerberos system.  Due to the sensitivity of the data these services deal with, their security is of great importance.  There has been done a lot of research about sniffing and replaying Kerberos  credentials  from  the  network.   However,  little  work  has  been  done  on  stealing  credentials from Kerberos clients on GNU/Linux.  We therefore investigate the feasibility of extracting and reusing Kerberos credentials from GNU/Linux machines.  In this research we show that all the credentials can be extracted, independently of how they are stored on the client.  We also show how these credentials can be reused to impersonate the compromised client.  In order to improve the security of Kerberos, we also propose mitigations to these attacks.
			* [Exfiltrating credentials via PAM backdoors & DNS requests - x-c3ll](https://x-c3ll.github.io/posts/PAM-backdoor-DNS/)
		* **Tools**
			* [linikatz](https://github.com/portcullislabs/linikatz)
			* [mimipenguin](https://github.com/huntergregal/mimipenguin)
				* A tool to dump the login password from the current linux user
			* [3snake](https://github.com/blendin/3snake)
				* Targeting rooted servers, reads memory from sshd and sudo system calls that handle password based authentication. Doesn't write any memory to the traced processes. Spawns a new process for every sshd and sudo command that is run. Listens for the proc event using netlink sockets to get candidate processes to trace. When it receives an sshd or sudo process ptrace is attached and traces read and write system calls, extracting strings related to password based authentication.
			* [Tickey](https://github.com/TarlogicSecurity/tickey)
				* Tool to extract Kerberos tickets from Linux kernel keys. [Paper](https://www.delaat.net/rp/2016-2017/p97/report.pdf)
			* [Impost3r](https://github.com/ph4ntonn/Impost3r/blob/master/README_EN.md)
				* Impost3r is a tool that aim to steal many kinds of linux passwords(including ssh,su,sudo) written by C
	* **Credentials from Web Browsers**
		* **Articles/Blogposts**
		* **Tools**
	* **Credentials in Files**
		* **Articles/Blogposts**
			* [Digging passwords in Linux swap](http://blog.sevagas.com/?Digging-passwords-in-Linux-swap)
		* **Tools**
			* [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
				* KeyTabExtract is a little utility to help extract valuable information from 502 type .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script will extract information such as the realm, Service Principal, Encryption Type and NTLM Hash.
			* [swap_digger](https://github.com/sevagas/swap_digger)
				* swap_digger is a bash script used to automate Linux swap analysis for post-exploitation or forensics purpose. It automates swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, HTTP basic authentication, WiFi SSID and keys, etc.
	* **Exploitation for Credential Access**
		* **Articles/Blogposts**
			* [Triple-Fetch-Kernel-Creds](https://github.com/coffeebreakerz/Tripple-Fetch-Kernel-Creds)
				* Attempt to steal kernelcredentials from launchd + task_t pointer (Based on: CVE-2017-7047)
		* **Tools**
	* **Input Capture**
		* **Articles/Blogposts**
		* **Tools**
			* [SudoHulk](https://github.com/hc0d3r/sudohulk)
				* This tool change sudo command, hooking the execve syscall using ptrace, tested under bash and zsh
	* **Network Sniffing**
		* **Articles/Blogposts**
		* **Tools**
	* **Private Keys**
		* **Articles/Blogposts**
		* **Tools**	
	* **Steal Web Session Cookie**
		* **Articles/Blogposts**
		* **Tools**
	* **Two-Factor Authentication Interception**
		* **Articles/Blogposts**
		* **Tools**
* **Lateral Movement**<a name="linlate"></a>
	* **Application Deployment Software**
	* **Exploitation of Remote Services**
	* **Internal Spearphishing**
	* **Port Forwarding & Proxies**
		* [PortPush](https://github.com/itsKindred/PortPush)
			* PortPush is a small Bash utility used for pivoting into internal networks upon compromising a public-facing host.
	* **Remote File Copy**
	* **Remote Services**
		* **RDP**
			* [The RDP Through SSH Encyclopedia - Carrie Roberts](https://www.blackhillsinfosec.com/the-rdp-through-ssh-encyclopedia/)
				* I have needed to remind myself how to set up RDP access through an SSH connection so many times that I’ve decided to document it here for future reference. I hope it proves useful to you as well. I do “adversary simulation” for work and so I present this information using terms like “attacker” and “target” but this info is also useful for performing system administration tasks.
		* **SSH**
			* [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
			* [SSH manpage](https://linux.die.net/man/1/ssh)
			* [SSH Essentials: Working with SSH Servers, Clients, and Keys - Justin Ellingwood](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys)
			* [An SSH tunnel via multiple hops - stackoverflow](https://superuser.com/questions/96489/an-ssh-tunnel-via-multiple-hops)
	* **SSH Hijacking**
 	* **Third-party Software**
* **Collection**<a name="lincollect"></a>
	* **Audio Capture**
	* **Automated Collection**
	* **Clipboard Data**
	* **Data from Information Repositories**
	* **Data from Local System**
		* **Tools**
			* [swap_digger](https://github.com/sevagas/swap_digger)
				* swap_digger is a bash script used to automate Linux swap analysis for post-exploitation or forensics purpose. It automates swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, HTTP basic authentication, WiFi SSID and keys, etc.
	* **Data from Network Shared Drive**
	* **Data from Removable Media**
	* **Data Staged**
	* **Input Capture**
	* **Screen Capture**
-----------------------------------------------------------------------------------------------------------------------------------




































-----------------------------------------------------------------------------------------------------------------------------------
### <a name="lict"></a>Linux Code Injection
* **101**
* **Articles/Blogposts/Writeups**
	* [Pure In-Memory (Shell)Code Injection In Linux Userland - blog.sektor7](https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md)
* **Talks & Presentations**
* **Tools**
	* [Jugaad - Thread Injection Kit](https://github.com/aseemjakhar/jugaad)
		* Jugaad is an attempt to create CreateRemoteThread() equivalent for `*nix` platform. The current version supports only Linux operating system. For details on what is the methodology behind jugaad and how things work under the hood visit http://null.co.in/section/projects for a detailed paper.
	* [linux-injector](https://github.com/dismantl/linux-injector)
		* Utility for injecting executable code into a running process on x86/x64 Linux. It uses ptrace() to attach to a process, then mmap()'s memory regions for the injected code, a new stack, and space for trampoline shellcode. Finally, the trampoline in the target process is used to create a new thread and execute the chosen shellcode, so the main thread is allowed to continue. This project borrows from a number of other projects and research, see References below.
	* [linux-inject](https://github.com/gaffe23/linux-inject)
		* Tool for injecting a shared object into a Linux process
	* [injectso64](https://github.com/ice799/injectso64)
		* This is the x86-64 rewrite of Shaun Clowes' i386/SPARC injectso which he presented at Blackhat Europe 2001.
* **Techniques**
-----------------------------------------------------------------------------------------------------------------------------------