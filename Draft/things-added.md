



-------------
### ATT&CK

* [macOS High Sierra 10.13.1 insecure cron system](https://m4.rkw.io/blog/macos-high-sierra-10131-insecure-cron-system.html)
	* Easy root

* [OS X El Capitan - Sinking the S\H/IP - Stefan Esser - Syscan360 - 2016](https://www.syscan360.org/slides/2016_SG_Stefan_Esser_OS_X_El_Capitan_Sinking_The_SHIP.pdf)

* [[ZeroNights / Syscan360 2016] Abusing the Mac Recovery & OS Update Process](https://speakerdeck.com/patrickwardle/syscan360-2016-abusing-the-mac-recovery-and-os-update-process)
	* Did you know that Macs contain a secondary OS that sits hidden besides OS X? This talk will initially dive into technical details of the Recovery OS, before showing that while on (newer) native hardware Apple verifies this OS, in virtualized environments this may not be the case. Due to this 'flaw' we'll describe how an attacker can infect a virtualized OS X instance with malware that is able to survive a full OS X restore. Though limited to virtual instances, such malware can also abuse this process install itself into SIP'd locations making disinfection far more difficult. It's also worth noting that this attack likely would succeed on older versions of non-virtualized OS X as well.


* [Kernel Extension Overview - developer.apple](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html)
* [Exploiting appliances presentation v1.1](https://www.slideshare.net/NCC_Group/exploiting-appliances-presentation-v11vidsremoved)
* [async_wake](https://github.com/benjibobs/async_wake)
	* async_wake - iOS 11.1.2 kernel exploit and PoC local kernel debugger by @i41nbeer

* [IOHIDeous](https://siguza.github.io/IOHIDeous/)

------------
## Anonymity/OpSec/Privacy




------------
## Basic Security Info



------------
## BIOS/UEFI/Firmware/Low Level Attacks
* [Meltdown and Spectre - Vulnerabilities in modern computers leak passwords and sensitive data.](https://meltdown.help/)
	* Meltdown and Spectre exploit critical vulnerabilities in modern processors. These hardware vulnerabilities allow programs to steal data which is currently processed on the computer. While programs are typically not permitted to read data from other programs, a malicious program can exploit Meltdown and Spectre to get hold of secrets stored in the memory of other running programs. This might include your passwords stored in a password manager or browser, your personal photos, emails, instant messages and even business-critical documents. Meltdown and Spectre work on personal computers, mobile devices, and in the cloud. Depending on the cloud provider's infrastructure, it might be possible to steal data from other customers.
* [Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)
* **Meltdown**
	* [Meltdown](https://meltdownattack.com/meltdown.pdf)
		* The security of computer systems fundamentally relies on memory isolation, e.g., kernel address ranges are marked as non-accessible and are protected from user access. In this paper, we present Meltdown. Meltdown exploits side effects of out-of-order execution on modern processors to read arbitrary kernel-memory locations including personal data and passwords. Out-of-order execution is an indispensable performance feature and present in a wide range of modern processors. The attack is independent of the operating system, and it does not rely on any software vulnerabilities. Meltdown breaks all security assumptions given by address space isolation as well as paravirtualized environments and, thus, every security mechanism building upon this foundation. On affected systems, Meltdown enables an adversary to read memory of other processes or virtual machines in the cloud without any permissions or privileges, affecting millions of customers and virtually every user of a personal computer. We show that the KAISER defense mechanism for KASLR [8] has the important (but inadvertent) side effect of impeding Meltdown. We stress that KAISER must be deployed immediately to prevent large-scale exploitation of this severe information leakage
	* [Meltdown Proof-of-Concept](https://github.com/IAIK/meltdown)
		* This repository contains several applications, demonstrating the Meltdown bug. For technical information about the bug, refer to the paper:
			* Meltdown by Lipp, Schwarz, Gruss, Prescher, Haas, Mangard, Kocher, Genkin, Yarom, and Hamburg
		* The applications in this repository are built with libkdump, a library we developed for the paper. This library simplifies exploitation of the bug by automatically adapting to certain properties of the environment.
* **Spectre**
	* [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf)
		* Modern processors use branch prediction and speculative execution to maximize performance. For example, if the destination of a branch depends on a memory value that is in the process of being read, CPUs will try guess the destination and attempt to execute ahead. When the memory value finally arrives, the CPU either discards or commits the speculative computation. Speculative logic is unfaithful in how it executes,can access to the victim’s memory and registers, and can perform operations with measurable side effects. Spectre attacks involve inducing a victim to speculatively perform  operations that would not occur during correct program execution and which leak the victim’s confidential information via a side channel to the adversary. This paper describes practical attacks that combine methodology from side channel attacks, fault  attacks, and return-oriented programming that can read arbitrary memory from the victim’s process. More broadly, the paper shows that speculative execution implementations violate the security assumptions underpinning numerous software security mechanisms, including operating system process separation, static analysis, containerization, just-in-time (JIT) compilation, and countermeasures to cache timing/side-channel attacks. These attacks repre- sent a serious threat to actual systems, since vulnerable speculative execution capabilities are found in microprocessors from Intel, AMD, and ARM that are used in billions of devices. While  makeshift processor-specific countermeasures are possible in some cases, sound solutions will require fixes to processor designs as well as updates to instruction set architectures (ISAs) to give hardware architects and software developers a common understanding as to what computation state CPU implementations are (and are not) permitted to leak.
	* [spec_poc_arm](https://github.com/lgeek/spec_poc_arm)
		* PoC code implementing variant 3a of the Meltdown attack for AArch64. This allows reading all (potentially excluding registers whose read has side effects - not verified) system registers from user mode, including those which should only be accessible from the EL1 (kernel), EL2 (hypervisor) and EL3 (secure monitor) modes.
	* [SpectrePoC](https://github.com/crozone/SpectrePoC)
		* Proof of concept code for the Spectre CPU exploit.
	* [spectre-attack](https://github.com/Eugnis/spectre-attack)
		* Example of using revealed "Spectre" exploit (CVE-2017-5753 and CVE-2017-5715)
* [I Boot when U-Boot, Bernardo Maia Rodrigues (@bernardomr) & Vincent Ruijter (`@_evict`)](https://www.youtube.com/watch?v=2-Y4X81QHys&index=11&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)


------------
## Building a Lab 


------------
## Car Hacking


------------
## Cheat Sheets


* [Using the Database in Metasploit](https://www.offensive-security.com/metasploit-unleashed/using-databases/)


* [Meterpreter Paranoid Mode - rapid7](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Paranoid-Mode)



------------
## Conferences







------------
## Courses








------------
## CTF



------------
## Cryptography & Timing Attacks
* [MASCAB: a Micro-Architectural Side-Channel Attack Bibliography](https://github.com/danpage/mascab/)
	* Cryptography is a fast-moving field, which is enormously exciting but also quite challenging: resources such as the IACR eprint archive and CryptoBib help, but even keeping track of new results in certain sub-fields can be difficult, let alone then making useful contributions. The sub-field of micro-architectural side-channel attacks is an example of this, in part as the result of it bridging multiple disciplines (e.g., cryptography and computer architecture). I've found this particularly challenging (and so frustrating) over say the last 5 years; the volume of papers has expanded rapidly, but the time I'd normally allocate to reading them has been eroded by other commitments (as evidenced by a pile of printed papers gathering dust on my desk). In the end, I decided to tackle this problem by progressively a) collating papers I could read, then b) reading them one-by-one, but in no particular order, and attempting to summarise their contribution (and so organise the sub-field as a whole in my head). MASCAB is the result: after starting to advise MSc and PhD students on how to navigate the sub-field, it seems likely to be of use to others as well.

From: https://www.reddit.com/r/securityengineering/comments/7o2uzy/a_collection_of_links_to_pdfs_of_papers_on/
```
    1973-10-01 "A note on the confinement problem" by Lampson https://www.cs.utexas.edu/~shmat/courses/cs380s_fall09/lampson73.pdf
    1994-??-?? - "Countermeasures and tradeoffs for a class of covert timing channels" by Ray https://pdfs.semanticscholar.org/5505/384390d0b0bf86de8804baeaf82254572363.pdf
    2003-09-08 - "Cryptanalysis of DES implemented on computers with cache" by Tsunoo et al. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.135.1221&rep=rep1&type=pdf
    2005-04-14 - "Cache-timing attacks on AES" by Bernstein https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
    2005-05-13 - "CACHE MISSING FOR FUN AND PROFIT" by Percival http://css.csail.mit.edu/6.858/2014/readings/ht-cache.pdf
    2006-02-13 - "Cache attacks and countermeasures: the case of AES" by Osvik et al. https://www.cs.tau.ac.il/~tromer/papers/cache.pdf
    2006-08-23 - "Predicting Secret Keys via Branch Prediction" by Aciicmez et al. https://eprint.iacr.org/2006/288.pdf
    2007-03-20 - "On the Power of Simple Branch Prediction Analysis" by Acıi¸cmez1 et al. https://eprint.iacr.org/2006/351.pdf
    2007-12-18 - "New Branch Prediction Vulnerabilities in OpenSSL and Necessary Software Countermeasures" by Aciicmez et al. https://eprint.iacr.org/2007/039.pdf
    2010-11-22 - "Cache Games -- Bringing Access-Based Cache Attacks on AES to Practice" by Gullasch et al https://eprint.iacr.org/2010/594.pdf
    2012-03-08 - "Plugging Side-Channel Leaks with Timing Information Flow Control" by Ford https://arxiv.org/pdf/1203.3428.pdf
    2013-05-19 - "Practical Timing Side Channel Attacks against Kernel Space ASLR" by Hund et al. http://www.ieee-security.org/TC/SP2013/papers/4977a191.pdf
    2013-08-13 - "The Page-Fault Weird Machine: Lessons in Instruction-less Computation" by Bangert et al. https://www.usenix.org/system/files/conference/woot13/woot13-bangert.pdf
    2013-08-15 - "CacheAudit: A Tool for the Static Analysis of Cache Side Channels" by Doychev et al. https://eprint.iacr.org/2013/253.pdf
    2013-09-26 - "On the Prevention of Cache-Based Side-Channel Attacks in a Cloud Environment" Godfrey et al. https://pdfs.semanticscholar.org/6367/9824606b1b0deb4a44639a4e4b3e5eb49303.pdf
    2014-01-01 - "CACHE-BASED SIDE-CHANNEL ATTACKS IN MULTI-TENANT PUBLIC CLOUDS AND THEIR COUNTERMEASURES" by Zhang https://pdfs.semanticscholar.org/95a2/40ac8a7bbee77b32120081f00477e38776fe.pdf
    2014-11-03 - "The Last Mile An Empirical Study of Timing Channels on seL4" by Cock et al http://research.davidcock.fastmail.fm/papers/Cock_GMH_14.pdf
    2015-04-02 - "An Empirical Bandwidth Analysis of Interrupt-Related Covert Channels" by Gay e tal. http://www.mais.informatik.tu-darmstadt.de/WebBibPHP/papers/2013/2013-GayMantelSudbrock-EmpiricalIRCC.pdf
    2015-05-17 - "Last-Level Cache Side-Channel Attacks are Practical" by Liu et al http://palms.ee.princeton.edu/system/files/SP_vfinal.pdf
    2015-05-17 - "S$A: A Shared Cache Attack That Works across Cores and Defies VM Sandboxing -- and Its Application to AES" - by Irazoqui et al http://users.wpi.edu/~teisenbarth/pdf/SharedCacheAttackSnP2015.pdf
    2016-03-07 - "Rigorous Analysis of Software Countermeasures against Cache Attacks" by Doychev et al. https://arxiv.org/pdf/1603.02187.pdf
    2016-06-12 - "Flush+Flush: a fast and stealthy cache attack" by Gruss et al. https://gruss.cc/files/flushflush.pdf
    2016-08-10 - "Verifying Constant-Time Implementations" by Almeida & Barbosa https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_almeida.pdf
    2016-10-?? - "Jump over ASLR: Attacking branch predictors to bypass ASLR" by Evtyushkin et al. http://www.cs.wm.edu/~dmitry/assets/files/evtyushkin-micro16-camera.pdf
    2016-10-?? - "Breaking Kernel Address Space Layout Randomization with Intel TSX" by Jang et al. https://sslab.gtisc.gatech.edu/assets/papers/2016/jang:drk-ccs.pdf
    2016-10-?? - "A Survey of Microarchitectural Timing Attacks and Countermeasures on Contemporary Hardware" by Qian Ge et al http://eprint.iacr.org/2016/613
    2016-10-24 - "Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR" by Gruss et al https://gruss.cc/files/prefetch.pdf
    2016-01-?? - "Attacking Cloud through cache based side channel in virtualized environment" by Teja et al. http://ijarcsee.org/index.php/IJARCSEE/article/download/301/267
    2017-02-27 - "ASLR on the Line: Practical Cache Attacks on the MMU" by Gras & Kaveh et al http://www.cs.vu.nl/~herbertb/download/papers/anc_ndss17.pdf
    2017-03-20 - "CacheZoom: How SGX Amplifies The Power of Cache Attacks" by Moghimi - https://arxiv.org/pdf/1703.06986.pdf
    2017-05-20 - "Leaky Cauldron on the Dark Land: Understanding Memory Side-Channel Hazards in SGX" by Wang et al https://arxiv.org/pdf/1705.07289.pdf
    2017-06-24 - "Kaslr is dead: long live kaslr", "the KAISER paper" by Gruss et al https://gruss.cc/files/kaiser.pdf
    2017-08-16 - "Prime+Abort: A Timer-Free High-Precision L3 Cache Attack using Intel TSX" by Disselkoen et al https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-disselkoen.pdf
    2017-10-?? - "LAZARUS: Practical Side-Channel Resilient Kernel-Space Randomization" by Gens et al http://jin.ece.ufl.edu/papers/RAID17.pdf
    2018-01-04 - "Spectre Attacks: Exploiting Speculative Execution" by Kocher et al https://spectreattack.com/spectre.pdf
    2018-01-04 - "Meltdown" by Lipp et al. https://meltdownattack.com/meltdown.pdf
```


------------
## Crypto Currencies



-------------
## Darknets





------------
## Data Analysis/Visualization





-----------------
## Defense

* [Real Incidents:Real Solutions - evil.plumbing](https://evil.plumbing/Current-version-June.pdf)

https://github.com/FallibleInc/security-guide-for-developers
https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/

https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=149b9032665345ba890ba51d3bf0d519&fl=4&uid=150127534&nid=244%20281088008

* [Disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b)

* [Device Guard and Credential Guard hardware readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337)

* [Introduction to Windows Defender Device Guard: virtualization-based security and Windows Defender Application Control - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies)
* [Requirements and deployment planning guidelines for Windows Defender Device Guard - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/requirements-and-deployment-planning-guidelines-for-device-guard#hardware-firmware-and-software-requirements-for-device-guard)
* [Driver compatibility with Device Guard in Windows 10 - docs.ms](https://blogs.msdn.microsoft.com/windows_hardware_certification/2015/05/22/driver-compatibility-with-device-guard-in-windows-10/)

* [Protecting Privileged Domain Accounts: Network Authentication In-Depth](https://digital-forensics.sans.org/blog/2012/09/18/protecting-privileged-domain-accounts-network-authentication-in-depth)
* [SMB 3.0 (Because 3 > 2) - David Kruse](http://www.snia.org/sites/default/orig/SDC2012/presentations/Revisions/DavidKruse-SMB_3_0_Because_3-2_v2_Revision.pdf)
* [Securing Domain Controllers to Improve Active Directory Security - adsecurity.org](https://adsecurity.org/?p=3377)
* [Securing Windows Workstations: Developing a Secure Baselineadsecurity.org](https://adsecurity.org/?p=3299)

* [Guidance on Deployment of MS15-011 and MS15-014 - blogs.technet](https://blogs.technet.microsoft.com/askpfeplat/2015/02/22/guidance-on-deployment-of-ms15-011-and-ms15-014/)

* [Require SMB Security Signatures - technet.ms](https://technet.microsoft.com/en-us/library/cc731957.aspx)

* [LuLu](https://github.com/objective-see/LuLu)
	* LuLu is the free open-source macOS firewall that aims to block unauthorized (outgoing) network traffic

* [Using an Expanded Cyber Kill Chain Model to Increase Attack Resiliency - Sean Malone - BHUSA16](https://www.youtube.com/watch?v=1Dz12M7u-S8)
	* We'll review what actions are taken in each phase, and what's necessary for the adversary to move from one phase to the next. We'll discuss multiple types of controls that you can implement today in your enterprise to frustrate the adversary's plan at each stage, to avoid needing to declare "game over" just because an adversary has gained access to the internal network. The primary limiting factor of the traditional Cyber Kill Chain is that it ends with Stage 7: Actions on Objectives, conveying that once the adversary reaches this stage and has access to a system on the internal network, the defending victim has already lost. In reality, there should be multiple layers of security zones on the internal network, to protect the most critical assets. The adversary often has to move through numerous additional phases in order to access and manipulate specific systems to achieve his objective. By increasing the time and effort required to move through these stages, we decrease the likelihood of the adversary causing material damage to the enterprise. 
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Malone-Using-An-Expanded-Cyber-Kill-Chain-Model-To-Increase-Attack-Resiliency.pdf)

	* [Protect derived domain credentials with Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)
	* [Using a hypervisor to secure your desktop – Credential Guard in Windows 10 - blogs.msdn](https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/10/26/using-a-hypervisor-to-secure-your-desktop-credential-guard-in-windows-10/)
	* [Credential Guard lab companion - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/05/15/credential-guard-lab-companion/)

* [Command line process auditing](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)

* [ADRecon](https://github.com/sense-of-security/ADRecon)
	* ADRecon is a tool which extracts various artifacts (as highlighted below) out of an AD environment in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis. The report can provide a holistic picture of the current state of the target AD environment.  It can be run from any workstation that is connected to the environment, even hosts that are not domain members. Furthermore, the tool can be executed in the context of a non-privileged (i.e. standard domain user) accounts. Fine Grained Password Policy, LAPS and BitLocker may require Privileged user accounts. The tool will use Microsoft Remote Server Administration Tools (RSAT) if available, otherwise it will communicate with the Domain Controller using LDAP. 


















------------
## Design

* [How Technology Hijacks People’s Minds — from a Magician and Google’s Design Ethicist](http://www.tristanharris.com/2016/05/how-technology-hijacks-peoples-minds%E2%80%8A-%E2%80%8Afrom-a-magician-and-googles-design-ethicist/)



------------
## Documentation

* [A presentation or presentations because presenting - Jason Blanchard - Derbycon7](https://www.youtube.com/watch?v=FcgM7c0vzcE&app=desktop)





------------
## Disclosure









------------
## Drones
* [DUMLRacer](https://github.com/CunningLogic/DUMLRacer)
	* Root Exploit for DJI Drones and Controllers (up to and including v01.04.0100)






------------
## Documentation/Technical writing




------------
## Embedded Devices/Hardware (Including Printers & PoS)

* [Cloning Credit Cards: A combined pre-play and downgrade attack on EMV Contactless](https://0b4af6cdc2f0c5998459-c0245c5c937c5dedcca3f1764ecc9b2f.ssl.cf2.rackcdn.com/12055-woot13-roland.pdf)
* [How to Hack a Contactless Payment System](https://hackfu.mwrinfosecurity.com/hackfu-blog/params/post/465447/how-to-hack-a-contactless-payment-system.html)
* [Owning and Cloning NFC Payment Cards](https://github.com/peterfillmore/Talk-Stuff/blob/master/Syscan2015/PeterFillmore_Syscan2015.pdf]
* [On Relaying NFC Payment Transactions using Android devices](https://www.slideshare.net/cgvwzq/on-relaying-nfc-payment-transactions-using-android-devices)
* [NFC Hacking: NFCProxy with Android Beam](https://www.youtube.com/watch?v=tFi0vYuYeAI&feature=youtu.be)
* [Practical Experiences on NFC Relay Attacks with Android: Virtual Pickpocketing Revisited](https://conference.hitb.org/hitbsecconf2015ams/materials/Whitepapers/Relay%20Attacks%20in%20EMV%20Contactless%20Cards%20with%20Android%20OTS%20Devices.pdf)
* [Pwning the POS! - Nick Douglas - Notacon11](https://www.irongeek.com/i.php?page=videos/notacon11/pwning-the-pos-mick-douglas)
	* Everybody’s talking about the Target breach. However, there’s lots wrong with the retail space… and it’s been this way for quite some time! Focusing on Point of Sale (POS) systems this talk will show you how to exploit friendly the POS ecosystem really is, and how you can help fix things.
* [An Inside Job: Remote Power Analysis Attacks on FPGAs](https://eprint.iacr.org/2018/012.pdf)


------------
## Exfiltration

* [Data Exfiltration Toolkit(DET)](https://github.com/PaulSec/DET)
	* DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. The idea was to create a generic toolkit to plug any kind of protocol/service to test implmented Network Monitoring and Data Leakage Prevention (DLP) solutions configuration, against different data exfiltration techniques.
* [EGRESSION](https://github.com/danielmiessler/egression)
	* EGRESSION is a tool that provides an instant view of how easy it is to upload sensitive data from any given network.
* [Covert Channels in the TCP/IP Protocol Suite](http://ojphi.org/ojs/index.php/fm/article/view/528/449)
* [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://cs.unc.edu/~fabian/course_papers/PtacekNewsham98.pdf)
* [Covert Channels - Communicating over TCP without the initial 3-way handshake](https://securitynik.blogspot.ca/2014/04/covert-channels-communicating-over-tcp.html)
* [Covert Channels - Part 2 - exfiltrating data through TCP Sequence Number field](https://securitynik.blogspot.com/2015/12/covert-channels-part-2-exfiltrating.html)

* [Covert Channels - Part 2 - exfiltrating data through TCP Sequence Number field](https://securitynik.blogspot.com/2015/12/covert-channels-part-2-exfiltrating.html)
* [Covert Channels - Communicating over TCP without the initial 3-way handshake](https://securitynik.blogspot.ca/2014/04/covert-channels-communicating-over-tcp.html)





------------
## Exploit Dev

* [A SysCall to ARMs - Brendan Watters - Brendan Watters -
Derbycon 2013](https://www.irongeek.com/i.php?page=videos/derbycon3/3304-a-syscall-to-arms-brendan-watters)
	* Description:ARM processors are growing more and more prevalent in the world; ARM itself claims that more than 20 billion chips have been shipped. Take a moment to appreciate that is about three chips for every man, woman, and child on earth. The three main topics I aim to cover are (1) how to perform a Linux system call on an ARM processor via assembly, ARM pipelining used in most modern ARM processors and how it came about, and (3) the really cool way ARM can avoid branching, even with conditional control flow. These will be explained in both code, English, and (hopefully successful) live demos using an ARM development board. The end result is to get the audience to understand how to create a simple socket program written in ARM assembly. 
* [Jumping the Fence Comparison and Improvements for Existing Jump Oriented Programming Tools - John Dunlap - Derbycon7](https://www.youtube.com/watch?v=eRICJ_bEC54&index=15&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
* [Proof of concept exploits / tools for Epson vulnerabilities: CVE-2017-12860 and CVE-2017-12861](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/exploits/Epson)
* [Exploits for Unitrends version 9.1.1 and earlier ; all by Dwight Hohnstein](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/exploits/Unitrends)
* [All AIX exploits written by Hector Monsegur](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/exploits/IBM)
* [GhostHook – Bypassing PatchGuard with Processor Trace Based Hooking](https://www.cyberark.com/threat-research-blog/ghosthook-bypassing-patchguard-processor-trace-based-hooking/)
* [Kernel Patch Protection - Wikipedia](https://en.wikipedia.org/wiki/Kernel_Patch_Protection)
* [An Introduction to Kernel Patch Protection - blogs.msdn](https://blogs.msdn.microsoft.com/windowsvistasecurity/2006/08/12/an-introduction-to-kernel-patch-protection/)
* [KPP Destroyer](http://forum.cheatengine.org/viewtopic.php?t=573311)
* [Bypassing PatchGuard 3](https://www.codeproject.com/Articles/28318/Bypassing-PatchGuard)
* [Disable PatchGuard - the easy/lazy way - fyyre](http://fyyre.ru/vault/bootloader.txt)
* [UPGSED Universal PatchGuard and Driver Signature Enforcement Disable](https://github.com/hfiref0x/UPGDSED)


------------
## Forensics

* [Mac OS X Keychain Forensic Tool](https://github.com/n0fate/chainbreaker)
	* The chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner. Master Key candidates can be extracted from volafox or volatility keychaindump module. Supports: Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra

* [wechat-dump](https://github.com/ppwwyyxx/wechat-dump)
	* Dump wechat messages from android. Right now it can dump messages in text-only mode, or generate a single-file html containing voice messages, images, emoji, etc.




------------
## Fuzzing/Bug Hunting
* [fuzzdb](https://github.com/fuzzdb-project/fuzzdb)
	* Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.

* [Paper Machete](https://github.com/cetfor/PaperMachete/wiki)
	* Paper Machete (PM) orchestrates Binary Ninja and GRAKN.AI to perform static analysis on binary targets with the goal of finding exploitable vulnerabilities. PM leverages the Binary Ninja MLIL SSA to extract semantic meaning about individual instructions, operations, register/variable state, and overall control flow. This data is then migrated into GRAKN.AI, a hyper-relational database. We then run queries against the database that are designed to look for indications of common software vulnerability classes.

* [Aiding Static Analysis: Discovering Vulnerabilities in Binary Targets through Knowledge Graph Inferences - John Toterhi - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t116-aiding-static-analysis-discovering-vulnerabilities-in-binary-targets-through-knowledge-graph-inferences-john-toterhi)
	* Static analysis is the foundation of vulnerability research (VR). Even with today's advanced genetic fuzzers, concolic analysis frameworks, emulation engines, and binary instrumentation tools, static analysis ultimately makes or breaks a successful VR program. In this talk, we will explore a method of enhancing our static analysis process using the GRAKN.AI implementation of Google's knowledge graph and explore the semantics from Binary Ninja's Medium Level static single assignment (SSA) intermediate language (IL) to perform inference queries on binary-only targets to identify vulnerabilities.
* [Triton](https://github.com/JonathanSalwan/Triton)
	* Triton is a dynamic binary analysis (DBA) framework. It provides internal components like a Dynamic Symbolic Execution (DSE) engine, a Taint engine, AST representations of the x86 and the x86-64 instructions set semantics, SMT simplification passes, an SMT Solver Interface and, the last but not least, Python bindings.

* [usercorn](https://github.com/lunixbochs/usercorn)
	* dynamic binary analysis via platform emulation 

* [Open Up and Say 0x41414141: Attacking Medical Devices - Robert PortvlIet - Toorcon19](https://www.youtube.com/watch?index=3&v=SBw78men_70&app=desktop)
	* Network accessible medical devices are ubiquitous in today’s clinical environment. These devices can be of great aid to healthcare profes- sionals in assessing, treating and monitoring a patient’s condition. However, they can also fall victim to a number of systemic vulnerabili- ties that can expose personal health information or PHI, compromise the integrity of patient data in transit, and affect the availability of the devices themselves. This talk looks at the methodology and approach to penetration testing of modern medical devices. It will provide an overview of the various stages of a medical device assessment, including discovery and analysis of a device’s remote and local attack surface, reverse engineering and exploitation of proprietary network protocols, vulner- ability discovery in network services, compromising supporting sys- tems, attacking common wireless protocols, exploitation of hardware debug interfaces and bus protocols and assessing proprietary wireless technologies. It will also cover a number of real world vulnerabilities that the speaker has discovered during medical device penetration testing assessments. These include weak cryptographic implementations, device impersonation and data manipulation vulnerabilities in pro- prietary protocols, unauthenticated database interfaces, hardcoded credentials/keys and other sensitive information stored in firmware/ binaries and the susceptibility of medical devices to remote denial of service attacks. The talk will conclude with some suggestions on how some of the most common classes of medical device vulnerabilities might be reme- diated by vendors and also how hospitals and other healthcare provid- ers can defend their medical devices in the meantime.





------------
## Game Hacking

* [PS4 4.05 Kernel Exploit](https://github.com/Cryptogenic/PS4-4.05-Kernel-Exploit/blob/master/README.md)
* [The First PS4 Kernel Exploit: Adieu](https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/)
* ["NamedObj" 4.05 Kernel Exploit Writeup.md](https://github.com/Cryptogenic/Exploit-Writeups/blob/master/PS4/%22NamedObj%22%204.05%20Kernel%20Exploit%20Writeup.md)
* [4.0x WebKit Exploit Writeup - Breaking down qwertyoruiopz's 4.0x userland exploit(https://github.com/Cryptogenic/Exploit-Writeups/blob/master/PS4/4.0x%20WebKit%20Exploit%20Writeup.md)
* [NamedObj Kernel Exploit Overview(writeup)](https://github.com/Cryptogenic/Exploit-Writeups/blob/master/PS4/NamedObj%20Kernel%20Exploit%20Overview.md)

* [libdragon](https://dragonminded.com/n64dev/libdragon/)
	* libdragon is meant to be a one stop library providing low level API for all hardware features of the N64.
* [Reversing the Nintendo 64 CIC - Mike Ryan, marshallh, and John McMaster - REcon 2015](https://www.youtube.com/watch?v=HwEdqAb2l50)
	* This presentation covers our successful efforts to reverse engineer and clone the Nintendo 64's copy protection chip: the N64 CIC. We describe the processes and techniques we used to finally conquer this chip, nearly 20 years after its introduction.
* [64Drive](http://64drive.retroactive.be/)
* [FAT64](https://lacklustre.net/projects/fat64/)
	* FAT64 is a FAT32 library for use on the 64drive, a development cart for the Nintendo 64. It is used by the 64drive bootloader and menu.
* [MTuner](https://github.com/milostosic/MTuner)
	* MTuner is a C/C++ memory profiler and memory leak finder for Windows, PlayStation 4, PlayStation 3, etc.
* [loadlibraryy](https://github.com/G-E-N-E-S-I-S/loadlibrayy)
	* x64 manualmapper with kernel elevation and thread hijacking capabilities to bypass anticheats








------------
## Honeypots
* [CSRecon - Censys and Shodan Reconnasiance Tool](https://github.com/markclayton/csrecon)
* [ICS Honeypot Detection using Shodan](https://asciinema.org/a/38992)
* [Honeypot Or Not? - shodanhq](https://honeyscore.shodan.io/)


------------
## ICS/SCADA
* [VirtualPlant](https://github.com/jseidl/virtuaplant)
	* VirtuaPlant is a Industrial Control Systems simulator which adds a “similar to real-world control logic” to the basic “read/write tags” feature of most PLC simulators. Paired with a game library and 2d physics engine, VirtuaPlant is able to present a GUI simulating the “world view” behind the control system allowing the user to have a vision of the would-be actions behind the control systems. All the software is written in (guess what?) Python. The idea is for VirtuaPlant to be a collection of different plant types using different protocols in order to be a learning platform and testbed. The first release introduces a as-simple-as-it-can-get one-process “bottle-filling factory” running Modbus as its protocol.
	* [Blogpost](https://wroot.org/projects/virtuaplant/)

* [Running a Better Red Team Through Understanding ICS SCADA Adversary Tactics - SANS Webcast](https://www.youtube.com/watch?v=ERnPuGvH_O0)
	* A good red team should be informed about adversary tactics to emulate them against networks to not only test the infrastructure but also the defenders. In this talk, SANS ICS515 and FOR578 course author Robert M. Lee will discuss a number of observed adversary tactics in ICS/SCADA environments for the purpose of educating the audience on tactics that red teams may consider for tests in these networks. The talk will cover some of the high profile attacks observed in the community such as the Ukraine power grid cyber-attack as well as lessons learned from incident response cases in the community. 

* [ICS Security Assessment Methodology, Tools & Tips - Dale Peterson](https://www.youtube.com/watch?v=0WoA9SYLDoM)
	* Dale Peterson of Digital Bond describes how to perform an ICS / SCADA cyber security assessment in this S4xJapan video. He goes into a lot of detail on the tools and how to use them in the fragile and insecure by design environment that is an ICS. There are also useful tips on when to bother applying security patches (this will likely surprise you), the importance of identifying the impact of a vulnerability, and an efficient risk reduction approach.

* [I Got You06 ICS SCADA Threat Hunting Robert M Lee Jon Lavender](https://www.youtube.com/watch?v=Zm5lDKxaaTY)
* [Redpoint](https://github.com/digitalbond/Redpoint)
	* Redpoint is a Digital Bond research project to enumerate ICS applications and devices. The Redpoint tools use legitimate protocol or application commands to discover and enumerate devices and applications. There is no effort to exploit or crash anything. However many ICS devices and applications are fragile and can crash or respond in an unexpected way to any unexpected traffic so use with care.


------------
## Interesting Things/Miscellaneous

* [BE YOUR OWN VPN PROVIDER WITH OPENBSD (v2)](https://networkfilter.blogspot.com/2017/04/be-your-own-vpn-provider-with-openbsd-v2.html)

* [Stealing Profits from Spammers or: How I learned to Stop Worrying and Love the Spam - Grant Jordan - Defcon17](https://www.youtube.com/watch?v=ytDamqTjPwg)
	* Every time you look at your inbox, there it is... SPAM! Your penis needs enlargement, a horny single girl from Russia "accidentally" emailed you, and a former Nigerian prince knows that you're just the man to safeguard his millions. But in 2007, while still a student at MIT, one particular kind caught my eye: stock spam. Those bizarre stock market "tips" that claim you should buy a particular stock because it's "about to go through the roof!!!!" Like most people, I initially thought nothing of these ridiculous emails. That was until Kyle Vogt (now of Justin.tv) proposed the stupidest idea I had ever heard: "There has to be some way we can make money off these spammers". After trying, and failing, to prove Kyle wrong, the two of us embarked on a 4-month study into the dark depths of stock spam. In this talk, I'll explain how we went from hand-sorting tens of thousands of spam emails to developing a trading strategy able to take a piece of the spammers' profits. And how, in the process, our work produced data that disproved the results of nearly all the existing stock spam research.




------------
## Lockpicking





------------
## Malware

* [atom-bombing](https://github.com/BreakingMalwareResearch/atom-bombing)
	* Here’s a new code injection technique, dubbed AtomBombing, which exploits Windows atom tables and Async Procedure Calls (APC). Currently, this technique goes undetected by common security solutions that focus on preventing infiltration.
* [ATOMBOMBING: BRAND NEW CODE INJECTION FOR WINDOWs](https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows)

* [VirtualBox Hardened Loader](https://github.com/hfiref0x/VBoxHardenedLoader)
* [Knowledge Fragment: Hardening Win7 x64 on VirtualBox for Malware Analysis](https://byte-atlas.blogspot.com/2017/02/hardening-vbox-win7x64.html)

* [On the Cutting Edge: Thwarting Virtual Machine Detection - Tom Liston, Ed Skoudis](http://handlers.sans.org/tliston/ThwartingVMDetection_Liston_Skoudis.pdf)
* [TitanHide](https://github.com/mrexodia/TitanHide)
	* TitanHide is a driver intended to hide debuggers from certain processes. The driver hooks various Nt* kernel functions (using SSDT table hooks) and modifies the return values of the original functions. To hide a process, you must pass a simple structure with a ProcessID and the hiding option(s) to enable, to the driver. The internal API is designed to add hooks with little effort, which means adding features is really easy.

* [recomposer](https://github.com/secretsquirrel/recomposer)
	* Randomly changes Win32/64 PE Files for 'safer' uploading to malware and sandbox sites.
* [IRMA](http://irma.quarkslab.com/overview.html)
	* Malware analysis platform
* [PlagueScanner](https://github.com/PlagueScanner/PlagueScanner)
	* PlagueScanner is a multiple AV scanner framework for orchestrating a group of individual AV scanners into one contiguous scanner. There are two basic components in this initial release: Core and Agents.
* [MultiAV](https://github.com/joxeankoret/multiav)
	* MultiAV scanner with Python and JSON API. [Not currently Maintained]
* [Process Hollowing Example in Linux - Volatility](https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/linux/process_hollow.py)

* [warbirdvm](https://github.com/airbus-seclab/warbirdvm)
	* An analysis of the Warbird virtual-machine protection
* [Botnet Lab](https://github.com/jpdias/botnet-lab)
	* An IRC based tool for testing the capabilities of a botnet
* [Universal Unhooking - Cylance](https://www.cylance.com/content/dam/cylance/pdfs/white_papers/Universal_Unhooking.pdf)







------------
## Mainframes






------------
## Network Scanning and Attacks

* [TCPCopy](https://github.com/session-replay-tools/tcpcopy)
	* TCPCopy is a TCP stream replay tool to support real testing of Internet server applications.
* [BeaconBits](https://github.com/bez0r/BeaconBits)
	* Beacon Bits is comprised of analytical scripts combined with a custom database that evaluate flow traffic for statistical uniformity over a given period of time. The tool relies on some of the most common characteristics of infected host persisting in connection attempts to establish a connection, either to a remote host or set of host over a TCP network connection. Useful to also identify automation, host behavior that is not driven by humans.


* [fragroute](https://www.monkey.org/~dugsong/fragroute/fragroute.8.txt)
* [Ask and you shall receive (Part 2)](https://securityhorror.blogspot.com/2012/07/ask-and-you-shall-receive-part-2.html)

* [Practically Exploiting MS15-014 and MS15-011 - MWR](https://labs.mwrinfosecurity.com/blog/practically-exploiting-ms15-014-and-ms15-011/)
* [MS15-011 - Microsoft Windows Group Policy real exploitation via a SMB MiTM attack - coresecurity](https://www.coresecurity.com/blog/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack)

* [Covert Channels in the TCP/IP Protocol Suite](http://ojphi.org/ojs/index.php/fm/article/view/528/449)
* [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://cs.unc.edu/~fabian/course_papers/PtacekNewsham98.pdf)

* [metasploitHelper](https://github.com/milo2012/metasploitHelper)
	* metasploitHelper (msfHelper) communicates with Metasploit via msrpc. It uses both port and web related exploits from Metasploit. You can point msfHelper at an IP address/Nmap XML file/File containing list of Ip addresses. First, it performs a Nmap scan of the target host(s) and then attempt to find compatible and possible Metasploit modules based on 1) nmap service banner and 2) service name and run them against the targets.
	* [Slides](https://docs.google.com/presentation/d/1No9K1OsuYy5mDP0FmRzb2fNWeuyyq2R41N0p7qu8r_0/edit#slide=id.g20261039dc_2_48)
PAC/WPAD
* [aPAColypse now: Exploiting Windows 10 in a Local Network with WPAD/PAC and JScript](https://googleprojectzero.blogspot.com/2017/12/apacolypse-now-exploiting-windows-10-in_18.html?m=1)

* [Crippling HTTPs With Unholy PAC - Itzik Kotler & Amit Klein](https://www.youtube.com/watch?v=7q40RLilXKw)
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Kotler-Crippling-HTTPS-With-Unholy-PAC.pdf)

* [Toxic Proxies - Bypassing HTTPS - Alex Chapman, Paul Stone - Defcon24](https://www.youtube.com/watch?v=3vegxj5a1Rw)
	* [Slides](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Chapman-Stone-Toxic-Proxies-Bypassing-HTTPS-and-VPNs.pdf)

* [badWPAD - Maxim Goncharov](https://www.blackhat.com/docs/us-16/materials/us-16-Goncharov-BadWpad.pdf)

* [Layer Four Traceroute (LFT) and WhoB](http://pwhois.org/lft/)
	* The alternative traceroute and whois tools for network (reverse) engineers
* [They see me scannin'; they hatin'](http://blog.bonsaiviking.com/2015/07/they-see-me-scannin-they-hatin.html)
* [They see me scannin' (part 2)](http://blog.bonsaiviking.com/2015/07/they-see-me-scannin-part-2.html)
* [Chiron](https://github.com/aatlasis/chiron)
	* Chiron is an IPv6 Security Assessment Framework, written in Python and employing Scapy. It is comprised of the following modules: • IPv6 Scanner • IPv6 Local Link • IPv4-to-IPv6 Proxy • IPv6 Attack Module • IPv6 Proxy. All the above modules are supported by a common library that allows the creation of completely arbitrary IPv6 header chains, fragmented or not.

* [Virtual host and DNS names enumeration techniques](https://jekil.sexy/blog/2009/virtual-host-and-dns-names-enumeration-techniques.html)
* [Chiron](https://github.com/aatlasis/Chiron)
	* Chiron is an IPv6 Security Assessment Framework, written in Python and employing Scapy. It is comprised of the following modules: • IPv6 Scanner • IPv6 Local Link • IPv4-to-IPv6 Proxy • IPv6 Attack Module • IPv6 Proxy. All the above modules are supported by a common library that allows the creation of completely arbitrary IPv6 header chains, fragmented or not.

* [Toxic Proxies - Bypassing HTTPS - Defcon24 - Alex Chapman, Paul Stone](https://www.youtube.com/watch?v=3vegxj5a1Rw&app=desktop)
	* In this talk we'll reveal how recent improvements in online security and privacy can be undermined by decades old design flaws in obscure specifications. These design weakness can be exploited to intercept HTTPS URLs and proxy VPN tunneled traffic. We will demonstrate how a rogue access point or local network attacker can use these new techniques to bypass encryption, monitor your search history and take over your online accounts. No logos, no acronyms; this is not a theoretical crypto attack. We will show our techniques working on $30 hardware in under a minute. Online identity? Compromised. OAuth? Forget about it. Cloud file storage? Now we're talking. 
	* [PAC HTTPS Leak Demos](https://github.com/ctxis/pac-leak-demo)
		* This is the code for the demos from our DEF CON 24 talk, [Toxic Proxies - Bypassing HTTPS and VPNs to Pwn Your Online Identity](https://defcon.org/html/defcon-24/dc-24-speakers.html#Chapman) The demos use the [PAC HTTPS leak](http://www.contextis.com/resources/blog/leaking-https-urls-20-year-old-vulnerability/) to steal data and do various fun things. Our demos worked in Chrome on Windows with default settings, until the issue was fixed in Chrome 52. You can use Chrome 52+ to try out these demos if you launch it with the --unsafe-pac-url flag.

* [httprecon - Advanced Web Server Fingerprinting](https://github.com/scipag/httprecon-win32)
	* The httprecon project is doing some research in the field of web server fingerprinting, also known as http fingerprinting. The goal is the highly accurate identification of given httpd implementations. This is very important within professional vulnerability analysis. Besides the discussion of different approaches and the documentation of gathered results also an implementation for automated analysis is provided. This software shall improve the easyness and efficiency of this kind of enumeration. Traditional approaches as like banner-grabbing, status code enumeration and header ordering analysis are used. However, many other analysis techniques were introduced to increase the possibilities of accurate web server fingerprinting. Some of them were already discussed in the book Die Kunst des Penetration Testing (Chapter 9.3, HTTP-Fingerprinting, pp. 530-550).

* [Fire Away Sinking the Next Gen Firewall - Russell Butturini - Derbycon6](https://www.youtube.com/watch?v=Qpty_f0Eu7Y)
* [Network Application Firewalls: Exploits and Defense - Brad Woodberg](https://www.youtube.com/watch?v=jgS74o-TVIw)
	* In the last few years, a so called whole new generation of firewalls have been released by various vendors, most notably Network Application Firewalling. While this technology has gained a lot of market attention, little is actually known by the general public about how it actually works, what limitations it has, and what you really need to do to ensure that you're not exposing yourself. This presentation will examine/demystify the technology, the implementation, demonstrate some of the technology and implementation specific vulnerabilities, exploits, what it can and can't do for you, and how to defend yourself against potential weaknesses.

* [Penetration Testing Tools that (do not) Support](https://www.ernw.de/download/newsletter/ERNW_Newsletter_45_PenTesting_Tools_that_Support_IPv6_v.1.1_en.pdf)
	* Find out which of our favorite penetration testing tools can be used natively using IPv6 as an underlying layer-3 protocol. Find alternative solutions for the rest.

* [Xeroxsploit](https://github.com/LionSec/xerosploit)
	* Xerosploit is a penetration testing toolkit whose goal is to perform man in the middle attacks for testing purposes. It brings various modules that allow to realise efficient attacks, and also allows to carry out denial of service attacks and port scanning. Powered by bettercap and nmap.

* [halberd](https://github.com/jmbr/halberd)
	* Load balancer detection tool
* [Inspecting Remote Network Topography by Monitoring Response Time-To-Live](http://howto.hackallthethings.com/2015/04/inspecting-remote-network-topography-by.html)
* [ttl-monitor](https://github.com/hack-all-the-things/ttl-monitor)
	* A TTL monitor utility for identifying route changes, port forwards, intrusion responses, and more

* [Fireaway](https://github.com/tcstool/Fireaway)
	* Fireaway is a tool for auditing, bypassing, and exfiltrating data against layer 7/AppID inspection rules on next generation firewalls, as well as other deep packet inspection defense mechanisms, such as data loss prevention (DLP) and application aware proxies. These tactics are based on the principle of having to allow connections to establish through the NGFW in order to see layer 7 data to filter, as well as spoofing applications to hide communication channels inside the firewall logs as normal user traffic, such as Internet surfing. In the case of bypassing data loss prevention tools, Fireaway sends data in small "chunks", which do not match regular expression triggers and other DLP rules, as well as embedding data in spoofed HTTP headers of legitimate applications which most data loss prevention technologies are not designed to inspect. The tool also has had success defeating anomaly detection and heursitics engines through its ability to spoof application headers and hide data inside them.

* [striptls - auditing proxy](https://github.com/tintinweb/striptls)
	* A generic tcp proxy implementation and audit tool to perform protocol independent ssl/tls interception and STARTTLS stripping attacks on SMTP, POP3, IMAP, FTP, NNTP, XMPP, ACAP and IRC.

* [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/)

* [Saving Polar Bears When Banner Grabbing](http://blog.ioactive.com/2015/07/saving-polar-bears-when-banner-grabbing.html)
* [polarbearscan](http://santarago.org/pbscan.html)
	*  polarbearscan is an attempt to do faster and more efficient banner grabbing and port scanning. It combines two different ideas which hopefully will make it somewhat worthy of your attention and time.  The first of these ideas is to use stateless SYN scanning using cryptographically protected cookies to parse incoming acknowledgements. To the best of the author's knowledge this technique was pioneered by Dan Kaminsky in scanrand. Scanrand was itself part of Paketto Keiretsu, a collection of scanning utilities, and it was released somewhere in 2001-2002. A mirror of this code can be found at Packet Storm. The second idea is use a patched userland TCP/IP stack such that the scanner can restore state immediately upon receiving a cryptographically verified packet with both the SYN and ACK flags set. The userland stack being used here by polarbearscan is called libuinet[2](http://wanproxy.org/libuinet.shtml). Unlike some of the other userland TCP/IP stacks out there this one is very mature as it's simply a port of FreeBSD's TCP/IP stack. By patching the libuinet stack one can then construct a socket and complete the standard TCP 3-way handshake by replying with a proper ACK. Doing it this way a fully functional TCP connection is immediately established. This as opposed to other scanners (such as nmap) who would have to, after noting that a TCP port is open, now perform a full TCP connect via the kernel to do things such as banner grabbing or version scanning. A full TCP connect leads leads to a whole new TCP 3-way handshake being performed. This completely discards the implicit state which was built up by the initial two packets being exchanged between the hosts. By avoiding this one can reduce bandwidth usage and immediately go from detecting that a port is open to connecting to it. This connection can then simply sit back and receive data in banner grab mode or it could send out an HTTP request. 

* [Zarp](https://github.com/hatRiot/zarp)
	* Zarp is a network attack tool centered around the exploitation of local networks. This does not include system exploitation, but rather abusing networking protocols and stacks to take over, infiltrate, and knock out. Sessions can be managed to quickly poison and sniff multiple systems at once, dumping sensitive information automatically or to the attacker directly. Various sniffers are included to automatically parse usernames and passwords from various protocols, as well as view HTTP traffic and more. DoS attacks are included to knock out various systems and applications. These tools open up the possibility for very complex attack scenarios on live networks quickly, cleanly, and quietly.


* [Behavioral Analysis using DNS, Network Traffic and Logs, Josh Pyorre (@joshpyorre)](https://www.youtube.com/watch?v=oLemvzZjDOs&index=13&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
	* Multiple methods exist for detecting malicious activity in a network, including intrusion detection, anti-virus, and log analysis. However, the majority of these use signatures, looking for already known events and they typically require some level of human intervention and maintenance. Using behavioral analysis methods, it may be possible to observe and create a baseline of average behavior on a network, enabling intelligent notification of anomalous activity. This talk will demonstrate methods of performing this activity in different environments. Attendees will learn new methods which they can apply to further monitor and secure their networks

* [StackOverflow Post on Scanning](https://security.stackexchange.com/questions/373/open-source-penetration-test-automation/82529#82529)

* [mitm6 – compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)

* [Windows: SMB Server (v1 and v2) Mount Point Arbitrary Device Open EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=1416&t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&refsrc=email&iid=0ba06fc942c7473c8c3669dfc193d5e0&fl=4&uid=150127534&nid=244+293670920)

* [SMB Spider](https://github.com/T-S-A/smbspider)
	* SMB Spider is a lightweight utility for searching SMB/CIFS/Samba file shares. This project was born during a penetration test, via the need to search hundreds of hosts quickly for sensitive password files. Simply run "python smbspider.py -h" to get started.


SDN
* [Finding the Low-Hanging Route](https://labs.mwrinfosecurity.com/blog/routing-101/)


------------
## Network/Endpoint Monitoring & Logging & Threat Hunting

* [Diamond](https://github.com/python-diamond/Diamond)
	* Diamond is a python daemon that collects system metrics and publishes them to [Graphite](http://diamond.readthedocs.io/en/latest/handlers/GraphiteHandler/) (and others). It is capable of collecting cpu, memory, network, i/o, load and disk metrics. Additionally, it features an API for implementing custom collectors for gathering metrics from almost any source.
	* [Documentation](http://diamond.readthedocs.io/en/latest/)


------------
## OSINT
[NAPALM FTP Indexer](https://www.searchftps.net/)

* [Linkedin_profiles](https://github.com/wpentester/Linkedin_profiles)
	* This script uses selenium to scrape linkedin employee details from a specified company. If the script isn't working, you can always browse to the desired company's employee page and paste in the link on line 69 like this: "employees_page = url"



------------
##	OS X






------------
## Password Cracking





------------
## Phishing

* [About Dynamic Data Exchange](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774(v=vs.85).aspx)

* [Pafish Macro](https://github.com/joesecurity/pafishmacro)
	* Pafish Macro is a Macro enabled Office Document to detect malware analysis systems and sandboxes. It uses evasion & detection techniques implemented by malicious documents.

* [Welcome to the Excel Software Development Kit](https://msdn.microsoft.com/en-us/library/office/bb687883.aspx)
* [Hello World XLL](https://github.com/edparcell/HelloWorldXll)
	* This is a simple XLL, showing how to create an XLL from scratch.

* [Add-In Opportunities for Office Persistence](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
	* This post will explore various opportunities for gaining persistence through native Microsoft Office functionality.  It was inspired by Kostas Lintovois’ similar work which identified ways to persist in transient Virtual Desktop Infrastructure (VDI) environments through adding a VBA backdoor to Office template files 

* [One Template To Rule 'Em All](https://labs.mwrinfosecurity.com/publications/one-template-to-rule-em-all/)
	* This presentation discussed how Office security settings and templates can be abused to gain persistence in VDI implementations where traditional techniques relying on the file system or the Registry are not applicable. Additionally, it was described how the introduction of application control and anti-exploitation technologies may affect code execution in locked down environments and how these controls can be circumvented through the use of VBA.
* [DLL Tricks with VBA to Improve Offensive Macro Capability](https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/)

* [DLL Execution via Excel.Application RegisterXLL() method](https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52)
	* A DLL can be loaded and executed via Excel by initializing the Excel.Application COM object and passing a DLL to the RegisterXLL method. The DLL path does not need to be local, it can also be a UNC path that points to a remote WebDAV server.
* [ExcelDllLoader](https://github.com/3gstudent/ExcelDllLoader)
	* Execute DLL via the Excel.Application object's RegisterXLL() method
* [xllpoc](https://github.com/MoooKitty/xllpoc)
	* A small project that aggregates community knowledge for Excel XLL execution, via xlAutoOpen() or PROCESS_ATTACH.










------------
## Physical Security


* [FATF blacklist - Wikipedia](https://en.wikipedia.org/wiki/FATF_blacklist)
	* The FATF blacklist was the common shorthand description for the Financial Action Task Force list of "Non-Cooperative Countries or Territories" (NCCTs) issued since 2000, which it perceived to be non-cooperative in the global fight against money laundering and terrorist financing.
* [The Green Beret Hotel Check-In Safety List](https://www.entrepreneur.com/article/286411)








------------
## Policy





------------
## Post Exploitation/Privilege Escalation/Pivoting

* [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM - foxglove security](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
* [Rotten Potato Privilege Escalation from Service Accounts to SYSTEM - Stephen Breen Chris Mallz - Derbycon6](https://www.youtube.com/watch?v=8Wjs__mWOKI)
* [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)
	* New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.

* [Windows: Local WebDAV NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=222&redir=1)
* [Hot Potato](https://foxglovesecurity.com/2016/01/16/hot-potato/)
	* Hot Potato (aka: Potato) takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.
* [SmashedPotato](https://github.com/Cn33liz/SmashedPotato)

* [Social Engineering The Windows Kernel: Finding And Exploiting Token Handling Vulnerabilities - James Forshaw - BHUSA2015](https://www.youtube.com/watch?v=QRpfvmMbDMg)
	* One successful technique in social engineering is pretending to be someone or something you're not and hoping the security guard who's forgotten their reading glasses doesn't look too closely at your fake ID. Of course there's no hyperopic guard in the Windows OS, but we do have an ID card, the Access Token which proves our identity to the system and let's us access secured resources. The Windows kernel provides simple capabilities to identify fake Access Tokens, but sometimes the kernel or other kernel-mode drivers are too busy to use them correctly. If a fake token isn't spotted during a privileged operation local elevation of privilege or information disclosure vulnerabilities can be the result. This could allow an attacker to break out of an application sandbox, elevate to administrator privileges, or even compromise the kernel itself. This presentation is about finding and then exploiting the incorrect handling of tokens in the Windows kernel as well as first and third party drivers. Examples of serious vulnerabilities, such as CVE-2015-0002 and CVE-2015-0062 will be presented. It will provide clear exploitable patterns so that you can do your own security reviews for these issues. Finally, I'll discuss some of the ways of exploiting these types of vulnerabilities to elevate local privileges. 

* [SMB Relay with Snarf - Making the Most of Your MitM](https://bluescreenofjeff.com/2016-02-19-smb-relay-with-snarfjs-making-the-most-of-your-mitm/)

[Kiosk/POS Breakout Keys in Windows - TrustedSec](https://www.trustedsec.com/2015/04/kioskpos-breakout-keys-in-windows/)

* [Alternative methods of becoming SYSTEM - XPN](https://blog.xpnsec.com/becoming-system/)
* [Wix Toolkit](http://wixtoolset.org/)
	* Tool for crafting msi binaries
* [Dump-Clear-Text-Password-after-KB2871997-installed](https://github.com/3gstudent/Dump-Clear-Password-after-KB2871997-installed)
	* Auto start Wdigest Auth,Lock Screen,Detect User Logon and get clear password.

* [Practically Exploiting MS15-014 and MS15-011 - MWR](https://labs.mwrinfosecurity.com/blog/practically-exploiting-ms15-014-and-ms15-011/)
* [MS15-011 - Microsoft Windows Group Policy real exploitation via a SMB MiTM attack - coresecurity](https://www.coresecurity.com/blog/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack)

* [Snagging creds from locked machines - mubix](https://malicious.link/post/2016/snagging-creds-from-locked-machines/)
* [Bash Bunny QuickCreds – Grab Creds from Locked Machines](https://www.doyler.net/security-not-included/bash-bunny-quickcreds)
* [PoisonTap](https://github.com/samyk/poisontap)
	* Exploits locked/password protected computers over USB, drops persistent WebSocket-based backdoor, exposes internal router, and siphons cookies using Raspberry Pi Zero & Node.js.

* [JVM Post-Exploitation One-Liners](https://gist.github.com/frohoff/a976928e3c1dc7c359f8)
* [How to Remotely Control Your PC (Even When it Crashes)](https://www.howtogeek.com/56538/how-to-remotely-control-your-pc-even-when-it-crashes/)


* [NTLM - Open-source script from root9B for manipulating NTLM authentication](https://github.com/root9b/NTLM)
	* This script tests a single hash or file of hashes against an ntlmv2 challenge/response e.g. from auxiliary/server/capture/smb The idea is that you can identify re-used passwords between accounts that you do have the hash for and accounts that you do not have the hash for, offline and without cracking the password hashes. This saves you from trying your hashes against other accounts live, which triggers lockouts and alerts.

* [Exploiting PowerShell Code Injection Vulnerabilities to Bypass Constrained Language Mode](http://www.exploit-monday.com/2017/08/exploiting-powershell-code-injection.html?m=1)

* [Invoke-Piper](https://github.com/p3nt4/Invoke-Piper)
	* Forward local or remote tcp ports through SMB pipes.

* [MeterSSH](https://github.com/trustedsec/meterssh)
	* MeterSSH is a way to take shellcode, inject it into memory then tunnel whatever port you want to over SSH to mask any type of communications as a normal SSH connection. The way it works is by injecting shellcode into memory, then wrapping a port spawned (meterpeter in this case) by the shellcode over SSH back to the attackers machine. Then connecting with meterpreter's listener to localhost will communicate through the SSH proxy, to the victim through the SSH tunnel. All communications are relayed through the SSH tunnel and not through the network.

* [AutoDane at BSides Cape Town](https://sensepost.com/blog/2015/autodane-at-bsides-cape-town/)
* [Auto DANE](https://github.com/sensepost/autoDANE)
	* Auto DANE attempts to automate the process of exploiting, pivoting and escalating privileges on windows domains.
* [Setting up Samba as a Domain Member](https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member)
* [CLR-Persistence](https://github.com/3gstudent/CLR-Injection)
	* Use CLR to inject all the .NET apps
* [Portia](https://github.com/milo2012/portia)
	* Portia aims to automate a number of techniques commonly performed on internal network penetration tests after a low privileged account has been compromised. Portia performs privilege escalation as well as lateral movement automatically in the network

* [ EDR, ETDR, Next Gen AV is all the rage, so why am I enraged? - Michael Gough - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t416-edr-etdr-next-gen-av-is-all-the-rage-so-why-am-i-enraged-michael-gough)
	* A funny thing happened when I evaluated several EDR, ETDR and Next Gen AV products, currently all the rage and latest must have security solution. Surprisingly to me the solutions kinda sucked at things we expected them to do or be better at, thus this talk so you can learn from our efforts. While testing, flaws were discovered and shared with the vendors, some of the flaws, bugs, or vulns that were discovered will be discussed. This talk takes a look at what we initially expected the solutions to provide us, the options or categories of what these solutions address, what to consider when doing an evaluation, how to go about testing these solutions, how they would fit into our process, and what we found while testing these solutions. What enraged me about these EDR solutions were how they were all over the place in how they worked, how hard or ease of use of the solutions, and the fact I found malware that did not trigger an alert on every solution I tested. And this is the next new bright and shiny blinky security savior solution? The news is not all bad, there is hope if you do some work to understand what these solutions target and provide, what to look for, and most importantly how to test them! What we never anticipated or expected is the tool we used to compare the tests and how well it worked and how it can help you. 

* [Escaping Restricted Linux Shells - SANS](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells#)
* [Breaking out of rbash using scp - pentestmonkey](http://pentestmonkey.net/blog/rbash-scp)
* [Escape From SHELLcatraz - Breaking Out of Restricted Unix Shells - knaps](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells)

* [GoGreen](https://github.com/leoloobeek/GoGreen)
	* This project was created to bring environmental (and HTTP) keying to scripting languages. As its common place to use PowerShell/JScript/VBScript as an initial vector of code execution, as a result of phishing or lateral movement, I see value of the techniques for these languages.

* [PSShell](https://github.com/fdiskyou/PSShell)
	* PSShell is an application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET). It doesn't need to be "installed" so it's very portable.
* [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
	* Tool to audit and attack LAPS environments

* [Active Directory Pentest Recon Part 1: SPN Scanning aka Mining Kerberos Service Principal Names](https://adsecurity.org/?p=230)
* [Practically Exploiting MS15-014 and MS15-011](https://labs.mwrinfosecurity.com/blog/practically-exploiting-ms15-014-and-ms15-011/)
* [MS15-011 - Microsoft Windows Group Policy real exploitation via a SMB MiTM attack](https://www.coresecurity.com/blog/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack)

* [IOHIDeous](https://siguza.github.io/IOHIDeous/)

* [Battle Of SKM And IUM How Windows 10 Rewrites OS Architecture - Alex Ionescu - BHUSA2015](https://www.youtube.com/watch?v=LqaWIn4y26E&index=15&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7)
	* [Slides](http://www.alex-ionescu.com/blackhat2015.pdf)

* [Mac OS X Keychain Forensic Tool](https://github.com/n0fate/chainbreaker)
	* The chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner. Master Key candidates can be extracted from volafox or volatility keychaindump module. Supports: Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra

* [ADRecon](https://github.com/sense-of-security/ADRecon)
	* ADRecon is a tool which extracts various artifacts (as highlighted below) out of an AD environment in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis. The report can provide a holistic picture of the current state of the target AD environment.  It can be run from any workstation that is connected to the environment, even hosts that are not domain members. Furthermore, the tool can be executed in the context of a non-privileged (i.e. standard domain user) accounts. Fine Grained Password Policy, LAPS and BitLocker may require Privileged user accounts. The tool will use Microsoft Remote Server Administration Tools (RSAT) if available, otherwise it will communicate with the Domain Controller using LDAP. 

* [Evading Autoruns](https://github.com/huntresslabs/evading-autoruns)
	* When it comes to offense, maintaining access to your endpoints is key. For defenders, it's equally important to discover these footholds within your network. During this talk, Kyle and Chris will expose several semi-public and private techniques used to evade the most common persistence enumeration tools. Their techniques will explore ways to re-invent the run key, unconventionally abuse search order, and exploit trusted applications. To complement their technical explanations, each bypass will include a live demo and recommendations for detection.
	* [Talk](https://www.youtube.com/watch?v=AEmuhCwFL5I&feature=youtu.be)

* [Raining shells on Linux environments with Hwacha](https://www.n00py.io/2017/12/raining-shells-on-linux-environments-with-hwacha/)
* [Hwacha](https://github.com/n00py/Hwacha)
	* Hwacha is a tool to quickly execute payloads on `*`Nix based systems. Easily collect artifacts or execute shellcode on an entire subnet of systems for which credentials are obtained.
* [HostEnum](https://github.com/threatexpress/red-team-scripts)
	* A PowerShell v2.0 compatible script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain, it can also perform limited domain enumeration with the -Domain switch. However, domain enumeration is significantly limited with the intention that PowerView or BoodHound could also be used.




















------------
## Programming/AppSec


* [FindBugs](https://find-sec-bugs.github.io/)
	* The FindBugs plugin for security audits of Java web applications.
* [bundler-audit](https://github.com/rubysec/bundler-audit)
	* Patch-level verification for Bundler
* [OWASP SafeNuGet](https://github.com/owasp/SafeNuGet)
	* OWASP SafeNuGet is an MsBuild task to warn about insecure NuGet libraries: https://nuget.org/packages/SafeNuGet/

* [One Line of Code that Compromises Your Server - The dangers of a simplistic session secret](https://martinfowler.com/articles/session-secret.html)

* [SourceTrail](https://www.sourcetrail.com/)
	* A cross-platform source explorer for C/C++ and Java* 

* [Attack Surface Meter](https://github.com/andymeneely/attack-surface-metrics)
	* Python package for collecting attack surface metrics from a software system. In its current version, Attack Surface Meter is capable of analyzing software systems written in the C programming language with skeletal support for analyzing software systems written in the Java programming language. The attack surface metrics collected are:
	* Proximity to Entry/Exit/Dangerous - The mean of shortest unweighted path length from a function/file to Entry Points/Exit Points/Dangerous Points.
    * Risky Walk - The probability that a function/file will be invoked on a random execution path starting at the attack surface.

* [Code Insecurity or Code in Security - Mano 'dash4rk' Paul - Derbycon2014](https://www.irongeek.com/i.php?page=videos/derbycon4/t205-code-insecurity-or-code-in-security-mano-dash4rk-paul)
	* Attendees of this talk will benefit from learning about what constitutes insecure code and the associated attacks that stem from such code. Applicable attacks ranging from injection to reversing will be demonstrated to reinforce contents of this talk. This way, the attendee would not only be taught about “What not to do?” but also, “Why this should not do, what they ought not to do?”. Finally, attendees will also be introduced to secure development processes such as protection needs elicitation, threat modeling, code review and analysis and secure deployment, to illustrate that while writing secure code is one important aspect of software security, there is more to securing applications, than what meets the eye. Come for a fun filled, interactive session and your chance to win one of the personalized and autographed copies of the speaker’s renowned book – The 7 qualities of highly secure software.



------------
## RE


* [osx & ios re 101](https://github.com/michalmalik/osx-re-101)










------------
## Red Team/Adversary Simulation/Pentesting 
* [Red Teaming Windows: Building a better Windows by hacking it - MS Ignite2017](https://www.youtube.com/watch?v=CClpjtgaJVI)
* [Breaking Red - Understanding Threats through Red Teaming - SANS Webcast](https://www.youtube.com/watch?v=QPmgV1SRTJY)
* ['Red Team: How to Succeed By Thinking Like the Enemy' - Council on Foreign Relations - Micah Zenko](https://www.youtube.com/watch?v=BM2wYbu4EFY)

* [Defenders, Bring Your 'A' Game](https://winterspite.com/security/defenders-bring-your-a-game/)
* [Planning Effective Red Team Exercises - Sean T Malone - BSidesSF2016](https://www.youtube.com/watch?v=cD-jKBfSKP4)
	* An effective red team exercise is substantially different from a penetration test, and it should be chartered differently as well. The scenario, objective, scope, and rules of engagement all need to be positioned correctly at the beginning in order to most closely simulate a real adversary and provide maximum value to the client.In this presentation, we'll review best practices in each of these areas, distilled from conducting dozens of successful red team exercises - along with some war stories highlighting why each element matters. Those in offensive security will gain an understanding of how to manage the client's expectations for this process, and how to guide them towards an engagement that provides a realistic measurement of their ability to prevent, detect, and respond to real attacks. Those in enterprise security will gain a deeper understanding of this style of assessment, and how to work with a red team to drive real improvement in their security programs. 

* [Using an Expanded Cyber Kill Chain Model to Increase Attack Resiliency - Sean Malone - BHUSA16](https://www.youtube.com/watch?v=1Dz12M7u-S8)
	* We'll review what actions are taken in each phase, and what's necessary for the adversary to move from one phase to the next. We'll discuss multiple types of controls that you can implement today in your enterprise to frustrate the adversary's plan at each stage, to avoid needing to declare "game over" just because an adversary has gained access to the internal network. The primary limiting factor of the traditional Cyber Kill Chain is that it ends with Stage 7: Actions on Objectives, conveying that once the adversary reaches this stage and has access to a system on the internal network, the defending victim has already lost. In reality, there should be multiple layers of security zones on the internal network, to protect the most critical assets. The adversary often has to move through numerous additional phases in order to access and manipulate specific systems to achieve his objective. By increasing the time and effort required to move through these stages, we decrease the likelihood of the adversary causing material damage to the enterprise. 
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Malone-Using-An-Expanded-Cyber-Kill-Chain-Model-To-Increase-Attack-Resiliency.pdf)

* [attacking encrypted systems with qemu and volatility](https://diablohorn.com/2017/12/12/attacking-encrypted-systems-with-qemu-and-volatility/) 

* [The hidden horrors that 3 years of global red-teaming, Jos van der Peet](https://www.youtube.com/watch?v=7z63HrEiQUY&index=10&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
	*  My last 3 years of global reteaming in small and large organisations has shown me that there still are a lot of misconceptions about security. We all know the ‘onion’ model for layered security. While useful for the ‘defence in depth’ principle, this talk will show that in reality, rather than an onion, security is more like a pyramid. The basis is the hardware people work on (laptops etc.) and the top your business applications. In between is everything else. Operating system, network components, proxies, shares, servers and their software stack. Like any hi-rise structure, the top cannot be secure if the base is not secure. Defence in depth matters, but it can be quite trivial for attackers to sidestep certain controls to get to the data they want. Just securing your ‘crown-jewels’ is insufficient. This talk will revolve around how we have defeated security controls on various levels, ranging from the systems your end-users work on, all the way through to 2FA and 4-eye principles on critical business assets. It will talk about common misconceptions which lull companies into a false sense of security, while making life far too easy for attackers. For example the fallacy of focussing security efforts only/mostly on ‘crown jewels’ and how misunderstanding of why certain controls are put in place jeopardize corporate and client data. The talk will be supported by real-life examples

* [“Tasking” Office 365 for Cobalt Strike C2](https://labs.mwrinfosecurity.com/blog/tasking-office-365-for-cobalt-strike-c2/)

* [Hacking Virtual Appliances - Jeremy Brown - Derbycon2015](https://www.irongeek.com/i.php?page=videos/derbycon5/fix-me08-hacking-virtual-appliances-jeremy-brown)
	* Virtual Appliances have become very prevalent these days as virtualization is ubiquitous and hypervisors commonplace. More and more of the major vendors are providing literally virtual clones for many of their once physical-only products. Like IoT and the CAN bus, it's early in the game and vendors are late as usual. One thing that it catching these vendors off guard is the huge additional attack surface, ripe with vulnerabilities, added in the process. Also, many vendors see software appliances as an opportunity for the customer to easily evaluate the product before buying the physical one, making these editions more accessible and debuggable by utilizing features of the platform on which it runs. During this talk, I will provide real case studies for various vulnerabilities created by mistakes that many of the major players made when shipping their appliances. You'll learn how to find these bugs yourself and how the vendors went about fixing them, if at all. By the end of this talk, you should have a firm grasp of how one goes about getting remotes on these appliances.
* [Pacdoor](https://github.com/SafeBreach-Labs/pacdoor)
	* Pacdoor is a proof-of-concept JavaScript malware implemented as a Proxy Auto-Configuration (PAC) File. Pacdoor includes a 2-way communication channel, ability to exfiltrate HTTPS URLs, disable access to cherry-picked URLs etc.
* [Attacking and Defending Full Disk Encryption - Tom Kopchak - BSides Cleveland2014](https://www.youtube.com/watch?v=-XLitSfOQ6U)


------------
## Rootkits


------------
## SCADA / Heavy Machinery

* [Offensive ICS Exploitation: A Description of an ICS CTF - MWR](https://labs.mwrinfosecurity.com/blog/offensive-ics-exploitation-a-technical-description/)














------------
## Social Engineering





------------
## System Internals

* [Understanding the Windows PowerShell Pipeline - docs.ms](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/fundamental/understanding-the-windows-powershell-pipeline?view=powershell-5.1)
* [PowerShell Language Modes - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-5.1)

* [Battle Of SKM And IUM How Windows 10 Rewrites OS Architecture - Alex Ionescu - BHUSA2015](https://www.youtube.com/watch?v=LqaWIn4y26E&index=15&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7)
	* [Slides](http://www.alex-ionescu.com/blackhat2015.pdf)
* [Isolated User Mode in Windows 10 with Dave Probert](https://channel9.msdn.com/Blogs/Seth-Juarez/Isolated-User-Mode-in-Windows-10-with-Dave-Probert)
* [Isolated User Mode Processes and Features in Windows 10 with Logan Gabriel](https://channel9.msdn.com/Blogs/Seth-Juarez/Isolated-User-Mode-Processes-and-Features-in-Windows-10-with-Logan-Gabriel)

* [Guarded fabric and shielded VMs](https://docs.microsoft.com/en-us/windows-server/virtualization/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms-top-node)









------------
## Threat Modeling & Analysis




--------------
## UI









------------
## Web: 

* [NodeGoat](https://github.com/OWASP/NodeGoat)
	* Being lightweight, fast, and scalable, Node.js is becoming a widely adopted platform for developing web applications. This project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.

* [Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
* [How to configure Json.NET to create a vulnerable web API](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html)

* [Tricks to improve web app excel export attacks - Jerome Smith - CamSec2016](https://www.slideshare.net/exploresecurity/camsec-sept-2016-tricks-to-improve-web-app-excel-export-attacks)

* [Java Server Faces - Wikipedia](https://en.wikipedia.org/wiki/JavaServer_Faces)
* [ Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)

https://github.com/stephenbradshaw/breakableflask
https://github.com/JasonHinds13/hackable
https://github.com/omarkurt/flask-injection


* [Retire.js](https://retirejs.github.io/retire.js/)
	* There is a plethora of JavaScript libraries for use on the web and in node.js apps out there. This greatly simplifies, but we need to stay update on security fixes. "Using Components with Known Vulnerabilities" is now a part of the OWASP Top 10 and insecure libraries can pose a huge risk for your webapp. The goal of Retire.js is to help you detect use of version with known vulnerabilities.

* [WebUSB - How a website could steal data off your phone](https://labs.mwrinfosecurity.com/blog/webusb/)
	* This blog post looks in to the capabilities of WebUSB to understand how it works, the new attack surface, and privacy issues. We will describe the processes necessary to get access to devices and how permissions are handled in the browser. Then we will discuss some security implications and shows, how a website can use WebUSB to establish an ADB connection and effectively compromise a connected Android phone.

SAML
* [With Great Power Comes Great Pwnage](https://www.compass-security.com/fileadmin/Datein/Research/Praesentationen/area41_2016_saml.pdf)
* [SAMLReQuest Burpsuite Extention](https://insinuator.net/2016/06/samlrequest-burpsuite-extention/)
* [Out of Band  XML External Entity Injection via SAML SSO - Sean Melia](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf)
* [Web-based Single Sign-On and the Dangers of SAML XML Parsing](https://blog.sendsafely.com/web-based-single-sign-on-and-the-dangers-of-saml-xml-parsing)
* [Following the white Rabbit Down the SAML Code](https://medium.com/section-9-lab/following-the-white-rabbit-5e392e3f6fb9)
* [Evilginx - Advanced Phishing with Two-factor Authentication Bypass](https://breakdev.org/evilginx-advanced-phishing-with-two-factor-authentication-bypass/)
	* [Evilginx - Update 1.0](https://breakdev.org/evilginx-1-0-update-up-your-game-in-2fa-phishing/)
	* [Evilginx - Update 1.1](https://breakdev.org/evilginx-1-1-release/)
	* [Evilginx](https://github.com/kgretzky/evilginx)
		* Evilginx is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. It's core runs on Nginx HTTP server, which utilizes proxy_pass and sub_filter to proxy and modify HTTP content, while intercepting traffic between client and server.


* [No SQL, No Injection? - Examining NoSQL Security](https://arxiv.org/pdf/1506.04082.pdf)
* [NoSQL Injection in Modern Web Applications - petecorey.com](http://www.petecorey.com/blog/2016/03/21/nosql-injection-in-modern-web-applications/)
* [Hacking NodeJS and MongoDB - websecurify](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
* [MongoDB Injection - How To Hack MongoDB](http://www.technopy.com/mongodb-injection-how-to-hack-mongodb-html/)

* [Django-Security](https://github.com/sdelements/django-security)
	* This package offers a number of models, views, middlewares and forms to facilitate security hardening of Django applications.
* [Syntribos](https://github.com/openstack/syntribos)
	* Given a simple configuration file and an example HTTP request, syntribos can replace any API URL, URL parameter, HTTP header and request body field with a given set of strings. Syntribos iterates through each position in the request automatically. Syntribos aims to automatically detect common security defects such as SQL injection, LDAP injection, buffer overflow, etc. In addition, syntribos can be used to help identify new security defects by automated fuzzing.

* [Abusing NoSQL Databases - Ming Chow](https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf)

* [Attacking MongoDB - ZeroNights2012](http://blog.ptsecurity.com/2012/11/attacking-mongodb.html)

* [From CSV to CMD to qwerty](http://www.exploresecurity.com/from-csv-to-cmd-to-qwerty/)
* [Comma Separated Vulnerabilities](https://www.contextis.com/blog/comma-separated-vulnerabilities)
	* This post introduces Formula Injection, a technique for exploiting ‘Export to Spreadsheet’ functionality in web applications to attack users and steal spreadsheet contents. It also details a command injection exploit for Apache OpenOffice and LibreOffice that can be delivered using this technique.
* [pwn.js](https://github.com/theori-io/pwnjs)
	* A Javascript library for browser exploitation

* [CloudFire](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/cfire)
	* This project focuses on discovering potential IP's leaking from behind cloud-proxied services, e.g. Cloudflare. Although there are many ways to tackle this task, we are focusing right now on CrimeFlare database lookups, search engine scraping and other enumeration techniques.
* [buckethead.py](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools)
	* buckethead.py searches across every AWS region for a variety of bucket names based on a domain name, subdomains, affixes given and more. Currently the tool will only present to you whether or not the bucket exists or if they're listable. If the bucket is listable, then further interrogation of the resource can be done. It does not attempt download or upload permissions currently but could be added as a module in the future. You will need the awscli to run this tool as this is a python wrapper around this tool.

* [XSS Web Filter Bypass list - rvrsh3ll](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec#file-xxsfilterbypass-lst-L1)
ID
* [Insecure HTTP Header Removal](https://www.aspectsecurity.com/blog/insecure-http-header-removal)
[The unexpected dangers of preg_replace()](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace)
* [Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution](https://www.exploit-db.com/exploits/41570/)



------------
## Wireless Stuff

* [Bluetooth: With Low Energy Comes Low Security](https://www.usenix.org/conference/woot13/workshop-program/presentation/ryan)
* [crEAP](https://github.com/Snizz/crEAP)
	* Python script to identify wireless networks EAP types and harvest users 
* [EAPEAK](https://github.com/securestate/eapeak)
	* EAPeak is a suite of open source tools to facilitate auditing of wireless networks that utilize the Extensible Authentication Protocol framework for authentication. It is meant to give useful information relating to the security of these networks for pentesters to use while searching for vulnerabilities. 

* [The NSA Playset: Bluetooth Smart Attack Tools - Mike Ryan](https://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/15-the-nsa-playset-bluetooth-smart-attack-tools-mike-ryan)
* [Slides](https://conference.hitb.org/hitbsecconf2014kul/sessions/bluetooth-smart-attack-tools/)
	* This talk is a part of the NSA Playset series, a collection of unique topics with a common theme: implementing the NSA’s toys as found in the NSA ANT catalog. I have developed multiple Bluetooth Smart (BLE) attack tools, inspired by capabilities likely to be present in the ANT catalog.
* [Outsmarting Bluetooth Smart - Mike Smart](https://www.youtube.com/watch?v=dYj6bpDzID0)
	* This talk covers Bluetooth Smart active attacks, fuzzing Bluetooth stacks, and remote Bluetooth exploitation. I presented this talk at CanSecWest 2014 in Vancouver, BC, Canada.
	* [Slides](https://lacklustre.net/bluetooth/outsmarting_bluetooth_smart-mikeryan-cansecwest_2014.pdf)
* [Bluetooth Smart: The Good, the Bad, the Ugly, and the Fix! - BHUSA 2013](https://www.youtube.com/watch?v=SoH11fi-FcA)
	* [Slides](https://lacklustre.net/bluetooth/bluetooth_smart_good_bad_ugly_fix-mikeryan-blackhat_2013.pdf)
* [How Smart Is Bluetooth Smart?](https://lacklustre.net/bluetooth/how_smart_is_bluetooth_smart-mikeryan-shmoocon_2013.pdf)
* [Hacking Bluetooth Low Energy: I Am Jack's Heart Monitor - Toorcon2012](https://www.youtube.com/watch?v=4POOiVrdnX8)
	* Bluetooth Low Energy (BTLE) is the hottest new mode in the latest and greatest Bluetooth 4.0 spec. A new generation of wireless devices, including medical devices will be implemented using this mode. BTLE is much simpler than classic Bluetooth. Simpler to implement, simpler to debug, and hey, simpler to hack. I present the progress of a BTLE sniffer/smasher/smusher written for Ubertooth in this WIP talk. 
	* [Slides](https://lacklustre.net/bluetooth/hacking_btle-i_am_jacks_heart_monitor-mikeryan-toorcon_2012.pdf)
* [Hacking Electric Skateboards - Mike Ryan and Richo Healey - DEF CON 23](https://www.youtube.com/watch?v=JZ3EB68v_B0)
	* Richo and Mike will investigate the security of several popular skateboards, including Boosted's flagship model and demonstrate several vulnerabilities that allow complete control of a an unmodified victim's skateboard, as well as other attacks on the firmware of the board and controller directly.
	* [Slides](https://media.defcon.org/DEF%20CON%2023/DEF%20CON%2023%20presentations/DEFCON-23-Richo-Healey-Mike-Ryan-Hacking-Electric-Skateboards.pdf)

* [Primary Security Threats For SS7 Cellular Networks](https://www.ptsecurity.com/upload/ptcom/SS7-VULNERABILITY-2016-eng.pdf)
* [SS7 MAP (pen-)testing toolkit](https://github.com/ernw/ss7MAPer)

* [Bluetooth: With Low Energy comes Low Security - Mike Ryan](https://lacklustre.net/bluetooth/Ryan_Bluetooth_Low_Energy_USENIX_WOOT.pdf)
	* We discuss our tools and techniques to monitor and inject packets in Bluetooth Low Energy. Also known as BTLE or Bluetooth Smart, it is found in recent high-end smartphones, sports devices, sensors, and will soon appear in many medical devices.  We show that we can effectively render useless the encryption of any Bluetooth Low Energy link
* [Now I wanna sniff some Bluetooth: Sniffing and Cracking Bluetooth with the UbertoothOne](https://www.security-sleuth.com/sleuth-blog/2015/9/6/now-i-wanna-sniff-some-bluetooth-sniffing-and-cracking-bluetooth-with-the-ubertoothone)
* [gattacker](https://github.com/securing/gattacker)
	* A Node.js package for BLE (Bluetooth Low Energy) Man-in-the-Middle & more
* [noble](https://github.com/sandeepmistry/noble)
	* A Node.js BLE (Bluetooth Low Energy) central module.
* [bleno](https://github.com/sandeepmistry/bleno)
	* A Node.js module for implementing BLE (Bluetooth Low Energy) peripherals.
* [This Is Not a Post About BLE, Introducing BLEAH](https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/)
* [Bluetooth Hacking Tools Comparison - Mark Loveless](https://duo.com/blog/bluetooth-hacking-tools-comparison)
* [Cracking the Bluetooth PIN - Yaniv Shaked and Avishai Wool](http://www.eng.tau.ac.il/~yash/shaked-wool-mobisys05/)
	* This paper describes the implementation of an attack on the Bluetooth security mechanism. Specifically, we describe a passive attack, in which an attacker can find the PIN used during the pairing process. We then describe the cracking speed we can achieve through three optimizations methods. Our fastest optimization employs an algebraic representation of a central cryptographic primitive (SAFER+) used in Bluetooth. Our results show that a 4-digit PIN can be cracked in less than 0.3 sec on an old Pentium III 450MHz computer, and in 0.06 sec on a Pentium IV 3Ghz HT computer. 

	* [crackle](https://github.com/mikeryan/crackle/)
	* crackle cracks BLE Encryption (AKA Bluetooth Smart). crackle exploits a flaw in the BLE pairing process that allows an attacker to guess or very quickly brute force the TK (Temporary Key). With the TK and other data collected from the pairing process, the STK (Short Term Key) and later the LTK (Long Term Key) can be collected. With the STK and LTK, all communications between the master and the slave can be decrypted.

	* [My journey towards Reverse Engineering a Smart Band — Bluetooth-LE RE](https://medium.com/@arunmag/my-journey-towards-reverse-engineering-a-smart-band-bluetooth-le-re-d1dea00e4de2)

* [Spread Spectrum Satcom Hacking: Attacking The Globalstar Simplex Data Service - Colby Moore - BHUSA2015](https://www.youtube.com/watch?v=1VbmHmzofmc)