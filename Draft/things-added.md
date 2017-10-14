[VMware Escape Exploit](https://github.com/unamer/vmware_escape)
* VMware Escape Exploit before VMware WorkStation 12.5.5

[Whitelist Evasion revisited](https://khr0x40sh.wordpress.com/2015/05/27/whitelist-evasion-revisited/)


[Comma Separated Vulnerabilities](https://www.contextis.com/blog/comma-separated-vulnerabilities)


-------------
### ATT&CK

[osxinj](https://github.com/scen/osxinj)
* Another dylib injector. Uses a bootstrapping module since mach_inject doesn't fully emulate library loading and crashes when loading complex modules.

[kcap](https://github.com/scriptjunkie/kcap)
* This program simply uses screen captures and programmatically generated key and mouse events to locally and graphically man-in-the-middle an OS X password prompt to escalate privileges.

[Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)

[Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.

[CloakifyFactory](https://github.com/TryCatchHCF/Cloakify)
* CloakifyFactory & the Cloakify Toolset - Data Exfiltration & Infiltration In Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat Data Whitelisting Controls; Evade AV Detection. Text-based steganography usings lists. Convert any file type (e.g. executables, Office, Zip, images) into a list of everyday strings. Very simple tools, powerful concept, limited only by your imagination.





------------
## Anonymity/Privacy

[.NET Github: .NET core should not SPY on users by default #3093](https://github.com/dotnet/cli/issues/3093)

[.NET Github: Revisit Telemetry configuration #6086 ](https://github.com/dotnet/cli/issues/6086)


[Decoy Routing: Toward Unblockable Internet Communication](https://www.usenix.org/legacy/events/foci11/tech/final_files/Karlin.pdf)
* We present decoy routing, a mechanism capable of cir- cumventing common network filtering strategies. Unlike other circumvention techniques, decoy routing does not require a client to connect to a specific IP address (which is easily blocked) in order to provide circumvention. We show that if it is possible for a client to connect to any unblocked host/service, then decoy routing could be used to connect them to a blocked destination without coop- eration from the host. This is accomplished by placing the circumvention service in the network itself – where a single device could proxy traffic between a significant fraction of hosts – instead of at the edge.

[obfs4 (The obfourscator)](https://gitweb.torproject.org/pluggable-transports/obfs4.git/tree/doc/obfs4-spec.txt)
* This is a protocol obfuscation layer for TCP protocols. Its purpose is to keep a third party from telling what protocol is in use based on message contents. Unlike obfs3, obfs4 attempts to provide authentication and data integrity, though it is still designed primarily around providing a layer of obfuscation for an existing authenticated protocol like SSH or TLS.

[obfs3 (The Threebfuscator)](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/tree/doc/obfs3/obfs3-protocol-spec.txt)
* This is a protocol obfuscation layer for TCP protocols. Its purpose is to keep a third party from telling what protocol is in use based on message contents. Like obfs2, it does not provide authentication or data integrity. It does not hide data lengths. It is more suitable for providing a layer of obfuscation for an existing authenticated protocol, like SSH or TLS. 

[StegoTorus: A Camouflage Proxy for the Tor Anonymity System](https://research.owlfolio.org/pubs/2012-stegotorus.pdf)
* Internet censorship by governments is an increasingly common practice worldwide. Internet users and censors are locked in an arms race: as users find ways to evade censorship schemes, the censors develop countermeasures for the evasion tactics. One of the most popular and effective circumvention tools, Tor, must regularly adjust its network traffic signature to remain usable. We present StegoTorus, a tool that comprehensively disguises Tor from protocol analysis. To foil analysis of packet contents, Tor’s traffic is steganographed to resemble an innocuous cover protocol, such as HTTP. To foil analysis at the transport level, the Tor circuit is distributed over many shorter-lived connections with per-packet characteristics that mimic cover-protocol traffic. Our evaluation demonstrates that StegoTorus improves the resilience of Tor to fingerprinting attacks and delivers usable performance.

[SkypeMorph: Protocol Obfuscation for Tor Bridges](https://www.cypherpunks.ca/~iang/pubs/skypemorph-ccs.pdf)
* The Tor network is designed to provide users with low- latency anonymous communications. Tor clients build circuits with publicly listed relays to anonymously reach their destinations. However, since the relays are publicly listed, they can be easily blocked by censoring adversaries. Consequently, the Tor project envisioned the possibility of unlisted entry points to the Tor network, commonly known as bridges. We address the issue of preventing censors from detecting the bridges by observing the communications between them and nodes in their network. We propose a model in which the client obfuscates its messages to the bridge in a widely used protocol over the Inter- net. We investigate using Skype video calls as our target protocol and our goal is to make it difficult for the censor- ing adversary to distinguish between the obfuscated bridge connections and actual Skype calls using statistical compar- isons. We have implemented our model as a proof-of-concept pluggable transport for Tor, which is available under an open-source licence. Using this implementation we observed the obfuscated bridge communications and compared it with those of Skype calls and presented the results.

[Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
* Deep packet inspection (DPI) technologies provide much needed visibility and control of network traffic using port- independent protocol identification, where a network flow is labeled with its application-layer protocol based on packet contents. In this paper, we provide the first comprehensive evaluation of a large set of DPI systems from the point of view of protocol misidentification attacks, in which adver- saries on the network attempt to force the DPI to mislabel connections. Our approach uses a new cryptographic prim- itive called format-transforming encryption (FTE), which extends conventional symmetric encryption with the ability to transform the ciphertext into a format of our choosing. We design an FTE-based record layer that can encrypt arbitrary application-layer traffic, and we experimentally show that this forces misidentification for all of the evaluated DPI systems. This set includes a proprietary, enterprise-class DPI system used by large corporations and nation-states. We also show that using FTE as a proxy system incurs no latency overhead and as little as 16% bandwidth overhead compared to standard SSH tunnels. Finally, we integrate our FTE proxy into the Tor anonymity network and demon- strate that it evades real-world censorship by the Great Fire- wall of China

[Cirripede: Circumvention Infrastructure using Router Redirection with Plausible Deniability](http://hatswitch.org/~nikita/papers/cirripede-ccs11.pdf)
* Many users face surveillance of their Internet communications and a significant fraction suffer from outright blocking of certain destinations. Anonymous communication systems allow users to conceal the destinations they communicate with, but do not hide the fact that the users are using them. The mere use of such systems may invite suspicion, or access to them may be blocked. We therefore propose Cirripede, a system that can be used for unobservable communication with Internet destinations. Cirripede is designed to be deployed by ISPs; it intercepts connections from clients to innocent-looking desti- nations and redirects them to the true destination requested by the client. The communication is encoded in a way that is indistinguishable from normal communications to anyone without the master secret key, while public-key cryptogra- phy is used to eliminate the need for any secret information that must be shared with Cirripede users. Cirripede is designed to work scalably with routers that handle large volumes of traffic while imposing minimal over- head on ISPs and not disrupting existing traffic. This allows Cirripede proxies to be strategically deployed at central lo- cations, making access to Cirripede very difficult to block. We built a proof-of-concept implementation of Cirripede and performed a testbed evaluation of its performance proper- ties

[TapDance: End-to-Middle Anticensorship without Flow Blocking](https://jhalderm.com/pub/papers/tapdance-sec14.pdf)
* In response to increasingly sophisticated state-sponsored Internet censorship, recent work has proposed a new ap- proach to censorship resistance: end-to-middle proxying. This concept, developed in systems such as Telex, Decoy Routing, and Cirripede, moves anticensorship technology into the core of the network, at large ISPs outside the censoring country. In this paper, we focus on two technical obstacles to the deployment of certain end-to-middle schemes: the need to selectively block flows and the need to observe both directions of a connection. We propose a new construction, TapDance, that removes these require- ments. TapDance employs a novel TCP-level technique that allows the anticensorship station at an ISP to function as a passive network tap, without an inline blocking com- ponent. We also apply a novel steganographic encoding to embed control messages in TLS ciphertext, allowing us to operate on HTTPS connections even under asymmetric routing. We implement and evaluate a TapDance proto- type that demonstrates how the system could function with minimal impact on an ISP’s network operations.

[Chipping Away at Censorship Firewalls with User-Generated Content](https://www.usenix.org/legacy/event/sec10/tech/full_papers/Burnett.pdf)
* Oppressive regimes and even democratic governments restrict Internet access. Existing anti-censorship systems often require users to connect through proxies, but these systems are relatively easy for a censor to discover and block. This paper offers a possible next step in the cen- sorship arms race: rather than relying on a single system or set of proxies to circumvent censorship firewalls, we explore whether the vast deployment of sites that host user-generated content can breach these firewalls. To explore this possibility, we have developed Collage, which allows users to exchange messages through hidden chan- nels in sites that host user-generated content. Collage has two components: a message vector layer for embedding content in cover traffic; and a rendezvous mechanism to allow parties to publish and retrieve messages in the cover traffic. Collage uses user-generated content (e.g. , photo-sharing sites) as “drop sites” for hidden messages. To send a message, a user embeds it into cover traffic and posts the content on some site, where receivers retrieve this content using a sequence of tasks. Collage makes it difficult for a censor to monitor or block these messages by exploiting the sheer number of sites where users can exchange messages and the variety of ways that a mes- sage can be hidden. Our evaluation of Collage shows that the performance overhead is acceptable for sending small messages (e.g. , Web articles, email). We show how Collage can be used to build two applications: a direct messaging application, and a Web content delivery sys- tem

[Unblocking the Internet: Social networks foil censors](http://kscope.news.cs.nyu.edu/pub/TR-2008-918.pdf)
* Many countries and administrative domains exploit control over their communication infrastructure to censor online content. This paper presents the design, im plementation and evaluation of Kaleidoscope , a peer-to-peer system of relays that enables users within a censored domain to access blocked content. The main challenge facing Kaleidoscope is to resist the cens or’s efforts to block the circumvention system itself. Kaleidoscope achieves blocking-resilienc e using restricted service discovery that allows each user to discover a small set of unblocked relays while only exposing a small fraction of relays to the censor. To restrict service discovery, Kaleidoscope leverages a trust network where links reflects real-world social relationships among users and uses a limited advertisement protocol based on random routes to disseminate relay addresses along the trust netwo rk; the number of nodes reached by a relay advertisement should ideally be inversely proportional to the maximum fraction of infiltration and is independent of the network size. To increase service availa bility in large networks with few exit relay nodes, Kaleidoscope forwards the actual data traffic across multiple relay hops without risking exposure of exit relays. Using detailed analysis and simulations, we show that Kalei doscope provides > 90% service availability even under substantial infiltration (close to 0.5% of edges) and when only 30% of the relay nodes are online. We have implemented and deployed our system on a small scale serving over 100,000 requests to 40 censored users (relatively small user base to realize Kaleidoscope’s anti-blocking guarantees) spread across different countries and administrative domains over a 6-month period

[A Technical Description of Psiphon](https://psiphon.ca/en/blog/psiphon-a-technical-description)





















------------
## Attacking/Defending Android






------------
## Basic Security Info



------------
## BIOS/UEFI




------------
## Building a Lab 

[SANS Webcast: Building Your Own Super Duper Home Lab](https://www.youtube.com/watch?v=uzqwoufhwyk&app=desktop)



------------
## Car Hacking



------------
## Conferences

[Derbycon 2017 Videos](https://www.irongeek.com/i.php?page=videos/derbycon7/mainlist)






------------
## Courses






------------
## CTF

[NightShade](https://github.com/UnrealAkama/NightShade)
* NightShade is a simple security capture the flag framework that is designed to make running your own contest as easy as possible.

[Mellivora](https://github.com/Nakiami/mellivora)
* Mellivora is a CTF engine written in PHP








------------
## Crypto

[SSH Bad Keys](https://github.com/rapid7/ssh-badkeys)
* This is a collection of static SSH keys (host and authentication) that have made their way into software and hardware products. This was inspired by the Little Black Box project, but focused primarily on SSH (as opposed to TLS) keys.


[House of Keys](https://github.com/sec-consult/houseofkeys)
* Certificates including the matching private key and various private keys found in the firmware of embedded systems. Most certificates are used as HTTPS server certificates. Some private keys are used as SSH host keys. Other uses of these cryptographic keys were not analyzed yet. The names of products that contained the certificates/keys are included as well.


[Project HashClash](https://marc-stevens.nl/p/hashclash/)
* Project HashClash is a Framework for MD5 & SHA-1 Differential Path Construction and Chosen-Prefix Collisions for MD5. It's goal is to further understanding and study of the weaknesses of MD5 and SHA-1. 

[CPC-MD5](https://github.com/dingelish/cpc-md5)
* This project is forked from Marc Steven's Hashclash project hashclash and follows GPL.











------------
## Crypto Currencies

[How the Bitcoin protocol actually works](http://www.michaelnielsen.org/ddi/how-the-bitcoin-protocol-actually-works/)



------------
## Data Analysis/Visualization





------------
## Design





------------
## Disclosure




------------
## Documentation/Technical writing




------------
## Embedded Devices/Hardware (Including Printers & PoS)





------------
## Exfiltration

[CloakifyFactory](https://github.com/TryCatchHCF/Cloakify)
* CloakifyFactory & the Cloakify Toolset - Data Exfiltration & Infiltration In Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat Data Whitelisting Controls; Evade AV Detection. Text-based steganography usings lists. Convert any file type (e.g. executables, Office, Zip, images) into a list of everyday strings. Very simple tools, powerful concept, limited only by your imagination.




------------
## Exploit Dev

[Build a database of libc offsets to simplify exploitation](https://github.com/niklasb/libc-database)

[TWindbg](https://github.com/bruce30262/TWindbg)
* PEDA-like debugger UI for WinDbg

[Return Oriented Programming Tutorial](https://github.com/akayn/demos/blob/master/Tutorials/README.md)

Sensepost Series on Linux Heap Exploitation (Intro level)
* [Painless intro to the Linux userland heap](https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/)
* [Linux Heap Exploitation Intro Series: Used and Abused – Use After Free](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-used-and-abused-use-after-free/)
* [Linux Heap Exploitation Intro Series: The magicians cape – 1 Byte Overflow](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-the-magicians-cape-1-byte-overflow/)


[Advanced Windows Debugging: Memory Corruption Part II—Heaps](http://www.informit.com/articles/article.aspx?p=1081496)
* Daniel Pravat and Mario Hewardt discuss security vulnerabilities and stability issues that can surface in an application when the heap is used in a nonconventional fashion.

[Loading a DLL from memory](https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/)

[From MS08 067 To EternalBlue by Denis Isakov - BSides Manchester2017](https://www.youtube.com/watch?v=LZ_G6RdqrHA&index=13&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)

[ADI vs ROP](https://lazytyped.blogspot.it/2017/09/adi-vs-rop.html)




------------
## Forensics

[Packet Capture Examples from "Practical Packet Analysis"](http://www.chrissanders.org/captures/)





------------
## Fuzzing





------------
## Game Hacking

[DEFCON 17: Fragging Game Servers - Bruce Potter](https://www.youtube.com/watch?v=SooVvF9qO_k&app=desktop)

[PortAIO-Loader](https://github.com/PirateEmpire/PortAIO-Loader)

[NoEye](https://github.com/Schnocker/NoEye)
* An usermode BE Rootkit Bypass

[CSGOSimple](https://github.com/MarkHC/CSGOSimple)
* A simple base for internal Counter-Strike: Global Offensive cheats.

[PubgPrivXcode85](https://github.com/TonyZesto/PubgPrivXcode85)
* Simple chams wallhack for Player Unknowns Battlegrounds using a D3D11DrawIndexed hook Feature List:


------------
## Honeypots



		
------------
## ICS/SCADA






------------
## Interesting Things

[grokbit](https://grokbit.com/)
* Code search engine

[Creative and unusual things that can be done with the Windows API.](https://github.com/LazoCoder/Windows-Hacks)


[Youre stealing it wrong 30 years of inter pirate battles - Jason Scott - Defcon 18](https://www.youtube.com/watch?v=a5AceLYWE1Q&app=desktop)





------------
## Lockpicking





------------
## Malware

[Offensive Malware Analysis: Dissecting OSX FruitFly - Patrick Wardle - DEF CON 25](https://www.youtube.com/watch?v=q7VZtCUphgg)
* FruitFly, the first OS X/macOS malware of 2017, is a rather intriguing specimen. Selectively targeting biomedical research institutions, it is thought to have flown under the radar for many years. In this talk, we'll focus on the 'B' variant of FruitFly that even now, is only detected by a handful of security products. We'll begin by analyzing the malware's dropper, an obfuscated perl script. As this language is rather archaic and uncommon in malware droppers, we'll discuss some debugging techniques and fully deconstruct the script. 





------------
## Mainframes





------------
## Network Scanning and Attacks

[DELTA: SDN SECURITY EVALUATION FRAMEWORK](https://github.com/OpenNetworkingFoundation/DELTA)
* DELTA is a penetration testing framework that regenerates known attack scenarios for diverse test cases. This framework also provides the capability of discovering unknown security problems in SDN by employing a fuzzing technique.


[BlackNurse attack PoC](https://github.com/jedisct1/blacknurse)
* A simple PoC for the Blacknurse attack. "Blacknurse is a low bandwidth ICMP attack that is capable of doing denial of service to well known firewalls".













------------
## Network | Monitoring & Logging

[Logging - Malware Archaeology](https://www.malwarearchaeology.com/logging/)

------------
## OSINT

[Truffle Hog](https://github.com/dxa4481/truffleHog)
* Searches through git repositories for high entropy strings, digging deep into commit history









------------
##	OS X






------------
## Password Cracking








------------
## Phishing/SE

[Ichthyology: Phishing as a Science - BH USA 2017](https://www.youtube.com/watch?v=Z20XNp-luNA&app=desktop)

[MailRaider](https://github.com/xorrior/EmailRaider)
* MailRaider is a tool that can be used to browse/search a user's Outlook folders as well as send phishing emails internally using their Outlook client.








------------
## Physical Security















------------
## Policy


[The Red Book: A Roadmap for Systems Security Research](http://www.red-book.eu/m/documents/syssec_red_book.pdf)











------------
## Post Exploitation/Privilege Escalation

[LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump)
* In an Active Directory domain, a lot of interesting information can be retrieved via LDAP by any authenticated user (or machine). This makes LDAP an interesting protocol for gathering information in the recon phase of a pentest of an internal network. A problem is that data from LDAP often is not available in an easy to read format. ldapdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via LDAP and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files.


[Reading Your Way Around UAC (Part 1)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-1.html)
* [Reading Your Way Around UAC (Part 2)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-2.html)
* [Reading Your Way Around UAC (Part 3)](https://tyranidslair.blogspot.no/2017/05/reading-your-way-around-uac-part-3.html)

[Breaking Out! of Applications Deployed via Terminal Services, Citrix, and Kiosks](https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/)

[Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)

[SigThief](https://github.com/secretsquirrel/SigThief)
* Stealing Signatures and Making One Invalid Signature at a Time

[Is it possible to escalate privileges and escaping from a Docker container? - StackOverflow](https://security.stackexchange.com/questions/152978/is-it-possible-to-escalate-privileges-and-escaping-from-a-docker-container)

[The Dangers of Docker.sock](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)

[Abusing Privileged and Unprivileged Linux Containers - nccgroup](https://www.nccgroup.trust/uk/our-research/abusing-privileged-and-unprivileged-linux-containers/)

[Understanding and Hardening Linux Containers - nccgroup](https://www.nccgroup.trust/uk/our-research/understanding-and-hardening-linux-containers/)
* Operating System virtualisation is an attractive feature for efficiency, speed and modern application deployment, amid questionable security. Recent advancements of the Linux kernel have coalesced for simple yet powerful OS virtualisation via Linux Containers, as implemented by LXC, Docker, and CoreOS Rkt among others. Recent container focused start-ups such as Docker have helped push containers into the limelight. Linux containers offer native OS virtualisation, segmented by kernel namespaces, limited through process cgroups and restricted through reduced root capabilities, Mandatory Access Control and user namespaces. This paper discusses these container features, as well as exploring various security mechanisms. Also included is an examination of attack surfaces, threats, and related hardening features in order to properly evaluate container security. Finally, this paper contrasts different container defaults and enumerates strong security recommendations to counter deployment weaknesses-- helping support and explain methods for building high-security Linux containers. Are Linux containers the future or merely a fad or fantasy? This paper attempts to answer that question.

[Docker: Security Myths, Security Legends - Rory McCune](https://www.youtube.com/watch?v=uQigvjSXMLw)

[osxinj](https://github.com/scen/osxinj)
* Another dylib injector. Uses a bootstrapping module since mach_inject doesn't fully emulate library loading and crashes when loading complex modules.

[kcap](https://github.com/scriptjunkie/kcap)
* This program simply uses screen captures and programmatically generated key and mouse events to locally and graphically man-in-the-middle an OS X password prompt to escalate privileges.

[Decrypting IIS Passwords to Break Out of the DMZ: Part 1 ](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/)
* [Decrypting IIS Passwords to Break Out of the DMZ: Part 2](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/)

[Whitelist Evasion revisited](https://khr0x40sh.wordpress.com/2015/05/27/whitelist-evasion-revisited/)

[Evading Autoruns Kyle Hanslovan Chris Bisnett - DerbyCon 7](https://www.youtube.com/watch?v=AEmuhCwFL5I&app=desktop)

[Untethered initroot (USENIX WOOT '17)](https://alephsecurity.com/2017/08/30/untethered-initroot/)












------------
## Programming:
[Phan](https://github.com/phan/phan)
* Phan is a static analyzer for PHP. Phan prefers to avoid false-positives and attempts to prove incorrectness rather than correctness.

[Book of the Runtime (BOTR) for the .NET Runtime](https://github.com/dotnet/coreclr/tree/master/Documentation/botr)
* This contains a collection of articles about the non-trivial internals of the .NET Runtime. Its intended audience are people actually modifying the code or simply wishing to have a deep understanding of the runtime.

[plog](https://github.com/SergiusTheBest/plog)
* Portable, simple and extensible C++ logging library

[SafeSQL](https://github.com/stripe/safesql)
* SafeSQL is a static analysis tool for Go that protects against SQL injections.

[GAS - Go AST Scanner](https://github.com/GoASTScanner/gas)
* Inspects source code for security problems by scanning the Go AST.

[Reference — What does this symbol mean in PHP?](https://stackoverflow.com/questions/3737139/reference-what-does-this-symbol-mean-in-php	)




------------
## Policy and Compliance



------------
## RE

[reductio [ad absurdum]](https://github.com/xoreaxeaxeax/reductio)
* an exploration of code homeomorphism: all programs can be reduced to the same instruction stream.

[REpsych - Psychological Warfare in Reverse Engineering](https://github.com/xoreaxeaxeax/REpsych/blob/master/README.md)
* The REpsych toolset is a proof-of-concept illustrating the generation of images through a program's control flow graph (CFG).

[The “Ultimate”Anti-Debugging Reference - Peter Ferrie 2011/4](http://pferrie.host22.com/papers/antidebug.pdf)

[IDAPython Embedded Toolkit](https://github.com/maddiestone/IDAPythonEmbeddedToolkit)
* IDAPython is a way to script different actions in the IDA Pro disassembler with Python. This repository of scripts automates many different processes necessary when analyzing the firmware running on microcontroller and microprocessor CPUs. The scripts are written to be easily modified to run on a variety of architectures. Read the instructions in the header of each script to determine what ought to be modified for each architecture.

[HexRaysCodeXplorer](https://github.com/REhints/HexRaysCodeXplorer)
* The Hex-Rays Decompiler plugin for better code navigation in RE process. CodeXplorer automates code REconstruction of C++ applications or modern malware like Stuxnet, Flame, Equation, Animal Farm ... :octocat:

[PulseDBG](https://github.com/honorarybot/PulseDBG)
* Hypervisor-based debugger

[Screwdriving. Locating and exploiting smart adult toys](https://www.pentestpartners.com/security-blog/screwdriving-locating-and-exploiting-smart-adult-toys/)

[pegasus - Windbg extension DLL for emulation](https://github.com/0a777h/pegasus)
* Windbg emulation plugin 
[Lighthouse - Code Coverage Explorer for IDA Pro](https://github.com/gaasedelen/lighthouse)
* Lighthouse is a code coverage plugin for IDA Pro. The plugin leverages IDA as a platform to map, explore, and visualize externally collected code coverage data when symbols or source may not be available for a given binary.





------------
## Red Team/Pentesting


[Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)

[Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.





------------
## Rootkits

[DragonKing Rootkit](https://github.com/mgrube/DragonKing)
* This is an open source rootkit created for a class taught on Rootkit Design. This rootkit hides by hooking the system call table and using an agent to do interactive manipulation in userland.

[GPU rootkit PoC by Team Jellyfish](https://github.com/x0r1/jellyfish)


------------
## SCADA









------------
## Social Engineering




------------
## System Internals



[windows-syscall-table](https://github.com/tinysec/windows-syscall-table)
* windows syscall table from xp ~ 10 rs2

[Debugging Functions - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679303.aspx)



------------
## Threat Modeling & Analysis




------------
## Threat Hunting



------------
## Web: 

[Postman - chrome plugin](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop)

[Discover DevTools](https://www.codeschool.com/courses/discover-devtools)
* Learn how Chrome DevTools can sharpen your dev process and discover the tools that can optimize your workflow and make life easier.

[Pwning OWASP Juice Shop](https://leanpub.com/juice-shop)

[Exploiting CVE-2017-8759: SOAP WSDL Parser Code Injection](https://www.mdsec.co.uk/2017/09/exploiting-cve-2017-8759-soap-wsdl-parser-code-injection/)


[Is PHP unserialize() exploitable without any 'interesting' methods? - StackOverflow](https://security.stackexchange.com/questions/77549/is-php-unserialize-exploitable-without-any-interesting-methods)


[Remote code execution via PHP [Unserialize] - notsosecure](https://www.notsosecure.com/remote-code-execution-via-php-unserialize/)

[PHP Magic Tricks: Type Juggling](https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf)

[Browser Security Whitepaper - Cure53](https://cure53.de/browser-security-whitepaper.pdf/)

[OWASP Proactive Controls 3.0](https://docs.google.com/document/d/1bQKisfXQ2XRwkcUaTvVTR7bpzVgbwIhDA1O6hUbywiY/mobilebasic)

[Going AUTH the Rails on a Crazy Train: A Dive into Rails Authentication and Authorization](https://www.blackhat.com/docs/eu-15/materials/eu-15-Jarmoc-Going-AUTH-The-Rails-On-A-Crazy-Train-wp.pdf)

[Executing commands in ruby](http://blog.bigbinary.com/2012/10/18/backtick-system-exec-in-ruby.html)


[Attacking Ruby on Rails Applications](http://phrack.org/issues/69/12.html#article)

[OpenDoor](https://github.com/stanislav-web/OpenDoor)
* OpenDoor OWASP is console multifunctional web sites scanner. This application find all possible ways to login, index of/ directories, web shells, restricted access points, subdomains, hidden data and large backups. The scanning is performed by the built-in dictionary and external dictionaries as well. Anonymity and speed are provided by means of using proxy servers.


[PHP Autoload Invalid Classname Injection](https://hakre.wordpress.com/2013/02/10/php-autoload-invalid-classname-injection/)

[Writing Exploits For Exotic Bug Classes: PHP Type Juggling](https://turbochaos.blogspot.com.au/2013/08/exploiting-exotic-bugs-php-type-juggling.html)

[PHP’s “Magic Hash” Vulnerability (Or Beware Of Type Juggling)](https://web.archive.org/web/20150530075600/http://blog.astrumfutura.com/2015/05/phps-magic-hash-vulnerability-or-beware-of-type-juggling)

[Writing Exploits For Exotic Bug Classes: unserialize()](https://www.alertlogic.com/blog/writing-exploits-for-exotic-bug-classes-unserialize()/)

[Bucketlist](https://github.com/michenriksen/bucketlist)
* Bucketlist is a quick project I threw together to find and crawl Amazon S3 buckets and put all the data into a PostgreSQL database for querying.

[Gone in 60 Milliseconds - Intrusion and Exfiltration in Server-less Architectures](https://media.ccc.de/v/33c3-7865-gone_in_60_milliseconds)
* More and more businesses are moving away from monolithic servers and turning to event-driven microservices powered by cloud function providers like AWS Lambda. So, how do we hack in to a server that only exists for 60 milliseconds? This talk will show novel attack vectors using cloud event sources, exploitabilities in common server-less patterns and frameworks, abuse of undocumented features in AWS Lambda for persistent malware injection, identifying valuable targets for pilfering, and, of course, how to exfiltrate juicy data out of a secure Virtual Private Cloud. 

[restclient - Firefox addon](https://addons.mozilla.org/de/firefox/addon/restclient/)





------------
## Wireless Stuff


[SniffAir](https://github.com/Tylous/SniffAir)

[CC1101-FSK](https://github.com/trishmapow/CC1101-FSK)
* Jam and replay attack on vehicle keyless entry systems.

[RTL-SDR and GNU Radio with Realtek RTL2832U [Elonics E4000/Raphael Micro R820T] software defined radio receivers.](http://superkuh.com/rtlsdr.html)

[nrsc5](https://github.com/theori-io/nrsc5)
* NRSC-5 receiver for rtl-sdr

[gr-nrsc5](https://github.com/argilo/gr-nrsc5)
* A GNU Radio implementation of HD Radio (NRSC-5)

[blueborne](https://www.armis.com/blueborne/)

[SniffAir An Open Source Framework for Wireless Security Assessments Matthew Eidelberg - DerbyCon7](https://www.youtube.com/watch?v=QxVkr-3RK94&app=desktop)