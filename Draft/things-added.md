-------------
### ATT&CK

* Updated Contents of each section
* [Adversary Emulation Plans](https://attack.mitre.org/wiki/Adversary_Emulation_Plans)
	* To showcase the practical use of ATT&CK for offensive operators and defenders, MITRE created Adversary Emulation Plans. These are prototype documents of what can be done with publicly available threat reports and ATT&CK. The purpose of this activity is to allow defenders to more effectively test their networks and defenses by enabling red teams to more actively model adversary behavior, as described by ATT&CK. This is part of a larger process to help more effectively test products and environments, as well as create analytics for ATT&CK behaviors rather than detecting a specific indicator of compromise (IOC) or specific tool.
* Plus other stuff






------------
## Anonymity/OpSec/Privacy


* [Achie­ving an­ony­mi­ty against major face re­co­gni­ti­on al­go­rith­ms -  Be­ne­dikt Dries­sen, Mar­kus Dür­muth](http://www.mobsec.rub.de/forschung/veroeffentlichungen/driessen-13-face-rec/)
* [Com­pro­mi­sing Re­flec­tions - or - How to Read LCD Mo­ni­tors Around the Cor­ner- Micha­el Ba­ckes, Mar­kus Dür­muth, Do­mi­ni­que Unruh](https://kodu.ut.ee/~unruh/publications/reflections.pdf)
	* We present a novel eavesdropping technique for spying at a distance on data that is displayed on an arbitrary computer screen, including the currently prevalent LCD monitors. Our technique exploits reflections of the screen’s optical emanations in various objects that one commonly finds in close proximity to the screen and uses those reflections to recover the original screen content. Such objects include eyeglasses, tea pots, spoons, plastic bottles,  and even the eye of the user. We have demonstrated that this attack can be successfully mounted to spy on even small fonts using inexpensive, off-the-shelf equipment (less than 1500 dollars) from a distance of up to 10 meters. Relying on more expensive equipment allowed us to conduct this attack from over 30 meters away, demonstrating that similar at- tacks are feasible from the other side of the street or from a close-by building. We additionally establish theoretical limitations of the attack; these limitations may help to estimate the risk that this attack can be successfully mounted in a given environment.
* [Acoustic Side-Channel Attacks on Printers -Michael Backes,Markus Drmuth,Sebastian Gerling,Manfred Pinkal,Caroline Sporleder](http://www.usenix.net/legacy/events/sec10/tech/full_papers/Backes.pdf)
	* We examine the problem of acoustic emanations of printers. We present a novel attack that recovers what a dot- matrix printer processing English text is printing based on a record of the sound it makes, if the microphone is close enough to the printer. In our experiments, the attack recovers up to 72% of printed  words, and up to 95% if we assume contextual knowledge about the text, with a microphone at a distance of 10 cm from the printer. After an upfront training phase, the attack is fully automated and uses a combination of machine learning, audio processing, and speech recognition techniques, including spectrum features, Hidden Markov Models and linear classification; moreover, it allows for feedback-based incremental learning. We evaluate the effectiveness of countermeasures, and we describe how we successfully mounted the attack in-field (with appropriate privacy protections) in a doctor’s practice to recover the content of medical prescriptions.
* https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-guri-update.pdf
* [Tempest in a Teapot: Compromising Reflections Revisited](http://www.mia.uni-saarland.de/Publications/backes-sp09.pdf)
	* Reflecting objects such as tea pots and glasses, but also diffusely reflecting objects such as a user’s shirt, can be used to spy on confidential data displayed on a monitor. First, we show how reflections in the user’s eye can be exploited for spying  on  confidential data. Second, we investigate to what extent monitor images can be reconstructed from the diffuse reflections on a wall or the user’s clothes, and provide information- theoretic bounds limiting this type of attack. Third, we evaluate the effectiveness of several countermeasures.
* [Speaker Recognition in Encrypted Voice Streams - Michael Backes,Goran Doychev,Markus Durmuth,Boris Kopf](http://software.imdea.org/~gdoychev/publications/esorics10.pdf)
	* We develop a novel approach for unveiling the identity of speakers who participate in encrypted voice communication, solely by eavesdropping on the encrypted traffic. Our approach exploits the concept of voice activity detection (VAD), a widely used technique for reducing the bandwidth consumption of voice traffic. We show that the reduction of traffic caused by VAD techniques creates patterns in the encrypted traffic, which in turn reveal the patterns of pauses in the underlying voice stream. We show that these patterns are speaker-characteristic, and that they are sufficient to undermine the anonymity of the speaker in encrypted voice communication. In an empirical setup with 20 speakers our analysis is able to correctly identify an unknown speaker in about 48% of all cases. Our work extends and generalizes existing work that exploits variable bit-rate encoding for identifying the conversation language and content of encrypted voice streams)








------------
## Basic Security Info



------------
## BIOS/UEFI/Firmware/Low Level Attacks

------------
## Building a Lab 

* [Down by the Docker](https://www.notsosecure.com/vulnerable-docker-vm/)
	* Ever fantasized about playing with docker misconfigurations, privilege escalation, etc. within a container? Download this VM, pull out your pentest hats and get started 


















------------
## Car Hacking


------------
## Cheat Sheets


[HTML5 Security Cheatsheet](https://github.com/jshaw87/Cheatsheets)







------------
## Conferences







------------
## Courses

* [cs-video-courses](https://github.com/Developer-Y/cs-video-courses)
	* List of Computer Science courses with video lectures.
* [Network Examples - knorrie](https://github.com/knorrie/network-examples)
	* Linux networking examples and tutorials
* [Low-Level Programming University](https://github.com/gurugio/lowlevelprogramming-university)
	* This page is for beginners who want to be low-level programmers. I'm inspired by [google-interview-university](https://github.com/jwasham/google-interview-university). I'd like to share my experience and show a roadmap to becoming a low-level programmer because I have found that these skills are not as common as they once were. In addition, many students and beginners ask me how they could become low-level programmers and Linux kernel engineers.




------------
## CTF
* [Flawed Fortress](https://github.com/rgajendran/ctf_marker)
	* Flawed Fortress is a front end platform for hosting Capture the Flag Event (CTF), it is programmed with PHP, JQuery, JavaScript and phpMyAdmin. Currently, It is designed to import SecGen CTF challenges using `marker.xml` file (which is generated in the project folder when creating a CTF Challenge)


------------
## Cryptography & Timing Attacks


* [The Problem with Calling Bitcoin a “Ponzi Scheme”](https://prestonbyrne.com/2017/12/08/bitcoin_ponzi/)
* [FeatherDuster](https://github.com/nccgroup/featherduster)
	* FeatherDuster is a tool written by Daniel "unicornfurnace" Crowley of NCC Group for breaking crypto which tries to make the process of identifying and exploiting weak cryptosystems as easy as possible. Cryptanalib is the moving parts behind FeatherDuster, and can be used independently of FeatherDuster.
* [Padding Oracle Exploit API](https://mwielgoszewski.github.io/python-paddingoracle/)
	* [tool](https://github.com/mwielgoszewski/python-paddingoracle)
	* python-paddingoracle is an API that provides pentesters a customizable alternative to PadBuster and other padding oracle exploit tools that can't easily (without a heavy rewrite) be used in unique, per-app scenarios. Think non-HTTP applications, raw sockets, client applications, unique encodings, etc.
* [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker)
	* TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is able to send arbitrary protocol messages in an arbitrary order to the TLS peer, and define their modifications using a provided interface. This gives the developer an opportunity to easily define a custom TLS protocol flow and test it against his TLS library.
* [PadBuster](https://github.com/GDSSecurity/PadBuster)
	* PadBuster is a Perl script for automating Padding Oracle Attacks. PadBuster provides the capability to decrypt arbitrary ciphertext, encrypt arbitrary plaintext, and perform automated response analysis to determine whether a request is vulnerable to padding oracle attacks.
* [xortool](https://github.com/hellman/xortool)
	* A tool to analyze multi-byte xor cipher
* [Project Wycheproof](https://github.com/google/wycheproof)
	* Project Wycheproof tests crypto libraries against known attacks. It is developed and maintained by members of Google Security Team, but it is not an official Google product.
* [Hash-Algorithm-Identifier](https://github.com/AnimeshShaw/Hash-Algorithm-Identifier)
	* A python tool to identify different Hash Function Algorithms. Supports 160+ Hash Algorithms.
* [HashPump](https://github.com/bwall/HashPump)
	* A tool to exploit the hash length extension attack in various hashing algorithms. Currently supported algorithms: MD5, SHA1, SHA256, SHA512.



* [Price Manipulation in the Bitcoin Ecosystem](https://www.sciencedirect.com/science/article/pii/S0304393217301666?via%3Dihub)
* [Meet ‘Spoofy’. How a Single entity dominates the price of Bitcoin.](https://hackernoon.com/meet-spoofy-how-a-single-entity-dominates-the-price-of-bitcoin-39c711d28eb4)
* [The Willy Report: proof of massive fraudulent trading activity at Mt. Gox, and how it has affected the price of Bitcoin](https://willyreport.wordpress.com/2014/05/25/the-willy-report-proof-of-massive-fraudulent-trading-activity-at-mt-gox-and-how-it-has-affected-the-price-of-bitcoin/)






-------------
## Darknets





------------
## Data Analysis/Visualization





-----------------
## Defense

* [SAMRi10 - Hardening SAM Remote Access in Windows 10/Server 2016](https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b#content)
	* "SAMRi10" tool is a short PowerShell (PS) script which alters remote SAM access default permissions on Windows 10 & Windows Server 2016. This hardening process prevents attackers from easily getting some valuable recon information to move laterally within their victim's network.
* [ssh-audit](https://github.com/arthepsy/ssh-audit)
	* SSH server auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)
* [Artillery](https://github.com/BinaryDefense/artillery)
	* Artillery is a combination of a honeypot, monitoring tool, and alerting system. Eventually this will evolve into a hardening monitoring platform as well to detect insecure configurations from nix systems.
* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
	* A collection of tools to enumerate and analyse Windows DACLs
* [Harden Windows with AppLocker – based on Case study Part 1 - oddvar.moe](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
* [Harden Windows with AppLocker – based on Case study part 2 - oddvar.moe](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
* [simplewall](https://github.com/henrypp/simplewall)
	* Simple tool to configure Windows Filtering Platform (WFP) which can configure network activity on your computer. The lightweight application is less than a megabyte, and it is compatible with Windows Vista and higher operating systems. You can download either the installer or portable version. For correct working, need administrator rights.
* [Secure-Host-Baseline](https://github.com/iadgov/Secure-Host-Baseline)
	* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
* [KB2871997 and Wdigest – Part 1](https://blogs.technet.microsoft.com/kfalde/2014/11/01/kb2871997-and-wdigest-part-1/)





------------
## Design




------------
## Documentation






------------
## Disclosure



------------
## Drones




------------
## Documentation/Technical writing




------------
## Embedded Devices/Hardware (Including Printers & PoS & IoS)


* [A Survey of Various Methods for Analyzing the Amazon Echo](https://vanderpot.com/Clinton_Cook_Paper.pdf)
* [Firmwalker](https://github.com/craigz28/firmwalker
	* A simple bash script for searching the extracted or mounted firmware file system. It will search through the extracted or mounted firmware file system for things of interest
* [Remote Code Execution on the Smiths Medical Medfusion 4000](https://raw.githubusercontent.com/sgayou/medfusion-4000-research/master/doc/README.md)
* [Attacking secure USB keys, behind the scene](https://www.j-michel.org/blog/2018/01/16/attacking-secure-usb-keys-behind-the-scene)
* [Attacking encrypted USB keys the hard(ware) way - Jean-Michel Picod, Rémi Audebert, Elie Bursztein -BHUSA 17](https://elie.net/talk/attacking-encrypted-usb-keys-the-hardware-way)
	* In this talk, we will present our methodology to assess "secure" USB devices both from the software and the hardware perspectives. We will demonstrate how this methodology works in practice via a set of case-studies. We will demonstrate some of the practical attacks we found during our audit so you will learn what type of vulnerability to look for and how to exploit them. Armed with this knowledge and our tools, you will be able to evaluate the security of the USB device of your choice.







------------
## Exfiltration

* [Data Exfil Toolkit](https://github.com/conix-security/DET)
	* DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. The idea was to create a generic toolkit to plug any kind of protocol/service.
* [PyExfil](https://github.com/ytisf/PyExfil)
	* This started as a PoC project but has later turned into something a bit more. Currently it's an Alpha-Alpha stage package, not yet tested (and will appriciate any feedbacks and commits) designed to show several techniques of data exfiltration is real world scenarios.
* [pingfs - "True cloud storage" - Erin Ekman](https://github.com/yarrick/pingfs)
	*  pingfs is a filesystem where the data is stored only in the Internet itself, as ICMP Echo packets (pings) travelling from you to remote servers and back again. It is implemented using raw sockets and FUSE, so superuser powers are required. Linux is the only intended target OS, portability is not a goal. Both IPv4 and IPv6 remote hosts are supported.
* [Egress-Assess](https://github.com/ChrisTruncer/Egress-Assess)
	* Egress-Assess is a tool used to test egress data detection capabilities.
	* [Egress-Assess – Testing your Egress Data Detection Capabilities](https://www.christophertruncer.com/egress-assess-testing-egress-data-detection-capabilities/)
	* [Egress-Assess in Action via Powershell](https://www.christophertruncer.com/egress-assess-action-via-powershell/)
* [QRXfer](https://github.com/leonjza/qrxfer)
	* Transfer files from Air gapped machines using QR codes








------------
## Exploit Dev

* [Linux Kernel Exploitation Paper Archive - xairy](https://github.com/xairy/linux-kernel-exploitation)
* [Vivisect](https://github.com/vivisect/vivisect)
	* Fairly un-documented static analysis / emulation / symbolic analysis framework for PE/Elf/Mach-O/Blob binary formats on various architectures.
* [Dr. Memory](https://github.com/DynamoRIO/drmemory)
	* Dr. Memory is a memory monitoring tool capable of identifying memory-related programming errors such as accesses of uninitialized memory, accesses to unaddressable memory (including outside of allocated heap units and heap underflow and overflow), accesses to freed memory, double frees, memory leaks, and (on Windows) handle leaks, GDI API usage errors, and accesses to un-reserved thread local storage slots. Dr. Memory operates on unmodified application binaries running on Windows, Linux, Mac, or Android on commodity IA-32, AMD64, and ARM hardware.
* [The Exploit Database Git Repository](https://github.com/offensive-security/exploit-database)
	* The official Exploit Database repository
* [GDB 'exploitable' plugin](https://github.com/jfoote/exploitable)
	* 'exploitable' is a GDB extension that classifies Linux application bugs by severity. The extension inspects the state of a Linux application that has crashed and outputs a summary of how difficult it might be for an attacker to exploit the underlying software bug to gain control of the system. The extension can be used to prioritize bugs for software developers so that they can address the most severe ones first. The extension implements a GDB command called 'exploitable'. The command uses heuristics to describe the exploitability of the state of the application that is currently being debugged in GDB. The command is designed to be used on Linux platforms and versions of GDB that include the GDB Python API. Note that the command will not operate correctly on core file targets at this time.
* [ropa](https://github.com/orppra/ropa)
	* ropa is a Ropper-based GUI that streamlines crafting ROP chains. It provides a cleaner interface when using Ropper as compared to the command line. It can provide a smoother workflow for crafting the rop chain in the GUI, then exporting the final chain in the desired format. For those used to using CLI, this tool may serve as a cleaner interface to filter out the relevant gadgets.
* [Epson Vulnerability: EasyMP Projector Takeover (CVE-2017-12860 / CVE-2017-12861)](https://rhinosecuritylabs.com/research/epson-easymp-remote-projection-vulnerabilities/)
* [Code Execution (CVE-2018-5189) Walkthrough On JUNGO Windriver 12.5.1](https://www.fidusinfosec.com/jungo-windriver-code-execution-cve-2018-5189)
* [Automating VMware RPC Request Sniffing - Abdul-Aziz Hariri - ZDI](https://www.zerodayinitiative.com/blog/2018/1/19/automating-vmware-rpc-request-sniffing)
	* In this blog, I will discuss how I was able to write a PyKD script to sniff RPC requests that helped me tremendously while writing VMware RPC exploits.
* [Linux Heap Exploitation Intro Series – (BONUS) printf might be leaking!](https://sensepost.com/blog/2018/linux-heap-exploitation-intro-series-bonus-printf-might-be-leaking/)
* [Linux Heap Exploitation Intro Series: Riding free on the heap – Double free attacks!](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-riding-free-on-the-heap-double-free-attacks/)
* [ Use-After-Silence: Exploiting a quietly patched UAF in VMware - Abdul-Aziz Hariri](https://www.thezdi.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware)
* [Android Security Ecosystem Investments Pay Dividends for Pixel](https://android-developers.googleblog.com/2018/01/android-security-ecosystem-investments.html)
* [Adobe Reader Escape... or how to steal research and be lame.](http://sandboxescaper.blogspot.be/2018/01/adobe-reader-escape-or-how-to-steal.html)
* [Cisco IOS MIPS GDB remote serial protocol implementation](https://github.com/artkond/ios_mips_gdb)
	* A hacky implementation of GDB RSP to aid exploit development for MIPS based Cisco routers



------------
## Forensics

* [Transport Neutral Encapsulation Format - Wikipedia](https://en.wikipedia.org/wiki/Transport_Neutral_Encapsulation_Format)
* [Analyzing TNEF files](https://isc.sans.edu/diary/rss/23175)

* [VolUtility](https://github.com/kevthehermit/VolUtility)
	* Web Interface for Volatility Memory Analysis framework

------------
## Fuzzing/Bug Hunting

* [FuzzManager](https://github.com/MozillaSecurity/FuzzManager)
	* With this project, we aim to create a management toolchain for fuzzing. Unlike other toolchains and frameworks, we want to be modular in such a way that you can use those parts of FuzzManager that seem interesting to you without forcing a process upon you that does not fit your requirements.
* [COMRaider](http://sandsprite.com/iDef/COMRaider/)
	* ActiveX Fuzzing tool with GUI, object browser, system scanner, and distributed auditing capabilities
	* [Github](https://github.com/dzzie/COMRaider)
* [Fuzzing TCP servers - Robert Swiecki](http://blog.swiecki.net/2018/01/fuzzing-tcp-servers.html)



------------
## Game Hacking

* [awesome-gbdev](https://github.com/avivace/awesome-gbdev)
	* A curated list of Game Boy development resources such as tools, docs, emulators, related projects and open-source ROMs.
* [FuckBattlEye](https://github.com/G-E-N-E-S-I-S/FuckBattlEye)
	* Bypassing kernelmode anticheats via handle inheritance (across sections)

------------
## Honeypots


------------
## ICS/SCADA


------------
## Interesting Things/Miscellaneous

* ["I want my money back!" Li­mi­t­ing On­line Pass­word-Gues­sing Fi­nan­ci­al­ly -Ma­xi­mi­li­an Golla, Da­ni­el V. Bai­ley, Mar­kus Dür­muth](http://www.mobsec.rub.de/forschung/veroeffentlichungen/limiting-online-password-guessing-financially/)
	* In this work-in-pro­gress re­port, we pro­po­se an opt-in de­po­sit-ba­sed ap­proach to ra­te-li­mi­t­ing that tack­les on­line gues­sing at­tacks. By de­man­ding a small de­po­sit for each login at­tempt, which is im­me­dia­te­ly re­fun­ded after a suc­cess­ful sign in, on­line gues­sing at­ta­ckers face high costs for re­pea­ted un­suc­cess­ful log­ins. We pro­vi­de an in­iti­al ana­ly­sis of sui­ta­ble pay­ment sys­tems and re­a­sonable de­po­sit va­lues for re­al-world im­ple­men­ta­ti­ons and di­s­cuss se­cu­ri­ty and usa­bi­li­ty im­pli­ca­ti­ons of the sys­tem.
* [Emo­ji­Auth: Quan­ti­fy­ing the Se­cu­ri­ty of Emo­ji-ba­sed Au­then­ti­ca­ti­on -  Ma­xi­mi­li­an Golla, Den­nis De­te­ring, Mar­kus Dür­muth](http://www.mobsec.rub.de/forschung/veroeffentlichungen/quantifying-security-emoji-based-authentication/)
	* Mo­bi­le de­vices, such as smart­pho­nes and ta­blets, fre­quent­ly store con­fi­den­ti­al data, yet im­ple­men­ting a se­cu­re de­vice un­lock func­tio­na­li­ty is non-tri­vi­al due to re­stric­ted input me­thods. Gra­phi­cal know­ledge-ba­sed sche­mes have been wi­de­ly used on smart­pho­nes and are ge­ne­ral­ly well ad­ap­ted to the touch­screen in­ter­face on small screens. Re­cent­ly, gra­phi­cal pass­word sche­mes based on emoji have been pro­po­sed. They offer po­ten­ti­al be­ne­fits due to the fa­mi­li­a­ri­ty of users with emoji and the ease of ex­pres­sing me­mo­ra­ble sto­ries. Howe­ver, it is well-known from other gra­phi­cal sche­mes that user-selec­ted au­then­ti­ca­ti­on secrets can sub­stan­ti­al­ly limit the re­sul­ting en­tro­py of the au­then­ti­ca­ti­on secret. In this work, we study the en­tro­py of user-selec­ted secrets for one ex­em­pla­ry in­stan­tia­ti­on of emo­ji-ba­sed au­then­ti­ca­ti­on. We ana­ly­zed an im­ple­men­ta­ti­on using 20 emoji dis­play­ed in ran­dom order on a grid, where a user selects pass­codes of length 4 wi­thout fur­ther re­stric­tions. We con­duc­ted an on­line user study with 795 par­ti­ci­pants, using the collec­ted pass­codes to de­ter­mi­ne the re­sis­tan­ce to gues­sing based on se­ver­al gues­sing stra­te­gies, thus esti­ma­ting the selec­tion bias. We eva­lua­ted Mar­kov mo­del-ba­sed gues­sing stra­te­gies based on the selec­ted se­quence of emoji, on its po­si­ti­on in the grid, and com­bined mo­dels ta­king into ac­count both fea­tures. While we find selec­tion bias based on both the emoji as well as the po­si­ti­on, the me­a­su­red bias is lower than for si­mi­lar sche­mes. De­pen­ding on the model, we can re­co­ver up to 7% at 100 gues­sing at­tempts, and up to 11% of the pass­codes at 1000 gues­sing at­tempts. (For com­pa­ri­son, pre­vious work on the gra­phi­cal An­dro­id Un­lock pat­tern sche­me (CCS 2013) re­co­ver­ed around 18% at 100 and 50% at 1000 gues­sing at­tempts, de­s­pi­te a theo­re­ti­cal key­space of more than dou­b­le the size for the An­dro­id sche­me.) These re­sults de­mons­tra­te some po­ten­ti­al for a usa­ble and re­la­tive­ly se­cu­re sche­me and show that the size of the theo­re­ti­cal key­space is a bad pre­dic­tor for the rea­lis­tic guessa­bi­li­ty of pass­codes.

------------
## Lockpicking





------------
## Malware

* [Daily dose of malware](https://github.com/woj-ciech/Daily-dose-of-malware)
	* Script lets you gather malicious software and c&c servers from open source platforms like Malshare, Malcode, Google, Cymon - vxvault, cybercrime tracker and c2 for Pony.
* [Detux: The Multiplatform Linux Sandbox](https://github.com/detuxsandbox/detux)
	* Detux is a sandbox developed to do traffic analysis of the Linux malwares and capture the IOCs by doing so. QEMU hypervisor is used to emulate Linux (Debian) for various CPU architectures.
* [WDBGARK](https://github.com/swwwolf/wdbgark)
	* WDBGARK is an extension (dynamic library) for the Microsoft Debugging Tools for Windows. It main purpose is to view and analyze anomalies in Windows kernel using kernel debugger. It is possible to view various system callbacks, system tables, object types and so on. For more user-friendly view extension uses DML. For the most of commands kernel-mode connection is required. Feel free to use extension with live kernel-mode debugging or with kernel-mode crash dump analysis (some commands will not work). Public symbols are required, so use them, force to reload them, ignore checksum problems, prepare them before analysis and you'll be happy.






------------
## Mainframes






------------
## Network Scanning and Attacks

* [SIET Smart Install Exploitation Toolkit](https://github.com/Sab0tag3d/SIET)
	* Cisco Smart Install is a plug-and-play configuration and image-management feature that provides zero-touch deployment for new switches. You can ship a switch to a location, place it in the network and power it on with no configuration required on the device.
* [IKEForce]()
	* IKEForce is a command line IPSEC VPN brute forcing tool for Linux that allows group name/ID enumeration and XAUTH brute forcing capabilities.
	* [Cracking IKE Mission:Improbable (Part 1)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part-1)/)
	* [Cracking IKE Mission:Improbable (Part 2) ](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part-2)/)
	* [Cracking IKE Mission:Improbable (Part3) ](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part3)/)
* [nmapdb - Parse nmap's XML output files and insert them into an SQLite database](https://census.gr/research/sw/nmapdb/)
* [NmapDB](https://github.com/mainframed/nmapdb)
	* nmapdb parses nmap's XML output files and inserts them into an SQLite database.
* [MassDNS](https://github.com/blechschmidt/massdns)
	* MassDNS is a simple high-performance DNS stub resolver targetting those who seek to resolve a massive amount of domain names in the order of millions or even billions. Without special configuration, MassDNS is capable of resolving over 350,000 names per second using publicly available resolvers.
* [bettercap](https://github.com/evilsocket/bettercap) 
	* A complete, modular, portable and easily extensible MITM framework. 
* [Fingerprinter](https://github.com/erwanlr/Fingerprinter)
	*  CMS/LMS/Library etc Versions Fingerprinter. This script's goal is to try to find the version of the remote application/third party script etc by using a fingerprinting approach.
* [NetRipper](https://github.com/NytroRST/NetRipper)
	* NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.
* [Where are my hashes? (Responder Observations) - markclayton](https://markclayton.github.io/where-are-my-hashes-responder-observations.html)




------------
## Network/Endpoint Monitoring & Logging & Threat Hunting

* [Yeti](https://github.com/yeti-platform/yeti)
	* Yeti is a platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository. Yeti will also automatically enrich observables (e.g. resolve domains, geolocate IPs) so that you don't have to. Yeti provides an interface for humans (shiny Bootstrap-based UI) and one for machines (web API) so that your other tools can talk nicely to it.
* [HELK - The Hunting ELK](https://github.com/Cyb3rWard0g/HELK)
	* A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.
* [DNSpop](https://github.com/bitquark/dnspop) 
* Tools to find popular trends by analysis of DNS data. For more information, see my [blog post](https://bitquark.co.uk/blog/2016/02/29/the_most_popular_subdomains_on_the_internet) on the most popular subdomains on the internet. Hit the results directory to get straight to the data.



------------
## OSINT

* [gitdigger](https://github.com/wick2o/gitDigger)
	* gitDigger: Creating realworld wordlists from github hosted data.
* [gitrob](https://github.com/michenriksen/gitrob)
	* Gitrob is a command line tool which can help organizations and security professionals find sensitive information lingering in publicly available files on GitHub. The tool will iterate over all public organization and member repositories and match filenames against a range of patterns for files that typically contain sensitive or dangerous information. Looking for sensitive information in GitHub repositories is not a new thing, it has been [known for a while](http://blog.conviso.com.br/2013/06/github-hacking-for-fun-and-sensitive.html) that things such as private keys and credentials can be found with GitHub's search functionality, however Gitrob makes it easier to focus the effort on a specific organization.
* [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage)
	* Pillage web accessible GIT, HG and BZR repositories. I thought it would be useful to automate some other techniques I found to extract code, configs and other information from a git,hg, and bzr repo's identified in a web root that was not 100% cloneable. Each script extracts as much knowledge about the repo as possible through predictable file names and known object hashes, etc.
* [OSRFramework](https://github.com/i3visio/osrframework)
	* OSRFramework is a GNU AGPLv3+ set of libraries developed by i3visio to perform Open Source Intelligence tasks. They include references to a bunch of different applications related to username checking, DNS lookups, information leaks research, deep web search, regular expressions extraction and many others. At the same time, by means of ad-hoc Maltego transforms, OSRFramework provides a way of making these queries graphically as well as several interfaces to interact with like OSRFConsole or a Web interface.
* [OSINT: Advanced tinder capture](https://www.learnallthethings.net/osmosis)
* [The Secrets of LinkedIn](https://webbreacher.com/2017/01/14/the-secrets-of-linkedin/)
	* Grabbing usernames/connections(link analysis)
* [pymk-inspector](https://github.com/GMG-Special-Projects-Desk/pymk-inspector/blob/master/README.md)
	* The pymk-inspector is a tool built by Gizmodo's Special Projects Desk that we used for our investigation into Facebook's people you may know (pymk) algorithm.





------------
##	OS X






------------
## Passwords

* [OMEN: Ordered Markov ENumerator](https://github.com/RUB-SysSec/OMEN)
	* OMEN is a Markov model-based password guesser written in C. It generates password candidates according to their occurrence probabilities, i.e., it outputs most likely passwords first. OMEN significantly improves guessing speed over existing proposals. If you are interested in the details on how OMEN improves on existing Markov model-based password guessing approaches, please refer to OMEN: Faster Password Guessing Using an Ordered Markov Enumerator.
* [cupp.py - Common User Passwords Profiler](https://github.com/Mebus/cupp)
	* The most common form of authentication is the combination of a username and a password or passphrase. If both match values stored within a locally stored table, the user is authenticated for a connection. Password strength is a measure of the difficulty involved in guessing or breaking the password through cryptographic techniques or library-based automated testing of alternate values. A weak password might be very short or only use alphanumberic characters, making decryption simple. A weak password can also be one that is easily guessed by someone profiling the user, such as a birthday, nickname, address, name of a pet or relative, or a common word such as God, love, money or password. That is why CUPP has born, and it can be used in situations like legal penetration tests or forensic crime investigations.
* [When Privacy meets Security: Leveraging personal information for password cracking - M. Dürmuth,A. ChaabaneD. Perito,C. Castelluccia]()
	* Passwords are widely used for user authentication and, de- spite their weaknesses, will likely remain in use in the fore seeable future. Human-generated passwords typically have a rich structure , which makes them susceptible to guessing attacks. In this paper, we stud y the effectiveness of guessing attacks based on Markov models. Our contrib utions are two-fold. First, we propose a novel password cracker based o n Markov models, which builds upon and extends ideas used by Narayana n and Shmatikov (CCS 2005). In extensive experiments we show that it can crack up to 69% of passwords at 10 billion guesses, more than a ll probabilistic password crackers we compared against. Second, we systematically analyze the idea that additional personal informatio n about a user helps in speeding up password guessing. We find that, on avera ge and by carefully choosing parameters, we can guess up to 5% more pas swords, especially when the number of attempts is low. Furthermore, we show that the gain can go up to 30% for passwords that are actually b ased on personal attributes. These passwords are clearly weaker an d should be avoided. Our cracker could be used by an organization to detect and reject them. To the best of our knowledge, we are the first to syst ematically study the relationship between chosen passwords and users’ personal in- formation. We test and validate our results over a wide colle ction of leaked password databases.




------------
## Phishing

* [King Phisher](https://github.com/securestate/king-phisher)
	* King Phisher is a tool for testing and promoting user awareness by simulating real world phishing attacks. It features an easy to use, yet very flexible architecture allowing full control over both emails and server content. King Phisher can be used to run campaigns ranging from simple awareness training to more complicated scenarios in which user aware content is served for harvesting credentials.
* [SpeedPhish Framework](https://github.com/tatanus/SPF)
	* SPF (SpeedPhish Framework) is a python tool designed to allow for quick recon and deployment of simple social engineering phishing exercises.
* [CredSniper](https://github.com/ustayready/CredSniper)
	* CredSniper is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens. Easily launch a new phishing site fully presented with SSL and capture credentials along with 2FA tokens using CredSniper. The API provides secure access to the currently captured credentials which can be consumed by other applications using a randomly generated API token.
* [Phishing catcher](https://github.com/x0rz/phishing_catcher)
	* Catching malicious phishing domain names using [certstream](https://certstream.calidog.io/) SSL certificates live stream.
* [Tabnabbing - An art of phishing - securelayer7](http://blog.securelayer7.net/tabnabbing-art-phishing/)
* [Catching phishing before they catch you](https://blog.0day.rocks/catching-phishing-using-certstream-97177f0d499a)
* [Certificate Transparency](https://www.certificate-transparency.org/)
	* [What is Certificate Transparency?](https://www.certificate-transparency.org/what-is-ct)

------------
## Physical Security









------------
## Policy

* [NIST Special Publication 800 -46 Revision 2 - Guide to Enterprise Telework, Remote Access, and Bring Your Own Device (BYOD) Security](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-46r2.pdf)



------------
## Post Exploitation/Privilege Escalation/Pivoting

* [ATA Suspicious Activity Playbook - technet.ms](https://gallery.technet.microsoft.com/ATA-Playbook-ef0a8e38)
* [SessionGopher](https://github.com/fireeye/SessionGopher)
	* SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It has WMI functionality built in so it can be run remotely. Its best use case is to identify systems that may connect to Unix systems, jump boxes, or point-of-sale terminals. SessionGopher works by querying the HKEY_USERS hive for all users who have logged onto a domain-joined box at some point. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. It automatically extracts and decrypts WinSCP, FileZilla, and SuperPuTTY saved passwords. When run in Thorough mode, it also searches all drives for PuTTY private key files (.ppk) and extracts all relevant private key information, including the key itself, as well as for Remote Desktop (.rdp) and RSA (.sdtid) files.
* [LyncSniper](https://github.com/mdsecresearch/LyncSniper)
	* LyncSniper: A tool for penetration testing Skype for Business and Lync deployments
	* [Blogpost](https://www.mdsec.co.uk/2017/04/penetration-testing-skype-for-business-exploiting-the-missing-lync/)
* [LyncSmash](https://github.com/nyxgeek/lyncsmash)
	* a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
	* [Talk](https://www.youtube.com/watch?v=v0NTaCFk6VI)
	* [Slides](https://github.com/nyxgeek/lyncsmash/blob/master/DerbyCon%20Files/TheWeakestLync.pdf)
* [AdEnumerator](https://github.com/chango77747/AdEnumerator)
	* Active Directory enumeration from non-domain system. Powershell script
* [CredNinja](https://github.com/Raikia/CredNinja)
	* A multithreaded tool designed to identify if credentials are valid, invalid, or local admin valid credentials within a network at-scale via SMB, plus now with a user hunter.
* [Kerberom](https://github.com/Fist0urs/kerberom)
	* Kerberom is a tool aimed to retrieve ARC4-HMAC'ed encrypted Tickets Granting Service (TGS) of accounts having a Service Principal Name (SPN) within an Active Directory
* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
	* A collection of tools to enumerate and analyse Windows DACLs
* [How to Accidently Win Against AV - RastaMouse](https://rastamouse.me/2017/07/how-to-accidently-win-against-av/)
* [Windows DLL Injection Basics - OpenSecurityTraining](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html)
* [An Improved Reflective DLL Injection Technique - Dan Staples](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html)
* [Reflective DLL Injection with PowerShell - clymb3r](https://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/)
* [Delivering custom payloads with Metasploit using DLL injection - blog.cobalstrike](https://blog.cobaltstrike.com/2012/09/17/delivering-custom-payloads-with-metasploit-using-dll-injection/)
* [Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump)
	* PowerShell script to dump Windows credentials from the Credential Manager. Invoke-WCMDump enumerates Windows credentials in the Credential Manager and then extracts available information about each one. Passwords are retrieved for "Generic" type credentials, but can not be retrived by the same method for "Domain" type credentials. Credentials are only returned for the current user. Does not require admin privileges!
* [icebreaker](https://github.com/DanMcInerney/icebreaker)
	* Automates network attacks against Active Directory to deliver you piping hot plaintext credentials when you're inside the network but outside of the Active Directory environment. Performs 5 different network attacks for plaintext credentials as well as hashes. Autocracks hashes found with JohnTheRipper and the top 10 million most common passwords.
* [[EN] Golang for pentests : Hershell](https://sysdream.com/news/lab/2018-01-15-en-golang-for-pentests-hershell/)
* [Hershell](https://github.com/sysdream/hershell)	
	* Simple TCP reverse shell written in Go. It uses TLS to secure the communications, and provide a certificate public key fingerprint pinning feature, preventing from traffic interception.
* [Putting data in Alternate data streams and how to execute it - oddvar.moe](https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/)
* [Kurt Seifried Security Advisory 003 (KSSA-003)](https://seifried.org/security/advisories/kssa-003.html)
* [token_manipulation](https://github.com/G-E-N-E-S-I-S/token_manipulation)
	* Bypass User Account Control by manipulating tokens (can bypass AlwaysNotify)
* [Nishang](https://github.com/samratashok/nishang)
	* Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
* [hunter](https://github.com/fdiskyou/hunter)
	* (l)user hunter using WinAPI calls only

* [AppLocker Case study: How insecure is it really? Part 1 oddvar.moe](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-1/)
* AppLocker Case study: How insecure is it really? Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)

* [DeviceGuard Bypasses - James Forshaw](https://github.com/tyranid/DeviceGuardBypasses)
	* This solution contains some of my UMCI/Device Guard bypasses. They're are designed to allow you to analyze a system, such as Windows 10 S which comes pre-configured with a restrictive UMCI policy.
* [Use AppDomainManager to maintain persistence](https://3gstudent.github.io/3gstudent.github.io/Use-AppDomainManager-to-maintain-persistence/)
* [Using CLR to maintain Persistence](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-maintain-persistence/)
* [The 68 things the CLR does before executing a single line of your code (`*`)](https://web.archive.org/web/20170614215931/http://mattwarren.org:80/2017/02/07/The-68-things-the-CLR-does-before-executing-a-single-line-of-your-code/)
* [Using Application Compatibility Shims](https://web.archive.org/web/20170815050734/http://subt0x10.blogspot.com/2017/05/using-application-compatibility-shims.html)
* [Demystifying Shims – or – Using the App Compat Toolkit to make your old stuff work with your new stuff](https://web.archive.org/web/20170910104808/https://blogs.technet.microsoft.com/askperf/2011/06/17/demystifying-shims-or-using-the-app-compat-toolkit-to-make-your-old-stuff-work-with-your-new-stuff/)
* [Consider Application Whitelisting with Device Guard](https://web.archive.org/web/20170517232357/http://subt0x10.blogspot.com:80/2017/04/consider-application-whitelisting-with.html)
* [Bypassing Application Whitelisting using MSBuild.exe - Device guard Exmaple and Mitigations](https://web.archive.org/web/20170714075746/http://subt0x10.blogspot.com:80/2017/04/bypassing-application-whitelisting.html)



------------
## Programming/AppSec

* [PMD](https://github.com/pmd/pmd)
	* PMD is a source code analyzer. It finds common programming flaws like unused variables, empty catch blocks, unnecessary object creation, and so forth. It supports Java, JavaScript, Salesforce.com Apex and Visualforce, PLSQL, Apache Velocity, XML, XSL.
* [Modern Memory Safety: C/C++ Vulnerability Discovery, Exploitation, Hardening](https://github.com/struct/mms)
	* This repo contains the slides for a training course originally developed in 2012. It has been delivered to many students since its creation. It's sold out at the Black Hat USA conference several years in a row. The content has gone through many iterations based on feedback from those classes. The original training focused mainly on browser vulnerability discovery and exploitation. This latest version still focuses on that but also covers more topics such as custom memory allocators, hardening concepts, and exploitation at a high level.
* [Infer](https://github.com/facebook/infer)
	* [Infer](http://fbinfer.com/) is a static analysis tool for Java, Objective-C and C, written in OCaml.
* Added some python stuff
* [Bandit](https://github.com/openstack/bandit)
	* Bandit is a tool designed to find common security issues in Python code. To do this Bandit processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files it generates a report.




------------
## RE

* [PLASMA](https://github.com/plasma-disassembler/plasma)
	* PLASMA is an interactive disassembler. It can generate a more readable assembly (pseudo code) with colored syntax. You can write scripts with the available Python api (see an example below). The project is still in big development.
* [Diaphora](https://github.com/joxeankoret/diaphora)
	* Diaphora (`διαφορά`, Greek for 'difference') is a program diffing plugin for IDA Pro and Radare2, similar to Zynamics Bindiff or the FOSS counterparts DarunGrim, TurboDiff, etc... It was released during SyScan 2015. It works with IDA Pro 6.9, 6.95 and 7.0. In batch mode, it supports Radare2 too (check this fork). In the future, adding support for Binary Ninja is also planned.
* [Krakatau](https://github.com/Storyyeller/Krakatau)
	* Java decompiler, assembler, and disassembler
* [Offensive & Defensive Android Reverse Engineering](https://github.com/rednaga/training/tree/master/DEFCON23)
	* Thinking like an attacker, you will learn to identify juicy Android targets, reverse engineer them, find vulnerabilities, and write exploits. We will deep dive into reverse engineering Android frameworks, applications, services, and boot loaders with the end goal of rooting devices. Approaching from a defensive perspective, we will learn quickly triage applications to determine maliciousness, exploits, and weaknesses. After learning triage skills, we will deep dive into malicious code along while dealing with packers, obfuscators, and anti-reversing techniques. Between the offensive and defensive aspects of this class, you should walk away with the fundamentals of reverse engineering and a strong understanding of how to further develop your skills for mobile platforms.
* [Luyten](https://github.com/deathmarine/Luyten)
	* Java Decompiler Gui for Procyon
* [pykd](https://pypi.python.org/pypi/pykd)
	* python windbg extension
* [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer)
	* Bytecode Viewer is an Advanced Lightweight Java Bytecode Viewer, GUI Java Decompiler, GUI Bytecode Editor, GUI Smali, GUI Baksmali, GUI APK Editor, GUI Dex Editor, GUI APK Decompiler, GUI DEX Decompiler, GUI Procyon Java Decompiler, GUI Krakatau, GUI CFR Java Decompiler, GUI FernFlower Java Decompiler, GUI DEX2Jar, GUI Jar2DEX, GUI Jar-Jar, Hex Viewer, Code Searcher, Debugger and more. It's written completely in Java, and it's open sourced. It's currently being maintained and developed by Konloch.





------------
## Red Team/Adversary Simulation/Pentesting 

* [A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/)
* [CICSpwn](https://github.com/ayoul3/cicspwn)
	* CICSpwn is a tool to pentest CICS Transaction servers on z/OS.
* [DNS-Persist](https://github.com/0x09AL/DNS-Persist)
	* DNS-Persist is a post-exploitation agent which uses DNS for command and control. The server-side code is in Python and the agent is coded in C++. This is the first version, more features and improvements will be made in the future.
* [cupp.py - Common User Passwords Profiler](https://github.com/Mebus/cupp)
	* The most common form of authentication is the combination of a username and a password or passphrase. If both match values stored within a locally stored table, the user is authenticated for a connection. Password strength is a measure of the difficulty involved in guessing or breaking the password through cryptographic techniques or library-based automated testing of alternate values. A weak password might be very short or only use alphanumberic characters, making decryption simple. A weak password can also be one that is easily guessed by someone profiling the user, such as a birthday, nickname, address, name of a pet or relative, or a common word such as God, love, money or password. That is why CUPP has born, and it can be used in situations like legal penetration tests or forensic crime investigations.




------------
## Rootkits

* [Vlany](https://github.com/mempodippy/vlany)
	* vlany is a Linux LD_PRELOAD rootkit.
* [Demon](https://github.com/x0r1/Demon)
	* GPU keylogger PoC by Team Jellyfish
* [WIN_JELLY](https://github.com/x0r1/WIN_JELLY)
	* Windows GPU RAT PoC by Team Jellyfish. Project demonstrates persistent executable code storage in gpu that later can be mapped back to userspace after reboot. The sole purpose why we titled this concept that of a trojan is due to what it's capable of. Simply use this code to hide your own basically; we aren't responsible.


------------
## SCADA / Heavy Machinery


* [A Collection of Resources for Getting Started in ICS/SCADA Cybersecurity - Robert M. Lee](http://www.robertmlee.org/a-collection-of-resources-for-getting-started-in-icsscada-cybersecurity/)
* [nmap-scada](https://github.com/jpalanco/nmap-scada)
	* nse scripts for scada identification
* [Conpot](https://github.com/mushorg/conpot)
	* Conpot is an ICS honeypot with the goal to collect intelligence about the motives and methods of adversaries targeting industrial control systems



------------
## Social Engineering





------------
## System Internals

* [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server)](https://msdn.microsoft.com/en-us/library/cc245476.aspx)
	* Specifies the Security Account Manager (SAM) Remote Protocol (Client-to-Server), which supports printing and spooling operations that are synchronous between client and server.

* [Kurt Seifried Security Advisory 003 (KSSA-003)](https://seifried.org/security/advisories/kssa-003.html)
* [Securing Privileged Access](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access)




------------
## Threat Modeling & Analysis




--------------
## UI









------------
## Web: 

* [Puppetnets: Misusing Web Browsers as a Distributed Attack Infrastructure - V. T. Lam,S. Antonatos,P. Akritidis,K. G. Anagnostakis](http://cseweb.ucsd.edu/%7Evtlam/papers/puppetnets-ccs06.pdf)
	* Most of the recent work on Web security focuses on preventing attacks that directly harm the browser’s host machine and user. In this paper we attempt to quantify the threat of browsers being indirectly misused for attacking third parties. Specifically, we look at how the existing Web infrastructure (e.g., the languages, protocols, and security policies) can be exploited by malicious Web sites to remotely instruct browsers to orchestrate actions including denial of service attacks, worm propagation and reconnaissance scans. We show that, depending mostly on the popularity of a malicious Web site and user browsing patterns, attackers are able to create powerful botnet-like infrastructures that can cause significant damage. We explore the effectiveness of countermeasures including anomaly detection and more fine-grained browser security policies
* [Autobinding vulns and Spring MVC - GreenDog](https://agrrrdog.blogspot.com/2017/03/autobinding-vulns-and-spring-mvc.html?m=1)
* [Deserialization vulnerabilities by GreenDog - ZeroNights](https://speakerdeck.com/greendog/deserialization-vulnerabilities)
* [ZeroNights-WebVillage-2017](https://github.com/GrrrDog/ZeroNights-WebVillage-2017)
	* Several simple webapps with deserialization vulnerabilities in Docker containers
* [Java Deserialization: Misusing OJDBC for SSRF - GreenDog](https://agrrrdog.blogspot.com/2018/01/java-deserialization-misusing-ojdbc-for.html?m=1)
* [Wapiti](http://wapiti.sourceforge.net/)
	* Wapiti works as a "black-box" vulnerability scanner, that means it won't study the source code of web applications but will work like a fuzzer, scanning the pages of the deployed web application, extracting links and forms and attacking the scripts, sending payloads and looking for error messages, special strings or abnormal behaviors.

* [BaRMIe](https://github.com/NickstaDB/BaRMIe)
	* BaRMIe is a tool for enumerating and attacking Java RMI (Remote Method Invocation) services.
* [webappurls](https://github.com/pwnwiki/webappurls)
	* A public list of URLs generally useful to webapp testers and pentesters.
* [sslscan - rbsec](https://github.com/rbsec/sslscan)
	* This is a fork of ioerror's version of sslscan
* [BBSQL](https://github.com/Neohapsis/bbqsql)
	* BBQSQL is a blind SQL injection framework written in Python. It is extremely useful when attacking tricky SQL injection vulnerabilities. BBQSQL is also a semi-automatic tool, allowing quite a bit of customization for those hard to trigger SQL injection findings. The tool is built to be database agnostic and is extremely versatile. It also has an intuitive UI to make setting up attacks much easier. Python gevent is also implemented, making BBQSQL extremely fast.
* [SQLiv](https://github.com/Hadesy2k/sqliv)
	* Massive SQL injection scanner
* [Zeus](https://github.com/DenizParlak/Zeus)
	* Zeus is a powerful tool for AWS EC2 / S3 / CloudTrail / CloudWatch / KMS best hardening practices. It checks security settings according to the profiles the user creates and changes them to recommended settings based on the CIS AWS Benchmark source at request of the user.
* [cs-suite](https://github.com/SecurityFTW/cs-suite)
	* Cloud Security Suite - One stop tool for auditing the security posture of AWS infrastructure.



Session Puzzling
* [Testing for Session puzzling (OTG-SESS-008) - OWASP](https://www.owasp.org/index.php/Testing_for_Session_puzzling_(OTG-SESS-008))


* [Fuzzapi](https://github.com/Fuzzapi/fuzzapi)
	* Fuzzapi is rails application which uses API_Fuzzer and provide UI solution for gem.
* [API-Fuzzer](https://github.com/Fuzzapi/API-fuzzer)
	* API Fuzzer which allows to fuzz request attributes using common pentesting techniques and lists vulnerabilities. API_Fuzzer gem accepts an API request as input and then returns vulnerabilities possible in the API.

* [Sleepy Puppy](https://github.com/Netflix/sleepy-puppy)
	* Sleepy Puppy is a cross-site scripting (XSS) payload management framework which simplifies the ability to capture, manage, and track XSS propagation over long periods of time.
* [CloudSploit](https://github.com/cloudsploit/scans)
	* CloudSploit scans is an open-source project designed to allow detection of security risks in an AWS account. These scripts are designed to run against an AWS account and return a series of potential misconfigurations and security risks.
* [Jira Information Gatherer (JIG)](https://github.com/NetSPI/JIG)
	* Jira Information Gatherer (JIG) is a python script that takes advantage of certain misconfigurations in Jira Core and Software instances that lead to the disclosure of usernames and email addresses.
* [BurpCollaboratorDNSTunnel](https://github.com/NetSPI/BurpCollaboratorDNSTunnel)
	* This extension sets up a private Burp Collaborator server as a DNS tunnel. One of the provided scripts will be used to exfiltrate data from a server through the DNS tunnel, displaying the tunneled data in Burp Suite.
* [EWS Cracker]()
	* EWS stands for Exchange Web Services. This is a SOAP based protocol used for free/busy scheduling, and leveraged by third party clients. It allows a user to read email, send email, test credentials. Unfortunately, EWS only supports Basic Authentication. If you have multi-factor authentication through a third party provider, such as Ping, Duo or Okta, EWS can be used to bypass MFA. It can also be used to bypass MDM solutions. [This was documented by the fine folks at Black Hills InfoSec](https://www.blackhillsinfosec.com/bypassing-two-factor-authentication-on-owa-portals/) as well as by [Duo](https://duo.com/blog/on-vulnerabilities-disclosed-in-microsoft-exchange-web-services) over a year ago. Microsoft's official response is to use Microsoft provided MFA, which produce an application specific password. This leaves an enourmous amount of O365 customers in a difficult state. Most customers seem unaware of this issue or choose to ignore it.
* [Truncation of SAML Attributes in Shibboleth 2](https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-013/-truncation-of-saml-attributes-in-shibboleth-2)
* [XSS - Survive The Deep End: PHP Security](https://phpsecurity.readthedocs.io/en/latest/Cross-Site-Scripting-(XSS).html)
* [Cross-origin resource sharing - Wikipedia](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing)
* [OWASP TOP 10: Security Misconfiguration #5 – CORS Vulnerability and Patch](http://blog.securelayer7.net/owasp-top-10-security-misconfiguration-5-cors-vulnerability-patch/)
* [Same-origin policy - developer.mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
* [ Your Recipe for BApp Store Success ](http://blog.portswigger.net/2018/01/your-recipe-for-bapp-store-success.html)
	* 11 Programming tips on writing Burp extensions
* [Yasuo](https://github.com/0xsauby/yasuo)
	* Yasuo is a ruby script that scans for vulnerable 3rd-party web applications.
* [Scout2](https://github.com/nccgroup/Scout2)
	* Scout2 is a security tool that lets AWS administrators assess their environment's security posture. Using the AWS API, Scout2 gathers configuration data for manual inspection and highlights high-risk areas automatically. Rather than pouring through dozens of pages on the web, Scout2 supplies a clear view of the attack surface automatically.
* [jSQL Injection](https://github.com/ron190/jsql-injection)
	* jSQL Injection is a Java application for automatic SQL database injection.


* [On The (In-)Se­cu­ri­ty Of Ja­va­Script Ob­ject Si­gning And En­cryp­ti­on](http://www.mobsec.rub.de/forschung/veroeffentlichungen/-security-javascript-object-signing-and-encryption/)
	* Ja­va­Script Ob­ject No­ta­ti­on (JSON) has evol­ved to the de-fac­to stan­dard file for­mat in the web used for ap­p­li­ca­ti­on con­fi­gu­ra­ti­on, cross- and sa­me-ori­gin data ex­chan­ge, as well as in Sin­gle Sign-On (SSO) pro­to­cols such as Open­ID Con­nect. To pro­tect in­te­gri­ty, au­then­ti­ci­ty, and con­fi­den­tia­li­ty of sen­si­ti­ve data, Ja­va­Script Ob­ject Si­gning and En­cryp­ti­on (JOSE) was crea­ted to apply cryp­to­gra­phic me­cha­nis­ms di­rect­ly in JSON mes­sa­ges. We in­ves­ti­ga­te the se­cu­ri­ty of JOSE and pre­sent dif­fe­rent ap­p­lica­ble at­tacks on se­ver­al po­pu­lar li­b­ra­ries. We in­tro­du­ce JO­SEPH (Ja­va­Script Ob­ject Si­gning and En­cryp­ti­on Pen­tes­ting Hel­per) – our newly de­ve­lo­ped Burp Suite ex­ten­si­on, which au­to­ma­ti­cal­ly per­forms se­cu­ri­ty ana­ly­sis on tar­ge­ted ap­p­li­ca­ti­ons. JO­SEPH’s au­to­ma­tic vul­nerabi­li­ty de­tec­tion ran­ges from exe­cu­ting sim­ple si­gna­tu­re ex­clu­si­on or si­gna­tu­re fa­king tech­ni­ques, which ne­glect JSON mes­sa­ge in­te­gri­ty, up to high­ly com­plex cryp­to­gra­phic Blei­chen­ba­cher at­tacks, brea­king the con­fi­den­tia­li­ty of en­cryp­ted JSON mes­sa­ges. We found se­ve­re vul­nerabi­li­ties in six po­pu­lar JOSE li­b­ra­ries. We re­s­pon­si­bly dis­clo­sed all we­ak­nes­ses to the de­ve­lo­pers and hel­ped them to pro­vi­de fixes.
* [Java Deserialization: Misusing OJDBC for SSRF](http://agrrrdog.blogspot.com/2018/01/java-deserialization-misusing-ojdbc-for.html?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&refsrc=email&iid=de938f915f384790931a34af58b0a680&fl=4&uid=150127534&nid=244+276893704)
* [Deserialization vulnerabilities  by GreenDog - ZeroNights](https://speakerdeck.com/greendog/deserialization-vulnerabilities)




------------
## Wireless Stuff

* [PixieWPS](https://github.com/wiire-a/pixiewps)
	* Pixiewps is a tool written in C used to bruteforce offline the WPS PIN exploiting the low or non-existing entropy of some software implementations, the so-called "pixie-dust attack" discovered by Dominique Bongard in summer 2014. It is meant for educational purposes only. Since version 1.4, it can also recover the WPA-PSK from a complete passive capture (M1 through M7) for some devices (currently only some devices which work with --mode 3).
* [WiFi Arsenal](https://github.com/0x90/wifi-arsenal)
* [SiGploit](https://github.com/SigPloiter/SigPloit)
	* Telecom Signaling Exploitation Framework - SS7, GTP, Diameter & SIP. SiGploit a signaling security testing framework dedicated to Telecom Security professionals and reasearchers to pentest and exploit vulnerabilites in the signaling protocols used in mobile operators regardless of the geneartion being in use. SiGploit aims to cover all used protocols used in the operators interconnects SS7, GTP (3G), Diameter (4G) or even SIP for IMS and VoLTE infrastructures used in the access layer and SS7 message encapsulation into SIP-T. Recommendations for each vulnerability will be provided to guide the tester and the operator the steps that should be done to enhance their security posture