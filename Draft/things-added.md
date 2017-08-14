

### Things added since last update:

https://www.nist.gov/itl/applied-cybersecurity/nice/about

https://github.com/isislab/Project-Ideas/wiki

https://github.com/enddo/awesome-windows-exploitation/blob/master/README.md

https://www.toshellandback.com/

https://www.class-central.com/


###### Some phrack articles?
* [cryptexec: Next-generation runtime binary encryption using on-demand function extraction](http://phrack.org/issues/63/13.html)

* [Defeating Sniffers and Intrusion Detection Systems](http://phrack.org/issues/54/10.html)

* Armouring the ELF: Binary Encryption on the UNIX Platform - grugq, scut, 12/28/2001

* Runtime Process Infection - anonymous, 07/28/2002

* Polymorphic Shellcode Engine Using Spectrum Analysis - theo detristan et al, 08/13/2003

* Stealth Hooking: Another Way to Subvert the Windows Kernel - mxatone, ivanlef0u, 04/11/2008

* Mystifying the Debugger for Ultimate Stealthness - halfdead, 04/11/2008

* Binary Mangling with Radare - pancake, 06/11/2009



[PENQUIN’S MOONLIT MAZE](https://ridt.co/d/jags-moore-raiu-rid.pdf)


## Android


## Anonymity/OPSEC

[PISSED: Privacy In a Surveillance State Evading Detection - Joe Cicero - CYPHERCON11 ](https://www.youtube.com/watch?v=keA3WcKwZwA)

[The Paranoid's Bible: An anti-dox effort.](https://paranoidsbible.tumblr.com/)




## Attacking Android

[Hacking Android phone. How deep the rabbit hole goes.](https://hackernoon.com/hacking-android-phone-how-deep-the-rabbit-hole-goes-18b62ad65727)

[Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)

## Attacking iOS

[Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)

## Basic Security

## BIOS/UEFI

[Advice for writing a Bootloader? - reddit](https://www.reddit.com/r/lowlevel/comments/30toah/advices_for_a_bootloader/)


## Building a Lab 




## Car Hacking

[Broadcasting your attack: Security testing DAB radio in cars - Andy Davis](http://2015.ruxcon.org.au/assets/2015/slides/Broadcasting-your-attack-Security-testing-DAB-radio-in-cars.pdf)







## Courses

## CTF

[AppJailLauncher](https://github.com/trailofbits/AppJailLauncher))
* [Sample](https://github.com/trailofbits/ctf-challenges/tree/master/csaw-2014/greenhornd)

## Crypto

[Top 10 Developer Crypto Mistakes](https://littlemaninmyhead.wordpress.com/2017/04/22/top-10-developer-crypto-mistakes/amp/)


[OMEMO Multi-End Message and Object Encryption](https://conversations.im/omemo/)
* OMEMO is an XMPP Extension Protocol (XEP) for secure multi-client end-to-end encryption. It is an open standard based on a Double Ratchet and PEP which can be freely used and implemented by anyone. The protocol has been audited by a third party.


## Crypto Currencies
[cryptocurrency](https://github.com/kilimchoi/cryptocurrency)
* Overview of top cryptocurrencies



## Data Analysis




## Design



## Disclosure


## Documentation/Technical writing


## Embedded Devices/Hardware

[Multiple Vulnerabilities in BHU WiFi “uRouter”](http://blog.ioactive.com/2016/08/multiple-vulnerabilities-in-bhu-wifi.html)

[SPI](https://trmm.net/SPI_flash)

[Jackson Thuraisamy & Jason Tran - Hacking POS PoS Systems](https://www.youtube.com/watch?v=-n7oJqmTUCo) 





## Exploit Dev
* Add use-after-free section
[Bypass Control Flow Guard Comprehensively](https://www.blackhat.com/docs/us-15/materials/us-15-Zhang-Bypass-Control-Flow-Guard-Comprehensively-wp.pdf)

[A brief history of Exploitation - Devin Cook](http://www.irongeek.com/i.php?page=videos/derbycon4/t514-a-brief-history-of-exploitation-devin-cook)

[ Shellcode Time: Come on Grab Your Friends](http://www.irongeek.com/i.php?page=videos/derbycon4/t116-shellcode-time-come-on-grab-your-friends-wartortell)
* Packed shellcode is a common deterrent against reverse engineering. Mainstream software will use it in order to protect intellectual property or prevent software cracking. Malicious binaries and Capture the Flag (CTF) challenges employ packed shellcode to hide their intended functionality. However, creating these binaries is an involved process requiring significant experience with machine language. Due to the complexity of creating packed shellcode, the majority of samples are painstakingly custom-created or encoded with very simple mechanisms, such as a single byte XOR. In order to aid in the creation of packed shellcode and better understand how to reverse engineer it, I created a tool to generate samples of modular packed shellcode. During this talk, I will demonstrate the use of the shellcode creation tool and how to reverse engineer the binaries it creates. I will also demonstrate an automated process for unpacking the binaries that are created.

[Writing my first shellcode - iptables -P INPUT ACCEPT](https://0day.work/writing-my-first-shellcode-iptables-p-input-accept/)

[Blind Return Oriented Programming](http://www.scs.stanford.edu/brop/)

[Blind Return Oriented Programming (BROP) Attack (1)](http://ytliu.info/blog/2014/05/31/blind-return-oriented-programming-brop-attack-yi/)

[Blind Return Oriented Programming (BROP) Attack (2)](http://ytliu.info/blog/2014/06/01/blind-return-oriented-programming-brop-attack-er/)

[English Shellcode](http://web.cs.jhu.edu/~sam/ccs243-mason.pdf)
* History indicates that the security community commonly takes a divide-and-conquer approach to battling malware threats: identify the essential and inalienable components of an attack, then develop detection and prevention techniques that directly target one or more of the essential components. This abstraction is evident in much of the literature for buffer overflow attacks including, for instance, stack protection and NOP sled detection. It comes as no surprise then that we approach shellcode detection and prevention in a similar fashion. However, the common belief that components of polymorphic shellcode (e.g., the decoder) cannot reliably be hidden suggests a more implicit and broader assumption that continues to drive contemporary research: namely, that valid and complete representations of shellcode are fundamentally different in structure than benign payloads. While the first tenet of this assumption is philosoph- ically undeniable (i.e., a string of bytes is either shellcode or it is not), truth of the latter claim is less obvious if there exist encoding techniques capable of producing shellcode with features nearly indistinguishable from non-executable content. In this paper, we challenge the assumption that shellcode must conform to superficial and discernible representations. Specifically, we demonstrate a technique for automatically producing English  Shellcode, transforming arbitrary shellcode into a representation that is superficially similar to English prose. The shellcode is completely self-contained - i.e., it does not require an external loader and executes as valid IA32 code)—and can typically be generated in under an hour on commodity hardware. Our primary objective in this paper is to promote discussion and stimulate new ideas for thinking ahead about preventive measures for tackling evolutions in code-injection attacks

[Breaking the links: Exploiting the linker](https://www.nth-dimension.org.uk/pub/BTL.pdf)

[QuickZip Stack BOF 0day: a box of chocolates](https://www.corelan.be/index.php/2010/03/27/quickzip-stack-bof-0day-a-box-of-chocolates/)

[Exploit writing tutorial part 10 : Chaining DEP with ROP – the Rubik’s[TM] Cube](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)

[Exploit writing tutorial part 11 : Heap Spraying Demystified](https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/)


[Part 9: Spraying the Heap [Chapter 2: Use-After-Free] – Finding a needle in a Haystack](https://www.fuzzysecurity.com/tutorials/expDev/11.html)

[An Introduction to Use After Free Vulnerabilities](https://www.purehacking.com/blog/lloyd-simon/an-introduction-to-use-after-free-vulnerabilities)

* [Windows Kernel Shellcode on Windows 10 – Part 1](https://improsec.com/blog//windows-kernel-shellcode-on-windows-10-part-1)
* [Windows Kernel Shellcode on Windows 10 – Part 2](https://improsec.com/blog//windows-kernel-shellcode-on-windows-10-part-2)
* [Windows Kernel Shellcode on Windows 10 – Part 3](https://improsec.com/blog//windows-kernel-shellcode-on-windows-10-part-3)
* [Windows Kernel Shellcode on Windows 10 – Part 4 - There is No Code](https://improsec.com/blog//windows-kernel-shellcode-on-windows-10-part-4-there-is-no-code)









## Forensics
* Roll anti into this.

[An Anti-Forensics Primer - Jason Andress](http://www.irongeek.com/i.php?page=videos/derbycon3/s216-an-anti-forensics-primer-jason-andress)
* This talk will cover the basics of anti-forensics, the tools and techniques that can be used to make life harder for computer forensic examiners. We will cover some of the basic methods that are used (disk wiping, time stomping, encryption, etc…) and talk about which of these methods might actually work and which are easily surmounted with common forensic tools.

[OpenPuff Steganography](http://embeddedsw.net/OpenPuff_Steganography_Home.html)

[Forensics Impossible: Self-Destructing Thumb Drives - Brandon Wilson](https://www.youtube.com/watch?v=NRMqwc5YEu4)



## Fuzzing

[Practical File Format Fuzzing](http://www.irongeek.com/i.php?page=videos/derbycon3/3301-practical-file-format-fuzzing-jared-allar)
* File format fuzzing has been very fruitful at discovering exploitable vulnerabilities. Adversaries take advantage of these vulnerabilities to conduct spear-phishing attacks. This talk will cover the basics of file format fuzzing and show you how to use CERT’s fuzzing frameworks to discovery vulnerabilities in file parsers.

## Game Hacking

[Gotta catch-em-all worldwide - Pokemon GO GPS spoofing](https://insinuator.net/2016/07/gotta-catch-em-all-worldwide-or-how-to-spoof-gps-to-cheat-at-pokemon-go/)

[The Multibillion dollar industry that's ignored](http://www.irongeek.com/i.php?page=videos/derbycon4/_t204-the-multibillion-dollar-industry-thats-ignored-jason-montgomery-and-ryan-sevey)

[ The Multibillion Dollar Industry That's Ignored - Jason Montgomery and Ryan Sevey](http://www.irongeek.com/i.php?page=videos/derbycon4/t204-the-multibillion-dollar-industry-thats-ignored-jason-montgomery-and-ryan-sevey)
* Video games are something that a lot of us enjoy playing to escape the realities of the world- and to just relax and have fun. What’s unknown to many gamers who work hard to up their skills- they often are losing to cheaters who can dominate them with low skills by subscribing to a ~$10 a month cheat service (which often requires disabling UAC, DEP, and AV).This talk will examine some of the security issues facing the gaming industry and the cheating marketplace, and will include a deep dive into how game “hacks” such as aimbots and extrasensory perception (ESP) work in current gaming engines. We’ll explore current anti-cheat technologies and techniques attackers use to easily bypass them, as well as how the cheats themselves are protected from being discovered. Finally we conclude with proposing new anti-cheat techniques including Machine Learning/Artificial Intelligence giving the legit gamers an enjoyable experience again.







## Honeypots

## ICS/SCADA


# iOS- ANYCON 2017




## Interesting Things

[Hacks, Lies, & Nation States - Mario DiNatale - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/303-hacks-lies-nation-states-mario-dinatale)
* A hilarious and non-technical skewering of the current state of Cybersecurity, the Cybersecurity

[CyberChef - GCHQ](https://github.com/gchq/CyberChef)
* CyberChef is a simple, intuitive web app for carrying out all manner of "cyber" operations within a web browser. These operations include simple encoding like XOR or Base64, more complex encryption like AES, DES and Blowfish, creating binary and hexdumps, compression and decompression of data, calculating hashes and checksums, IPv6 and X.509 parsing, changing character encodings, and much more.

[Your Project from Idea to Reality](http://www.slideshare.net/maltman23/your-project-from-idea-to-reality)

[Beyond Information Warfare: You aint seen nothing yet - Winn Scwartau](http://www.irongeek.com/i.php?page=videos/derbycon3/2206-beyond-information-warfare-you-ain-t-seen-nothing-yet-winn-schwartau)

[Bootstrapping A Security Research Project Andrew Hay](https://www.youtube.com/watch?v=gNU2J-IcK4E)
* It has become increasingly common to see a headline in the mainstream media talking about the latest car, television, or other IoT device being hacked (hopefully by a researcher). In each report, blog, or presentation, we learn about the alarming lack of security and privacy associated with the device's hardware, communications mechanisms, software/app, and hosting infrastructure in addition to how easy it might be for an attacker to take advantage of one, or multiple, threat vectors. The truth is, anyone can perform this kind of research if given the right guidance. To many security professionals, however, the act of researching something isn,t the problem...it's what to research, how to start, and when to stop. Academics think nothing of researching something until they feel it's "done" (or their funding/tenure runs out). Security professionals, however, often do not have that luxury. This session will discuss how to research, well, ANYTHING. Proven methods for starting, continuing, ending, leading, and collaborating on reproducible research will be discussed - taking into account real-world constraints such as time, money, and a personal life. We will also discuss how to generate data, design your experiments, analyze your results, and present (and in some cases defend) your research to the public.

[Killing you softly Josh Bressers](http://www.irongeek.com/i.php?page=videos/circlecitycon2016/302-killing-you-softly-josh-bressers)
* The entire security industry has a serious skill problem. We,re technically able, but we have no soft skills. We can,t talk to normal people at all. We can barely even talk to each other, and it's killing our industry. Every successful industry relies on the transfer of skills from the experienced to the inexperienced. Security lacks this today. If I asked you how you learned what you know about security, what would your answer be? In most cases you learned everything you know on your own. There was minimal learning from someone else. This has left us with an industry full of magicians, but even worse it puts us in a place where there is no way to transfer skill and knowledge from one generation to the next. Magicians don,t scale. If we think about this in the context of how we engage non security people it's even worse! Most non security people have no idea what security is, what security does, or even why security is important. It's easy to laugh at the horrible security problems almost everything has today, but in reality we,re laughing at ourselves. Historically we,ve blamed everything else for this problem when in reality it's 100% our fault. One of the our great weaknesses is failing to get the regular people to understand security and why it's important. This isn,t a surprise if you think about how the industry communicates. We can barely talk to each other, how can we possibly talk to someone who doesn,t know anything about security? Normal people are confused and scared, they want to do the right thing but they have no idea what that is. The future leaders in security are going to have to be able to teach and talk to their security peers, but more importantly they will have to engage everyone else. Security is being paid attention to like never before, and yet we have nothing to say to anyone. What has changed in the last few years? If we don,t do our jobs, someone else will do them for us, and we,re not going to like the results. Security isn,t a technical problem, technical problems are easy, security is a communication problem. Communications problems are difficult. Let's figure out how we can fix that.

[Medical Device Law: Compliance Issues, Best Practices and Trends - American Bar Association](https://www.americanbar.org/content/dam/aba/events/cle/2015/10/ce1510mdm/ce1510mdm_interactive.authcheckdam.pdf)

[Virtualization Based Security - Part 2: kernel communications](http://blog.amossys.fr/virtualization-based-security-part2.html)

[NSARCHIVE - The Cyber Vault](http://nsarchive.gwu.edu/cybervault/)
* An online resource documenting cyber activities of the U.S. and foreign governments as well as international organizations.

[How to Steal a Nuclear Warhead Without Voiding Your XBox Warranty (paper)](https://www.scribd.com/document/47334072/How-to-Steal-a-Nuclear-Warhead-Without-Voiding-Your-XBox-Warranty-paper)

[A Look In the Mirror: Attacks on Package Managers](https://isis.poly.edu/~jcappos/papers/cappos_mirror_ccs_08.pdf)

[“Considered Harmful” Essays Considered Harmful](http://meyerweb.com/eric/comment/chech.html)

[Detecting Automation of Twitter Accounts:Are You a Human, Bot, or Cyborg](http://www.cs.wm.edu/~hnw/paper/tdsc12b.pdf)

[gibbersense](https://github.com/smxlabs/gibbersense)
* Extract Sense out of Gibberish stuff

[Netdude](http://netdude.sourceforge.net/)
* The Network Dump data Displayer and Editor is a framework for inspection, analysis and manipulation of tcpdump trace files. It addresses the need for a toolset that allows easy inspection, modification, and creation of pcap/tcpdump trace files. Netdude builds on any popular UNIX-like OS, such as Linux, the BSDs, or OSX.



## Lockpicking


## Malware
[Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)

[Advanced Desktop Application Sandboxing via AppContainer](https://www.malwaretech.com/2015/09/advanced-desktop-application-sandboxing.html)

[The Economics of Exploit Kits & E-Crime](http://www.irongeek.com/i.php?page=videos/bsidescolumbus2016/offense03-the-economics-of-exploit-kits-e-crime-adam-hogan)
* I will discuss how the market for exploit kits has been changing, in techniques, marketing and prices. I argue that the competitiveness between exploit kits shows a maturing market, but will leverage economic theory to demonstrate the limits to which that market will continue to mature. This should allow us to understand how exploit kits affect (and are affected by) the rest of the greater market for hacker services, from malware (as an input) to nation-state level attacks (e.g. trickle down from Hacking Team). I hope to provide a better understanding of how exploit kits work and how their sold as well as how this market can teach us about the rational choice to engage in criminal activity and how we might dissuade them.

[PyTrigger: A System to Trigger & Extract User-Activated Malware Behavior](http://cs.gmu.edu/~astavrou/research/PyTrigger_ARES2013.pdf)
* Abstract: We introduce PyTrigger, a dynamic malware analy- sis system that automatically exercises a malware binary extract- ing its behavioral profile even when specific user activity or input is required. To accomplish this, we developed a novel user activity record and playback framework and a new  behavior  extraction approach.  Unlike  existing research, the activity recording and playback  includes the context of every object  in  addition  to traditional keyboard and mouse actions. The addition of the con- text makes the playback more accurate and avoids dependenciesand pitfalls that come with pure mouse and keyboard  replay. Moreover,  playback  can  become  more  efficient by condensing common activities into a single action. After playback, PyTrigger analyzes the system trace using a combination of multiple states and  behavior  differencing  to accurately extract  the  malware behavior and user triggered behavior from the complete system trace  log.  We  present the  algorithms, architecture and evaluate the   PyTrigger prototype using 3994 real malware samples. Results and analysis are presented showing PyTrigger extracts additional behavior in 21% of the samples

[VirtualBox Detection Via WQL Queries](http://waleedassar.blogspot.com/)

[Code Injection Techniques -2013](http://resources.infosecinstitute.com/code-injection-techniques/)

[PowerLoaderEX](https://github.com/BreakingMalware/PowerLoaderEx)

[Injection on Steroids: Code-less Code Injections and 0-Day Techniques](https://breakingmalware.com/injection-techniques/code-less-code-injections-and-0-day-techniques/)

[BG00 Injection on Steroids Code less Code Injections and 0 Day Techniques Paul Schofield Udi Yavo](https://www.youtube.com/watch?v=0BAaAM2wD4s)


## Mainframes


## Network Scanning and Attacks

[ VLAN hopping, ARP Poisoning and Man-In-The-Middle Attacks in Virtualized Environments - Ronny L. Bull - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/110-vlan-hopping-arp-poisoning-and-man-in-the-middle-attacks-in-virtualized-environments-dr-ronny-l-bull)
* Cloud service providers and data centers offer their customers the ability to deploy virtual machines within multi-tenant environments. These virtual machines are typically connected to the physical network via a virtualized network configuration. This could be as simple as a bridged interface to each virtual machine or as complicated as a virtual switch providing more robust networking features such as VLANs, QoS, and monitoring. In this talk I will demonstrate the effects of VLAN hopping, ARP poisoning and Man-in-the-Middle attacks across every major hypervisor platform, including results of attacks originating from the physically connected network as well as within the virtual networks themselves. Each attack category that is discussed will be accompanied by a detailed proof of concept demonstration of the attack.

[LLMNR and NBT-NS Poisoning Using Responder](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)


## Network | Monitoring & Logging

[Stenographer](https://github.com/google/stenographer/blob/master/README.md)
* Stenographer is a full-packet-capture utility for buffering packets to disk for intrusion detection and incident response purposes. It provides a high-performance implementation of NIC-to-disk packet writing, handles deleting those files as disk fills up, and provides methods for reading back specific sets of packets quickly and easily.

[Netdude](http://netdude.sourceforge.net/)
* The Network Dump data Displayer and Editor is a framework for inspection, analysis and manipulation of tcpdump trace files. It addresses the need for a toolset that allows easy inspection, modification, and creation of pcap/tcpdump trace files. Netdude builds on any popular UNIX-like OS, such as Linux, the BSDs, or OSX.


## OSINT

[Tinfoleak](http://vicenteaguileradiaz.com/tools/)
* tinfoleak is a simple Python script that allow to obtain:
..* basic information about a Twitter user (name, picture, location, followers, etc.)
..* devices and operating systems used by the Twitter user
..* applications and social networks used by the Twitter user
..* place and geolocation coordinates to generate a tracking map of locations visited
..* show user tweets in Google Earth!
..* download all pics from a Twitter user
..* hashtags used by the Twitter user and when are used (date and time)
..* user mentions by the the Twitter user and when are occurred (date and time)
..* topics used by the Twitter user

[dvcs-ripper](https://github.com/kost/dvcs-ripper)
* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even 
when directory browsing is turned off.

[ZOMG Its OSINT Heaven Tazz Tazz](https://www.youtube.com/watch?v=cLmEJLy7dv8)

[Practical OSINT - Shane MacDougall](https://www.youtube.com/watch?v=cLmEJLy7dv8)
*  There’s more to life to OSINT than google scraping and social media harvesting. Learn some practical methods to automate information gathering, explore some of the most useful tools, and learn how to recognize valuable data when you see it. Not only will we explore various tools, attendees will get access to unpublished transforms they can use/modify for their own use.


##	OS X

## Password Cracking


## Phishing/SE



## Policy



## Post Exploitation/Privilege Escalation

[Noob 101: Practical Techniques for AV Bypass - Jared Hoffman - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/103-noob-101-practical-techniques-for-av-bypass-jared-hoffman)
* The shortcomings of anti-virus (AV) solutions have been well known for some time. Nevertheless, both public and private organizations continue to rely on AV software as a critical component of their information security programs, acting as a key protection mechanism over endpoints and other information systems within their networks. As a result, the security posture of these organizations is significantly jeopardized by relying only on this weakened control.

[SYSTEM Context Persistence in GPO Startup Scripts](https://cybersyndicates.com/2016/01/system-context-persistence-in-gpo-startup/)

[Scanning Effectively Through a SOCKS Pivot with Nmap and Proxychains](https://cybersyndicates.com/2015/12/nmap-and-proxychains-scanning-through-a-socks-piviot/)
* [Script](https://github.com/killswitch-GUI/PenTesting-Scripts/blob/master/Proxychains-Nmap.py)

[MacroShop](https://github.com/khr0x40sh/MacroShop)
* Collection of scripts to aid in delivering payloads via Office Macros. 

[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
* Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
* [Presentation](https://www.youtube.com/watch?v=P1lkflnWb0I)

[How to Bypass Anti-Virus to Run Mimikatz](http://www.blackhillsinfosec.com/?p=5555)

[Dragon: A Windows, non-binding, passive download / exec backdoor](http://www.shellntel.com/blog/2015/6/11/dragon-a-windows-non-binding-passive-downloadexec-backdoor)

[injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.

[Inject All the Things - Shut up and hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
* Accompanying above project

[Windows Driver and Service enumeration with Python](https://cybersyndicates.com/2015/09/windows-driver-and-service-enumeration-with-python/)

[PowerLoaderEX](https://github.com/BreakingMalware/PowerLoaderEx)

[Injection on Steroids: Code-less Code Injections and 0-Day Techniques](https://breakingmalware.com/injection-techniques/code-less-code-injections-and-0-day-techniques/)

[Injection on Steroids: Code less Code Injections and 0 Day Techniques - Paul Schofield Udi Yavo](https://www.youtube.com/watch?v=0BAaAM2wD4s)

[PowerShell and Token Impersonation](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)

[Accessing the Windows API in PowerShell via internal .NET methods and reflection](http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html)
* It is possible to invoke Windows API function calls via internal .NET native method wrappers in PowerShell without requiring P/Invoke or C# compilation. How is this useful for an attacker? You can call any Windows API function (exported or non-exported) entirely in memory. For those familiar with Metasploit internals, think of this as an analogue to railgun.

[How Attackers Dump Active Directory Database Credentials](https://adsecurity.org/?p=2398)


## Programming:


## Policy and Compliance


## RE

[Hyper-V debugging for beginners](http://hvinternals.blogspot.com/2015/10/hyper-v-debugging-for-beginners.html?m=1)

[Software Hooking methods reveiw(2016)]((https://www.blackhat.com/docs/us-16/materials/us-16-Yavo-Captain-Hook-Pirating-AVs-To-Bypass-Exploit-Mitigations-wp.pdf)

[Deviare v2.0](http://whiteboard.nektra.com/deviare-v-2-0)
* The Deviare API has been developed to intercept any API calls, letting you get control of the flow of execution of any application.

[Reverse History Part Two – Research](http://jakob.engbloms.se/archives/1554)

[SpyStudio Tutorials](http://whiteboard.nektra.com/spystudio-2-0-quickstart)








## Red Team/Pentesting

[Adam Compton - Hillbilly Storytime - Pentest Fails](https://www.youtube.com/watch?v=GSbKeTPv2TU)
* Whether or not you are just starting in InfoSec, it is always important to remember that mistakes happen, even to the best and most seasoned of analysts. The key is to learn from your mistakes and keep going. So, if you have a few minutes and want to talk a load off for a bit, come and join in as a hillbilly spins a yarn about a group unfortunate pentesters and their misadventures. All stories and events are true (but the names have been be changed to prevent embarrassment).

[Sniffing Sunlight - Erik Kamerling - ANYCON2017](http://www.irongeek.com/i.php?page=videos/anycon2017/102-sniffing-sunlight-erik-kamerling)
* Laser listening devices (laser microphones) are a well understood technology. They have historically been used in the surreptitious surveillance of protected spaces. Using such a device, an attacker bounces an infrared laser off of a reflective surface, and receives the ricocheted beam with a photoreceptor. If the beam is reflected from a surface that is vibrating due to sound (voice is a typical background target), that sound is subsequently modulated into the beam and can be demodulated at the receptor. This is a known attack method and will be briefly discussed. However, does this principle also hold for non-amplified or naturally concentrated light sources? Can one retrieve modulated audio from reflected sunlight? The idea of modulating voice with sunlight was pioneered by Alexander Graham Bell in 1880 with an invention called the Photophone. A Photophone uses the audio modulation concept now used in laser microphones, but relied on a concentrated beam of sunlight rather than a laser to communicate at distance. Considering that Bell proved that intentionally concentrated sunlight can be used to modulate voice, we will explore under what natural conditions modulated audio can be found in reflected ambient light. Using off the shelf solar-cells and handmade amplifiers, Erik will demonstrate the use of the receiver side of a historic Photophone to identify instances of modulated audio in reflected light under common conditions.

[DIY Spy Covert Channels With Scapy And Python - Jen Allen - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/diy-spy-covert-channels-with-scapy-and-python-jen-allen)

[Egressing Bluecoat with CobaltStike & Let's Encrypt](https://cybersyndicates.com/2016/12/egressing-bluecoat-with-cobaltstike-letsencrypt/)

[Expand Your Horizon Red Team – Modern SaaS C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)

[Expand Your Horizon Red Team – Modern SaaS C2 - Python WSGI C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)

[High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)

[Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/talks/fronting-pets2015/)

[Camouflage at encryption layer: domain fronting](https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/)

[Domain Fronting - Infosec Institute](http://resources.infosecinstitute.com/domain-fronting/)

[injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.

[Inject All the Things - Shut up and hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)

[Pen Testing a City](https://www.blackhat.com/docs/us-15/materials/us-15-Conti-Pen-Testing-A-City-wp.pdf)

[Staying Persistent in Software Defined Networks](https://www.blackhat.com/docs/us-15/materials/us-15-Pickett-Staying-Persistent-In-Software-Defined-Networks-wp.pdf)

[Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)

[Hacking Corporate Em@il Systems - Nate Power](http://www.irongeek.com/i.php?page=videos/bsidescolumbus2016/offense04-hacking-corporate-emil-systems-nate-power)
* In this talk we will discuss current email system attack vectors and how these systems can be abused and leveraged to break into corporate networks. A penetration testing methodology will be discussed and technical demonstrations of attacks will be shown. Phases of this methodology include information gathering, network mapping, vulnerability identification, penetration, privilege escalation, and maintaining access. Methods for organizations to better protect systems will also be discussed.

[A JOURNEY FROM JNDI/LDAP  MANIPULATION TO REMOTE CODE  EXECUTION DREAM LAND](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)

[Code Injection Techniques -2013](http://resources.infosecinstitute.com/code-injection-techniques/)

[Offensive Encrypted Data Storage](http://www.harmj0y.net/blog/redteaming/offensive-encrypted-data-storage/)

[Offensive Encrypted Data Storage (DPAPI edition)](https://posts.specterops.io/offensive-encrypted-data-storage-dpapi-edition-adda90e212ab)

[PowerLoaderEX](https://github.com/BreakingMalware/PowerLoaderEx)

[Injection on Steroids: Code-less Code Injections and 0-Day Techniques](https://breakingmalware.com/injection-techniques/code-less-code-injections-and-0-day-techniques/)

[Injection on Steroids: Code less Code Injections and 0 Day Techniques - Paul Schofield Udi Yavo](https://www.youtube.com/watch?v=0BAaAM2wD4s)

[knit_brute.sh](https://gist.github.com/ropnop/8711392d5e1d9a0ba533705f7f4f455f)
* A quick tool to bruteforce an AD user's password by requesting TGTs from the Domain Controller with 'kinit'







## SCADA

[Remote Physical Damage 101 - Bread and Butter Attacks](https://www.blackhat.com/docs/us-15/materials/us-15-Larsen-Remote-Physical-Damage-101-Bread-And-Butter-Attacks.pdf)

[Simulated Physics And Embedded Virtualization Integration (SPAEVI) - Overview](http://www.spaevi.org/p/the-simulated-physics-and-embedded.html)






## Social Engineering

[Jedi Mind Tricks: People Skills for Security Pros - Alex DiPerma - 2017 ANYCON](http://www.irongeek.com/i.php?page=videos/anycon2017/104-jedi-mind-tricks-people-skills-for-security-pros-alex-diperna)
* People skills for security professionals but WAY MORE FUN!

[PG12 Classic Misdirection Social Engineering to Counter Surveillance Peter Clemenko III](https://www.youtube.com/watch?v=AysOwnSUmgg)

[Patching the Human Vulns  - Leonard Isham](http://www.irongeek.com/i.php?page=videos/derbycon4/t300-patching-the-human-vulns-leonard-isham)
* You are a hacker, you learn, you play, and you break. The very nature of a hacker is to question what is given to us and to play with the rules. However, most of us do not apply this methodology in all parts of our lives. Many take what is given to us about mood and health as fact and what are the results...overweight, depression, anxiety, and self esteem issues. In this presentation, we will show 2 hackers and their journey on how they addressed the issues mentioned above. Len and Moey followed two separate paths to losing over a combined 150 lbs, gaining confidence, and changing their outlook. The talk will not only cover the touchy feely portion of how to deal with weight, mood,and self esteem but will also be supported by the science behind diets, supplements and perspective. The talk will provide what worked for two hackers. YMMV. 


[Cheat Codez: Level UP Your SE Game - Eric Smith (@InfoSecMafia)](http://www.irongeek.com/i.php?page=videos/derbycon3/1206-cheat-codez-level-up-your-se-game-eric-smith)
* Everyone knows what phishing is. Everyone realizes Java applets lead to massive storms of shells. Everyone accepts tailgating is the easiest way into your building. Everyone knows smoking (areas) are bad for you AND your business. Admit it, you paid for that EXACT assessment last year. I could write your report for you without even doing the job. So what’s the problem you ask? That’s EXACTLY the problem, I say. So how do we fix these issues that plague our industry and misalign business expectations? This talk will discuss the value of Social Engineering exercises when conducted with realistic goals yielding actionable results. Of course, that means putting in REAL work throughout the engagement, not “point, click, report, rinse and repeat”. We’ll discuss tips, techniques and secrets that the PROS don’t always blog about. *PRO TIP* – This won’t be a talk on how to use a particular framework or release of a tool (there are plenty of those already). So bring your work boots, it’s time to get dirty and UP your game.



## System Internals

[Windows Data Protection](https://msdn.microsoft.com/en-us/library/ms995355.aspx)

[AD Local Domain groups, Global groups and Universal groups.](https://ss64.com/nt/syntax-groups.html)

[Demystifying AppContainers in Windows 8 (Part I)](https://blog.nextxpert.com/2013/01/31/demystifying-appcontainers-in-windows-8-part-i/)

[AppContainer Isolation](https://msdn.microsoft.com/en-us/library/windows/desktop/mt595898(v=vs.85).aspx)

[Evolution of Process Environment Block (PEB)](http://blog.rewolf.pl/blog/?p=573)

[PEB32 and PEB64 in one definition](http://blog.rewolf.pl/blog/?p=294)

[Unkillable Processes](https://blogs.technet.microsoft.com/markrussinovich/2005/08/17/unkillable-processes/)

[Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)

[Advanced Desktop Application Sandboxing via AppContainer](https://www.malwaretech.com/2015/09/advanced-desktop-application-sandboxing.html)

[VirtualAlloc function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx)

[BATTLE OF SKM AND IUM - How Windows 10 rewrites OS Architecture - Alex Ionescu](http://www.alex-ionescu.com/blackhat2015.pdf)





## Threat Modeling & Analysis


## Threat Hunting

## Training




## Web: 

[backslash-powered-scanner](https://github.com/PortSwigger/backslash-powered-scanner)
* This extension complements Burp's active scanner by using a novel approach capable of finding and confirming both known and unknown classes of server-side injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.

[distribute-damage](https://github.com/PortSwigger/distribute-damage)
* Designed to make Burp evenly distribute load across multiple scanner targets, this extension introduces a per-host throttle, and a context menu to trigger scans from. It may also come in useful for avoiding detection.

[Backslash Powered Scanning: Hunting Unknown Vulnerability Classes](http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html)
*  Existing web scanners search for server-side injection vulnerabilities by throwing a canned list of technology-specific payloads at a target and looking for signatures - almost like an anti-virus. In this document, I'll share the conception and development of an alternative approach, capable of finding and confirming both known and unknown classes of injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering. 

[NodeJS: Remote Code Execution as a Service - Peabnuts123 – Kiwicon 2016](https://www.youtube.com/watch?v=Qvtfagwlfwg)
* [SLIDES](http://archivedchaos.com/post/153372061089/kiwicon-2016-slides-upload)

[Server Side Template Injection](http://blog.portswigger.net/2015/08/server-side-template-injection.html)

[Hacking Jenkins Servers With No Password](https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password)






## Wireless Stuff

[SO YOU WANT TO HACK RADIOS - A PRIMER ON WIRELESS REVERSE ENGINEERING](http://conference.hitb.org/hitbsecconf2017ams/materials/D1T4%20-%20Marc%20Newlin%20and%20Matt%20Knight%20-%20So%20You%20Want%20to%20Hack%20Radios.pdf)

[ebay.com: RCE using CCS](http://secalert.net/#ebay-rce-ccs)

[The unexpected dangers of preg_replace()](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace)

[Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys Mathy Vanhoef and Frank Piessens,  Katholieke Universiteit Leuven](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_vanhoef.pdf)

[ If it fits - it sniffs: Adventures in WarShipping - Larry Pesce](http://www.irongeek.com/i.php?page=videos/derbycon4/t104-if-it-fits-it-sniffs-adventures-in-warshipping-larry-pesce)
*  There are plenty of ways to leverage known wireless attacks against our chosen victims. We've discovered a new WiFi discovery methodology that can give us insight into attack paths, internal distribution methods, internal policies and procedures as well as an opportunity to launch wireless attacks deep inside a facility without even stepping inside; no physical penetration test needed. How do we make that happen? Box it, tape it and slap an address on it: WARSHIPPING. Thanks FedEx, UPS and USPS for doing the heavy lifting for us. We've even got a new tool to do some of the heavy lifting for location lookups too!

[Funtenna - Transmitter: XYZ Embedded device + RF Funtenna Payload](https://www.blackhat.com/docs/us-15/materials/us-15-Cui-Emanate-Like-A-Boss-Generalized-Covert-Data-Exfiltration-With-Funtenna.pdf)

[The Wireless World of the Internet of Things -  JP Dunning ".ronin"](http://www.irongeek.com/i.php?page=videos/derbycon4/t214-the-wireless-world-of-the-internet-of-things-jp-dunning-ronin)
* The Internet of Things brings all the hardware are home together. Most of these devices are controlled through wireless command and control network. But what kind of wireless? And what are the security is in place? This talk with cover the wireless tech used by the Internet of Things and some of the risks to your home or corporate security.



