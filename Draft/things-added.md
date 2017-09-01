 * Up txt sizes, put -------- under sections?

* Merging Physical with lockpicking

https://github.com/onethawt/reverseengineering-reading-list

https://github.com/caesar0301/awesome-pcaptools

https://github.com/paralax/awesome-honeypots

https://github.com/meirwah/awesome-incident-response#log-analysis-tools

https://github.com/nebgnahz/awesome-iot-hacks





















## Anonymity
------------
[FakeNameGenerator](http://www.fakenamegenerator.com/)

[Wifi Tracking: Collecting the (probe) Breadcrumbs - David Switzer](https://www.youtube.com/watch?v=HzQHWUM8cNo)
* Wifi probes have provided giggles via Karma and Wifi Pineapples for years, but is there more fun to be had? Like going from sitting next to someone on a bus, to knowing where they live and hang out? Why try to MITM someone’s wireless device in an enterprise environment where they may notice — when getting them at their favorite burger joint is much easier. In this talk we will review ways of collecting and analyzing probes. We’ll use the resulting data to figure out where people live, their daily habits, and discuss uses (some nice, some not so nice) for this information. We’ll also dicuss how to make yourself a little less easy to track using these methods. Stingrays are price prohibitive, but for just tracking people’s movements.. this is cheap and easy.

[How Tor Users Got Caught - Defcon 22](https://www.youtube.com/watch?v=7G1LjQSYM5Q)
* [Part 2](https://www.youtube.com/watch?v=TQ2bk9kMneI)
* [Article -  How Tor Users Got Caught by Government Agencies](http://se.azinstall.net/2015/11/how-tor-users-got-caught.html)







## Attacking/Defending Android
------------

[Miroslav Stampar - Android: Practical Introduction into the (In)Security](https://www.youtube.com/watch?v=q1_rvrY4VHI)
* This presentation covers the user’s deadly sins of Android (In)Security, together with implied system security problems. Each topic could potentially introduce unrecoverable damage from security perspective. Both local and remote attacks are covered, along with accompanying practical demo of most interesting ones. 




## Basic Security Info
------------
[So you think you want to be a penetration tester - Defcon24](https://www.youtube.com/watch?v=be7bvZkgFmY)
* So, you think you want to be a penetration tester, or you already are and don't understand what the difference between you and all the other "so called" penetration testers out there. Think you know the difference between a Red Team, Penetration Test and a Vulnerability assessment? Know how to write a report your clients will actually read and understand? Can you leverage the strengths of your team mates to get through tough roadblocks, migrate, pivot, pwn and pillage? No? well this talk is probably for you then! We will go through the fascinating, intense and often crazily boring on-site assessment process. Talk about planning and performing Red Teams, how they are different, and why they can be super effective and have some fun along the way. I'll tell you stories that will melt your face, brain and everything in between. Give you the answers to all of your questions you never knew you had, and probably make you question your life choices. By the end of this session you will be ready to take your next steps into the job you've always wanted, or know deep inside that you should probably look for something else. There will be no judgment or shame, only information, laughter and fun.



## BIOS/UEFI
------------
[Disabling Intel ME 11 via undocumented mode - ptsecurity](http://blog.ptsecurity.com/2017/08/disabling-intel-me.html)





## Building a Lab 
------------






## Car Hacking
------------

[An Introduction to the CAN Bus: How to Programmatically Control a Car: Hacking the Voyage Ford Fusion to Change A/C Temperature](https://news.voyage.auto/an-introduction-to-the-can-bus-how-to-programmatically-control-a-car-f1b18be4f377)




## Courses
------------






## CTF
------------








## Crypto
------------

[Quick'n easy gpg cheatsheet](http://irtfweb.ifa.hawaii.edu/%7Elockhart/gpg/)

[Hunting For Vulnerabilities In Signal - Markus Vervier - HITB 2017 AMS](https://www.youtube.com/watch?v=2n9HmllVftA)
* Signal is the most trusted secure messaging and secure voice application, recommended by Edward Snowden and the Grugq. And indeed Signal uses strong cryptography, relies on a solid system architecture, and you’ve never heard of any vulnerability in its code base. That’s what this talk is about: hunting for vulnerabilities in Signal. We will present vulnerabilities found in the Signal Android client, in the underlying Java libsignal library, and in example usage of the C libsignal library. Our demos will show how these can be used to crash Signal remotely, to bypass the MAC authentication for certain attached files, and to trigger memory corruption bugs. Combined with vulnerabilities in the Android system it is even possible to remotely brick certain Android devices. We will demonstrate how to initiate a permanent boot loop via a single Signal message. We will also describe the general architecture of Signal, its attack surface, the tools you can use to analyze it, and the general threat model for secure mobile communication apps.




## Crypto Currencies
------------
[Blockchain Graveyard](https://magoo.github.io/Blockchain-Graveyard/)
* These cryptocurrency institutions have suffered intrusions resulting in stolen financials, or shutdown of the product. Nearly all closed down afterward. 



## Data Analysis
------------






## Design
------------





## Disclosure
------------




## Documentation/Technical writing
------------





## Embedded Devices/Hardware
------------

[Rooting the MikroTik routers (SHA2017)](https://www.youtube.com/watch?v=KZWGD9fWIcM)
* In this talk I describe my journey into reverse engineering parts of MikroTik system to gain access to hardware features and the shell behind the RouterOS that has no “ls”.



## Exfiltration
------------
[Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)

[A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)
* Covert channels are used for the secret transfer of information. Encryption only protects communication from being decoded by unauthorised parties, whereas covert channels aim to hide the very existence of the communication. Initially, covert channels were identified as a security threat on monolithic systems i.e. mainframes. More recently focus has shifted towards covert channels in computer network protocols. The huge amount of data and vast number of different protocols in the Internet seems ideal as a high-bandwidth vehicle for covert communication. This article is a survey of the existing techniques for creating covert channels in widely deployed network and application protocols. We also give an overview of common methods for their detection, elimination, and capacity limitation, required to improve security in future computer networks. 

[Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)
* [Covert Timing Channels Based on HTTP Cache Headers - Paper](scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)

[[DS15] Bridging the Air Gap Data Exfiltration from Air Gap Networks - Mordechai Guri & Yisroel Mirsky](https://www.youtube.com/watch?v=bThJEX4l_Ks)
* Air-gapped networks are isolated, separated both logically and physically from public networks. Although the feasibility of invading such systems has been demonstrated in recent years, exfiltration of data from air-gapped networks is still a challenging task. In this talk we present GSMem, a malware that can exfiltrate data through an air-gap over cellular frequencies. Rogue software on an infected target computer modulates and transmits electromagnetic signals at cellular frequencies by invoking specific memory-related instructions and utilizing the multichannel memory architecture to amplify the transmission. Furthermore, we show that the transmitted signals can be received and demodulated by a rootkit placed in the baseband firmware of a nearby cellular phone. We present crucial design issues such as signal generation and reception, data modulation, and transmission detection. We implement a prototype of GSMem consisting of a transmitter and a receiver and evaluate its performance and limitations. Our current results demonstrate its efficacy and feasibility, achieving an effective transmission distance of 1-5.5 meters with a standard mobile phone. When using a dedicated, yet affordable hardware receiver, the effective distance reached over 30 meters.

[Inter VM Data Exfiltration: The Art of Cache Timing Covert Channel on x86 Multi-Core - Etienne Martineau](https://www.youtube.com/watch?v=SGqUGHh3UZM)
* On x86 multi-core covert channels between co-located Virtual Machine (VM) are real and practical thanks to the architecture that has many imperfections in the way shared resources are isolated. This talk will demonstrate how a non-privileged application from one VM can ex-filtrate data or even establish a reverse shell into a co-located VM using a cache timing covert channel that is totally hidden from the standard access control mechanisms while being able to offer surprisingly high bps at a low error rate. In this talk you’ll learn about the various concepts, techniques and challenges involve in the design of a cache timing covert channel on x86 multi-core such as: X86 shared resources and fundamental concept behind cache line encoding / decoding. Getting around the hardware pre-fetching logic ( without disabling it from the BIOS! ) Abusing the X86 ‘clflush’ instruction. Bi-directional handshake for free! Data persistency and noise. What can be done? Guest to host page table de-obfuscation. The easy way, the VM’s vendors defense and another way to get around it. Phase Lock Loop and high precision inter-VM synchronization. All about timers. At the end of this talk we will go over a working VM to VM reverse shell example as well as some surprising bandwidth measurement results. We will also cover the detection aspect and the potential countermeasure to defeat such a communication channel.

[Boston BSides - Simple Data Exfiltration in a Secure Industry Environment - Phil Cronin](https://www.youtube.com/watch?v=IofUpzYZNko)
* This presentaion explores the top 10 data exfiltration methods that can be accomplished with only ‘user-level’ privileges and that are routinely overlooked in security-conscious industries.

[Emanate Like A Boss: Generalized Covert Data Exfiltration With Funtenna](https://www.youtube.com/watch?v=-YXkgN2-JD4)
* Funtenna is a software-only technique which causes intentional compromising emanation in a wide spectrum of modern computing hardware for the purpose of covert, reliable data exfiltration through secured and air-gapped networks. We present a generalized Funtenna technique that reliably encodes and emanates arbitrary data across wide portions of the electromagnetic spectrum, ranging from the sub-acoustic to RF and beyond. The Funtenna technique is hardware agnostic, can operate within nearly all modern computer systems and embedded devices, and is specifically intended to operate within hardware not designed to to act as RF transmitters. We believe that Funtenna is an advancement of current state-of-the-art covert wireless exfiltration technologies. Specifically, Funtenna offers comparable exfiltration capabilities to RF-based retro-reflectors, but can be realized without the need for physical implantation and illumination. We first present a brief survey of the history of compromising emanation research, followed by a discussion of the theoretical mechanisms of Funtenna and intentionally induced compromising emanation in general. Lastly, we demonstrate implementations of Funtenna as small software implants within several ubiquitous embedded devices, such as VoIP phones and printers, and in common computer peripherals, such as hard disks, console ports, network interface cards and more.

[Data Exfiltration: Secret Chat Application Using Wi-Fi Covert Channel by Yago Hansen at the BSidesMunich 2017](https://www.youtube.com/watch?v=-cSu63s4zPY)

[Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)
* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.

[In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)
* In this session, we will reveal and demonstrate perfect exfiltration via indirect covert channels (i.e. the communicating parties don’t directly exchange network packets). This is a family of techniques to exfiltrate data (low throughput) from an enterprise in a manner indistinguishable from genuine traffic. Using HTTP and exploiting a byproduct of how some websites choose to cache their pages, we will demonstrate how data can be leaked without raising any suspicion. These techniques are designed to overcome even perfect knowledge and analysis of the enterprise network traffic.

[Can You Hear Me Now?!? Thoery of SIGTRAN Stego. BSidesPHX 2012](https://www.youtube.com/watch?v=vzpzL-UlpdA)
* Ever wanted to know how to communicate with someone and not be heard? As many know, the internal cellular network uses SS7 and SIGTRAN to communicate via out-of-band signalling. What many don't know is what can be done with this. CC-MSOBS (Covert Channel via Multi-Streaming Out of Band Signalling) is a new form of covert communication which can be utilized by taking advantage of the multi-streaming aspects of SCTP and the using it with the out-of-band signalling capabilities of SIGTRAN. Come explore this developing covert channel as Drew Porter covers not only his idea but also his current research on this new covert channel. 

[Ma­gne­tic Side- and Co­vert-Chan­nels using Smart­pho­ne Ma­gne­tic Sen­sors](https://www.youtube.com/watch?v=-LZJqRXZ2OM)
* Side- and co­vert-chan­nels are un­in­ten­tio­nal com­mu­ni­ca­ti­on chan­nels that can leak in­for­ma­ti­on about ope­ra­ti­ons being per­for­med on a com­pu­ter, or serve as means of secre­te com­mi­na­ti­on bet­ween at­ta­ckers, re­spec­tive­ly. This pre­sen­ta­ti­on will di­s­cuss re­cent, new side- and co­vert-chan­nels uti­li­zing smart­pho­ne ma­gne­tic sen­sors. In par­ti­cu­lar, our work on these chan­nels has shown that sen­sors outside of a com­pu­ter hard drive can pick up the ma­gne­tic fields due to the mo­ving hard disk head. With these me­a­su­re­ments, we are able to de­du­ce pat­terns about on­go­ing ope­ra­ti­ons, such as de­tect what type of the ope­ra­ting sys­tem is boo­ting up or what ap­p­li­ca­ti­on is being star­ted. Mo­re­over, by in­du­cing elec­tro­ma­gne­tic si­gnals from a com­pu­ter in a con­trol­led way, at­ta­ckers can mo­du­la­te and trans­mit ar­bi­tra­ry bi­na­ry data over the air. We show that mo­dern smart­pho­nes are able to de­tect dis­tur­ban­ces in the ma­gne­tic field at a dis­tan­ce of dozen or more cm from the com­pu­ter, and can act as re­cei­vers of the trans­mit­ted in­for­ma­ti­on. Our me­thods do not re­qui­re any ad­di­tio­nal equip­ment, firm­ware mo­di­fi­ca­ti­ons or pri­vi­le­ged ac­cess on eit­her the com­pu­ter (sen­der) or the smart­pho­ne (re­cei­ver). Based on the thre­ats, po­ten­ti­al coun­ter-me­a­su­res will be pre­sen­ted that can miti­ga­te some of the chan­nels.














## Exploit Dev
------------

* [Introduction to Windows shellcode development – Part 1](https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/)
* [Introduction to Windows shellcode development – Part 2](https://securitycafe.ro/2015/12/14/introduction-to-windows-shellcode-development-part-2/)
* [Introduction to Windows shellcode development – Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/)






## Forensics
------------
[dotNET_WinDBG](https://github.com/Cisco-Talos/dotNET_WinDBG)
* This python script is designed to automate .NET analysis with WinDBG. It can be used to analyse a PowerShell script or to unpack a binary packed using a .NET packer.

[Unravelling .NET with the Help of WinDBG - TALOS](http://blog.talosintelligence.com/2017/07/unravelling-net-with-help-of-windbg.html)
* This article describes:
  * How to analyse PowerShell scripts by inserting a breakpoint in the .NET API.
  * How to easily create a script to automatically unpack .NET samples following analysis of the packer logic.




## Fuzzing
------------
[Introduction to Custom Protocol Fuzzing](https://www.youtube.com/watch?v=ieatSJ7ViBw)






## Game Hacking
------------





## Honeypots
------------






## ICS/SCADA
------------







## Interesting Things
------------
[Pwning pwners like a n00b](https://www.youtube.com/watch?v=E8O8bB3I3i0)
* Cybercrime, blackhat hackers and some Ukrainians. If that doesn’t catch your attention, then stop reading. Follow the story of how stupid mistakes, OPSEC fails, and someone with a little too much time on his hands was able to completely dismantle a spamming and webshell enterprise using really simple skills and techniques you could pick up in a week. Did we mention that d0x were had as well? This talk will be an in-depth examination at the investigation and exploitation process involved. 

[Binary SMS - The old backdoor to your new thing](https://www.contextis.com/resources/blog/binary-sms-old-backdoor-your-new-thing/)

[Bridging the Air Gap: Cross Domain Solutions - Patrick Orzechowski](https://www.irongeek.com/i.php?page=videos/bsideslasvegas2014/pg08-bridging-the-air-gap-cross-domain-solutions-patrick-orzechowski)
* For years the government has been using CDS to bridge networks with different classification levels. This talk will focus on what CDS systems are, how they’re built, and what kind of configurations are common in the wild. Furthermore, we’ll look at testing techniques to evaluate the security of these systems and potential ways to exploit holes in configuration and design. We’ll also look at the ways the commercial world might benefit from a data and type-driven firewall as well as some of the downfalls and negative aspects of implementing a cross-domain system. 





## Lockpicking
------------





## Malware
------------

[The Economics of Exploit Kits & E-Crime](http://www.irongeek.com/i.php?page=videos/bsidescolumbus2016/offense03-the-economics-of-exploit-kits-e-crime-adam-hogan)
* I will discuss how the market for exploit kits has been changing, in techniques, marketing and prices. I argue that the competitiveness between exploit kits shows a maturing market, but will leverage economic theory to demonstrate the limits to which that market will continue to mature. This should allow us to understand how exploit kits affect (and are affected by) the rest of the greater market for hacker services, from malware (as an input) to nation-state level attacks (e.g. trickle down from Hacking Team). I hope to provide a better understanding of how exploit kits work and how their sold as well as how this market can teach us about the rational choice to engage in criminal activity and how we might dissuade them.

[Loffice - Analyzing malicious documents using WinDbg](https://thembits.blogspot.com/2016/06/loffice-analyzing-malicious-documents.html)

[Writing Bad @$$ Malware for OS X - Patrick Wardle](https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf)

[Malware: From your text editor, to the United States Government's Lab (SHA2017)](https://www.youtube.com/watch?v=PtufumVvN-E)
* How Universities in the US collaborate with the United States Government to make America stronger, and the rest weaker. Ever wonder where your malware ends up after you deploy it? Are you curious how the United States Government researches Cyber Security on the backs of students? First, this is not a technical talk. This is an informative talk on the insides of how the inner workings of an Information Security Lab in one of the Top Technical Universities in the United States works with its Government to provide insights in the world of, as the feds like to call it, "CyberSecurity". (All Americans apologize for Trump. We're sorry.)












## Mainframes
------------

[Privilege escalation on z/OSINT - ayoul3 github](https://github.com/ayoul3/Privesc)
* Some scripts to quickly escalate on z/OS given certain misconfigurations.

[REX_Scripts](https://github.com/ayoul3/Rexx_scripts)
* A collection of interesting REXX scripts to ease the life a mainframe pentester

[Mainframes - Mopeds and Mischief; A PenTesters Year in Review](http://www.irongeek.com/i.php?page=videos/derbycon4/t203-mainframes-mopeds-and-mischief-a-pentesters-year-in-review-tyler-wrightson)





## Network Scanning and Attacks
------------

[NSEInfo](https://github.com/christophetd/nmap-nse-info/blob/master/README.md)
* NSEInfo is a tool to interactively search through nmap's NSE scripts.

[Get-Help: An Intro to PowerShell and How to Use it for Evil - Jared Haight](https://www.psattack.com/presentations/get-help-an-intro-to-powershell-and-how-to-use-it-for-evil/)

[Attack Methods for Gaining Domain Admin Rights in Active Directory - hackingandsecurity](https://hackingandsecurity.blogspot.com/2017/07/attack-methods-for-gaining-domain-admin.html?view=timeslide)

[ShareCheck Windows Enumeration Tool v2.0 - sec1](http://www.sec-1.com/blog/2014/sharecheck)

[Abusing Kerberos](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It-wp.pdf)

[MQTT](http://mqtt.org/)
* MQTT is a machine-to-machine (M2M)/"Internet of Things" connectivity protocol. It was designed as an extremely lightweight publish/subscribe messaging transport. 

[krb5-enum-users - nse script](https://nmap.org/nsedoc/scripts/krb5-enum-users.html)
* Discovers valid usernames by brute force querying likely usernames against a Kerberos service. When an invalid username is requested the server will respond using the Kerberos error code KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, allowing us to determine that the user name was invalid. Valid user names will illicit either the TGT in a AS-REP response or the error KRB5KDC_ERR_PREAUTH_REQUIRED, signaling that the user is required to perform pre authentication. 









## Network | Monitoring & Logging
------------




## OSINT
------------

[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
* AWSBucketDump is a tool to quickly enumerate AWS S3 buckets to look for loot. It's similar to a subdomain bruteforcer but is made specifically for S3 buckets and also has some extra features that allow you to grep for delicious files as well as download interesting files if you're not afraid to quickly fill up your hard drive.



##	OS X
------------






## Password Cracking
------------





## Phishing/SE
------------

[Outlook and Exchange for the Bad Guys Nick Landers](https://www.youtube.com/watch?v=cVhc9VOK5MY)

[Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)








## Physical Security
------------

[Physical Security - Everything That's Wrong With Your Typical Door - Deviant Ollam - SANS Webcast](https://www.youtube.com/watch?v=raBMFqZRB0s&t=&feature=youtu.be&app=desktop)

[Safe to Armed in Seconds - Deviant Ollam - DEF CON 19](https://www.youtube.com/watch?v=3SVMT_zNlgA)

[What Does The Perfect Door Or Padlock Look Like? - Deviant Ollam - BruCON 0x08](https://www.youtube.com/watch?v=4skSBwBBI-s)

["Lockpicking in Real Life versus on the Screen" - The Eleventh HOPE (2016)](https://www.youtube.com/watch?v=mjBSocgMCPU)
* We all know that Hollywood has a difficult time portraying hackers accurately. This quirk often extends to the realm of showing lockpicking in movies and on TV. But sometimes, a film gets it really right! This talk is both an introduction to lockpicking (in case you still need to learn) as well as a walk through some of the best - and some of the worst - scenes of lockpicking that have ever been seen by movie and TV audiences. Learn about how to be a better lockpicker and a better filmmaker... all at the same time!

[Lockpicking, Safecracking, & More by Deviant Ollam & renderman at ShmooCon 3](https://www.youtube.com/watch?v=WTgUVhjts2U)
* For the first time on the same stage together at ShmooCon, renderman and i give a funny and informative presentation about lockpicking using much of my traditional material as well as a whole load of new content that my favorite Canadian demonstrates. In addition to his all-around general badassery, renderman even opened up a locked safe on stage... one that he had never seen before and was simply given by an audience member. That took fucking balls.

[!$@$Lockpicking & Physical security - Deviant Ollam - Best lockpicking course abc tutorial diy](https://www.youtube.com/watch?v=j6WCe-4XQ3Q)

[The Search for the Perfect Door - Deviant Ollam - Shakacon](https://www.youtube.com/watch?v=4YYvBLAF4T8)
* You have spent lots of money on a high-grade, pick-resistant, ANSI-rated lock for your door. Your vendor has assured you how it will resist attack and how difficult it would be for someone to copy your key. Maybe they’re right. But… the bulk of attacks that both penetration testers and also criminals attempt against doors have little or nothing to do with the lock itself! This talk will be a hard-hitting exploration (full of photo and video examples) of the ways in which your door — the most fundamental part of your physical security — can possibly be thwarted by someone attempting illicit entry. The scary problems will be immediately followed by simple solutions that are instantly implementable and usually very within-budget. You, too, can have a near-perfect door… if you’re willing to learn and understand the problems that all doors tend to have. 

[This Key is Your Key, This Key is My Key - Howard Payne & Deviant Ollam](https://www.youtube.com/watch?v=a9b9IYqsb_U)

[I'll Let Myself In Tactics of Physical Pentesters - Deviant Ollam -B-sides Orlando 2017](https://www.youtube.com/watch?v=Rctzi66kCX4)

[Mastering Master Keys - Deviant Ollam - HOPE Number 9](https://www.youtube.com/watch?v=aVPSaKLKHd4)

[Ways your alarm system can fail - abak Javadi Keith Howell](https://www.youtube.com/watch?v=g4-B7d3ZQUA)

[Alarmed About Your Alarm System Yet - Keith Howell, Babak Javadi](https://www.youtube.com/watch?v=5rnkhqEj_Po)

[Electronic Locks - are really secure?!](https://www.youtube.com/watch?v=ZK0MfE7o4HU)
* Many people are familiar with the ways in which mechanical locks can be attacked, compromised, and bypassed. Indeed, the hands-on workshops and the availability of pick tools at the Lockpick Village is an enduring part of the fun at DeepSec and other popular security conferences around the world. Often, attendees will ask questions like, "So, this is really great... but what if someone is using an electronic lock? How hard is it to open the door, then?" Unfortunately, due to time and space constraints, our answer is typically, "Well... that's a very complicated question. Sometimes they're good, and sometimes they're weak." We often promise greater detail another day, another time... but until now that time has not come. Finally now, however, TOOOL will describe some of the most popular electronic locks and show examples of how they can sometimes be attacked. 

[Distinguishing Lockpicks: Raking vs Lifting vs Jiggling and More - Deviant Ollam](https://www.youtube.com/watch?v=e07VRxJ01Fs)




## Policy
------------
[NIST Cybersecurity Practice Guide, Securing Wireless Infusion Pumps in Healthcare Delivery Organizations](https://nccoe.nist.gov/projects/use-cases/medical-devices)
* [SP 1800-8a: Executive Summary](https://nccoe.nist.gov/publication/draft/1800-8/VolA/)
* [SP 1800-8b: Approach, Architecture, and Security Characteristics ](https://nccoe.nist.gov/publication/draft/1800-8/VolB/)
* [SP 1800-8c: How-To Guides](https://nccoe.nist.gov/publication/draft/1800-8/VolC/)




## Politics
------------
[Guccifer 2.0: Game Over - Six Months In](http://g-2.space/sixmonths/)





## Post Exploitation/Privilege Escalation
------------
[CredCrack](https://github.com/gojhonny/CredCrack)
* CredCrack is a fast and stealthy credential harvester. It exfiltrates credentials recusively in memory and in the clear. Upon completion, CredCrack will parse and output the credentials while identifying any domain administrators obtained. CredCrack also comes with the ability to list and enumerate share access and yes, it is threaded! CredCrack has been tested and runs with the tools found natively in Kali Linux. CredCrack solely relies on having PowerSploit's "Invoke-Mimikatz.ps1" under the /var/www directory.

[Sandboxes from a pen tester’s view - Rahul Kashyap](http://www.irongeek.com/i.php?page=videos/derbycon3/4303-sandboxes-from-a-pen-tester-s-view-rahul-kashyap)
* Description: In this talk we’ll do an architectural decomposition of application sandboxing technology from a security perspective. We look at various popular sandboxes such as Google Chrome, Adobe ReaderX, Sandboxie amongst others and discuss the limitations of each technology and it’s implementation. Further, we discuss in depth with live exploits how to break out of each category of sandbox by leveraging various kernel and user mode exploits – something that future malware could leverage. Some of these exploit vectors have not been discussed widely and awareness is important.

[Windows Security Center: Fooling WMI Consumers](https://www.opswat.com/blog/windows-security-center-fooling-wmi-consumers)

[Script Task](https://docs.microsoft.com/en-us/sql/integration-services/control-flow/script-task)
* Persistence Via MSSQL

[“Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)

[Userland Persistence with Scheduled Tasks and COM Handler Hijacking](https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)

[Shackles, Shims, and Shivs - Understanding Bypass Techniques](http://www.irongeek.com/i.php?page=videos/derbycon6/535-shackles-shims-and-shivs-understanding-bypass-techniques-mirovengi)

[How to determine Linux guest VM virtualization technology](https://www.cyberciti.biz/faq/linux-determine-virtualization-technology-command/)

[Introducing PowerShell into your Arsenal with PS>Attack - Jared Haight](http://www.irongeek.com/i.php?page=videos/derbycon6/119-introducing-powershell-into-your-arsenal-with-psattack-jared-haight)

[Attacking ADFS Endpoints with PowerShell](http://www.irongeek.com/i.php?page=videos/derbycon6/118-attacking-adfs-endpoints-with-powershell-karl-fosaaen)

[pywerview](https://github.com/the-useless-one/pywerview)
* A (partial) Python rewriting of PowerSploit's PowerView

[LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.

[Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
* The quick lowdown: I wrote a DLL capable of logging the credentials entered at logon for Windows Vista, 7 and future versions which you can download at http://www.leetsys.com/programs/credentialprovider/cp.zip. The credentials are logged to a file located at c:\cplog.txt. Simply copy the dll to the system32 directory and run the included register.reg script to create the necessary registry settings.

[Get-Help: An Intro to PowerShell and How to Use it for Evil - Jared Haight](https://www.psattack.com/presentations/get-help-an-intro-to-powershell-and-how-to-use-it-for-evil/)

[Attack and Defend: Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)

[Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)

[Batch, attach and patch: using windbg’s local kernel debugger to execute code in windows kernel](https://vallejo.cc/2015/06/07/batch-attach-and-patch-using-windbgs-local-kernel-debugger-to-execute-code-in-windows-kernel/)
* In this article I am going to describe a way to execute code in windows kernel by using windbg local kernel debugging. It’s not a vulnerability, I am going to use only windbg’s legal functionality, and I am going to use only a batch file (not powershell, or vbs, an old style batch only) and some Microsoft’s signed executables (some of them that are already in the system and windbg, that we will be dumped from the batch file). With this method it is not necessary to launch executables at user mode (only Microsoft signed executables) or load signed drivers. PatchGuard and other protections don’t stop us. We put our code directly into kernel memory space and we hook some point to get a thread executing it. As we will demonstrate, a malware consisting of a simple batch file would be able to jump to kernel, enabling local kernel debugging and using windbg to get its code being executed in kernel.

[Hack Microsoft Using Microsoft Signed Binaries - Pierre-Alexandre Braeken](https://www.youtube.com/watch?v=V9AJ9M8_-RE&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=15)
* Imagine being attacked by legitimate software tools that cannot be detected by usual defender tools.
How bad could it be to be attacked by malicious threat actors only sending bytes to be read and bytes to be written in order to achieve advanced attacks?
The most dangerous threat is the one you can’t see. At a time when it is not obvious to detect memory attacks using API like VirtualAlloc, what would be worse than having to detect something like “f 0xffffe001`0c79ebe8+0x8 L4 0xe8 0xcb 0x04 0x10”? We will be able to demonstrate that we can achieve every kind of attacks you can imagine using only PowerShell and a Microsoft Signed Debugger. We can retrieve passwords from the userland memory, execute shellcode by dynamically parsing loaded PE or attack the kernel achieving advanced persistence inside any system.

[Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)

[Hack Microsoft Using Microsoft Signed Binaries - BH17 - pierre - alexandre braeken](https://www.blackhat.com/docs/asia-17/materials/asia-17-Braeken-Hack-Microsoft-Using-Microsoft-Signed-Binaries-wp.pdf)










## Programming:
------------
[Trollius and asyncio](https://trollius.readthedocs.io/asyncio.html)

[The Hitchhiker’s Guide to Python!](http://docs.python-guide.org/en/latest/)

[Lua code: security overview and practical approaches to static analysis](http://spw17.langsec.org/papers/costin-lua-static-analysis.pdf)
* Abstract — Lua is an interpreted, cross-platform, embeddable, performant and low-footprint language. Lua’s popularity is on the rise in the last couple of years. Simple design and efficient usage of resources combined with its performance make it attractive or production web applications even to big organizations such as Wikipedia, CloudFlare and GitHub. In addition to this, Lua is one of the preferred choices for programming embedded and IoT devices. This context allows to assume a large and growing Lua codebase yet to be assessed. This growing Lua codebase could be potentially driving production servers and extremely large number of devices, some perhaps with mission-critical function for example in automotive or home-automation domains. However, there is a substantial and obvious lack of static analysis tools and vulnerable code corpora for Lua as compared to other increasingly popular languages, such as PHP, Python and JavaScript. Even the state-of-the-art commercial tools that support dozens of languages and technologies actually do not support Lua static code analysis. In this paper we present the first public Static Analysis for SecurityTesting (SAST) tool for Lua code that is currently focused on web vulnerabilities. We show its potential with good and promising preliminary results that we obtained on simple and intentionally vulnerable Lua code samples that we synthesized for our experiments. We also present and release our synthesized corpus of intentionally vulnerable Lua code, as well as the testing setups used in our experiments in form of virtual and completely reproducible environments. We hope our work can spark additional and renewed interest in this apparently overlooked area of language security and static analysis, as well as motivate community’s contribution to these open-source projects. The tool, the samples and the testing VM setups will be released and updated at http://lua.re and http://lua.rocks








## Policy and Compliance
------------



## RE
------------
[Flipping Bits and Opening Doors: Reverse Engineering the Linear Wireless Security DX Protocol](https://duo.com/blog/flipping-bits-and-opening-doors-reverse-engineering-the-linear-wireless-security-dx-protocol)

[Reverse Engineering of Proprietary Protocols, Tools and Techniques - Rob Savoye - FOSDEM 2009 ](https://www.youtube.com/watch?v=t3s-mG5yUjY)
* This talk is about reverse engineering a proprietary network protocol, and then creating my own implementation. The talk will cover the tools used to take binary data apart, capture the data, and techniques I use for decoding unknown formats. The protocol covered is the RTMP protocol used by Adobe flash, and this new implementation is part of the Gnash project.

[Jailbreaks and Pirate Tractors: Reverse Engineering Do’s and Don’ts](https://www.youtube.com/watch?v=8_mMTVsOM6Y)

[Multiple vulnerabilities found in the Dlink DWR-932B (backdoor, backdoor accounts, weak WPS, RCE ...)](https://pierrekim.github.io/blog/2016-09-28-dlink-dwr-932b-lte-routers-vulnerabilities.html)











## Red Team/Pentesting
------------

[Data Sound Modulation POC](https://github.com/iiamit/data-sound-poc)

[Goodbye Data, Hello Exfiltration - Itzik Kotler](https://www.youtube.com/watch?v=GwaIvm2HJKc)
* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
* [Slides](http://www.ikotler.org/GoodbyeDataHelloExfiltration_BSidesORL.pdf)

[Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)
* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.

[In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)
* In this session, we will reveal and demonstrate perfect exfiltration via indirect covert channels (i.e. the communicating parties don’t directly exchange network packets). This is a family of techniques to exfiltrate data (low throughput) from an enterprise in a manner indistinguishable from genuine traffic. Using HTTP and exploiting a byproduct of how some websites choose to cache their pages, we will demonstrate how data can be leaked without raising any suspicion. These techniques are designed to overcome even perfect knowledge and analysis of the enterprise network traffic.

[Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)

[A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)
* Covert channels are used for the secret transfer of information. Encryption only protects communication from being decoded by unauthorised parties, whereas covert channels aim to hide the very existence of the communication. Initially, covert channels were identified as a security threat on monolithic systems i.e. mainframes. More recently focus has shifted towards covert channels in computer network protocols. The huge amount of data and vast number of different protocols in the Internet seems ideal as a high-bandwidth vehicle for covert communication. This article is a survey of the existing techniques for creating covert channels in widely deployed network and application protocols. We also give an overview of common methods for their detection, elimination, and capacity limitation, required to improve security in future computer networks. 

[Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)
* [Covert Timing Channels Based on HTTP Cache Headers - Paper](scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)

[P4wnP1](https://github.com/mame82/P4wnP1)
* P4wnP1 is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W.






## Rootkits
------------





## SCADA
------------
[SCADA Strangelove or: How I Learned to Start Worrying and Love Nuclear Plants](https://www.youtube.com/watch?v=o2r7jbwTv6w)
* Modern civilization unconditionally depends on information systems. It is paradoxical but true that ICS/SCADA systems are the most insecure systems in the world. From network to application, SCADA is full of configuration issues and vulnerabilities. During our report, we will demonstrate how to obtain full access to a plant via:
* a sniffer and a packet generator; FTP and Telnet; Metasploit and oslq; a webserver and a browser; 
* About 20 new vulnerabilities in common SCADA systems including Simatic WinCC will be revealed.

[Introduction to Attacking ICS/SCADA Systems for Penetration Testers -GDS Sec](http://blog.gdssecurity.com/labs/2017/5/17/introduction-to-attacking-icsscada-systems-for-penetration-t.html)













## Social Engineering
------------





## System Internals
------------
[Waitfor - tehcnet](https://technet.microsoft.com/en-us/library/cc731613(v=ws.11).aspx?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&iid=22f4306f9238443891cea105281cfd3f&uid=150127534&nid=244+289476616)

[Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))

[Credential Providers in Windows 10 - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/mt158211(v=vs.85).aspx)

[Registering Network Providers and Credential Managers - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa379389(v=vs.85).aspx)

[Authentication Registry Keys - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374737(v=vs.85).aspx)
* When it installs a network provider, your application should create the registry keys and values described in this topic. These keys and values provide information to the MPR about the network providers installed on the system. The MPR checks these keys when it starts and loads the network provider DLLs that it finds.

[ICredentialProvider interface - msdn](https://msdn.microsoft.com/en-us/library/bb776042(v=vs.85).aspx)
* Exposes methods used in the setup and manipulation of a credential provider. All credential providers must implement this interface.

[Custom Credential Provider for Password Reset - blogs.technet](https://blogs.technet.microsoft.com/aho/2009/11/14/custom-credential-provider-for-password-reset/)

[](http://archive.msdn.microsoft.com/ShellRevealed/Release/ProjectReleases.aspx?ReleaseId=2871)

[V2 Credential Provider Sample - code.msdn](https://code.msdn.microsoft.com/windowsapps/V2-Credential-Provider-7549a730)
* Demonstrates how to build a v2 credential provider that makes use of the new capabilities introduced to credential provider framework in Windows 8 and Windows 8.1.

[Starting to build your own Credential Provider](https://blogs.msmvps.com/alunj/2011/02/21/starting-to-build-your-own-credential-provider/)
* If you’re starting to work on a Credential Provider (CredProv or CP, for short) for Windows Vista, Windows Server 2008, Windows Server 2008 R2 or Windows 7, there are a few steps I would strongly recommend you take, because it will make life easier for you.

[BCDEdit /dbgsettings - msdn](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542187(v=vs.85).aspx)

[Winlogon and Credential Providers](https://msdn.microsoft.com/en-us/library/windows/desktop/bb648647(v=vs.85).aspx)
* Winlogon is the Windows module that performs interactive logon for a logon session. Winlogon behavior can be customized by implementing and registering a Credential Provider.







## Threat Modeling & Analysis
------------


[Global Adversarial Capability Modeling](https://www.youtube.com/watch?v=56T3JN09SrY#t=41)



## Threat Hunting
------------



## Training
------------






## Web: 
------------
[WeasyPrint](http://weasyprint.org/)
* WeasyPrint is a visual rendering engine for HTML and CSS that can export to PDF. It aims to support web standards for printing. WeasyPrint is free software made available under a BSD license.

[Pen test and hack microsoft sql server (mssql)](http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/)

[Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)

[SQLi Lab lessons](https://github.com/Audi-1/sqli-labs)

[Introducing G-Scout](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/august/introducing-g-scout/)
* G-Scout is a tool to help assess the security of Google Cloud Platform (GCP) environment configurations. By leveraging the Google Cloud API, G-Scout automatically gathers a variety of configuration data and analyzes this data to determine security risks. It produces HTML output.
* [Google Cloud Platform Security Tool](https://github.com/nccgroup/G-Scout)

[API Security Checklist](https://github.com/shieldfy/API-Security-Checklist/blob/master/README.md)







## Wireless Stuff
------------
[Bluetooth Penetration Testing Framework - 2011](http://bluetooth-pentest.narod.ru/)

[Hacking Bluetooth connections - hackingandsecurity](https://hackingandsecurity.blogspot.com/2017/08/hacking-bluetooth-connections.html?view=timeslide)

[Wifi Tracking: Collecting the (probe) Breadcrumbs - David Switzer](https://www.youtube.com/watch?v=HzQHWUM8cNo)
* Wifi probes have provided giggles via Karma and Wifi Pineapples for years, but is there more fun to be had? Like going from sitting next to someone on a bus, to knowing where they live and hang out? Why try to MITM someone’s wireless device in an enterprise environment where they may notice — when getting them at their favorite burger joint is much easier. In this talk we will review ways of collecting and analyzing probes. We’ll use the resulting data to figure out where people live, their daily habits, and discuss uses (some nice, some not so nice) for this information. We’ll also dicuss how to make yourself a little less easy to track using these methods. Stingrays are price prohibitive, but for just tracking people’s movements.. this is cheap and easy.

[probemon](https://github.com/nikharris0/probemon)
* A simple command line tool for monitoring and logging 802.11 probe frames
