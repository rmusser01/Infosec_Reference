# Red Teaming & Explicitly Pen testing stuff



#### ToC
* Sort
* Talks/Videos
* Articles/Blogposts
* Papers
* Tools

### Sort


[PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)
* PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement.
* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)



#### End sort












--------------
### General

[Common Ground Part 1: Red Team History & Overview](https://www.sixdub.net/?p=705)

[Red Teaming Tips - Vincent Yiu](https://threatintel.eu/2017/06/03/red-teaming-tips-by-vincent-yiu/)

[Red Team Tips as posted by @vysecurity on Twitter](https://github.com/vysec/RedTips)

[Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
* Wiki to collect Red Team infrastructure hardening resources
* Accompanying Presentation: [Doomsday Preppers: Fortifying Your Red Team Infrastructure](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure)



--------------
### Talks/Videos

[Stupid RedTeamer Tricks - Laurent Desaulniers](https://www.youtube.com/watch?v=2g_8oHM0nwA&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=11)

[Abusing Webhooks for Command and Control - Dimitry Snezhkov](https://www.youtube.com/watch?v=1d3QCA2cR8o&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=12)

[Finding Diamonds in the Rough- Parsing for Pentesters](https://bluescreenofjeff.com/2016-07-26-finding-diamonds-in-the-rough-parsing-for-pentesters/)

[Hacking Corporate Em@il Systems - Nate Power](http://www.irongeek.com/i.php?page=videos/bsidescolumbus2016/offense04-hacking-corporate-emil-systems-nate-power)
* In this talk we will discuss current email system attack vectors and how these systems can be abused and leveraged to break into corporate networks. A penetration testing methodology will be discussed and technical demonstrations of attacks will be shown. Phases of this methodology include information gathering, network mapping, vulnerability identification, penetration, privilege escalation, and maintaining access. Methods for organizations to better protect systems will also be discussed.

[Looping Surveillance Cameras through Live Editing - Van Albert and Banks - Defcon23](https://www.youtube.com/watch?v=RoOqznZUClI)
* This project consists of the hardware and software necessary to hijack wired network communications. The hardware allows an attacker to splice into live network cabling without ever breaking the physical connection. This allows the traffic on the line to be passively tapped and examined. Once the attacker has gained enough knowledge about the data being sent, the device switches to an active tap topology, where data in both directions can be modified on the fly. Through our custom implementation of the network stack, we can accurately mimic the two devices across almost all OSI layers.
* We have developed several applications for this technology. Most notable is the editing of live video streams to produce a “camera loop,” that is, hijacking the feed from an Ethernet surveillance camera so that the same footage repeats over and over again. More advanced video transformations can be applied if necessary. This attack can be executed and activated with practically no interruption in service, and when deactivated, is completely transparent.

[Sniffing Sunlight - Erik Kamerling - ANYCON2017](http://www.irongeek.com/i.php?page=videos/anycon2017/102-sniffing-sunlight-erik-kamerling)
* Laser listening devices (laser microphones) are a well understood technology. They have historically been used in the surreptitious surveillance of protected spaces. Using such a device, an attacker bounces an infrared laser off of a reflective surface, and receives the ricocheted beam with a photoreceptor. If the beam is reflected from a surface that is vibrating due to sound (voice is a typical background target), that sound is subsequently modulated into the beam and can be demodulated at the receptor. This is a known attack method and will be briefly discussed. However, does this principle also hold for non-amplified or naturally concentrated light sources? Can one retrieve modulated audio from reflected sunlight? The idea of modulating voice with sunlight was pioneered by Alexander Graham Bell in 1880 with an invention called the Photophone. A Photophone uses the audio modulation concept now used in laser microphones, but relied on a concentrated beam of sunlight rather than a laser to communicate at distance. Considering that Bell proved that intentionally concentrated sunlight can be used to modulate voice, we will explore under what natural conditions modulated audio can be found in reflected ambient light. Using off the shelf solar-cells and handmade amplifiers, Erik will demonstrate the use of the receiver side of a historic Photophone to identify instances of modulated audio in reflected light under common conditions.

[Hillbilly Storytime - Pentest Fails - Adam Compton](https://www.youtube.com/watch?v=GSbKeTPv2TU)
* Whether or not you are just starting in InfoSec, it is always important to remember that mistakes happen, even to the best and most seasoned of analysts. The key is to learn from your mistakes and keep going. So, if you have a few minutes and want to talk a load off for a bit, come and join in as a hillbilly spins a yarn about a group unfortunate pentesters and their misadventures. All stories and events are true (but the names have been be changed to prevent embarrassment).

[88MPH Digital tricks to bypass Physical security - ZaCon4 - Andrew MacPherson](https://vimeo.com/52865794)

[Building A Successful Internal Adversarial Simulation Team - C. Gates & C. Nickerson - BruCON 0x08](https://www.youtube.com/watch?v=Q5Fu6AvXi_A&list=PLtb1FJdVWjUfCe1Vcj67PG5Px8u1VY3YD&index=1)

[A  Year In The Red by Dominic Chell and Vincent Yiu - BSides Manchester2017](https://www.youtube.com/watch?v=-FQgWGktYtw&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP&index=23)

[Attacking EvilCorp: Anatomy of a Corporate Hack](http://www.irongeek.com/i.php?page=videos/derbycon6/111-attacking-evilcorp-anatomy-of-a-corporate-hack-sean-metcalf-will-schroeder)

[Hacks Lies Nation States - Mario DiNatale](https://www.youtube.com/watch?v=nyh_ORq1Qwk)

[The Impact of Dark Knowledge and Secrets on Security and Intelligence Professionals - Richard Thieme](https://www.youtube.com/watch?v=0MzcPBAj88A&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe)
* Dismissing or laughing off concerns about what it does to a person to know critical secrets does not lessen the impact on life, work, and relationships of building a different map of reality than “normal people” use. One has to calibrate narratives to what another believes. One has to live defensively, warily. This causes at the least cognitive dissonance which some manage by denial. But refusing to feel the pain does not make it go away. It just intensifies the consequences when they erupt. Philip K. Dick said, reality is that which, when you no longer believe in it, does not go away. When cognitive dissonance evolves into symptoms of traumatic stress, one ignores those symptoms at one’s peril. But the very constraints of one’s work often make it impossible to speak aloud about those symptoms, because that might threaten one’s clearances, work, and career. And whistle blower protection is often non-existent.










--------------
### Slides

[Make It Count: Progressing through Pentesting - Bálint Varga-Perke -Silent Signal](https://silentsignal.hu/docs/Make_It_Count_-_Progressing_through_Pentesting_Balint_Varga-Perke_Silent_Signal.pdf)

[Pen Testing a City](https://www.blackhat.com/docs/us-15/materials/us-15-Conti-Pen-Testing-A-City-wp.pdf)

[Implanting a Dropcam](https://www.defcon.org/images/defcon-22/dc-22-presentations/Moore-Wardle/DEFCON-22-Colby-Moore-Patrick-Wardle-Synack-DropCam-Updated.pdf)

--------------
### Articles / Blogposts

[Fools of Golden Gate](https://blog.silentsignal.eu/2017/05/08/fools-of-golden-gate/)
* How major vulnerabilities/large amounts of publicly vulnerable systems can exist without public recognition for long periods of time. (i.e. CVEs(10.0) exist, but no mapping in nessus/metasploit/etc)

[how-to-make-communication-profiles-for-empire](https://github.com/bluscreenofjeff/bluscreenofjeff.github.io/blob/master/_posts/2017-03-01-how-to-make-communication-profiles-for-empire.md)

[Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)

[#OLEOutlook - bypass almost every Corporate security control with a point’n’click GUI](https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0)

[Penetration Testing considered Harmful Today](http://blog.thinkst.com/p/penetration-testing-considered-harmful.html)

[Offensive Encrypted Data Storage](http://www.harmj0y.net/blog/redteaming/offensive-encrypted-data-storage/)

[Offensive Encrypted Data Storage (DPAPI edition)](https://posts.specterops.io/offensive-encrypted-data-storage-dpapi-edition-adda90e212ab)





--------------
### Papers
[Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/papers/fronting/)

[Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)

[Command & Control: Understanding, Denying and Detecting - 2014](https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf)
* Joseph Gardiner, Marco Cova, Shishir Nagaraja

[Project Loki - Phrack 7-49](http://phrack.org/issues/49/6.html)
* This whitepaper is intended as a complete description of the covert channel that exists in networks that allow ping traffic (hereon referred to in the more general sense of ICMP_ECHO traffic --see below) to pass.

[Software Distribution Malware Infection Vector](https://dl.packetstormsecurity.net/papers/general/Software.Distribution.Malware.Infection.Vector.pdf)



--------------
### Tools

[PenTesting-Scripts - killswitch-GUI](https://github.com/killswitch-GUI/PenTesting-Scripts)

[stupid_malware](https://github.com/andrew-morris/stupid_malware)
* Python malware for pentesters that bypasses most antivirus (signature and heuristics) and IPS using sheer stupidity

[Dragon: A Windows, non-binding, passive download / exec backdoor](http://www.shellntel.com/blog/2015/6/11/dragon-a-windows-non-binding-passive-downloadexec-backdoor)

[knit_brute.sh](https://gist.github.com/ropnop/8711392d5e1d9a0ba533705f7f4f455f)
* A quick tool to bruteforce an AD user's password by requesting TGTs from the Domain Controller with 'kinit'

[PlugBot-C2C](https://github.com/redteamsecurity/PlugBot-C2C)
* This is the Command & Control component of the PlugBot project




--------------
##### HW
[DigiDucky - How to setup a Digispark like a rubber ducky](http://www.redteamr.com/2016/08/digiducky/)

[How to Build Your Own Penetration Testing Drop Box - BHIS](https://www.blackhillsinfosec.com/?p=5156&)

[P4wnP1](https://github.com/mame82/P4wnP1)
* P4wnP1 is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W.






--------------
###### SW

[Domain Hunter](https://github.com/minisllc/domainhunter)
* Checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names

[Chameleon](https://github.com/mdsecactivebreach/Chameleon)
* A tool for evading Proxy categorisation



--------------
### Command & Control
[Expand Your Horizon Red Team – Modern SaaS C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)

[Expand Your Horizon Red Team – Modern SaaS C2 - Python WSGI C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)

[Empire – Modifying Server C2 Indicators](http://threatexpress.com/2017/05/empire-modifying-server-c2-indicators/)

[How to Build a 404 page not found C2](https://www.blackhillsinfosec.com/?p=5134)

[404 File not found C2 PoC](https://github.com/theG3ist/404)

[JSBN](https://github.com/Plazmaz/JSBN)
	* JSBN is a bot client which interprets commands through Twitter, requiring no hosting of servers or infected hosts from the command issuer. It is written purely in javascript as a Proof-of-Concept for javascript's botnet potentials.

[Spidernet](https://github.com/wandering-nomad/Spidernet)
	* Proof of Concept of SSH Botnet C&C Using Python 

[Pupy](https://github.com/n1nj4sec/pupy)
	* Pupy is an opensource, multi-platform Remote Administration Tool with an embedded Python interpreter. Pupy can load python packages from memory and transparently access remote python objects. Pupy can communicate using different transports and have a bunch of cool features & modules. On Windows, Pupy is a reflective DLL and leaves no traces on disk.

[OPSEC Considerations for Beacon Commands - CobaltStrike](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)

[twittor - twitter based backdoor](https://github.com/PaulSec/twittor)
	* A stealthy Python based backdoor that uses Twitter (Direct Messages) as a command and control server This project has been inspired by Gcat which does the same but using a Gmail account.

[Command and Control Using Active Directory](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)


### Domain Fronting

[FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains)
* Search for potential frontable domains

[High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)

[Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/talks/fronting-pets2015/)

[Camouflage at encryption layer: domain fronting](https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/)

[Domain Fronting - Infosec Institute](http://resources.infosecinstitute.com/domain-fronting/)





--------------
### Egress

#### Talks

[DIY Spy Covert Channels With Scapy And Python - Jen Allen - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/diy-spy-covert-channels-with-scapy-and-python-jen-allen)

[Goodbye Data, Hello Exfiltration - Itzik Kotler](https://www.youtube.com/watch?v=GwaIvm2HJKc)
* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
* [Slides](http://www.ikotler.org/GoodbyeDataHelloExfiltration_BSidesORL.pdf)

[Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)
* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.

[In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)
* In this session, we will reveal and demonstrate perfect exfiltration via indirect covert channels (i.e. the communicating parties don’t directly exchange network packets). This is a family of techniques to exfiltrate data (low throughput) from an enterprise in a manner indistinguishable from genuine traffic. Using HTTP and exploiting a byproduct of how some websites choose to cache their pages, we will demonstrate how data can be leaked without raising any suspicion. These techniques are designed to overcome even perfect knowledge and analysis of the enterprise network traffic.

[How To Bypass Email Gateways Using Common Payloads by Neil Lines - BSides Manchester2017](https://www.youtube.com/watch?v=eZxWDCetqkE&index=11&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)


#### Tools

[Data Sound Modulation POC](https://github.com/iiamit/data-sound-poc)


#### Writeups

[Egressing Bluecoat with CobaltStike & Let's Encrypt](https://cybersyndicates.com/2016/12/egressing-bluecoat-with-cobaltstike-letsencrypt/)

[Hiding Malicious Traffic Under the HTTP 404 Error](https://blog.fortinet.com/2015/04/09/hiding-malicious-traffic-under-the-http-404-error)

[Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)

[A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)
* Covert channels are used for the secret transfer of information. Encryption only protects communication from being decoded by unauthorised parties, whereas covert channels aim to hide the very existence of the communication. Initially, covert channels were identified as a security threat on monolithic systems i.e. mainframes. More recently focus has shifted towards covert channels in computer network protocols. The huge amount of data and vast number of different protocols in the Internet seems ideal as a high-bandwidth vehicle for covert communication. This article is a survey of the existing techniques for creating covert channels in widely deployed network and application protocols. We also give an overview of common methods for their detection, elimination, and capacity limitation, required to improve security in future computer networks.

[Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)
* [Covert Timing Channels Based on HTTP Cache Headers - Paper](https://scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)



--------------
### Persistence

[Staying Persistent in Software Defined Networks](https://www.blackhat.com/docs/us-15/materials/us-15-Pickett-Staying-Persistent-In-Software-Defined-Networks-wp.pdf)

[Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)

[Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.


--------------
### Code Injection


[injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.

[Inject All the Things - Shut up and hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)




--------------
### Domain Reputation Check
Domain Reputation Sites
* [Alien Vault](http://www.alienvault.com)
* [Isithacked?](http://www.isithacked.com)
* [Robtex](https://dns.robtex.com)
* [Scan4You](http://scan4you.net/)
* [Sucuri](http://sitecheck.sucuri.net/scanner/)
* [Trustedsource](http://www.trustedsource.org/)
* [urlQuery](http://urlquery.net/search.php)
* [URLVoid](http://www.urlvoid.com/scan/)
* [VirusTotal](https://www.virustotal.com/)
* [WOT](http://www.mywot.com/en/scorecard)
* [Zeltser BL](http://zeltser.com)


--------------
### Pen Testing X

#### AIX
[AIX for Penetration Testers 2017 thevivi.net](https://thevivi.net/2017/03/19/aix-for-penetration-testers/)









