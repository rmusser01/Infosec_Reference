# Red Teaming/Adversary Simulation/Explicitly Pen testing stuff



### Table of Contents
* [General](#general)
* [Talks]()
* [Cobalt Strike](#cobalt)
* [Command and Control](#cnc)
* [Domains](#domains)
* [Egress](#egress)
* [Empire](#empire)
* [Hardware](#hw)
* [Infrastructure](#infra)
* [Payloads](#payload)
* [Persistence](#persist)
* [Tactics](#tactics)
* [Pen Testing X](#)
	* * [AIX](#aix)
	* * [Embedded](#embedded)
	* * [MainFrames](#main)
	* * [SCADA/PLCs](#scada)
	* * [Virtual Appliances](#va)

### Sort
To Do
* Sort articles better
* [PenTesting-Scripts - killswitch-GUI](https://github.com/killswitch-GUI/PenTesting-Scripts)
* [Software Distribution Malware Infection Vector](https://dl.packetstormsecurity.net/papers/general/Software.Distribution.Malware.Infection.Vector.pdf)
* [File Server Triage on Red Team Engagements](http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/)
* [Full Contact Recon int0x80 of Dual Core savant - Derbycon7](https://www.youtube.com/watch?v=XBqmvpzrNfs)
* [Advanced Threat Analytics Attack Simulation Playbook - Microsoft](https://gallery.technet.microsoft.com/Advanced-Threat-Analytics-8b0a86bc)
* [Week of Evading Microsoft ATA - Announcement and Day 1 to Day 5](http://www.labofapenetrationtester.com/2017*8/week-of-evading-microsoft-ata-day1.html)

https://github.com/mainframed/

* [Using an Expandedf Cyber Kill Chain Model to Increase Attack Resiliency - Sean Malone - BHUSA16](https://www.youtube.com/watch?v=1Dz12M7u-S8)
	* We'll review what actions are taken in each phase, and what's necessary for the adversary to move from one phase to the next. We'll discuss multiple types of controls that you can implement today in your enterprise to frustrate the adversary's plan at each stage, to avoid needing to declare "game over" just because an adversary has gained access to the internal network. The primary limiting factor of the traditional Cyber Kill Chain is that it ends with Stage 7: Actions on Objectives, conveying that once the adversary reaches this stage and has access to a system on the internal network, the defending victim has already lost. In reality, there should be multiple layers of security zones on the internal network, to protect the most critical assets. The adversary often has to move through numerous additional phases in order to access and manipulate specific systems to achieve his objective. By increasing the time and effort required to move through these stages, we decrease the likelihood of the adversary causing material damage to the enterprise. 
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Malone-Using-An-Expanded-Cyber-Kill-Chain-Model-To-Increase-Attack-Resiliency.pdf)

* [Implanting a Dropcam](https://www.defcon.org/images/defcon-22/dc-22-presentations/Moore-Wardle/DEFCON-22-Colby-Moore-Patrick-Wardle-Synack-DropCam-Updated.pdf)
* [Stealthy Dopant-Level Hardware Trojans](Hardware level trojans http://sharps.org/wp-content/uploads/BECKER-CHES.pdf)
	* Abstract: In this paper we propose an extremely stealthy approach for implementing hardware Trojans below the gate level, and we evaluate their impact on the security of the target device. Instead of adding additional circuitry to the target design, we insert our hardware Trojans by changing the dopant polarity of existing transistors. Since the modied circuit ap- pears legitimate on all wiring layers (including all metal and polysilicon), our family of Trojans is resistant to most detection techniques, including negrain optical inspection and checking against \golden chips". We demonstrate the e ectiveness of our approach by inserting Trojans into two designs | a digital post-processing derived from Intel's cryptographically secure RNG design used in the Ivy Bridge processors and a side-channel resistant SBox implementation | and by exploring their detectability and their effects on security.
* [Implementation and Implications of a Stealth Hard-Drive Backdoor](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf) 
	* Modern workstations and servers implicitly trust hard disks to act as well-behaved block devices. This paper analyzes the catastrophic loss of security that occurs when hard disks are not trustworthy. First, we show that it is possible to compromise the firmware of a commercial ovt-the-shelf hard drive, by resorting only to public information and reverse engineering. Using such a compromised firmware, we present a stealth rootkit that replaces arbitrary blocks from the disk while they are written, providing a data replacement back- door . The measured performance overhead of the compromised disk drive is less than 1% compared with a normal, non-malicious disk drive. We then demonstrate that a re- mote attacker can even establish a communication channel with a compromised disk to infiltrate commands and to ex-filtrate data. In our example, this channel is established over the Internet to an unmodified web server that relies on the compromised drive for its storage, passing through the original webserver, database server, database storage engine, filesystem driver, and block device driver. Additional experiments, performed in an emulated disk-drive environment, could automatically extract sensitive data such as /etc/shadow (or a secret key le) in less than a minute. This paper claims that the diffculty of implementing such an at- tack is not limited to the area of government cyber-warfare; rather, it is well within the reach of moderately funded criminals, botnet herders and academic researchers.
* [Inside a low budget consumer hardware espionage implant](https://ha.cking.ch/s8_data_line_locator/)

* [USB teensy attack set OSX](http://samy.pl/usbdriveby/)
* [Paensy](https://github.com/Ozuru/Paensy)
	* Paensy is a combination of the word payload and Teensy - Paensy is an attacker-oriented library written for the development of Teensy devices. Paensy simplifies mundane tasks and allows an easier platform for scripting.
	* [Blogpost](http://malware.cat/?p=89)


	
#### End sort




--------------
### <a name="general"></a>General
* **101/Educational**
	* [Red Team - Wikipedia](https://en.m.wikipedia.org/wiki/Red_team)
	* [Common Ground Part 1: Red Team History & Overview](https://www.sixdub.net/?p=705)
	* [Target Analysis - Wikipedia](https://en.wikipedia.org/wiki/Target_analysis)
	* [Center of Gravity Analysis - Dale C. Eikmeier](http://www.au.af.mil/au/awc/awcgate/milreview/eikmeier.pdf)
		* Center of Gravity: A system's source of power to act.
	* [A Tradecraft Primer: Structured Analytic Techniques for Improving Intelligence Analysis - USGov 2009](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/Tradecraft%20Primer-apr09.pdf)
* **Courses**
	* [Advanced Threat Tactics – Course and Notes - CobaltStrike](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/)
* **General Informative Information**
	* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
		* Wiki to collect Red Team infrastructure hardening resources
		* Accompanying Presentation: [Doomsday Preppers: Fortifying Your Red Team Infrastructure](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure)
	* [Fools of Golden Gate](https://blog.silentsignal.eu/2017/05/08/fools-of-golden-gate/)
		* How major vulnerabilities/large amounts of publicly vulnerable systems can exist without public recognition for long periods of time. (i.e. CVEs(10.0) exist, but no mapping in nessus/metasploit/etc)
	* [Red Teaming and the Adversarial Mindset: Have a Plan, Backup Plan and Escape Plan - ITS](https://www.itstactical.com/digicom/security/red-teaming-and-the-adversarial-mindset-have-a-plan-backup-plan-and-escape-plan/)
	* [Raphael’s Magic Quadrant - Mudge](https://blog.cobaltstrike.com/2015/08/03/raphaels-magic-quadrant/)
	* [RAT - Repurposing Adversarial Tradecraft - killswitch_GUI](https://speakerdeck.com/killswitch_gui/rat-repurposing-adversarial-tradecraft)
	* [Penetration Testing considered Harmful Today](http://blog.thinkst.com/p/penetration-testing-considered-harmful.html)
	* [Planning a Red Team exercise](https://github.com/magoo/redteam-plan)
	* [Planning Effective Red Team Exercises - Sean T Malone - BSidesSF2016](https://www.youtube.com/watch?v=cD-jKBfSKP4)
		* An effective red team exercise is substantially different from a penetration test, and it should be chartered differently as well. The scenario, objective, scope, and rules of engagement all need to be positioned correctly at the beginning in order to most closely simulate a real adversary and provide maximum value to the client.In this presentation, we'll review best practices in each of these areas, distilled from conducting dozens of successful red team exercises - along with some war stories highlighting why each element matters. Those in offensive security will gain an understanding of how to manage the client's expectations for this process, and how to guide them towards an engagement that provides a realistic measurement of their ability to prevent, detect, and respond to real attacks. Those in enterprise security will gain a deeper understanding of this style of assessment, and how to work with a red team to drive real improvement in their security programs. 

* **Educational(Specific Tactics/Techniques/Misc)**
	* [#OLEOutlook - bypass almost every Corporate security control with a point’n’click GUI](https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0)
	* [Offensive Encrypted Data Storage](http://www.harmj0y.net/blog/redteaming/offensive-encrypted-data-storage/)
	* [Offensive Encrypted Data Storage (DPAPI edition)](https://posts.specterops.io/offensive-encrypted-data-storage-dpapi-edition-adda90e212ab)
	* [Goodbye OODA Loop](http://armedforcesjournal.com/goodbye-ooda-loop/)
	* [Planning a Red Team exercise](https://github.com/magoo/redteam-plan)
	* [Some Comments and Thoughts on Tradecraft](https://www.darkoperator.com/blog/2017/11/20/some-comments-and-thoughts-on-tradecraft)
	* [Stupid RedTeamer Tricks - Laurent Desaulniers](https://www.youtube.com/watch?v=2g_8oHM0nwA&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=11)
	* [Abusing Webhooks for Command and Control - Dimitry Snezhkov](https://www.youtube.com/watch?v=1d3QCA2cR8o&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=12)
	* [Looping Surveillance Cameras through Live Editing - Van Albert and Banks - Defcon23](https://www.youtube.com/watch?v=RoOqznZUClI)
		* This project consists of the hardware and software necessary to hijack wired network communications. The hardware allows an attacker to splice into live network cabling without ever breaking the physical connection. This allows the traffic on the line to be passively tapped and examined. Once the attacker has gained enough knowledge about the data being sent, the device switches to an active tap topology, where data in both directions can be modified on the fly. Through our custom implementation of the network stack, we can accurately mimic the two devices across almost all OSI layers. We have developed several applications for this technology. Most notable is the editing of live video streams to produce a “camera loop,” that is, hijacking the feed from an Ethernet surveillance camera so that the same footage repeats over and over again. More advanced video transformations can be applied if necessary. This attack can be executed and activated with practically no interruption in service, and when deactivated, is completely transparent.
	* [Sniffing Sunlight - Erik Kamerling - ANYCON2017](http://www.irongeek.com/i.php?page=videos/anycon2017/102-sniffing-sunlight-erik-kamerling)
		* Laser listening devices (laser microphones) are a well understood technology. They have historically been used in the surreptitious surveillance of protected spaces. Using such a device, an attacker bounces an infrared laser off of a reflective surface, and receives the ricocheted beam with a photoreceptor. If the beam is reflected from a surface that is vibrating due to sound (voice is a typical background target), that sound is subsequently modulated into the beam and can be demodulated at the receptor. This is a known attack method and will be briefly discussed. However, does this principle also hold for non-amplified or naturally concentrated light sources? Can one retrieve modulated audio from reflected sunlight? The idea of modulating voice with sunlight was pioneered by Alexander Graham Bell in 1880 with an invention called the Photophone. A Photophone uses the audio modulation concept now used in laser microphones, but relied on a concentrated beam of sunlight rather than a laser to communicate at distance. Considering that Bell proved that intentionally concentrated sunlight can be used to modulate voice, we will explore under what natural conditions modulated audio can be found in reflected ambient light. Using off the shelf solar-cells and handmade amplifiers, Erik will demonstrate the use of the receiver side of a historic Photophone to identify instances of modulated audio in reflected light under common conditions.
	* [Red Teaming Back and Forth 5ever Fuzzynop - Derbycon4](https://www.youtube.com/watch?time_continue=6&v=FTiBwFJQg64)
	* [Advanced Red Teaming: All Your Badges Are Belong To Us - DEF CON 22 - Eric Smith and Josh Perrymon](https://www.youtube.com/watch?v=EEGxifOAk48)
	* [Operating in the Shadows Carlos Perez - Derbycon5](https://www.youtube.com/watch?v=NXTr4bomAxk)
	* [Building a Better Moat: Designing an Effective Covert Red Team Attack Infrastructure - @bluescreenofjeff](https://speakerdeck.com/bluscreenofjeff/building-a-better-moat-designing-an-effective-covert-red-team-attack-infrastructure)
	* [88MPH Digital tricks to bypass Physical security - ZaCon4 - Andrew MacPherson](https://vimeo.com/52865794)
	* [Attacking EvilCorp: Anatomy of a Corporate Hack](http://www.irongeek.com/i.php?page=videos/derbycon6/111-attacking-evilcorp-anatomy-of-a-corporate-hack-sean-metcalf-will-schroeder)
	* [Detect Me If You Can Ben Ten - Derbycon7](https://www.youtube.com/watch?v=AF3arWoKfKg&index=23&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
	* [Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
		* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.
* **Red Team Experiences**
	* [Passing the Torch: Old School Red Teaming, New School Tactics?](https://www.slideshare.net/harmj0y/derbycon-passing-the-torch)
	* [Red Teaming Tips - Vincent Yiu](https://threatintel.eu/2017/06/03/red-teaming-tips-by-vincent-yiu/)
	* [Red Team Tips as posted by @vysecurity on Twitter](https://github.com/vysec/RedTips)
	* [Red Teams - Facebook Experiences Writeup - Ryan McGeehan](https://medium.com/starting-up-security/red-teams-6faa8d95f602)
	* [Reflections from a Red Team Leader - Susan Craig](http://usacac.army.mil/CAC2/MilitaryReview/Archives/English/MilitaryReview_20070430_art011.pdf)
	* [Red Teaming: Using Cutting-Edge Threat Simulation to Harden the Microsoft Enterprise Cloud](https://azure.microsoft.com/en-us/blog/red-teaming-using-cutting-edge-threat-simulation-to-harden-the-microsoft-enterprise-cloud/)
	* [10 Red Teaming Lessons Learned over 20 Years](https://redteamjournal.com/2015/10/10-red-teaming-lessons-learned-over-20-years/)
	* [Red team versus blue team: How to run an effective simulation - CSOonline](https://www.csoonline.com/article/2122440/disaster-recovery/emergency-preparedness-red-team-versus-blue-team-how-to-run-an-effective-simulation.html)
	* [Red Teaming for Pacific Rim CCDC 2017](https://bluescreenofjeff.com/2017-05-02-red-teaming-for-pacific-rim-ccdc-2017/)
	* [How I Prepared to Red Team at PRCCDC 2015](https://bluescreenofjeff.com/2015-04-15-how-i-prepared-to-red-team-at-prccdc-2015/)
	* [Red Teaming for Pacific Rim CCDC 2016](https://bluescreenofjeff.com/2016-05-24-pacific-rim-ccdc_2016/)
	* [Red Teaming Windows: Building a better Windows by hacking it - MS Ignite2017](https://www.youtube.com/watch?v=CClpjtgaJVI)
	* [Breaking Red - Understanding Threats through Red Teaming - SANS Webcast](https://www.youtube.com/watch?v=QPmgV1SRTJY)
	* ['Red Team: How to Succeed By Thinking Like the Enemy' - Council on Foreign Relations - Micah Zenko](https://www.youtube.com/watch?v=BM2wYbu4EFY)
	* [Defenders, Bring Your 'A' Game](https://winterspite.com/security/defenders-bring-your-a-game/)
	* [The hidden horrors that 3 years of global red-teaming, Jos van der Peet](https://www.youtube.com/watch?v=7z63HrEiQUY&index=10&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
		* My last 3 years of global reteaming in small and large organisations has shown me that there still are a lot of misconceptions about security. We all know the ‘onion’ model for layered security. While useful for the ‘defence in depth’ principle, this talk will show that in reality, rather than an onion, security is more like a pyramid. The basis is the hardware people work on (laptops etc.) and the top your business applications. In between is everything else. Operating system, network components, proxies, shares, servers and their software stack. Like any hi-rise structure, the top cannot be secure if the base is not secure. Defence in depth matters, but it can be quite trivial for attackers to sidestep certain controls to get to the data they want. Just securing your ‘crown-jewels’ is insufficient. This talk will revolve around how we have defeated security controls on various levels, ranging from the systems your end-users work on, all the way through to 2FA and 4-eye principles on critical business assets. It will talk about common misconceptions which lull companies into a false sense of security, while making life far too easy for attackers. For example the fallacy of focussing security efforts only/mostly on ‘crown jewels’ and how misunderstanding of why certain controls are put in place jeopardize corporate and client data. The talk will be supported by real-life examples
	* [A  Year In The Red by Dominic Chell and Vincent Yiu - BSides Manchester2017](https://www.youtube.com/watch?v=-FQgWGktYtw&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP&index=23)
* **Papers**
	* [Red teaming - A Short Introduction (1.0) June 2009 - Mark Mateski](https://redteamjournal.com/papers/A%20Short%20Introduction%20to%20Red%20Teaming%20(1dot0).pdf)
	* [Red Teaming Guide - UK Ministry of Defense](https://www.gov.uk/government/uploads/system/uploads/attachment_data/file/142533/20130301_red_teaming_ed2.pdf)
	* [Red Team Handbook(2012) - University of Foreign Military And Cultural studies](http://www.au.af.mil/au/awc/awcgate/army/ufmcs_red_team_handbook_apr2012.pdf)
	* [Red Teaming of Advanced Information Assurance Concepts - Bradley Wood, Ruth Duggan](http://cs.uccs.edu/~gsc/pub/master/sjelinek/doc/research/red.pdf)
	* [A Guide To Red Teaming - NATO](http://www.act.nato.int/images/stories/events/2011/cde/rr_ukdcdc.pdf)
	* [Modeling and Simulation of Red Teaming - Part 1: Why Red Team M&S? - Michael J Skroch](https://redteamjournal.com/wp-content/uploads/2009/12/msrt0.3-2nov2009-sand2009-7215J.pdf)
	* [Moving Forward with Computational Red Teaming - Scott Wheeler - Australian DoD](http://www.dtic.mil/dtic/tr/fulltext/u2/a569437.pdf)
	* [Cyber Red Teaming  Organisational, technical and legal implications in a military context - NATO](https://ccdcoe.org/sites/default/files/multimedia/pdf/Cyber_Red_Team.pdf)
	* [Traditions In Military-Strategic Thought In Germany And The Problem Of Deterrence - 1989 - Detlef Bald](http://www.mgfa.de/html/einsatzunterstuetzung/downloads/ap018englisch.pdf?PHPSESSID=931748af0e86616800373655acaf2902)
	* [Force Protection and Suicide Bombers: The Necessity for Two Types of Canadian Military Red Teams](http://www.journal.forces.gc.ca/vol12/no4/page35-eng.asp)
	* [The Applied Critical Thinking Handbook(2015) - University of Foreign Military And Cultural studies](http://usacac.army.mil/sites/default/files/documents/ufmcs/The_Applied_Critical_Thinking_Handbook_v7.0.pdf)
	* [Preparing for the War of the Future in the Wake of Defeat: The Evolution of German Strategic Thought, 1919 - 1935 - Mark Shannon](https://www.ciaonet.org/attachments/25573/uploads)
	* [Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains](https://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf)		
	* [Ananalysis of the Metasploit Framework relative to the Penetration Testing Execution Standard(PTES) guidance(2011) - Brandon Perry](http://www.nothink.org/metasploit/documentation/metasploit_msf_analysis_ptes.pdf)







--------------
### <a name="talks"></a>Talks/Videos
* [Hacks Lies Nation States - Mario DiNatale](https://www.youtube.com/watch?v=nyh_ORq1Qwk)
* [The Impact of Dark Knowledge and Secrets on Security and Intelligence Professionals - Richard Thieme](https://www.youtube.com/watch?v=0MzcPBAj88A&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe)
	* Dismissing or laughing off concerns about what it does to a person to know critical secrets does not lessen the impact on life, work, and relationships of building a different map of reality than “normal people” use. One has to calibrate narratives to what another believes. One has to live defensively, warily. This causes at the least cognitive dissonance which some manage by denial. But refusing to feel the pain does not make it go away. It just intensifies the consequences when they erupt. Philip K. Dick said, reality is that which, when you no longer believe in it, does not go away. When cognitive dissonance evolves into symptoms of traumatic stress, one ignores those symptoms at one’s peril. But the very constraints of one’s work often make it impossible to speak aloud about those symptoms, because that might threaten one’s clearances, work, and career. And whistle blower protection is often non-existent.
* **Educational**
	* [Finding Diamonds in the Rough- Parsing for Pentesters](https://bluescreenofjeff.com/2016-07-26-finding-diamonds-in-the-rough-parsing-for-pentesters/)
	* [Hillbilly Storytime - Pentest Fails - Adam Compton](https://www.youtube.com/watch?v=GSbKeTPv2TU)
		* Whether or not you are just starting in InfoSec, it is always important to remember that mistakes happen, even to the best and most seasoned of analysts. The key is to learn from your mistakes and keep going. So, if you have a few minutes and want to talk a load off for a bit, come and join in as a hillbilly spins a yarn about a group unfortunate pentesters and their misadventures. All stories and events are true (but the names have been be changed to prevent embarrassment).
	* [Building A Successful Internal Adversarial Simulation Team - C. Gates & C. Nickerson - BruCON 0x08](https://www.youtube.com/watch?v=Q5Fu6AvXi_A&list=PLtb1FJdVWjUfCe1Vcj67PG5Px8u1VY3YD&index=1)
* Phishing
	* [Hacking Corporate Em@il Systems - Nate Power](http://www.irongeek.com/i.php?page=videos/bsidescolumbus2016/offense04-hacking-corporate-emil-systems-nate-power)
		* In this talk we will discuss current email system attack vectors and how these systems can be abused and leveraged to break into corporate networks. A penetration testing methodology will be discussed and technical demonstrations of attacks will be shown. Phases of this methodology include information gathering, network mapping, vulnerability identification, penetration, privilege escalation, and maintaining access. Methods for organizations to better protect systems will also be discussed.


--------------
### <a name="cobalt"></a>Cobalt Strike
* **Agressor Scripts**
	* [Aggressor Script - cs](https://www.cobaltstrike.com/aggressor-script/index.html)
	* [CS Aggressor Scripts - ramen0x3f](https://github.com/ramen0x3f/AggressorScripts#utilscna)
	[aggressor_scripts_collection - invokethreatguy](https://github.com/invokethreatguy/aggressor_scripts_collection)
		* Collection of various Aggressor Scripts for Cobalt Strike from awesome people. Will be sure to update this repo with credit to each person.
	* [Aggressor Scripts - oldb00t](https://github.com/oldb00t/AggressorScripts)
* **C2**
	* [Cobalt Strike External C2 Paper](https://www.cobaltstrike.com/downloads/externalc2spec.pdf)
	* [External C2 - cs](https://github.com/outflanknl/external_c2)
		* POC for Cobalt Strike external C2
	* [Cobalt Strike over external C2 – beacon home in the most obscure ways](https://outflank.nl/blog/2017/09/17/blogpost-cobalt-strike-over-external-c2-beacon-home-in-the-most-obscure-ways/)
	* [OPSEC Considerations for Beacon Commands - CobaltStrike](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
	* [Valid SSL Certificates with SSL Beacon - cs](https://www.cobaltstrike.com/help-malleable-c2#validssl)
	* [Randomized Malleable C2 Profiles Made Easy](https://bluescreenofjeff.com/2017-08-30-randomized-malleable-c2-profiles-made-easy/)
	* [OPSEC Considerations for beacon commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
	* [Agentless Post Exploitation](https://blog.cobaltstrike.com/2016/11/03/agentless-post-exploitation/)
* **Documentation**
	* [Malleable C2 Documenation - cs](https://www.cobaltstrike.com/help-malleable-c2)
* **Phishing**
	* [Cobalt Strike - Spear Phishing documentation](https://www.cobaltstrike.com/help-spear-phish)
	* [Spear phishing with Cobalt Strike - Raphael Mudge](https://www.youtube.com/watch?v=V7UJjVcq2Ao)
	* [Cobalt Strike Blog - What's the go-to phishing technique or exploit?](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
* **Other**
	* [ANGRYPUPPY](https://github.com/vysec/ANGRYPUPPY)
		* Bloodhound Attack Path Execution for Cobalt Strike
	* [Modern Defense and You - CS](https://blog.cobaltstrike.com/2017/10/25/modern-defenses-and-you/)
	* [User Driven Attacks - cs](https://blog.cobaltstrike.com/2014/10/01/user-driven-attacks/)
	* [DDEAutoCS](https://github.com/p292/DDEAutoCS)
		* A cobaltstrike script that integrates DDEAuto Attacks (launches a staged powershell CS beacon). This is not massively stealthy as far as CS scripts go anything like that at the moment, more of a proof of concept, and for having a play. Customise as you see fit to your needs.
	* [CSFM - Cobal Strike Field Manual](https://github.com/001SPARTaN/csfm)
		* Cobalt Strike Field Manual - A quick reference for Windows commands that can be accessed in a beacon console.





--------------
### <a name="cnc"></a>Command & Control
* **Communication Channel Example PoCs**
	* [Using WebSockets and IE/Edge for C2 communications](https://arno0x0x.wordpress.com/2017/11/10/https://github.com/leoloobeek/GoG reen/blob/master/README.mdusing-websockets-and-ie-edge-for-c2-communications/)
	* [Spidernet](https://github.com/wandering-nomad/Spidernet)
		* Proof of Concept of SSH Botnet C&C Using Python 
	* [twittor - twitter based backdoor](https://github.com/PaulSec/twittor)
		* A stealthy Python based backdoor that uses Twitter (Direct Messages) as a command and control server This project has been inspired by Gcat which does the same but using a Gmail account.
	* [Instegogram](https://github.com/endgameinc/instegogram)
	* [WSC2](https://github.com/Arno0x/WSC2)
		* WSC2 is a PoC of using the WebSockets and a browser process to serve as a C2 communication channel between an agent, running on the target system, and a controller acting as the actual C2 server.
* **PoCs**
	* [RemoteRecon](https://github.com/xorrior/RemoteRecon)
		* RemoteRecon provides the ability to execute post-exploitation capabilities against a remote host, without having to expose your complete toolkit/agent. Often times as operator's we need to compromise a host, just so we can keylog or screenshot (or some other miniscule task) against a person/host of interest. Why should you have to push over beacon, empire, innuendo, meterpreter, or a custom RAT to the target? This increases the footprint that you have in the target environment, exposes functionality in your agent, and most likely your C2 infrastructure. An alternative would be to deploy a secondary agent to targets of interest and collect intelligence. Then store this data for retrieval at your discretion. If these compromised endpoints are discovered by IR teams, you lose those endpoints and the information you've collected, but nothing more.
	* [Expand Your Horizon Red Team – Modern SaaS C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)
	* [JSBN](https://github.com/Plazmaz/JSBN)
		* JSBN is a bot client which interprets commands through Twitter, requiring no hosting of servers or infected hosts from the command issuer. It is written purely in javascript as a Proof-of-Concept for javascript's botnet potentials.
	* [Command and Control Using Active Directory](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
	* [PoshC2 v3 with SOCKS Proxy (SharpSocks)](https://labs.nettitude.com/blog/poshc2-v3-with-socks-proxy-sharpsocks/)
	* [Abusing "Accepted Risk" With 3rd Party C2 - HackMiamiCon5](https://www.slideshare.net/sixdub/abusing-accepted-risk-with-3rd-party-c2-hackmiamicon5)
	* [MurDock - Mutable Universal Relay Document Kit](https://github.com/themson/MurDocK)
		* The purpose of this tool is to provide a protocol independent framework that contains a base set of features that can piggyback on top of any collaborative web platform or service. The base docClient and docServer are meant to be extended upon with Buffer classes written for individual web services. These buffer classes can be plugged into the MurDock framework in order to create a unique shell infrastructure that will always contains a base set of features, as well as the ability to tunnel over any web application traffic for which a buffer class has been constructed. The framework can be extended to operate over lower level protocols if desired.
	[PoshC2](https://github.com/nettitude/PoshC2)
		* Powershell C2 Server and Implants
	[FruityC2](https://github.com/xtr4nge/FruityC2)
		* FruityC2 is a post-exploitation (and open source) framework based on the deployment of agents on compromised machines. Agents are managed from a web interface under the control of an operator.
	* [PlugBot-C2C](https://github.com/redteamsecurity/PlugBot-C2C)
		* This is the Command & Control component of the PlugBot project
	* [How to Build a 404 page not found C2](https://www.blackhillsinfosec.com/?p=5134)
	* [404 File not found C2 PoC](https://github.com/theG3ist/404)
	* [Command and Control Using Active Directory](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
	* [C2 with twitter](https://pentestlab.blog/2017/09/26/command-and-control-twitter/)
	* [C2 with DNS](https://pentestlab.blog/2017/09/06/command-and-control-dns/)
	* [ICMP C2](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
	* [C2 with Dropbox](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/)
	* [C2 with https](https://pentestlab.blog/2017/10/04/command-and-control-https/)
	* [C2 with webdav](https://pentestlab.blog/2017/09/12/command-and-control-webdav/)
	* [C2 with gmail](https://pentestlab.blog/2017/08/03/command-and-control-gmail/)
	* [C2 with ICMP](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
	* [C2 with Telegram](https://github.com/graniet/gshark-framework)
	* [“Tasking” Office 365 for Cobalt Strike C2](https://labs.mwrinfosecurity.com/blog/tasking-office-365-for-cobalt-strike-c2/)
	* [Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
	* [Using WebDAV features as a covert channel](https://arno0x0x.wordpress.com/2017/09/07/using-webdav-features-as-a-covert-channel/)
	* [A Guide to Configuring Throwback](https://silentbreaksecurity.com/throwback-thursday-a-guide-to-configuring-throwback/)
		* [Throwback - beacon](https://github.com/silentbreaksec/Throwback)
		* [Throwback Listener](https://github.com/silentbreaksec/ThrowbackLP)
	* [DBC2](https://github.com/Arno0x/DBC2)
		* DBC2 (DropboxC2) is a modular post-exploitation tool, composed of an agent running on the victim's machine, a controler, running on any machine, powershell modules, and Dropbox servers as a means of communication.
	* [External C2](https://github.com/ryhanson/ExternalC2)
		* A library for integrating communication channels with the Cobalt Strike External C2 server
	* [Galvatron](https://github.com/khr0x40sh/Galvatron)
		* Powershell fork of Monohard by Carlos Ganoza P. This botnet/backdoor was designed to egress over unecrypted web using very little, but effective obfuscation. Egress over ICMP and DNS are planned as features. Lastly, the server code is designed to setup the C2 on a LAMP-esque server. The default creds are admin/admin.
	* [Merlin](https://github.com/Ne0nd0g/merlin)
		* Merlin is a cross-platform post-exploitation HTTP/2 Command & Control  server and agent written in golang.
	* [emptynest](https://github.com/empty-nest/emptynest)
		* Emptynest is a plugin based C2 server framework. The goal of this project is not to replace robust tools such as Empire, Metasploit, or Cobalt Strike. Instead, the goal is to create a supporting framework for quickly creating small, purpose built handlers for custom agents. No agent is provided. Users of Emptynest should create their own agents that implement minimal functionality and can be used to evade detection and establish a more robust channel. An example of an agent might support Unhooking, DLL Unloading, and code execution. Due to the simple nature of this project, it is recommended that agents be kept private.
	* [CheckPlease](https://github.com/Arvanaghi/CheckPlease)
		* Implant-Security modules written in PowerShell, Python, Go, Ruby, C, C#, Perl, and Rust. 
	* [ThunderShell](https://github.com/Mr-Un1k0d3r/ThunderShell)
		* ThunderShell is a Powershell based RAT that rely on HTTP request to communicate. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network hooks.
	* [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell)
		* A Powershell client for dnscat2, an encrypted DNS command and control tool
	* [WMImplant](https://github.com/ChrisTruncer/WMImplant)
		* WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines, but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
	* [DNS-Persist](https://github.com/0x09AL/DNS-Persist)
		* DNS-Persist is a post-exploitation agent which uses DNS for command and control. The server-side code is in Python and the agent is coded in C++.
	* [BrainDamage](https://github.com/mehulj94/BrainDamage)
		* A fully featured backdoor that uses Telegram as a C&C server
	* [EggShell](https://github.com/neoneggplant/EggShell)
		* EggShell is an iOS and macOS post exploitation surveillance pentest tool written in Python. This tool creates 1 line multi stage payloads that give you a command line session with extra functionality. EggShell gives you the power and convenience of uploading/downloading files, taking pictures, location tracking, shell command execution, persistence, escalating privileges, password retrieval, and much more. Server communication features end to end encryption with 128 bit AES and the ability to handle multiple clients. This is a proof of concept pentest tool, intended for use on machines you own.
		* [EggShell Blogpost](http://lucasjackson.me/dWkKX/index.php/eggshell)
	* [Pacdoor](https://github.com/SafeBreach-Labs/pacdoor)
		* Pacdoor is a proof-of-concept JavaScript malware implemented as a Proxy Auto-Configuration (PAC) File. Pacdoor includes a 2-way communication channel, ability to exfiltrate HTTPS URLs, disable access to cherry-picked URLs etc.
* **Papers**
	* [Command & Control: Understanding, Denying and Detecting - 2014 - Joseph Gardiner, Marco Cova, Shishir Nagaraja](https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf)

	
### <a name="domains"></a>Domains
* **Domain Fronting**
	* [FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains)
		* Search for potential frontable domains
	* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
	* [Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/talks/fronting-pets2015/)
	* [Camouflage at encryption layer: domain fronting](https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/)
	* [Domain Fronting - Infosec Institute](http://resources.infosecinstitute.com/domain-fronting/)
	* [Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
		* In this entry we continue with domain fronting; on this occasion we will explore how to implement a simple PoC of a command and control and exfiltration server on Google App Engine (GAE), and we will see how to do the domain fronting from Windows, with a VBS or PowerShell script, to hide interactions with the C2 server.
	* [TOR Fronting – Utilising Hidden Services for Privacy](https://www.mdsec.co.uk/2017/02/tor-fronting-utilising-hidden-services-for-privacy/)
	* [Finding Domain frontable Azure domains - thoth / Fionnbharr (@a_profligate)](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
	* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)
	* [Domain Fronting Via Cloudfront Alternate Domains](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
* **Domain Tools**
	* [Domain Hunter](https://github.com/minisllc/domainhunter)
		* Checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names
	* [AIRMASTER](https://github.com/t94j0/AIRMASTER)
		* Use ExpiredDomains.net and BlueCoat to find useful domains for red team.
	* [Chameleon](https://github.com/mdsecactivebreach/Chameleon)
		* A tool for evading Proxy categorisation
	* [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish)
		* Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C.  It relies on expireddomains.net to obtain a list of expired domains. The domain availability is validated using checkdomain.com
	* [Finding Frontable Domain](https://github.com/rvrsh3ll/FindFrontableDomains)
* **Domain Reputation Sites**
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
* Redirectors
	* [Apache2Mod Rewrite Setup](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup)
	* [Redirecting Cobalt Strike DNS Beacons](http://www.rvrsh3ll.net/blog/offensive/redirecting-cobalt-strike-dns-beacons/)
	* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
	* [Cobalt Strike HTTP C2 Redirectors with Apache mod_rewrite - Jeff Dimmock](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)








### <a name="egress"></a>Egress/Exfiltration
* **Articles**
	* [Practical Comprehensive Bounds on Surreptitious Communication Over DNS](http://www.icir.org/vern/papers/covert-dns-usec13.pdf)
	* [Exfiltration by encoding data in pixel colour values](https://www.pentestpartners.com/security-blog/exfiltration-by-encoding-data-in-pixel-colour-values/)
	* [Data Sound Modulation POC](https://github.com/iiamit/data-sound-poc)
	* [Hiding Malicious Traffic Under the HTTP 404 Error](https://blog.fortinet.com/2015/04/09/hiding-malicious-traffic-under-the-http-404-error)
	* [Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)
	* [A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)
		* Covert channels are used for the secret transfer of information. Encryption only protects communication from being decoded by unauthorised parties, whereas covert channels aim to hide the very existence of the communication. Initially, covert channels were identified as a security threat on monolithic systems i.e. mainframes. More recently focus has shifted towards covert channels in computer network protocols. The huge amount of data and vast number of different protocols in the Internet seems ideal as a high-bandwidth vehicle for covert communication. This article is a survey of the existing techniques for creating covert channels in widely deployed network and application protocols. We also give an overview of common methods for their detection, elimination, and capacity limitation, required to improve security in future computer networks.
	* [Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)
	* [Covert Timing Channels Based on HTTP Cache Headers - Paper](https://scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)
	* [Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/papers/fronting/)
	* [Egressing Bluecoat with CobaltStike & Let's Encrypt](https://cybersyndicates.com/2016/12/egressing-bluecoat-with-cobaltstike-letsencrypt/)
	* [Project Loki - Phrack 7-49](http://phrack.org/issues/49/6.html)
		* This whitepaper is intended as a complete description of the covert channel that exists in networks that allow ping traffic (hereon referred to in the more general sense of ICMP_ECHO traffic --see below) to pass.
	* [Escape and Evasion Egressing Restricted Networks - Tom Steele and Chris Patten](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks)
* **Talks**
	* [DIY Spy Covert Channels With Scapy And Python - Jen Allen - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/diy-spy-covert-channels-with-scapy-and-python-jen-allen)
	* [Goodbye Data, Hello Exfiltration - Itzik Kotler](https://www.youtube.com/watch?v=GwaIvm2HJKc)
		* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
		* [Slides](http://www.ikotler.org/GoodbyeDataHelloExfiltration_BSidesORL.pdf)
	* [Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)
		* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
	* [In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)
		* In this session, we will reveal and demonstrate perfect exfiltration via indirect covert channels (i.e. the communicating parties don’t directly exchange network packets). This is a family of techniques to exfiltrate data (low throughput) from an enterprise in a manner indistinguishable from genuine traffic. Using HTTP and exploiting a byproduct of how some websites choose to cache their pages, we will demonstrate how data can be leaked without raising any suspicion. These techniques are designed to overcome even perfect knowledge and analysis of the enterprise network traffic.
	* [How To Bypass Email Gateways Using Common Payloads by Neil Lines - BSides Manchester2017](https://www.youtube.com/watch?v=eZxWDCetqkE&index=11&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)
* **Tools**
	* [PTP-RAT](https://github.com/pentestpartners/PTP-RAT)
		* Exfiltrate data over screen interfaces
	

--------------
### <a name="empire"></a>Empire
* **Articles**
	* [Hunting Red Team Empire C2 Infrastructure](http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html)
	* [Athena: The CIA’s RAT vs Empire](https://bneg.io/2017/05/22/athena-the-cias-rat-vs-empire/)
	* [Bringing the hashes home with reGeorg & Empire](https://sensepost.com/blog/2016/bringing-the-hashes-home-with-regeorg-empire/)
	* [Intercepting passwords with Empire and winning](https://sensepost.com/blog/2016/intercepting-passwords-with-empire-and-winning/)
* **Customizing**
	* [Using PowerShell Empire with a Trusted Certificate](https://www.blackhillsinfosec.com/using-powershell-empire-with-a-trusted-certificate/)
	* [How to Make Empire Communication profiles - bluescreenofjeff](https://github.com/bluscreenofjeff/bluscreenofjeff.github.io/blob/master/_posts/2017-03-01-how-to-make-communication-profiles-for-empire.md)
	* [Empire – Modifying Server C2 Indicators](http://threatexpress.com/2017/05/empire-modifying-server-c2-indicators/)
	* [Empire Domain Fronting](https://www.xorrior.com/Empire-Domain-Fronting/)
	* [Empire without powershell](https://bneg.io/2017/07/26/empire-without-powershell-exe/)





--------------
##### <a name="hardware"></a>HW
* [DigiDucky - How to setup a Digispark like a rubber ducky](http://www.redteamr.com/2016/08/digiducky/)
* [Bash Bunny](https://hakshop.com/products/bash-bunny)
* [How to Build Your Own Penetration Testing Drop Box - BHIS](https://www.blackhillsinfosec.com/?p=5156&)
* [P4wnP1](https://github.com/mame82/P4wnP1)
	* P4wnP1 is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W.
	* [Contents of a Physical Pentester Backpack](https://www.tunnelsup.com/contents-of-a-physical-pen-testers-backpack/)




--------------
### <a name="infrastructure"></a>Infrastructure
* **General**
	* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
		* Wiki to collect Red Team infrastructure hardening resources
		* Accompanying Presentation: [Doomsday Preppers: Fortifying Your Red Team Infrastructure](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure)
	* [How to Build a C2 Infrastructure with Digital Ocean – Part 1](https://www.blackhillsinfosec.com/build-c2-infrastructure-digital-ocean-part-1/)
	* [Infrastructure for Ongoing Red Team Operations](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/)
	* [Automated Red Team Infrastructure Deployment with Terraform - Part 1](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform---part-1/)
	* [6 RED TEAM INFRASTRUCTURE TIPS](https://cybersyndicates.com/2016/11/top-red-team-tips/)
	* [Migrating Your infrastructure](https://blog.cobaltstrike.com/2015/10/21/migrating-your-infrastructure/)
* **Logging**
	* [Attack Infrastructure Log Aggregation and Monitoring](https://posts.specterops.io/attack-infrastructure-log-aggregation-and-monitoring-345e4173044e)



------------------
### <a name="payload"></a>Payloads
* [Malice](https://github.com/maliceio/malice)
	* Malice's mission is to be a free open source version of VirusTotal that anyone can use at any scale from an independent researcher to a fortune 500 company.
* [Pupy](https://github.com/n1nj4sec/pupy)
	* Pupy is an opensource, multi-platform Remote Administration Tool with an embedded Python interpreter. Pupy can load python packages from memory and transparently access remote python objects. Pupy can communicate using different transports and have a bunch of cool features & modules. On Windows, Pupy is a reflective DLL and leaves no traces on disk.
	* [Pupy WebSocket Transport](https://bitrot.sh/post/28-11-2017-pupy-websocket-transport/)
* [RedSails](https://github.com/BeetleChunks/redsails)
	* Python based post-exploitation project aimed at bypassing host based security monitoring and logging. [DerbyCon 2017 Talk](https://www.youtube.com/watch?v=Ul8uPvlOsug)
* [stupid_malware](https://github.com/andrew-morris/stupid_malware)
	* Python malware for pentesters that bypasses most antivirus (signature and heuristics) and IPS using sheer stupidity
* [Dragon: A Windows, non-binding, passive download / exec backdoor](http://www.shellntel.com/blog/2015/6/11/dragon-a-windows-non-binding-passive-downloadexec-backdoor)
* [MetaTwin](https://github.com/minisllc/metatwin)
	* The project is designed as a file resource cloner. Metadata, including digital signature, is extracted from one file and injected into another. Note: Signatures are copied, but no longer valid.
	* [Blogpost](http://threatexpress.com/2017/10/metatwin-borrowing-microsoft-metadata-and-digital-signatures-to-hide-binaries/)
* [Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

----------
### <a name="persistence"></a>Persistence
* [Staying Persistent in Software Defined Networks](https://www.blackhat.com/docs/us-15/materials/us-15-Pickett-Staying-Persistent-In-Software-Defined-Networks-wp.pdf)
* [Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)
* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
	* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.




--------------
### <a name="tactics"></a>Tactics
* **Ideas**
	* [unindexed](https://github.com/mroth/unindexed/blob/master/README.md)
		* The site is constantly searching for itself in Google, over and over and over, 24 hours a day. The instant it finds itself in Google search results, the site will instantaneously and irrevocably securely delete itself. Visitors can contribute to the public content of the site, these contributions will also be destroyed when the site deletes itself.
	* [Hiding your process from sysinternals](https://riscybusiness.wordpress.com/2017/10/07/hiding-your-process-from-sysinternals/)
	* [Google Calendar Event Injection with MailSniper](https://www.blackhillsinfosec.com/google-calendar-event-injection-mailsniper/)
* **Keying Payloads**
	* [Context-keyed Payload Encoding](http://uninformed.org/?v=all&a=42&t=sumry)
		* A common goal of payload encoders is to evade a third-party detection mechanism which is actively observing attack traffic somewhere along the route from an attacker to their target, filtering on commonly used payload instructions. The use of a payload encoder may be easily detected and blocked as well as opening up the opportunity for the payload to be decoded for further analysis. Even so-called keyed encoders utilize easily observable, recoverable, or guessable key values in their encoding algorithm, thus making decoding on-the-fly trivial once the encoding algorithm is identified. It is feasible that an active observer may make use of the inherent functionality of the decoder stub to decode the payload of a suspected exploit in order to inspect the contents of that payload and make a control decision about the network traffic. This paper presents a new method of keying an encoder which is based entirely on contextual information that is predictable or known about the target by the attacker and constructible or recoverable by the decoder stub when executed at the target. An active observer of the attack traffic however should be unable to decode the payload due to lack of the contextual keying information.
	* [Keying Payloads for Scripting Languages](https://adapt-and-attack.com/2017/11/15/keying-payloads-for-scripting-languages/)
	* [GoGreen](https://github.com/leoloobeek/GoGreen/blob/master/README.md)
		* This project was created to bring environmental (and HTTP) keying to scripting languages. As its common place to use PowerShell/JScript/VBScript as an initial vector of code execution, as a result of phishing or lateral movement, I see value of the techniques for these languages.
* **Lateral Movement**
	* **WMI**
		* [The Grammar of WMIC](https://isc.sans.edu/diary/The+Grammar+of+WMIC/2376)
		* [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
		* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)
		* [PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)
			* PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement.
		* [Windows Security Center: Fooling WMI Consumers](https://www.opswat.com/blog/windows-security-center-fooling-wmi-consumers)
		* [CimSweep](https://github.com/PowerShellMafia/CimSweep)
			* CimSweep is a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows. CimSweep may also be used to engage in offensive reconnaisance without the need to drop any payload to disk. Windows Management Instrumentation has been installed and its respective service running by default since Windows XP and Windows 2000 and is fully supported in the latest versions of Windows including Windows 10, Nano Server, and Server 2016.
* **Simulation**
	* [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)
		* [Slides](https://github.com/TryCatchHCF/DumpsterFire/raw/master/CactusCon_2017_Presentation/DumpsterFire_CactusCon_2017_Slides.pdf)
		* The DumpsterFire Toolset is a modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations. Turn paper tabletop exercises into controlled "live fire" range events. Build event sequences ("narratives") to simulate realistic scenarios and generate corresponding network and filesystem artifacts.
	* [Caldera](https://github.com/mitre/caldera)
		* CALDERA is an automated adversary emulation system that performs post-compromise adversarial behavior within enterprise networks. It generates plans during operation using a planning system and a pre-configured adversary model based on the Adversarial Tactics, Techniques & Common Knowledge (ATT&CK™) project. These features allow CALDERA to dynamically operate over a set of systems using variable behavior, which better represents how human adversaries perform operations than systems that follow prescribed sequences of actions.


#### Code Injection
* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
	* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
* [Inject All the Things - Shut up and hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)



--------------
### Pen Testing

* [An Introduction to Writing .NET Executables for Pentesters](https://www.peew.pw/blog/2017/11/24/an-introduction-to-writing-net-executables-for-pentesters)
* [attacking encrypted systems with qemu and volatility](https://diablohorn.com/2017/12/12/attacking-encrypted-systems-with-qemu-and-volatility/) 
* [Attacking and Defending Full Disk Encryption - Tom Kopchak - BSides Cleveland2014](https://www.youtube.com/watch?v=-XLitSfOQ6U)
* [Make It Count: Progressing through Pentesting - Bálint Varga-Perke -Silent Signal](https://silentsignal.hu/docs/Make_It_Count_-_Progressing_through_Pentesting_Balint_Varga-Perke_Silent_Signal.pdf)
* [Pen Testing a City](https://www.blackhat.com/docs/us-15/materials/us-15-Conti-Pen-Testing-A-City-wp.pdf)


### Pen Testing Specific (not-generally-encountered) Stuff

#### <a name="aix"></a> AIX
* **General**
	* [AIX for Penetration Testers 2017 thevivi.net](https://thevivi.net/2017/03/19/aix-for-penetration-testers/)
	* [Hunting Bugs in AIX : Pentesting writeup](https://rhinosecuritylabs.com/2016/11/03/unix-nostalgia-hunting-zeroday-vulnerabilities-ibm-aix/)
	* [Penetration Testing Trends John Strand - Derbycon6](https://www.youtube.com/watch?v=QyxdUe1iMNk)



#### <a name="embedded"></a>Embedded
* **General**
	* [War Stories on Embedded Security Pentesting IoT Building Managers and how to do Better Dr Jared - Derbycon7](https://www.youtube.com/watch?v=bnTWysHT0I4&index=8&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)

#### <a name="scada"></a>SCADA/PLCs
* **General**
	* [Industrial Control Systems : Pentesting PLCs 101 (Part 1/2)](https://www.youtube.com/watch?v=iGwm6-lyn2Y)
	* [Industrial Control Systems : Pentesting PLCs 101 (Part 2/2)](https://www.youtube.com/watch?v=rP_Jys1_OJk)
	* [Adventures in Attacking Wind Farm Control Networks - Jason Stagg](https://www.blackhat.com/docs/us-17/wednesday/us-17-Staggs-Adventures-In-Attacking-Wind-Farm-Control-Networks.pdf)
	* [Protocol Me Maybe? How to Date SCADA - Stephen Hilt](http://www.irongeek.com/i.php?page=videos/derbycon4/t124-protocol-me-maybe-how-to-date-scada-stephen-hilt)
	* [Offensive ICS Exploitation: A Description of an ICS CTF - MWR](https://labs.mwrinfosecurity.com/blog/offensive-ics-exploitation-a-technical-description/)



#### <a name="main"></a>MainFrames
**MainFrames**
* Articles/General
	* [Introduction to z/OS and IBM mainframes world and security](https://www.whitewinterwolf.com/posts/2017/10/01/introduction-to-zos-and-ibm-mainframes-world-and-security/)
	* [mainframed767 - tumblr(Soldier of Fortran)](https://mainframed767.tumblr.com/post/43170687339/shmoocon-presentation-links?is_related_post=1)
	* [Everything you wanted to know about mainframe security, pen testing and vulnerability scanning .. But were  too afraid to ask!](http://www.newera.com/INFO/SEC_12_17_2015.pdf)
	* [Introduction to the New Mainframe z/OS Basics](https://www.redbooks.ibm.com/redbooks/pdfs/sg246366.pdf)
	* [2017 - A New Look at Mainframe Hacking and Penetration Testing v2.2](https://www.slideshare.net/rmfeio/2017-a-new-look-at-mainframe-hacking-and-penetration-testing-v22)
		* Sequel to above link
	* [Re: PenTest for Mainframe - Seclists](http://seclists.org/basics/2012/Aug/26)
	* [Reduce Risk and Improve Security on IBM Mainframes: Volume 1 Architecture and Platform Security](https://www.redbooks.ibm.com/redbooks/pdfs/sg247803.pdf)
	* [MVS Commands](http://hansen-family.com/mvs/MVS%20Commands.htm)
	* [Command reference](https://www.redbooks.ibm.com/tips/TIPS0091/tips0091.pdf)
		* This summary lists many of the commonly used commands (with  brief descriptions) for FTP and TCP/IP, as well as related z/OS,  z/VM, VSE, Linux, and VTAM commands. 
	* [Soldier of Fortran Tumblr](https://mainframed767.tumblr.com/)
	* [Internet Mainframe Project](https://mainframesproject.tumblr.com/)
* **Talks/Videos/Slides**
	* [Hacking Mainframes; Vulnerabilities in applications exposed over TN3270 - Dominic White](http://www.irongeek.com/i.php?page=videos/derbycon4/t217-hacking-mainframes-vulnerabilities-in-applications-exposed-over-tn3270-dominic-white)
		* IBM System Z Mainframes are in regular use in Fortune 500 companies. Far from being legacy these systems are running an actively maintained operating system (z/OS). Applications on these often occupy roles critical to the business processes they underpin, with much of the later technology built around them, rather than replacing them. However, these systems are often bypassed by security testing due to worried of availability or assumptions about legacy. This talk will introduce you to assessing mainframe applications, which turn out to be quite similar to web applications. For this purpose we built a tool, Big Iron Recon & Pwnage (BIRP), to assist with performing such assessments. Importantly, our research uncovered a family of mainframe application vulnerabilities introduced by the TN3270 protocol. We found numerous applications, but not all, vulnerable to these flaws. Applications running within the two most popular transaction managers (CICS and IMS) as well as one of IBM’s own applications. The tool released assists with the exploitation of these flaws.
	* [Learning Mainframe Hacking: Where the hell did all my free time go? - Chad Rikansrud - Derbycon5](https://www.irongeek.com/i.php?page=videos/derbycon5/stable31-learning-mainframe-hacking-where-the-hell-did-all-my-free-time-go-chad-rikansrud)
	* [Security Necromancy : Further Adventures in Mainframe Hacking - Phillip Young/Chad Rikansrud - Defcon23](https://www.youtube.com/watch?v=LgmqiugpVyU&feature=youtu.be)
	* [Slides](https://www.slideshare.net/bigendiansmalls/security-necromancy-publish)
	* [Smashing the Mainframe for Fun and Prison Time - Phillip Young - Hacktivity2014](https://www.youtube.com/watch?v=SjtyifWTqmc)
	* [How to Embrace Hacker Culture For z/OS | Phil Young at SHARE in Seattle2015](https://www.youtube.com/watch?v=5Ra4Ehmifh4)
	* [Hacking Mainframes Vulnerabilities in applications exposed over TN3270 - Dominic White - Derbycon4](https://www.youtube.com/watch?v=3HFiv7NvWrM)
	* [Why You Should (But Don't) Care About Mainframe Security - Northsec2015 - Phillip Young](https://www.youtube.com/watch?v=YLxvrklh2tM)
	* [Hack the Legacy: IBM I aka AS400 Revealed - Bart Kulach - Defcon23](https://www.youtube.com/watch?v=JsqUZ3xGdLc)
	* [From root to SPECIAL - Pwning IBM Mainframes - Defcon22 - Philip Young](https://www.youtube.com/watch?v=MZDIblU9pBw)
	* [Mainframed: The Secrets Inside that Black Box [Shmoocon 2013] - Philip Young](https://www.youtube.com/watch?v=KIavTQeQqSw)
	* [Mainframed - The Forgotten Fortress - Philip Young - BSidesLV2012](https://www.youtube.com/watch?v=tjYlXW2Dldc)
	* [we hacked the gibson now what - Philip Young - BSidesLV2014](https://www.youtube.com/watch?v=n_sXG0Ff2oM)
	* [Mainframes - Mopeds and Mischief; A PenTesters Year in Review](http://www.irongeek.com/i.php?page=videos/derbycon4/t203-mainframes-mopeds-and-mischief-a-pentesters-year-in-review-tyler-wrightson)
* **Tools**
	* [The Hercules System/370, ESA/390, and z/Architecture Emulator](http://www.hercules-390.org/)
		* Hercules is an open source software implementation of the mainframe System/370 and ESA/390 architectures, in addition to the new 64-bit z/Architecture
	* [Privilege escalation on z/OS](https://github.com/ayoul3/Privesc)
		* Privilege escalation tools on Mainframe
	* [Nmap Mainframe Scripts](https://github.com/zedsec390/NMAP)
		* NMAP scripts for TN3270 interaction as well as NJE. Most notably TSO User Enumeration and Brute Force. CICS transaction ID enumeration and NJE node name brute forcing.
	* [shells-payloads - Source code for SystemZ Shells / Payloads](https://github.com/zedsec390/shells-payloads)
	* [TN3270 Python Library](https://github.com/zedsec390/tn3270lib)
		* This library is a pure python implemnation of a TN3270e emulator. To test this library you can issue the command python tn3270lib.py <hostname> <port>.
	* [REXX-tools](https://github.com/zedsec390/REXX-tools)
		* Various tools in REXX
	* [NJElib](https://github.com/zedsec390/NJElib)
		* z/OS (mainframe) Network Job Entry (NJE) python library and example scripts.
	* [Privilege escalation on z/OSINT - ayoul3 github](https://github.com/ayoul3/Privesc)
		* Some scripts to quickly escalate on z/OS given certain misconfigurations.
	* [REX_Scripts](https://github.com/ayoul3/Rexx_scripts)
		* A collection of interesting REXX scripts to ease the life a mainframe pentester
* **Writeups**




#### <a name="va"></a> Virtual Appliances
* **General**
	* [Hacking Virtual Appliances - Jeremy Brown - Derbycon2015](https://www.irongeek.com/i.php?page=videos/derbycon5/fix-me08-hacking-virtual-appliances-jeremy-brown)
		* Virtual Appliances have become very prevalent these days as virtualization is ubiquitous and hypervisors commonplace. More and more of the major vendors are providing literally virtual clones for many of their once physical-only products. Like IoT and the CAN bus, it's early in the game and vendors are late as usual. One thing that it catching these vendors off guard is the huge additional attack surface, ripe with vulnerabilities, added in the process. Also, many vendors see software appliances as an opportunity for the customer to easily evaluate the product before buying the physical one, making these editions more accessible and debuggable by utilizing features of the platform on which it runs. During this talk, I will provide real case studies for various vulnerabilities created by mistakes that many of the major players made when shipping their appliances. You'll learn how to find these bugs yourself and how the vendors went about fixing them, if at all. By the end of this talk, you should have a firm grasp of how one goes about getting remotes on these appliances.
