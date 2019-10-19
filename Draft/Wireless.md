# Wireless Networks


### Table of Contents

* [General](#general)
* [General Software Tools](#generalswt)
* [Tutorials and Guides](#tut)
* [Non Tutorial Writeups](#non-tut)
* [Dongles/HW Tools](#dongles)
* [Cellular Networks](#cn)
* [Software Defined Radio](#sdr)
* [802.11](#80211)
* [RFID](#rfid)
* [Zigbee](#zigbee)
* [Bluetooth](#bt)
* [Z-Wave](#zwave)
* [RetroReflectors](#retroreflectors)
* [Foxhunting & WarDriving](#fxh}
* [General Blogs/Sites](#gbs)
* [Talks/Presentations & Videos](#talks)
* [Papers](#papers)
* [Miscellaneous](#misc)


-----------------
#### Sort
* Fix ToC
* Add 101 stuff
* Add SMS Standards/related
https://www.usenix.org/legacy/events/sec11/tech/full_papers/Clark.pdf

* [RFC 7710: Captive-Portal Identification Using DHCP or Router Advertisements (RAs)](https://tools.ietf.org/html/rfc7710)

Bluetooth Low-Energy
	* https://blog.attify.com/the-practical-guide-to-hacking-bluetooth-low-energy/
	* https://csrc.nist.gov/csrc/media/publications/sp/800-121/rev-2/draft/documents/sp800_121_r2_draft.pdf
	* https://obvi.us/presentation/rf-sig/

	* https://www.usenix.org/system/files/conference/nsdi16/nsdi16-paper-vasisht.pdf
	* https://github.com/gsmaxwell/DopplerFi
	* https://github.com/seemoo-lab/nexmon
	* https://www.arxiv-vanity.com/papers/1811.10948/
	* https://arxiv.org/abs/1811.10948
https://github.com/hexway/apple_bleee

* https://papers.mathyvanhoef.com/dragonblood.pdf
https://www.blackhat.com/presentations/bh-europe-07/Butti/Presentation/bh-eu-07-Butti.pdf
https://www.youtube.com/watch?v=FCu8rnQVU5M

https://comsecuris.com/blog/posts/theres_life_in_the_old_dog_yet_tearing_new_holes_into_inteliphone_cellular_modems/

* [New Privacy Threat on 3G, 4G, and Upcoming5G AKA Protocols - Ravishankar Borgaonkar, Lucca Hirschi∗, Shinjo Park, and Altaf Shaik](https://eprint.iacr.org/2018/1175.pdf)
	* In this paper, we reveal a new privacy attack against allvariants of the AKA protocol, including 5G AKA, thatbreaches subscriber privacy more severely than knownlocation privacy attacks do. Our attack exploits a newlogical vulnerability we uncovered that would requirededicated fixes. We demonstrate the practical feasibilityof our attack using low cost and widely available setups.Finally we conduct a security analysis of the vulnerabil-ity and discuss countermeasures to remedy our attack

* [Security and Protocol Exploit Analysis of the 5GSpecifications - Roger Jover, Vuk Marojevic](https://arxiv.org/pdf/1809.06925.pdf)
	* ? Abstract—The Third Generation Partnership Project (3GPP)released  its  first  5G  security  specifications  in  March  2018.This paper reviews the proposed security architecture, its mainrequirements and procedures, and evaluates them in the contextof  known  and  new  protocol  exploits.  Although  security  hasbeen improved from previous generations, our analysis identifiesunrealistic 5G system assumptions and protocol edge cases thatcan render 5G communication systems vulnerable to adversarialattacks. For example, null encryption and null authentication arestill supported and can be used in valid system configurations.With no clear proposal to tackle pre-authentication messages,mobile devices continue to implicitly trust any serving network,which may or may not enforce a number of optional securityfeatures, or which may not be legitimate. Moreover, severalcritical security and key management functions are left outsideof the scope of the specifications. The comparison with known 4GLong-Term Evolution (LTE) protocol exploits reveals that the 5Gsecurity specifications, as of Release 15, Version 1.0.0, do not fullyaddress the user privacy and network availability challenges.Keywords–Security, 5G, 3GPP Release 15, LTE
* [A Formal Analysis of 5G Authentication](https://arxiv.org/pdf/1806.10360.pdf)
* [Component-Based Formal Analysis of 5G-AKA:Channel Assumptions and Session Confusion - Cas Cremers, Martin Dehnel-Wild](https://people.cispa.io/cas.cremers/downloads/papers/CrDe2018-5G.pdf)
	* We perform fine-grained formal analysis of 5G’s main au-thentication and key agreement protocol (AKA), and providethe first models to explicitly consider all parties defined by theprotocol specification. Our analysis reveals that the security of5G-AKA critically relies on unstated assumptions on the innerworkings of the underlying channels. In practice this means thatfollowing the 5G-AKA specification, a provider can easily and ‘correctly’ implement the standard insecurely, leaving the protocolvulnerable to a security-critical race condition. We provide thefirst models and analysis considering component and channelcompromise in 5G, whose results further demonstrate the fragilityand subtle trust assumptions of the 5G-AKA protocol.We propose formally verified fixes to the encountered issues,and have worked with 3GPP to ensure these fixes are adopted.

* add krack
* [Captive-Portal Identification Using DHCP or Router Advertisements (RAs) - RFC 7718](https://tools.ietf.org/html/rfc7710)
	* This document describes a DHCP option (and a Router Advertisement(RA) extension) to inform clients that they are behind some sort ofcaptive-portal device and that they will need to authenticate to getInternet access. It is not a full solution to address all of theissues that clients may have with captive portals; it is designed tobe used in larger solutions. The method of authenticating to andinteracting with the captive portal is out of scope for thisdocument
https://wpa3.mathyvanhoef.com/#new
https://news.ycombinator.com/item?id=6942389
* [RPL Attacks Framework](https://github.com/dhondta/rpl-attacks)
	* This project is aimed to provide a simple and convenient way to generate simulations and deploy malicious motes for a Wireless Sensor Network (WSN) that uses Routing Protocol for Low-power and lossy devices (RPL) as its network layer. With this framework, it is possible to easily define campaign of simulations either redefining RPL configuration constants, modifying single lines from the ContikiRPL library or using an own external RPL library. Moreover, experiments in a campaign can be generated either based on a same or a randomized topology for each simulation.
* [Funtenna - Transmitter: XYZ Embedded device + RF Funtenna Payload](https://www.blackhat.com/docs/us-15/materials/us-15-Cui-Emanate-Like-A-Boss-Generalized-Covert-Data-Exfiltration-With-Funtenna.pdf)
https://github.com/steve-m/fl2k-examples
https://osmocom.org/projects/osmo-fl2k/wiki


https://wpa3.mathyvanhoef.com/#new

https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html?m=1
https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_11.html
https://blade.tencent.com/en/advisories/qualpwn/

https://devtty0.io/pwning-wireless-peripherals/


https://www.blackhat.com/asia-17/arsenal.html#damn-vulnerable-ss7-network















-------------------------------
### <a name="general">General</a>
* [Cyberspectrum SDR Meetups](https://www.youtube.com/watch?v=MFBkX4CNb08&list=PLPmwwVknVIiXGzKhtimTMjhcyppeRRsnE&index=3)
* **101**
	* [IEEE 802.11 Tutorial](http://wow.eecs.berkeley.edu/ergen/docs/ieee.pdf)
		* This document describes IEEE 802.11 Wireless Local Area Network (WLAN) Standard. It describes IEEE 802.11 MAC Layer in detail and it briefly mentions IEEE 802.11a, IEEE 802.11b physical layer standard and IEEE 802.11e MAC layer standard
	* [FM and Bluetooth and Wifi Oh My Aaron Lafferty - Derbycon7](https://www.youtube.com/watch?v=_yAvPo4pVGA&index=5&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
* **Articles**
	* [sysmocom publicly releases Osmocom user manuals](https://www.sysmocom.de/news/sysmocom-publicly-releases-osmocom-user-manuals/)
* **Documentation**
	* [Management Frames Reference Sheet](http://download.aircrack-ng.org/wiki-files/other/managementframes.pdf)
* **Educational**
	* [Guide to Basics of Wireless Networking](http://documentation.netgear.com/reference/fra/wireless/TOC.html)
	* [US Marine Antenna Handbook](http://www.zerobeat.net/r3403c.pdf)
	* [So You Want To Hack Radios - A Primer On Wireless Reverse Engineering](http://conference.hitb.org/hitbsecconf2017ams/materials/D1T4%20-%20Marc%20Newlin%20and%20Matt%20Knight%20-%20So%20You%20Want%20to%20Hack%20Radios.pdf)
	* [PHYs, MACs, and SDRs - Robert Ghilduta](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/17-phys-macs-and-sdrs-robert-ghilduta)
		* The talk will touch on a variety of topics and projects that have been under development including YateBTS, PHYs, MACs, and GNURadio modules. The talk will deal with GSM/LTE/WiFi protocol stacks.
	* [Intro to SDR and RF Signal Analysis](https://www.elttam.com.au/blog/intro-sdr-and-rf-analysis/)
* **Fuzzing**
	* [Unifying RF Fuzzing Techniques under a Common API: Introducing unfAPI - Matt Knight, Ryan Speers - Troopers18](https://www.youtube.com/watch?v=sfV_O_dZycE)
		* [TumbleRF](https://github.com/riverloopsec/tumblerf)
			* TumbleRF is a framework that orchestrates the application of fuzzing techniques to RF systems. While fuzzing has always been a powerful mechanism for fingerprinting and enumerating bugs within software systems, the application of these techniques to wireless and hardware systems has historically been nontrivial due to fragmented and siloed tools. TumbleRF aims to enable RF fuzzing by providing an API to unify these techniques across protocols, radios, and drivers.
* **Testing**
	* [Introduction to Wireless Security Testing](http://www.grymoire.com/Security/Hardware.html)
	* [RF Testing Methodology - NCCGroup](https://nccgroup.github.io/RFTM/)
		* The RFTM is an Open Source, collaborative testing methodology. It is specifically written in a straightforward way, avoiding mathematics where possible and focussed on providing the information that security researchers and consultants need to know in order to effectively test systems that employ RF technologies.
		* [Signals and Modulation](https://nccgroup.github.io/RFTM/basics.html)
		* [Information Sources](https://nccgroup.github.io/RFTM/information_sources.html)
		* [Receiving Signals](https://nccgroup.github.io/RFTM/receiving_signals.html)
		* [Developing an FSK receiver step-by-step](https://nccgroup.github.io/RFTM/fsk_receiver.html)
		* [Transmitting Data](https://nccgroup.github.io/RFTM/transmitting_data.html)
		* [ Developing an FSK transmitter step-by-step](https://nccgroup.github.io/RFTM/fsk_transmitter.html)
		* [Signals Identification](https://nccgroup.github.io/RFTM/signals_identification.html)	
* **General Videos**
	* [The Wireless World of the Internet of Things -  JP Dunning ".ronin"](http://www.irongeek.com/i.php?page=videos/derbycon4/t214-the-wireless-world-of-the-internet-of-things-jp-dunning-ronin)
		* The Internet of Things brings all the hardware are home together. Most of these devices are controlled through wireless command and control network. But what kind of wireless? And what are the security is in place? This talk with cover the wireless tech used by the Internet of Things and some of the risks to your home or corporate security.
	* [Drive it like you Hacked it- Samy Kamkar - Defcon23](https://www.youtube.com/watch?v=UNgvShN4USU)
		* In this talk I’ll reveal new research and real attacks in the area of wirelessly controlled gates, garages, and cars. Many cars are now controlled from mobile devices over GSM, while even more can be unlocked and ignitions started from wireless keyfobs over RF. All of these are subject to attack with low-cost tools (such as RTL-SDR, GNU Radio, HackRF, Arduino, and even a Mattel toy).
**APCO Project 25 (P25)**
	* [HOPE Number Nine (2012): Practical Insecurity in Encrypted Radio](https://www.youtube.com/watch?v=7or-_gT8TWU&app=desktop)
		* APCO Project 25 ("P25") is a suite of wireless communications protocols used in the United States and elsewhere for public safety two-way (voice) radio systems. The protocols include security options in which voice and data traffic can be cryptographically protected from eavesdropping. This talk analyzes the security of P25 systems against passive and active adversaries. The panel found a number of protocol, implementation, and user interface weaknesses that routinely leak information to a passive eavesdropper or that permit highly efficient and difficult to detect active attacks. They found new "selective subframe jamming" attacks against P25, in which an active attacker with very modest resources can prevent specific kinds of traffic (such as encrypted messages) from being received, while emitting only a small fraction of the aggregate power of the legitimate transmitter. And, more significantly, they found that even passive attacks represent a serious immediate threat. In an over-the-air analysis conducted over a two year period in several U.S. metropolitan areas, they found that a significant fraction of the "encrypted" P25 tactical radio traffic sent by federal law enforcement surveillance operatives is actually sent in the clear - in spite of their users' belief that they are encrypted - and often reveals such sensitive data as the names of informants in criminal investigations.
* **Miscellaneous**
	* [RF-Capture](http://rfcapture.csail.mit.edu/)
		* RF-Capture is a device that captures a human figure through walls and occlusions. It transmits wireless signals and reconstructs a human figure by analyzing the signals' reflections. RF-Capture does not require the person to wear any sensor, and its transmitted power is 10,000 times lower than that of a standard cell-phone.
		* [Paper](http://rfcapture.csail.mit.edu/rfcapture-paper.pdf)
	* [One Billion Apples' Secret Sauce: Recipe for the Apple Wireless Direct Link Ad hoc Protocol](https://arxiv.org/abs/1808.03156)


----------------------
### <a name="bt">BlueTooth</a> BlueTooth
* **101**
	* [Bluetooth - Wikipedia](https://en.wikipedia.org/wiki/Bluetooth)
* **(Big)Attacks**
	* [blueborne](https://www.armis.com/blueborne/)
* **Articles/Presentations/Talks/Writeups**
	* [Now I wanna sniff some Bluetooth: Sniffing and Cracking Bluetooth with the UbertoothOne](https://www.security-sleuth.com/sleuth-blog/2015/9/6/now-i-wanna-sniff-some-bluetooth-sniffing-and-cracking-bluetooth-with-the-ubertoothone)
	* [Hacking Electric Skateboards - Mike Ryan and Richo Healey - DEF CON 23](https://www.youtube.com/watch?v=JZ3EB68v_B0)
		* Richo and Mike will investigate the security of several popular skateboards, including Boosted's flagship model and demonstrate several vulnerabilities that allow complete control of a an unmodified victim's skateboard, as well as other attacks on the firmware of the board and controller directly.
		* [Slides](https://media.defcon.org/DEF%20CON%2023/DEF%20CON%2023%20presentations/DEFCON-23-Richo-Healey-Mike-Ryan-Hacking-Electric-Skateboards.pdf)
	* [The NSA Playset: Bluetooth Smart Attack Tools - Mike Ryan](https://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/15-the-nsa-playset-bluetooth-smart-attack-tools-mike-ryan)
		* [Slides](https://conference.hitb.org/hitbsecconf2014kul/sessions/bluetooth-smart-attack-tools/)
		* This talk is a part of the NSA Playset series, a collection of unique topics with a common theme: implementing the NSA’s toys as found in the NSA ANT catalog. I have developed multiple Bluetooth Smart (BLE) attack tools, inspired by capabilities likely to be present in the ANT catalog.
	* [Outsmarting Bluetooth Smart - Mike Smart](https://www.youtube.com/watch?v=dYj6bpDzID0)
		* This talk covers Bluetooth Smart active attacks, fuzzing Bluetooth stacks, and remote Bluetooth exploitation. I presented this talk at CanSecWest 2014 in Vancouver, BC, Canada.
		* [Slides](https://lacklustre.net/bluetooth/outsmarting_bluetooth_smart-mikeryan-cansecwest_2014.pdf)
	* [Bluetooth Smart: The Good, the Bad, the Ugly, and the Fix! - BHUSA 2013](https://www.youtube.com/watch?v=SoH11fi-FcA)
		* [Slides](https://lacklustre.net/bluetooth/bluetooth_smart_good_bad_ugly_fix-mikeryan-blackhat_2013.pdf)
	* [How Smart Is Bluetooth Smart?](https://lacklustre.net/bluetooth/how_smart_is_bluetooth_smart-mikeryan-shmoocon_2013.pdf)
	* [Bluetooth Hacking Tools Comparison - Mark Loveless](https://duo.com/blog/bluetooth-hacking-tools-comparison)
* **Documentation**
	* [NIST Special Publication 800-121 Revision 2: Guide to Bluetooth Security](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-121r2.pdf)
	* [Protocol Specs - bluetooth.com](https://www.bluetooth.com/specifications/protocol-specifications)
* **Testing**
	* [Bluetooth Penetration Testing Framework - 2011](http://bluetooth-pentest.narod.ru/)
	* [Hacking Bluetooth connections - hackingandsecurity](https://hackingandsecurity.blogspot.com/2017/08/hacking-bluetooth-connections.html?view=timeslide)
* **Tools**
	* [PyBT](https://github.com/mikeryan/PyBT)
		* PyBT is a crappy half implementation of a Bluetooth stack in Python. At the moment it only supports Bluetooth Smart (BLE).
	* [Bluetooth NSA Toolset Talk/Attacks video](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/15-the-nsa-playset-bluetooth-smart-attack-tools-mike-ryan)
	* [bluepot](https://github.com/andrewmichaelsmith/bluepot)
		* Bluepot is a Bluetooth Honeypot written in Java, it runs on Linux.
	* [BlueHydra](https://github.com/pwnieexpress/blue_hydra)
		* BlueHydra is a Bluetooth device discovery service built on top of the bluez library. BlueHydra makes use of ubertooth where available and attempts to track both classic and low energy (LE) bluetooth devices over time.
	* [crackle](https://github.com/mikeryan/crackle)
		* crackle exploits a flaw in the BLE pairing process that allows an attacker to guess or very quickly brute force the TK (Temporary Key). With the TK and other data collected from the pairing process, the STK (Short Term Key) and later the LTK (Long Term Key) can be collected.
* **Bluetooth Low Energy**
	* **101**
	* **Articles/Presentations/Talks/Writeups**
		* [Bluetooth: With Low Energy comes Low Security - Mike Ryan](https://lacklustre.net/bluetooth/Ryan_Bluetooth_Low_Energy_USENIX_WOOT.pdf)
			* We discuss our tools and techniques to monitor and inject packets in Bluetooth Low Energy. Also known as BTLE or Bluetooth Smart, it is found in recent high-end smartphones, sports devices, sensors, and will soon appear in many medical devices.  We show that we can effectively render useless the encryption of any Bluetooth Low Energy link
		* [Getting started with Bluetooth Low Energy on iOS](https://medium.com/@yostane/getting-started-with-bluetooth-low-energy-on-ios-ada3090fc9cc)
		* [This Is Not a Post About BLE, Introducing BLEAH](https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/)
		* [Bluetooth: With Low Energy Comes Low Security](https://www.usenix.org/conference/woot13/workshop-program/presentation/ryan)
		* [My journey towards Reverse Engineering a Smart Band — Bluetooth-LE RE](https://medium.com/@arunmag/my-journey-towards-reverse-engineering-a-smart-band-bluetooth-le-re-d1dea00e4de2)
		* [Hacking Bluetooth Low Energy: I Am Jack's Heart Monitor - Toorcon2012](https://www.youtube.com/watch?v=4POOiVrdnX8)
			* Bluetooth Low Energy (BTLE) is the hottest new mode in the latest and greatest Bluetooth 4.0 spec. A new generation of wireless devices, including medical devices will be implemented using this mode. BTLE is much simpler than classic Bluetooth. Simpler to implement, simpler to debug, and hey, simpler to hack. I present the progress of a BTLE sniffer/smasher/smusher written for Ubertooth in this WIP talk. 
			* [Slides](https://lacklustre.net/bluetooth/hacking_btle-i_am_jacks_heart_monitor-mikeryan-toorcon_2012.pdf)
	* **Tools**
		* [BtleJuice](https://github.com/DigitalSecurity/btlejuice/blob/master/README.md)
			* BtleJuice is a complete framework to perform Man-in-the-Middle attacks on Bluetooth Smart devices (also known as Bluetooth Low Energy).
		* [crackle](https://github.com/mikeryan/crackle)
			* cracks BLE Encryption (AKA Bluetooth Smart).  crackle exploits a flaw in the BLE pairing process that allows an attacker to guess or very quickly brute force the TK (Temporary Key). With the TK and other data collected from the pairing process, the STK (Short Term Key) and later the LTK (Long Term Key) can be collected.
		* [gattacker](https://github.com/securing/gattacker)
			* A Node.js package for BLE (Bluetooth Low Energy) Man-in-the-Middle & more
		* [noble](https://github.com/sandeepmistry/noble)
			* A Node.js BLE (Bluetooth Low Energy) central module.
		* [bleno](https://github.com/sandeepmistry/bleno)
			* A Node.js module for implementing BLE (Bluetooth Low Energy) peripherals.
		* [crackle](https://github.com/mikeryan/crackle/)
			* crackle cracks BLE Encryption (AKA Bluetooth Smart). crackle exploits a flaw in the BLE pairing process that allows an attacker to guess or very quickly brute force the TK (Temporary Key). With the TK and other data collected from the pairing process, the STK (Short Term Key) and later the LTK (Long Term Key) can be collected. With the STK and LTK, all communications between the master and the slave can be decrypted.
* **Papers**
	* [Cracking the Bluetooth PIN - Yaniv Shaked and Avishai Wool](http://www.eng.tau.ac.il/~yash/shaked-wool-mobisys05/)
		* This paper describes the implementation of an attack on the Bluetooth security mechanism. Specifically, we describe a passive attack, in which an attacker can find the PIN used during the pairing process. We then describe the cracking speed we can achieve through three optimizations methods. Our fastest optimization employs an algebraic representation of a central cryptographic primitive (SAFER+) used in Bluetooth. Our results show that a 4-digit PIN can be cracked in less than 0.3 sec on an old Pentium III 450MHz computer, and in 0.06 sec on a Pentium IV 3Ghz HT computer. 




-----------------------
### <a name="cn">Cellular Networks</a>
* **101**
* **Educational**
	* [Guide to LTE Security - NIST Special Publication 800-187](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-187.pdf)
	* [Demystifying the Mobile Network by Chuck McAuley](http://2014.video.sector.ca/video/110383258)
		* Must watch video. Very informative.
	* [LTE Security - How good is it?](http://csrc.nist.gov/news_events/cif_2015/research/day2_research_200-250.pdf)
	* [Mobile self-defense - Karsten Nohl](https://www.youtube.com/watch?v=GeCkO0fWWqc)
	* [Taming Mr Hayes: Mitigating Signaling Based Attacks on Smartphones](https://www.mulliner.org/collin/academic/publications/mrhayes_mulliner_dsn2012.pdf)
		* Malicious injection of cellular signaling traffic from mobile phones is an emerging security issue. The respective attacks can be performed by hijacked smartphones and by malware resident on mobile phones. Until today there are no protection mechanisms in place to prevent signaling based attacks other than implementing expensive additions to the cellular core network. In this work we present a protection system that resides on the mobile phone. Our solution works by partitioning the phone software stack into the application operating system and the communication partition. The application system is a standard fully featured Android sys tem. On the other side, communication to the cellular network is mediated by a flexible monitoring and enforcement system running on the communication partition. We implemented and evaluated our protection system on a real smartphone. Our evaluation shows that it can mitigate all currently know n signaling based attacks and in addition can protect users fr om cellular Trojans.
* **Tools**
	* [SiGploit](https://github.com/SigPloiter/SigPloit)
		* Telecom Signaling Exploitation Framework - SS7, GTP, Diameter & SIP. SiGploit a signaling security testing framework dedicated to Telecom Security professionals and reasearchers to pentest and exploit vulnerabilites in the signaling protocols used in mobile operators regardless of the geneartion being in use. SiGploit aims to cover all used protocols used in the operators interconnects SS7, GTP (3G), Diameter (4G) or even SIP for IMS and VoLTE infrastructures used in the access layer and SS7 message encapsulation into SIP-T. Recommendations for each vulnerability will be provided to guide the tester and the operator the steps that should be done to enhance their security posture
	* [LTE-Cell-Scanner](https://github.com/Evrytania/LTE-Cell-Scanner)
		* This is a collection of tools to locate and track LTE basestation cells using very low performance RF front ends. For example, these tools work with RTL2832 based dongles (E4000, R820T, etc.) which have a noise figure of 20dB, only 8 bits in the A/D, and a crystal with a frequency error of about 100 ppm.
	* [UmTRX](https://umtrx.org/products/)
		* UmTRX is a dual-channel wide-band SDR platform with gigabit Ethernet connectivity, that is developed by Fairwaves and designed to be used as a transceiver (TRX) with OpenBTS and OsmoBTS GSM base stations.
* **SIM Cards**
	* **101**
	* **Articles/Presentations/Talks/Writeups**
		* [Rooting Sim Cards](https://media.blackhat.com/us-13/us-13-Nohl-Rooting-SIM-cards-Slides.pdf)
		* [Secrets of Sim](http://www.hackingprojects.net/2013/04/secrets-of-sim.html)
		* [Security mechanisms for the (U)SIM application toolkit; Test specification](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1801#)
		* [Small Tweaks do Not Help: Differential Power Analysis of MILENAGE Implementations in 3G/4G USIM Cards](https://www.blackhat.com/docs/us-15/materials/us-15-Yu-Cloning-3G-4G-SIM-Cards-With-A-PC-And-An-Oscilloscope-Lessons-Learned-In-Physical-Security-wp.pdf)
		* [4G Security: Hacking USB Modem and SIM Card via SMS](http://blog.ptsecurity.com/2014/12/4g-security-hacking-usb-modem-and-sim.html)
		* [The Secret Life of SIM Cards - Defcon21](https://www.youtube.com/watch?v=31D94QOo2gY)
		* [Small Tweaks do Not Help: Differential Power Analysis of MILENAGE Implementations in 3G/4G USIM Cards](https://www.blackhat.com/docs/us-15/materials/us-15-Yu-Cloning-3G-4G-SIM-Cards-With-A-PC-And-An-Oscilloscope-Lessons-Learned-In-Physical-Security-wp.pdf)
		* [Mobile: Cellular Exploitation on a Global Scale The Rise & Fall of the Control](https://www.youtube.com/watch?v=HD1ngJ85vWM)
		* [The Great SIM Heist How Spies Stole the Keys to the Encryption Castle - The Intercept](https://theintercept.com/2015/02/19/great-sim-heist/)
	* **Tools**
		* [Osmocom SIMtrace](http://bb.osmocom.org/trac/wiki/SIMtrace)
			* Osmocom SIMtrace is a software and hardware system for passively tracing SIM-ME communication between the SIM card and the mobile phone. 	
* **FemtoCell**
	* **101**
	* **Articles/Presentations/Talks/Writeups**
		* [The Vodafone Access Gateway / UMTS Femto cell / Vodafone Sure Signal](https://wiki.thc.org/vodafone)
		* [Adventures in Femtoland: 350 Yuan for Invaluable Fun](https://www.slideshare.net/arbitrarycode/adventures-in-femtoland-350-yuan-for-invaluable-fun)
* **GSM**
	* **101**
	* **Articles/Presentations/Talks/Writeups**
		* [Practical attacks against GSM networks (Part 1/3): Impersonation](https://blog.blazeinfosec.com/practical-attacks-against-gsm-networks-part-1/)
		* [RTL-SDR Tutorial: Analyzing GSM with Airprobe and Wireshark](http://www.rtl-sdr.com/rtl-sdr-tutorial-analyzing-gsm-with-airprobe-and-wireshark/)
			* The RTL-SDR software defined radio can be used to analyze cellular phone GSM signals, using Linux based tools Airprobe and Wireshark. This tutorial shows how I set up these tools for use with the RTL-SDR.
		* [How To Build Your Own Rogue GSM BTS For Fun And Profit](https://www.evilsocket.net/2016/03/31/how-to-build-your-own-rogue-gsm-bts-for-fun-and-profit/)
		* [Sniffing GSM with HackRF](https://web.archive.org/web/20130825000211/http://binaryrf.com/viewtopic.php?t=6&f=9)
		* [GSM/GPRS Traffic Interception for Penetration Testing Engagements](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/may/gsmgprs-traffic-interception-for-penetration-testing-engagements/)
		* [CampZer0 // Domonkos Tomcsányi: GSM - have we overslept the last wake-up call?](https://www.youtube.com/watch?v=3cnnQFP3VqE)
		* [Intercepting GSM Traffic](https://www.blackhat.com/presentations/bh-dc-08/Steve-DHulton/Presentation/bh-dc-08-steve-dhulton.pdf)
		* [GSM: SRSLY?](https://events.ccc.de/congress/2009/Fahrplan/events/3654.en.html)
			* The worlds most popular radio system has over 3 billion handsets in 212 countries and not even strong encryption. Perhaps due to cold-war era laws, GSM's security hasn't received the scrutiny it deserves given its popularity. This bothered us enough to take a look; the results were surprising. From the total lack of network to handset authentication, to the "Of course I'll give you my IMSI" message, to the iPhone that really wanted to talk to us. It all came as a surprise  stunning to see what $1500 of USRP can do. Add a weak cipher trivially breakable after a few months of distributed table generation and you get the most widely deployed privacy threat on the planet. Cloning, spoofing, man-in-the-middle, decrypting, sniffing, crashing, DoS'ing, or just plain having fun. If you can work a BitTorrent client and a standard GNU build process then you can do it all, too. Prepare to change the way you look at your cell phone, forever
		* [Wideband GSM Sniffing [27C3]](https://www.youtube.com/watch?v=ZrbatnnRxFc)
			* GSM is still the most widely used security technology in the world with a user base of 5 billion and a quickly growing number of critical applications. 26C3's rainbow table attack on GSM's A5/1 encryption convinced many users that GSM calls should be considered unprotected. The network operators, however, have not woken up to the threat yet. Perhaps the new capabilities to be unleashed this year -- like wide-band sniffing and real-time signal processing -- will wake them up. Now that GSM A5/1 encryption can be cracked in seconds, the complexity of wireless phone snooping moved to signal processing. Since GSM hops over a multitude of channels, a large chunk of radio spectrum needs to be analyzed, for example with USRPs, and decoded before storage or decoding. We demonstrate how this high bandwidth task can be achieved with cheap programmable phones.
		* [29C3 GSM: Cell phone network review](https://www.youtube.com/watch?v=9wwco24EsHs)
			* Did you notice 262 42 in your mobile phone network search list at the last CCC events? Did you and your friends buy SIM cards at the PoC and help test the network by calling each other, or by calling through the bridge to the DECT network services? Did you ever wonder about the details of this open source test network, set up by a team of volunteers in the middle of the city? We would like to tell you all the details of the cell phone network we operate at 29C3, and show you some fancy graphs based on the network activity! We will describe the process of setting up the test network we operate at 29C3, what legal and technical challenges we have faced, and we will describe the actual installation at the CCH. We will also compare this with the 262 42 test networks that were operated using the same open source software but otherwise very different installations at CCC Camp 2011 and 28C3. We will go on to show various statistics that we collect from the network while it has been running.
		* [Building a portable GSM BTS using the Nuand bladeRF, Raspberry Pi and YateBTS (The Definitive and Step by Step Guide) ](https://blog.strcpy.info/2016/04/21/building-a-portable-gsm-bts-using-bladerf-raspberry-and-yatebts-the-definitive-guide/)
		* [The big GSM write-up; how to capture, analyze and crack GSM?](http://domonkos.tomcsanyi.net/?p=418)
		* [StackOverflow post on intercepting GSM traffic](https://reverseengineering.stackexchange.com/questions/2962/intercepting-gsm-communications-with-an-usrp-and-gnu-radio)
		* [NSA Playset - GSM Sniffing - Pierce&Loki - Defcon22](https://www.youtube.com/watch?v=tnn_qJGh1gc)
		* [Sniffing GSM with RTL-SDR](https://www.youtube.com/watch?v=7OW0YOa6CYs)
		* [Capturing and Cracking GSM traffic using a rtl-sdr](https://www.youtube.com/watch?v=TOl4Q4lyJTI)
	* **Tools**
		* [GSM MAP](http://gsmmap.org/#!/about) 
			* The GSM Security Map compares the protection capabilities of mobile networks. Networks are rated in their protection capabilities relative to a reference network that implements all protection measures that have been seen in the wild. The reference is regularly updated to reflect new protection ideas becoming commercially available. Networks, therefore, have to improve continuously to maintain their score, just as hackers are continuously improving their capabilities.
		* [gr-gsm](https://github.com/ptrkrysik/gr-gsm)
			* Gnuradio blocks and tools for receiving GSM transmissions
* **LTE**
	* **101**
	* **Articles/Presentations/Talks/Writeups**
		* [LTE Security - How good is it?](http://csrc.nist.gov/news_events/cif_2015/research/day2_research_200-250.pdf)
		* [4G LTE Architecture and Security Concerns](http://www.secforce.com/blog/2014/03/4g-lte-architecture-and-security-concerns/)
		* [LTEInspector : A Systematic Approach for Adversarial Testing of 4G LTE](http://wp.internetsociety.org/ndss/wp-content/uploads/sites/25/2018/02/ndss2018_02A-3_Hussain_paper.pdf)
			* In this paper, we investigate the security and privacy of the three critical procedures of the 4G LTE protocol (i.e., attach, detach, and paging), and in the process, uncover potential design flaws of the protocol and unsafe practices employed by the stakeholders. For exposing vulnerabilities, we propose a model-based testing approach LTEInspector which lazily combines a symbolic model checker and a cryptographic protocol verifier in the symbolic attacker model. Using LTEInspector, we have uncovered 10 new attacks along with 9 prior attacks, cate- gorized into three abstract classes (i.e., security, user privacy, and disruption of service), in the three procedures of 4G LTE. Notable among our findings is the authentication relay attack that enables an adversary to spoof the location of a legitimate user to the core network without possessing appropriate credentials. To ensure that the exposed attacks pose real threats and are indeed realizable in practice, we have validated 8 of the 10 new attacks and their accompanying adversarial assumptions through experimentation in a real testbed
		* [Breaking LTE on Layer Two](https://alter-attack.net/)
			* Our security analysis of the mobile communication standard LTE ( Long-Term Evolution, also know as 4G) on the data link layer (so called layer two) has uncovered three novel attack vectors that enable different attacks against the protocol. On the one hand, we introduce two passive attacks that demonstrate an identity mapping attack and a method to perform website fingerprinting. On the other hand, we present an active cryptographic attack called aLTEr attack that allows an attacker to redirect network connections by performing DNS spoofing due to a specification flaw in the LTE standard. In the following, we provide an overview of the website fingerprinting and aLTE attack, and explain how we conducted them in our lab setup. Our work will appear at the 2019 IEEE Symposium on Security & Privacy and all details are available in a pre-print version of the paper.
* **SMS**
	* [Binary SMS - The old backdoor to your new thing - Contextis](https://www.contextis.com/blog/binary-sms-the-old-backdoor-to-your-new-thing)
	* [#root via SMS: 4G access level security assessment](https://conference.hitb.org/hitbsecconf2015ams/materials/D1T1%20-%20T.%20Yunusov%20K.%20Nesterov%20-%20Bootkit%20via%20SMS.pdf)
* **SS7**
	* **101**
	* **Articles/Presentations/Talks/Writeups**
		* [SS7: Locate. Track. Manipulate. You have a tracking device in your pocket](http://media.ccc.de/browse/congress/2014/31c3_-_6249_-_en_-_saal_1_-_201412271715_-_ss7_locate_track_manipulate_-_tobias_engel.html#video&t=424) 
			* Companies are now selling the ability to track your phone number whereever you go. With a precision of up to 50 meters, detailed movement profiles can be compiled by somebody from the other side of the world without you ever knowing about it. But that is just the tip of the iceberg.
		* [Primary Security Threats For SS7 Cellular Networks](https://www.ptsecurity.com/upload/ptcom/SS7-VULNERABILITY-2016-eng.pdf)
	* **Tools**
		* [SS7 MAP (pen-)testing toolkit](https://github.com/ernw/ss7MAPer)
* **IMSI Catcher related**
	* [Android IMSI-Catcher Detector (AIMSICD)](https://github.com/SecUpwN/Android-IMSI-Catcher-Detector)
		* Android-based project to detect and avoid fake base stations (IMSI-Catchers) in GSM/UMTS Networks.
	* [SnoopSnitch](https://opensource.srlabs.de/projects/snoopsnitch)
		* SnoopSnitch is an Android app that collects and analyzes mobile radio data to make you aware of your mobile network security and to warn you about threats like fake base stations (IMSI catchers), user tracking and over-the-air updates. With SnoopSnitch you can use the data collected in the GSM Security Map at gsmmap.org and contribute your own data to GSM Map. This application currently only works on Android phones with a Qualcomm chipset and a stock Android ROM (or a suitable custom ROM with Qualcomm DIAG driver). It requires root priviliges to capture mobile network data.




----------------------
### Dongles
* [FunCube dongle](http://www.funcubedongle.com)
* [RZUSBstick](http://www.atmel.com/tools/rzusbstick.aspx)
	* The starter kit accelerates development, debugging, and demonstration for a wide range of low power wireless applications including IEEE 802.15.4, 6LoWPAN, and ZigBee networks.  The kit includes one USB stick with a 2.4GHz transceiver and a USB connector. The included AT86RF230 transceiver's high sensitivity supports the longest range for wireless products. The AT90USB1287 incorporates fast USB On-the-Go.
* [Gr0SMoSDR](http://sdr.osmocom.org/trac/wiki/GrOsmoSDR)
* [PyBOMBS](https://github.com/gnuradio/pybombs)
	* PyBOMBS (Python Build Overlay Managed Bundle System) is the new GNU Radio install management system for resolving dependencies and pulling in out-of-tree projects. One of the main purposes of PyBOMBS is to aggregate out-of-tree projects, which means that PyBOMBS needs to have new recipes for any new project. We have done a lot of the initial work to get known projects into the PyBOMBS system as is, but we will need project developers for new OOT projects or other projects not currently listed to help us out with this effort.	
* [UAV Transponders & Tracker Kits - UST](http://www.unmannedsystemstechnology.com/company/sagetech-corporation/) 





----------------------
### <a name="80211">802.11 - WiFi</a>
* **101**
	* [802.11 frames : A starter guide to learn wireless sniffer traces](https://supportforums.cisco.com/t5/wireless-mobility-documents/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/ta-p/3110019)
	* [IEEE 802.11 Pocket Reference Guide ](http://www.willhackforsushi.com/papers/80211_Pocket_Reference_Guide.pdf)
* **Documentation**
	* [Establishing Wireless Robust Security Networks: A Guide to IEEE 802.11i - NIST](http://csrc.nist.gov/publications/nistpubs/800-97/SP800-97.pdf)
* **Educational**
	* [IEEE 802.11 Tutorial](http://wow.eecs.berkeley.edu/ergen/docs/ieee.pdf)
		* This document describes IEEE 802.11 Wireless Local Area Network (WLAN) Standard. It describes IEEE 802.11 MAC Layer in detail and it briefly mentions IEEE 802.11a, IEEE 802.11b physical layer standard and IEEE 802.11e MAC layer standard
	* [Wi-Fi Protected Access 2 (WPA2) Overview](https://technet.microsoft.com/library/bb878054)
	* [Wireless Leakage - Robin Wood](https://digi.ninja/files/Tech_for_Troops-Wi-Fi_Leakage.pdf)
	* [Emulation and Exploration of BCM WiFi Frame Parsing using LuaQEMU](https://comsecuris.com/blog/posts/luaqemu_bcm_wifi/)
* **Fox Hunting & Wardriving**
	* [Practical Foxhunting 101](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/04-practical-foxhunting-101-simonj)
	* [iSniff](https://github.com/hubert3/iSniff-GPS) 
		* iSniff GPS passively sniffs for SSID probes, ARPs and MDNS (Bonjour) packets broadcast by nearby iPhones, iPads and other wireless devices. The aim is to collect data which can be used to identify each device and determine previous geographical locations, based solely on information each device discloses about previously joined WiFi networks. iOS devices transmit ARPs which sometimes contain MAC addresses (BSSIDs) of previously joined WiFi networks, as described in [1]. iSniff GPS captures these ARPs and submits MAC addresses to Apple's WiFi location service (masquerading as an iOS device) to obtain GPS coordinates for a given BSSID. If only SSID probes have been captured for a particular device, iSniff GPS can query network names on wigle.net and visualise possible locations.
	* [If it fits - it sniffs: Adventures in WarShipping - Larry Pesce](http://www.irongeek.com/i.php?page=videos/derbycon4/t104-if-it-fits-it-sniffs-adventures-in-warshipping-larry-pesce)
		*  There are plenty of ways to leverage known wireless attacks against our chosen victims. We've discovered a new WiFi discovery methodology that can give us insight into attack paths, internal distribution methods, internal policies and procedures as well as an opportunity to launch wireless attacks deep inside a facility without even stepping inside; no physical penetration test needed. How do we make that happen? Box it, tape it and slap an address on it: WARSHIPPING. Thanks FedEx, UPS and USPS for doing the heavy lifting for us. We've even got a new tool to do some of the heavy lifting for location lookups too!
* **Identification/Tracking**
	* [Fingerprinting 802.11 Implementations via Statistical Analysis of the Duration Field](http://uninformed.org/?v=all&a=23&t=sumry)
		* The research presented in this paper provides the reader with a set of algorithms and techniques that enable the user to remotely determine what chipset and device driver an 802.11 device is using. The technique outlined is entirely passive, and given the amount of features that are being considered for inclusion into the 802.11 standard, seems quite likely that it will increase in precision as the standard marches forward. The implications of this are far ranging. On one hand, the techniques can be used to implement innovative new features in Wireless Intrusion Detection Systems (WIDS). On the other, they can be used to target link layer device driver attacks with much higher precision. 
	* [Meeting People Over WiFi - JoshInGeneral - DC23](https://www.youtube.com/watch?v=9SIMe0yMy78)
		* In this talk we will talk about some of the things that can identify you in an environment and how people can track you. We will look at bluetooth scanning apps that you can use every day to track people inconspicuously from your phone, while walking, metroing, or as a passenger in a car driving.
* **Testing**
	* [Wireless Pentesting on the Cheap](http://securitysynapse.blogspot.com/2013/12/wireless-pentesting-on-cheap-kali-tl.html)
		* In this article, we proved the capabilities of an inexpensive wireless adapter and a flexible virtualized wireless attack image by breaking into a WEP protected test network.  For just $16 
	* [WPA/WPA2 Dictionaries](https://wifi0wn.wordpress.com/wepwpawpa2-cracking-dictionary/)
* **Tools**
	* **General**
		* [Aircrack](https://www.aircrack-ng.org/doku.php?id=links)
		* [wifi-arsenal](https://github.com/0x90/wifi-arsenal/)
	* **D/DOS**
		* [wifijammer](https://github.com/DanMcInerney/wifijammer)
			* Continuously jam all wifi clients and access points within range. The effectiveness of this script is constrained by your wireless card. Alfa cards seem to effectively jam within about a block radius with heavy access point saturation. Granularity is given in the options for more effective targeting.
		* [ESP8266 deauther](https://github.com/spacehuhn/esp8266_deauther)
			* Deauthentication attack and other exploits using an ESP8266!
	* **Logging/Monitoring**
		* [SniffAir An Open Source Framework for Wireless Security Assessments Matthew Eidelberg - DerbyCon7](https://www.youtube.com/watch?v=QxVkr-3RK94&app=desktop)
		* [SniffAir](https://github.com/Tylous/SniffAir)
		* [probemon](https://github.com/nikharris0/probemon)
			* A simple command line tool for monitoring and logging 802.11 probe frames
		* [Snifflab: An environment for testing mobile devices](https://openeffect.ca/snifflab-an-environment-for-testing-mobile-devices/)
			* Specifically, we have created a WiFi hotspot that is continually collecting all the packets sent over it. All connected clients’ HTTPS communications are subjected to a “Man-in-the-middle” attack, whereby they can later be decrypted for analysis.
		* [Nzyme](https://github.com/lennartkoopmann/nzyme)
			* Nzyme collects 802.11 management frames directly from the air and sends them to a Graylog (Open Source log management) setup for WiFi IDS, monitoring, and incident response. It only needs a JVM and a WiFi adapter that supports monitor mode.
	* **MiTM**
		* [Fluxion](https://github.com/wi-fi-analyzer/fluxion)
			* Fluxion is a security auditing and social-engineering research tool. It is a remake of linset by vk496 with (hopefully) less bugs and more functionality. The script attempts to retrieve the WPA/WPA2 key from a target access point by means of a social engineering (phishing) attack. It's compatible with the latest release of Kali (rolling). Fluxion's attacks' setup is mostly manual, but experimental auto-mode handles some of the attacks' setup parameters
	* **WPS**
		* [pixiewps](https://github.com/wiire/pixiewps)
			* Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack). It is meant for educational purposes only. All credits for the research go to Dominique Bongard.
	* **Cracking Passwords**
		* [Wireless Password Cracking With Cloud Clusters](http://www.commonexploits.com/wireless-password-cracking-with-cloud-clusters/)
		* [hcxtools](https://github.com/ZerBea/hcxtools)
			* Portable solution for capturing wlan traffic and conversion to hashcat formats (recommended by hashcat) and to John the Ripper formats. hcx: h = hash, c = capture, convert and calculate candidates, x = different hashtypes
* **Eduroam**
	* **101**
		* [The eduroam Architecture for Network Roaming - RFC 7593](https://tools.ietf.org/html/rfc7593)
		* [Eduroam - Wikipedia](https://en.wikipedia.org/wiki/Eduroam)
	* **Articles/Blogposts/Writeups**
		* [Server Certificate Practices in Eduroam (2015)](http://services.geant.net/cbp/Knowledge_Base/Wireless/Documents/cbp-33_server-certificate-practices-in-eduroam.pdf)
	* **Attacking**
		* [MITM Attack Model against eduroam (2013)](http://www.eduroam.zm/Maninmiddle.pdf)
		* [A Practical Investigation of Identity Theft Vulnerabilities in Eduroam (2015)](https://www.syssec.rub.de/media/infsec/veroeffentlichungen/2015/05/07/eduroam_WiSec2015.pdf)
	* **Tools**
		* [eduroam FreeRADIUS Docker](https://github.com/spgreen/eduroam-freeradius-docker)
* **EAP**
	* [EAP-PWD: Extensible Authentication Protocol (EAP) Authentication Using Only a Password - RFC 5931](https://tools.ietf.org/html/rfc5931)
	* [eaphammer](https://github.com/s0lst1c3/eaphammer)
		* EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. It is designed to be used in full scope wireless assessments and red team engagements. As such, focus is placed on providing an easy-to-use interface that can be leveraged to execute powerful wireless attacks with minimal manual configuration. To illustrate how fast this tool is, here's an example of how to setup and execute a credential stealing evil twin attack against a WPA2-TTLS network in just two commands:
	* [crEAP](https://github.com/Snizz/crEAP)
		* Python script to identify wireless networks EAP types and harvest users 
	* [EAPEAK](https://github.com/securestate/eapeak)
		* EAPeak is a suite of open source tools to facilitate auditing of wireless networks that utilize the Extensible Authentication Protocol framework for authentication. It is meant to give useful information relating to the security of these networks for pentesters to use while searching for vulnerabilities. 
	* [eapmd5pass](http://www.willhackforsushi.com/?page_id=67)
		* An implementation of an offline dictionary attack against the EAP-MD5 protocol. This utility can be used to audit passwords used for EAP-MD5 networks from wireless packet captures, or by manually specifying the challenge, response and associated authentication information.
* **Evil/Infernal Twin**
	* [Infernal twin](https://n0where.net/automated-evil-twin-attack/)
	* [Evil Twin vulnerabilities in Wi-Fi networks (Master Thesis, 2016)](http://www.cs.ru.nl/bachelorscripties/2016/Matthias_Ghering___4395727___Evil_Twin_Vulnerabilities_in_Wi-Fi_Networks.pdf)
	* [Evil Twin Vulnerabilities in Wi-Fi Networks (Bachelor Thesis, 2016)](http://www.cs.ru.nl/bachelorscripties/2016/Matthias_Ghering___4395727___Evil_Twin_Vulnerabilities_in_Wi-Fi_Networks.pdf)
	* [Infernal-Twin](https://github.com/entropy1337/infernal-twin)
		* This is the tool created to automate Evil Twin attack and capturing public and guest credentials of Access Point
* **Exploit Dev**
	* [Exploiting 802.11 Wireless Driver Vulnerabilities on Windows](http://uninformed.org/?v=all&a=29&t=sumry)
		* This paper describes the process of identifying and exploiting 802.11 wireless device driver vulnerabilities on Windows. This process is described in terms of two steps: pre-exploitation and exploitation. The pre-exploitation step provides a basic introduction to the 802.11 protocol along with a description of the tools and libraries the authors used to create a basic 802.11 protocol fuzzer. The exploitation step describes the common elements of an 802.11 wireless device driver exploit. These elements include things like the underlying payload architecture that is used when executing arbitrary code in kernel-mode on Windows, how this payload architecture has been integrated into the 3.0 version of the Metasploit Framework, and the interface that the Metasploit Framework exposes to make developing 802.11 wireless device driver exploits easy. Finally, three separate real world wireless device driver vulnerabilities are used as case studies to illustrate the application of this process. It is hoped that the description and illustration of this process can be used to show that kernel-mode vulnerabilities can be just as dangerous and just as easy to exploit as user-mode vulnerabilities. In so doing, awareness of the need for more robust kernel-mode exploit prevention technology can be raised. 
* **KARMA**
	* [Karma](http://www.theta44.org/karma/)
	* [Attacking automatic Wireless network selection (2005)](https://www.trailofbits.com/resources/attacking_automatic_network_selection_paper.pdf)
	* [Why do Wi-Fi Clientes disclose their PNL for Free Still Today? (2015)](http://blog.dinosec.com/2015/02/why-do-wi-fi-clients-disclose-their-pnl.html)
	* [Instant KARMA might still gets you (2015)](https://insights.sei.cmu.edu/cert/2015/08/instant-karma-might-still-get-you.html)
* **KRACK**
	* [Key Reinstallation Attacks](https://www.krackattacks.com/)
	* [KRACK - Wikipedia](https://en.wikipedia.org/wiki/KRACK)
	* **Tools**
		* [krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts)
			* This project contains scripts to test if clients or access points (APs) are affected by the KRACK attack against WPA2. For [details behind this attack see our website](https://www.krackattacks.com/) and [the research paper](https://papers.mathyvanhoef.com/ccs2017.pdf).
* **RADIUS**
	* [apbleed](https://github.com/vanhoefm/apbleed/)
		* Allows you to use existing heartbleed tools to test the RADIUS server
	* [Authentication protocols that DO support hashed passwords (FreeRADIUS mailing list)](http://freeradius-users.freeradius.narkive.com/ixOQ7yiK/authentication-protocols-that-do-support-hashed-passwords)
* **TKIP Related**
	* [Practical attacks against WEP and WPA (2008)](http://dl.aircrack-ng.org/breakingwepandwpa.pdf)
	* [An Improved Attack on TKIP (2009)  ](http://link.springer.com/chapter/10.1007/978-3-642-04766-4_9#page-1)
	* [Cryptanalysis of IEEE 802.11i TKIP](http://download.aircrack-ng.org/wiki-files/doc/tkip_master.pdf)
	* [Enhanced TKIP Michael Attacks (2010)](http://download.aircrack-ng.org/wiki-files/doc/enhanced_tkip_michael.pdf)
	* [Plaintext Recovery Attacks Against WPA/TKIP (2013)](https://eprint.iacr.org/2013/748.pdf)
	* [Practical verification of WPA-TKIP vulnerabilities (2013)](https://lirias.kuleuven.be/bitstream/123456789/401042/1/wpatkip.pdf)
	* [On the security of RC4 in TLS (USENIX, 2013)](http://www.isg.rhul.ac.uk/tls/RC4biases.pdf)
	* [All Your Biases Belong to Us: Breaking RC4 in WPA-TKIP and TLS (USENIX, 2015)](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-vanhoef.pdf)
	* [A Security Analysis of the WPA-TKIP and TLS Security Protocols (PhD Thesis, 2016)](https://lirias.kuleuven.be/bitstream/123456789/543228/1/thesis.pdf)
	* [Predicting and Abusing WPA2/802.11 Group Keys (2016)](http://papers.mathyvanhoef.com/33c3-broadkey-slides.pdf)
* **WEP**
	* [WPA Migration Mode:  WEP is back to haunt you...(slides)](http://dl.aircrack-ng.org/wiki-files/doc/technique_papers/Meiners,_Sor_-_WPA_Migration_Mode_WEP_is_back_to_haunt_you_-_slides.pdf)
		* Migration mode, from Cisco, allows both WEP and WPA clients on the same AP. Besides the fact that the WEP key can be cracked easily, they also bypass the additional security settings offered by Cisco. 
* **WPA/2**
	* [Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys Mathy Vanhoef and Frank Piessens,  Katholieke Universiteit Leuven](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_vanhoef.pdf) 
	* [Wifi Tracking: Collecting the (probe) Breadcrumbs - David Switzer](https://www.youtube.com/watch?v=HzQHWUM8cNo)
		* Wifi probes have provided giggles via Karma and Wifi Pineapples for years, but is there more fun to be had? Like going from sitting next to someone on a bus, to knowing where they live and hang out? Why try to MITM someone’s wireless device in an enterprise environment where they may notice — when getting them at their favorite burger joint is much easier. In this talk we will review ways of collecting and analyzing probes. We’ll use the resulting data to figure out where people live, their daily habits, and discuss uses (some nice, some not so nice) for this information. We’ll also dicuss how to make yourself a little less easy to track using these methods. Stingrays are price prohibitive, but for just tracking people’s movements.. this is cheap and easy.
	* [Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys](https://github.com/vanhoefm/broadkey)
		* Attacks against weak 802.11 Random Number Generators
* **WPS**
	* **101**
		* [Brute forcing Wi-Fi Protected Setup - Stefan Viehböck](https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf)
			* The original paper on WPS cracking.
		* [Offline bruteforce attack on wifi protected setup (**Pixie dust attack**, 2014)](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf)
	* **Articles/Blogposts/Writeups**
		* [An Investigation into the Wi-Fi Protected Setup PIN of the Linksys WRT160N v2 (2012)](http://ro.ecu.edu.au/cgi/viewcontent.cgi?article=1139&context=ism)
		* [Reversing D-Links WPS pin algorithm](http://www.devttys0.com/2014/10/reversing-d-links-wps-pin-algorithm/)
	* **Tools**
		* [wpscrack](https://github.com/ml31415/wpscrack/)
			* Continuation of wpscrack originally written by Stefan Viehböck
		* [reaver_reattempt](https://github.com/kurobeats/reaver_reattempt/)
			* Change the Mac address of the wifi connection as well as the emulated one created by airmon-ng in an attempt to avoid being locked out of routers for repeated WPS attack attempts
		* [Reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x/)
			* Community forked version which includes various bug fixes, new features and additional attack method (such as the offline Pixie Dust attack)
		* [WPSIG](https://www.coresecurity.com/corelabs-research/open-source-tools/wpsig)
			* Simple tool (written in Python) that does information gathering using WPS information elements.
* **Misc**
	* [Scrutinizing WPA2 Password Generating Algorithms in Wireless Routers (WOOT, 2015)](https://www.usenix.org/system/files/conference/woot15/woot15-paper-lorente.pdf)
	* [Keyspace List for WPA on Default Routers](https://hashcat.net/forum/thread-6170.html)
	* [nexmon](https://github.com/seemoo-lab/nexmon)
		* Nexmon is our C-based firmware patching framework for Broadcom/Cypress WiFi chips that enables you to write your own firmware patches, for example, to enable monitor mode with radiotap headers and frame injection.
	* [BoopSuite](https://github.com/MisterBianco/BoopSuite/)
		* BoopSuite a wireless pentesting suite designed to emulate aircrack-ng functionality for personal growth.
	* [New attack on WPA/WPA2 using PMKID - atom - hashcat.net](https://hashcat.net/forum/thread-7717.html)
* **Why not?**
	* [Start Your Own (Wireless) ISP](https://startyourownisp.com/)




----------------------
### <a name="rfid">RFID - Radio Frequency Identification</a>
* **101**
	* [Radio-frequency identification - Wikipedia](https://en.wikipedia.org/wiki/Radio-frequency_identification)
	* [NFC Frequently Asked Questions](https://www.securetechalliance.org/publications-nfc-frequently-asked-questions/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* Security of RFID Protocols A Case Study** | 
		* In the context of Dolev-Yao style analysis of security proto cols, we investigate the security claims of a pro- posed strong-security RFID authentication protocol. We ex hibit a flaw which has gone unnoticed in RFID protocol literature and present the resulting attacks on au thentication, untraceability, and desynchroniza- tion resistance. We analyze and discuss the authors proofs of security. References to other vulnerable protocols are given.
	* [Exploring NFC Attack Surface](https://media.blackhat.com/bh-us-12/Briefings/C_Miller/BH_US_12_Miller_NFC_attack_surface_WP.pdf)
	* [Owning and Cloning NFC Payment Cards](https://github.com/peterfillmore/Talk-Stuff/blob/master/Syscan2015/PeterFillmore_Syscan2015.pdf]
	* [On Relaying NFC Payment Transactions using Android devices](https://www.slideshare.net/cgvwzq/on-relaying-nfc-payment-transactions-using-android-devices)
	* [NFC Hacking: NFCProxy with Android Beam](https://www.youtube.com/watch?v=tFi0vYuYeAI&feature=youtu.be)
	* [Practical Experiences on NFC Relay Attacks with Android: Virtual Pickpocketing Revisited](https://conference.hitb.org/hitbsecconf2015ams/materials/Whitepapers/Relay%20Attacks%20in%20EMV%20Contactless%20Cards%20with%20Android%20OTS%20Devices.pdf)
	* [Practical Guide to RFID Badge copying](https://blog.nviso.be/2017/01/11/a-practical-guide-to-rfid-badge-copying/)
	* [RFID Hacking with The Proxmark 3](https://blog.kchung.co/rfid-hacking-with-the-proxmark-3/)
* **Tools**
	* [ravenhid](https://github.com/emperorcow/ravenhid)
		* Hardware and software to run a RFID reader to harvest card information. This is the PCB design and Arduino code that will run a RFID reader, allowing you to gather and harvest cards. Typically, a larger reader, such as those in garages, will be more successful, allowing you to ready over a couple feet instead of inches. The board itself is designed to be modular and support multiple methods to output harvested cards once they are read:
			* Text file on a MicroSD card; Print out to LCD; Bluetooth Low Energy Arduino serial connection 
		* Each of these options are supported in code, but can be ignored on the PCB. The PCB itself has been designed to use a pluggable module for each of these options, making it easy to ignore, install, or change out which ones you find useful.
	* [RFIDiggity - Pentester Guide to Hacking HF/NFC and UHF RFID - Defcon23](https://www.youtube.com/watch?v=7o38hyQWw6g)
	* [Wiegotcha: Long Range RFID Thieving](https://github.com/lixmk/Wiegotcha)
		* Wiegotcha is the next evolution of Long Range RFID badge capturing. Based on previous work by Fran Brown and Bishop Fox (Tastic RFID Thief), Wiegotcha uses a Raspberry Pi in place of an Arduino for the added capabilities and ease of customization. One of the immediate benefits of using an RPi is quick and easy wireless communication with the badge reader.
	* [Swiss Army Knife for RFID](https://www.cs.bham.ac.uk/~garciaf/publications/Tutorial_Proxmark_the_Swiss_Army_Knife_for_RFID_Security_Research-RFIDSec12.pdf)



----------------------
### <a name="retroreflectors">RF RetroReflectors</a>
* **101**
	* [Modulating retro-reflector - Wikipedia](https://en.wikipedia.org/wiki/Modulating_retro-reflector)
* **Articles/Presentations/Talks/Writeups**
	* [[TROOPERS15] Michael Ossmann - RF Retroflectors, Emission Security and SDR](https://www.youtube.com/watch?v=9DABAS-PCFM)
	* [The NSA Playset - RF Retroreflectors - Defcon22](https://www.youtube.com/watch?v=5gb3C80_wXI)
* **Tools**
	* [CONGAFLOCK - NSA Playset](http://www.nsaplayset.org/congaflock)
		* CONGAFLOCK is a general purpose RF retroreflector intended for experimentation.
	* [The Thing (Listening Device) - Wikipedia](https://en.wikipedia.org/wiki/The_Thing_(listening_device))
	* [retroreflectors](https://github.com/mossmann/retroreflectors)

----------------------
### <a name="satellite">Satellite Related</a>
* [SATELLITE TV RECEIVERS: FROM REMOTE CONTROL TO ROOT SHELL - Sofiane Talmat](https://vimeo.com/album/3682874/video/148910624)
* [Spread Spectrum Satcom Hacking: Attacking The Globalstar Simplex Data Service - Colby Moore - BHUSA2015](https://www.youtube.com/watch?v=1VbmHmzofmc)
* [A Wake-Up Call for SATCOM Security - Ruben Santamarta](https://ioactive.com/pdfs/IOActive_SATCOM_Security_WhitePaper.pdf)
* [Inmarsat-C - Inmarsat](https://www.inmarsat.com/services/safety/inmarsat-c/)
* [Inmarsat-C - Wikipedia](https://en.wikipedia.org/wiki/Inmarsat-C)
* [Very-small-aperture terminal - Wikipedia](https://en.wikipedia.org/wiki/Very-small-aperture_terminal)
* [BGAN](https://www.inmarsat.com/service/bgan/)
* [Broadband Global Area Network - Wikipedia](https://en.wikipedia.org/wiki/Broadband_Global_Area_Network)
* [SwiftBroadband - inmarsat](https://www.inmarsat.com/service-collection/swiftbroadband/)
* [SwiftBroadband - Wikipedia](https://en.wikipedia.org/wiki/SwiftBroadband)
* [FleetBroadband](https://www.inmarsat.com/service/fleetbroadband/)
* [Fleet Broadband - Wikipedia](https://en.wikipedia.org/wiki/FleetBroadband)


----------------------
### <a name="sdr">Software Defined Radio</a>
* **101**
	* [Software Defined Radio for Infosec People 101](http://garrettgee.com/appearances/software-defined-radio-for-infosec-people-101/)
	* [So you want to get into SDR talk](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/01-so-ya-wanna-get-into-sdr-russell-handorf)
	* [Bringing Software Defined Radio to the Penetration Testing Community](https://www.youtube.com/watch?v=hZJDdz6kVJ4)
* **Articles/Presentations/Talks/Writeups**	* [Introduction to SDR and the Wireless Village(Defcon)](https://www.youtube.com/watch?v=F9kKo190_oE)
	* [Software Defined Radio with HackRF](https://greatscottgadgets.com/sdr/[WebSDR](http://websdr.org/)
		* A WebSDR is a Software-Defined Radio receiver connected to the internet, allowing many listeners to listen and tune it simultaneously. SDR technology makes it possible that all listeners tune independently, and thus listen to different signals; this is in contrast to the many classical receivers that are already available via the internet.
	* [Hacking the Wireless World with Software Defined Radio 2.0](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/14-hacking-the-wireless-world-with-software-defined-radio-2-0-balint-seeber)
	* [Exploit: Hacking the Wireless World with Software Defined Radio BlackHat USA 2014](https://www.youtube.com/watch?v=XWbwFfxzw6w) 
	* [From baseband to bitstream and back again: What security researchers really want to do with SDR - Andy Davis - nccgroup](https://cansecwest.com/slides/2015/From_Baseband_to_bitstream_Andy_Davis.pdf)
	* [Using Software Defined radio to attack Smart home systems](https://www.sans.org/reading-room/whitepapers/threats/software-defined-radio-attack-smart-home-systems-35922)
	* [Using Software Defined Radio for IoT Analysis](https://www.irongeek.com/i.php?page=videos/bsidesnova2017/102-using-software-defined-radio-for-iot-analysis-samantha-palazzolo)
	* [Decoding the LoRa IoT Protocol with an RTL-SDR](http://www.rtl-sdr.com/decoding-the-iot-lora-protocol-with-an-rtl-sdr/)
* **Documentation**
* **General**
	* [PHYs, MACs, and SDRs - Robert Ghilduta](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/17-phys-macs-and-sdrs-robert-ghilduta)
		* The talk will touch on a variety of topics and projects that have been under development including YateBTS, PHYs, MACs, and GNURadio modules. The talk will deal with GSM/LTE/WiFi protocol stacks.
	* [RTL-SDR and GNU Radio with Realtek RTL2832U [Elonics E4000/Raphael Micro R820T] software defined radio receivers.](http://superkuh.com/rtlsdr.html)
* **Tools**
	* [GNU Radio](http://gnuradio.org/redmine/projects/gnuradio/wiki)
		* GNU Radio is a free & open-source software development toolkit that provides signal processing blocks to implement software radios. It can be used with readily-available low-cost external RF hardware to create software-defined radios, or without hardware in a simulation-like environment. It is widely used in hobbyist, academic and commercial environments to support both wireless communications research and real-world radio systems.
	* [Gqrx](http://gqrx.dk/)
		* Gqrx is a software defined radio receiver powered by the GNU Radio SDR framework and the Qt graphical toolkit.
		* [Documentation](http://gqrx.dk/category/doc)
		* [Practical Tips & Tricks](http://gqrx.dk/doc/practical-tricks-and-tips)
	* [GPS-SDR-SIM](https://github.com/osqzss/gps-sdr-sim)
		* Software-Defined GPS Signal Simulator; GPS-SDR-SIM
	* [nrsc5](https://github.com/theori-io/nrsc5)
		* NRSC-5 receiver for rtl-sdr
	* [gr-nrsc5](https://github.com/argilo/gr-nrsc5)
		* A GNU Radio implementation of HD Radio (NRSC-5)
	* [rtlamr](https://github.com/bemasher/rtlamr)
		* An rtl-sdr receiver for Itron ERT compatible smart meters operating in the 900MHz ISM band. 
	* [Uni-SDR Link](https://github.com/ms-dev-1/uni-sdr-link/releases)
		* The initial release of Uni-SDR Link. This applications sole purpose is to allow Universal Trunker (aka Unitrunker) to control the tuning frequency of individual VFO's in SDR Console v2. This is achieved by translating Unitrunker Receiver Control commands into a format accepted by SDR Console. Communication occurs over virtual com / serial ports.
	* [ShinySDR](https://github.com/kpreid/shinysdr)
		* This is the software component of a software-defined radio receiver. When combined with hardware devices such as the USRP, RTL-SDR, or HackRF, it can be used to listen to a wide variety of radio transmissions, and can be extended via plugins to support even more modes.
	* [Scapy-Radio](https://bitbucket.org/cybertools/scapy-radio/src)
		* This tool is a modified version of scapy that aims at providing an quick and efficient pentest tool with RF capabilities. A modified version of scapy that can leverage GNU Radio to handle a SDR card. 
	* [Universal Radio Hacker](https://github.com/jopohl/urh)
	* [RTLSDR Scanner](https://github.com/EarToEarOak/RTLSDR-Scanner)
		* A cross platform Python frequency scanning GUI for the OsmoSDR rtl-sdr library.
		* [Details](https://eartoearoak.com/software/rtlsdr-scanner)
		* [Manual](https://github.com/EarToEarOak/RTLSDR-Scanner/blob/master/doc/Manual.pdf)
	* [gr-lora](https://github.com/BastilleResearch/gr-lora)
		* This is an open-source implementation of the LoRa CSS PHY, based on the blind signal analysis conducted by @matt-knight. The original research that guided this implementation may be found at https://github.com/matt-knight/research
	* [hdfm](https://github.com/KYDronePilot/hdfm)
		* hdfm displays weather and traffic maps received from iHeartRadio HD radio stations. It relies on nrsc5 to decode and dump the radio station data for it to process and display.



* **Wi-Max**
	* [Ghosts from the Past: Authentication bypass and OEM backdoors in WiMAX routers](http://blog.sec-consult.com/2017/06/ghosts-from-past-authentication-bypass.html)


--------------------------------
### <a name="zigbee">Zigbee Wireless Networks</a>
* **101**
	* [Zigbee - Wikipedia](https://en.wikipedia.org/wiki/Zigbee)
	* [IEEE 802.15.4 - Wikipedia](https://en.wikipedia.org/wiki/IEEE_802.15.4)
	* [IEEE Std 802.15.4-2015 (Revision of IEEE Std 802.15.4-2011) - IEEE Standard for Low-Rate Wireless Networks](https://standards.ieee.org/findstds/standard/802.15.4-2015.html)
* **Articles/Presentations/Talks/Writeups**
	* [ZigBee Exploited: The good, the bad and the ugly - Tobias Zillner](http://www.sicherheitsforschung-magdeburg.de/uploads/journal/MJS_045_Zillner_ZigBee.pdf)
	* [KillerBee Framework](https://code.google.com/p/killerbee/)
		* KillerBee is a Python based framework and tool set for exploring and exploiting the security of ZigBee and IEEE 802.15.4 networks. Using KillerBee tools and a compatible IEEE 802.15.4 radio interface, you can eavesdrop on ZigBee networks, replay traffic, attack cryptosystems and much more. Using the KillerBee framework, you can build your own tools, implement ZigBee fuzzing, emulate and attack end-devices, routers and coordinators and much more. 
	* [SecBee](https://github.com/Cognosec/SecBee)
		* SecBee is a ZigBee security testing tool developed by Cognosec. The goal is to enable developers and security testers to test ZigBee implementations for security issues.
	* [Frony Fronius - Exploring Zigbee signals from Solar City](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t102-frony-fronius-exploring-zigbee-signals-from-solar-city-jose-fernandez)
		* Solar equipment is becoming more readily used in homes and businesses due to cost savings, eco-friendly conservationism and current tax incentives. Companies like SolarCity use Power Inverters/Meters from 3rd parties in order to provide it's services while making the solution affordable for customers. This research will focus on understanding the communication between the Inverter, Internet Gateway and web portal used to view electrical consumption of subscriber.
* **Tools**
* [KillerBee](https://github.com/riverloopsec/killerbee)
	* Framework and Tools for Attacking ZigBee and IEEE 802.15.4 networks.



### <a name="zwave">Z-Wave</a>
* **101**
* **Articles/Presentations/Talks/Writeups**
	* [Stealthy and Persistent Back Door for Z-Wave Gateways](http://www.irongeek.com/i.php?page=videos/derbycon5/stable18-stealthy-and-persistent-back-door-for-z-wave-gateways-jonathan-fuller-ben-ramsey)
		* Z-Wave is a proprietary wireless protocol that is gaining market share in home automation and security systems. However, very little work has been done to investigate the security implications of these sub-GHz devices. In this talk we review recent work on hacking Z-Wave networks, and introduce a new attack that creates a persistent back door. This attack maintains a stealthy, parallel, and persistent control channel with all Z-Wave devices in the home. We will demonstrate the attack against a commercial Z-Wave security system.
	* [Honey, I'm Home!! Hacking Z-Wave Home Automation Systems - video](https://www.youtube.com/watch?v=KYaEQhvodc8)
		* [Slides - PDF](https://cybergibbons.com/wp-content/uploads/2014/11/honeyimhome-131001042426-phpapp01.pdf)
* **Tools**


## Miscellaneous
* [Wireless Keyboard Sniffer](https://samy.pl/keysweeper/)
* [nexmon](https://github.com/seemoo-lab/nexmon)
	* Nexmon is our C-based firmware patching framework for Broadcom/Cypress WiFi chips that enables you to write your own firmware patches, for example, to enable monitor mode with radiotap headers and frame injection.





