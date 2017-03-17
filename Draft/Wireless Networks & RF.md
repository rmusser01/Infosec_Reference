##Wireless Networks


TOC
Cull

* [General(#general
* [General Software Tools](#generalswt)
* [Dongles/HW Tools](#dongles)
* [Cellular Networks](#cn)
* [Software Defined Radio(#sdr)
* [802.11](#80211)
* [Zigbee](#zigbee)
* [Bluetooth](#bt)
* [RetroReflectors](#retroreflectors)
* [Foxhunting & WarDriving](#fxh}
* [General Blogs/Sites](#gbs)
* [Talks/Presentations & Videos](#talks)
* [Papers](#papers)

* [Miscellaneous](#misc)



#### Sort

http://umtrx.org/

[RZUSBstick](http://www.atmel.com/tools/rzusbstick.aspx)
* The starter kit accelerates development, debugging, and demonstration for a wide range of low power wireless applications including IEEE 802.15.4, 6LoWPAN, and ZigBee networks.  The kit includes one USB stick with a 2.4GHz transceiver and a USB connector. The included AT86RF230 transceiver's high sensitivity supports the longest range for wireless products. The AT90USB1287 incorporates fast USB On-the-Go.

http://dl.aircrack-ng.org/wiki-files/doc/technique_papers/Meiners,_Sor_-_WPA_Migration_Mode_WEP_is_back_to_haunt_you_-_slides.pdf 

[rtlamr](https://github.com/bemasher/rtlamr)
* An rtl-sdr receiver for Itron ERT compatible smart meters operating in the 900MHz ISM band. 


[HOPE Number Nine (2012): Practical Insecurity in Encrypted Radio](https://www.youtube.com/watch?v=7or-_gT8TWU&app=desktop)

[sysmocom publicly releases Osmocom user manuals](https://www.sysmocom.de/news/sysmocom-publicly-releases-osmocom-user-manuals/)

[Building a portable GSM BTS using the Nuand bladeRF, Raspberry Pi and YateBTS (The Definitive and Step by Step Guide) ](https://blog.strcpy.info/2016/04/21/building-a-portable-gsm-bts-using-bladerf-raspberry-and-yatebts-the-definitive-guide/)

[DEF CON 23 - JoshInGeneral - Meeting People Over WiFi ](https://www.youtube.com/watch?v=9SIMe0yMy78)
* In this talk we will talk about some of the things that can identify you in an environment and how people can track you. We will look at bluetooth scanning apps that you can use every day to track people inconspicuously from your phone, while walking, metroing, or as a passenger in a car driving.

https://media.blackhat.com/us-13/us-13-Nohl-Rooting-SIM-cards-Slides.pdf 

[Universal Radio Hacker](https://github.com/jopohl/urh)


| **Security of RFID Protocols  A Case Study** | 
In the context of Dolev-Yao style analysis of security proto cols, we investigate the security claims of a pro- posed strong-security RFID authentication protocol. We ex hibit a flaw which has gone unnoticed in RFID protocol literature and present the resulting attacks on au thentication, untraceability, and desynchroniza- tion resistance. We analyze and discuss the authors proofs of security. References to other vulnerable protocols are given.


https://www.evilsocket.net/2016/03/31/how-to-build-your-own-rogue-gsm-bts-for-fun-and-profit/ 


https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/may/gsmgprs-traffic-interception-for-penetration-testing-engagements/ 


http://www.irongeek.com/i.php?page=videos/derbycon5/stable18-stealthy-and-persistent-back-door-for-z-wave-gateways-jonathan-fuller-ben-ramsey 


[ HOPE Number Nine (2012): Practical Insecurity in Encrypted Radio](https://www.youtube.com/watch?v=7or-_gT8TWU&app=desktop)
* APCO Project 25 ("P25") is a suite of wireless communications protocols used in the United States and elsewhere for public safety two-way (voice) radio systems. The protocols include security options in which voice and data traffic can be cryptographically protected from eavesdropping. This talk analyzes the security of P25 systems against passive and active adversaries. The panel found a number of protocol, implementation, and user interface weaknesses that routinely leak information to a passive eavesdropper or that permit highly efficient and difficult to detect active attacks. They found new "selective subframe jamming" attacks against P25, in which an active attacker with very modest resources can prevent specific kinds of traffic (such as encrypted messages) from being received, while emitting only a small fraction of the aggregate power of the legitimate transmitter. And, more significantly, they found that even passive attacks represent a serious immediate threat. In an over-the-air analysis conducted over a two year period in several U.S. metropolitan areas, they found that a significant fraction of the "encrypted" P25 tactical radio traffic sent by federal law enforcement surveillance operatives is actually sent in the clear - in spite of their users' belief that they are encrypted - and often reveals such sensitive data as the names of informants in criminal investigations.

[Scapy-Radio](https://bitbucket.org/cybertools/scapy-radio/src
* This tool is a modified version of scapy that aims at providing an quick and efficient pentest tool with RF capabilities.
A modified version of scapy that can leverage GNU Radio to handle a SDR card
GNU Radio flow graphs (GRC files) we have build that allows full duplex communication
GNU Radio blocks we have written to handle several protocols
[The big GSM write-up  how to capture, analyze and crack GSM?](http://domonkos.tomcsanyi.net/?p=418)

[KillerBee](https://github.com/riverloopsec/killerbee)
* Framework and Tools for Attacking ZigBee and IEEE 802.15.4 networks.
[ShinySDR](https://github.com/kpreid/shinysdr)
* This is the software component of a software-defined radio receiver. When combined with hardware devices such as the USRP, RTL-SDR, or HackRF, it can be used to listen to a wide variety of radio transmissions, and can be extended via plugins to support even more modes.
[SecBee](https://github.com/Cognosec/SecBee) 
* SecBee is a ZigBee security testing tool developed by Cognosec. The goal is to enable developers and security testers to test ZigBee implementations for security issues.

[The Secret Life of SIM Cards - Defcon21](https://www.youtube.com/watch?v=31D94QOo2gY)


How To Build Your Own Rogue GSM BTS For Fun And Profit
https://www.evilsocket.net/2016/03/31/how-to-build-your-own-rogue-gsm-bts-for-fun-and-profit/

[Uni-SDR Link](https://github.com/ms-dev-1/uni-sdr-link/releases)
* The initial release of Uni-SDR Link. This applications sole purpose is to allow Universal Trunker (aka Unitrunker) to control the tuning frequency of individual VFO's in SDR Console v2. This is achieved by translating Unitrunker Receiver Control commands into a format accepted by SDR Console. Communication occurs over virtual com / serial ports.


[StackOverflow post on intercepting GSM traffic](https://reverseengineering.stackexchange.com/questions/2962/intercepting-gsm-communications-with-an-usrp-and-gnu-radio)

[Guide to Basics of Wireless Networking](http://documentation.netgear.com/reference/fra/wireless/TOC.html)

[Wi-Fi Protected Access 2 (WPA2) Overview](https://technet.microsoft.com/library/bb878054)

[Establishing Wireless Robust Security Networks: A Guide to IEEE 802.11i - NIST](http://csrc.nist.gov/publications/nistpubs/800-97/SP800-97.pdf)


[SS7: Locate. Track. Manipulate.[31c3] by Tobias Engel (SnoopSnitch)](https://www.youtube.com/watch?v=lQ0I5tl0YLY)

[SnoopSnitch](https://opensource.srlabs.de/projects/snoopsnitch)
* SnoopSnitch is an Android app that collects and analyzes mobile radio data to make you aware of your mobile network security and to warn you about threats like fake base stations (IMSI catchers), user tracking and over-the-air updates. With SnoopSnitch you can use the data collected in the GSM Security Map at gsmmap.org and contribute your own data to GSM Map. This application currently only works on Android phones with a Qualcomm chipset and a stock Android ROM (or a suitable custom ROM with Qualcomm DIAG driver). It requires root priviliges to capture mobile network data.


[Brute forcing Wi-Fi Protected Setup - Stefan Viehböck](https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf)
* The original paper on WPS cracking.

[IEEE 802.11 Tutorial](http://wow.eecs.berkeley.edu/ergen/docs/ieee.pdf)
This document describes IEEE 802.11 Wireless Local Area Network (WLAN) Standard. It describes IEEE 802.11 MAC Layer in detail and it briefly mentions IEEE 802.11a, IEEE 802.11b physical layer standard and IEEE 802.11e MAC layer standard

[Management Frames Reference Sheet](http://download.aircrack-ng.org/wiki-files/other/managementframes.pdf)


[RTL-SDR Tutorial: Analyzing GSM with Airprobe and Wireshark](http://www.rtl-sdr.com/rtl-sdr-tutorial-analyzing-gsm-with-airprobe-and-wireshark/)
* The RTL-SDR software defined radio can be used to analyze cellular phone GSM signals, using Linux based tools Airprobe and Wireshark. This tutorial shows how I set up these tools for use with the RTL-SDR.

[Sniffing GSM with HackRF](https://web.archive.org/web/20130825000211/http://binaryrf.com/viewtopic.php?t=6&f=9)

[ CampZer0 // Domonkos Tomcsányi: GSM - have we overslept the last wake-up call?](https://www.youtube.com/watch?v=3cnnQFP3VqE)

[Intercepting GSM Traffic](https://www.blackhat.com/presentations/bh-dc-08/Steve-DHulton/Presentation/bh-dc-08-steve-dhulton.pdf)

[GSM: SRSLY?](https://events.ccc.de/congress/2009/Fahrplan/events/3654.en.html)
* The worlds most popular radio system has over 3 billion handsets in 212 countries and not even strong encryption. Perhaps due to cold-war era laws, GSM's security hasn't received the scrutiny it deserves given its popularity. This bothered us enough to take a look; the results were surprising. From the total lack of network to handset authentication, to the "Of course I'll give you my IMSI" message, to the iPhone that really wanted to talk to us. It all came as a surprise  stunning to see what $1500 of USRP can do. Add a weak cipher trivially breakable after a few months of distributed table generation and you get the most widely deployed privacy threat on the planet. Cloning, spoofing, man-in-the-middle, decrypting, sniffing, crashing, DoS'ing, or just plain having fun. If you can work a BitTorrent client and a standard GNU build process then you can do it all, too. Prepare to change the way you look at your cell phone, forever

[Wideband GSM Sniffing [27C3]](https://www.youtube.com/watch?v=ZrbatnnRxFc)
* GSM is still the most widely used security technology in the world with a user base of 5 billion and a quickly growing number of critical applications. 26C3's rainbow table attack on GSM's A5/1 encryption convinced many users that GSM calls should be considered unprotected. The network operators, however, have not woken up to the threat yet. Perhaps the new capabilities to be unleashed this year -- like wide-band sniffing and real-time signal processing -- will wake them up. Now that GSM A5/1 encryption can be cracked in seconds, the complexity of wireless phone snooping moved to signal processing. Since GSM hops over a multitude of channels, a large chunk of radio spectrum needs to be analyzed, for example with USRPs, and decoded before storage or decoding. We demonstrate how this high bandwidth task can be achieved with cheap programmable phones.


[29C3 GSM: Cell phone network review](https://www.youtube.com/watch?v=9wwco24EsHs
* Did you notice 262 42 in your mobile phone network search list at the last CCC events? Did you and your friends buy SIM cards at the PoC and help test the network by calling each other, or by calling through the bridge to the DECT network services? Did you ever wonder about the details of this open source test network, set up by a team of volunteers in the middle of the city? We would like to tell you all the details of the cell phone network we operate at 29C3, and show you some fancy graphs based on the network activity! We will describe the process of setting up the test network we operate at 29C3, what legal and technical challenges we have faced, and we will describe the actual installation at the CCH. We will also compare this with the 262 42 test networks that were operated using the same open source software but otherwise very different installations at CCC Camp 2011 and 28C3. We will go on to show various statistics that we collect from the network while it has been running.


http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/17-phys-macs-and-sdrs-robert-ghilduta


http://blog.ptsecurity.com/2014/12/4g-security-hacking-usb-modem-and-sim.html



http://www.3gpp.org/DynaReport/31048.htm

Ubertooth


Github.com/mikeryan/crackle

Scapy


Bluez.org

PyBT




###<a name="general">General</a>

[RF Testing Methodology - NCCGroup](https://nccgroup.github.io/RFTM/)
* The RFTM is an Open Source, collaborative testing methodology. It is specifically written in a straightforward way, avoiding mathematics where possible and focussed on providing the information that security researchers and consultants need to know in order to effectively test systems that employ RF technologies.
* [Signals and Modulation](https://nccgroup.github.io/RFTM/basics.html)
* [Information Sources](https://nccgroup.github.io/RFTM/information_sources.html)
* [Receiving Signals](https://nccgroup.github.io/RFTM/receiving_signals.html)
* [Developing an FSK receiver step-by-step](https://nccgroup.github.io/RFTM/fsk_receiver.html)
* [Transmitting Data](https://nccgroup.github.io/RFTM/transmitting_data.html)
* [ Developing an FSK transmitter step-by-step](https://nccgroup.github.io/RFTM/fsk_transmitter.html)
* [Signals Identification](https://nccgroup.github.io/RFTM/signals_identification.html)






###<a name="retroreflectors">RF RetroReflectors</a>

[[TROOPERS15] Michael Ossmann - RF Retroflectors, Emission Security and SDR](https://www.youtube.com/watch?v=9DABAS-PCFM)

[The NSA Playset - RF Retroreflectors - Defcon22](https://www.youtube.com/watch?v=5gb3C80_wXI)



###<a name="cn">Cellular Networks</a>

[gr-gsm](https://github.com/ptrkrysik/gr-gsm)
* Gnuradio blocks and tools for receiving GSM transmissions

[GSM MAP](http://gsmmap.org/#!/about) 
* The GSM Security Map compares the protection capabilities of mobile networks. Networks are rated in their protection capabilities relative to a reference network that implements all protection measures that have been seen in the wild. The reference is regularly updated to reflect new protection ideas becoming commercially available. Networks, therefore, have to improve continuously to maintain their score, just as hackers are continuously improving their capabilities.

[Mobile self-defense - Karsten Nohl](https://www.youtube.com/watch?v=GeCkO0fWWqc)

[Osmocom SIMtrace](http://bb.osmocom.org/trac/wiki/SIMtrace)
* Osmocom SIMtrace is a software and hardware system for passively tracing SIM-ME communication between the SIM card and the mobile phone. 

[NSA Playset - GSM Sniffing - Pierce&Loki - Defcon22](https://www.youtube.com/watch?v=tnn_qJGh1gc)

[Mobile: Cellular Exploitation on a Global Scale The Rise & Fall of the Control](https://www.youtube.com/watch?v=HD1ngJ85vWM)

[SS7: Locate. Track. Manipulate. You have a tracking device in your pocket](http://media.ccc.de/browse/congress/2014/31c3_-_6249_-_en_-_saal_1_-_201412271715_-_ss7_locate_track_manipulate_-_tobias_engel.html#video&t=424) 
* Companies are now selling the ability to track your phone number whereever you go. With a precision of up to 50 meters, detailed movement profiles can be compiled by somebody from the other side of the world without you ever knowing about it. But that is just the tip of the iceberg.

[Secrets of Sim](http://www.hackingprojects.net/2013/04/secrets-of-sim.html)

[4G LTE Architecture and Security Concerns](http://www.secforce.com/blog/2014/03/4g-lte-architecture-and-security-concerns/)

Cellular Networks in use North America:
	In use in Europe:
	In use in Asia:
	In use in Africa:
	In use in South America:






###<a name="sdr">Software Defined Radio</a>

[GNU Radio](http://gnuradio.org/redmine/projects/gnuradio/wiki)
* GNU Radio is a free & open-source software development toolkit that provides signal processing blocks to implement software radios. It can be used with readily-available low-cost external RF hardware to create software-defined radios, or without hardware in a simulation-like environment. It is widely used in hobbyist, academic and commercial environments to support both wireless communications research and real-world radio systems.

[So you want to get into SDR talk](www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/01-so-ya-wanna-get-into-sdr-russell-handorf)

[Software Defined Radio with HackRF](https://greatscottgadgets.com/sdr/[WebSDR](http://websdr.org/)
* A WebSDR is a Software-Defined Radio receiver connected to the internet, allowing many listeners to listen and tune it simultaneously. SDR technology makes it possible that all listeners tune independently, and thus listen to different signals; this is in contrast to the many classical receivers that are already available via the internet. 

[Hacking the Wireless World with Software Defined Radio 2.0](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/14-hacking-the-wireless-world-with-software-defined-radio-2-0-balint-seeber)

[Bringing Software Defined Radio to the Penetration Testing Community](https://www.youtube.com/watch?v=hZJDdz6kVJ4)

[Exploit: Hacking the Wireless World with Software Defined Radio BlackHat USA 2014](https://www.youtube.com/watch?v=XWbwFfxzw6w)

[From baseband to bitstream and back again: What security researchers really want to do with SDR - Andy Davis - nccgroup](https://cansecwest.com/slides/2015/From_Baseband_to_bitstream_Andy_Davis.pdf)

[Gqrx](http://gqrx.dk/)
* Gqrx is a software defined radio receiver powered by the GNU Radio SDR framework and the Qt graphical toolkit.
* [Documentation](http://gqrx.dk/category/doc)
* [Practical Tips & Tricks](http://gqrx.dk/doc/practical-tricks-and-tips)



###<a name="generalswt">General Software Tools</a>

Android IMSI-Catcher Detector (AIMSICD)](https://github.com/SecUpwN/Android-IMSI-Catcher-Detector)
* Android-based project to detect and avoid fake base stations (IMSI-Catchers) in GSM/UMTS Networks.

[Infernal-Twin](https://github.com/entropy1337/infernal-twin)
* This is the tool created to automate Evil Twin attack and capturing public and guest credentials of Access Point


###Dongles


[FunCube dongle](http://www.funcubedongle.com)


[Gr0SMoSDR](http://sdr.osmocom.org/trac/wiki/GrOsmoSDR)

[PyBOMBS](http://gnuradio.org/redmine/projects/pybombs/wiki)
* PyBOMBS (Python Build Overlay Managed Bundle System) is the new GNU Radio install management system for resolving dependencies and pulling in out-of-tree projects. One of the main purposes of PyBOMBS is to aggregate out-of-tree projects, which means that PyBOMBS needs to have new recipes for any new project. We have done a lot of the initial work to get known projects into the PyBOMBS system as is, but we will need project developers for new OOT projects or other projects not currently listed to help us out with this effort.	

 

###<a name="fxh">Fox Hunting & Wardriving</a>
[Practical Foxhunting 101](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/04-practical-foxhunting-101-simonj)
[iSniff](https://github.com/hubert3/iSniff-GPS) 
* iSniff GPS passively sniffs for SSID probes, ARPs and MDNS (Bonjour) packets broadcast by nearby iPhones, iPads and other wireless devices. The aim is to collect data which can be used to identify each device and determine previous geographical locations, based solely on information each device discloses about previously joined WiFi networks.
* iOS devices transmit ARPs which sometimes contain MAC addresses (BSSIDs) of previously joined WiFi networks, as described in [1]. iSniff GPS captures these ARPs and submits MAC addresses to Apple's WiFi location service (masquerading as an iOS device) to obtain GPS coordinates for a given BSSID. If only SSID probes have been captured for a particular device, iSniff GPS can query network names on wigle.net and visualise possible locations.



##<a name="80211">802.11</a>
[Karma](http://www.theta44.org/karma/)
[Wireless Password Cracking With Cloud Clusters](http://www.commonexploits.com/wireless-password-cracking-with-cloud-clusters/)

[Exploiting 802.11 Wireless Driver Vulnerabilities on Windows](http://uninformed.org/?v=all&a=29&t=sumry)
* This paper describes the process of identifying and exploiting 802.11 wireless device driver vulnerabilities on Windows. This process is described in terms of two steps: pre-exploitation and exploitation. The pre-exploitation step provides a basic introduction to the 802.11 protocol along with a description of the tools and libraries the authors used to create a basic 802.11 protocol fuzzer. The exploitation step describes the common elements of an 802.11 wireless device driver exploit. These elements include things like the underlying payload architecture that is used when executing arbitrary code in kernel-mode on Windows, how this payload architecture has been integrated into the 3.0 version of the Metasploit Framework, and the interface that the Metasploit Framework exposes to make developing 802.11 wireless device driver exploits easy. Finally, three separate real world wireless device driver vulnerabilities are used as case studies to illustrate the application of this process. It is hoped that the description and illustration of this process can be used to show that kernel-mode vulnerabilities can be just as dangerous and just as easy to exploit as user-mode vulnerabilities. In so doing, awareness of the need for more robust kernel-mode exploit prevention technology can be raised. 

[Fingerprinting 802.11 Implementations via Statistical Analysis of the Duration Field](http://uninformed.org/?v=all&a=23&t=sumry)
* The research presented in this paper provides the reader with a set of algorithms and techniques that enable the user to remotely determine what chipset and device driver an 802.11 device is using. The technique outlined is entirely passive, and given the amount of features that are being considered for inclusion into the 802.11 standard, seems quite likely that it will increase in precision as the standard marches forward. The implications of this are far ranging. On one hand, the techniques can be used to implement innovative new features in Wireless Intrusion Detection Systems (WIDS). On the other, they can be used to target link layer device driver attacks with much higher precision. 

[Wireless Pentesting on the Cheap](http://securitysynapse.blogspot.com/2013/12/wireless-pentesting-on-cheap-kali-tl.html)
In this article, we proved the capabilities of an inexpensive wireless adapter and a flexible virtualized wireless attack image by breaking into a WEP protected test network.  For just $16 

[WPA/WPA2 Dictionaries](https://wifi0wn.wordpress.com/wepwpawpa2-cracking-dictionary/)

[pixiewps](https://github.com/wiire/pixiewps)
* Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack). It is meant for educational purposes only. All credits for the research go to Dominique Bongard.




###<a name="rfid">RFID - Radio Frequency Identification</a>



[ravenhid](https://github.com/emperorcow/ravenhid)
* Hardware and software to run a RFID reader to harvest card information. This is the PCB design and Arduino code that will run a RFID reader, allowing you to gather and harvest cards. Typically, a larger reader, such as those in garages, will be more successful, allowing you to ready over a couple feet instead of inches. The board itself is designed to be modular and support multiple methods to output harvested cards once they are read:
	*	 Text file on a MicroSD card
*	 Print out to LCD
*	 Bluetooth Low Energy Arduino serial connection 
* Each of these options are supported in code, but can be ignored on the PCB. The PCB itself has been designed to use a pluggable module for each of these options, making it easy to ignore, install, or change out which ones you find useful.




###<a name="zigbee">Zigbee Wireless Networks</a>


[KillerBee Framework](https://code.google.com/p/killerbee/)
* KillerBee is a Python based framework and tool set for exploring and exploiting the security of ZigBee and IEEE 802.15.4 networks. Using KillerBee tools and a compatible IEEE 802.15.4 radio interface, you can eavesdrop on ZigBee networks, replay traffic, attack cryptosystems and much more. Using the KillerBee framework, you can build your own tools, implement ZigBee fuzzing, emulate and attack end-devices, routers and coordinators and much more. 

[SecBee](https://github.com/Cognosec/SecBee)
* SecBee is a ZigBee security testing tool developed by Cognosec. The goal is to enable developers and security testers to test ZigBee implementations for security issues.



###<a name="bt">BlueTooth</a>

[Bluetooth NSA Toolset Talk/Attacks video](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/15-the-nsa-playset-bluetooth-smart-attack-tools-mike-ryan)








###<a name="gbs">Blogs/Sites</a>












###<a name="talks">Talks/Presentations & Videos</a>

[Demystifying the Mobile Network by Chuck McAuley](http://2014.video.sector.ca/video/110383258)
* Must watch video. Very informative.




###<a name="papers">Papers</a>
[Taming Mr Hayes: Mitigating Signaling Based Attacks on Smartphones](https://www.mulliner.org/collin/academic/publications/mrhayes_mulliner_dsn2012.pdf)
* Malicious injection of cellular signaling traffic from mobile phones is an emerging security issue. The respective attacks can be performed by hijacked smartphones and by malware resident on mobile phones. Until today there are no protection mechanisms in place to prevent signaling based attacks other than implementing expensive additions to the cellular core network. In this work we present a protection system that resides on the mobile phone. Our solution works by partitioning the phone software stack into the application operating system and the communication partition. The application system is a standard fully featured Android sys tem. On the other side, communication to the cellular network is mediated by a flexible monitoring and enforcement system running on the communication partition. We implemented and evaluated our protection system on a real smartphone. Our evaluation shows that it can mitigate all currently know n signaling based attacks and in addition can protect users fr om cellular Trojans.






###<a name="misc">Miscellaneous</a>

[US Marine Antenna Handbook](http://www.zerobeat.net/r3403c.pdf?1)


