##Wireless Networks


###CULL

http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/17-phys-macs-and-sdrs-robert-ghilduta








[NSA Playset - GSM Sniffing - Pierce&Loki - Defcon22](https://www.youtube.com/watch?v=tnn_qJGh1gc)
* 

[The blackjack vulnerability - WPS Pins cracked in 18 packets](http://méric.fr/blog/blackjack.html)


[Fingerprinting 802.11 Implementations via Statistical Analysis of the Duration Field](http://uninformed.org/?v=all&a=23&t=sumry)
* The research presented in this paper provides the reader with a set of algorithms and techniques that enable the user to remotely determine what chipset and device driver an 802.11 device is using. The technique outlined is entirely passive, and given the amount of features that are being considered for inclusion into the 802.11 standard, seems quite likely that it will increase in precision as the standard marches forward. The implications of this are far ranging. On one hand, the techniques can be used to implement innovative new features in Wireless Intrusion Detection Systems (WIDS). On the other, they can be used to target link layer device driver attacks with much higher precision. 


[Exploiting 802.11 Wireless Driver Vulnerabilities on Windows](http://uninformed.org/?v=all&a=29&t=sumry)
* This paper describes the process of identifying and exploiting 802.11 wireless device driver vulnerabilities on Windows. This process is described in terms of two steps: pre-exploitation and exploitation. The pre-exploitation step provides a basic introduction to the 802.11 protocol along with a description of the tools and libraries the authors used to create a basic 802.11 protocol fuzzer. The exploitation step describes the common elements of an 802.11 wireless device driver exploit. These elements include things like the underlying payload architecture that is used when executing arbitrary code in kernel-mode on Windows, how this payload architecture has been integrated into the 3.0 version of the Metasploit Framework, and the interface that the Metasploit Framework exposes to make developing 802.11 wireless device driver exploits easy. Finally, three separate real world wireless device driver vulnerabilities are used as case studies to illustrate the application of this process. It is hoped that the description and illustration of this process can be used to show that kernel-mode vulnerabilities can be just as dangerous and just as easy to exploit as user-mode vulnerabilities. In so doing, awareness of the need for more robust kernel-mode exploit prevention technology can be raised. 

[Hacking the Wireless World with Software Defined Radio 2.0](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/14-hacking-the-wireless-world-with-software-defined-radio-2-0-balint-seeber)

[So you want to get into SDR talk](www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/01-so-ya-wanna-get-into-sdr-russell-handorf)


[Bringing Software Defined Radio to the Penetration Testing Community](https://www.youtube.com/watch?v=hZJDdz6kVJ4)


[Exploit: Hacking the Wireless World with Software Defined Radio BlackHat USA 2014](https://www.youtube.com/watch?v=XWbwFfxzw6w)


###Dongles

[FunCube dongle](http://www.funcubedongle.com)


[Gr0SMoSDR](http://sdr.osmocom.org/trac/wiki/GrOsmoSDR)

[PyBOMBS](http://gnuradio.org/redmine/projects/pybombs/wiki)
* PyBOMBS (Python Build Overlay Managed Bundle System) is the new GNU Radio install management system for resolving dependencies and pulling in out-of-tree projects.  One of the main purposes of PyBOMBS is to aggregate out-of-tree projects, which means that PyBOMBS needs to have new recipes for any new project. We have done a lot of the initial work to get known projects into the PyBOMBS system as is, but we will need project developers for new OOT projects or other projects not currently listed to help us out with this effort.

Bluetooth NSA toolset talk/attacks vid
http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/15-the-nsa-playset-bluetooth-smart-attack-tools-mike-ryan

[Software Defined Radio with HackRF](https://greatscottgadgets.com/sdr/)

[WPA/WPA2 Dictionaries](https://wifi0wn.wordpress.com/wepwpawpa2-cracking-dictionary/)


Ubertooth


Github.com/mikeryan/crackle

Scapy


Bluez.org

PyBT


[Infernal-Twin](https://github.com/entropy1337/infernal-twin)
* This is the tool created to automate Evil Twin attack and capturing public and guest credentials of Access Point

[SS7: Locate. Track. Manipulate. You have a tracking device in your pocket](http://media.ccc.de/browse/congress/2014/31c3_-_6249_-_en_-_saal_1_-_201412271715_-_ss7_locate_track_manipulate_-_tobias_engel.html#video&t=424)
* Companies are now selling the ability to track your phone number whereever you go. With a precision of up to 50 meters, detailed movement profiles can be compiled by somebody from the other side of the world without you ever knowing about it. But that is just the tip of the iceberg. 








###Fox Hunting & Wardriving

[Practical Foxhunting 101](http://www.irongeek.com/i.php?page=videos/defcon-wireless-village-2014/04-practical-foxhunting-101-simonj)


Wireless Reconnaissance

Tools:

iSniff
Description: iSniff GPS passively sniffs for SSID probes, ARPs and MDNS (Bonjour) packets broadcast by nearby iPhones, iPads and other wireless devices. The aim is to collect data which can be used to identify each device and determine previous geographical locations, based solely on information each device discloses about previously joined WiFi networks.  
iOS devices transmit ARPs which sometimes contain MAC addresses (BSSIDs) of previously joined WiFi networks, as described in [1]. iSniff GPS captures these ARPs and submits MAC addresses to Apple's WiFi location service (masquerading as an iOS device) to obtain GPS coordinates for a given BSSID. If only SSID probes have been captured for a particular device, iSniff GPS can query network names on wigle.net and visualise possible locations.
Link: https://github.com/hubert3/iSniff-GPS




Guide to setting up/doing wifi attacks
http://securitysynapse.blogspot.com/2013/12/wireless-pentesting-on-cheap-kali-tl.html
this article, we proved the capabilities of an inexpensive wireless adapter and a flexible virtualized wireless attack image by breaking into a WEP protected test network.  For just $16 


Piece to purchase: http://www.newegg.com/Product/Product.aspx?Item=N82E16833704045




##802.11


Karma
http://www.theta44.org/karma/





RFID - Radio Frequency Identification


ravenhid
Hardware and software to run a RFID reader to harvest card information. This is the PCB design and Arduino code that will run a RFID reader, allowing you to gather and harvest cards. Typically, a larger reader, such as those in garages, will be more successful, allowing you to ready over a couple feet instead of inches. The board itself is designed to be modular and support multiple methods to output harvested cards once they are read: 
Text file on a MicroSD card
Print out to LCD
Bluetooth Low Energy Arduino serial connection 
Each of these options are supported in code, but can be ignored on the PCB. The PCB itself has been designed to use a pluggable module for each of these options, making it easy to ignore, install, or change out which ones you find useful. 
https://github.com/emperorcow/ravenhid



##Zigbee Wireless Networks


KillerBee Framework
https://code.google.com/p/killerbee/
KillerBee is a Python based framework and tool set for exploring and exploiting the security of ZigBee and IEEE 802.15.4 networks. Using KillerBee tools and a compatible IEEE 802.15.4 radio interface, you can eavesdrop on ZigBee networks, replay traffic, attack cryptosystems and much more. Using the KillerBee framework, you can build your own tools, implement ZigBee fuzzing, emulate and attack end-devices, routers and coordinators and much more. 









##Cellular Networks




Cellular Networks in use North America:
	In use in Europe:
	In use in Asia:
	In use in Africa:
	In use in South America:


###Blogs/Sites

[Secrets of Sim](http://www.hackingprojects.net/2013/04/secrets-of-sim.html)


[4G LTE Architecture and Security Concerns](http://www.secforce.com/blog/2014/03/4g-lte-architecture-and-security-concerns/)










####Videos

[Demystifying the Mobile Network by Chuck McAuley](http://2014.video.sector.ca/video/110383258)
* Must watch video. Very informative.


http://blog.ptsecurity.com/2014/12/4g-security-hacking-usb-modem-and-sim.html




[Osmocom SIMtrace](http://bb.osmocom.org/trac/wiki/SIMtrace)
* Osmocom SIMtrace is a software and hardware system for passively tracing SIM-ME communication between the SIM card and the mobile phone. 



http://www.3gpp.org/DynaReport/31048.htm

y



###Tools
Android IMSI-Catcher Detector (AIMSICD)](https://github.com/SecUpwN/Android-IMSI-Catcher-Detector)
* Android-based project to detect and avoid fake base stations (IMSI-Catchers) in GSM/UMTS Networks.



