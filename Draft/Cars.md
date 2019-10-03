# Car Hacking

## Table of Contents
- [General](#general)

------------------
### <a name="general"></a> General
* **Seriously check this first --->** [Awesome Vehicle Security List(github awesome lists)](https://github.com/jaredthecoder/awesome-vehicle-security)
* **101**
	* [Introduction to Hacking in Car Systems - Craig Smith - Troopers15](https://www.youtube.com/watch?v=WHDkf6kpE58)
	* [Intro to Automotive Security - Ariel Zentner](https://www.youtube.com/watch?v=yAzqFhq06_E)
* **Blogposts/How-To's/Writeups**
	* [Broadcasting Your Attack: Security Testing DAB Radio In Cars](https://www.youtube.com/watch?v=ryNtz1nxmO4)
	* [Tesla Model S JSON API (unofficial RE post)](http://docs.timdorr.apiary.io/#reference/vehicles)
	* [Tesla Model S JSON API (unofficial RE post)](http://docs.timdorr.apiary.io/#reference/vehicles)
	* [Cyber-attacks on vehicles P-I!](http://dn5.ljuska.org/napadi-na-auto-sistem-1.html)
	* [Cyber-attacks on vehicles P-II!](http://dn5.ljuska.org/cyber-attacks-on-vehicles-2.html)
	* [An Introduction to the CAN Bus: How to Programmatically Control a Car: Hacking the Voyage Ford Fusion to Change A/C Temperature](https://news.voyage.auto/an-introduction-to-the-can-bus-how-to-programmatically-control-a-car-f1b18be4f377)
	* [CC1101-FSK](https://github.com/trishmapow/CC1101-FSK)
		* Jam and replay attack on vehicle keyless entry systems.
	* [rf-jam-replay](https://github.com/trishmapow/rf-jam-replay)
		* Jam and Replay Attack on Vehicular Keyless Entry Systems
* **DMV**
	* [Report of Traffic Collision Involving an Autonomous Vehicle (OL 316) - dmv.ca.gov](https://www.dmv.ca.gov/portal/dmv/detail/vr/autonomous/autonomousveh_ol316+)
* **Papers**
	* [Remote Exploitation of an  Unaltered Passenger Vehicle](http://illmatics.com/Remote%20Car%20Hacking.pdf)
* **Talks & Presentations**
	* [Hacking Cars with Python -Eric Evenchick PyCon 2017](https://www.youtube.com/watch?v=3bZNhMcv4Y8&app=desktop)
		* Modern cars are networks of computers, and a high end vehicle could have nearly 100 different computers inside. These devices control everything from the engine to the airbags. By understanding how these systems work, we can interface with vehicles to read data, perform diagnostics, and even modify operation.  In this talk, we'll discuss pyvit, the Python Vehicle Interface Toolkit. This library, combined with some open source hardware, allows developers to talk to automotive controllers from Python.  We will begin with an introduction to automotive networks, to provide a basis for understanding the tools. Next, we will look at the tools and show the basics of using them. Finally, we'll discuss real world applications of these tools, and how they're being used in the automotive world today.
	* [Adventures in Automotive Networks and Control Units](https://www.youtube.com/watch?v=MEYCU62yeYk&app=desktop)
		* Charlie Miller & Chris Valasek
	* [Broadcasting your attack: Security testing DAB radio in cars - Andy Davis](http://2015.ruxcon.org.au/assets/2015/slides/Broadcasting-your-attack-Security-testing-DAB-radio-in-cars.pdf)
	* [A Survey of Remote Automotive Attack Surfaces  - Black Hat USA 2014](https://www.youtube.com/watch?v=mNhFGJVq2HE)
	* [Broadcasting your attack: Security testing DAB radio in cars - Andy Davis](http://2015.ruxcon.org.au/assets/2015/slides/Broadcasting-your-attack-Security-testing-DAB-radio-in-cars.pdf)
	* [A Vulnerability in Modern Automotive Standards and How We Exploited It](https://documents.trendmicro.com/assets/A-Vulnerability-in-Modern-Automotive-Standards-and-How-We-Exploited-It.pdf)
	* [Car hacking: getting from A to B with Eve (SHA2017)](https://www.youtube.com/watch?v=l9760bzUN3E)
		* Car security is, not surprisingly, a hot topic; after all they are fast and heavy computer controlled machinery that nowadays come with all kinds of internet connectivity. So we decided to have a look at it. In our presentation, we’ll first cover some theory behind the IT-part of car architecture. We’ll discuss attack vectors and their likelihood of success, and then discuss the various vulnerabilities we found. Finally, we will combine these vulnerabilities into a remote attack. Depending on the disclosure process with the vendor, which is pending, we might be able to demonstrate the attack.
* **Tools**
	* **Hardware**
		* [CBM - The Bicho](https://github.com/UnaPibaGeek/CBM)
			* For the first time, a hardware backdoor tool is presented having several advanced features, such as: remote control via SMS commands, automated launch of attack payloads at a GPS location or when a specific car status is reached; and a configuration interface that allows users to create attack payloads in an easy manner. Have you ever imagined the possibility of your car being automatically attacked based on its GPS coordinates, its current speed or any other set of parameters? Now it's possible :-)
		* [The OpenXC Platform](http://openxcplatform.com/)
			* OpenXC™ is a combination of open source hardware and software that lets you extend your vehicle with custom applications and pluggable modules.
	* **Software**
		* [CANBus Triple](https://canb.us/)
			* General purpose Controller Area Network swiss army knife / development platform.
		* [Yet Another Car Hacking Tool](https://asintsov.blogspot.ro/2016/03/yet-another-car-hacking-tool.html?m=1)
		* [CANToolz](https://github.com/eik00d/CANToolz)
			* CANToolz is a framework for analysing CAN networks and devices. This tool based on different modules which can be assembled in pipe together and can be used by security researchers and automotive/OEM security testers for black-box analysis and etc. You can use this software for ECU discovery, MITM testing, fuzzing, bruteforcing, scanning or R&D testing and validation
		* [canspy](https://github.com/manux81/canspy)
			* Very simple tool for users who need to interface with a device based on CAN (CAN/CANopen/J1939/NMEA2000/DeviceNet) such as motors, sensors and many other devices.
		* [CBM - The Bicho](https://github.com/UnaPibaGeek/CBM)
			* For the first time, a hardware backdoor tool is presented having several advanced features, such as: remote control via SMS commands, automated launch of attack payloads at a GPS location or when a specific car status is reached; and a configuration interface that allows users to create attack payloads in an easy manner. Have you ever imagined the possibility of your car being automatically attacked based on its GPS coordinates, its current speed or any other set of parameters? Now it's possible :-)
* **QNX**
	* [QNX Security Tools - Alex Plaskett & Georgi Geshev](https://github.com/alexplaskett/QNXSecurity)
		* Random scripts produced as part of the research into QNX security. For more information please see the following publications:
			* [QNX: 99 Problems but a Microkernel ain’t one!](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-qnx-troopers-99-problems-but-a-microkernel-aint-one.pdf)
			* [QNX Security Architecture - Alex Plaskett](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-qnx-security-whitepaper-2016-03-14.pdf)



#### Sort
* [Jailbreaking Subaru StarLink](https://github.com/sgayou/subaru-starlink-research/blob/master/doc/README.md)

* [Vehicle Telematics Security; getting it right - Andrew Tierney](https://www.pentestpartners.com/security-blog/vehicle-telematics-security-getting-it-right/)
* [Hacking All the Cars - Part 2 - ConsoleCowboys](https://console-cowboys.blogspot.com/2019/04/hacking-all-cars-part-2.html)
* [Want to become an autonomous vehicle engineer? - Kyle Martin](https://becomeautonomous.com/)
* [FREE-FALL: TESLA HACKING 2016: Hacking Tesla from Wireless to CAN Bus - Keenlab](https://www.blackhat.com/docs/us-17/thursday/us-17-Nie-Free-Fall-Hacking-Tesla-From-Wireless-To-CAN-Bus.pdf)
* [Getting your head under the hood and out of the sand: Automotive security testing - Andrew Tierney](https://www.pentestpartners.com/security-blog/getting-your-head-under-the-hood-and-out-of-the-sand-automotive-security-testing/)
* [Lojack’d: Pwning Smart vehicle trackers - Vangelis Stykas](https://www.pentestpartners.com/security-blog/lojackd-pwning-smart-vehicle-trackers/)