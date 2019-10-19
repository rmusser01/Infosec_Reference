# SCADA/Industrial Control Systems



-------
### Table of Contents
* [General](#general)
* [Articles/Blogposts](#articles)
* [Talks/Presentations](#talks)
* [Tools](#tools)
* [Simulators](#sim)
* [Testing Tools](#test)
* [Honeypots](#honey)



https://labs.mwrinfosecurity.com/blog/offensive-ics-exploitation-a-technical-description/
https://www.icscybersecurityconference.com/intelligence-gathering-on-u-s-critical-infrastructure/
https://scadahacker.com/training.html

----------------------
### <a name="general"></a>General
* **101/Educational**
	* [A Collection of Resources for Getting Started in ICS/SCADA Cybersecurity - Robert M. Lee](http://www.robertmlee.org/a-collection-of-resources-for-getting-started-in-icsscada-cybersecurity/)
	* [Control System Basics](https://www.youtube.com/watch?v=VQLRVjEFRGI)
	* [PLC Training Org](http://plc-training.org/plc-network-to-hmi-scada.html)
	* [Serial Communication RS232 & RS485](https://www.youtube.com/watch?v=2DQdEHvnqvI)
	* [How Ethernet TCP/IP is Used by Industrial Protocols](https://www.youtube.com/watch?v=DL_zIjhCEpU)
	* [SCADA Systems - Utility 101 Session with Rusty Wiliiams](https://www.youtube.com/watch?v=vv2CoTiaWPI)
	* [Control System Lectures - Brian Douglas - youtube channel](https://www.youtube.com/user/ControlLectures/about)
		* Welcome to Control Systems Lectures!  This collection of videos is intended to supplement a first year controls class, not replace it.  My goal is to take specific concepts in controls and expand on them in order to provide an intuitive understanding which will ultimately make you a better controls engineer.  
	* [plcprofessor - youtube channel](https://www.youtube.com/user/plcprofessor)
		*  The PLC Professor YouTube Channel is soley dedicated to technical education, specifically industrial control systems and their supporting technologies. The "Complete PLCLearn Series" is comprised of lectures, hands on lab projects and lab project wrap up discussions. The playlists to use for the series are titled "Lectures", "Basics" lab discussions, "Advanced I" lab discussions and "Advanced II" lab discussions. There is also a "Support" playlist for miscellaneous supporting knowledge, "RSLogix5000", "How to Program", as well as many more to come. These lectures and lab projects were developed for actual classroom training and have been improved as hundreds of electricians and engineers completed and commented on the content. 
	* [Robust control system networks: how to achieve reliable control after Stuxnet / Ralph Langner.](https://catalog.princeton.edu/catalog/9908132)
	* [Hacking US Traffic Control Systems - Cesar Cerrudo - Defcon22](https://www.defcon.org/images/defcon-22/dc-22-presentations/Cerrudo/DEFCON-22-Cesar-Cerrudo-Hacking-Traffic-Control-Systems-UPDATED.pdf)
	* [Industrial Control Systems Pattern - opensecurityarchitecture.com](http://www.opensecurityarchitecture.org/cms/en/library/patternlandscape/293-draft-sp-023-industrial-control-systems)
	* [SCADApedia](https://www.digitalbond.com/wiki)
* **EDIFACT**
	* [EDIFACT - Wikipedia](https://en.wikipedia.org/wiki/EDIFACT)
	* [SMDG.org](http://www.smdg.org/)
		* SMDG develops and promotes UN/EDIFACT EDI-messages for the Maritime Industry and is an official Global User Group, recognised by the UN/EDIFACT Board. 
	* [Making prawn espressos, or hacking ships by deciphering BAPLIE EDIFACT messaging](https://www.pentestpartners.com/security-blog/making-prawn-espressos-or-hacking-ships-by-deciphering-baplie-edifact-messaging/)
	* [BAPLIE](http://www.portofantwerp.com/apcs/en/node/449)
		* The BAPLIE message is a widely used EDIFACT message in the shipping industry. It is used by and between various parties to advise the exact stowage positions of the cargo on board of an ocean vessel. It is currently chiefly used for container cargo. Besides the container number and the exact position on board, general information regarding the containers is also specified such as weight and hazardous cargo class. 
* **Modbus**
	* [Modbus Stager: Using PLCs as a payload/shellcode distribution system](http://www.shelliscoming.com/2016/12/modbus-stager-using-plcs-as.html)
	* [All You Need to Know About Modbus RTU](https://www.youtube.com/watch?v=OvRD2UvrHjE)
	* [All You need to know about Modbus TCP](https://www.youtube.com/watch?v=E1nsgukeKKA)
	* [Modbus Data structure](https://www.youtube.com/watch?v=8FYFai21JPA)
	* [Modbus interface tutorial](https://www.lammertbies.nl/comm/info/modbus.html)
	* [Modbus Protocol Overview](https://www.lammertbies.nl/comm/info/modbus.html)
* **General**
	* [A Collection of Resources for Getting Started in ICS/SCADA Cybersecurity - Robert M. Lee](http://www.robertmlee.org/a-collection-of-resources-for-getting-started-in-icsscada-cybersecurity/)
	* [Different Type of SCADA](http://scadastrangelove.blogspot.com/2014/10/different-type-of-scada.html)
	* [awesome-industrial-control-system-security](https://github.com/hslatman/awesome-industrial-control-system-security)
	* [Cassandra coefficient and ICS cyber – is this why the system is broken](http://www.controlglobal.com/blogs/unfettered/cassandra-coefficient-and-ics-cyber-is-this-why-the-system-is-broken/)
	* [Remote Physical Damage 101 - Bread and Butter Attacks](https://www.blackhat.com/docs/us-15/materials/us-15-Larsen-Remote-Physical-Damage-101-Bread-And-Butter-Attacks.pdf)
	* [Sinking container ships by hacking load plan software](https://www.pentestpartners.com/security-blog/sinking-container-ships-by-hacking-load-plan-software/)
	* [SCADA Strangelove or: How I Learned to Start Worrying and Love Nuclear Plants](https://www.youtube.com/watch?v=o2r7jbwTv6w)
		* Modern civilization unconditionally depends on information systems. It is paradoxical but true that ICS/SCADA systems are the most insecure systems in the world. From network to application, SCADA is full of configuration issues and vulnerabilities. During our report, we will demonstrate how to obtain full access to a plant via: a sniffer and a packet generator; FTP and Telnet; Metasploit and oslq; a webserver and a browser; About 20 new vulnerabilities in common SCADA systems including Simatic WinCC will be revealed.
	* [Rocking the Pocket Book: Hacking Chemical Plant for Competition and Extortion - Marina Krotofil - Jason Larsen](https://www.youtube.com/watch?v=AL8L76n0Q9w)
		* The appeal of hacking a physical process is dreaming about physical damage attacks lighting up the sky in a shower of goodness. Let’s face it, after such elite hacking action nobody is going to let one present it even at a conference like DEF CON. As a poor substitute, this presentation will get as close as using a simulated plant for Vinyl Acetate production for demonstrating a complete attack, from start to end, directed at persistent economic damage to a production site while avoiding attribution of production loss to a cyber-event. Such an attack scenario could be useful to a manufacturer aiming at putting competitors out of business or as a strong argument in an extortion attack. Exploiting physical process is an exotic and hard to develop skill which have so far kept a high barrier to entry. Therefore real-world control system exploitation has remained in the hands of a few. To help the community mastering new skills we have developed „Damn Vulnerable Chemical Process“ – first open source framework for cyber-physical experimentation based on two realistic models of chemical plants. Come to the session and take your first master class on complex physical hacking.
	* [Offensive ICS Exploitation: A Description of an ICS CTF - MWR](https://labs.mwrinfosecurity.com/blog/offensive-ics-exploitation-a-technical-description/)
* **Wireless**
	* [Dissecting Industrial Wireless Implementations - DEF CON 25](https://github.com/voteblake/DIWI)






----------------------
### Tools
* **General Tools**
	* [python-opcua](https://github.com/FreeOpcUa/python-opcua/blob/master/README.md)
		* OPC UA binary protocol implementation is quasi complete and has been tested against many different OPC UA stacks. API offers both a low level interface to send and receive all UA defined structures and high level classes allowing to write a server or a client in a few lines. It is easy to mix high level objects and low level UA calls in one application.
	* [UaExpert—A Full-Featured OPC UA Client](https://www.unified-automation.com/products/development-tools/uaexpert.html)
		* The UaExpert® is a full-featured OPC UA Client demonstrating the capabilities of our C++ OPC UA Client SDK/Toolkit. The UaExpert is designed as a general purpose test client supporting OPC UA features like DataAccess, Alarms & Conditions, Historical Access and calling of UA Methods. The UaExpert is a cross-platform OPC UA test client programmed in C++. It uses the sophisticated GUI library QT form Nokia (formerly Trolltech) forming the basic framework which is extendable by Plugins.
	* [dyode](https://github.com/arnaudsoullie/dyode)
		* A low-cost data diode, aimed at Industrial Control Systems
	* [GRASSMARLIN](https://github.com/iadgov/GRASSMARLIN)
	* [Moki Linux](https://github.com/moki-ics/moki)
		* Moki is a modification of Kali to encorporate various ICS/SCADA Tools scattered around the internet, to create a customized Kali Linux geared towards ICS/SCADA pentesting professionals.
	* [nmap-scada](https://github.com/jpalanco/nmap-scada)
		* nse scripts for scada identification
* **Assessment Tools**
	* [Redpoint](https://github.com/digitalbond/Redpoint)
		* Redpoint is a Digital Bond research project to enumerate ICS applications and devices. The Redpoint tools use legitimate protocol or application commands to discover and enumerate devices and applications. There is no effort to exploit or crash anything. However many ICS devices and applications are fragile and can crash or respond in an unexpected way to any unexpected traffic so use with care.
* **Honeypots**
	* [T-Pot](https://dtag-dev-sec.github.io/mediator/feature/2016/03/11/t-pot-16.03.html)
		* T-Pot 16.03 - Enhanced Multi-Honeypot Platform
	* [Conpot](https://github.com/mushorg/conpot)
		* Conpot is an ICS honeypot with the goal to collect intelligence about the motives and methods of adversaries targeting industrial control systems
* **Passwords**
	* [SCADAPASS](https://github.com/scadastrangelove/SCADAPASS)
		* SCADA StrangeLove Default/Hardcoded Passwords List 
* **Simulation Software**
	* [MiniCPS](https://github.com/scy-phy/minicps)
		* MiniCPS is a framework for Cyber-Physical Systems real-time simulation. It includes support for physical process and control devices simulation, and network emulation. It is build on top of mininet.
	* [Simulated Physics And Embedded Virtualization Integration (SPAEVI) - Overview](http://www.spaevi.org/p/the-simulated-physics-and-embedded.html)
	* [VirtualPlant](https://github.com/jseidl/virtuaplant)
		* VirtuaPlant is a Industrial Control Systems simulator which adds a “similar to real-world control logic” to the basic “read/write tags” feature of most PLC simulators. Paired with a game library and 2d physics engine, VirtuaPlant is able to present a GUI simulating the “world view” behind the control system allowing the user to have a vision of the would-be actions behind the control systems. All the software is written in (guess what?) Python. The idea is for VirtuaPlant to be a collection of different plant types using different protocols in order to be a learning platform and testbed. The first release introduces a as-simple-as-it-can-get one-process “bottle-filling factory” running Modbus as its protocol.
	* [Blogpost](https://wroot.org/projects/virtuaplant/)
* **Testing Tools**
	* [smod - MODBUS Penetration Testing Framework](https://github.com/enddo/smod)
		* smod is a modular framework with every kind of diagnostic and offensive feature you could need in order to pentest modbus protocol. It is a full Modbus protocol implementation using Python and Scapy. This software could be run on Linux/OSX under python 2.7.x.
	* [SCADA Shutdown Tool](https://github.com/0xICF/SCADAShutdownTool)
		* SCADAShutdownTool is an industrial control system automation and testing tool allows security researchers and experts to test SCADA security systems, enumerate slave controllers, read controller's registers values and rewrite registers data. SCADAShutdownTool allow enumeration of all registers types of a controller include coil outputs, digital inputs, analogue inputs, holding registers and extended registers.
	* [Redpoint](https://github.com/digitalbond/Redpoint)
	* Digital Bond's ICS Enumeration Tools
* **Assessment Testing(/Methodology)**
	* [ICS Security Assessment Methodology, Tools & Tips](https://www.youtube.com/watch?v=0WoA9SYLDoM)
		* Dale Peterson of Digital Bond describes how to perform an ICS / SCADA cyber security assessment in this S4xJapan video.  He goes into a lot of detail on the tools and how to use them in the fragile and insecure by design environment that is an ICS.  There are also useful tips on when to bother applying security patches (this will likely surprise you), the importance of identifying the impact of a vulnerability, and an efficient risk reduction approach.
	* [Running a Better Red Team Through Understanding ICS SCADA Adversary Tactics - SANS Webcast](https://www.youtube.com/watch?v=ERnPuGvH_O0)
		* A good red team should be informed about adversary tactics to emulate them against networks to not only test the infrastructure but also the defenders. In this talk, SANS ICS515 and FOR578 course author Robert M. Lee will discuss a number of observed adversary tactics in ICS/SCADA environments for the purpose of educating the audience on tactics that red teams may consider for tests in these networks. The talk will cover some of the high profile attacks observed in the community such as the Ukraine power grid cyber-attack as well as lessons learned from incident response cases in the community. 
	* [Introduction to Attacking ICS/SCADA Systems for Penetration Testers -GDS Sec](http://blog.gdssecurity.com/labs/2017/5/17/introduction-to-attacking-icsscada-systems-for-penetration-t.html)
	* [Damn Vulnerable Chemical Process](https://www.slideshare.net/phdays/damn-vulnerable-chemical-process)
	* [Hacking Chemical Plants for Competition and Extortion - Marina Krotofil - HITBGSEC 2015](https://www.youtube.com/watch?v=0B-sG1rKJ2U)
* **Threat Hunting** 
	* [I Got You06 ICS SCADA Threat Hunting Robert M Lee Jon Lavender](https://www.youtube.com/watch?v=Zm5lDKxaaTY)


















