# Logging/Network(/Host) Security Monitoring



## Table of Contents

* [Presentations/Videos](#videos)
* [Writeups](#writeups)
* [Tools](#tools)
* [IDS/IPS](#ips)
* [IDS/IPS Monitoring](#monitor)
* [Logging](#log)
	* [Linux](#linux)
	* [Windows](#win)
* [PCaps/Static Data](#pcap)
* Making Sense of the Data
* [Papers](#papers)
* [Tricks & Tips](#tricks)



##### To Do
* Create incident Response section
* Expand ELK Stack



#### Sort
* [Advanced Security Audit Policy Settings](https://technet.microsoft.com/en-us/library/dn319056(v=ws.11).aspx)

* [Many ways of malware persistence (that you were always afraid to ask) ](http://jumpespjump.blogspot.com/2015/05/many-ways-of-malware-persistence-that.html)
* [Utilizing SysInternal Tools for IT Pros](http://www.microsoftvirtualacademy.com/training-courses/utilizing-sysinternals-tools-for-it-pros#fbid=1IKsqgyvnWp)
* [License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)
* [Aktaion: Open Source Tool For "Micro Behavior Based" Exploit Detection and Automated GPO Policy Generation](https://github.com/jzadeh/Aktaion)
	* Aktaion is a lightweight JVM based project for detecting exploits (and more generally attack behaviors). The project is meant to be a learning/teaching tool on how to blend multiple security signals and behaviors into an expressive framework for intrusion detection. The cool thing about the project is it provides an expressive mechanism to add high level IOCs (micro beahviors) such as timing behavior of a certain malware family.
* [Diamond](https://github.com/python-diamond/Diamond)
	* Diamond is a python daemon that collects system metrics and publishes them to [Graphite](http://diamond.readthedocs.io/en/latest/handlers/GraphiteHandler/) (and others). It is capable of collecting cpu, memory, network, i/o, load and disk metrics. Additionally, it features an API for implementing custom collectors for gathering metrics from almost any source.
	* [Documentation](http://diamond.readthedocs.io/en/latest/)
* [laikaboss](https://github.com/lmco/laikaboss)
http://www.netfort.com/wp-content/uploads/PDF/WhitePapers/NetFlow-Vs-Packet-Analysis-What-Should-You-Choose.pdf
* [limacharlie](https://github.com/refractionpoint/limacharlie)
	* Endpoint monitoring stack.
* [Using rwuniq for Top-10 Lists](https://tools.netsa.cert.org/confluence/display/tt/Using+rwuniq+for+Top-10+Lists)
* [ELSA](https://github.com/mcholste/elsa)
* [bmon - bandwidth monitor and rate estimator](https://github.com/tgraf/bmon)
	* bmon is a monitoring and debugging tool to capture networking related statistics and prepare them visually in a human friendly way. It features various output methods including an interactive curses user interface and a programmable text output for scripting.
* [Aktaion: Open Source Tool For "Micro Behavior Based" Exploit Detection and Automated GPO Policy Generation](https://github.com/jzadeh/Aktaion)
	* Aktaion is a lightweight JVM based project for detecting exploits (and more generally attack behaviors). The project is meant to be a learning/teaching tool on how to blend multiple security signals and behaviors into an expressive framework for intrusion detection. The cool thing about the project is it provides an expressive mechanism to add high level IOCs (micro beahviors) such as timing behavior of a certain malware family.

#### End Sort


---------------------------
### Network Security Monitoring/Logging/Threat Hunting
* **101/Educational**
* **Courses**
* **General**
* **Articles/Presentations/Talks/Writeups**
	* **IDS/IPS**
		* [Passive IPS Reconnaissance and Enumeration - false positive (ab)use - Arron Finnon](https://vimeo.com/108775823)
			* Network Intrusion Prevention Systems or NIPS have been plagued by "False Positive" issues almost since their first deployment. A "False Positive" could simply be described as incorrectly or mistakenly detecting a threat that is not real. A large amount of research has gone into using "False Positive" as an attack vector either to attack the very validity of an IPS system or to conduct forms of Denial of Service attacks. However the very reaction to a "False Positive" in the first place may very well reveal more detailed information about defences than you might well think.
		* [You Pass Butter: Next Level Security Monitoring Through Proactivity](http://www.irongeek.com/i.php?page=videos/nolacon2016/110-you-pass-butter-next-level-security-monitoring-through-proactivity-cry0-s0ups)
	* **Logging**
		* [Logging ALL THE THINGS Without All The Cost With Open Source Big Data Tools - DEFCON22 - Zach Fasel](https://www.youtube.com/watch?v=2AAnVeIwXBo)
			* Many struggle in their job with the decision of what events to log in battle against costly increases to their licensing of a commercial SIEM or other logging solution. Leveraging the open source solutions used for "big-data" that have been proven by many can help build a scalable, reliable, and hackable event logging and security intelligence system to address security and (*cringe*) compliance requirements. We’ll walk through the various components and simple steps to building your own logging environment that can extensively grow (or keep sized just right) with just additional hardware cost and show numerous examples you can implement as soon as you get back to work (or home).
		* [Automating large-scale memory forensics](https://medium.com/@henrikjohansen/automating-large-scale-memory-forensics-fdc302dc3383)
		* [Real Incidents:Real Solutions - evil.plumbing](https://evil.plumbing/Current-version-June.pdf)
		* [Securi-Tay 2017 - Advanced Attack Detection](https://www.youtube.com/watch?v=ihElrBBJQo8)
		* [Windows Commands Abused by Attackers](http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html)
	* **Traffic Analysis**
		* [Network Profiling Using Flow](https://resources.sei.cmu.edu/asset_files/technicalreport/2012_005_001_28167.pdf)
			* This report provides a step-by-step guide for profiling—discovering public-facing assets on a  network—using network flow (netflow) data. Netflow data can be used for forensic purposes, for  finding malicious activity, and for determining appropriate prioritization settings. The goal of this  report is to create a profile to see a potential  attacker’s view of an external network.   Readers will learn how to choose a data set, find the top assets and services with the most traffic  on the network, and profile several services. A cas e study provides an example of the profiling  process. The underlying concepts of using netflow data are presented so that readers can apply the  approach to other cases. A reader using this repor t to profile a network can expect to end with a  list of public-facing assets and the ports on which  each is communicating and may also learn other  pertinent information, such as external IP addresses, to which the asset is connecting. This report  also provides ideas for using, maintaining, and reporting on findings. The appendices include an  example profile and scripts for running the commands in the report. The scripts are a summary  only and cannot replace reading and understanding this report.
		* [Making the Most of OSSEC](http://www.ossec.net/files/Making_the_Most_of_OSSEC.pdf)
		* [Using SiLK for Network  Traffic Analysis](https://tools.netsa.cert.org/silk/analysis-handbook.pdf)
		* [Current State of Virtualizing Network Monitoring](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t202-current-state-of-virtualizing-network-monitoring-daniel-lohin-ed-sealing)
* **Breach Detection/Response**
	* **Articles/Blogposts/Presentations/Talks/Writeups**
		* [The fox is in the Henhouse - Detecting a breach before the damage is done](http://www.irongeek.com/i.php?page=videos/houseccon2015/t302-the-fox-is-in-the-henhouse-detecting-a-breach-before-the-damage-is-done-josh-sokol)
	* **Tools**
		* [Infection Monkey](https://github.com/guardicore/monkey)
			* The Infection Monkey is an open source security tool for testing a data center's resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Command and Control(C&C) server.
		* [411](https://github.com/kiwiz/411)
			* Configure Searches to periodically run against a variety of data sources. You can define a custom pipeline of Filters to manipulate any generated Alerts and forward them to multiple Targets.
		* [Pattern](https://github.com/clips/pattern/blob/master/README.md)
			* Pattern is a web mining module for Python. It has tools for: Data Mining: web services (Google,; Twitter, Wikipedia), web crawler, HTML DOM parser; Natural Language Processing: part-of-speech taggers, n-gram search, sentiment analysis, WordNet; Machine Learning: vector space model, clustering, classification (KNN, SVM, Perceptron); Network Analysis: graph centrality and visualization.
* **Building a ___(/Lab/)**
	* [Response Operation Collections Kit Reference Build](https://github.com/rocknsm/rock)
	* [Building a Home Network Configured to Collect Artifacts for Supporting Network Forensic Incident Response](https://www.sans.org/reading-room/whitepapers/forensics/building-home-network-configured-collect-artifacts-supporting-network-forensic-incident-response-37302)
	* [SweetSecurity](https://github.com/TravisFSmith/SweetSecurity)
		* Scripts to setup and install Bro IDS, Elastic Search, Logstash, Kibana, and Critical Stack on a Raspberry Pi 3 device
	* [Response Operation Collections Kit Reference Build](https://github.com/rocknsm/rock)
* **General Tools**
	* **General**
		* [Security Onion](http://blog.securityonion.net/p/securityonion.html)
			* Security Onion is a Linux distro for intrusion detection, network security monitoring, and log management. It's based on Ubuntu and contains Snort, Suricata, Bro, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner, and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!
	* **Data Tranformation**
		* [Pip3line, the Swiss army knife of byte manipulation](https://nccgroup.github.io/pip3line/index.html) 
			* Pip3line is a raw bytes manipulation utility, able to apply well known and less well known transformations from anywhere to anywhere (almost).
		* [dnstwist](https://github.com/elceef/dnstwist)
			* Domain name permutation engine for detecting typo squatting, phishing and corporate espionage
	* **DNS**
		* [DNSChef](https://thesprawl.org/projects/dnschef/)
			* DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example, a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
		* [Passive DNS](https://github.com/gamelinux/passivedns) 
			* A tool to collect DNS records passively to aid Incident handling, Network Security Monitoring (NSM) and general digital forensics.  * PassiveDNS sniffs traffic from an interface or reads a pcap-file and outputs the DNS-server answers to a log file. PassiveDNS can cache/aggregate duplicate DNS answers in-memory, limiting the amount of data in the logfile without losing the essense in the DNS answer.
	* **HTTP Traffic**
		* [Captipper](http://www.omriher.com/2015/01/captipper-malicious-http-traffic.html)
			* CapTipper is a python tool to analyze, explore and revive HTTP malicious traffic. CapTipper sets up a web server that acts exactly as the server in the PCAP file, and contains internal tools, with a powerful interactive console, for analysis and inspection of the hosts, objects and conversations found.  
	* **PCAPs/Packet Capture**
		* [CapLoader](http://www.netresec.com/?page=CapLoader) 
			* CapLoader is a Windows tool designed to handle large amounts of captured network traffic. CapLoader performs indexing of PCAP/PcapNG files and visualizes their contents as a list of TCP and UDP flows. Users can select the flows of interest and quickly filter out those packets from the loaded PCAP files. Sending the selected flows/packets to a packet analyzer tool like Wireshark or NetworkMiner is then just a mouse click away. 
		* [Netdude](http://netdude.sourceforge.net/)
			* The Network Dump data Displayer and Editor is a framework for inspection, analysis and manipulation of tcpdump trace files. It addresses the need for a toolset that allows easy inspection, modification, and creation of pcap/tcpdump trace files. Netdude builds on any popular UNIX-like OS, such as Linux, the BSDs, or OSX.
		* [Stenographer](https://github.com/google/stenographer/blob/master/README.md)
			* Stenographer is a full-packet-capture utility for buffering packets to disk for intrusion detection and incident response purposes. It provides a high-performance implementation of NIC-to-disk packet writing, handles deleting those files as disk fills up, and provides methods for reading back specific sets of packets quickly and easily.
		* [PCAPDB](https://github.com/dirtbags/pcapdb)
			* PcapDB is a distributed, search-optimized open source packet capture system. It was designed to replace expensive, commercial appliances with off-the-shelf hardware and a free, easy to manage software system. Captured packets are reorganized during capture by flow (an indefinite length sequence of packets with the same src/dst ips/ports and transport proto), indexed by flow, and searched (again) by flow. The indexes for the captured packets are relatively tiny (typically less than 1% the size of the captured data).
		* [Network Miner](http://www.netresec.com/?page=NetworkMiner)
			* NetworkMiner is a Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool in order to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.
		* **SilLK**	
			* [Silk](https://tools.netsa.cert.org/silk/)
				* The SiLK analysis suite is a collection of command-line tools for processing SiLK Flow records created by the SiLK packing system. These tools read binary files containing SiLK Flow records and partition, sort, and count these records. The most important analysis tool is rwfilter, an application for querying the central data repository for SiLK Flow records that satisfy a set of filtering options. The tools are intended to be combined in various ways to perform an analysis task. A typical analysis uses UNIX pipes and intermediate data files to share data between invocations of the tools. 
			* [Administering/Installing SiLK](https://tools.netsa.cert.org/confluence/display/tt/Administration)
			* [SiLK Tool Tips](https://tools.netsa.cert.org/confluence/display/tt/Tooltips)
			* [SiLK Reference Guide](https://tools.netsa.cert.org/silk/silk-reference-guide.html)
			* [SiLK Toolsuite Quick Reference Guide](https://tools.netsa.cert.org/silk/silk-quickref.pdf)
			* [flowbat](http://www.appliednsm.com/introducing-flowbat/)
				* Awesome flow tool, SiLK backend
	* **ShellCode Analysis**
		* [Shellcode Analysis Pipeline](https://7h3ram.github.io/2014/3/18/shellcode-pipeline/)
			* I recently required an automated way of analyzing shellcode and verifying if it is detected by Libemu, Snort, Suricata, Bro, etc. Shellcode had to come from public sources like Shell-Storm, Exploit-DB and Metasploit. I needed an automated way of sourcing shellcode from these projects and pass it on to the analysis engines in a pipeline-like mechanism. This posts documents the method I used to complete this task and the overall progress of the project.
* **Logging**
	* **Linux**
		* [Syslong-ng](https://github.com/balabit/syslog-ng) 
	* syslog-ng is an enhanced log daemon, supporting a wide range of input and output methods: syslog, unstructured text, message queues, databases (SQL and NoSQL alike) and more.
	* **OS X**
	* **Windows**
		* **Cheat Sheets**
			* [Windows logging Cheat sheet - Malware Archaelogy](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/580595db9f745688bc7477f6/1476761074992/Windows+Logging+Cheat+Sheet_ver_Oct_2016.pdf)
			* [Windows Splunk Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a3187b4419202f0fb8b2dd1/1513195444728/Windows+Splunk+Logging+Cheat+Sheet+v2.2.pdf)
			* [Windows Registry Auditing Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a00963153450a8779b23489/1509987890282/Windows+Registry+Auditing+Cheat+Sheet+ver+Nov+2017.pdf)
			* [Windows PowerShell Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
			* [Windows File Auditing Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a0097e5f9619a8960daef69/1509988326168/Windows+File+Auditing+Cheat+Sheet+ver+Nov+2017.pdf)
		* **Event Collector**
			* [Windows event Collector - Setting up source initiated Subscriptions](https://msdn.microsoft.com/en-us/library/bb870973(v=vs.85).aspx)
			* [Windows Event Collector(For centralizing windows domain logging with no local agent, windows actually has built-in logging freely available)](https://msdn.microsoft.com/en-us/library/bb427443(v=vs.85).aspx)
		* **Event Forwarding**
			[Introduction to Windows Event Forwarding](https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4)
			* [Use Windows Event Forwarding to help with intrusion detection](https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection)
			* [Monitoring what matters – Windows Event Forwarding for everyone (even if you already have a SIEM.)](https://blogs.technet.microsoft.com/jepayne/2015/11/23/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem/)
		* **Event Log**
			* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
				* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it-s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What-s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."
			* [Public:Windows Event Log Zero 2 Hero Slides](https://docs.google.com/presentation/d/1dkrldTTlN3La-OjWtkWJBb4hVk6vfsSMBFBERs6R8zA/edit#slide=id.g21acf94f3f_2_27)
			* [Spotting the Adversary with Windows Event Log Monitoring - NSA](https://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf)
	* **Parsing**
		* [Parsing Text Logs with Message Analyzer - Microsoft](http://blogs.technet.com/b/messageanalyzer/archive/2015/02/23/parsing-text-logs-with-message-analyzer.aspx)
	* **PowerShell**
		* **Articles/Blogposts/Writeups**
			* [Uncovering Indicators of Compromise (IoC) Using PowerShell, Event Logs, and a Traditional Monitoring Tool](https://www.sans.org/reading-room/whitepapers/critical/uncovering-indicators-compromise-ioc-powershell-event-logs-traditional-monitoring-tool-36352)
			* [Revoke -­‐ Obfuscation: PowerShell Obfuscation Detection Using Science](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf)
			* [Greater Visibility Through PowerShell Logging](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
		* **Tools**
			* [check_ioc](https://github.com/oneoffdallas/check_ioc)
				* Check_ioc is a script to check for various, selectable indicators of compromise on Windows systems via PowerShell and Event Logs. It was primarily written to be run on a schedule from a monitoring engine such as Nagios, however, it may also be run from a command-line (for incident response).
			* [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
				* Looks for threads that were created as a result of code injection.
			* [PowerShellMethodAuditor](https://github.com/zacbrown/PowerShellMethodAuditor)
			* [Revoke-Obfuscation - Github](https://github.com/danielbohannon/Revoke-Obfuscation)
				* Revoke-Obfuscation is a PowerShell v3.0+ compatible PowerShell obfuscation detection framework.
			* [GetInjectedThreads.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
				* Looks for threads that were created as a result of code injection.
			* [block-parser](https://github.com/matthewdunwoody/block-parser)
				* Parser for Windows PowerShell script block logs
	* **WMI**
		* [WMI-IDS](https://github.com/fireeye/flare-wmi/tree/master/WMI-IDS)
			* WMI-IDS is a proof-of-concept agent-less host intrusion detection system designed to showcase the unique ability of WMI to respond to and react to operating system events in real-time.
* **Threat Hunting**
	* [Hunting Red Team Empire C2 Infrastructure](http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html)
	* [Windows Log Hunting with PowerShell](http://909research.com/windows-log-hunting-with-powershell/)
	* [Hunting in Memory](https://www.endgame.com/blog/technical-blog/hunting-memory)
	* [Windows Log Hunting with PowerShell](http://909research.com/windows-log-hunting-with-powershell/)
	* [Taking Hunting to the Next Level Hunting in Memory - Jared Atkinson 2017](https://www.youtube.com/watch?v=3RUMShnJq_I)
	* [Sysmon - The Best Free Windows Monitoring Tool You Aren't Using](http://909research.com/sysmon-the-best-free-windows-monitoring-tool-you-arent-using/)
	* [SysInternals: SysMon Unleashed](https://blogs.technet.microsoft.com/motiba/2016/10/18/sysinternals-sysmon-unleashed/)
* **Traffic Analysis**
	* [Behavioral Analysis using DNS, Network Traffic and Logs, Josh Pyorre (@joshpyorre)](https://www.youtube.com/watch?v=oLemvzZjDOs&index=13&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
		* Multiple methods exist for detecting malicious activity in a network, including intrusion detection, anti-virus, and log analysis. However, the majority of these use signatures, looking for already known events and they typically require some level of human intervention and maintenance. Using behavioral analysis methods, it may be possible to observe and create a baseline of average behavior on a network, enabling intelligent notification of anomalous activity. This talk will demonstrate methods of performing this activity in different environments. Attendees will learn new methods which they can apply to further monitor and secure their networks
	* **Tools**
		* **Frameworks**
			* [RITA - Real Intelligence Threat Analytics](https://github.com/ocmdev/rita)
				* RITA is an open source network traffic analysis framework.
				* [RITA - Finding Bad Things on Your Network Using Free and Open Source Tools](https://www.youtube.com/watch?v=mpCBOQSjbOA)
			* [HELK - The Hunting ELK](https://github.com/Cyb3rWard0g/HELK)
				* A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.
		* **General**
			* [DNSpop](https://github.com/bitquark/dnspop) 
				* Tools to find popular trends by analysis of DNS data. For more information, see my [blog post](https://bitquark.co.uk/blog/2016/02/29/the_most_popular_subdomains_on_the_internet) on the most popular subdomains on the internet. Hit the results directory to get straight to the data.
			* [Yeti](https://github.com/yeti-platform/yeti)
				* Yeti is a platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository. Yeti will also automatically enrich observables (e.g. resolve domains, geolocate IPs) so that you don't have to. Yeti provides an interface for humans (shiny Bootstrap-based UI) and one for machines (web API) so that your other tools can talk nicely to it.
			* [Malcom - Malware Communication Analyzer](https://github.com/tomchop/malcom)
				* Malcom is a tool designed to analyze a system's network communication using graphical representations of network traffic, and cross-reference them with known malware sources. This comes handy when analyzing how certain malware species try to communicate with the outside world.
			* [BeaconBits](https://github.com/bez0r/BeaconBits)
				* Beacon Bits is comprised of analytical scripts combined with a custom database that evaluate flow traffic for statistical uniformity over a given period of time. The tool relies on some of the most common characteristics of infected host persisting in connection attempts to establish a connection, either to a remote host or set of host over a TCP network connection. Useful to also identify automation, host behavior that is not driven by humans.
* **IDS/IPS Tools**
	* **Snort**
		* [Snort](https://www.snort.org/)
			* A free lightweight network intrusion detection system for UNIX and Windows.
		* [Snort FAQ](https://www.snort.org/faq)
		* [Snort User Manual](http://manual.snort.org/)
		* [Snort Documentation](https://www.snort.org/documents)
	* **Bro**
		* [Bro](https://www.bro.org/index.html)
			* Bro is a powerful network analysis framework that is much different from the typical IDS you may know. 
		* [Bro FAQ](https://www.bro.org/documentation/faq.html)
		* [Bro Documentation](https://www.bro.org/documentation/index.html)
		* [Bro Training Exercises](https://www.bro.org/documentation/exercises/index.html)
		* [Download Bro](https://www.bro.org/download/index.html)
		* [Try Bro in your browser!](http://try.bro.org/#/trybro)
		* [Bro QuickStart](https://www.bro.org/sphinx/quickstart/index.html)
		* [Writing Bro Scripts](https://www.bro.org/sphinx/scripting/index.html)
		* [Bro Script References](https://www.bro.org/sphinx/script-reference/index.html)
		* [ bro-intel-generator](https://github.com/exp0se/bro-intel-generator)
			* Script for generating Bro intel files from pdf or html reports
		* [bro-domain-generation](https://github.com/denji/bro-domain-generation)
			* Detect domain generation algorithms (DGA) with Bro. The module will regularly generate domains by any implemented algorithms and watch for those domains in DNS queries. This script only works with Bro 2.1+.
		* [Exfil Framework](https://github.com/reservoirlabs/bro-scripts/tree/master/exfil-detection-framework)
			* The Exfil Framework is a suite of Bro scripts that detect file uploads in TCP connections. The Exfil Framework can detect file uploads in most TCP sessions including sessions that have encrypted payloads (SCP,SFTP,HTTPS).
	* **Suricata**
		* [Suricata](https://suricata-ids.org/)
			* Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. Open Source and owned by a community run non-profit foundation, the Open Information Security Foundation (OISF).
			* [Suricata Documentation](https://redmine.openinfosecfoundation.org/projects/suricata/wiki)
			* [Suricata Quick Start Guide](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Quick_Start_Guide)
			* [Suricata Installation Guides for various platforms](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation)
			* [Setting up Suricata on a Microtik Router](http://robert.penz.name/849/howto-setup-a-mikrotik-routeros-with-suricata-as-ids/)
	* **Argus**
		* [Argus](http://qosient.com/argus/#)
			* Argus is an open source layer 2+ auditing tool (including IP audit) written by Carter Bullard which has been under development for over 10 years.
		* [Argus on NSM Wiki](https://www.nsmwiki.org/index.php?title=Argus)
		* [Argus FAQ](http://qosient.com/argus/faq.shtml)
		* [Argus How-To](http://qosient.com/argus/howto.shtml)
		* [Argus Manual](http://qosient.com/argus/manuals.shtml)
* **IDS/IPS Monitoring Tools**
	* [Snorby](https://www.snorby.org/)
	* [Snorby - Github](https://github.com/snorby/snorby)
		* Snorby is a ruby on rails web application for network security monitoring that interfaces with current popular intrusion detection systems (Snort, Suricata and Sagan). The basic fundamental concepts behind Snorby are simplicity, organization and power. The project goal is to create a free, open source and highly competitive application for network monitoring for both private and enterprise use.
	* [Squil](https://bammv.github.io/sguil/index.html)
		* Sguil (pronounced sgweel) is built by network security analysts for network security analysts. Sguil's main component is an intuitive GUI that provides access to realtime events, session data, and raw packet captures. Sguil facilitates the practice of Network Security Monitoring and event driven analysis. The Sguil client is written in tcl/tk and can be run on any operating system that supports tcl/tk (including Linux, * BSD, Solaris, MacOS, and Win32). 
		* [Squil FAQ](http://nsmwiki.org/Sguil_FAQ)
	* [Squert](http://www.squertproject.org/)
		* Squert is a web application that is used to query and view event data stored in a Sguil database (typically IDS alert data). Squert is a visual tool that attempts to provide additional context to events through the use of metadata, time series representations and weighted and logically grouped result sets. The hope is that these views will prompt questions that otherwise may not have been asked. 
		* [Slide Deck on Squert](https://ea01c580-a-62cb3a1a-s-sites.googlegroups.com/site/interrupt0x13h/squert-canheit2014.pdf?attachauth=ANoY7crNJbed8EeVy3r879eb2Uze_ky7eiO-jvwXp2J7ik_hOyk0kK6uhX3_oT3u4Kuzw7AiuTAQhYGze5jdlQ-w8lagM1--XESGAf0ebLBZU6bGYd7mIC9ax1H49jvQHGb8kojEal8bayL0evZpOFqsr135DpazJ6F5HkVACpHyCqh3Gzafuxxog_Ybp7k4IgqltqH0pZddcIcjI0LwhHaj3Al085C3tbw2YMck1JQSeeBYvF9hL-0%3D&attredirects=0)
		* [Install/setup/etc - Github](https://github.com/int13h/squert)
* **ELK Stack**
	* **101**
		* [Introduction and Demo to the Elasticsearch, Logstash and Kibana](https://www.youtube.com/watch?v=GrdzX9BNfkg)
	* **Elastic Search**
		* [Elasticsearch: The Definitive Guide The Definitive Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html)
	* **Kibana**
		* [Kibana](https://github.com/elasticsearch/kibana)
			* Kibana is an open source (Apache Licensed), browser based analytics and search dashboard for Elasticsearch. Kibana is a snap to setup and start using. Kibana strives to be easy to get started with, while also being flexible and powerful, just like Elasticsearch.
		* [Introduction to Kibana](http://www.elasticsearch.org/guide/en/kibana/current/introduction.html)
		* [Kibana Documentation/Guides](http://www.elasticsearch.org/guide/en/kibana/current/)
		* [Installing Kibana](http://www.elasticsearch.org/overview/kibana/installation/)
	* **LogStash**
		* [LogStash](https://github.com/elasticsearch/logstash)
			* Logstash is a tool for managing events and logs. You can use it to collect logs, parse them, and store them for later use (like, for searching). If you store them in Elasticsearch, you can view and analyze them with Kibana. It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.
		* [Getting Started With Logstash](http://logstash.net/docs/1.4.2/tutorials/getting-started-with-logstash)
		* [Logstash Documentation](http://logstash.net/docs/1.4.2/)
		* [logstash anonymize](http://logstash.net/docs/1.4.2/filters/anonymize) * Anonymize fields using by replacing values with a consistent hash.
