##Network Security Monitoring



Cull
* [Presentations/Videos](#videos)
* Writeups
* [Tools](#tools)
* [IDS/IPS](#ips)
* [IDS/IPS Monitoring](#monitor)
* [Logging](#log)
	* [Linux](#linux)
	* [Windows](#win)
* [PCaps/Static Data](#pcap)
* [Papers](#papers)
* [Tricks & Tips](#tricks)



##### To Do
* Create incident Response section

#### Cull


[laikaboss](https://github.com/lmco/laikaboss)

[](http://www.irongeek.com/i.php?page=videos/houseccon2015/t302-the-fox-is-in-the-henhouse-detecting-a-breach-before-the-damage-is-done-josh-sokol)

[411](https://github.com/kiwiz/411)
* Configure Searches to periodically run against a variety of data sources. You can define a custom pipeline of Filters to manipulate any generated Alerts and forward them to multiple Targets.

| **WMI-IDS** - WMI-IDS is a proof-of-concept agent-less host intrusion detection system designed to showcase the unique ability of WMI to respond to and react to operating system events in real-time. | https://github.com/fireeye/flare-wmi/tree/master/WMI-IDS

http://www.netfort.com/wp-content/uploads/PDF/WhitePapers/NetFlow-Vs-Packet-Analysis-What-Should-You-Choose.pdf

[](http://www.appliednsm.com/introducing-flowbat/)
* Awesome flow tool, SiLK backend


#### End Cull







### <a name="videos">Presentations/Videos</a>
[Logging ALL THE THINGS Without All The Cost With Open Source Big Data Tools - DEFCON22 - Zach Fasel](https://www.youtube.com/watch?v=2AAnVeIwXBo)
* Many struggle in their job with the decision of what events to log in battle against costly increases to their licensing of a commercial SIEM or other logging solution. Leveraging the open source solutions used for "big-data" that have been proven by many can help build a scalable, reliable, and hackable event logging and security intelligence system to address security and (*cringe*) compliance requirements. We’ll walk through the various components and simple steps to building your own logging environment that can extensively grow (or keep sized just right) with just additional hardware cost and show numerous examples you can implement as soon as you get back to work (or home).

[Current State of Virtualizing Network Monitoring](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t202-current-state-of-virtualizing-network-monitoring-daniel-lohin-ed-sealing)



### Writeups

[Many ways of malware persistence (that you were always afraid to ask) ](http://jumpespjump.blogspot.com/2015/05/many-ways-of-malware-persistence-that.html)

[Shellcode Analysis Pipeline](https://7h3ram.github.io/2014/3/18/shellcode-pipeline/)
* I recently required an automated way of analyzing shellcode and verifying if it is detected by Libemu, Snort, Suricata, Bro, etc. Shellcode had to come from public sources like Shell-Storm, Exploit-DB and Metasploit. I needed an automated way of sourcing shellcode from these projects and pass it on to the analysis engines in a pipeline-like mechanism. This posts documents the method I used to complete this task and the overall progress of the project.



### <a name="tools">Tools</a>
[Security Onion](http://blog.securityonion.net/p/securityonion.html)
* Security Onion is a Linux distro for intrusion detection, network security monitoring, and log management. It's based on Ubuntu and contains Snort, Suricata, Bro, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner, and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!

[Pip3line, the Swiss army knife of byte manipulation](https://nccgroup.github.io/pip3line/index.html) 
* Pip3line is a raw bytes manipulation utility, able to apply well known and less well known transformations from anywhere to anywhere (almost).

[RITA - Real Intelligence Threat Analytics](https://github.com/ocmdev/rita)
* RITA is an open source network traffic analysis framework.

[Malcom - Malware Communication Analyzer](https://github.com/tomchop/malcom)
* Malcom is a tool designed to analyze a system's network communication using graphical representations of network traffic, and cross-reference them with known malware sources. This comes handy when analyzing how certain malware species try to communicate with the outside world.

[Captipper](http://www.omriher.com/2015/01/captipper-malicious-http-traffic.html)
* CapTipper is a python tool to analyze, explore and revive HTTP malicious traffic. 
CapTipper sets up a web server that acts exactly as the server in the PCAP file, 
and contains internal tools, with a powerful interactive console, for analysis and inspection of the hosts, objects and conversations found.  

[CapLoader](http://www.netresec.com/?page=CapLoader) 
*  CapLoader is a Windows tool designed to handle large amounts of captured network traffic. CapLoader performs indexing of PCAP/PcapNG files and visualizes their contents as a list of TCP and UDP flows. Users can select the flows of interest and quickly filter out those packets from the loaded PCAP files. Sending the selected flows/packets to a packet analyzer tool like Wireshark or NetworkMiner is then just a mouse click away. 

[dnstwist](https://github.com/elceef/dnstwist)
* Domain name permutation engine for detecting typo squatting, phishing and corporate espionage







### <a name="ips">IDS/IPS</a>


#### [Snort](https://www.snort.org/)
* A free lightweight network intrusion detection system for UNIX and Windows.
* [Snort FAQ](https://www.snort.org/faq)
* [Snort User Manual](http://manual.snort.org/)
* [Snort Documentation](https://www.snort.org/documents)

#### [Bro](https://www.bro.org/index.html)
* Bro is a powerful network analysis framework that is much different from the typical IDS you may know. 

* [Bro FAQ](https://www.bro.org/documentation/faq.html)
* [Bro Documentation](https://www.bro.org/documentation/index.html)
* [Bro Training Exercises](https://www.bro.org/documentation/exercises/index.html)
* [Download Bro](https://www.bro.org/download/index.html)
* [Try Bro in your browser!](http://try.bro.org/#/trybro)
* [Bro QuickStart](https://www.bro.org/sphinx/quickstart/index.html)
* [Writing Bro Scripts](https://www.bro.org/sphinx/scripting/index.html)
* [Bro Script References](https://www.bro.org/sphinx/script-reference/index.html)

[ bro-intel-generator](https://github.com/exp0se/bro-intel-generator)
* Script for generating Bro intel files from pdf or html reports

[bro-domain-generation](https://github.com/denji/bro-domain-generation)
* Detect domain generation algorithms (DGA) with Bro. The module will regularly generate domains by any implemented algorithms and watch for those domains in DNS queries. This script only works with Bro 2.1+.

[Exfil Framework](https://github.com/reservoirlabs/bro-scripts/tree/master/exfil-detection-framework)
* The Exfil Framework is a suite of Bro scripts that detect file uploads in TCP connections. The Exfil Framework can detect file uploads in most TCP sessions including sessions that have encrypted payloads (SCP,SFTP,HTTPS).



#### [Suricata](suricata?)
* Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. Open Source and owned by a community run non-profit foundation, the Open Information Security Foundation (OISF).
* [Suricata Documentation](https://redmine.openinfosecfoundation.org/projects/suricata/wiki)
* [Suricata Quick Start Guide](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Quick_Start_Guide)
* [Suricata Installation Guides for various platforms](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation)
* [Setting up Suricata on a Microtik Router](http://robert.penz.name/849/howto-setup-a-mikrotik-routeros-with-suricata-as-ids/)

#### [Argus](http://qosient.com/argus/#)
* Argus is an open source layer 2+ auditing tool (including IP audit) written by Carter Bullard which has been under development for over 10 years.
* [Argus on NSM Wiki](nsmwiki.org/index.php?title=Argus)
* [Argus FAQ](http://qosient.com/argus/faq.shtml)
* [Argus How-To](http://qosient.com/argus/howto.shtml)
* [Argus Manual](http://qosient.com/argus/manuals.shtml)

[bmon - bandwidth monitor and rate estimator](https://github.com/tgraf/bmon)
* bmon is a monitoring and debugging tool to capture networking related statistics and prepare them visually in a human friendly way. It features various output methods including an interactive curses user interface and a programmable text output for scripting.






### DNS

[DNSChef](https://thesprawl.org/projects/dnschef/)
* DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example, a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.

[Passive DNS](https://github.com/gamelinux/passivedns) 
* A tool to collect DNS records passively to aid Incident handling, Network Security Monitoring (NSM) and general digital forensics.  * PassiveDNS sniffs traffic from an interface or reads a pcap-file and outputs the DNS-server answers to a log file. PassiveDNS can cache/aggregate duplicate DNS answers in-memory, limiting the amount of data in the logfile without losing the essense in the DNS answer.

[Passive DNS](https://github.com/gamelinux/passivedns)
* A tool to collect DNS records passively to aid Incident handling, Network
Security Monitoring (NSM) and general digital forensics.
* PassiveDNS sniffs traffic from an interface or reads a pcap-file and outputs
the DNS-server answers to a log file. PassiveDNS can cache/aggregate duplicate
DNS answers in-memory, limiting the amount of data in the logfile without
losing the essense in the DNS answer.








### <a name="monitor">IDS/IPS Monitoring Tools</a>

[Snorby](https://www.snorby.org/)
[Snorby - Github](https://github.com/snorby/snorby)
* Snorby is a ruby on rails web application for network security monitoring that interfaces with current popular intrusion detection systems (Snort, Suricata and Sagan). The basic fundamental concepts behind Snorby are simplicity, organization and power. The project goal is to create a free, open source and highly competitive application for network monitoring for both private and enterprise use.


[Squil](https://bammv.github.io/sguil/index.html)
* Sguil (pronounced sgweel) is built by network security analysts for network security analysts. Sguil's main component is an intuitive GUI that provides access to realtime events, session data, and raw packet captures. Sguil facilitates the practice of Network Security Monitoring and event driven analysis. The Sguil client is written in tcl/tk and can be run on any operating system that supports tcl/tk (including Linux, *BSD, Solaris, MacOS, and Win32). 
* [Squil FAQ](http://nsmwiki.org/Sguil_FAQ)

[Squert](
* Squert is a web application that is used to query and view event data stored in a Sguil database (typically IDS alert data). Squert is a visual tool that attempts to provide additional context to events through the use of metadata, time series representations and weighted and logically grouped result sets. The hope is that these views will prompt questions that otherwise may not have been asked. 
* [Slide Deck on Squert](https://ea01c580-a-62cb3a1a-s-sites.googlegroups.com/site/interrupt0x13h/squert-canheit2014.pdf?attachauth=ANoY7crNJbed8EeVy3r879eb2Uze_ky7eiO-jvwXp2J7ik_hOyk0kK6uhX3_oT3u4Kuzw7AiuTAQhYGze5jdlQ-w8lagM1--XESGAf0ebLBZU6bGYd7mIC9ax1H49jvQHGb8kojEal8bayL0evZpOFqsr135DpazJ6F5HkVACpHyCqh3Gzafuxxog_Ybp7k4IgqltqH0pZddcIcjI0LwhHaj3Al085C3tbw2YMck1JQSeeBYvF9hL-0%3D&attredirects=0)
* [Install/setup/etc - Github](https://github.com/int13h/squert)









### <a name="log">Logging - General</a>

[Introduction and Demo to the Elasticsearch, Logstash and Kibana](https://www.youtube.com/watch?v=GrdzX9BNfkg)

[ELSA](https://github.com/mcholste/elsa)

[Elasticsearch: The Definitive Guide The Definitive Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html)

[LogStash](https://github.com/elasticsearch/logstash)
* Logstash is a tool for managing events and logs. You can use it to collect logs, parse them, and store them for later use (like, for searching). If you store them in Elasticsearch, you can view and analyze them with Kibana. It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.
* [Getting Started With Logstash](http://logstash.net/docs/1.4.2/tutorials/getting-started-with-logstash)
* [Logstash Documentation](http://logstash.net/docs/1.4.2/)
* [logstash anonymize](http://logstash.net/docs/1.4.2/filters/anonymize) * Anonymize fields using by replacing values with a consistent hash.

[Kibana](https://github.com/elasticsearch/kibana)
* Kibana is an open source (Apache Licensed), browser based analytics and search dashboard for Elasticsearch. Kibana is a snap to setup and start using. Kibana strives to be easy to get started with, while also being flexible and powerful, just like Elasticsearch.
* [Introduction to Kibana](http://www.elasticsearch.org/guide/en/kibana/current/introduction.html)
* [Kibana Documentation/Guides](http://www.elasticsearch.org/guide/en/kibana/current/)
* [Installing Kibana](http://www.elasticsearch.org/overview/kibana/installation/)









### <a name="linux">Logging - Linux</a>

[Syslong-ng](https://github.com/balabit/syslog-ng) 
* syslog-ng is an enhanced log daemon, supporting a wide range of input and output methods: syslog, unstructured text, message queues, databases (SQL and NoSQL alike) and more.











### <a name="win">Logging - Windows</a>

[Parsing Text Logs with Message Analyzer - Microsoft](http://blogs.technet.com/b/messageanalyzer/archive/2015/02/23/parsing-text-logs-with-message-analyzer.aspx)

[Windows logging Cheat sheet - Sniper Forensics](https://sniperforensicstoolkit.squarespace.com/storage/logging/Windows%20Logging%20Cheat%20Sheet%20v1.1.pdf)

[Spotting the Adversary with Windows Event Log Monitoring - NSA](https://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf)









### <a name="pcap">Pcaps/Static Analysis(I.e. you have a pcap file or you're not trying to do live analysis/Aren't trying to use one of the above tools)</a>

[Silk - 
* The SiLK analysis suite is a collection of command-line tools for processing SiLK Flow records created by the SiLK packing system. These tools read binary files containing SiLK Flow records and partition, sort, and count these records. The most important analysis tool is rwfilter, an application for querying the central data repository for SiLK Flow records that satisfy a set of filtering options. The tools are intended to be combined in various ways to perform an analysis task. A typical analysis uses UNIX pipes and intermediate data files to share data between invocations of the tools. 
* [Administering/Installing SiLK](https://tools.netsa.cert.org/confluence/display/tt/Administration)
* [SiLK Tool Tips](https://tools.netsa.cert.org/confluence/display/tt/Tooltips
* [SiLK Reference Guide](https://tools.netsa.cert.org/silk/silk-reference-guide.html)
* [SiLK Toolsuite Quick Reference Guide](https://tools.netsa.cert.org/silk/silk-quickref.pdf)

[CapLoader](http://www.netresec.com/?page=CapLoader) *  CapLoader is a Windows tool designed to handle large amounts of captured network traffic. CapLoader performs indexing of PCAP/PcapNG files and visualizes their contents as a list of TCP and UDP flows. Users can select the flows of interest and quickly filter out those packets from the loaded PCAP files. Sending the selected flows/packets to a packet analyzer tool like Wireshark or NetworkMiner is then just a mouse click away. 

[Network Miner](http://www.netresec.com/?page=NetworkMiner)
* NetworkMiner is a Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool in order to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.










### <a name="papers">Papers</a>

[Network Profiling Using Flow](https://resources.sei.cmu.edu/asset_files/technicalreport/2012_005_001_28167.pdf)
* This report provides a step-by-step guide for profiling—discovering public-facing assets on a  network—using network flow (netflow) data. Netflow data can be used for forensic purposes, for  finding malicious activity, and for determining appropriate prioritization settings. The goal of this  report is to create a profile to see a potential  attacker’s view of an external network.   Readers will learn how to choose a data set, find the top assets and services with the most traffic  on the network, and profile several services. A cas e study provides an example of the profiling  process. The underlying concepts of using netflow data are presented so that readers can apply the  approach to other cases. A reader using this repor t to profile a network can expect to end with a  list of public-facing assets and the ports on which  each is communicating and may also learn other  pertinent information, such as external IP addresses, to which the asset is connecting. This report  also provides ideas for using, maintaining, and reporting on findings. The appendices include an  example profile and scripts for running the commands in the report. The scripts are a summary  only and cannot replace reading and understanding this report.

[Making the Most of OSSEC](http://www.ossec.net/files/Making_the_Most_of_OSSEC.pdf)

[Using SiLK for Network  Traffic Analysis](https://tools.netsa.cert.org/silk/analysis-handbook.pdf)










### <a name="tricks">Tricks & Tips</a>
[Using rwuniq for Top-10 Lists](https://tools.netsa.cert.org/confluence/display/tt/Using+rwuniq+for+Top-10+Lists)



