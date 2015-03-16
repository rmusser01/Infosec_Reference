##Network Security Monitoring


[Snorby](https://www.snorby.org/)


[ELSA](https://github.com/mcholste/elsa)


###Cull

[Logging ALL THE THINGS Without All The Cost With Open Source Big Data Tools - DEFCON22 - Zach Fasel](https://www.youtube.com/watch?v=2AAnVeIwXBo)
* Many struggle in their job with the decision of what events to log in battle against costly increases to their licensing of a commercial SIEM or other logging solution. Leveraging the open source solutions used for "big-data" that have been proven by many can help build a scalable, reliable, and hackable event logging and security intelligence system to address security and (*cringe*) compliance requirements. We’ll walk through the various components and simple steps to building your own logging environment that can extensively grow (or keep sized just right) with just additional hardware cost and show numerous examples you can implement as soon as you get back to work (or home).






[bro-domain-generation](https://github.com/denji/bro-domain-generation)
* Detect domain generation algorithms (DGA) with Bro. The module will regularly generate domains by any implemented algorithms and watch for those domains in DNS queries. This script only works with Bro 2.1+.

[ bro-intel-generator](https://github.com/exp0se/bro-intel-generator)
* Script for generating Bro intel files from pdf or html reports



###ELK Stack (Elastic Search, Logstash, Kibana)

[Introduction and Demo to the Elasticsearch, Logstash and Kibana](https://www.youtube.com/watch?v=GrdzX9BNfkg)


[Argus](http://qosient.com/argus/#)
* Argus is an open source layer 2+ auditing tool (including IP audit) written by Carter Bullard which has been under development for over 10 years.
* [Argus on NSM Wiki](nsmwiki.org/index.php?title=Argus)
* [Argus FAQ](http://qosient.com/argus/faq.shtml)
* [Argus How-To](http://qosient.com/argus/howto.shtml)
* [Argus Manual](http://qosient.com/argus/manuals.shtml)


[LogStash](https://github.com/elasticsearch/logstash)
* Logstash is a tool for managing events and logs. You can use it to collect logs, parse them, and store them for later use (like, for searching). If you store them in Elasticsearch, you can view and analyze them with Kibana. It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.
* [Getting Started With Logstash](http://logstash.net/docs/1.4.2/tutorials/getting-started-with-logstash)
* [Logstash Documentation](http://logstash.net/docs/1.4.2/)




[Kibana](https://github.com/elasticsearch/kibana)
* Kibana is an open source (Apache Licensed), browser based analytics and search dashboard for Elasticsearch. Kibana is a snap to setup and start using. Kibana strives to be easy to get started with, while also being flexible and powerful, just like Elasticsearch.
* [Introduction to Kibana](http://www.elasticsearch.org/guide/en/kibana/current/introduction.html)
* [Kibana Documentation/Guides](http://www.elasticsearch.org/guide/en/kibana/current/)
* [Installing Kibana](http://www.elasticsearch.org/overview/kibana/installation/)


###Tools

[Security Onion](http://blog.securityonion.net/p/securityonion.html)
* Security Onion is a Linux distro for intrusion detection, network security monitoring, and log management. It's based on Ubuntu and contains Snort, Suricata, Bro, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner, and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!


[Network Miner](http://www.netresec.com/?page=NetworkMiner)
* NetworkMiner is a Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool in order to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files. 



[Bro](https://www.bro.org/index.html)
* Bro is a powerful network analysis framework that is much different from the typical IDS you may know. 

* [Bro FAQ](https://www.bro.org/documentation/faq.html)
* [Bro Documentation](https://www.bro.org/documentation/index.html)
* [Bro Training Exercises](https://www.bro.org/documentation/exercises/index.html)
* [Download Bro](https://www.bro.org/download/index.html)
* [Try Bro in your browser!](http://try.bro.org/#/trybro)
* [Bro QuickStart](https://www.bro.org/sphinx/quickstart/index.html)
* [Writing Bro Scripts](https://www.bro.org/sphinx/scripting/index.html)
* [Bro Script References](https://www.bro.org/sphinx/script-reference/index.html)


[Squil](https://bammv.github.io/sguil/index.html)
* Sguil (pronounced sgweel) is built by network security analysts for network security analysts. Sguil's main component is an intuitive GUI that provides access to realtime events, session data, and raw packet captures. Sguil facilitates the practice of Network Security Monitoring and event driven analysis. The Sguil client is written in tcl/tk and can be run on any operating system that supports tcl/tk (including Linux, *BSD, Solaris, MacOS, and Win32). 
* [Squil FAQ](http://nsmwiki.org/Sguil_FAQ)



[Squert](
* Squert is a web application that is used to query and view event data stored in a Sguil database (typically IDS alert data). Squert is a visual tool that attempts to provide additional context to events through the use of metadata, time series representations and weighted and logically grouped result sets. The hope is that these views will prompt questions that otherwise may not have been asked. 
* [Slide Deck on Squert](https://ea01c580-a-62cb3a1a-s-sites.googlegroups.com/site/interrupt0x13h/squert-canheit2014.pdf?attachauth=ANoY7crNJbed8EeVy3r879eb2Uze_ky7eiO-jvwXp2J7ik_hOyk0kK6uhX3_oT3u4Kuzw7AiuTAQhYGze5jdlQ-w8lagM1--XESGAf0ebLBZU6bGYd7mIC9ax1H49jvQHGb8kojEal8bayL0evZpOFqsr135DpazJ6F5HkVACpHyCqh3Gzafuxxog_Ybp7k4IgqltqH0pZddcIcjI0LwhHaj3Al085C3tbw2YMck1JQSeeBYvF9hL-0%3D&attredirects=0)
* [Install/setup/etc - Github](https://github.com/int13h/squert)


Suricata]
* Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. Open Source and owned by a community run non-profit foundation, the Open Information Security Foundation (OISF).
* [Suricata Documentation](https://redmine.openinfosecfoundation.org/projects/suricata/wiki)
* [Suricata Quick Start Guide](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Quick_Start_Guide)
* [Suricata Installation Guides for various platforms](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation)



Snort](https://www.snort.org/)
* A free lightweight network intrusion detection system for UNIX and Windows.
* [Snort FAQ](https://www.snort.org/faq)
* [Snort User Manual](http://manual.snort.org/)
* [Snort Documentation](https://www.snort.org/documents)






[Setting up Suricata on a Microtik Router](http://robert.penz.name/849/howto-setup-a-mikrotik-routeros-with-suricata-as-ids/)


[Passive DNS](https://github.com/gamelinux/passivedns)
* A tool to collect DNS records passively to aid Incident handling, Network
Security Monitoring (NSM) and general digital forensics.
* PassiveDNS sniffs traffic from an interface or reads a pcap-file and outputs
the DNS-server answers to a log file. PassiveDNS can cache/aggregate duplicate
DNS answers in-memory, limiting the amount of data in the logfile without
losing the essense in the DNS answer.