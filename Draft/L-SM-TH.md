# Logging(Host/Network) / Security Monitoring / Threat Hunting


--------------------
## Table of Contents


https://www.youtube.com/watch?v=YGJaj6_3dGA

https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf

* [Mental Models for Effective Searching - Chris Sanders](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1555082140.pdf)
* [kethash](https://github.com/cyberark/ketshash)
	* A little tool for detecting suspicious privileged NTLM connections, in particular Pass-The-Hash attack, based on event viewer logs.
https://www.endgame.com/blog/technical-blog/hunting-memory-net-attacks
* [Hunting for SILENTTRINITY - Wee-Jing Chung](https://countercept.com/blog/hunting-for-silenttrinity/)
* [Use Windows Event Forwarding to help with intrusion detection - docs.ms](Use Windows Event Forwarding to help with intrusion detection)
* [Digital Steganography as an Advanced Malware Detection Evasion Technique - z3roTrust(Masters Thesis)](https://medium.com/@z3roTrust/digital-steganography-as-an-advanced-malware-detection-evasion-technique-40d4eeb19830)
* [Sysinternals Sysmon suspicious activity guide - Moti Bani](https://blogs.technet.microsoft.com/motiba/2017/12/07/sysinternals-sysmon-suspicious-activity-guide/)
* [Background Intelligent Transfer Protocol - TH Team](https://medium.com/@threathuntingteam/background-intelligent-transfer-protocol-ab81cd900aa7)
https://blog.xpnsec.com/evading-sysmon-dns-monitoring/
* [GENE: Go Evtx sigNature Engine](https://github.com/0xrawsec/gene)
	* The idea behind this project is to provide an efficient and standard way to look into Windows Event Logs (a.k.a EVTX files). For those who are familiar with Yara, it can be seen as a Yara engine but to look for information into Windows Events.
https://medium.com/mitre-attack/getting-started-with-attack-detection-a8e49e4960d0
		* [Obtaining and Detecting Domain Persistence - Grant Bugher(DEF CON 23)](https://www.youtube.com/watch?v=gajEuuC2-Dk)
			* When a Windows domain is compromised, an attacker has several options to create backdoors, obscure his tracks, and make his access difficult to detect and remove. In this talk, I discuss ways that an attacker who has obtained domain administrator privileges can extend, persist, and maintain control, as well as how a forensic examiner or incident responder could detect these activities and root out an attacker.


https://fortinetweb.s3.amazonaws.com/fortiguard/research/Learn_How_to_Build_Your_Own_Utility_to_Monitor_Malicious_Behaviors_of_Malware_on%20macOS_KaiLu.pdf
https://www.blackhat.com/us-18/arsenal.html#learn-how-to-build-your-own-utility-to-monitor-malicious-behaviors-of-malware-on-macos
https://jpcertcc.github.io/ToolAnalysisResultSheet/
https://techcommunity.microsoft.com/t5/Azure-Sentinel/Identifying-Threat-Hunting-opportunities-in-your-data/ba-p/915721




https://www.peerlyst.com/posts/security-monitoring-and-attack-detection-with-elasticsearch-logstash-and-kibana-martin-boller
https://github.com/littl3field/Audix
https://digital-forensics.sans.org/blog/2019/02/09/investigating-wmi-attacks
https://github.com/hunters-forge/API-To-Event
https://www.peerlyst.com/posts/threat-hunting-basics-getting-manual-soc-prime
* [Windows Privilege Abuse: Auditing, Detection, and Defense - Palantir](https://medium.com/palantir/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)

https://www.youtube.com/watch?v=iweEI60PWeY
* [Container Forensics: What to Do When Your Cluster is a Cluster - Maya Kaczorowski & Ann Wallace(CloudNativeConEU19) ](https://www.youtube.com/watch?v=MyXROAqO7YI&list=PLKDRii1YwXnLmd8ngltnf9Kzvbja3DJWx&index=7&t=0s)
	* When responding to an incident in your containers, you don’t necessarily have the same tools at your disposal that you do with VMs - and so your incident investigation process and forensics are different. In a best case scenario, you have access to application logs, orchestrator logs, node snapshots, and more.  In this talk, we’ll go over where to get information about what’s happening in your cluster, including logs and open source tools you can install, and how to tie this information together to get a better idea of what’s happening in your infrastructure. Armed with this info, we’ll review the common mitigation options such as to alert, isolate, pause, restart, or kill a container. For common types of container attacks, we'll discuss what options are best and why. Lastly, we’ll talk about restoring services after an incident, and the best steps to take to prevent the next one.
* [Get Cozy with OpenBSM Auditing...the good, the bad, & the ugly - Patrick Wardle](https://objective-see.com/talks/Wardle_ShmooCon2018.pdf)
* [Getting Cozy With OpenBSM Auditing On MacOS - Patrick Wardle](https://www.youtube.com/watch?v=CqlpJ7rIT6M)
	* With the demise of dtrace on macOS, and Apple’s push to rid the kernel of 3rd-party kexts, another option is needed to perform effective auditing on macOS. Lucky for us, OpenBSM fits the bill. Though quite powerful, this auditing mechanism is rather poorly documented and suffered from a variety of kernel vulnerabilities. In this talk, we’ll begin with an introductory overview of OpenBSM’s goals, capabilities, and components before going ‘behind-the-scenes’ to take a closer look at it’s kernel-mode implementation. Armed with this understanding, we’ll then detail exactly how to build powerful user-mode macOS monitoring utilities such as file, process, and networking monitors based on the OpenBSM framework and APIs. Next we’ll don our hacker hats and discuss a handful of kernel bugs discovered during a previous audit of the audit subsystem (yes, quite meta): a subtle off-by-one read error, a blotched patch that turned the off-by-one into a kernel info leak, and finally an exploitable heap overflow. Though now patched, the discussion of these bugs provides an interesting ‘case-study’ of finding and exploiting several types of bugs that lurked within the macOS kernel for many years
https://github.com/maus-/slack-auditor
* [When Macs Come Under ATT&CK - Richie Cyrus(Derbycon2018)](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-01-when-macs-come-under-attck-richie-cyrus)
	* Macs are becoming commonplace in corporate environments as a alternative to Windows systems. Developers, security teams, and executives alike favor the ease of use and full administrative control Macs provide. However, their systems are often joined to an active directory domain and ripe for attackers to leverage for initial access and lateral movement. Mac malware is evolving as Mac computers continue to grow in popularity. As a result, there is a need for proactive detection of attacks targeting MacOS systems in a enterprise environment. Despite advancements in MacOS security tooling for a single user/endpoint, little is known and discussed regarding detection at a enterprise level. This talk will discuss common tactics, techniques and procedures used by attackers on MacOS systems, as well as methods to detect adversary activity. We will take a look at known malware, mapping the techniques utilized to the MITRE ATT&CK framework. Attendees will leave equipped to begin hunting for evil lurking within their MacOS fleet.
https://blog.stealthbits.com/windows-file-activity-monitoring/
https://github.com/salesforce/bro-sysmon
* [Detecting Kerberoasting activity using Azure Security Center - Moti Bani](https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/)
* [Practical PowerShell Security: Enable Auditing and Logging with DSC - Ashley McGlone](https://blogs.technet.microsoft.com/ashleymcglone/2017/03/29/practical-powershell-security-enable-auditing-and-logging-with-dsc/)
* [Detecting Offensive PowerShell Attack Tools - adsecurity.org](https://adsecurity.org/?p=2604)
https://github.com/djhohnstein/EventLogParser
https://blog.redteam.pl/2019/08/threat-hunting-dns-firewall.html?m=1
* [Windows 10, version 1809 basic level Windows diagnostic events and fields](https://docs.microsoft.com/en-gb/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1809#windows-error-reporting-events)
* [How to Detect Overpass-The-Hash Attacks - Jeff Warren](https://blog.stealthbits.com/how-to-detect-overpass-the-hash-attacks/)

* [Implementing Sysmon and Applocker - BHIS](https://www.youtube.com/watch?v=9qsP5h033Qk)
	* In almost every BHIS webcast we talk about how important application whitelisting and Sysmon are to a healthy security infrastructure. And yet, we have not done a single webcast on these two topics. Let's fix that. In this webcast we cover how to implement Sysmon and Applocker. We cover overall strategies for implementation and how to deploy them via Group Policy. We walk through a basic sample of malware and show how both of these technologies react to it. Finally, we cover a couple of different "bypass" techniques for each. Everything in security has weaknesses, and these two technologies are no exception.

* [The Role of Evidence Intention - Chris Sanders](https://rhinosecuritylabs.com/application-security/simplifying-api-pentesting-swagger-files/)
* [$SignaturesAreDead = “Long Live RESILIENT Signatures” wide ascii nocase - Matthew Dunwoody, Daniel Bohannon(BruCON 0x0A)](https://www.youtube.com/watch?v=YGJaj6_3dGA)
	* Signatures are dead, or so we're told. It's true that many items that are shared as Indicators of Compromise (file names/paths/sizes/hashes and network IPs/domains) are no longer effective. These rigid indicators break at the first attempt at evasion. Creating resilient detections that stand up to evasion attempts by dedicated attackers and researchers is challenging, but is possible with the right tools, visibility and methodical (read iterative) approach.   As part of FireEye's Advanced Practices Team, we are tasked with creating resilient, high-fidelity detections that run across hundreds of environments and millions of endpoints. In this talk we will share insights on our processes and approaches to detection development, including practical examples derived from real-world attacks.
https://github.com/miriamxyra/EventList
* [Different Approaches to Linux Monitoring - Kelly Shortridge](https://capsule8.com/blog/different-approaches-to-linux-monitoring/)
* [Detecting the Elusive Active Directory Threat Hunting - Sean Metcalf(BSidesCharm2017)](https://www.youtube.com/watch?v=9Uo7V9OUaUw)
	* Attacks are rarely detected even after months of activity. What are defenders missing and how could an attack by detected? This talk covers effective methods to detect attacker activity using the features built into Windows and how to optimize a detection strategy. The primary focus is on what knobs can be turned and what buttons can be pushed to better detect attacks. One of the latest tools in the offensive toolkit is ""Kerberoast"" which involves cracking service account passwords offline without admin rights. This attack technique is covered at length including the latest methods to extract and crack the passwords. Furthermore, this talk describes a new detection method the presenter developed. The attacker's playbook evolves quickly, defenders need to stay up to speed on the latest attack methods and ways to detect them. This presentation will help you better understand what events really matter and how to better leverage Windows features to track, limit, and detect attacks.
	* [Slides](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)

* [What’s in a name? TTPs in Info Sec - Robby Winchester](https://posts.specterops.io/whats-in-a-name-ttps-in-info-sec-14f24480ddcc)

https://blog.kolide.com/monitoring-macos-hosts-with-osquery-ba5dcc83122d?gi=e42e60717e0
https://blog.trailofbits.com/2017/11/09/how-are-teams-currently-using-osquery/
https://blog.trailofbits.com/2017/12/21/osquery-pain-points/
https://blog.trailofbits.com/2018/04/10/what-do-you-wish-osquery-could-do/
https://github.com/davehull/Kansa
* [WebDAV Traffic To Malicious Sites - Didier Stevens](https://blog.didierstevens.com/2017/11/13/webdav-traffic-to-malicious-sites/)

* https://github.com/beahunt3r/Windows-Hunting

https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
https://www.microsoft.com/en-us/download/confirmation.aspx?id=52630
https://www.microsoft.com/en-us/download/details.aspx?id=50034


* [Logs Are Streams, Not Files - Adam Wiggins](https://adam.herokuapp.com/past/2011/4/1/logs_are_streams_not_files/)

https://www.youtube.com/watch?v=YwR7m3Qt2ao&feature=youtu.be

* [Getting Cozy With OpenBSM Auditing On MacOS - Patrick Wardle(Shmoocon2018)](https://www.youtube.com/watch?v=CqlpJ7rIT6M)

https://posts.specterops.io/threat-hunting-with-jupyter-notebooks-part-1-your-first-notebook-9a99a781fde7

OSQuery
	* https://github.com/facebook/osquery/tree/master/packs
	* https://osquery.readthedocs.io/en/stable/

* [Mordor](https://github.com/Cyb3rWard0g/mordor)
	* The Mordor project provides pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files for easy consumption. The pre-recorded data is categorized by platforms, adversary groups, tactics and techniques defined by the Mitre ATT&CK Framework. The pre-recorded data represents not only specific known malicious events but additional context/events that occur around it. This is done on purpose so that you can test creative correlations across diverse data sources, enhancing your detection strategy and potentially reducing the number of false positives in your own environment.

ThreatHunting
	* https://github.com/ThreatHuntingProject/ThreatHunting
	* https://sqrrl.com/media/Framework-for-Threat-Hunting-Whitepaper.pdf
	* https://www.threathunting.net/files/huntpedia.pdf
	* https://www.sans.org/reading-room/whitepapers/threats/paper/37172


* [Mental Models for Effective Searching - Chris Sanders](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1555082140.pdf)


* [DNS based threat hunting and DoH (DNS over HTTPS) - blog.redteam.pl](https://blog.redteam.pl/2019/04/dns-based-threat-hunting-and-doh.html)

* [Hunting COM Objects - Charles Hamilton](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html)
* [Hunting COM Objects (Part Two) - Brett Hawkins](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects-part-two.html)


https://posts.specterops.io/threat-hunting-with-jupyter-notebooks-part-4-sql-join-via-apache-sparksql-6630928c931e
* **Osquery**
	* [Using Osquery to Detect Reverse Shells on MacOS - Chris Long](https://www.clo.ng/blog/osquery_reverse_shell/)
* **File Monitoring**
	* [Practical PowerShell for IT Security, Part I: File Event Monitoring - varonis.com](https://www.varonis.com/blog/practical-powershell-for-it-security-part-i-file-event-monitoring/)
* [Use Windows Event Forwarding to help with intrusion detection - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)

* [Threat Hunting: Fine Tuning Sysmon & Logstash to find Malware Callbacks C&C - Pablo Delgado](https://www.syspanda.com/index.php/2018/07/30/threat-hunting-fine-tuning-sysmon-logstash-find-malware-callbacks-cc/)

* [Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK - Part I (Event ID 7) - Roberto Rodriguez](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html?m=1)
* [Threat Hunting With Python Part 1 - Dan Gunter](https://dragos.com/blog/industry-news/threat-hunting-with-python-part-1/)
* [Windows-Hunting](https://github.com/beahunt3r/Windows-Hunting)
	* The Purpose of this repository is to aid windows threat hunters to look for some common artifacts during their day to day operations.
* [Danger-Zone](https://github.com/woj-ciech/Danger-zone)
	* Correlate data between domains, IPs and email addresses, present it as a graph and store everything into Elasticsearch and JSON files.
https://medium.com/@maarten.goet/analyzing-your-microsoft-defender-atp-data-in-real-time-in-elk-using-the-new-streaming-api-c435d2943605

https://blog.redteam.pl/2019/04/dns-based-threat-hunting-and-doh.html
https://www.peerlyst.com/posts/security-monitoring-and-attack-detection-with-elasticsearch-logstash-and-kibana-martin-boller

https://www.youtube.com/watch?v=SzbABydoz0k

* https://github.com/Patrowl/PatrowlManager
https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950

https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation-wp.pdf

https://github.com/kolide/fleet

https://github.com/deviantony/docker-elk
https://techcommunity.microsoft.com/t5/Microsoft-Defender-ATP/Hunting-for-reconnaissance-activities-using-LDAP-search-filters/ba-p/824726

https://github.com/github/vulcanizer

* [Hunting for Bad Apples – Part 1 - Richie Cyrus](https://securityneversleeps.net/2018/06/25/hunting-for-bad-apples-part-1/)

http://penconsultants.com/blog/crown-jewels-monitoring-vs-mitigating/

https://github.com/Yelp/elastalert

* [Mordor](https://github.com/Cyb3rWard0g/mordor)
	* The Mordor project provides pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files for easy consumption. The pre-recorded data is categorized by platforms, adversary groups, tactics and techniques defined by the Mitre ATT&CK Framework. The pre-recorded data represents not only specific known malicious events but additional context/events that occur around it. This is done on purpose so that you can test creative correlations across diverse data sources, enhancing your detection strategy and potentially reducing the number of false positives in your own environment.





---------------------------
### Network Security Monitoring/Logging/Threat Hunting
* **History**
	* [The Origin of Threat Hunting - TaoSecurity](https://taosecurity.blogspot.com/2017/03/the-origin-of-threat-hunting.html?m=1)
* **101**
* **Educational**
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
		* [The Quieter You Become, the More You’re Able to (H)ELK -  Nate Guagenti, Roberto Rodriquez - BSides Colombus Ohio 2018](https://www.irongeek.com/i.php?page=videos/bsidescolumbus2018/p05-the-quieter-you-become-the-more-youre-able-to-helk-nate-guagenti-roberto-rodriquez)
			* Enabling the correct endpoint logging and centralizing the collection of different data sources has finally become a basic security standard. This allows organizations to not just increase the level of visibility, but to enhance their threat detection. Solutions such as an (Elastic) ELK stack have largely been adopted by small and large organizations for data ingestion, storage and visualization. Although, it might seem that collecting a massive amount of data is all analysts need to do their jobs, there are several challenges for them when faced with large, unstructured and often incomplete/disparate data sets. In addition to the sisyphean task of detecting and responding to adversaries there may be pitfalls with organizational funding, support, and or approval (Government). Although “everyone” is collecting logs and despite the many challenges, we will show you how to make sense of these logs in an efficient and consistent way. Specifically when it comes to Windows Event logs (ie: Sysmon, PowerShell, etc) and the ability to map fields to other logs such as Bro NSM or some other network monitoring/prevention device. This will include different Windows Event log data normalization techniques across the 1,000+ unique Event IDs and its 3,000+ unique fields. Also, proven data normalization techniques such as hashing fields/values for logs such as PowerShell, Scheduled Tasks, Command Line, and more. These implementations will show how it allows an analyst to efficiently “pivot” from an endpoint log to a NSM log or a device configuration change log. However, we will also show how an analyst can make an informed decision without degrading/hindering their investigation as well as to enhance their decision. Whether this is preventing an analyst from excluding keywords that a malicious actor may include as an “evasion” technique or adding additional analysis techniques (ie: graphing).
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
* **Infrastructure Monitoring**
	* [Ninja Level Infrastructure Monitoring Workshop - Defcon24](https://github.com/appsecco/defcon24-infra-monitoring-workshop)
		* This repository contains all the presentation, documentation and the configuration, sample logs, ansible playbook, customized dashboards and more.
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
	* **Bandwidth**
		* [bmon - bandwidth monitor and rate estimator](https://github.com/tgraf/bmon)
			* bmon is a monitoring and debugging tool to capture networking related statistics and prepare them visually in a human friendly way. It features various output methods including an interactive curses user interface and a programmable text output for scripting.
	* **ESXi**
		* **Articles/Writeups**
			* [ESXi Security Events Log Monitoring - communities.vmware](https://communities.vmware.com/docs/DOC-11542)
			* [Analyze ESXi Logs for Security-Related Messages](http://buildvirtual.net/analyze-esxi-logs-for-security-related-messages/)
		* **Tools**
			* [sexilog](https://github.com/sexibytes/sexilog)
				* SexiLog is a specific ELK virtual appliance designed for vSphere environment 
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
			* [Windows Event Forwarding Guidance](https://github.com/palantir/windows-event-forwarding) 
				* Over the past few years, Palantir has a maintained an internal Windows Event Forwarding (WEF) pipeline for generating and centrally collecting logs of forensic and security value from Microsoft Windows hosts. Once these events are collected and indexed, alerting and detection strategies (ADS) can be constructed not only on high-fidelity security events (e.g. log deletion), but also for deviations from normalcy, such as unusual service account access, access to sensitive filesystem or registry locations, or installation of malware persistence. The goal of this project is to provide the necessary building blocks for organizations to rapidly evaluate and deploy WEF to a production environment, and centralize public efforts to improve WEF subscriptions and encourage adoption. While WEF has become more popular in recent years, it is still dramatically underrepresented in the community, and it is our hope that this project may encourage others to adopt it for incident detection and response purposes. We acknowledge the efforts that Microsoft, IAD, and other contributors have made to this space and wish to thank them for providing many of the subscriptions, ideas, and techniques that will be covered in this post.
	* **Event Log**
			* [Event Logging Structures - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/eventlog/event-logging-structures)
			* [ Windows security audit events - ms.com](https://www.microsoft.com/en-us/download/details.aspx?id=50034)
				*  This spreadsheet details the security audit events for Windows. 
			* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
				* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it-s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What-s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."
			* [Public:Windows Event Log Zero 2 Hero Slides](https://docs.google.com/presentation/d/1dkrldTTlN3La-OjWtkWJBb4hVk6vfsSMBFBERs6R8zA/edit#slide=id.g21acf94f3f_2_27)
			* [Spotting the Adversary with Windows Event Log Monitoring - NSA](https://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf)
			* [Advanced Audit Policy – which GPO corresponds with which Event ID - girl-germs.com](https://girl-germs.com/?p=363)
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
	* **101**
		* [Threat Hunting Workshop - Methodologies for Threat Analysis - RiskIQ](https://www.youtube.com/playlist?list=PLgLzPE5LJevb_PcjMYMF2ypjnVcKf8rjY)
	* **Articles/Writeups**
		* [Hunting Red Team Empire C2 Infrastructure](http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html)
		* [Windows Log Hunting with PowerShell](http://909research.com/windows-log-hunting-with-powershell/)
		* [Hunting in Memory](https://www.endgame.com/blog/technical-blog/hunting-memory)
		* [Windows Log Hunting with PowerShell](http://909research.com/windows-log-hunting-with-powershell/)
		* [Taking Hunting to the Next Level Hunting in Memory - Jared Atkinson 2017](https://www.youtube.com/watch?v=3RUMShnJq_I)
		* [Sysmon - The Best Free Windows Monitoring Tool You Aren't Using](http://909research.com/sysmon-the-best-free-windows-monitoring-tool-you-arent-using/)
		* [SysInternals: SysMon Unleashed](https://blogs.technet.microsoft.com/motiba/2016/10/18/sysinternals-sysmon-unleashed/)
		* [Sysinternals Sysmon suspicious activity guide - blogs.technet](https://blogs.technet.microsoft.com/motiba/2017/12/07/sysinternals-sysmon-suspicious-activity-guide/)
	* **Persistence**
		* [Many ways of malware persistence (that you were always afraid to ask)](http://jumpespjump.blogspot.com/2015/05/many-ways-of-malware-persistence-that.html)
	* **Talks & Presentations**
		* [WEBCAST: Tales from the Network Threat Hunting Trenches - BHIS](https://www.blackhillsinfosec.com/webcast-tales-network-threat-hunting-trenches/)
			* In this webcast John walks through a couple of cool things we’ve found useful in some recent network hunt teams. He also shares some of our techniques and tools (like RITA) that we use all the time to work through massive amounts of data. There are lots of awesome websites that can greatly increase the effectiveness of your in network threat hunting.
		* [License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)
		* [Utilizing SysInternal Tools for IT Pros](http://www.microsoftvirtualacademy.com/training-courses/utilizing-sysinternals-tools-for-it-pros#fbid=1IKsqgyvnWp)
	* **Tools**
		* **OSQuery**
		* [ThreatHunting - GossiTheDog](https://github.com/GossiTheDog/ThreatHunting)
			* Tools for hunting for threats.)
		* [Windows-Hunting](https://github.com/beahunt3r/Windows-Hunting)
			* The Purpose of this repository is to aid windows threat hunters to look for some common artifacts during their day to day operations.
* **Traffic Analysis**
	* [Behavioral Analysis using DNS, Network Traffic and Logs, Josh Pyorre (@joshpyorre)](https://www.youtube.com/watch?v=oLemvzZjDOs&index=13&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
		* Multiple methods exist for detecting malicious activity in a network, including intrusion detection, anti-virus, and log analysis. However, the majority of these use signatures, looking for already known events and they typically require some level of human intervention and maintenance. Using behavioral analysis methods, it may be possible to observe and create a baseline of average behavior on a network, enabling intelligent notification of anomalous activity. This talk will demonstrate methods of performing this activity in different environments. Attendees will learn new methods which they can apply to further monitor and secure their networks
	* **DNS**
		* [Network Forensics with Windows DNS Analytical Logging](https://blogs.technet.microsoft.com/teamdhcp/2015/11/23/network-forensics-with-windows-dns-analytical-logging/)
	* **SMB**
		* [An Introduction to SMB for Network Security Analysts - 401trg](https://401trg.com/an-introduction-to-smb-for-network-security-analysts/)
	* **TLS**
		* [TLS client fingerprinting with Bro](https://www.securityartwork.es/2017/02/02/tls-client-fingerprinting-with-bro/)
		* [JA3 - A method for profiling SSL/TLS Clients](https://github.com/salesforce/ja3)
			* JA3 is a method for creating SSL/TLS client fingerprints that are easy to produce and can be easily shared for threat intelligence. 
			* [Talk/Presentation](https://www.youtube.com/watch?v=oprPu7UIEuk&feature=youtu.be)
				* In this talk we will show the benefits of SSL fingerprinting, JA3’s capabilities, and how best to utilize it in your detection and response operations. We will show how to utilize JA3 to find and detect SSL malware on your network. Imagine detecting every Meterpreter shell, regardless of C2 and without the need for SSL interception. We will also announce JA3S, JA3 for SSL server fingerprinting. Imagine detecting every Metasploit Multi Handler or [REDACTED] C2s on AWS. Then we’ll tie it all together, making you armed to the teeth for detecting all things SSL.
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
		* **101**
			* [Elasticsearch: The Definitive Guide The Definitive Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html)
		* **Reference**
		* **Articles/Writeups**
		* **Tools**
			* [ElastAlert](https://github.com/Yelp/elastalert)
				* ElastAlert is a simple framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch.
		* [dejavu](https://github.com/appbaseio/dejavu)
			* The Missing Web UI for Elasticsearch: Import, browse and edit data with rich filters and query views, create search UIs visually.
	* **Kibana**
		* **101**
			* [Kibana](https://github.com/elasticsearch/kibana)
				* Kibana is an open source (Apache Licensed), browser based analytics and search dashboard for Elasticsearch. Kibana is a snap to setup and start using. Kibana strives to be easy to get started with, while also being flexible and powerful, just like Elasticsearch.
			* [Introduction to Kibana](http://www.elasticsearch.org/guide/en/kibana/current/introduction.html)
		* **Reference**
			* [Kibana Documentation/Guides](http://www.elasticsearch.org/guide/en/kibana/current/)
			* [Installing Kibana](http://www.elasticsearch.org/overview/kibana/installation/)
		* **Articles/Writeups**
			* [Kibana 5 Introduction - timroe.de](https://www.timroes.de/2016/10/23/kibana5-introduction/)
	* **LogStash**
		* [LogStash](https://github.com/elasticsearch/logstash)
			* Logstash is a tool for managing events and logs. You can use it to collect logs, parse them, and store them for later use (like, for searching). If you store them in Elasticsearch, you can view and analyze them with Kibana. It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.
		* [Getting Started With Logstash](http://logstash.net/docs/1.4.2/tutorials/getting-started-with-logstash)
		* [Logstash Documentation](http://logstash.net/docs/1.4.2/)
		* [logstash anonymize](http://logstash.net/docs/1.4.2/filters/anonymize) * Anonymize fields using by replacing values with a consistent hash.
