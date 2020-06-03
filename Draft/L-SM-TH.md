# Logging(Host/Network) / Security Monitoring / Threat Hunting

--------------------
## Table of Contents
- [101](#101)
- [Logging](#logging)
	- [101](#101)
	- [Non-OS](#non-os)
	- [Linux](#linlog)
	- [macOS/OS X](#maclog)
	- [Windows](#winlog)
- [Monitoring](#monitor)
	- [101](#mon101)
	- [Breach Detection/Response](#brdp)
	- [Infrastructure Monitoring](#inframon)
	- [Network-based](#netmon)
		- [IDS/IPS](ips)
		- [IDS/IPS Monitoring tools](#ipsmon)
	- [Linux](#linmon)
	- [macOS/OS X](#macmon)
	- [Windows](#winmon)
- [Detection Engineeing](#detect)
- [Threat Hunting	](#th)
	- [101](#th101)
	- [Data Analysis](#data)
	- [In Memory](#inmem)
	- [Metrics](#thmetrics)
	- [OS Agnostic](#osag)
	- [Network-based](#thnet)
	- [Traffic Analysis](#traffic)
	- [Linux](#thlin)
	- [macOS](#thmac)
	- [Windows](#thwin)
	- [Simulation & Testing](#simulation)
- [Data Storage & Analysis](#stacks	)
	- [ELK](#elk)
	- [Graylog](#gray)
	- [Splunk](#splunk)


------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

### 101 <a name="101"></a>


------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

### Logging <a name="logging"></a>
* **101**<a name='101'></a>
	* **Articles/Writeups**
		* [Logs Are Streams, Not Files - Adam Wiggins](https://adam.herokuapp.com/past/2011/4/1/logs_are_streams_not_files/)
	* **Talks/Presentations/Videos**
* **General**
	* **Articles/Writeups**
		* [Log File Monitoring and Alerting - DHound](https://pentesting.dhound.io/blog/critical-security-logs)
	* **Talks/Presentations/Videos**
		* [Logging ALL THE THINGS Without All The Cost With Open Source Big Data Tools - DEFCON22 - Zach Fasel](https://www.youtube.com/watch?v=2AAnVeIwXBo)
			* Many struggle in their job with the decision of what events to log in battle against costly increases to their licensing of a commercial SIEM or other logging solution. Leveraging the open source solutions used for "big-data" that have been proven by many can help build a scalable, reliable, and hackable event logging and security intelligence system to address security and (*cringe*) compliance requirements. We’ll walk through the various components and simple steps to building your own logging environment that can extensively grow (or keep sized just right) with just additional hardware cost and show numerous examples you can implement as soon as you get back to work (or home).
* **Non-OS**<a name='non-os'></a>
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
	* **Slack**
		* [Slack API Auditor](https://github.com/maus-/slack-auditor)
			* Provides a quick method of collecting Slack access logs and integration logs, then forwards them via Logstash.
* **Linux**<a name='linlog'></a>
	* **101**
	* **Articles/Writeups**
	* **Understanding**
	* **Tools**
		* [Syslong-ng](https://github.com/balabit/syslog-ng) 
			* syslog-ng is an enhanced log daemon, supporting a wide range of input and output methods: syslog, unstructured text, message queues, databases (SQL and NoSQL alike) and more.
* **macOS/OS X**<a name='maclog'></a>
	* **101**
		* [How long does your Mac keep its log for? - hoakley(2020)](https://eclecticlight.co/2020/02/07/how-long-does-your-mac-keep-its-log-for/)
			* "macOS keeps around 52 tracev3 log files in /var/db/diagnostics/Persist, so the active log extends back as long as it has taken to write those"
		* [Capturing the moment in your log: how to identify a problem  - hoakley(2019)](https://eclecticlight.co/2019/09/17/capturing-the-moment-in-your-log-how-to-identify-a-problem/)
		* [Making your own logarchive from a backup - hoakley](https://eclecticlight.co/2020/02/07/making-your-own-logarchive-from-a-backup/)
	* **Tools**
		* [T2M2, Ulbow, Consolation and log utilities - hoakley](https://eclecticlight.co/consolation-t2m2-and-log-utilities/)
			* [Investigating a crash using Consolation 3 - hoakley(2019)](https://eclecticlight.co/2019/05/23/investigating-a-crash-using-consolation-3/)
		* [UnifiedLogReader](https://github.com/ydkhatri/UnifiedLogReader)
			* A parser for Unified logging tracev3 files
		* [OSXMon](https://github.com/AlfredoAbarca/OSXMon)
			* Small project demonstrating log collection using SUpraudit + splunk
		* [SUpraudit](http://newosxbook.com/tools/supraudit.html)
			* RE'd praudit rewrite by Jonathan Levin
	* **Understanding**
		* **Articles/Blogposts/Writeups**
			* [Starting up in Catalina: sequence and waypoints in the log - hoakley(2019)](https://eclecticlight.co/2019/11/06/starting-up-in-catalina-sequence-and-waypoints-in-the-log/)
			* [When did my Mac last start up, and why? An exploration with Ulbow - hoakley(2020)](https://eclecticlight.co/2020/01/02/when-did-my-mac-last-start-up-and-why-an-exploration-with-ulbow/)
			* [Mac shutdown and sleep cause codes - hoakley](https://eclecticlight.co/2017/02/28/mac-shutdown-and-sleep-cause-codes/)
			* [RunningBoard: a new subsystem in Catalina to detect errors - hoakley(2019)](https://eclecticlight.co/2019/11/07/runningboard-a-new-subsystem-in-catalina-to-detect-errors/)
			* [How RunningBoard tracks every app, and manages some - hoakley(2019)](https://eclecticlight.co/2019/11/09/how-runningboard-tracks-every-app-and-manages-some/)
			* [Introducing 'Analysis of Apple Unified Logs: Quarantine Edition' [Entry 0] - Sarah Edwards](https://www.mac4n6.com/blog/2020/4/19/introducing-analysis-of-apple-unified-logs-quarantine-edition-entry-0)
				* Check out the whole series.
	* **Unified Log**
		* **101**
			* [Logging(macOS) - developer.apple](https://developer.apple.com/documentation/os/logging)
		* **Articles/Blogposts/Writeups**
			* [macOS Unified log: 1 why, what and how - hoakley(2018)](https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how/)
			* [macOS Unified log: 2 content and extraction - hoakley](https://eclecticlight.co/2018/03/20/macos-unified-log-2-content-and-extraction/)
			* [macOS Unified log: 3 finding your way - hoakley](https://eclecticlight.co/2018/03/21/macos-unified-log-3-finding-your-way/)
			* [Inside Catalina’s unified log: how has it changed? - hoakley(2019)](https://eclecticlight.co/2019/10/16/inside-catalinas-unified-log-how-has-it-changed/)
			* [How to use the unified log to see what’s going wrong - hoakley(2018)](https://eclecticlight.co/2018/10/12/how-to-use-the-unified-log-to-see-whats-going-wrong/)
			* [Logs Unite! Forensic Analysis Of Apple Unified Logs - Sarah Edwards(2017)](https://papers.put.as/papers/macosx/2017/LogsUnite.pdf)
		* **Talks/Presentations/Videos**
			* [Unified Logging and Activity Tracing - AppleWWDC2018](https://developer.apple.com/videos/play/wwdc2016/721/)
				* The new Unified Logging and Tracing System for iOS and macOS uses Activity Tracing for performance, consolidates kernel and user-space logging, and has many other improvements. Learn how Logging and Tracing can help you debug and troubleshoot issues with your apps.
	* **Endpoint Security Framework**
		* **Articles/Blogposts/Writeups**
			* [Taking The macOS Endpoint Security Framework For A Quick Spin - Cedric Owens](https://medium.com/red-teaming-with-a-blue-team-mentaility/taking-the-macos-endpoint-security-framework-for-a-quick-spin-802a462dba06)
	* **OpenBSM**
		* **Articles/Blogposts/Writeups**
			* [Real-time auditing on macOS with OpenBSM: developing an application to monitor file system accesses and activities for every application - meliot(2017)](https://meliot.me/2017/07/02/mac-os-real-time-auditing/)
			* [Working with TrustedBSD in Mac OS X - Alexander Stavonin](https://sysdev.me/trusted-bsd-in-osx/)
			* [SunSHIELD Basic Security Module Guide - docs.oracle](https://docs.oracle.com/cd/E19457-01/801-6636/801-6636.pdf)
		* **Talks/Videos/Presentations**
			* [Getting Cozy With OpenBSM Auditing On MacOS - Patrick Wardle(Shmoocon2018)](https://www.youtube.com/watch?v=CqlpJ7rIT6M)
				* [Slides](https://objective-see.com/talks/Wardle_ShmooCon2018.pdf)
			* [Getting Cozy With OpenBSM Auditing On MacOS - Patrick Wardle](https://www.youtube.com/watch?v=CqlpJ7rIT6M)
				* With the demise of dtrace on macOS, and Apple’s push to rid the kernel of 3rd-party kexts, another option is needed to perform effective auditing on macOS. Lucky for us, OpenBSM fits the bill. Though quite powerful, this auditing mechanism is rather poorly documented and suffered from a variety of kernel vulnerabilities. In this talk, we’ll begin with an introductory overview of OpenBSM’s goals, capabilities, and components before going ‘behind-the-scenes’ to take a closer look at it’s kernel-mode implementation. Armed with this understanding, we’ll then detail exactly how to build powerful user-mode macOS monitoring utilities such as file, process, and networking monitors based on the OpenBSM framework and APIs. Next we’ll don our hacker hats and discuss a handful of kernel bugs discovered during a previous audit of the audit subsystem (yes, quite meta): a subtle off-by-one read error, a blotched patch that turned the off-by-one into a kernel info leak, and finally an exploitable heap overflow. Though now patched, the discussion of these bugs provides an interesting ‘case-study’ of finding and exploiting several types of bugs that lurked within the macOS kernel for many years
	* **Process Creation**
		* [Monitoring Process Creation via the Kernel (Part I) - Patrick Wardle(2015)](https://objective-see.com/blog.html#blogEntry9)
		* [Monitoring Process Creation via the Kernel (Part II) - Patrick Wardle(2015)](https://objective-see.com/blog/blog_0x0A.html)
* **Windows**<a name="winlog"></a>
	* **101**
		* [Windows 10, version 1809 basic level Windows diagnostic events and fields](https://docs.microsoft.com/en-gb/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1809#windows-error-reporting-events)
		* [Windows Logging Basics - loggly](https://www.loggly.com/ultimate-guide/windows-logging-basics/)
	* **General Articles/Overview aka How to use Event Viewer**
		* * [Windows Logging Basics - loggly](https://web.archive.org/web/20200520162154/https://www.loggly.com/ultimate-guide/windows-logging-basics/)
	* **Auditing/Audit Events**
		* [Windows 10 and Windows Server 2016 security auditing and monitoring reference - microsoft.com](https://www.microsoft.com/en-us/download/details.aspx?id=52630)
			* This reference details most advanced security audit events for Windows 10 and Windows Server 2016. 
		* [ Windows security audit events - ms.com](https://www.microsoft.com/en-us/download/details.aspx?id=50034)
			*  This spreadsheet details the security audit events for Windows. 
	* **Cheat Sheets**
		* [Windows logging Cheat sheet - Malware Archaelogy](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/580595db9f745688bc7477f6/1476761074992/Windows+Logging+Cheat+Sheet_ver_Oct_2016.pdf)
		* [Windows Splunk Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a3187b4419202f0fb8b2dd1/1513195444728/Windows+Splunk+Logging+Cheat+Sheet+v2.2.pdf)
		* [Windows Registry Auditing Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a00963153450a8779b23489/1509987890282/Windows+Registry+Auditing+Cheat+Sheet+ver+Nov+2017.pdf)
		* [Windows PowerShell Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
		* [Windows File Auditing Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a0097e5f9619a8960daef69/1509988326168/Windows+File+Auditing+Cheat+Sheet+ver+Nov+2017.pdf)
	* **Command Line Auditing**
		* [Command line process auditing - docs.ms(2017)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
		* [Microsoft security advisory: Update to improve Windows command-line auditing: February 10, 2015](https://support.microsoft.com/en-us/help/3004375/microsoft-security-advisory-update-to-improve-windows-command-line-aud)
		* [Audit Process Creation - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn319093(v=ws.11)\)
			* Prior to Win10
		* [Command line process auditing - docs.ms(2017)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
			* 'Applies To: Windows Server 2016, Windows Server 2012 R2'
		* [Invoke-DOSfuscation: Techniques FOR %F IN (-style) DO (S-level CMD Obfuscation) - Daniel Bohannon(BHAsia2018)](https://www.youtube.com/watch?v=mej5L9PE1fs)
			* "In this presentation, I will dive deep into cmd[.]exe's multi-faceted obfuscation opportunities beginning with carets, quotes and stdin argument hiding. Next I will extrapolate more complex techniques including FIN7's string removal/replacement concept and two never-before-seen obfuscation and full encoding techniques – all performed entirely in memory by cmd[.]exe. Finally, I will outline three approaches for obfuscating binary names from static and dynamic analysis while highlighting lesser-known cmd[.]exe replacement binaries."
	* **Event Collector**
		* [Windows event Collector - Setting up source initiated Subscriptions](https://msdn.microsoft.com/en-us/library/bb870973(v=vs.85).aspx)
		* [Windows Event Collector(For centralizing windows domain logging with no local agent, windows actually has built-in logging freely available)](https://msdn.microsoft.com/en-us/library/bb427443(v=vs.85).aspx)
	* **Event Forwarding**
		* **101**
			* [Introduction to Windows Event Forwarding](https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4)
			* [Windows Event Collector - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wec/windows-event-collector)
			* [Using Windows Event Collector - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wec/using-windows-event-collector)
				* This section lists the topics that explain the tasks that can be accomplished using the Windows Event Collector SDK.
			* [Windows Event Forwarding - Centralized logging for everyone! (Even if you already have centralized logging!) - Jessica Payne(2015)](https://web.archive.org/web/20171212201838/https://channel9.msdn.com/Events/Ignite/Australia-2015/INF327)
			* [Use Windows Event Forwarding to help with intrusion detection - docs.ms(2019)](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
				* Learn about an approach to collect events from devices in your organization. This article talks about events in both normal operations and when an intrusion is suspected.
			* [Creating Custom Windows Event Forwarding Logs - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/russellt/creating-custom-windows-event-forwarding-logs)
			* [Use Windows Event Forwarding to help with intrusion detection](https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection)
			* [Monitoring what matters – Windows Event Forwarding for everyone (even if you already have a SIEM.) - docs.ms(2015)](https://web.archive.org/web/20200402150250/https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem)
		* **Articles/Writeups**
			* [Windows Event Logging and Forwarding - Australian Cybersecurity Center](https://www.cyber.gov.au/publications/windows-event-logging-and-forwarding)
				* This document has been developed as a guide to the setup and configuration of Windows event logging and forwarding. This advice has been developed to support both the detection and investigation of malicious activity by providing an ideal balance between the collection of important events and management of data volumes. This advice is also designed to complement existing host-based intrusion detection and prevention systems.  This document is intended for information technology and information security professionals. It covers the types of events which can be generated and an assessment of their relative value, centralised collection of event logs, the retention of event logs, and recommended Group Policy settings along with implementation notes.
				* [Paper - 2019](https://web.archive.org/web/20200507235341/https://www.cyber.gov.au/sites/default/files/2019-05/PROTECT%20-%20Windows%20Event%20Logging%20and%20Forwarding%20%28April%202019%29_0.pdf)
				* [Australian Cyber Security Center's Windows Event Logging repository](https://github.com/AustralianCyberSecurityCentre/windows_event_logging)
			* [Windows Event Forwarding Guidance - Palantir](https://github.com/palantir/windows-event-forwarding) 
				* Over the past few years, Palantir has a maintained an internal Windows Event Forwarding (WEF) pipeline for generating and centrally collecting logs of forensic and security value from Microsoft Windows hosts. Once these events are collected and indexed, alerting and detection strategies (ADS) can be constructed not only on high-fidelity security events (e.g. log deletion), but also for deviations from normalcy, such as unusual service account access, access to sensitive filesystem or registry locations, or installation of malware persistence. The goal of this project is to provide the necessary building blocks for organizations to rapidly evaluate and deploy WEF to a production environment, and centralize public efforts to improve WEF subscriptions and encourage adoption. While WEF has become more popular in recent years, it is still dramatically underrepresented in the community, and it is our hope that this project may encourage others to adopt it for incident detection and response purposes. We acknowledge the efforts that Microsoft, IAD, and other contributors have made to this space and wish to thank them for providing many of the subscriptions, ideas, and techniques that will be covered in this post.
			* [Event-Forwarding-Guidance - NSA](https://github.com/nsacyber/Event-Forwarding-Guidance)
				* Configuration guidance for implementing collection of security relevant Windows Event Log events by using Windows Event Forwarding.				
			* [Windows Event Forwarding for Network Defense - Palantir](https://medium.com/palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)
			* [End-Point Log Consolidation with Windows Event Forwarder - Derek Banks(2017)](https://www.blackhillsinfosec.com/end-point-log-consolidation-windows-event-forwarder/)
			* [The Windows Event Forwarding Survival Guide - Chris Long(2017)](https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4)
			* [Setting up Windows Event Forwarder Server (WEF) (Domain) Part 1/3 - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-part-13/)
				* [Setting up Windows Event Forwarder Server (WEF) (Domain) – Sysmon Part 2/3 - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-sysmon-part-23/)
				* [Setting up Windows Event Forwarder Server (WEF) (Domain) – GPO Deployment Part 3/3 - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-gpo-deployment-part-33/)
		* **Custom Logs**
			* [Introducing Project Sauron - Centralised Storage of Windows Events - Domain Controller Edition - docs.ms(2017)](https://docs.microsoft.com/en-us/archive/blogs/russellt/project-sauron-introduction)
				* [Code](https://github.com/russelltomkins/project-sauron)
			* [Creating Custom Windows Event Forwarding Logs - docs.ms(2016)](https://web.archive.org/web/20200508010912/https://docs.microsoft.com/en-us/archive/blogs/russellt/creating-custom-windows-event-forwarding-logs)
		* **Filtering/XPath**
			* [XPath - Wikipedia](https://en.wikipedia.org/wiki/XPath)
			* [XPath Standard Documentation](https://www.w3.org/TR/xpath/all/)
			* [Advanced XML filtering in the Windows Event Viewer - Ned Pyle(2011)](https://web.archive.org/web/20190712091207/https://blogs.technet.microsoft.com/askds/2011/09/26/advanced-xml-filtering-in-the-windows-event-viewer/)
			* [Consuming Events - docs.ms(2015)](https://docs.microsoft.com/en-us/windows/win32/wes/consuming-events?redirectedfrom=MSDN#limitations)
		* **Tools**
			* [WEFFLES](https://github.com/jepayneMSFT/WEFFLES)
				* Build a fast, free, and effective Threat Hunting/Incident Response Console with Windows Event Forwarding and PowerBI 
				* [Blogpost](https://web.archive.org/web/20200308233607/https://blogs.technet.microsoft.com/jepayne/2017/12/08/weffles/)
	* **Event Log**
		* **101**
			* [Windows Event Log Reference - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log-reference?redirectedfrom=MSDN)
			* [Event Logging Structures - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/eventlog/event-logging-structures)
			* [Log Everything Right? - Edward Ruprecht](https://medium.com/@e_rupert/log-everything-right-13d86224ef7f)
		* **Reference for Logs**
			* [My Event Log](https://www.myeventlog.com)
				* Searchable database of Windows Event log entries.
			* [Windows Event Log Encyclopedia - ultimatewindowsecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
		* **Articles/Writeups**
			* [Get-EventLog shows wrong maximum size of event logs - Przemyslaw Klys(2018)](https://evotec.xyz/get-eventlog-shows-wrong-maximum-size-of-event-logs/)
			* [Use Windows Event Forwarding to help with intrusion detection - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
			* [Windows Event Log Zero 2 Hero Slides](https://docs.google.com/presentation/d/1dkrldTTlN3La-OjWtkWJBb4hVk6vfsSMBFBERs6R8zA/edit#slide=id.g21acf94f3f_2_27)
			* [Advanced Audit Policy – which GPO corresponds with which Event ID - girl-germs.com](https://girl-germs.com/?p=363)
			* [Windows Event Logging for Insider Threat Detection  - Derrick Spooner(2019)](https://insights.sei.cmu.edu/insider-threat/2019/05/windows-event-logging-for-insider-threat-detection.html)
			* [JPCert Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
				* This site summarizes the results of examining logs recorded in Windows upon execution of the 49 tools which are likely to be used by the attacker that has infiltrated a network. The following logs were examined. Note that it was confirmed that traces of tool execution is most likely to be left in event logs. Accordingly, examination of event logs is the main focus here. 
		* **Understanding**
			* [EVTX and Windows Event Logging - Brandon Charter(2008)](https://www.sans.org/reading-room/whitepapers/logging/paper/32949)
				* This paper will explore Microsoft’s EVTX log format and Windows Event Logging framework. 
			* [Event Log File Format - docs.ms](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
			* [[MS-EVEN6]: EventLog Remoting Protocol Version 6.0 - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/18000371-ae6d-45f7-95f3-249cbe2be39b?redirectedfrom=MSDN)
		* **Talks/Presentations/Videos**
		* **Tools**
			* [EventLogParser](https://github.com/djhohnstein/EventLogParser)
				* Parse PowerShell and Security event logs for sensitive information.
			* [libevtx](https://github.com/libyal/libevtx)
				* Library and tools to access the Windows XML Event Log (EVTX) format
			* [python-evtx](https://github.com/williballenthin/python-evtx)
				* python-evtx is a pure Python parser for recent Windows Event Log files (those with the file extension ".evtx"). The module provides programmatic access to the File and Chunk headers, record templates, and event entries.
	* **Event Tracing for Windows**<a name="etw"></a>
		* **101**
			* [Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
			* [About Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
			* [Using Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/using-event-tracing)
			* [Event Tracing for Windows - Core OS Events in Windows 7, Part 1 - Dr. Insung Park, Alex Bendetovers](https://docs.microsoft.com/en-us/archive/msdn-magazine/2009/september/core-os-events-in-windows-7-part-1)
				* [Part 2](https://docs.microsoft.com/en-us/archive/msdn-magazine/2009/october/core-instrumentation-events-in-windows-7-part-2)
		* **Articles/Blogposts/Writeups**
			* [ETW Event Tracing for Windows and ETL Files - Nicole Ibrahim](https://www.hecfblog.com/2018/06/etw-event-tracing-for-windows-and-etl.html)
			* [SilkETW: Because Free Telemetry is … Free! - Ruben Boonnen](https://www.fireeye.com/blog/threat-research/2019/03/silketw-because-free-telemetry-is-free.html)
				* [Slides](https://github.com/FuzzySecurity/BH-Arsenal-2019/blob/master/Ruben%20Boonen%20-%20BHArsenal_SilkETW_v0.2.pdf)
			* [Tampering with Windows Event Tracing: Background, Offense, and Defense - Palantir](https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
			* [Getting started with Event Tracing for Windows in C# - Alex Khanin](https://medium.com/@alexkhanin/getting-started-with-event-tracing-for-windows-in-c-8d866e8ab5f2)
			* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
				* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it-s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What-s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."
		* **Talks/Videos**
			* [Production tracing with Event Tracing for Windows (ETW) - Doug Cook](https://channel9.msdn.com/Events/Build/2017/P4099)
			* [ETW - Monitor Anything, Anytime, Anywhere - Dina Goldshtein(NDC Oslo 2017)](https://www.youtube.com/watch?v=ZNdpLM4uIpw)
				* You’ll learn how to diagnose incredibly complex issues in production systems such as excessive garbage collection pauses, slow startup due to JIT and disk accesses, and even sluggishness during the Windows boot process. We will also explore some ways to automate ETW collection and analysis to build self-diagnosing applications that identify high CPU issues, resource leaks, and concurrency problems and produce alerts and reports. In the course of the talk we will use innovative performance tools that haven’t been applied to ETW before — flame graphs for visualising call stacks and a command-line interface for dynamic, scriptable ETW tracing. ETW is truly a window into everything happening on your system, and it doesn’t require expensive licenses, invasive tools, or modifying your code in any way. It is a critical, first-stop skill on your way to mastering application performance and diagnostics.
			* [Windows Forensics: Event Trace Logs - Nicole Ibrahim(SANS DFIR Summit 2018)](https://www.youtube.com/watch?v=TUR-L9AtzQE)
				* This talk will cover what ETL files are and where you can expect to find them, how to decode ETL files, caveats associated with those files, and some interesting and forensically relevant data that ETL files can provide. 
		* **Tools**
			* [SilkETW & SilkService](https://github.com/fireeye/SilkETW)
				* SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection. While both projects have obvious defensive (and offensive) applications they should primarily be considered as research tools. For easy consumption, output data is serialized to JSON. The JSON data can either be written to file and analyzed locally using PowerShell, stored in the Windows eventlog or shipped off to 3rd party infrastructure such as Elasticsearch.
	* **Logon Events**
		* [Audit logon events - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)
			* Win10
	* **Parsing**
		* [Parsing Text Logs with Message Analyzer - Microsoft](http://blogs.technet.com/b/messageanalyzer/archive/2015/02/23/parsing-text-logs-with-message-analyzer.aspx)
	* **PowerShell**
		* **101**
			* [PowerShell ♥ the Blue Team - PowerShell Team(2015)](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)
			* [About Group Policy Settings - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-7)
				* Describes the Group Policy settings for Windows PowerShell
			* [Windows PowerShell Logging CheatSheet - Malware Archaeology](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
		* **Articles/Blogposts/Writeups**
			* [Greater Visibility Through PowerShell Logging](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
			* [Practical PowerShell Security: Enable Auditing and Logging with DSC - Ashley McGlone](https://blogs.technet.microsoft.com/ashleymcglone/2017/03/29/practical-powershell-security-enable-auditing-and-logging-with-dsc/)
			* [Everything You Need To Know To Get Started Logging PowerShell - robwillisinfo(2019)](http://robwillis.info/2019/10/everything-you-need-to-know-to-get-started-logging-powershell/)
		* **Event Log**
			* [About Eventlogs - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs?view=powershell-5.1&viewFallbackFrom=powershell-7)
				* Windows PowerShell creates a Windows event log that is named "Windows PowerShell" to record Windows PowerShell events. You can view this log in Event Viewer or by using cmdlets that get events, such as the Get-EventLog cmdlet. By default, Windows PowerShell engine and provider events are recorded in the event log, but you can use the event log preference variables to customize the event log. For example, you can add events about Windows PowerShell commands.			
			* [PowerShell – Everything you wanted to know about Event Logs and then some - Przemyslaw Klys(2019)](https://evotec.xyz/powershell-everything-you-wanted-to-know-about-event-logs/)
		* **Script Block Logging**
		* **Transcript Logging**
			* [PowerShell: Documenting your work with Start-Transcript - Patrick Gruenauer](https://sid-500.com/2017/07/15/powershell-documenting-your-work-with-start-transcript/)
			* [PowerShell Security: Enabling Transcription Logging by using Group Policy - Patrick Gruenauer](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
		* **Talks/Presentations/Videos**
			* [When Logging Everything Becomes an Issue - Edward Ruprecht(WWHF19)](https://www.youtube.com/watch?v=g-1l9ZPhc2A)
				* [Slides](https://docs.google.com/presentation/d/12rMlIRE3136TlRnbhs65V-rqZTo_u-T7raEwUu2P2L4/edit#slide=id.p1)
				* Discussing potential issues with logging Sysmon and PowerShell logs. Potential sensitive data leakage, best practices, and scalability issues.
			* [Invoke-Obfuscation: PowerShell obFUsk8tion - Daniel Bohannon(Hactivity2016)](https://www.youtube.com/watch?v=uE8IAxM_BhE)
				* "Today’s detection techniques monitor for certain strings in powershell.exe’s command-line arguments. While this provides tremendous value for most of today’s PowerShell attacks, I will introduce over a dozen obfuscation techniques that render today’s detection techniques grossly ineffective. These techniques will enable the innovative Red Team to continue using PowerShell undetected while challenging the Blue Team to identify these attacks more effectively. Finally, I will unveil Invoke-Obfuscation.ps1 which will enable both Red and Blue Teams to effortlessly create highly obfuscated PowerShell commands so organizations can test their detection capabilities against these obfuscation techniques."
			* [Revoke-Obfuscation: PowerShell Obfuscation Detection (And Evasion) Using Science - Daniel Bohannon(BHUSA2017)](https://www.youtube.com/watch?v=x97ejtv56xw&list=TLPQMjAwNTIwMjBVJ_NawM9s8A&index=2)
				* Attackers, administrators and many legitimate products rely on PowerShell for their core functionality. However, being a Windows-signed binary native on Windows 7 and later that enables reflective injection of binaries and DLLs and memory-resident execution of remotely hosted scripts, has made it increasingly attractive for attackers and commodity malware authors alike. In environments where PowerShell is heavily used, filtering out legitimate activity to detect malicious PowerShell usage is not trivial.
			* [Malicious payloads vs. deep visibility: a PowerShell story - Daniel Bohannon(PSConEU2019)](https://www.youtube.com/watch?v=h1Sbb-1wRKw)
				* "This talk draws from over four years of Incident Response experience to lay out a technical buffet of in-the-wild malicious PowerShell payloads and techniques. In addition to diving deep into the mechanics of each malicious example, this presentation will highlight forensic artifacts, detection approaches and the deep visibility that the latest versions of PowerShell provides security practitioners to defend their organizations against the latest attacks that utilize PowerShell. So if you are new to security or just want to learn about how attackers have used PowerShell in their attacks, then this talk is for you. If you want to see what obfuscated and multi-stage, evasive PowerShell-based attacks look like under the microscope of PowerShell deep inspection capabilities, this talk is for you. And if you want to see why these security advancements to PowerShell are causing many attackers to shift their tradecraft development away from PowerShell, this talk is for you."
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
			* [EventList](https://github.com/miriamxyra/EventList)
				* EventList is a tool to help improving your Audit capabilities and to help to build your Security Operation Center. It helps you combining Microsoft Security Baselines with MITRE ATT&CK and generating hunting queries for your SIEM system - regardless of the product used.
			* [GENE: Go Evtx sigNature Engine](https://github.com/0xrawsec/gene)
				* The idea behind this project is to provide an efficient and standard way to look into Windows Event Logs (a.k.a EVTX files). For those who are familiar with Yara, it can be seen as a Yara engine but to look for information into Windows Events.
	* **WMI**
		* [WMI-IDS](https://github.com/fireeye/flare-wmi/tree/master/WMI-IDS)
			* WMI-IDS is a proof-of-concept agent-less host intrusion detection system designed to showcase the unique ability of WMI to respond to and react to operating system events in real-time.

























------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

### Monitoring <a name="monitor"></a>
* **101**<a name="mon101"></a>
	* **Articles/Blogposts/Writeups**
		* [Crown Jewels: Monitoring vs Mitigating - Pen Consultants](https://penconsultants.com/home/crown-jewels-monitoring-vs-mitigating/)
		* [Introducing the Funnel of Fidelity - Jared Atkinson(2019)](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036)
			* [...]As a result, I created a model to describe the conceptual process that organizations follow to quantify the high level roles and responsibilities of a detection and response program. As events pass through the model the depth of event analysis and fidelity is increased. For this reason I call the model the Funnel of Fidelity (following the naming convention of David Bianco’s Pyramid of Pain).
	* **Talks/Presentations/Videos**
* **Breach Detection/Response**<a name="brdp"></a>
	* **Articles/Blogposts/Presentations/Talks/Writeups**
		* [The fox is in the Henhouse - Detecting a breach before the damage is done](http://www.irongeek.com/i.php?page=videos/houseccon2015/t302-the-fox-is-in-the-henhouse-detecting-a-breach-before-the-damage-is-done-josh-sokol)
	* **Tools**
		* [Infection Monkey](https://github.com/guardicore/monkey)
			* The Infection Monkey is an open source security tool for testing a data center's resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Command and Control(C&C) server.
		* [411](https://github.com/kiwiz/411)
			* Configure Searches to periodically run against a variety of data sources. You can define a custom pipeline of Filters to manipulate any generated Alerts and forward them to multiple Targets.
		* [Pattern](https://github.com/clips/pattern/blob/master/README.md)
			* Pattern is a web mining module for Python. It has tools for: Data Mining: web services (Google,; Twitter, Wikipedia), web crawler, HTML DOM parser; Natural Language Processing: part-of-speech taggers, n-gram search, sentiment analysis, WordNet; Machine Learning: vector space model, clustering, classification (KNN, SVM, Perceptron); Network Analysis: graph centrality and visualization.
* **Infrastructure Monitoring**<a name="inframon"></a>
	* [Ninja Level Infrastructure Monitoring Workshop - Defcon24](https://github.com/appsecco/defcon24-infra-monitoring-workshop)
		* This repository contains all the presentation, documentation and the configuration, sample logs, ansible playbook, customized dashboards and more.
* **Network-based**<a name="netmon"></a>
	* **101**
	* **Articles/Writeups**
	* **Talks/Presentations**
		* [Passive IPS Reconnaissance and Enumeration - false positive (ab)use - Arron Finnon](https://vimeo.com/108775823)
			* Network Intrusion Prevention Systems or NIPS have been plagued by "False Positive" issues almost since their first deployment. A "False Positive" could simply be described as incorrectly or mistakenly detecting a threat that is not real. A large amount of research has gone into using "False Positive" as an attack vector either to attack the very validity of an IPS system or to conduct forms of Denial of Service attacks. However the very reaction to a "False Positive" in the first place may very well reveal more detailed information about defences than you might well think.
		* [You Pass Butter: Next Level Security Monitoring Through Proactivity](http://www.irongeek.com/i.php?page=videos/nolacon2016/110-you-pass-butter-next-level-security-monitoring-through-proactivity-cry0-s0ups)
	* **Understanding**
	* **Sigma**
		* [Sigma](https://github.com/Neo23x0/sigma)
			* Sigma is a generic and open signature format that allows you to describe relevant log events in a straight forward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.	Sigma is for log files what Snort is for network traffic and YARA is for files.
		* [Sigma Specification](https://github.com/Neo23x0/sigma/wiki/Specification)
		* [How to Write Sigma Rules - Florian Roth](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/)
		* [Sigma - Generic Signatures for Log Events - Thomas Patzke(Hack.lu2017)](https://www.youtube.com/watch?v=OheVuE9Ifhs)
			* Log files are a great resource for hunting threats and analysis of incidents. Unfortunately, there is no standardized signature format like YARA for files or Snort signatures for network traffic. This makes sharing of log signatures by security researchers and software developers problematic. Further, most SIEM systems have their own query language, which makes signature distribution in large heterogeneous environments inefficient and increases costs for replacement of SIEM solutions.Sigma tries to fill these gaps by providing a YAML-based format for log signatures, an open repository of signatures and an extensible tool that converts Sigma signatures into different query languages. Rules and tools were released as open source and are actively developed. This presentation gives an overview about use cases, Sigma rules and the conversion tool, the development community and future plans of the project.
		* [MITRE ATT&CK and Sigma Alerting - Justin Henderson, John Hubbard(2019)](https://www.sans.org/webcasts/mitre-att-ck-sigma-alerting-110010)
			* This webcast will introduce the Sigma Alert project and show examples of creating alert rules against MITRE ATT&CK framework items to discover attacks in a way that works for multiple products. Sigma allows for writing rules in a neutral rule format that supports converting the rule to support your product of choice.
	* **IDS/IPS Tools**<a name="ips"></a>
		* **Snort**
			* [Snort](https://www.snort.org/)
				* A free lightweight network intrusion detection system for UNIX and Windows.
			* [Snort FAQ](https://www.snort.org/faq)
			* [Snort User Manual](http://manual.snort.org/)
			* [Snort Documentation](https://www.snort.org/documents)
		* **Bro/Zeek**
			* **101**
				* [Zeek](https://zeek.org/)
					* Zeek is an open source software platform that provides compact, high-fidelity transaction logs, file content, and fully customized output to analysts, from the smallest home office to the largest, fastest research and commercial networks.
				* [Zeek Quick Start Guide](https://docs.zeek.org/en/current/quickstart/index.html)
				* [Zeek Documentation](https://docs.zeek.org/en/master/)
				* [Try Zeek in your browser!](https://try.zeek.org/#/?example=hello)
				* [Writing Zeek Scripts](https://docs.zeek.org/en/current/examples/scripting/)
			* **Articles/Blogposts**
				* [Simplifying Bro IDS Log Parsing with ParseBroLogs - Dan Gunter](https://dgunter.com/2018/01/25/simplifying-bro-ids-log-parsing-with-parsebrologs/)
			* **Tools**
				* [bro-intel-generator](https://github.com/exp0se/bro-intel-generator)
					* Script for generating Bro intel files from pdf or html reports
				* [bro-domain-generation](https://github.com/denji/bro-domain-generation)
					* Detect domain generation algorithms (DGA) with Bro. The module will regularly generate domains by any implemented algorithms and watch for those domains in DNS queries. This script only works with Bro 2.1+.
				* [Exfil Framework](https://github.com/reservoirlabs/bro-scripts/tree/master/exfil-detection-framework)
					* The Exfil Framework is a suite of Bro scripts that detect file uploads in TCP connections. The Exfil Framework can detect file uploads in most TCP sessions including sessions that have encrypted payloads (SCP,SFTP,HTTPS).
				* [brim](https://github.com/brimsec/brim)
					* Desktop application to efficiently search large packet captures and Zeek logs.
		* **Suricata**
			* [Suricata](https://suricata-ids.org/)
				* Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. Open Source and owned by a community run non-profit foundation, the Open Information Security Foundation (OISF).
			* [Suricata Documentation](https://redmine.openinfosecfoundation.org/projects/suricata/wiki)
				* [Suricata Quick Start Guide](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Quick_Start_Guide)
				* [Suricata Installation Guides for various platforms](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation)
				* [Setting up Suricata on a Microtik Router](http://robert.penz.name/849/howto-setup-a-mikrotik-routeros-with-suricata-as-ids/)
		* **Snort**
		* **Argus**
			* [Argus](http://qosient.com/argus/#)
				* Argus is an open source layer 2+ auditing tool (including IP audit) written by Carter Bullard which has been under development for over 10 years.
			* [Argus on NSM Wiki](https://www.nsmwiki.org/index.php?title=Argus)
			* [Argus FAQ](http://qosient.com/argus/faq.shtml)
			* [Argus How-To](http://qosient.com/argus/howto.shtml)
			* [Argus Manual](http://qosient.com/argus/manuals.shtml)
		* **Other**
			* [Maltrail](https://github.com/stamparm/maltrail)
				* Maltrail is a malicious traffic detection system, utilizing publicly available (black)lists containing malicious and/or generally suspicious trails, along with static trails compiled from various AV reports and custom user defined lists, where trail can be anything from domain name (e.g. zvpprsensinaix.com for Banjori malware), URL (e.g. `http://109.162.38.120/harsh02.exe` for known malicious executable), IP address (e.g. 185.130.5.231 for known attacker) or HTTP User-Agent header value (e.g. sqlmap for automatic SQL injection and database takeover tool). Also, it uses (optional) advanced heuristic mechanisms that can help in discovery of unknown threats (e.g. new malware).
	* **IDS/IPS Monitoring Tools**<a name="ipsmon"></a>
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
	* **General Tools**<a name="gentoolmon"></a>
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
* **OSQuery**
	* **101**
		* [osquery](https://github.com/osquery/osquery)
			* osquery is a SQL powered operating system instrumentation, monitoring, and analytics framework. Available for Linux, macOS, Windows, and FreeBSD. 
		* [Table Schema v4.3](https://osquery.io/schema/4.3.0/)
		* [Getting Started Documentation](https://osquery.readthedocs.io/en/latest/)
		* [Optimizing Queries in OSQuery - Dennis Griffin(2018)](https://osquery.io/blog/optimizing-queries-in-osquery)
	* **Articles/Blogposts/Writeups**
		* [osquery Across the Enterprise - Chris L(Palantir 2017)](https://medium.com/palantir/osquery-across-the-enterprise-3c3c9d13ec55)
		* [Palantir osquery Configuration](https://github.com/palantir/osquery-configuration)
			The goal of this project is to provide a baseline template for any organization considering a deployment of osquery in a production environment. 
		* [Blue Team Diary, Entry #1: Leveraging Osquery For Enhanced Incident Response & Threat Hunting - Dimitrios Bougioukas(2019)](https://medium.com/@d.bougioukas/blue-team-diary-entry-1-leveraging-osquery-for-enhanced-incident-response-threat-hunting-70935538c9c3)
	* **Talks/Presentations/Videos**
		* [Leveraging Osquery For Enhanced Incident Response & Threat Hunting - Dimitrios Bougioukas(2019)](https://www.youtube.com/watch?v=E6vJGEXCaLM)
			* This video accompanies eLearnSecurity's [Blue Team Diary, Entry #1: Leveraging Osquery For Enhanced Incident Response & Threat Hunting](https://medium.com/@d.bougioukas/blue-team-diary-entry-1-leveraging-osquery-for-enhanced-incident-response-threat-hunting-70935538c9c3) post on medium.
		* [Osquery across compliance, monitoring, risk and threat hunting - Hugh Neale(QueryCon2019)](https://www.youtube.com/watch?v=zQFXLm-SweY)
			* Stories, use cases and lessons learnt from the front line: Hugh will demonstrate how powerful osquery is across compliance, monitoring, risk IAM and threat hunting. The goal is to help build a complete picture of your IT estate and security posture. This talk is aimed at IT and Security operations. Zercurity has been using osquery in production workloads from startups to listed companies. They use osquery for inventory management, monitoring, compliance, risk, vulnerability management and IAM to name a few. Hugh will share some of their takeaways over the last few years and tell you about some of the things you can build atop osquery.
			* [Slides](https://docs.google.com/presentation/d/1lEAIa5CwUHh7CvKl7Q8plmFwNKPBQDfFfMWtZNlGBuo/edit#slide=id.g5b5f9e628d_0_42)
		* [Monitoring Ephemeral Infrastructure with osquery - Matt Jane(Querycon219)](https://www.youtube.com/watch?v=03tCsq-vDbA)
			* Modern infrastructure and deployment methods, as well as web-scale infrastructure have brought about a new paradigm in infrastructure management. Short lived and ephemeral resources allow applications to scale up and down on demand. Unfortunately this means that one of the primary information gather methods of osquery, scheduled queries, becomes far less useful if queries are scheduled for a longer interval than the infrastructure will exist. This doesn’t mean osquery and scheduled queries are no longer useful, far from it. It simply means that we need to adjust our way of thinking a bit and adapt our methods of information gathering to overcome these new issues.
			* [Slides](https://github.com/securityclippy/QueryCon/blob/master/monitoring_ephemeral_infrastructure_with_osquery.pdf)
		* [Linux security event monitoring with osquery - Alessandro Gario(Querycon2019)](https://www.youtube.com/watch?v=t5weGeLvhBY)
			* This talk introduces security event monitoring on Linux, and our lessons learned from attempts to implement it within osquery. Our first experience with osquery event monitoring was rewriting its use of Auditd. In order to capture events within containers, we next implemented an event publisher based on eBPF. We discovered what works, what doesn’t, and some paths forward.
		* [How osquery uses sqlite3 and rocksdb - Alex Malone(Querycon2019)](https://www.youtube.com/watch?v=Epl3k3mAfEM)
			* We will walk through a query from SQL to the logged JSON results, noting the important interactions with sqlite3 and rocksdb. For example, the processes table specifies an INDEX on pid. What does that entail, and how does it impact how the table generate() function is called? In this talk, listeners will gain insight into the sqlite3 virtual table API.
	* **Tooling**
		* Fleet Managers
			* [Fleet](https://github.com/kolide/fleet)
				* Fleet is the most widely used open-source osquery Fleet manager. Deploying osquery with Fleet enables live queries, and effective management of osquery infrastructure.
			* [Doorman](https://github.com/mwielgoszewski/doorman)
				* Doorman is an osquery fleet manager that allows administrators to remotely manage the osquery configurations retrieved by nodes. Administrators can dynamically configure the set of packs, queries, and/or file integrity monitoring target paths using tags. Doorman takes advantage of osquery's TLS configuration, logger, and distributed read/write endpoints, to give administrators visibility across a fleet of devices with minimal overhead and intrusiveness.
		* Plugins/Extensions
			* [osquery-go](https://github.com/kolide/osquery-go)
				* This project contains Go bindings for creating osquery extensions in Go.
			* [osquery-python](https://github.com/osquery/osquery-python)
				* This project contains the official Python bindings for creating osquery extensions in Python.
			* [brosquery](https://github.com/jandre/brosquery)
				* This project builds an OSQuery module libbro.so for loading bro logs as tables in osquery.
			* [osquery extensions by Trail of Bits](https://github.com/trailofbits/osquery-extensions)
				* This repository includes osquery extensions developed and maintained by Trail of Bits.
* **Linux**<a name="linmon"></a>
	* **101**
	* **Articles/Writeups**
		* [Different Approaches to Linux Monitoring - Kelly Shortridge](https://capsule8.com/blog/different-approaches-to-linux-monitoring/)
	* **Understanding**
	* **Tools**
* **macOS/OS X**<a name='macmon'></a>
	* **101**
	* **Articles/Writeups**
		* [Monitoring macOS, Part I: Monitoring Process Execution via MACF - Kai Lu](https://www.fortinet.com/blog/threat-research/monitoring-macos--part-i--monitoring-process-execution-via-macf.html)
			* [Part II: Monitoring File System Events and Dylib Loading via MACF - Kai Lu](https://www.fortinet.com/blog/threat-research/monitor-file-system-events-and-dylib-loading-via-macf-on-macos.html)
			* [Part III: Monitoring Network Activities Using Socket Filters - Kai Lu](https://www.fortinet.com/blog/threat-research/monitoring-macos--part-iii--monitoring-network-activities-using-.html)
		* [Writing a Process Monitor with Apple's Endpoint Security Framework - Patrick Wardle](https://objective-see.com/blog/blog_0x47.html)
		* [Monitoring macOS, Part I: Monitoring Process Execution via MACF - Kai Lu](https://www.fortinet.com/blog/threat-research/monitoring-macos--part-i--monitoring-process-execution-via-macf.html)
	* **Understanding**
	* **Tools**
		* [Crescendo](https://github.com/SuprHackerSteve/Crescendo)
			* Crescendo is a swift based, real time event viewer for macOS. It utilizes Apple's Endpoint Security Framework.
			* [Blogpost](https://segphault.io/posts/2020/03/crescendo/)
		* [Learn How to Build Your Own Utility to Monitor Malicious Behaviors of Malware on macOS - Kai Lu(BH USA 2018)](https://www.blackhat.com/us-18/arsenal.html#learn-how-to-build-your-own-utility-to-monitor-malicious-behaviors-of-malware-on-macos)
			* [Slides](https://fortinetweb.s3.amazonaws.com/fortiguard/research/Learn_How_to_Build_Your_Own_Utility_to_Monitor_Malicious_Behaviors_of_Malware_on%20macOS_KaiLu.pdf)
			* [Blogpost](https://www.fortinet.com/blog/threat-research/fortiappmonitor--a-powerful-utility-for-monitoring-system-activi.html)
	* **File System/Files/Folders**
		* **Articles/Blogposts/Writeups**
			* [Writing a File Monitor with Apple's Endpoint Security Framework - Patrick Wardle](https://objective-see.com/blog/blog_0x48.html)
		* **Tooling**
			* [filemon - An FSEvents client]()http://newosxbook.com/tools/filemon.html
			* [filewatcher(2018)](https://github.com/meliot/filewatcher)
				* Filewatcher is an auditing and monitoring utility for macOS. It can audit all events from the system auditpipe of macOS and filter them by process or by file
			* [FileMonitor](https://github.com/objective-see/FileMonitor)
				* A macOS File Monitor (based on Apple's new Endpoint Security Framework)	
	* **Processes**
		* **Articles/Blogposts/Writeups**
			* [Writing a Process Monitor with Apple's Endpoint Security Framework - Patrick Wardle(2019)](https://objective-see.com/blog/blog_0x47.html)
		* **Tooling**
			* [Process Monitor](https://github.com/objective-see/ProcessMonitor)
				* Process Monitor Library (based on Apple's new Endpoint Security Framework)
			* [ProcInfo](https://github.com/objective-see/ProcInfo)
				* Proc Info is a open-source, user-mode, library for macOS. It provides simple interface to retrieve detailed information about running processes, plus allows one to asynchronously monitor process creation & exit events.
* **Windows**<a name='winmon'></a>
	* **Articles/Writeups**
		* [Challenges with Native File System Access Auditing - Farrah Gamboa(2019)](https://blog.stealthbits.com/challenges-with-native-file-system-access/)
		* [Windows File Activity Monitoring - Farrah Gamboa(2019)](https://blog.stealthbits.com/windows-file-activity-monitoring/)
		* [Practical PowerShell for IT Security, Part I: File Event Monitoring - varonis.com](https://www.varonis.com/blog/practical-powershell-for-it-security-part-i-file-event-monitoring/)
	* **Talks/Presentations/Videos**		
		* [Sysinternals Video Library - Tour of the Sysinternals Tools - Mark Russinovich, David Solomon](https://www.youtube.com/watch?v=TMlTwRsO5F8&list=PL96F5PDvO1HHuVewlKWQDzzTUrhMm-wGS)
		* [How To Do Consolidated Endpoint Monitoring on a Shoe-String Budget - Derek Banks & Joff Thyer(2017)](https://www.blackhillsinfosec.com/webcast-consolidated-endpoint-monitoring-shoestring-budget/)
			* [Blogpost Writeup](https://www.blackhillsinfosec.com/endpoint-monitoring-shoestring-budget-webcast-write/)
	* **Understanding**
	* **Tools**
	* **Audit Policy**
		* **101**
			* [Advanced security audit policy settings - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
				* This reference for IT professionals provides information about the advanced audit policy settings that are available in Windows and the audit events that they generate. The security audit policy settings under Security Settings\Advanced Audit Policy Configuration can help your organization audit compliance with important business-related and security-related rules by tracking precisely defined activities
	* **Files/Folders**
		* [Real-time file monitoring on Windows with osquery - trailofbits](https://blog.trailofbits.com/2020/03/16/real-time-file-monitoring-on-windows-with-osquery/)
			* Trail of Bits has developed ntfs_journal_events, a new event-based osquery table for Windows that enables real-time file change monitoring.
	* **Processes**
		* [Blue Team fundamentals Part Two: Windows Processes. - Pete(2017)](https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2)
	* **Sysmon**
		* [Sysmon - The Best Free Windows Monitoring Tool You Aren't Using](http://909research.com/sysmon-the-best-free-windows-monitoring-tool-you-arent-using/)
		






















------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

### Detection Engineering <a name="detect"></a>
* **101**
	* **Articles/Writeups**	
		* [Methods of Detection - Jack Crook](https://findingbad.blogspot.com/2018/06/methods-of-detection.html)
		* [What’s in a name? TTPs in Info Sec - Robby Winchester(2017)](https://posts.specterops.io/whats-in-a-name-ttps-in-info-sec-14f24480ddcc)
		* [Capability Abstraction - Jared Atkinson](https://posts.specterops.io/capability-abstraction-fbeaeeb26384)
			* This is the first of a multipart blog series by the SpecterOps detection team. The goal of this series is to introduce and discuss foundational detection engineering concepts. To make these concepts as consumable as possible, we are focusing the entire series around Kerberoasting. Focusing on this technique allows readers to focus on the strategies presented in each article instead of worrying about the details of the technique itself. The focus of this post is a concept we call “capability abstraction.” The idea is that an attacker’s tools are merely an abstraction of their attack capabilities, and detection engineers must understand how to evaluate abstraction while building detection logic.
		* [Uncovering The Unknowns - Jonathan Johnson(2019)](https://posts.specterops.io/uncovering-the-unknowns-a47c93bb6971)
			* Mapping Windows API’s to Sysmon Events
		* [Getting Started with ATT&CK: Detection and Analytics - John Wunder(2019)](https://medium.com/mitre-attack/getting-started-with-attack-detection-a8e49e4960d0)
		* [The Detection Maturity Level Model - Ryan Stillion(2014)](https://web.archive.org/web/20200501220417/http://ryanstillions.blogspot.com/web/20191003131310/http://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html)
	* **Talks & Presentations**
		* [$SignaturesAreDead = “Long Live RESILIENT Signatures” wide ascii nocase - Matthew Dunwoody, Daniel Bohannon(BruCON 0x0A)](https://www.youtube.com/watch?v=YGJaj6_3dGA)
			* Signatures are dead, or so we're told. It's true that many items that are shared as Indicators of Compromise (file names/paths/sizes/hashes and network IPs/domains) are no longer effective. These rigid indicators break at the first attempt at evasion. Creating resilient detections that stand up to evasion attempts by dedicated attackers and researchers is challenging, but is possible with the right tools, visibility and methodical (read iterative) approach.   As part of FireEye's Advanced Practices Team, we are tasked with creating resilient, high-fidelity detections that run across hundreds of environments and millions of endpoints. In this talk we will share insights on our processes and approaches to detection development, including practical examples derived from real-world attacks.
* **Linux**
* **macOS**
* **Windows**
	* **Articles/Writeups**	
		* [Engineering Process Injection Detections - Part 1: Research - Jonathan Johnson(2020)](https://posts.specterops.io/engineering-process-injection-detections-part-1-research-951e96ad3c85)
			* [Code](https://github.com/jsecurity101/Detecting-Process-Injection-Techniques)
		* [Execution - Powershell (T1086) - Rafael Bono, José Miguel Colmena]](https://ackcent.com/blog/execution-powershell-t1086/)
		* [Detection Engineering with Kerberoasting Series]()
			* [Part1 - Capability Abstraction - Jared Atkinson](https://posts.specterops.io/capability-abstraction-fbeaeeb26384)
			* [Part2 - Detection Spectrum - Jared Atkinson](https://posts.specterops.io/detection-spectrum-198a0bfb9302)
		* [Host-based Threat Modeling & Indicator Design - Jared Atkinson(2017)](https://posts.specterops.io/host-based-threat-modeling-indicator-design-a9dbbb53d5ea)
		* [Thoughts on Host-based Detection Techniques - Jared Atkinson(2017)](https://posts.specterops.io/thoughts-on-host-based-detection-techniques-21d9c97082ce)
		* [Black Hat: Detecting the unknown and disclosing a new attack technique at Black Hat 2019 - Brian Donohue](https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/)
			* Researchers Casey Smith and Ross Wolf demonstrated how to threat hunt for the unknown—and disclosed a new attack technique in the process—at the Black Hat security conference in Las Vegas, Nevada Thursday afternoon.
	* **Talks & Presentations**
		* [How do I detect technique X in Windows?? Applied Methodology to Definitively Answer this Question - Matt Graeber(Derbycon 2019)](http://www.irongeek.com/i.php?page=videos/derbycon9/1-05-how-do-i-detect-technique-x-in-windows-applied-methodology-to-definitively-answer-this-question-matt-graeber)
			* Traditionally, the answer to this question has been to execute an attack technique in a controlled environment and to observe relevant events that surface. While this approach may suffice in some cases, ask yourself the following questions: ?Will this scale? Will this detect current/future variants of the technique? Is this resilient to bypass?? If your confidence level in answering these questions is not high, it?s time to consider a more mature methodology for identifying detection data sources. With a little bit of reverse engineering, a defender can unlock a multitude of otherwise unknown telemetry. This talk will establish a methodology for identifying detection data sources and will cover concepts including Event Tracing for Windows, WPP, TraceLogging, and security product analysis.
	* **Tools/Tooling**
		* API-To-Event](https://github.com/hunters-forge/API-To-Event)
			* A repo focused primarily on documenting the relationships between API functions and security events that get generated when using such functions. 























------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

### Threat Hunting <a name="th"></a>
* **101**<a name="th101"></a>
	* **Articles/Writeups**
		* [The Origin of Threat Hunting - TaoSecurity](https://taosecurity.blogspot.com/2017/03/the-origin-of-threat-hunting.html?m=1)
		* [The Cyber Hunting Maturity Model - Sqrrl(2015)](https://medium.com/@sqrrldata/the-cyber-hunting-maturity-model-6d506faa8ad5)
		* [The ThreatHunting Project Annotated Reading List](https://www.threathunting.net/reading-list)
		* [Incident Response is Dead… Long Live Incident Response - Scott J Roberts(2015)](https://medium.com/@sroberts/incident-response-is-dead-long-live-incident-response-5ba1de664b95)
		* [Demystifying Threat Hunting Concepts - Josh Liburdi(2017)](https://medium.com/@jshlbrd/demystifying-threat-hunting-concepts-9de5bad2d818)
			* This post is about demystifying threat hunting concepts that seem to trip up practitioners and outsiders. 
		* [A Simple Hunting Maturity Model - detect-respond.blogspot (2015)](https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html)
		* [The Threat Hunting Reference Model Part 2: The Hunting Loop - Sqrrl](https://www.threathunting.net/files/The%20Threat%20Hunting%20Reference%20Model%20Part%202_%20The%20Hunting%20Loop%20_%20Sqrrl.pdf)
		* [The Who, What, Where, When, Why and How of Effective Threat Hunting - Robert Lee, Rob Lee(2016)](https://www.sans.org/reading-room/whitepapers/analyst/membership/36785)
		* [Building Threat Hunting Strategies with the Diamond Model - Sergio Caltagirone(2016)](http://www.activeresponse.org/building-threat-hunting-strategy-with-the-diamond-model/)
		* [Cyber Threat Hunting (1): Intro - Samuel Alonso(2016)](https://cyber-ir.com/2016/01/21/cyber-threat-hunting-1-intro/)
			* [Part 2: Getting Ready](https://cyber-ir.com/2016/02/05/cyber-threat-hunting-2-getting-ready/)
			* [Part 3: Hunting in the perimeter](https://cyber-ir.com/2016/03/01/cyber-threat-hunting-3-hunting-in-the-perimeter/)
		* [Cyber Hunting: 5 Tips To Bag Your Prey - David J. Bianco](https://www.darkreading.com/risk/cyber-hunting-5-tips-to-bag-your-prey/a/d-id/1319634)
		* [Data Science Hunting Funnel - Austin Taylor(2017)](http://www.austintaylor.io/network/traffic/threat/data/science/hunting/funnel/machine/learning/domain/expertise/2017/07/11/data-science-hunting-funnel/)
		* [DeTT&CT: Mapping your Blue Team to MITRE ATT&CK™ - Marcus Bakker](https://www.mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack)
			* [DeTTECT - Detect Tactics, Techniques & Combat Threats](https://github.com/rabobank-cdc/DeTTECT)
		* [The Role of Evidence Intention - Chris Sanders](https://chrissanders.org/2018/10/the-role-of-evidence-intention/)
		* [Threat Hunting - Getting Closer to Anomalous Behavior - findingbad.blogspot](https://findingbad.blogspot.com/2016/10/threat-hunting-getting-closer-to.html)
		* [On TTPs - Ryan Stillions](https://web.archive.org/web/20200501220419/http://ryanstillions.blogspot.com/web/20191003131313/http://ryanstillions.blogspot.com/2014/04/on-ttps.html)
			* [...]I set off a few months ago on a personal quest.  I wanted to see if I could locate any official citations that attempted to clearly define, compare or contrast "TTPs" in a cyber context, and show how they could be used both individually and jointly with other models to further advance our work in the context of things above and beyond atomic Indicators of Compromise (IOCs).  In this blog post I'll share with you what I found regarding the definitions of "TTPs", and then transition into how I believe they apply to incident detection and response.
		* [The PARIS Model](http://threathunter.guru/blog/the-paris-model/)
	* **Resources**
		* [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection)
	* **Talks & Presentations**
		* [Threat Hunting Workshop - Methodologies for Threat Analysis - RiskIQ](https://www.youtube.com/playlist?list=PLgLzPE5LJevb_PcjMYMF2ypjnVcKf8rjY)
		* [Find_Evil - Threat Hunting Anurag Khanna(SANS2020)](https://www.youtube.com/watch?v=GrhVz1Sjd_0)
			* Today, organizations are constantly under attack. While security teams are getting good at monitoring and incident response, the frontier to conquer is proactively looking for evil in the environment. Threat hunting is one of the ways in which organizations can proactively look for threats. This talk would discuss the fundamentals of threat hunting, what the hunting teams should look for and how to collect and analyze relevant data. We will discuss some of the recipes to perform threat hunting.
	* **Papers**
		* [Generating Hypotheses for Successful Threat Hunting - Robert M. Lee, David Bianco](https://www.sans.org/reading-room/whitepapers/threats/paper/37172)
			* Threat hunting is a proactive and iterative approach to detecting threats. Although threat hunters should rely heavily on automation and machine assistance, the process itself cannot be fully automated. One of the human’s key contributions to a hunt is the formulation of a hypotheses to guide the hunt. This paper explores three types of hypotheses and outlines how and when to formulate each of them.
		* [Hunt Evil: Your Practical Guide to Threat Hunting - threathunting.net](https://www.threathunting.net/files/hunt-evil-practical-guide-threat-hunting.pdf)
		* [Huntpedia - Sqrrl](https://www.threathunting.net/files/huntpedia.pdf)
		* [Threat Hunting: Open Season on the Adversary - Eric Cole(2016)](https://www.sans.org/reading-room/whitepapers/analyst/membership/36882)
		* [Mental Models for Effective Searching - Chris Sanders](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1555082140.pdf)
* **Data Analysis**<a name="data"></a>
	* **Articles/Blogposts/Writeups**
		* [An In-Depth Look Into Data Stacking - M-Labs](https://www.fireeye.com/blog/threat-research/2012/11/indepth-data-stacking.html)
	* **Labs**
		* HELK
			* [HELK - The Hunting ELK](https://github.com/Cyb3rWard0g/HELK)
				* A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.
			* [The Quieter You Become, the More You’re Able to (H)ELK -  Nate Guagenti, Roberto Rodriquez - BSides Colombus Ohio 2018](https://www.irongeek.com/i.php?page=videos/bsidescolumbus2018/p05-the-quieter-you-become-the-more-youre-able-to-helk-nate-guagenti-roberto-rodriquez)
				* Enabling the correct endpoint logging and centralizing the collection of different data sources has finally become a basic security standard. This allows organizations to not just increase the level of visibility, but to enhance their threat detection. Solutions such as an (Elastic) ELK stack have largely been adopted by small and large organizations for data ingestion, storage and visualization. Although, it might seem that collecting a massive amount of data is all analysts need to do their jobs, there are several challenges for them when faced with large, unstructured and often incomplete/disparate data sets. In addition to the sisyphean task of detecting and responding to adversaries there may be pitfalls with organizational funding, support, and or approval (Government). Although “everyone” is collecting logs and despite the many challenges, we will show you how to make sense of these logs in an efficient and consistent way. Specifically when it comes to Windows Event logs (ie: Sysmon, PowerShell, etc) and the ability to map fields to other logs such as Bro NSM or some other network monitoring/prevention device. This will include different Windows Event log data normalization techniques across the 1,000+ unique Event IDs and its 3,000+ unique fields. Also, proven data normalization techniques such as hashing fields/values for logs such as PowerShell, Scheduled Tasks, Command Line, and more. These implementations will show how it allows an analyst to efficiently “pivot” from an endpoint log to a NSM log or a device configuration change log. However, we will also show how an analyst can make an informed decision without degrading/hindering their investigation as well as to enhance their decision. Whether this is preventing an analyst from excluding keywords that a malicious actor may include as an “evasion” technique or adding additional analysis techniques (ie: graphing).
	* **EQL**
		* **101**
			* [Event Query Language](https://github.com/endgameinc/eql)
			* [Getting Started](https://eqllib.readthedocs.io/en/latest/guides/index.html)
			* [Query Guide](https://eql.readthedocs.io/en/latest/query-guide/)
			* [Schemas](https://eqllib.readthedocs.io/en/latest/schemas.html)
		* **Articles/Blogposts/Writeups**
			* [Introducing Event Query Language - Ross Wolf(2019)](https://www.elastic.co/blog/introducing-event-query-language)
			* [The No Hassle Guide to Event Query Language (EQL) for Threat Hunting - Andy Green](https://www.varonis.com/blog/guide-no-hassle-eql-threat-hunting/)
		* **Talks/Presentations/Videos**
			* [Fantastic Red Team Attacks and How To Find Them - Casey Smith, Ross Wolf(BHUSA2019)](https://www.youtube.com/watch?v=9bUrVgP8Duk)
				* [Slides](https://i.blackhat.com/USA-19/Thursday/us-19-Smith-Fantastic-Red-Team-Attacks-And-How-To-Find-Them.pdf)
		* **Tooling**
			* [EQL Analytics Library](https://github.com/endgameinc/eqllib)
				* The Event Query Language Analytics Library (eqllib) is a library of event based analytics, written in EQL to detect adversary behaviors identified in MITRE ATT&CK™.
			* [Varna](https://github.com/endgameinc/varna)
				* Varna is an AWS serverless cloud security tool that parses and alerts on CloudTrail logs using Event Query Language (EQL). Varna is deployed as a lambda function, for scanning and serving web requests, and a dynamodb table, for keeping track of seen alerts. Varna is cheap & efficient to run, costing less than 15 dollars a month with proper configuration and ingesting alerts as soon as CloudTrail stores them in S3.
* **Hunt Experiences/Demonstrations of**
	* **Articles/Blogposts/Writeups**
		* [Threat Hunting with Python: Prologue and Basic HTTP Hunting - Dan Gunter(2017)](https://dgunter.com/2017/09/17/threat-hunting-with-python-prologue-and-basic-http-hunting/)
			* [Part 2: Detecting Nmap Behavior with Bro HTTP Logs](https://dgunter.com/2017/11/28/threat-hunting-with-python-part-2-detecting-nmap-behavior-with-bro-http-logs/)
			* [Part 3: Taming SMB](https://dgunter.com/2018/02/17/threat-hunting-with-python-and-bro-ids-part-3-taming-smb/)
			* [Part 4: Examining Microsoft SQL Based Historian Traffic](https://dgunter.com/2018/03/20/threat-hunting-with-python-part-4-examining-microsoft-sql-based-historian-traffic/)
		* [Threat Hunting Part 1: Improving Through Hunting - Dan Gunter](https://dragos.com/blog/industry-news/threat-hunting-part-1-improving-through-hunting/)
			* [Part 2: Hunting on ICS Networks](https://dgunter.com/2017/10/03/threat-hunting-part-2-hunting-on-ics-networks/)
		* [Active Defense and the Hunting Maturity Model - Jamie Buening](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492176467.pdf)
		* [Hunting Red Team Empire C2 Infrastructure  - Chokepoint](https://web.archive.org/web/20190521071950/http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html)
	* **Talks/Presentations/Papers**
		* [License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)
		* [Advanced Attack Detection - William Burgess, Matt Watkins(Securi-Tay2017)](https://www.youtube.com/watch?v=ihElrBBJQo8)
			* In this talk, we’ll explain some of the technical concepts of threat hunting. We will be looking at what is beyond traditional signature detection – the likes of AV, IPS/IDS and SIEMs, which in our experience are ineffective – and detailing some of the ways you can catch real attackers in the act. As a case study, we’ll look at some of the specifics of common attack frameworks - the likes of Metasploit and Powershell Empire - walking through an example attack, and showing how they can be detected. From large-scale process monitoring to live memory analysis and anomaly detection techniques, we will cover some of the technical quirks when it comes to effective attack detection.
* **In Memory**<a name="inmem"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK - Part I (Event ID 7) - Roberto Rodriguez](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html?m=1)
		* [Automating large-scale memory forensics](https://medium.com/@henrikjohansen/automating-large-scale-memory-forensics-fdc302dc3383)
	* **Tooling**
		* [memhunter](https://github.com/marcosd4h/memhunter)
			* Memhunter is an endpoint sensor tool that is specialized in detecing resident malware, improving the threat hunter analysis process and remediation times. The tool detects and reports memory-resident malware living on endpoint processes. Memhunter detects known malicious memory injection techniques. The detection process is performed through live analysis and without needing memory dumps. The tool was designed as a replacement of memory forensic volatility plugins such as malfind and hollowfind. The idea of not requiring memory dumps helps on performing the memory resident malware threat hunting at scale, without manual analysis, and without the complex infrastructure needed to move dumps to forensic environments. Besides the data collection and hunting heuristics, the project has also led to the creation of a companion tool called "minjector" that contains +15 code injection techniques. The minjector tool cannot onlybe used to exercise memhunter detections, but also as a one-stop location to learn on well-known code injection techniques out there.
* **Metrics**<a name="thmetrics"></a>
	* [The Hunting Cycle and Measuring Success - findingbad.blogspot(2016)](https://findingbad.blogspot.com/2016/11/the-hunting-cycle-and-measuring-success.html)
	* [Creating & Tracking Threat Hunting Metrics - Josh Liburdi(2020)](https://medium.com/@jshlbrd/creating-tracking-threat-hunting-metrics-fc66e6b84076)
* **OS Agnostic**<a name="osag"></a>
	* **101**
	* **Articles/Writeups**
		* [The ThreatHunting Project](https://github.com/ThreatHuntingProject/ThreatHunting)
			* An informational repo about hunting for adversaries in your IT environment.
		* [Outbound RDP Surprises - Justin Vaicaro()](https://www.trustedsec.com/blog/threat-hunting-outbound-rdp-surprises/)
			* The goal of this blog post is not to dissect the threat hunting process or dive into the various hunting strategies and tactics. Rather, the intent is to show the importance of focusing on a legitimate protocol within a threat hunt engagement that can be easily used for potential data exfiltration, hide in plain sight with other normal traffic, and go unnoticed by a security operations center (SOC) that is untrained to identify potentially suspicious network behavior.
	* **Talks & Presentations**
	* **Tools**
		* [grapl](https://github.com/grapl-security/grapl)
			* Grapl is a Graph Platform for Detection and Response with a focus on helping Detection Engineers and Incident Responders stop fighting their data and start connecting it. Grapl leverages graph data structures at its core to ensure that you can query and connect your data efficiently, model complex attacker behaviors for detection, and easily expand suspicious behaviors to encompass the full scope of an ongoing intrusion.
* **Network-based**<a name="thnet"></a>
	* **101**
	* **Articles/Writeups**
		* [Part 1: Threat hunting with BRO/Zeek and EQL - Spartan2194(2019)](https://holdmybeersecurity.com/2019/02/20/part-1-threat-hunting-with-bro-zeek-and-eql/)
		* [DNS based threat hunting and DoH (DNS over HTTPS) - blog.redteam.pl](https://blog.redteam.pl/2019/04/dns-based-threat-hunting-and-doh.html)
	* **Talks & Presentations**
		* [Tales from the Network Threat Hunting Trenches - BHIS](https://www.blackhillsinfosec.com/webcast-tales-network-threat-hunting-trenches/)
			* In this webcast John walks through a couple of cool things we’ve found useful in some recent network hunt teams. He also shares some of our techniques and tools (like RITA) that we use all the time to work through massive amounts of data. There are lots of awesome websites that can greatly increase the effectiveness of your in network threat hunting.
		* [Network gravity: Exploiring a enterprise network - Casey Martin(BSides Tampa2020)](https://www.irongeek.com/i.php?page=videos/bsidestampa2020/track-d-01-network-gravity-exploiring-a-enterprise-network-casey-martin)
			* Enterprise networks are often complex, hard to understand, and worst of all - undocumented. Few organizations have network diagrams and asset management systems and even fewer organizations have those that are effective and up to date. Leveraging an organization's SIEM or logging solution, network diagrams and asset inventories can be extrapolated from this data through the 'gravity' of the network. Similar to our solar system and galaxy, even if you cannot confirm or physically see an object, you can measure the forces of gravity it exerts on the observable objects around it that we do know about. For example, unconfirmed endpoints can be enumerated by the authentication activity they register on known domain controllers. The inferred list of endpoints and their network addresses can begin to map out logical networks. The unpolished list of logical networks can be mapped against known egress points to identify physical networks and potentially identify undiscovered egress points and the technologies that exist at the egress points. As more objects are extrapolated and inferred, the more accurate the model of your enterprise network will become. Through this iterative and repeatable process, network diagrams and asset inventories can be drafted, further explored, refined, and ultimately managed. Even the weakest of observable forces can create fingerprints that security professionals can leverage to more effectively become guardians of the galaxy.
	* **Papers**
		* [Under the Shadow of Sunshine: Understanding and Detecting Bulletproof Hosting on Legitimate Service Provider Networks - Sumayah Alrwais, Xiaojing Liao, Xianghang Mi, Peng Wang, XiaoFeng Wang, Feng Qian, Raheem Beyah, Damon McCoy](http://damonmccoy.com/papers/alrwais2017under.pdf)
			* In this paper, we present the first systematic study on thisnew trend of BPH services. By collecting and analyzing a large amount of data (25 Whois snapshots of the entire IPv4 addressspace, 1.5 TB of passive DNS data, and longitudinal data fromseveral blacklist feeds), we are able to identify a set of newfeatures that uniquely characterizes BPH on sub-allocations and are costly to evade. Based upon these features, we train a classifierfor detecting malicious sub-allocated network blocks, achieving a 98% recall and 1.5% false discovery rates according to our evaluation. Using a conservatively trained version of our classifier,we scan the whole IPv4 address space and detect 39K malicious network blocks. This allows us to perform a large-scale study ofthe BPH service ecosystem, which sheds light on this underground business strategy, including patterns of network blocks being recycled and malicious clients migrating to different network blocks, in an effort to evade IP address based blacklisting. Our study highlights the trend of agile BPH services and points to potential methods of detecting and mitigating this emerging threat.
	* **Tools**
		* [Imaginary C2](https://github.com/felixweyne/imaginaryC2)
			* A python tool which aims to help in the behavioral (network) analysis of malware. Imaginary C2 hosts a HTTP server which captures HTTP requests towards selectively chosen domains/IPs. Additionally, the tool aims to make it easy to replay captured Command-and-Control responses/served payloads.
	* **DNS**
		* **Articles/Writeups**
			* [Hunting Your DNS Dragons - Derek King(2018)](https://www.splunk.com/en_us/blog/security/hunting-your-dns-dragons.html)
			* [Threat hunting using DNS firewalls and data enrichment - Adam Ziaja](https://blog.redteam.pl/2019/08/threat-hunting-dns-firewall.html)


* **Traffic Analysis**<a name="traffic"></a>
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
		* [RITA - Real Intelligence Threat Analytics](https://github.com/ocmdev/rita)
			* RITA is an open source network traffic analysis framework.
			* [RITA - Finding Bad Things on Your Network Using Free and Open Source Tools](https://www.youtube.com/watch?v=mpCBOQSjbOA)
		* **General**
			* [DNSpop](https://github.com/bitquark/dnspop) 
				* Tools to find popular trends by analysis of DNS data. For more information, see my [blog post](https://bitquark.co.uk/blog/2016/02/29/the_most_popular_subdomains_on_the_internet) on the most popular subdomains on the internet. Hit the results directory to get straight to the data.
			* [Yeti](https://github.com/yeti-platform/yeti)
				* Yeti is a platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository. Yeti will also automatically enrich observables (e.g. resolve domains, geolocate IPs) so that you don't have to. Yeti provides an interface for humans (shiny Bootstrap-based UI) and one for machines (web API) so that your other tools can talk nicely to it.
			* [Malcom - Malware Communication Analyzer](https://github.com/tomchop/malcom)
				* Malcom is a tool designed to analyze a system's network communication using graphical representations of network traffic, and cross-reference them with known malware sources. This comes handy when analyzing how certain malware species try to communicate with the outside world.
			* [BeaconBits](https://github.com/bez0r/BeaconBits)
				* Beacon Bits is comprised of analytical scripts combined with a custom database that evaluate flow traffic for statistical uniformity over a given period of time. The tool relies on some of the most common characteristics of infected host persisting in connection attempts to establish a connection, either to a remote host or set of host over a TCP network connection. Useful to also identify automation, host behavior that is not driven by humans.

* **Linux**<a name='thlin'></a>
* **macOS**<a name='thmac'></a>
	* **101**
		* [Capturing the moment in your log: how to identify a problem - hoakley(2019)](https://eclecticlight.co/2019/09/17/capturing-the-moment-in-your-log-how-to-identify-a-problem/)
	* **Articles/Writeups**
		* [Mac system extensions for threat detection: Part 1 - Will Yu](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-1)
			* [Part 2](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-2)
			* [Part 3](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-3)
			* In part 1 of this series, we’ll go over some of the frameworks accessible by kernel extensions that provide information about file system, process, and network events. These frameworks include the Mandatory Access Control Framework, the KAuth framework, and the IP/socket filter frameworks. We won't do a deep dive into each one of these frameworks specifically, as there have been many other posts and guides [0](https://www.synack.com/blog/monitoring-process-creation-via-the-kernel-part-i/) [1](https://www.apriorit.com/dev-blog/411-mac-os-x-kauth-listeners) [2](https://reverse.put.as/2014/10/03/can-i-suid-a-trustedbsd-policy-module-to-control-suid-binaries-execution/) [3](https://developer.apple.com/library/archive/technotes/tn2127/_index.html) [4](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) regarding how to use these frameworks. Instead, we’ll recap and review each of these frameworks, then in [part 2](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-2) we’ll cover some valuable tips and tricks we can use inside the kernel extensions framework that will no longer be available in the new SystemExtensions framework starting in macOS 10.15. And finally, in [part 3](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-3) of the series, we’ll cover the new SystemExtensions framework and the features it provides to third-party developers.
		* [Hunting for Bad Apples – Part 1 - Richie Cyrus](https://securityneversleeps.net/2018/06/25/hunting-for-bad-apples-part-1/)
		* [Logs Unite! Forensic Analysis Of Apple Unified Logs - Sarah Edwards(2017)](https://papers.put.as/papers/macosx/2017/LogsUnite.pdf)
	* **Talks & Presentations**
		* [When Macs Come Under ATT&CK - Richie Cyrus(OBTSv1.0)](https://www.youtube.com/watch?v=X99QKMCVOBc)
			* This talk will discuss common tactics, techniques and procedures used by attackers on MacOS systems, as well as methods to detect adversary activity. We will take a look at known malware, mapping the techniques utilized to the MITRE ATT&CK framework. Attendees will leave equipped to begin hunting for evil lurking within their MacOS fleet.
			* [When Macs Come Under ATT&CK - Richie Cyrus(Derbycon2018)](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-01-when-macs-come-under-attck-richie-cyrus)
	* **Tools**
		* [Venator](https://github.com/richiercyrus/Venator)
			* Venator is a python tool used to gather data for proactive detection of malicious activity on macOS devices.
			* [Blogpost - Richie Cyrus(2019)](https://posts.specterops.io/introducing-venator-a-macos-tool-for-proactive-detection-34055a017e56)
			* [Cleaning the Apple Orchard Using Venator to Detect macOS Compromise - Richie Cyrus(BSides Charm 2019)]
				* Various solutions exist to detect malicious activity on macOS. However, they are not intended for enterprise use or involve installation of an agent. This session will introduce and demonstrate how to detect malicious macOS activity using the tool Venator. Venator is a python based macOS tool designed to provide defenders with the data to proactively identify malicious macOS activity at scale.
		* [TrueTree](https://github.com/themittenmac/TrueTree)
			* TrueTree is more than just a pstree command for macOS. It is used to display a process tree for current running processes while using a hierarchy built on additoinal pids that can be collected from the operating system. The standard process tree on macOS that can be built with traditional pids and ppids is less than helpful on macOS due to all the XPC communication at play. The vast majority of processes end up having a parent process of launchd. TrueTree however displays a process tree that is meant to be useful to incident responders, threat hunters, researchers, and everything in between!
			* [Blogpost](https://themittenmac.com/the-truetree-concept/)
* **Windows**<a name='thwin'></a>
	* **General**
		* **Articles/Writeups**
			* [Part 1: Intro to Threat Hunting with Powershell Empire, Windows event logs, and Graylog - Spartan2194(2017)](https://holdmybeersecurity.com/2017/12/05/part-1-intro-to-threat-hunting-with-powershell-empire-windows-event-logs-and-graylog/)
			* [Spotting the Adversary with Windows Event Log Monitoring - NSA](https://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf)
			* [Windows Event ID 4649 “A replay attack was detected “ — Oh really? Are we under ATTACK? Should we do Incident Response? - Iveco Aliza(2020)](https://medium.com/@ivecodoe/windows-event-id-4649-a-replay-attack-was-detected-ab02968d91ee)
			* [Sysmon Threat Analysis Guide - Andy Green(2020)](https://www.varonis.com/blog/sysmon-threat-detection-guide/)
			* [Blue Team Hacks - Binary Rename](https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html)
				* "In this post I thought I would share an interesting proof of concept I developed to detect Binary Rename of commonly abused binaries. Im going to describe the detection, its limitations and share the code."
			* [Binary Rename 2](https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html)
				* In this post I am focusing on static detection, that is assessing files on disk. I am going to describe differences between both Yara and Powershell based detections, then share the code.
		* **Papers**
			* [Detecting Security Incidents Using Windows WorkstationEvent Logs - Russ Anthony(2013)](https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262)
				* Windows event logs can be an extremely valuable resource todetect securityincidents. While many companies collect logs from security devices and critical serversto comply with regulatory requirements, few collect them from their windows workstations;even fewer proactively analyze theselogs.  Collecting and analyzingworkstation logs is critical because it is increasinglyatthe workstation levelwherethe initial compromiseishappening.If we areto get better at detecting theseinitial compromisesthen it is imperative that we develop an efficient,common sense approach to collectingand analyzingthese events.
			* [Windows Logon Forensics - Sunil Gupta(2013)](https://www.sans.org/reading-room/whitepapers/forensics/windows-logon-forensics-34132)
				* A compromised Windows® system's forensic analysis may not yield much relevant information about the actual target. Microsoft® Windows Operating System uses a variety of logon and authentication mechanisms to connect to remote systems over the network. Incident Response and Forensic Analysis outcomes are prone to errors without proper understanding of different account types, Windows logons and authentication methods available on a Windows platform. This paper walks thru the logon and authentication and how they are audited for various Windows account types’ logons for a successful investigation. In the process it describes common authentication protocols such as Kerberos, NTLM to better understanding of the logon process communications in the Windows environment.
			* [Detecting Advanced Threats With Sysmon, WEF, and ElasticSearch - Josh Lewis(2015)](https://www.root9b.com/sites/default/files/whitepapers/R9B_blog_005_whitepaper_01.pdf)
		* **Talks & Presentations**
			* 
	* **Active Directory**
		* **101**
			* [Monitoring Active Directory for Signs of Compromise - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
				* Applies To: Windows Server 2016, Windows Server 2012 R2, Windows Server 2012
			* [Appendix L: Events to Monitor - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
				* The following table lists events that you should monitor in your environment, according to the recommendations provided in [Monitoring Active Directory for Signs of Compromise](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise).
		* **Articles/Writeups**
			* [Detecting Kerberoasting activity using Azure Security Center - Moti Bani](https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/)
			* [The only PowerShell Command you will ever need to find out who did what in Active Directory - Przemyslaw Klys(2019)](https://evotec.xyz/the-only-powershell-command-you-will-ever-need-to-find-out-who-did-what-in-active-directory/)
			* [Detecting Attackers in a Windows Active Directory Network - Mark Gamache(2017)](https://markgamache.blogspot.com/2017/08/detecting-attackers-in-windows-active.html)
		* **Talks/Presentations/Videos**
			* [Detecting the Elusive Active Directory Threat Hunting - Sean Metcalf(BSidesCharm2017)](https://www.youtube.com/watch?v=9Uo7V9OUaUw)
				* Attacks are rarely detected even after months of activity. What are defenders missing and how could an attack by detected? This talk covers effective methods to detect attacker activity using the features built into Windows and how to optimize a detection strategy. The primary focus is on what knobs can be turned and what buttons can be pushed to better detect attacks. One of the latest tools in the offensive toolkit is ""Kerberoast"" which involves cracking service account passwords offline without admin rights. This attack technique is covered at length including the latest methods to extract and crack the passwords. Furthermore, this talk describes a new detection method the presenter developed. The attacker's playbook evolves quickly, defenders need to stay up to speed on the latest attack methods and ways to detect them. This presentation will help you better understand what events really matter and how to better leverage Windows features to track, limit, and detect attacks.
				* [Slides](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)
		* **Tools**
			* [WatchAD](https://github.com/0Kee-Team/WatchAD)
				* After Collecting event logs and kerberos traffic on all domain controllers, WatchAD can detect a variety of known or unknown threats through features matching, Kerberos protocol analysis, historical behaviors, sensitive operations, honeypot accounts and so on. The WatchAD rules cover the many common AD attacks.
	* **Azure**
		* **Articles/Writeups**
			* [Identifying Threat Hunting opportunities in your data - shainw](https://techcommunity.microsoft.com/t5/azure-sentinel/identifying-threat-hunting-opportunities-in-your-data/ba-p/915721)
	* **Browser Extensions**
		* **Articles/Writeups**
			* [Chrome Extensions: Bypassing your security - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/11/02/chrome-extensions-bypassing-security/)
				* Hunting Chrome extensions in Win AD environment with Sysmon and ELK.
	* **Credential Access**
		* **Articles/Writeups**
			* [How to Detect Overpass-The-Hash Attacks - Jeff Warren](https://blog.stealthbits.com/how-to-detect-overpass-the-hash-attacks/)
			* [Hunting for Credentials Dumping in Windows Environment - Teymur Kheirhabaro(ZeroNights2017)](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
		* **Papers**
			* [A Process is No One: Hunting for Token Manipulation - Jared Atkinson, Robby Winchester(2017)](https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation-wp.pdf)
				*  In this paper, we will outline how we view hunting through our five step approach to perform hypothesis driven hunting. In addition, we will walk through a case study detecting Access Token Manipulation, highlighting the actions performed at each step of the process. At the conclusion of the paper, the reader should better understand hunting, our five-step hypothesis process, and how to apply it to real world scenarios.
	* **COM**
		* **Articles/Writeups**
			* [Hunting COM Objects - Charles Hamilton](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html)
			* [Hunting COM Objects (Part Two) - Brett Hawkins](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects-part-two.html)
	* **Event Logs**
		* **Articles/Writeups**
		* **Talks/Presentations/Videos**
			* [What Event Logs? Part 1: Attacker Tricks to Remove Event Logs - Matt Bromiley(SANS DFIR 2018)](https://www.youtube.com/watch?v=7JIftAw8wQY)
				* In part 1 of this series, SANS instructor and incident responder Matt Bromiley focuses on techniques, old and new, that attackers are using to neutralize event logs as a recording mechanism. Ranging from clearing of logs to surgical, specific event removal, in this webcast we will discuss how the attackers are doing what they're doing, and the forensic techniques we can use to detect their methods. There has been a lot of discussions lately about attackers' ability to fool the system into not writing event logs - but are our attackers truly staying hidden when they do this? Let's find out!
			* [What Event Logs Part 2 Lateral Movement without Event Logs - Matt Bromiley(SANS DFIR 2018)](https://www.youtube.com/watch?v=H8ybADELHzk)
				* In part 2 of this series, SANS instructor and incident responder Matt Bromiley will discuss techniques to identify lateral movement when Windows Event Logs are not present. Sometimes logs roll without preservation, and sometimes attackers remove them from infected systems. Despite this, there are still multiple artifacts we can rely on to identify where our attackers came from, and where they went. In this webcast, we'll discuss the techniques and artifacts to identify this activity.
	* **Lateral Movement**
		* **Articles/Writeups**
			* [Threat Hunting for PsExec, Open-Source Clones, and Other Lateral Movement Tools - Tony Lambert(2018)](https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/)
			* [Digging Into Sysinternals: PsExec - Matt B(2016)](https://medium.com/@bromiley/digging-into-sysinternals-psexec-64c783bace2b#.htmvaklhy)
		* **Tools**
			* [kethash](https://github.com/cyberark/ketshash)
				* A little tool for detecting suspicious privileged NTLM connections, in particular Pass-The-Hash attack, based on event viewer logs.
	* **LoLBins**
		* **Articles/Writeups**
			* [Background Intelligent Transfer Protocol - TH Team](https://medium.com/@threathuntingteam/background-intelligent-transfer-protocol-ab81cd900aa7)
	* **.NET**
		* **Articles/Writeups**
			* [Interesting DFIR traces of .NET CLR Usage Logs - menasec.net](https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html)
			* [Detecting attacks leveraging the .NET Framework - Zac Brown, Shane Welcher(2020)](https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/)
			* [Hunting For In-Memory .NET Attacks - Joe Desimone(2017)](https://www.elastic.co/blog/hunting-memory-net-attacks)
			* [Hunting for SILENTTRINITY - Wee-Jing Chung(2019)](https://blog.f-secure.com/hunting-for-silenttrinity/)
				* SILENTTRINITY (byt3bl33d3r, 2018) is a recently released post-exploitation agent powered by IronPython and C#. This blog post will delve into how it works and techniques for detection.
		* **Tools**
			* [ClrGuard](https://github.com/endgameinc/ClrGuard)
				* ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes. ClrGuard leverages a simple appInit DLL (ClrHook32/64.dll) in order to load into all CLR/.NET processes. From there, it performs an in-line hook of security critical functions. Currently, the only implemented hook is on the native LoadImage() function. When events are observed, they are sent over a named pipe to a monitoring process for further introspection and mitigation decision.
	* **Network-Facing Services**
		* **Articles/Writeups**
			* [WebDAV Traffic To Malicious Sites - Didier Stevens](	https://blog.didierstevens.com/2017/11/13/webdav-traffic-to-malicious-sites/)
				* TL;DR: when files are retrieved remotely with the file:// URI scheme on Windows, Windows will fallback to WebDAV when SMB connections can not be established.
	* **Persistence**
		* **Articles/Writeups**
			* [Many ways of malware persistence (that you were always afraid to ask)](http://jumpespjump.blogspot.com/2015/05/many-ways-of-malware-persistence-that.html)
		* **Talks/Presentations/Videos**		
			* [Obtaining and Detecting Domain Persistence - Grant Bugher(DEF CON 23)](https://www.youtube.com/watch?v=gajEuuC2-Dk)
				* When a Windows domain is compromised, an attacker has several options to create backdoors, obscure his tracks, and make his access difficult to detect and remove. In this talk, I discuss ways that an attacker who has obtained domain administrator privileges can extend, persist, and maintain control, as well as how a forensic examiner or incident responder could detect these activities and root out an attacker.
		* **Tools**
			* [Windows-Hunting](https://github.com/beahunt3r/Windows-Hunting)
				* (Has info on Persistence) The Purpose of this repository is to aid windows threat hunters to look for some common artifacts during their day to day operations.
	* **Privilege Escalation**
		* **Articles/Writeups**
			* [Hunting for Privilege Escalation in Windows Environment - Teymur Kheirkhabarov](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)
			* [Windows Privilege Abuse: Auditing, Detection, and Defense - Palantir](https://medium.com/palantir/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)
		* **Talks/Presentations/Videos**
			* [Hunting for Privilege Escalation in Windows Environment - Teymur Kheirkhabarov(OffZone2018)](https://www.youtube.com/watch?v=JGs-aKf2OtU&list=PL0xCSYnG_iTsyu-1GZef-adx5pxBJX4Et&index=27&t=0s)
				* [Slides](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)
	* **Processes**
		* **Articles/Writeups**
			* [Verifying Running Processes against VirusTotal - Domain-Wide - Rob VandenBrink(isc.sans 2019)](https://isc.sans.edu/diary/Verifying+Running+Processes+against+VirusTotal+-+Domain-Wide/25078)
		* **Talks/Presentations/Videos**
			* [Tricking modern endpoint security products - Michel Coene(SANS2020)](https://www.youtube.com/watch?v=xmNpS9mbwEc)
				* The current endpoint monitoring capabilities we have available to us are unprecedented. Many tools and our self/community-built detection rules rely on parent-child relationships and command-line arguments to detect malicious activity taking place on a system. There are, however, ways the adversaries can get around these detections. During this presentation, we'll talk about the following techniques and how we can detect them: Parent-child relationships spoofing; Command-line arguments spoofing; Process injection; Process hollowing
		* **Tools**
			* [PE-Sieve](https://github.com/hasherezade/pe-sieve)
				* [..]tool that helps to detect malware running on the system, as well as to collect the potentially malicious material for further analysis. Recognizes and dumps variety of implants within the scanned process: replaced/injected PEs, shellcodes, hooks, and other in-memory patches. Detects inline hooks, Process Hollowing, Process Doppelgänging, Reflective DLL Injection, etc.
	* **Process Injection**
		* **Articles/Writeups**
			* [Engineering Process Injection Detections - Part 1: Research - Jonathan Johnson(2020)](https://posts.specterops.io/engineering-process-injection-detections-part-1-research-951e96ad3c85)
				* [Code](https://github.com/jsecurity101/Detecting-Process-Injection-Techniques)
		* **Tools**
			* [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
				* Looks for threads that were created as a result of code injection.
	* **PowerShell**
		* **Articles/Writeups**
			* [Revoke -­‐ Obfuscation: PowerShell Obfuscation Detection Using Science](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf)
			* [Attack and Defense Around PowerShell Event Logging - Mina Hao(2019)](https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging)
				* Blogpost discussing logging mechanisms in PowerShell up to v6.
			* [Greater Visibility Through PowerShell Logging - Matthew Dunwoody(2016)](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
			* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
				* a PowerShell Module for Threat Hunting via Windows Event Logs
			* [Securing PowerShell in the Enterprise - Australian Cyber Security Center(2020)](https://www.cyber.gov.au/publications/securing-powershell-in-the-enterprise)
				* This document describes a maturity framework for PowerShell in a way that balances the security and business requirements of organisations. This maturity framework will enable organisations to take incremental steps towards securing PowerShell across their environment; Appendix E - Strings for log analysis
			* [From PowerShell to P0W3rH3LL – Auditing PowerShell - ingmar.koecher(2018)](https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html)
			* [Windows Log Hunting with PowerShell](http://909research.com/windows-log-hunting-with-powershell/)
			* [Uncovering Indicators of Compromise (IoC) Using PowerShell, Event Logs, and a Traditional Monitoring Tool](https://www.sans.org/reading-room/whitepapers/critical/uncovering-indicators-compromise-ioc-powershell-event-logs-traditional-monitoring-tool-36352)
			* [Detecting Offensive PowerShell Attack Tools - adsecurity.org](https://adsecurity.org/?p=2604)
			* [Attack and Defense Around PowerShell Event Logging - Mina Hao(2019)](https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging)
				* This document dwells upon security features of the logging function of major versions of PowerShell, as well as attack means, ideas, and techniques against each version of the event viewer.
			* [Detecting Modern PowerShell Attacks with SIEM - Justin Henderson](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1511980157.pdf)
			* [PowerShell Security: Is itEnough? - Timothy Hoffman](https://www.sans.org/reading-room/whitepapers/microsoft/powershell-security-enough-38815)
				* "This paper aims to analyze a PowerShell-based attack campaign and evaluate each security feature in its ability to effectively prevent or detect the attacksindividually and collectively.  These results will in no way be all inclusive, as technology is ever-changing, andnewmethods are emergingto counteract current security measures"
		* **Talks/Presentations/Videos**
			* [Hunting for PowerShell Abuse - Teymur Kheirkhabarov(Offzone2019)](https://www.youtube.com/watch?v=_zDdf0GGqdA&list=PL0xCSYnG_iTuNQV9RrCLHdnZgthISKxP4&index=4&t=0s)
				* [Slides](https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse)
				* In the presentation author is going to demostrate an approaches for detection of PowerShell abuses based on different event sources like native Windows logging capabilities as well as usage of additional tools, like Sysmon or EDR solutions. How to collect traces of using PowerShell, how to filter out false positives, and how to find evidence of malicious uses among the remaining after filtering volume of events — all these questions will be answered in the talk for present and future threat hunters.
			* [Tracking Activity and Abuse of PowerShell - Carlos Perez(PSConEU 2019)](https://www.youtube.com/watch?v=O-80e7z4THo)
				* [Slides](https://github.com/darkoperator/Presentations/blob/master/PSConfEU%202019%20Tracking%20PowerShell%20Usage.pdf)
			* [Investigating PowerShell Attacks - Ryan Kazanciyan, Matt Hastings(BHUSA2014)](https://www.youtube.com/watch?v=zUbTM9N7V7w)
				* [Paper](https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks-WP.pdf)
				* This presentation will focus on common attack patterns performed through PowerShell - such as lateral movement, remote command execution, reconnaissance, file transfer, and establishing persistence - and the sources of evidence they leave behind. We'll demonstrate how to collect and interpret these forensic artifacts, both on individual hosts and at scale across the enterprise. Throughout the presentation, we'll include examples from real-world incidents and recommendations on how to limit exposure to these attacks."
		* **Tooling**
			* [Kansa](https://github.com/davehull/Kansa)
				* A modular incident response framework in Powershell. It's been tested in PSv2 / .NET 2 and later and works mostly without issue. It uses Powershell Remoting to run user contributed, ahem, user contri- buted modules across hosts in an enterprise to collect data for use during incident response, breach hunts, or for building an environmental baseline.
	* **ShimCache**
		* **Articles/Writeups**
			* [Is Windows ShimCache a threat hunting goldmine? - Tim Bandos](https://www.helpnetsecurity.com/2018/07/10/windows-shimcache-threat-hunting/)
	* **Services**
		* [Services: Windows 10 Services(ss64)](https://ss64.com/nt/syntax-services.html)
			* A list of the default services in Windows 10 (build 1903).
	* **Sysmon**
		* **101**
			* [Sysinternals Sysmon suspicious activity guide - blogs.technet](https://blogs.technet.microsoft.com/motiba/2017/12/07/sysinternals-sysmon-suspicious-activity-guide/)
			* [SysmonCommunityGuide](https://github.com/trustedsec/SysmonCommunityGuide)
				* TrustedSec Sysinternals Sysmon Community Guide
			* [(SwiftOnSecurity's )sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
				* Sysmon configuration file template with default high-quality event tracing
		* **Articles/Writeups**
			* [SysInternals: SysMon Unleashed](https://blogs.technet.microsoft.com/motiba/2016/10/18/sysinternals-sysmon-unleashed/)
			* [Threat Hunting: Fine Tuning Sysmon & Logstash to find Malware Callbacks C&C - Pablo Delgado](https://www.syspanda.com/index.php/2018/07/30/threat-hunting-fine-tuning-sysmon-logstash-find-malware-callbacks-cc/)
			* [Tales of a Blue Teamer: Detecting Powershell Empire shenanigans with Sysinternals - Spartan2194(2019)](https://holdmybeersecurity.com/2019/02/27/sysinternals-for-windows-incident-response/)
			* [Visualise Sysmon Logs and Detect Suspicious Device Behaviour -SysmonSearch-](https://blogs.jpcert.or.jp/en/2018/09/visualise-sysmon-logs-and-detect-suspicious-device-behaviour--sysmonsearch.html)
				* JPCERT/CC has developed and released a system “SysmonSearch” which consolidates Sysmon logs to perform faster and more accurate log analysis. We are happy to introduce the details in this article.
			* [Investigate Suspicious Account Behaviour Using SysmonSearch](https://blogs.jpcert.or.jp/en/2019/02/sysmonsearch2.html)
				* In a past article in September 2018, we introduced a Sysmon log analysis tool "SysmonSearch" and its functions. Today, we will demonstrate how this tool can be used for incident investigation by showing some examples.
		* **Talks & Presentations**
			* [Implementing Sysmon and Applocker - BHIS](https://www.youtube.com/watch?v=9qsP5h033Qk)
				* In almost every BHIS webcast we talk about how important application whitelisting and Sysmon are to a healthy security infrastructure. And yet, we have not done a single webcast on these two topics. Let's fix that. In this webcast we cover how to implement Sysmon and Applocker. We cover overall strategies for implementation and how to deploy them via Group Policy. We walk through a basic sample of malware and show how both of these technologies react to it. Finally, we cover a couple of different "bypass" techniques for each. Everything in security has weaknesses, and these two technologies are no exception.
			* [Endpoint Detection Super Powers on the cheap, with Sysmon - Olaf Harton(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-36-endpoint-detection-super-powers-on-the-cheap-with-sysmon-olaf-hartong)
				* Based on my experience as a blue and purple teamer I wanted to create a workflow toolkit for anyone with access to Splunk to get started with a set of tools that enables them to hit the ground running on a tight budget without compromising on quality. I will explain the pain of lacking visibility in a common Enterprise environment. I will present my hunting app, which contains over 150 searches and over 15 dashboards. Knowledge is power; The workflow has been intentionally built on generic searches to cover all attack variations, to be able to uncover most potentially malicious behaviour. The dashboards contain overviews, threat indicators and facilitate consecutive drilldown workflows to help the analyst determine whether this is a threat or not and allow them to whitelist.
	* **WMI**
		* **Articles/Writeups**
			* [Investigating WMI Attacks - Chad Tilbury(2019)](https://www.sans.org/blog/investigating-wmi-attacks/)
		* **Talks & Presentations**
	* **Talks & Presentations**
	* **Tools**
		* [BLUESPAWN](https://github.com/ION28/BLUESPAWN)
			* BLUESPAWN is an active defense and endpoint detection and response tool which means it can be used by defenders to quickly detect, identify, and eliminate malicious activity and malware across a network.
* **Simulation & Testing**<a name='simulation'></a>
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
	* **Tools**
		* **Data Sets**
			* [Mordor](https://github.com/Cyb3rWard0g/mordor)
				* The Mordor project provides pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files for easy consumption. The pre-recorded data is categorized by platforms, adversary groups, tactics and techniques defined by the Mitre ATT&CK Framework. The pre-recorded data represents not only specific known malicious events but additional context/events that occur around it. This is done on purpose so that you can test creative correlations across diverse data sources, enhancing your detection strategy and potentially reducing the number of false positives in your own environment.
	


### Threat Analysis
* **Tools**
	* [Danger-Zone](https://github.com/woj-ciech/Danger-zone)
		* Correlate data between domains, IPs and email addresses, present it as a graph and store everything into Elasticsearch and JSON files.


### Data Storage & Analysis Stacks<a name="stacks"></a>
* **ELK Stack**<a name="elk"></a>
	* **101**
		* [Introduction and Demo to the Elasticsearch, Logstash and Kibana](https://www.youtube.com/watch?v=GrdzX9BNfkg)
	* **Setting up a lab**
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
* **Graylog**<a name="gray"></a>
	* **Setting up a lab**
		* [No More Secrets: Logging Made Easy Through Graylog - VDA Labs]()
			* [Part 1: Installation, securing, and optimizing the setup part 1](https://vdalabs.com/2020/02/20/no-more-secrets-logging-made-easy-through-graylog-part-1/)
			* [Part 2: Installation, securing, and optimizing the setup part 2](https://vdalabs.com/2020/02/21/no-more-secrets-logging-made-easy-through-graylog-part-2/)
			* [Part 3: Domain Controller/DHCP log collection and alerts](https://vdalabs.com/2020/02/26/no-more-secrets-logging-made-easy-through-graylog-part-3/)
			* [Part 4: File/print server log collection and alerts](https://vdalabs.com/2020/03/02/file-and-print-server-logging/)
			* [Part 5: Exchange server log collection](https://vdalabs.com/2020/03/09/exchange-logging-graylog/)
			* [Part 6: IIS log collection](https://vdalabs.com/2020/03/13/graylog-iis/)
			* [Part 7: Firewall log collection](https://vdalabs.com/2020/03/25/graylog-firewall-syslog/)
* **Splunk**<a name='splunk'></a>
* **Articles/Writeups**
		* [Hunting Red Team Empire C2 Infrastructure](http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html)

		* [Hunting in Memory](https://www.endgame.com/blog/technical-blog/hunting-memory)
		* [Taking Hunting to the Next Level Hunting in Memory - Jared Atkinson 2017](https://www.youtube.com/watch?v=3RUMShnJq_I)

	* **Talks & Presentations**
		* [Utilizing SysInternal Tools for IT Pros](http://www.microsoftvirtualacademy.com/training-courses/utilizing-sysinternals-tools-for-it-pros#fbid=1IKsqgyvnWp)



* [Bootsy](https://github.com/IndustryBestPractice/Bootsy)
	* Designed to be installed on a fresh install of raspbian on a raspberry pi, by combining Respounder (Responder detection) and Artillery (port and service spoofing) for network deception, this tool allows you to detect an attacker on the network quickly by weeding out general noisy alerts with only those that matter.