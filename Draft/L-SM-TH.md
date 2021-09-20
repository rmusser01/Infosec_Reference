# Logging(Host/Network) / Security Monitoring / Threat Hunting

------------------------------------------------------------------------------------------------------------------------
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
		- [Flow Data](#flow)
		- [IDS/IPS](#ips)
		- [IDS/IPS Monitoring tools](#ipsmon)
	- [Linux](#linmon)
	- [macOS/OS X](#macmon)
	- [Windows](#winmon)
- [Detection Engineeing](#detect)
	- [Agnostic](#dag)
	- [Network](#dnet)
	- [Linux](#dlin)
	- [macOS](#dmac)
	- [Windows](#dwin)
- [Threat Hunting](#th)
	- [101](#th101)
	- [Data Analysis](#data)
	- [Hunt Experiences/Demonstrations of]
	- [In Memory](#inmem)
	- [Metrics](#thmetrics)
	- [OS Agnostic](#osag)
	- [Network-based](#thnet)
	- [Traffic Analysis](#traffic)
	- [Linux](#thlin)
	- [macOS](#thmac)
	- [Windows](#thwin)
		- []()
	- [Cloud](#cloud)
		- [AWS](#aws)
		- [Azure](#azure)
		- [GCP](#gcp)
	- [Simulation & Testing](#simulation)
	- [Cobalt Strike](#cs)
- [Data Storage & Analysis](#stacks	)
	- [ELK](#elk)
	- [Graylog](#gray)
	- [Splunk](#splunk)
------------------------------------------------------------------------------------------------------------------------

* To Add:
	* OSQuery
	* Auditpol
	* ETW
	* ELK/Splunk/Graylog stuff
	* Zeek/Bro
	* SOAR
	* Jupyter
	* Hunt experiences
	* Mordor
	* Hunter's Forge
	* HELK Lab
	* In-Memory Hunting


------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------

### Logging <a name="logging"></a>
* **101**<a name="101"></a>
	* **Articles/Writeups**
		* [Logs Are Streams, Not Files - Adam Wiggins](https://adam.herokuapp.com/past/2011/4/1/logs_are_streams_not_files/)
	* **Talks/Presentations/Videos**
* **General**
	* **Articles/Writeups**
		* [Log File Monitoring and Alerting - DHound](https://pentesting.dhound.io/blog/critical-security-logs)
	* **Talks/Presentations/Videos**
		* [Logging ALL THE THINGS Without All The Cost With Open Source Big Data Tools - DEFCON22 - Zach Fasel](https://www.youtube.com/watch?v=2AAnVeIwXBo)
			* Many struggle in their job with the decision of what events to log in battle against costly increases to their licensing of a commercial SIEM or other logging solution. Leveraging the open source solutions used for "big-data" that have been proven by many can help build a scalable, reliable, and hackable event logging and security intelligence system to address security and (*cringe*) compliance requirements. We’ll walk through the various components and simple steps to building your own logging environment that can extensively grow (or keep sized just right) with just additional hardware cost and show numerous examples you can implement as soon as you get back to work (or home).
* **Non-OS**<a name="non-os"></a>
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
* **Linux**<a name="linlog"></a>
	* **101**
	* **Articles/Writeups**
		* [Building a SIEM: centralized logging of all Linux commands with ELK + auditd - Security Shenanigans(2020)](https://securityshenaningans.medium.com/building-a-siem-centralized-logging-of-all-linux-commands-with-elk-auditd-3f2e70503933)
	* **Understanding**
	* **Tools**
		* [Syslong-ng](https://github.com/balabit/syslog-ng) 
			* syslog-ng is an enhanced log daemon, supporting a wide range of input and output methods: syslog, unstructured text, message queues, databases (SQL and NoSQL alike) and more.
* **macOS/OS X**<a name="maclog"></a>
	* **101**
		* [Logging - developer.apple](https://developer.apple.com/documentation/os/logging?language=occ)
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
			* [When did my Mac last start up, and why? An exploration with Ulbow - hoakley(2020)](https://eclecticlight.co/2020/01/02/when-did-my-mac-last-start-up-and-why-an-exploration-with-ulbow/)
	* **Unified Log**
		* **101**
			* [Logging(macOS) - developer.apple](https://developer.apple.com/documentation/os/logging)
			* [Unified Logging and Activity Tracing - WWDC2016](https://developer.apple.com/videos/play/wwdc2016/721/)
				* "The new Unified Logging and Tracing System for iOS and macOS uses Activity Tracing for performance, consolidates kernel and user-space logging, and has many other improvements. Learn how Logging and Tracing can help you debug and troubleshoot issues with your apps."
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
			* [Use Windows Event Forwarding to help with intrusion detection - docs.ms](https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection)
			* [Monitoring what matters – Windows Event Forwarding for everyone (even if you already have a SIEM.) - docs.ms(2015)](https://web.archive.org/web/20200402150250/https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem)
			* [Windows Event Forwarding - Centralized logging for everyone! (Even if you already have centralized logging!) - Jessica Payne(2015)](https://web.archive.org/web/20171212201838/https://channel9.msdn.com/Events/Ignite/Australia-2015/INF327)
			* [Use Windows Event Forwarding to help with intrusion detection - docs.ms(2019)](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
				* Learn about an approach to collect events from devices in your organization. This article talks about events in both normal operations and when an intrusion is suspected.
			* [Creating Custom Windows Event Forwarding Logs - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/russellt/creating-custom-windows-event-forwarding-logs)
			* [Windows Event Forwarding: The Best Thing You’ve Never Heard Of - Josh Frantz(2018)](https://blog.rapid7.com/2018/12/18/windows-event-forwarding-the-best-thing-youve-never-heard-of/)
		* **Articles/Writeups**
			* [Windows Event Logging and Forwarding - Australian Cybersecurity Center](https://www.cyber.gov.au/publications/windows-event-logging-and-forwarding)
				* This document has been developed as a guide to the setup and configuration of Windows event logging and forwarding. This advice has been developed to support both the detection and investigation of malicious activity by providing an ideal balance between the collection of important events and management of data volumes. This advice is also designed to complement existing host-based intrusion detection and prevention systems.  This document is intended for information technology and information security professionals. It covers the types of events which can be generated and an assessment of their relative value, centralised collection of event logs, the retention of event logs, and recommended Group Policy settings along with implementation notes.
				* [Paper - 2019](https://web.archive.org/web/20200507235341/https://www.cyber.gov.au/sites/default/files/2019-05/PROTECT%20-%20Windows%20Event%20Logging%20and%20Forwarding%20%28April%202019%29_0.pdf)
				* [Australian Cyber Security Center's Windows Event Logging repository](https://github.com/AustralianCyberSecurityCentre/windows_event_logging)
			* [Windows Event Forwarding Guidance - Palantir](https://github.com/palantir/windows-event-forwarding) 
				* Over the past few years, Palantir has a maintained an internal Windows Event Forwarding (WEF) pipeline for generating and centrally collecting logs of forensic and security value from Microsoft Windows hosts. Once these events are collected and indexed, alerting and detection strategies (ADS) can be constructed not only on high-fidelity security events (e.g. log deletion), but also for deviations from normalcy, such as unusual service account access, access to sensitive filesystem or registry locations, or installation of malware persistence. The goal of this project is to provide the necessary building blocks for organizations to rapidly evaluate and deploy WEF to a production environment, and centralize public efforts to improve WEF subscriptions and encourage adoption. While WEF has become more popular in recent years, it is still dramatically underrepresented in the community, and it is our hope that this project may encourage others to adopt it for incident detection and response purposes. We acknowledge the efforts that Microsoft, IAD, and other contributors have made to this space and wish to thank them for providing many of the subscriptions, ideas, and techniques that will be covered in this post.
			* [Event-Forwarding-Guidance - NSA](https://github.com/nsacyber/Event-Forwarding-Guidance)
				* Configuration guidance for implementing collection of security relevant Windows Event Log events by using Windows Event Forwarding.
			* [Xpath Event Log Filtering - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/kfalde/xpath-event-log-filtering)
			* [Windows Event Forwarding for Network Defense - Palantir](https://medium.com/palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)
			* [End-Point Log Consolidation with Windows Event Forwarder - Derek Banks(2017)](https://www.blackhillsinfosec.com/end-point-log-consolidation-windows-event-forwarder/)
			* [The Windows Event Forwarding Survival Guide - Chris Long(2017)](https://hackernoon.com/the-windows-event-forwarding-survival-guide-2010db7a68c4)
			* [Setting up Windows Event Forwarder Server (WEF) (Domain) Part 1/3 - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-part-13/)
				* [Setting up Windows Event Forwarder Server (WEF) (Domain) – Sysmon Part 2/3 - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-sysmon-part-23/)
				* [Setting up Windows Event Forwarder Server (WEF) (Domain) – GPO Deployment Part 3/3 - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-gpo-deployment-part-33/)
			* [How To Set Up Windows Event Log Forwarding In Windows Server 2016 - Jeff Christman(2019)](https://adamtheautomator.com/windows-event-collector/)
		* **Custom Logs**
			* [Introducing Project Sauron - Centralised Storage of Windows Events - Domain Controller Edition - docs.ms(2017)](https://docs.microsoft.com/en-us/archive/blogs/russellt/project-sauron-introduction)
				* [Code](https://github.com/russelltomkins/project-sauron)
			* [Creating Custom Windows Event Forwarding Logs - docs.ms(2016)](https://web.archive.org/web/20200508010912/https://docs.microsoft.com/en-us/archive/blogs/russellt/creating-custom-windows-event-forwarding-logs)
		* **Filtering/XPath**
			* [XPath - Wikipedia](https://en.wikipedia.org/wiki/XPath)
			* [XPath Standard Documentation](https://www.w3.org/TR/xpath/all/)
			* [Advanced XML filtering in the Windows Event Viewer - Ned Pyle(2011)](https://web.archive.org/web/20190712091207/https://blogs.technet.microsoft.com/askds/2011/09/26/advanced-xml-filtering-in-the-windows-event-viewer/)
			* [Advanced XML filtering in the Windows Event Viewer - Joji Oshima2011](https://docs.microsoft.com/en-us/archive/blogs/askds/advanced-xml-filtering-in-the-windows-event-viewer)
			* [Consuming Events - docs.ms(2015)](https://docs.microsoft.com/en-us/windows/win32/wes/consuming-events?redirectedfrom=MSDN#limitations)
		* **Tools**
			* [WEFFLES](https://github.com/jepayneMSFT/WEFFLES)
				* Build a fast, free, and effective Threat Hunting/Incident Response Console with Windows Event Forwarding and PowerBI 
				* [Blogpost](https://web.archive.org/web/20200308233607/https://blogs.technet.microsoft.com/jepayne/2017/12/08/weffles/)
			* [WindowsEventForwarding](https://github.com/PSSecTools/WindowsEventForwarding)
				* A module for working with Windows Event Collector service and maintain Windows Event Forwarding subscriptions.
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
			* [Event Log Queries Using PowerShell - Dr Scripto(2015)](https://devblogs.microsoft.com/scripting/event-log-queries-using-powershell/)
			* [PowerTip: Query Multiple Event Logs at Once - Dr Scripto(2015)](https://devblogs.microsoft.com/scripting/powertip-query-multiple-event-logs-at-once/)
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
			* [ EventID Field Hunter (EFH) – Looking for malicious activities in your Windows events - Rodrigo Montoro(Sector.ca2016)](https://sector.ca/sessions/eventid-field-hunter-efh-looking-for-malicious-activities-in-your-windows-events/)
				* In this talk we will discuss how we analyzed and scored each field from those events, ideas for implementation, projects, and results based on our deployment. We will illustrate how you can use EventID as a more powerful detection vector to identify specific user behaviors and activity patterns.
			* [O Event, Where Art Thou? - Grzegorz Tworek(x33fcon2021)](https://www.youtube.com/watch?v=pQTKje_nU4s&list=PL7ZDZo2Xu330UamX3LZeOEGE_VniwyLS5&index=6)
		* **Tools**
			* [EventLogParser](https://github.com/djhohnstein/EventLogParser)
				* Parse PowerShell and Security event logs for sensitive information.
			* [libevtx](https://github.com/libyal/libevtx)
				* Library and tools to access the Windows XML Event Log (EVTX) format
			* [python-evtx](https://github.com/williballenthin/python-evtx)
				* python-evtx is a pure Python parser for recent Windows Event Log files (those with the file extension ".evtx"). The module provides programmatic access to the File and Chunk headers, record templates, and event entries.
			* [evtx](https://github.com/Velocidex/evtx)
				* Golang Parser for Microsoft Event Logs
			* [EVTXtract](https://github.com/williballenthin/EVTXtract)
				* EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.
			* [Windows Event Tools](https://github.com/ohjeongwook/WindowsEventTools)
				* Collection Of Scripts And Utilities For Windows Event Hunting 
			* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter)
				* [Blogpost](https://shells.systems/introducing-apt-hunter-threat-hunting-tool-via-windows-event-log/)
				* APT-Hunter is Threat Hunting tool for windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity. this tool will make a good use of the windows event logs collected and make sure to not miss critical events configured to be detected. If you are a Threat Hunter, Incident Responder or forensic investigator, i assure you will enjoy using this tool, why? i will discuss the reason in this article and how it will make your life easy just it made mine. Kindly note this tool is heavily tested but still a beta version and may contain bugs.
			* [evtx-hunter](https://github.com/NVISOsecurity/evtx-hunter)
				* evtx-hunter helps to quickly spot interesting security-related activity in Windows Event Viewer (EVTX) files.
	* **Event Tracing for Windows**<a name="etw"></a>
		* **101**
			* [Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
			* [About Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
			* [Using Event Tracing - docs.ms](https://docs.microsoft.com/en-us/windows/win32/etw/using-event-tracing)
			* [Event Tracing for Windows - Core OS Events in Windows 7, Part 1 - Dr. Insung Park, Alex Bendetovers](https://docs.microsoft.com/en-us/archive/msdn-magazine/2009/september/core-os-events-in-windows-7-part-1)
				* [Part 2](https://docs.microsoft.com/en-us/archive/msdn-magazine/2009/october/core-instrumentation-events-in-windows-7-part-2)
			* [Windows 10 ETW Events](https://github.com/jdu2600/Windows10EtwEvents)
				* Events from all manifest-based and mof-based ETW providers across Windows 10 versions
			* [Tracing WMI Activity - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity)
			* [Introduction to Threat Intelligence ETW - NtRaiseHardError(2020)](https://undev.ninja/introduction-to-threat-intelligence-etw/)
		* **Articles/Blogposts/Writeups**
			* [A Primer On Event Tracing For Windows (ETW) - Nasreddine Bencherchali(2021)](https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf)
			* [ETW Event Tracing for Windows and ETL Files - Nicole Ibrahim](https://www.hecfblog.com/2018/06/etw-event-tracing-for-windows-and-etl.html)
			* [SilkETW: Because Free Telemetry is … Free! - Ruben Boonnen](https://www.fireeye.com/blog/threat-research/2019/03/silketw-because-free-telemetry-is-free.html)
				* [Slides](https://github.com/FuzzySecurity/BH-Arsenal-2019/blob/master/Ruben%20Boonen%20-%20BHArsenal_SilkETW_v0.2.pdf)
			* [Windows Event Trace Logs - Nicole Ibrahim](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1528388048.pdf)
			* [Tampering with Windows Event Tracing: Background, Offense, and Defense - Palantir](https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
			* [Getting started with Event Tracing for Windows in C# - Alex Khanin](https://medium.com/@alexkhanin/getting-started-with-event-tracing-for-windows-in-c-8d866e8ab5f2)
			* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
				* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it-s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What-s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."
			* [Threat Hunting with ETW events and HELK — Part 1: Installing SilkETW - Roberto Rodriguez(2019)](https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-1-installing-silketw-6eb74815e4a0)
			* [German Gov Paid for Research into ETW](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/Workpackage4_Telemetry.pdf?__blob=publicationFile&amp;v=2)
		* **Talks/Videos**
			* [Production tracing with Event Tracing for Windows (ETW) - Doug Cook](https://channel9.msdn.com/Events/Build/2017/P4099)
			* [Tracing Adversaries: Detecting Attacks with ETW -  Matt Hastings & Dave Hull(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/s25-tracing-adversaries-detecting-attacks-with-etw-matt-hastings-dave-hull)
				* Event Tracing for Windows (ETW) is a powerful debugging and system telemetry feature that's been available since Windows 2000, but greatly expanded in recent years. Modern versions of Windows offer hundreds of ETW providers that are a veritable treasure trove of forensic data. This talk will take a fresh look at operationalizing ETW to combat contemporary intrusion methodologies and tradecraft. We'll walk through real world examples, covering both common malware behaviors and stealthy attacks that "live off the land", and demonstrate how to effectively utilize key ETW providers to detect and respond to these techniques.
			* [ETW - Monitor Anything, Anytime, Anywhere - Dina Goldshtein(NDC Oslo 2017)](https://www.youtube.com/watch?v=ZNdpLM4uIpw)
				* You’ll learn how to diagnose incredibly complex issues in production systems such as excessive garbage collection pauses, slow startup due to JIT and disk accesses, and even sluggishness during the Windows boot process. We will also explore some ways to automate ETW collection and analysis to build self-diagnosing applications that identify high CPU issues, resource leaks, and concurrency problems and produce alerts and reports. In the course of the talk we will use innovative performance tools that haven’t been applied to ETW before — flame graphs for visualising call stacks and a command-line interface for dynamic, scriptable ETW tracing. ETW is truly a window into everything happening on your system, and it doesn’t require expensive licenses, invasive tools, or modifying your code in any way. It is a critical, first-stop skill on your way to mastering application performance and diagnostics.
			* [Hidden Treasure: Detecting Intrusions with ETW - Zac Brown(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t208-hidden-treasure-detecting-intrusions-with-etw-zac-brown)
				* Today, defenders consume the Windows Event Log to detect intrusions. While useful, audit logs don't capture the full range of data needed for detection and response. ETW (Event Tracing for Windows) is an additional source of events that defenders can leverage to make post-breach activity more visible in Windows. ETW provides a rich set of data, largely intended for debugging scenarios. As a side effect, these traces also have data that is ideal for detecting potentially malicious behavior, such as raw networking data and detailed PowerShell data. Unfortunately, the ETW API is low level and primitive, making it difficult to use at scale reliably. Because our security team in Office 365 supports monitoring over 150,000 machines, we needed a reliable way to consume the events in real-time, while adhering to strict memory and CPU usage constraints. To accomplish this, our team built the open-source krabsetw library to simplify dynamically consuming ETW events. We currently use this library to collect 6.5TB of data per day, from our service. In this talk, we’ll discuss a few ETW sources we’ve found to be high value as well as the detections they enable. We’ll also demo an example of using krabsetw as well as some considerations in using ETW in your intrusion detection pipeline at scale.
			* [Windows Forensics: Event Trace Logs - Nicole Ibrahim(SANS DFIR Summit 2018)](https://www.youtube.com/watch?v=TUR-L9AtzQE)
				* This talk will cover what ETL files are and where you can expect to find them, how to decode ETL files, caveats associated with those files, and some interesting and forensically relevant data that ETL files can provide. 
		* **Tools**
			* [SilkETW & SilkService](https://github.com/fireeye/SilkETW)
				* SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection. While both projects have obvious defensive (and offensive) applications they should primarily be considered as research tools. For easy consumption, output data is serialized to JSON. The JSON data can either be written to file and analyzed locally using PowerShell, stored in the Windows eventlog or shipped off to 3rd party infrastructure such as Elasticsearch.
			* [ETW Python Library](https://github.com/fireeye/pywintrace)
				* ETW is a tracing facility that allows a user to log events to a file or buffer. An overview of ETW can be found [here](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363668(v=vs.85).aspx). The basic architecture includes an Provider, Controller, and a Consumer. The controller defines and controls a capture session. This includes what providers are in the as well as starting and stopping the session. The provider, specified using a GUID (Globally Unique Identifier), logs events to a series of buffers. The Consumer receives messages either from a buffer or a file and processes them in chronological order. This module is an entirely Python-based ctypes wrapper around the Win32 APIs necessary for for controlling ETW sessions and processing message data. The module is very flexible and can set pre or post capture filters.
			* [EtwExplorer](https://github.com/zodiacon/EtwExplorer)
				* View ETW Provider metadata
			* [KrabsETW](https://github.com/microsoft/krabsetw)
				* KrabsETW provides a modern C++ wrapper and a .NET wrapper around the low-level ETW trace consumption functions. 
			* [ProcMonX](https://github.com/zodiacon/ProcMonX)
				* Extended Process Monitor-like tool based on Event Tracing for Windows
			* [ProcMonXv2](https://github.com/zodiacon/ProcMonXv2)
			* [Sealighter](https://github.com/pathtofile/Sealighter)
				* Sysmon-Like research tool for ETW
			* [etwbreaker](https://github.com/airbus-cert/etwbreaker)
				* An IDA Plugin to statically find ETW events in a PE file and generate a Conditional Breakpoint to facilitate Security Research.
			* [UIforETW](https://github.com/google/UIforETW)
				* User interface for recording and managing ETW traces 
* [TiEtwAgent](https://github.com/xinbailu/TiEtwAgent)
	* PoC memory injection detection agent based on ETW, for offensive and defensive research purposes 

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
			* [about_Logging_Windows - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7)
				* PowerShell logs internal operations from the engine, providers, and cmdlets to the Windows event log.
		* **Articles/Blogposts/Writeups**
			* [Greater Visibility Through PowerShell Logging - (2016)](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
			* [PowerShell Logging for the Blue Team - Joff Thyer(2016)](https://www.blackhillsinfosec.com/powershell-logging-blue-team/)
			* [Practical PowerShell Security: Enable Auditing and Logging with DSC - Ashley McGlone(2017)](https://blogs.technet.microsoft.com/ashleymcglone/2017/03/29/practical-powershell-security-enable-auditing-and-logging-with-dsc/)
			* [Everything You Need To Know To Get Started Logging PowerShell - robwillisinfo(2019)](http://robwillis.info/2019/10/everything-you-need-to-know-to-get-started-logging-powershell/)
			* [PowerDrive: Accurate De-Obfuscation and Analysis of PowerShell Malware - Denis Ugarte1, Davide Maiorca1, Fabrizio Cara1, Giorgio Giacinto(2019)](http://pralab.diee.unica.it/sites/default/files/dimva19-paper76-final.pdf)
			* [ Detecting Malicious PowerShell - Austin Reid(2021)](https://blog.cyberabilities.ca/2021/01/detecting-malicious-powershell.html)
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
			* [Hunting PowerShell Attacks on The Open Internet - Paul Melson(2019)](https://www.youtube.com/watch?v=pY-xTjJl-yw&list=PLEJJRQNh3v_PF6cecq0ES2w25JtoG631g&index=16)
			* [ Hunting for PowerShell Abuse - Heirhabarov(2019)](https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=2)
				* Because of so prevalence of PowerShell among adversaries for Threat Hunters it is very important to be able to detect malicious uses of PowerShell and defend against it. In the presentation author is going to demostrate an approaches for detection of PowerShell abuses based on different event sources like native Windows logging capabilities as well as usage of additional tools, like Sysmon or EDR solutions. How to collect traces of using PowerShell, how to filter out false positives, and how to find evidence of malicious uses among the remaining after filtering volume of events — all these questions will be answered in the talk for present and future threat hunters.
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
			* [PSTrace](https://github.com/airbus-cert/PSTrace)
				* Trace ScriptBlock execution for powershell v2
	* **WMI**
		* [WMI-IDS](https://github.com/fireeye/flare-wmi/tree/master/WMI-IDS)
			* WMI-IDS is a proof-of-concept agent-less host intrusion detection system designed to showcase the unique ability of WMI to respond to and react to operating system events in real-time.
	
	* [PowerShell Deobfuscation with Curtain - Jeff White(2017)](http://ropgadget.com/posts/intro_curtain.html)
		* In this post I want to give a brief introduction to a new tool I'm working on called "Curtain". It will be complimentary to another post I'm working on for $dayjob where I created a Curtain Cuckoo module. Curtain is basically just a small script that can be used to detonate malicious files or PowerShell scripts and then scrape out the ScriptBlock logs for fast analysis. I'll go into the concept behind it more in my other post.




















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
* **File Analysis**
	* [BinaryAlert](https://github.com/airbnb/binaryalert)
		* BinaryAlert is an open-source serverless AWS pipeline where any file uploaded to an S3 bucket is immediately scanned with a configurable set of YARA rules. An alert will fire as soon as any match is found, giving an incident response team the ability to quickly contain the threat before it spreads.
	* [StreamAlert](https://github.com/airbnb/streamalert)
		* StreamAlert is a serverless, real-time data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using data sources and alerting logic you define. Computer security teams use StreamAlert to scan terabytes of log data every day for incident detection and response.
* **Infrastructure Monitoring**<a name="inframon"></a>
	* [Ninja Level Infrastructure Monitoring Workshop - Defcon24](https://github.com/appsecco/defcon24-infra-monitoring-workshop)
		* This repository contains all the presentation, documentation and the configuration, sample logs, ansible playbook, customized dashboards and more.
* **Network-based**<a name="netmon"></a>
	* **101**
	* **Articles/Writeups**
		* [Making the Most of OSSEC](http://www.ossec.net/files/Making_the_Most_of_OSSEC.pdf)
		* [Using SiLK for Network  Traffic Analysis](https://tools.netsa.cert.org/silk/analysis-handbook.pdf)
		* [Current State of Virtualizing Network Monitoring](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t202-current-state-of-virtualizing-network-monitoring-daniel-lohin-ed-sealing)
	* **Talks/Presentations**
		* [Passive IPS Reconnaissance and Enumeration - false positive (ab)use - Arron Finnon](https://vimeo.com/108775823)
			* Network Intrusion Prevention Systems or NIPS have been plagued by "False Positive" issues almost since their first deployment. A "False Positive" could simply be described as incorrectly or mistakenly detecting a threat that is not real. A large amount of research has gone into using "False Positive" as an attack vector either to attack the very validity of an IPS system or to conduct forms of Denial of Service attacks. However the very reaction to a "False Positive" in the first place may very well reveal more detailed information about defences than you might well think.
		* [You Pass Butter: Next Level Security Monitoring Through Proactivity](http://www.irongeek.com/i.php?page=videos/nolacon2016/110-you-pass-butter-next-level-security-monitoring-through-proactivity-cry0-s0ups)

	* **Flow-Data**<a name="flow"></a>
		* **Talks/Presentations/Videos**
			* [Go with the Flow: Get Started with Flow Analysis Quickly and Cheaply - Jason Smith(2016](https://www.irongeek.com/i.php?page=videos/derbycon6/500-go-with-the-flow-get-started-with-flow-analysis-quickly-and-cheaply-jason-smith)
				* Some people love buzzwords. I hate them personally. This is especially true for zazzy terms that describe things people have been doing or dealing with for ages. This talk will focus on setting up a next generation platform that will allow you to take control of big data, and hone your hunting skills at the same time. I'm kidding. Whats old is new again, so we're diving into some network flow data. I'll show you how to set it up quickly (less than 10 minutes) and for free (hardware not included). I'll also be showing you how to get started with analysis using some common and not-so-common situations.
		* **Papers**
			* [Network Profiling Using Flow - (2012](https://resources.sei.cmu.edu/asset_files/technicalreport/2012_005_001_28167.pdf)
				* This report provides a step-by-step guide for profiling—discovering public-facing assets on a  network—using network flow (netflow) data. Netflow data can be used for forensic purposes, for  finding malicious activity, and for determining appropriate prioritization settings. The goal of this  report is to create a profile to see a potential  attacker’s view of an external network.   Readers will learn how to choose a data set, find the top assets and services with the most traffic  on the network, and profile several services. A cas e study provides an example of the profiling  process. The underlying concepts of using netflow data are presented so that readers can apply the  approach to other cases. A reader using this repor t to profile a network can expect to end with a  list of public-facing assets and the ports on which  each is communicating and may also learn other  pertinent information, such as external IP addresses, to which the asset is connecting. This report  also provides ideas for using, maintaining, and reporting on findings. The appendices include an  example profile and scripts for running the commands in the report. The scripts are a summary  only and cannot replace reading and understanding this report.
	* **PCAPs**<a name="pcap"></a>
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
* **OSQuery**<a name="osquery"></a>
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
* **macOS/OS X**<a name="macmon"></a>
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
		* [Sinter](https://github.com/trailofbits/sinter)
			* Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above, written in Swift.  Sinter uses the user-mode EndpointSecurity API to subscribe to and receive authorization callbacks from the macOS kernel, for a set of security-relevant event types. The current version of Sinter supports allowing/denying process executions; in future versions we intend to support other types of events such as file, socket, and kernel events.
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
	* **Sysdiagnose**
		* [Mac OS X Sysdiagnose – Advanced Mac Troubleshooting Diagnostics - becomethesolution.com](https://becomethesolution.com/blogs/mac/mac-os-x-sysdiagnose-advanced-mac-troubleshooting-diagnostics)
		* [sysdiagnose(1) [osx man page]](https://www.unix.com/man-page/osx/1/sysdiagnose/)
		* [sysdiag-who? - Harry Senior(2020)](https://labs.f-secure.com/blog/sysdiag-who/)
			* sysdiagnose is a utility on most macOS and iOS devices that can be used to gather system-wide diagnostic information. Currently on version 3.0, sysdiagnose collects a large amount of data from a wide array of locations on the system. This blog post will seek to outline the immediate value of the data collected by sysdiagnose for the purpose of an investigation.
* **Windows**<a name="winmon"></a>
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
		* [The Detection Maturity Level Model - Ryan Stillion(2014)](https://web.archive.org/web/20200501220417/http://ryanstillions.blogspot.com/web/20191003131310/http://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html)
		* [Capability Abstraction - Jared Atkinson](https://posts.specterops.io/capability-abstraction-fbeaeeb26384)
			* This is the first of a multipart blog series by the SpecterOps detection team. The goal of this series is to introduce and discuss foundational detection engineering concepts. To make these concepts as consumable as possible, we are focusing the entire series around Kerberoasting. Focusing on this technique allows readers to focus on the strategies presented in each article instead of worrying about the details of the technique itself. The focus of this post is a concept we call “capability abstraction.” The idea is that an attacker’s tools are merely an abstraction of their attack capabilities, and detection engineers must understand how to evaluate abstraction while building detection logic.
		* [What’s in a name? TTPs in Info Sec - Robby Winchester(2017)](https://posts.specterops.io/whats-in-a-name-ttps-in-info-sec-14f24480ddcc)
		* [Lessons Learned in Detection Engineering - Ryan McGeehan(2017)](https://medium.com/starting-up-security/lessons-learned-in-detection-engineering-304aec709856)
		* [Uncovering The Unknowns - Jonathan Johnson(2019)](https://posts.specterops.io/uncovering-the-unknowns-a47c93bb6971)
			* Mapping Windows API’s to Sysmon Events
		* [Getting Started with ATT&CK: Detection and Analytics - John Wunder(2019)](https://medium.com/mitre-attack/getting-started-with-attack-detection-a8e49e4960d0)
		* [Can We Have “Detection as Code”? - Anton Chuvakin(2020](https://medium.com/anton-on-security/can-we-have-detection-as-code-96f869cfdc79)
		* [Introducing the Funnel of Fidelity - Jared Atkinson(2019)](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036)
		* [Detection Spectrum - Jared Atkinson(2020)](https://posts.specterops.io/detection-spectrum-198a0bfb9302)
		* [Capability Abstraction - Jared Atkinson(2020)](https://posts.specterops.io/capability-abstraction-fbeaeeb26384)
		* [Detection In Depth - Joshua Prager(2020)](https://bouj33boy.com/detection-in-depth/)
		* [Detections of Past, Present, and Future - Robby Winchester(2020)](https://posts.specterops.io/detections-of-past-present-and-future-26af95517e77)
		* [Implementing DevOps and CI/CD Pipelines to Detection Engineering - Mehmet Ergene(2020)](https://posts.bluraven.io/implementing-devops-and-ci-cd-pipelines-to-detection-engineering-885ca5878614)
		* [Dissecting a Detection: An Analysis of ATT&CK Evaluations Data (Sources) Part 1 of 2 - Jamie Williams(2020)](https://medium.com/mitre-attack/dissecting-a-detection-part-1-19fd8f00266c)
		* [Detection Engineering Maturity Matrix - Kyle Bailey(2021](https://kyle-bailey.medium.com/detection-engineering-maturity-matrix-f4f3181a5cc7)
			* [Detection Engineering Maturity Matrix](https://github.com/k-bailey/detection-engineering-maturity-matrix)
		* [Playing Detection with a Full Deck - Jared Atkinson(2021)](https://posts.specterops.io/thoughts-on-detection-3c5cab66f511)
		* [The why, what, and how of threat research - Matt Graeber(2020)](https://redcanary.com/blog/threat-research-questions/)
	* **Talks & Presentations**
		* [Waking up the data engineer in you! - Jared Atkinson(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-34-waking-up-the-data-engineer-in-you-jared-atkinson)
			* At almost every company we visit, we find that there is a disconnect between data engineers and security analysts. Security analysts are responsible for using available data to find potential adversaries, while data engineers are responsible for securing, standardizing, and making data available for analysts. It may seem obvious that these two roles should work together, but it is usually not the case which limits how analysts can use data and technology to detect adversaries. This talk focuses on why it is important for security analysts to understand data engineering basics before building detections. We will use a detection use case to show how a non-scalable process can be made into an efficient detection by looking at telemetry as the foundation of a strong detection capability.
		* [$SignaturesAreDead = “Long Live RESILIENT Signatures” wide ascii nocase - Matthew Dunwoody, Daniel Bohannon(BruCON 0x0A)](https://www.youtube.com/watch?v=YGJaj6_3dGA)
			* Signatures are dead, or so we're told. It's true that many items that are shared as Indicators of Compromise (file names/paths/sizes/hashes and network IPs/domains) are no longer effective. These rigid indicators break at the first attempt at evasion. Creating resilient detections that stand up to evasion attempts by dedicated attackers and researchers is challenging, but is possible with the right tools, visibility and methodical (read iterative) approach.   As part of FireEye's Advanced Practices Team, we are tasked with creating resilient, high-fidelity detections that run across hundreds of environments and millions of endpoints. In this talk we will share insights on our processes and approaches to detection development, including practical examples derived from real-world attacks.
		* [The Unified Kill Chain: Designing a Unified Kill Chain for analyzing, comparing and defending against cyber attacks - Mr. drs. Paul Pols(2017)](https://www.csacademy.nl/images/scripties/2018/Paul-Pols---The-Unified-Kill-Chain.pdf)
			* "In this thesis,a Unified Kill Chain(UKC)modelis developedthat focuses on the tactics that form the consecutive phases of cyber attacks(Table 1). Ahybrid research approach is used to develop the UKC,combiningdesign science with qualitative research methods. The UKC is first developed through literature study, extendingthe CKC by uniting improvements that were previously proposed by other authors withthe tactics of MITRE’s ATT&CK™model. The UKC is subsequently iteratively evaluatedand improved through case studies of attacksby Fox-IT’s Red Team and APT28(alias Fancy Bear). The resulting UKC is a meta model that supports the development of end-to-end attack specific kill chains and actor specific kill chains, that can subsequently be analyzed, compared and defended against."
		* [The Art of Detection - Jay Dimartino(DEFCON27 Packet Hacking Village)](https://www.youtube.com/watch?v=68-sFqv4FJE&list=PL9fPq3eQfaaButbVrT4iuAGpdLhCjEjM_&index=15)
			* Ever inherited a security rule you were afraid to modify? Ever import a Yara rule only to have the alerts blow up in your face? Does your SEIM or security appliance keep you up at night with email alerts? The Art of Detection focuses on the methodology of writing and sharing accurate detections to make you a better detection author. Gain confidence in managing false positives, learn rule sharing best practices, tackle large monolithic detections, and write detections that feed other detections. Learn the importance of your intelligence test data, and if your intelligence streams could be causing bias.
		* [The return of detection engineering: detection development using CI/CD - Patrick Bareiß(x33fcon2020)](https://www.youtube.com/watch?v=3JmHBa7q91o&list=PL7ZDZo2Xu330gMHAoeGvH9QkCJMC-qgeK&index=3)
			* The later you find a bug in your detections, the more expensive it is to solve it! Therefore, the presenters will introduce CI pipelines in order to proactively find bugs in detection rules, before they are deployed in production. The CI pipelines leverage a combination of lab and attack simulation.  Well developed detection rules provide strong signals into anomalous and potentially malicious activity. Poorly developed detection rules flood the analysts with low-level alerts and are the cause of alert fatigue. This talk will introduce a modern approach of detection engineering using Continuous Integration and Continuous Delivery (CI/CD). The later you find a bug in your detections, the more expensive it is to solve it! Therefore, the presenter will introduce CI pipelines in order to proactively find bugs in detection rules, before they are deployed in production. In order to successfully test the effectiveness of your detection, you need a lab and an attack simulation engine. The attack range combines both a lab and attack simulation into an easy to use tool. The presenter will introduce the attack range tool and show how you can integrate it into your CI/CD pipeline to automatically test your detections. Lastly, the presenter will share how CD can automatically deliver the detection rules to the SIEM via either a package or over an API.
		* [Rethinking Detection Engineering – Jared Atkinson (SO-CON 2020)](https://www.youtube.com/watch?v=CRtmeWCbRZQ&list=PLJK0fZNGiFU-2vFpjnt96j_VSuQVTkAnO&index=16)
			* Psychologist Jean Piaget is renown for his investigation into cognitive development and how we learn to deal with abstract concepts. In Information Security we often deal with abstract concepts like "find evil" or "detect malicious activity," however it is often difficult to break these down from the abstract concept into their specific elements. In this talk, I will discuss my perspective of common follies of abstraction in detection, triage, and investigation and how I approach breaking down problems into discrete components.
		* [Understanding Technique Abstraction for Detection Engineers - Jared Atkinson, Luke Paine, and Jonny](https://www.youtube.com/watch?v=Xxj-jvNQWHU&list=PLJK0fZNGiFU-2vFpjnt96j_VSuQVTkAnO&index=19)
			* Have you ever struggled to build a detection because you didn't know where to start? In sports, it is important to understand strengths and weaknesses of your opponent. Before a game, teams study their opponents in painstaking detail to make sure they understand what they are up against. Not only can this approach win championships, but it can help build powerful detections. In this workshop you will learn to look past the superficial nature of attack tools, revealing how tools are a simple abstraction layer hiding the inner workings of a technique. We will use this understanding to discuss and demonstrate how this understanding can be used to build detections beyond simple tool signatures.
		* [Converting Blue Team Expertise of Customer Networks into Advanced Host-Based Alerting - Stephen Spence(2020)](https://www.youtube.com/watch?v=Jlf-CMFYNtw&list=PLXF21PFPPXTMmtx0XBXqjxSMZSipIMXwX&index=12)
			* What happens when the dream of host event log aggregation is realized and you have to figure out what to do with ALL that data? Through solutions such as Splunk and the Elastic Stack, many blue teamers finally have access to millions/billions of windows event logs, Sysmon, endpoint protection logs, and other log types. Often the challenge of creating alerts off this data looks a lot like attempt to implement Sigma and hope you can alert on evil. This presentation will describe how to transform a blue team’s knowledge of a customer’s network into advanced signature creation. We will cover my experiences in tuning to a customer’s traffic and creating alerts on the negative space, simplify complex Sigma rules, future proof alerts against schema changes, and consider search performance at the same time. Additionally this presentation will show how to take events collected during Red Team engagements and build alerting that is specific to the customer environment that will pay dividends in the future.
		* [Resilient Detection Engineering - Olaf Hartong(WWHF Deadwood2020)](https://www.youtube.com/watch?v=zMPouyUNX5c&list=PLXF21PFPPXTOZ9LsDnCTY0tfio0uxRz41&index=16)
		* [A Voyage to Uncovering RPC Telemetry – Jonathan Johnson (SO-CON 2020)](https://www.youtube.com/watch?v=TEHQwgd7i7Y&list=PLJK0fZNGiFU-2vFpjnt96j_VSuQVTkAnO&index=14)
			* Remote Procedure Calls (RPC) is a core component of the Windows Operating System. This technology is commonly leveraged by adversaries when performing various attacks. "A Voyage to Uncovering Telemetry" provides a walk-through on how Jonathan studied this technology to uncover various telemetry sources that provides detection engineers with the proper insight needed to identify this behavior, whether benign or malicious.
		* [Identifying Novel Malware at Scale - Pedram Amini(SANS HackFest&Ranges Summit2020)](https://www.youtube.com/watch?v=77o60EvxBPI&list=PLdVJWiil7RxoW8rBeKc0flY8bRuD3M68L&index=21&t=0s)
			* It's no secret that client-side attacks are a common source of compromise for many organizations. Web browser and e-mail borne malware campaigns target users by way of phishing, social engineering, and exploitation. Office suites from vendors such as Adobe and Microsoft are ubiquitous and provide a rich and ever-changing attack surface. Poor user awareness and clever social engineering tactics frequently result in users consenting to the execution of malicious embedded logic such as macros, JavaScript, ActionScript, and Java applets. In this talk, we'll explore a mechanism for harvesting a variety of these malware lures for the purposes of dissection and detection.  We'll explore mechanisms for clustering and identifying "interesting" samples. Specifically, we're on the hunt for malware lures that can provide a heads up to defenders on upcoming campaigns as adversaries frequently test their lures against AV consensus. Multiple real-world examples are provided, proving that an astute researcher, can harvest zero-day exploits from the public domain.
	* **Papers**
* **Agnostic**<a name="dag"></a>
	* **Command-Line Obfuscation**
		* **Tools**
			* [Flerken](https://github.com/We5ter/Flerken)
				* This talk first shares some key observations on CLOB such as its attack vectors and analyzing strategies. Then we give a detailed design of Flerken. The description is divided in two parts, namely Kindle (for Windows) and Octopus (for Linux). Respectively, we will show how human readability can serve as an effective statistical feature against PS/CMD obfuscation, and how dynamic syntax parsing can be adopted to eliminate false positives/negatives against Bash CLOB. The effectiveness of Flerken is evaluated via representative black/white command samples and performance experiments.
	* **Detection Ideas & Techniques**
		* [Detection Ideas & Rules](https://github.com/vadim-hunter/Detection-Ideas-Rules)
			* Every day a number of Threat Intelligence reports come into the world. Prepared by different vendors and teams almost none of them contain ready to use detection ideas and rules. In most cases we get only list of IOCs associated with particular threat actor. From my perspective, the reason of that is that DFIR teams do their job perfectly, but detection engineering is simply not their job. It is our - Threat Hunters' job. The idea of this repository is to analyze public Threat Intelligence reports, interesting TTPs, tools and various offensive tradecraft to generate ready to use detection ideas and rules implementations, which can be used by threat hunters and security monitoring teams.
	* **YARA-related**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tools**
			* [ReversingLabs YARA Rules](https://github.com/reversinglabs/reversinglabs-yara-rules)
	* **Tools**
		* [huntlib](https://github.com/target/huntlib)
			* A Python library to help with some common threat hunting data analysis operations 
* **Network**<a name="dnet"></a>
* **Linux**<a name="dlin"></a>
	* **Shell**
			* [Using eBPF to uncover in-memory loading - pat_h/to/file(2021)](https://blog.tofile.dev/2021/02/15/ebpf-01.html)
			* [BPF-PipeSnoop](https://github.com/pathtofile/bpf-pipesnoop)
				* Example program using eBPF to log data being based in using shell pipes (|)
* **macOS**<a name="dmac"></a>
	https://labs.f-secure.com/blog/attack-detection-fundamentals-2021-macos-lab-1/
	https://labs.f-secure.com/blog/attack-detection-fundamentals-2021-macos-lab-2/
	https://labs.f-secure.com/blog/attack-detection-fundamentals-2021-macos-lab-3/

	* **Tooling**
		* [Swift-Attack](https://github.com/cedowens/Swift-Attack)
			* Unit tests for blue teams to aid with building detections for some common macOS post exploitation methods. I have included some post exploitation examples using both command line history and on disk binaries (which should be easier for detection) as well as post exploitation examples using API calls only (which will be more difficult for detection). The post exploitation examples included here are not all encompassing. Instead these are just some common examples that I thought would be useful to conduct unit tests around. I plan to continue to add to this project over time with additional unit tests.
* **Windows**<a name="dwin"></a>
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
		* [How do I detect technique X in Windows?? Applied Methodology to Definitively Answer this Question - Matt Graeber(2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/1-05-how-do-i-detect-technique-x-in-windows-applied-methodology-to-definitively-answer-this-question-matt-graeber)
			* Traditionally, the answer to this question has been to execute an attack technique in a controlled environment and to observe relevant events that surface. While this approach may suffice in some cases, ask yourself the following questions: ?Will this scale? Will this detect current/future variants of the technique? Is this resilient to bypass?? If your confidence level in answering these questions is not high, it?s time to consider a more mature methodology for identifying detection data sources. With a little bit of reverse engineering, a defender can unlock a multitude of otherwise unknown telemetry. This talk will establish a methodology for identifying detection data sources and will cover concepts including Event Tracing for Windows, WPP, TraceLogging, and security product analysis.
		* [Uncovering The Unknowns: Mapping Windows API’s to Sysmon Events - Jonathan Johnson](https://posts.specterops.io/uncovering-the-unknowns-a47c93bb6971)
		* [Auditing and Bypassing Windows Defender Application Control - Matt Graeber](https://www.youtube.com/watch?v=GU5OS7UN8nY)
	* **Active Directory**(Will be moved)
		* **Articles/Writeups**
			* [FalconFriday — Certified Pre-Owned— 0xFF12 - Olaf Harton(2021](https://medium.com/falconforce/falconfriday-certified-pre-owned-0xff12-40f00a35e51a)
			* [Detecting BloodHound - http://www.stuffithoughtiknew.com/(2019)](http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html)
	* **Browser Addons**
	* **COM**
		* **Articles/Writeups**
			* [What is the “DLLHOST.EXE” Process Actually Running - Nasreddine Bencherchali(2020)](https://nasbench.medium.com/what-is-the-dllhost-exe-process-actually-running-ef9fe4c19c08)
	* **Credential Attacks**
		* [MiniDumpWriteDump via COM+ Services DLL - odzhan(2019)](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/)
	* **DLLs**
		* [Detecting Dll Unhooking - makosec(2021)](https://makosecblog.com/malware-dev/detecting-dll-unhooking/)
	* **ETW**
		* **Articles/Writeups**
		* **Tools**
			* [Sealighter-TI](https://github.com/pathtofile/SealighterTI)
				* Combining Sealighter with unpatched exploits and PPLDump to run the Microsoft-Windows-Threat-Intelligence ETW Provider without a signed driver.
	* **Mimikatz**
		* []YOU « TRY » TO DETECT MIMIKATZ ;) - Vincent Le Toux(https://hackinparis.com/data/slides/2019/talks/HIP2019-Vincent_Le_Toux-You_Try_To_Detect_Mimikatz.pdf)
	* **Native Binaries**
		* **Articles/Writeups**		
			* [Tracking Malware with Import Hashing - Mandiant(2014)](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)
			* [Import Hash - secana](https://secana.github.io/PeNet/articles/imphash.html)
			* [Defeating Imphash - Tim MalcomVetter(2019)](https://malcomvetter.medium.com/defeating-imphash-fb7cf0183ac)
			* [Masking Malicious Memory Artifacts – Part I: Phantom DLL Hollowing - Forrest Orr(2020)](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing)
			* [Masking Malicious Memory Artifacts – Part II: Insights from Moneta - Forrest Orr(2020)](https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-ii-insights-from-moneta)
		* **Papers**
			* [Breaking Imphash - Chris Balles, Ateeq Sharfuddin(2019)](https://arxiv.org/abs/1909.07630)
				* There are numerous schemes to generically signature artifacts. We specifically consider how to circumvent signatures based on imphash. Imphash is used to signature Portable Executable (PE) files and an imphash of a PE file is an MD5 digest over all the symbols that PE file imports. Imphash has been used in numerous cases to accurately tie a PE file seen in one environment to PE files in other environments, although each of these PE files' contents was different. An argument made for imphash is that alteration of imphashes of derived PE file artifacts is unlikely since it is an expensive process, such that you will need to either modify the source code and recompile or relink in a different order. Nevertheless, we present a novel algorithm that generates derivative PE files such that its imphash is different from the original PE file. This straightforward algorithm produces feasible solutions that defeat approaches relying on the impash algorithm to signature PE files.
		* **Tools**
			* [Moneta](https://github.com/forrest-orr/moneta)
				* Moneta is a live usermode memory analysis tool for Windows with the capability to detect malware IOCs 
	* **.NET**
		* **Articles/Writeups**
			* [Detecting Malicious Use of .NET – Part 1 - Noora Hyvärinen(2018)](https://blog.f-secure.com/detecting-malicious-use-of-net-part-1/)
				* [Part 2](https://blog.f-secure.com/detecting-malicious-use-of-net-part-2/)
			* [.NET Core Evasion Detection - netbiosX(2020)](https://pentestlaboratories.com/2020/07/02/net-core-evasion-detection/)
			* [COMPlus_ETWEnabled_detection_notes.md](https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3)
			* [Detecting attacks leveraging the .NET Framework - Zac Brown, Shane Welcher(2020)](https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/)
			* [Detecting .NET/C# injection (Execute-Assembly) - readhead0ntherun(2021)](https://redhead0ntherun.medium.com/detecting-net-c-injection-execute-assembly-1894dbb04ff7)
		* **Tools**
			* [CollectDotNetEvents.ps1](https://gist.github.com/mattifestation/444323cb669e4747373833c5529b29fb)
				* A PoC script to capture relevant .NET runtime artifacts for the purposes of potential detections 
			* [ModuleMonitor](https://github.com/TheWover/ModuleMonitor)
				* Uses WMI Event Win32_ModuleLoadTrace to monitor module loading. Provides filters, and detailed data. Has an option to monitor for CLR Injection attacks. 
	* **Networking**
		* [Blue Team: Port Forwarding Detection! - CyberSecurity Hub(2020)](https://sechub.medium.com/blue-team-port-forwarding-detection-3800ec1fbf4c)
	* **PowerShell**
		* **Articles/Writeups**
			* [Detecting and Preventing PowerShell Downgrade Attacks - Lee Holmes(2017)](https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/)
			* [Antimalware Scan Interface Detection Optics Analysis Methodology: Identification and Analysis of AMSI for WMI - Matt Graeber(2019)](https://posts.specterops.io/antimalware-scan-interface-detection-optics-analysis-methodology-858c37c38383)
			* [Powersploit usage & detection - 0xf0x(2020)](https://neil-fox.github.io/PowerSploit-usage-&-detection/)
	* **Processes & Related**
		* **Articles/Writeups**			
			* [Windows System Processes — An Overview For Blue Teams - Nasreddine Bencherchali(2020)](https://nasbench.medium.com/windows-system-processes-an-overview-for-blue-teams-42fa7a617920)
			* [On Process Doppelganging and developing an unpacker for it - KrabsOnSecurity(2018)](https://krabsonsecurity.com/2018/01/17/on-process-doppelganging-and-developing-an-unpacker-for-it/)
			* [Detecting Parent PID Spoofing - Noora Hyvärinen(2018)](https://blog.f-secure.com/detecting-parent-pid-spoofing/)
			* [A Deep Dive Into RUNDLL32.EXE - Nasreddine Bencherchali(2020)](https://nasbench.medium.com/a-deep-dive-into-rundll32-exe-642344b41e90)
			* [Detecting PPL Manipulation? A Test using LSASS as an Example - Dominik Altermatt(2020)](https://www.scip.ch/en/?labs.20200116)
			* [Babysitting child processes - Matt Graeber, Sarah Lewis(2021](https://redcanary.com/blog/child-processes/)
			* [Enterprise Scale Threat Hunting with Process Tree Analysis - Mehmet Ergene(2021)](https://posts.bluraven.io/detecting-threats-with-process-tree-analysis-without-machine-learning-838d85f78b2c)
		* **Tools**
	* **Process Injection**
		* **Articles/Writeups**
			* [Reflective Injection Detection – Andrew King(Defcon20)](https://www.youtube.com/watch?v=ZB1yD8LlFns)
				* [Tool](https://github.com/aking1012/dc20)
				* [Slides](https://defcon.org/images/defcon-20/dc-20-presentations/King/DEFCON-20-King-Reflective-Injection-Detection.pdf)
					* This talk will focus on detecting reflective injection with some mildly humorous notes and bypassing said protections until vendors start actually working on this problem. It seems amazing that reflective injection still works. Why is that? Because programmers are lazy. They don't want to write new engines, they want to write definitions for an engine that already exists. So what do we do about it? Release a $5 tool that does what $50 AV has failed epically at for several years now...oh and it took me a week or so...Alternately, you could license it to vendors since their programmers are lazy.
			* [Detecting reflective DLL injection - StackOverflow](https://stackoverflow.com/questions/12697292/detecting-reflective-dll-injection)
			* [DLL Injection - netbiosX(2017)](https://pentestlab.blog/2017/04/04/dll-injection/)
			* [Detecting reflective DLL loading with Windows Defender ATP - Microsoft Defender Security Research Team(2017)](https://www.microsoft.com/security/blog/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/)
			* [Memory Injection Like a Boss - Noora Hyvärinen(2018)](https://blog.f-secure.com/memory-injection-like-a-boss/)
			* [Detecting process injection with ETW - `@_lpvoid`](https://blog.redbluepurple.io/windows-security-research/kernel-tracing-injection-detection)
			* [Injecting Into The Hunt - Jonathan Johsnon(2019)](https://jsecurity101.medium.com/injecting-into-the-hunt-185af9d56636)
			* [Engineering Process Injection Detections - Part 1: Research - Jonathan Johsnon(2020)](https://posts.specterops.io/engineering-process-injection-detections-part-1-research-951e96ad3c85?gi=79f32240e903)
				* [Part 2: Data Modeling - Jonathan Johsnon(2020)](https://posts.specterops.io/engineering-process-injection-detections-part-2-data-modeling-c11f5aedf5e0)
				* [Part 3: Analytic Logic - David Polojac(2020)](https://posts.specterops.io/engineering-process-injection-detections-part-3-analytic-logic-b6014a83d4c8)
			* [DLL Injection And Process Hollowing Detection in Pest Code Analysis - Omer(2020)](https://www.systemconf.com/2020/07/31/dll-injection-and-process-hollowing-detection-in-pest-code-analysis/)
			* https://www.mertsarica.com/antimeter-tool/
		* **Talks/Presentations/Videos**
			* [Taking Hunting to the Next Level: Hunting in Memory -Jared Atkinson, Joe Desimone(SANS Threat Hunting Summit2017)](https://www.youtube.com/watch?v=EVBCoV8lpWc)
				* In this talk, we will describe both common and advanced stealth malware techniques which evade today’s hunt tools and methodologies. Attendees will learn about adversary stealth and understand ways to detect some of these methods.  Then, we will demonstrate and release a Powershell tool which will allow a hunter to automatically analyze memory across systems and rapidly highlight injected in-memory-only attacks across systems at scale.  This will help move memory analysis from the domain of forensics to the domain of detection and hunting, allowing hunters to close the detection gap against in-memory threats, all without relying on without signatures. 
			* [Gargoyle Hunting In-Depth — Presented by Aliz Hammond()](https://www.youtube.com/watch?v=T73GK1Y8jLU)
				* Detecting certain user-mode code-hiding techniques, such as Josh Lospinoso's 'Gargoyle', is almost impossible from user-space. In this talk, I will examine Gargoyle, and explain how it can be detected from kernel mode. I will first walk through using WinDbg to locate hidden code and then write a Volatility plugin to turn this process into a practical method of detecting real-world attacks — in the process, adding a reliable method of differentiating these from legitimate behavior.
			* [Part 2 - Investigation Hollow Process Injection Using Memory Forensics - Monnappa K A](https://www.youtube.com/watch?v=GlwEG1oLNvg)
		* **Tools**
			* [Get-Injected-Thread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
				* Code from "Taking Hunting to the Next Level: Hunting in Memory" presentation at SANS Threat Hunting Summit 2017 by Jared Atkinson and Joe Desimone
			* [Detecting-Process-Injection-Techniques](https://github.com/jsecurity101/Detecting-Process-Injection-Techniques)
				* This is a repository that is meant to hold detections for various process injection techniques.
			* [pe-sieve](https://github.com/hasherezade/pe-sieve)
				* Scans a given process. Recognizes and dumps a variety of potentially malicious implants (replaced/injected PEs, shellcodes, hooks, in-memory patches). 
			* [MemProcFS-Analyzer](https://github.com/evild3ad/MemProcFS-Analyzer)
				* MemProcFS-Analyzer - Automated Forensic Analysis of Windows Memory Dumps for DFIR
			* [eif](https://github.com/psmitty7373/eif)
				* Evil Reflective DLL Injection Finder 
			* [reflective-injection-detection](https://github.com/papadp/reflective-injection-detection)
				* A program to detect reflective dll injection on a live machine using a "naive" approach of looking for a PE header. The program also dumps other unlinked executable pages to the disk for your convenience.
			* [hollows_hunter](https://github.com/hasherezade/hollows_hunter)
				* Scans all running processes. Recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches). 
	* **RPC & SMB**
		* **Articles/Writeups**
			* [A Dive on SMBEXEC - dmcxblue](https://0x00sec.org/t/a-dive-on-smbexec/24961)
			* [Impacket usage & detection - 0xf0x(2020](https://neil-fox.github.io/Impacket-usage-&-detection/)
			* [Utilizing RPC Telemetry - Jonathan Johnson(2020)](https://posts.specterops.io/utilizing-rpc-telemetry-7af9ea08a1d5)
			* [Determining Which Process Is Making SMB Requests On Windows - @mdjxkln(2021)](https://xkln.net/blog/determining-which-process-is-making-smb-requests-on-windows/)
			* [A Voyage to Uncovering Telemetry: Identifying RPC Telemetry for Detection Engineers - Jonathan Johnson(2020](https://ipc-research.readthedocs.io/en/latest/subpages/RPC.html)
			* [Extending the Exploration and Analysis of Windows RPC Methods Calling other Functions with Ghidra 🐉, Jupyter Notebooks 📓 and Graphframes 🔗! - Roberto Rodriguez(2020)](https://medium.com/threat-hunters-forge/extending-the-exploration-and-analysis-of-windows-rpc-methods-calling-other-functions-with-ghidra-e4cdaa9555bd)
	* **Services**
		* **Articles/Writeups**
			* [Detecting Lateral Movement via Service Configuration Manager - Cyb3rSn0rlax](https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-lateral-movement-via-service-configuration-manager)
	* **Shellcode**
		* **Articles/Writeups**
			* [RIFT: Analysing a Lazarus Shellcode Execution Method - Research and Intelligence Fusion Team(RIFT)(2021](https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/)
			* [Using Memory Artifacts As Shellcode Emulation Environment (ft. Unicorn Framework) - DarunGrim(2020)](https://darungrim.com/research/2020-06-04-UsingMemoryArtifactsAsShellcodeEmulationEnvironment.html)
	* **Syscalls/WinAPI**
		* [Windows APIs To Sysmon-Events](https://github.com/jsecurity101/Windows-API-To-Sysmon-Events)
		* [SyscallExtractorAnalyzer](https://github.com/Truvis/SyscallExtractorAnalyzer)
			* This script will pull and analyze syscalls in given application(s) allowing for easier security research purposes
		* [System Call Monitoring Despite KPP - Jason(2018)](https://redvice.org/2018/system-call-monitoring/)
		* [Malware Mitigation when Direct System Calls are Used - Hod Gavriel(2018)](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/)
	* **WMI**
		* **101**
			* Introduction to CIM Cmdlets - PowerShell Team(2012)](https://devblogs.microsoft.com/powershell/introduction-to-cim-cmdlets/)
			* [What is CIM and Why Should I Use It in PowerShell? - Dr Scripto(2014)](https://devblogs.microsoft.com/scripting/what-is-cim-and-why-should-i-use-it-in-powershell/)
		* **Articles/Writeups**
			* [Detecting WMI Exploitation v1.1 - Michael Gough(2018)](https://www.slideshare.net/Hackerhurricane/detecting-wmi-exploitation-v11)
			* [Détecter la persistance WMI - Guichard Jean-Philip, Wyttenbach Bruno(2017)](https://connect.ed-diamond.com/MISC/misc-091/detecter-la-persistance-wmi)
			* [Detecting & Removing an Attacker’s WMI Persistence - David French](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96)
			* [Keep an Eye on Your WMI Logs - Xavier Mertens(2019](https://isc.sans.edu/forums/diary/Keep+an+Eye+on+Your+WMI+Logs/25012/)
			* [Detecting WMI: Your top questions answered - RedCanary2021)](https://redcanary.com/blog/detecting-wmi/)
		* **Talks & Presentations**
			* [The Detection Series: Windows Management Instrumentation - RedCanary(2021)](https://redcanary.com/resources/webinars/detection-series-windows-management-instrumentation/)
		* **Tools**
			* [WMI Process Watcher](https://github.com/malcomvetter/WMIProcessWatcher)
	* **Talks & Presentations**
		* [How do I detect technique X in Windows?? Applied Methodology to Definitively Answer this Question - Matt Graeber(Derbycon 2019)](http://www.irongeek.com/i.php?page=videos/derbycon9/1-05-how-do-i-detect-technique-x-in-windows-applied-methodology-to-definitively-answer-this-question-matt-graeber)
			* Traditionally, the answer to this question has been to execute an attack technique in a controlled environment and to observe relevant events that surface. While this approach may suffice in some cases, ask yourself the following questions: ?Will this scale? Will this detect current/future variants of the technique? Is this resilient to bypass?? If your confidence level in answering these questions is not high, it?s time to consider a more mature methodology for identifying detection data sources. With a little bit of reverse engineering, a defender can unlock a multitude of otherwise unknown telemetry. This talk will establish a methodology for identifying detection data sources and will cover concepts including Event Tracing for Windows, WPP, TraceLogging, and security product analysis.
	* **Tools/Tooling**
		* API-To-Event](https://github.com/hunters-forge/API-To-Event)
			* A repo focused primarily on documenting the relationships between API functions and security events that get generated when using such functions. 
		* [PeaceMaker](https://github.com/D4stiny/PeaceMaker)
			* PeaceMaker Threat Detection is a kernel-mode utility designed to detect a variety of methods commonly used in advanced forms of malware. Compared to a stereotypical anti-virus that may detect via hashes or patterns, PeaceMaker targets the techniques malware commonly uses in order to catch them in the act. Furthermore, PeaceMaker is designed to provide an incredible amount of detail when a malicious technique is detected, allowing for effective containment and response.
		* [FalconEye](https://github.com/rajiv2790/FalconEye)
			* FalconEye is a windows endpoint detection software for real-time process injections. It is a kernel-mode driver that aims to catch process injections as they are happening (real-time). Since FalconEye runs in kernel mode, it provides a stronger and reliable defense against process injection techniques that try to evade various user-mode hooks.
	* **Misc**
		* [Mimikatz usage & detection - 0xf0x(2020)](https://neil-fox.github.io/Mimikatz-usage-&-detection/)
		* [Impacket Deep Dives Vol. 1: Command Execution - Kyle Mistele(2021)](https://kylemistele.medium.com/impacket-deep-dives-vol-1-command-execution-abb0144a351d)















------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------
### Threat Hunting <a name="th"></a>
* **101**<a name="th101"></a>
	* **101**
		* [The Alexiou Principle - cepogue(2009)](https://thedigitalstandard.blogspot.com/2009/06/alexiou-principle.html)
		* [Cyber Threat Hunting | Chris Brenton | October 2020 | 4 Hours](https://www.youtube.com/watch?v=FzYPT1xTVHY)
			* Chris Brenton from Active Countermeasures is conducting another free, one-day, Cyber Threat Hunting Training online course! One of the biggest challenges in security today is identifying when our protection tools have failed and a threat actor has made it onto our network. In this free, 4-hour course, we will cover how to leverage network and host data to perform a cyber threat hunt. The course includes hands-on labs using packet captures of various command and control channels. We also discuss how you can use our new Sysmon tool BeaKer to detect attacks on the host with Sysmon... for free! The labs enable you to apply what you've learned using various open-source tools. By the end of the course, you’ll understand the tools and techniques needed to perform compromise assessments within your own environment. While the course will be available later for download, live attendees will receive a "Cyber Security Threat Hunter Level-1" certificate.
		* [attack-coverage](https://github.com/RealityNet/attack-coverage)
			* An excel-centric approach for managing the MITRE ATT&CK® tactics and techniques. The Excel file AttackCoverage.xlsx can be used to get a coverage measure of MITRE ATT&CK® tactics and techniques, in terms of detections rules. Working as DFIR consultants for different companies, with different SOCs and technologies in place, it was needed a simple and portable way to get a sort of awareness about which attackers' tactics/techniques a customer is able to detect and, more important, what is missing.			
	* **Articles/Writeups**
		* [Incident Response is Dead… Long Live Incident Response - Scott J Roberts(2015)](https://medium.com/@sroberts/incident-response-is-dead-long-live-incident-response-5ba1de664b95)
		* [A Simple Hunting Maturity Model - detect-respond.blogspot (2015)](https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html)		
		* [The Origin of Threat Hunting - TaoSecurity(2017)](https://taosecurity.blogspot.com/2017/03/the-origin-of-threat-hunting.html)
		* [The Pyramid of Pain - David Bianco(2014)](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
		* [Expanding on Pyramid of Pain - limbenjamin(2020)](https://limbenjamin.com/articles/expanding-on-pyramid-of-pain.html)
		* [The Cyber Hunting Maturity Model - Sqrrl(2015)](https://medium.com/@sqrrldata/the-cyber-hunting-maturity-model-6d506faa8ad5)
		* [Threat Hunting - Getting Closer to Anomalous Behavior - Jack Crook(2016)](https://findingbad.blogspot.com/2016/10/threat-hunting-getting-closer-to.html)
		* [The ThreatHunting Project Annotated Reading List](https://www.threathunting.net/reading-list)
		* "I hereby declare the Law Of A Threat Hunter (LOATH): `𝘍𝘰𝘳 𝘦𝘷𝘦𝘳𝘺 𝘵𝘸𝘰 𝘮𝘰𝘴𝘵 𝘥𝘪𝘴𝘵𝘢𝘯𝘵 𝘵𝘦𝘤𝘩𝘯𝘰𝘭𝘰𝘨𝘪𝘦𝘴 𝘵𝘩𝘦𝘳𝘦 𝘦𝘹𝘪𝘴𝘵 𝘢 𝘥𝘦𝘷𝘦𝘭𝘰𝘱𝘦𝘳 𝘵𝘩𝘢𝘵 𝘸𝘪𝘭𝘭 𝘣𝘳𝘪𝘯𝘨 𝘵𝘩𝘦𝘮 𝘵𝘰𝘨𝘦𝘵𝘩𝘦𝘳.`" - Hexacorn[Tweet](https://mobile.twitter.com/hexacorn/status/1108726593848049664)		
		* [The Threat Hunting Reference Model Part 2: The Hunting Loop - Sqrrl](https://www.threathunting.net/files/The%20Threat%20Hunting%20Reference%20Model%20Part%202_%20The%20Hunting%20Loop%20_%20Sqrrl.pdf)
		* [The Who, What, Where, When, Why and How of Effective Threat Hunting - Robert Lee, Rob Lee(2016)](https://www.sans.org/reading-room/whitepapers/analyst/membership/36785)
		* [Building Threat Hunting Strategies with the Diamond Model - Sergio Caltagirone(2016)](http://www.activeresponse.org/building-threat-hunting-strategy-with-the-diamond-model/)
		* [Cyber Threat Hunting (1): Intro - Samuel Alonso(2016)](https://cyber-ir.com/2016/01/21/cyber-threat-hunting-1-intro/)
			* [Part 2: Getting Ready](https://cyber-ir.com/2016/02/05/cyber-threat-hunting-2-getting-ready/)
			* [Part 3: Hunting in the perimeter](https://cyber-ir.com/2016/03/01/cyber-threat-hunting-3-hunting-in-the-perimeter/)
		* [Cyber Hunting: 5 Tips To Bag Your Prey - David J. Bianco](https://www.darkreading.com/risk/cyber-hunting-5-tips-to-bag-your-prey/a/d-id/1319634)
		* [Data Science Hunting Funnel - Austin Taylor(2017)](http://www.austintaylor.io/network/traffic/threat/data/science/hunting/funnel/machine/learning/domain/expertise/2017/07/11/data-science-hunting-funnel/)
		* [Demystifying Threat Hunting Concepts - Josh Liburdi(2017)](https://medium.com/@jshlbrd/demystifying-threat-hunting-concepts-9de5bad2d818)
			* This post is about demystifying threat hunting concepts that seem to trip up practitioners and outsiders.
		* [The Role of Evidence Intention - Chris Sanders(2018)](https://chrissanders.org/2018/10/the-role-of-evidence-intention/)
		* [DeTT&CT: Mapping your Blue Team to MITRE ATT&CK™ - Marcus Bakker(2019)](https://www.mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack)
			* [DeTTECT - Detect Tactics, Techniques & Combat Threats](https://github.com/rabobank-cdc/DeTTECT)
		* [A Deep Drive on Proactive Threat Hunting - Nisha Sharma(2020)](https://www.hackingarticles.in/a-deep-drive-on-proactive-threat-hunting/)
		* [On TTPs - Ryan Stillions(2020)](https://web.archive.org/web/20200501220419/http://ryanstillions.blogspot.com/web/20191003131313/http://ryanstillions.blogspot.com/2014/04/on-ttps.html)
			* [...]I set off a few months ago on a personal quest.  I wanted to see if I could locate any official citations that attempted to clearly define, compare or contrast "TTPs" in a cyber context, and show how they could be used both individually and jointly with other models to further advance our work in the context of things above and beyond atomic Indicators of Compromise (IOCs).  In this blog post I'll share with you what I found regarding the definitions of "TTPs", and then transition into how I believe they apply to incident detection and response.
		* [Hunting mindmaps - sbousseaden](https://github.com/sbousseaden/Slides/tree/master/Hunting%20MindMaps)
			* Summarized Overview of different hunting paths an Analyst can take per EventId or technique.
		* [Threat Hunting - Zero to Hero - Slavi Parpulev(2020)](https://improsec.com/tech-blog/threat-hunting-zero-to-hero)
		* [The PARIS Model](http://threathunter.guru/blog/the-paris-model/)
	* **Resources**
		* [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection)
	* **Talks & Presentations**
		* [Threat Hunting Workshop - Methodologies for Threat Analysis - RiskIQ](https://www.youtube.com/playlist?list=PLgLzPE5LJevb_PcjMYMF2ypjnVcKf8rjY)
		* [Threat Hunting 101: Become The Hunter - Hamza Beghal(HITBGSEC 2017)](https://www.youtube.com/watch?v=vmVE2PCVwHU)
		* [Threat Hunting, The New Way - In Ming, Wei Chea(HITCon Pacific2017)](https://hitcon.org/2017/pacific/0composition/pdf/Day1/R1/R1-5.12.7.pdf)
		* [A Process is No One: Hunting for Token Manipulation - Jared Atkinson, Robby Winchester(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/stable-01-a-process-is-no-one-hunting-for-token-manipulation-jared-atkinson-robby-winchester)
			* Does your organization want to start Threat Hunting, but you’re not sure how to begin? Most people start with collecting ALL THE DATA, but data means nothing if you’re not able to analyze it properly. This talk begins with the often overlooked first step of hunt hypothesis generation which can help guide targeted collection and analysis of forensic artifacts. We will demonstrate how to use the MITRE ATTACK Framework and our five-phase Hypothesis Generation Process to develop actionable hunt processes, narrowing the scope of your Hunt operation and avoiding “analysis paralysis.” We will then walk through a detailed case study of detecting access token impersonation/manipulation from concept to technical execution by way of the Hypothesis Generation Process.
		* [On the Hunt: Hacking the Hunt Group - Chris Silvers, Taylor Banks(NolaCon2018](https://www.irongeek.com/i.php?page=videos/nolacon2018/nolacon-2018-204-on-the-hunt-hacking-the-hunt-group-chris-silvers-taylor-banks)
			* Goal is to motivate listeners to be better cyber practitioners, employees, and patients and end result will be better patient medical record security for all of society. In theory
		* [Find_Evil - Threat Hunting Anurag Khanna(SANS2020)](https://www.youtube.com/watch?v=GrhVz1Sjd_0)
			* Today, organizations are constantly under attack. While security teams are getting good at monitoring and incident response, the frontier to conquer is proactively looking for evil in the environment. Threat hunting is one of the ways in which organizations can proactively look for threats. This talk would discuss the fundamentals of threat hunting, what the hunting teams should look for and how to collect and analyze relevant data. We will discuss some of the recipes to perform threat hunting.
	* **Papers**
		* [Hunt Evil: Your Practical Guide to Threat Hunting - threathunting.net](https://www.threathunting.net/files/hunt-evil-practical-guide-threat-hunting.pdf)
		* [Huntpedia - Sqrrl](https://www.threathunting.net/files/huntpedia.pdf)
		* [Threat Hunting: Open Season on the Adversary - Eric Cole(2016)](https://www.sans.org/reading-room/whitepapers/analyst/membership/36882)
		* [Mental Models for Effective Searching - Chris Sanders](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1555082140.pdf)
		* [A Practical Model for Conducting Cyber Threat Hunting - Dan Gunter, Marc Seitz(2018)](https://www.sans.org/white-papers/38710/)
			* There remains a lack of definition and a formal model from which to base threat hunting operations and quantifying the success of said operations from the beginning of a threat hunt engagement to the end that also allows analysis of analytic rigor and completeness. The formal practice of threat hunting seeks to uncover the presence of attacker tactics, techniques, and procedures (TTP) within an environment not already discovered by existing detection technologies. This research outlines a practical and rigorous model to conduct a threat hunt to discover attacker presence by using six stages: purpose, scope, equip, plan review, execute, and feedback. This research defines threat hunting as the proactive, analyst-driven process to search for attacker TTP within an environment. The model was tested using a series of threat hunts with real-world datasets. Threat hunts conducted with and without the model observed the effectiveness and practicality of this research. Furthermore, this paper contains a walkthrough of the threat hunt model based on the information from the Ukraine 2016 electrical grid attacks in a simulated environment to demonstrate the model’s impact on the threat hunt process. The outcome of this research provides an effective and repeatable process for threat hunting as well as quantifying the overall integrity, coverage, and rigor of the hunt.
		* [Generating Hypotheses for Successful Threat Hunting - Robert M. Lee, David Bianco](https://www.sans.org/reading-room/whitepapers/threats/paper/37172)
			* Threat hunting is a proactive and iterative approach to detecting threats. Although threat hunters should rely heavily on automation and machine assistance, the process itself cannot be fully automated. One of the human’s key contributions to a hunt is the formulation of a hypotheses to guide the hunt. This paper explores three types of hypotheses and outlines how and when to formulate each of them.
		* **TaHiTI**
			* [TaHiTI Threat Hunting Methodology](https://www.betaalvereniging.nl/wp-content/uploads/DEF-TaHiTI-Threat-Hunting-Methodology.pdf)
			* [TaHiTI: a threat hunting methodology (whitepaper)](https://www.betaalvereniging.nl/wp-content/uploads/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf)
* **Non-101 General**
	* **Articles/Blogposts/Writeups**
		* [Hunting From The Top - Jack Crook(2016)](https://findingbad.blogspot.com/2016/08/hunting-from-top.html)
		* [Categories of Abnormal - Jack Crook(2016)](https://findingbad.blogspot.com/2016/09/categories-of-abnormal.html)
		* [My Thoughts on Threat Hunting - Jack Crook(2016)](https://findingbad.blogspot.com/2016/07/my-thoughts-on-threat-hunting.html)		
		* [Don't wait for an intrusion to find you - Jack Crook(2016)](https://findingbad.blogspot.com/2016/09/dont-wait-for-intrusion-to-find-you.html)
		* [A Few Of My Favorite Things - Jack Crook(2017)](https://findingbad.blogspot.com/2017/11/a-few-of-my-favorite-things.html)
		* [A Few of My Favorite Things - Continued - Jack Crook(2017)](https://findingbad.blogspot.com/2017/12/a-few-of-my-favorite-things-continued.html)
		* [Patterns of Behavior - Jack Crook(2017)](https://findingbad.blogspot.com/2017/02/patterns-of-behavior.html)
		* [Hunting for Chains  - Jack Crook(2017)](https://findingbad.blogspot.com/2017/02/hunting-for-chains.html)	
		* [Dynamic Correlation, ML and Hunting - Jack Crook(2020)](https://findingbad.blogspot.com/2020/06/dynamic-correlation-ml-and-hunting.html)
		* [Blue Team: System Live Analysis [Part 1]- A Proactive Hunt! - Meisam Eslahi(2020)](https://sechub.medium.com/blue-team-system-live-analysis-part-1-a-proactive-hunt-8258feb7cb14)
			* [[Part 2]- Windows: Rules and Tools](https://sechub.medium.com/blue-team-system-live-analysis-part-2-windows-rules-and-tools-fc42be6c060d)
			* [[Part 3]- Windows: Technical Checklist](https://sechub.medium.com/blue-team-system-live-analysis-part-3-windows-technical-checklist-1ef79284cbdc)
			* [[Part 4] - Windows: System Information and Configurations](https://sechub.medium.com/blue-team-system-live-analysis-part-4-windows-system-information-and-configurations-8d87211164d1)
			* [[Part 5] - Windows: Users, Groups, and Privileges](https://sechub.medium.com/blue-team-system-live-analysis-part-5-windows-users-groups-and-privileges-eba13a5a4615)
		* [Spotting the Red Team on VirusTotal! - Xavier Mertens(2021)](https://isc.sans.edu/forums/diary/Spotting+the+Red+Team+on+VirusTotal/27174/)
		* [The Myth of Part-time Hunting, Part 1: The Race Against Ever-diminishing Breakout Times - Falcon OverWatch Team(2021)](https://www.crowdstrike.com/blog/the-myth-of-part-time-threat-hunting-part-1/)
* **Data Analysis**<a name="data"></a>
	* **Articles/Blogposts/Writeups**
		* [An In-Depth Look Into Data Stacking - M-Labs](https://www.fireeye.com/blog/threat-research/2012/11/indepth-data-stacking.html)
			* Data stacking is the application of frequency analysis to large volumes of similar data in an effort to isolate and identify anomalies. In short, data stacking is an investigative technique that can be used to find a needle in a digital haystack. It involves an iterative process of reducing large amounts of data into manageable chunks that can be consumed and investigated.	
		* [Defining ATT&CK Data Sources, Part I: Enhancing the Current State - Jose Luis Rodriguez(2020)](https://medium.com/mitre-attack/defining-attack-data-sources-part-i-4c39e581454f)
		* [Defining ATT&CK Data Sources, Part II: Operationalizing the Methodology - Jose Luis Rodriguez(2020)](https://medium.com/mitre-attack/defining-attack-data-sources-part-ii-1fc98738ba5b)
	* **Analysis of**
		* **Articles/Blogposts/Writeups**
			* [Analysis of Variance - RPubs]()https://rpubs.com/aaronsc32/anova-compare-more-than-two-groups
			* [What is the Tukey Test / Honest Significant Difference? - statisticshowto.com](https://www.statisticshowto.com/tukey-test-honest-significant-difference/)
			* [Tukey's Test for Post-Hoc Analysis - Aaron Schlegel(2018)](https://aaronschlegel.me/tukeys-test-post-hoc-analysis.html)
			* [WATSON: Abstracting Behaviors from Audit Logs via Aggregation of Contextual Semantics - Jun Zeng, Zheng Leong Chua, Yinfang Chen, Kaihang Ji, Zhenkai Liang, Jian Mao](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_7A-3_24549_paper.pdf)
		* **Talks/Presentations/Videos**
			* [Top 10 2015-2016 compromise patterns observed & how to use non-traditional Internet datasets to detect & avoid them - Arian J Evans, James Pleger(Derbycon2016)](https://www.irongeek.com/i.php?page=videos/derbycon6/401-top-10-2015-2016-compromise-patterns-observed-how-to-use-non-traditional-internet-datasets-to-detect-avoid-them-arian-j-evans-james-pleger)
				* We have seen a consistent set of patterns in attacker behaviors, and breach targets, over the last year. We often see where adversaries are repeat offenders - reusing the same recon techniques, and the same threat infrastructure (in new ways), to attack the same target again - if the target continues to play whack-a-mole treating hardening systems and investigating breaches as one-off events. This presentation will focus on the common patterns of compromise, and adversarial behavior in the early stages of the "kill-chain", leading up to the first attack. The goal for Red-teams & vuln-managers is to show how adversaries do recon and setup, to enable you to measure & manage your attack surface more realistically to how your adversaries will map it out. The goal for Blue-teams & IR is to show new patterns and pivots we see adversaries make, and what Internet security datasets you can use to pinpoint them. 
			* [StringSifter: Learning to Rank Strings Output for Speedier Malware Analysis - Philip Tully, Matthew Haigh, Jay Gibble, Michael Sikorski(Derbycon2019)](https://www.youtube.com/watch?v=pLiaVzOMJSk&feature=emb_title)
				* In static analysis, one of the most useful initial steps is to inspect a binary's printable characters via the Strings program. However, running Strings on a piece of malware inevitably produces noisy strings mixed in with important ones, which can only be uncovered after sifting through the entirety of its messy output. To address this, we are releasing StringSifter: a machine learning-based tool that automatically ranks strings based on their relevance for malware analysis. In our presentation, we'll show how StringSifter allows analysts to conveniently focus on strings located towards the top of its predicted output, and that it performs well based on criteria used to evaluate web search and recommendation engines. We?ll also demonstrate StringSifter live in action on sample binaries.
	* **Analytics Creation & Curation**
		* **Articles/Blogposts/Writeups**
			* [Introducing Explainable Threat Intelligence - Tomislav Peričin(2020)](https://blog.reversinglabs.com/blog/introducing-explainable-threat-intelligence)
			* [Let's build a Full-Text Search engine - Artem Krylysov(2020)](https://artem.krylysov.com/blog/2020/07/28/lets-build-a-full-text-search-engine/)
			* [Building a full-text search engine in 150 lines of Python code - Bart de Goede(2021)](https://bart.degoe.de/building-a-full-text-search-engine-150-lines-of-code/)
			* [Hunting for anomalies with time-series analysis - m365guy(2021)](https://m365internals.com/2021/02/16/hunting-for-anomalies-with-time-series/)
			* [Evadere Classifications - Jonathan Johnson(2021)](https://posts.specterops.io/evadere-classifications-8851a429c94b)
	* **Presenting Data**
		* [How to numerically represent semi-structured log data for anomaly detection? - Marcin Kowiel(PyData Warsaw2019)](https://www.youtube.com/watch?v=I0M6Qb-B8nU)
	* **Tools**
		* [atomic-threat-coverage](https://github.com/atc-project/atomic-threat-coverage)
			* Atomic Threat Coverage is highly automatable framework for accumulation, development and sharing actionable analytics.
	* **OSSEM**
		* [OSSEM](https://github.com/OTRF/OSSEM)
			* The Open Source Security Events Metadata (OSSEM) is a community-led project that focuses primarily on the documentation and standardization of security event logs from diverse data sources and operating systems. Security events are documented in a dictionary format and can be used as a reference while mapping data sources to data analytics used to validate the detection of adversarial techniques. In addition, the project provides a common data model (CDM) that can be used for data engineers during data normalization procedures to allow security analysts to query and analyze data across diverse data sources. Finally, the project also provides documentation about the structure and relationships identified in specific data sources to facilitate the development of data analytics.
		* [OSSEM MODULAR](https://github.com/secgroundzero/ossem_modular)
			* Started this project for documenting Windows logs and performing threat hunting in a sensible and manageable manner. OSSEM Modular is aimed to help when starting ingesting logs and troubleshoot in an easier way.
		* [Mapping ATT&CK Data Sources to Security Events via OSSEM - Jose Luis Rodriguez(2020)](https://medium.com/threat-hunters-forge/mapping-att-ck-data-sources-to-security-events-via-ossem-%EF%B8%8F-b606d99e738c)
	* **SIGMA**
		* [Automated Detection Rule Analysis with Dredd - Evan Perotti(2020)](https://sra.io/blog/automated-detection-rule-analysis-with-dredd/)
	* **Labs & Datasets**
		* Datasets
			* [Security Datasets](https://github.com/OTRF/Security-Datasets)
				* The Security Datasets project is an open-source initiatve that contributes malicious and benign datasets, from different platforms, to the infosec community to expedite data analysis and threat research.
			* [Public dataset of Cloudtrail logs from flaws.cloud - Scott Piper(2020)](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/)
			* [APT29 Evals Detection Hackathon May 2nd, 2020](https://github.com/OTRF/detection-hackathon-apt29)
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
* **APT Hunts**
	* **Articles/Blogposts/Writeups**
		* [Light in the Dark: Hunting for SUNBURST - Matt Bromiley, Andrew Rector, Robert Wallace(2021)](https://www.fireeye.com/blog/products-and-services/2021/02/light-in-the-dark-hunting-for-sunburst.html)
		* [Threat Hunting. Why might you need it - CyberPolygon](https://cyberpolygon.com/materials/threat-hunting-why-might-you-need-it/)
		* [Threat Hunting in action - CyberPolygon](https://cyberpolygon.com/materials/threat-hunting-in-action/)
		* [Hunting for advanced Tactics, Techniques and Procedures (TTPs) - CyberPolygon](https://cyberpolygon.com/materials/hunting-for-advanced-tactics-techniques-and-procedures-ttps/)
		* [Hunting Red Team Activities with Forensic Artifacts - Haboob Team(2020)](https://dl.packetstormsecurity.net/papers/general/hunting-redteamactivities.pdf)
		* [Let’s set ice on fire: Hunting and detecting IcedID infections - Thomas Barabosch(2021)](https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240)
		* [Breaking down NOBELIUM’s latest early-stage toolset - Microsoft Threat Intelligence Center(2021)](https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/)
* **Browser-Plugins**
	* [FalconFriday — Detecting Malicious Browser Extensions and code signing- 0xFF01 - Olaf Hartong(2020)](https://medium.com/falconforce/falcon-friday-detecting-malicious-browser-extensions-and-code-signing-0xff01-db622e6a6519)
* **C2 Hunting**
	* **Articles/Blogposts/Writeups**
		* [C2 Hunting - Jack Crook(2018)](https://findingbad.blogspot.com/2018/03/c2-hunting.html)
		* [Let’s Go Hunting! How to Hunt Command & Control Channels Using Bro IDS and RITA - Logan Lembke(2017)](https://www.blackhillsinfosec.com/how-to-hunt-command-and-control-channels-using-bro-ids-and-rita/)
		* [Detect Beaconing with Flare, Elastic Stack, and Intrusion Detection Systems - Austin Taylor(2017)](http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/)
		* [Hunting for Anomalous Usage of MSBuild and Covenant - Riccardo Ancarani(2019)](https://riccardoancarani.github.io/2019-10-19-hunting-covenant-msbuild/)
		* [Hunting for SILENTTRINITY - Wee-Jing Chung(2019)](https://blog.f-secure.com/hunting-for-silenttrinity/)
		* [C2-JARM](https://github.com/cedowens/C2-JARM)
			* A list of JARM hashes for different ssl implementations used by some C2 tools. 
		* [Hunting for Beacons - Jack Crook(2020)](https://findingbad.blogspot.com/2020/05/hunting-for-beacons.html)
			* [Part 2](http://findingbad.blogspot.com/2020/05/hunting-for-beacons-part-2.html)
		* [Do You C2? If You Do, ICU. - Jonathan Ham(WWHF 2020)](https://www.youtube.com/watch?v=d5W7TgGmgIg&list=PLXF21PFPPXTPwX8mccVIQB5THhU_paWmN&index=18)
		* [From The Hunter Diaries - Detecting C2 Servers - Oded Awaskar(2021)](https://www.paloaltonetworks.com/blog/security-operations/from-the-hunter-diaries-detecting-c2-servers/)
		* [C2 Traffic Patterns: Personal Notes - marcoramilli(2021)](https://marcoramilli.com/2021/01/09/c2-traffic-patterns-personal-notes/)
		* [Understanding & Detecting C2 Frameworks — BabyShark - Nasreddine Bencherchali(2021)](https://nasbench.medium.com/understanding-detecting-c2-frameworks-babyshark-641be4595845)
			* [TrevorC2 - Nasreddine Bencherchali(2021)](https://nasbench.medium.com/understanding-detecting-c2-frameworks-trevorc2-2a9ce6f1f425)
			* [Ares - Nasreddine Bencherchali(2021)](https://nasbench.medium.com/understanding-detecting-c2-frameworks-ares-8c96aa47e50d)
			* [HARS (HTTP/S Asynchronous Reverse Shell) - Nasreddine Bencherchali(2021)](https://nasbench.medium.com/understanding-detecting-c2-frameworks-hars-682b30f0505c)
	* **Talks/Presentations/Videos**
		* [Threat Hunting Beacon Analysis - Chris Brenton(2018)](https://www.youtube.com/watch?v=FzGbVMntLT0)
			* Join Chris Brenton, COO of Active Countermeasures, as he discusses the anatomy of beacons and why you need to be looking for them during a threat hunt. He also talks through the challenges of detecting beacons, and some tricks you can use.
* **Cloud-Based**
	* **AWS**
		* [Quick and Dirty CloudTrail Threat Hunting Log Analysis - George Fekkas(2021)](https://medium.com/@george.fekkas/quick-and-dirty-cloudtrail-threat-hunting-log-analysis-b64af10ef923)
* **Email-Logs**
	* **Articles/Blogposts/Writeups**
		* [Threat Hunting and Detection with Email Logs - Mehmet Ergene(2020)](https://medium.com/@mergene/threat-hunting-and-detection-with-email-logs-4b1e37f5d035)
* **Execution**
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [GOing 4 a Hunt](https://posts.specterops.io/going-4-a-hunt-66c9f0d7f32c)
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
		* [Threat Hunting for Ransomware with CarbonBlack Response and AnyRun - Manfred Chang(2021)](https://threat.tevora.com/threat-hunting-for-ransomware-with-carbonblack-response-and-anyrun/)
	* **Talks/Presentations/Papers**
		* [License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)
		* [Advanced Attack Detection - William Burgess, Matt Watkins(Securi-Tay2017)](https://www.youtube.com/watch?v=ihElrBBJQo8)
			* In this talk, we’ll explain some of the technical concepts of threat hunting. We will be looking at what is beyond traditional signature detection – the likes of AV, IPS/IDS and SIEMs, which in our experience are ineffective – and detailing some of the ways you can catch real attackers in the act. As a case study, we’ll look at some of the specifics of common attack frameworks - the likes of Metasploit and Powershell Empire - walking through an example attack, and showing how they can be detected. From large-scale process monitoring to live memory analysis and anomaly detection techniques, we will cover some of the technical quirks when it comes to effective attack detection.
* **Hunt Stuff/Supporting Info**
	* **Tools**
		* [threathunting](https://github.com/bradleyjkemp/threathunting)
			* Assorted, MIT licensed, threat hunting rules from `@bradleyjkemp`
		* [TheThreatHuntLibrary](https://github.com/svch0stz/TheThreatHuntLibrary)
			* A collection of organised hunts based of yaml files to create markdown pages for analyst use.
		* [AutonomousThreatSweep](https://github.com/Securonix/AutonomousThreatSweep)
			* The repository provides threat hunting queries for various threats/attacks that can be leveraged directly within the Securonix Snypr platform. 
		* [Wild Hunt](https://github.com/RiccardoAncarani/wild-hunt)
			* A collection of tools and offensive techniques aimed at actively finding adversaries 
		* [Advanced hunting queries for Microsoft 365 Defender](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
			* This repo contains sample queries for advanced hunting in Microsoft 365 Defender. With these sample queries, you can start to experience advanced hunting, including the types of data that it covers and the query language it supports. You can also explore a variety of attack techniques and how they may be surfaced through advanced hunting.
		* [Hunts - Threat Hunting Project](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts)
* **ICS**
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Papers**
		* [Hunting for Threats in Industrial Environments and Other Scary Places - Nick Tsamis(BSides Charm2019)](https://www.youtube.com/watch?v=BbE_op7xhcI)
			* Threat hunting in Industrial Control Systems is a proactive tactic that can be employed by network defenders to gain familiarity with network terrain and to seek out malicious behavior, presence of vulnerabilities, or otherwise unknown activity. Unique constraints in operational technology environments present significantly different challenges than more standard computing environments. This presentation provides the audience with an inside look into challenges that ICS threat hunters face.
* **Insider(Malicious) Hunting**
	* **Articles/Blogposts/Writeups**
		* [More Behavioral Hunting and Insider Data Theft - Jack Crook(2021)](https://findingbad.blogspot.com/2021/02/more-behavioral-hunting-and-insider.html)
	* **Talks/Presentations/Papers**
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
		* [ Part 2: Intro to Threat Hunting – Understanding the attacker mindset with Powershell Empire and the Mandiant Attack Lifecycle - Spartan2194(2020)](https://holdmybeersecurity.com/2020/01/23/part-2-intro-to-threat-hunting-understanding-the-attacker-mindset-with-powershell-empire-and-the-mandiant-attack-lifecycle/)
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
* **Linux**<a name="thlin"></a>
	* **Hunting Privilege Escalation**
		* [Detecting MITRE ATT&CK: Privilege escalation with Falco - Stefano Chierici(2021)](https://sysdig.com/blog/mitre-privilege-escalation-falco/)
* **macOS**<a name="thmac"></a>
	* [Making your own logarchive from a backup - hoakley](https://eclecticlight.co/2020/02/07/making-your-own-logarchive-from-a-backup/)
	* [Creating Privacy Preferences Policy Control profiles for macOS - rtrouton(2018)](https://derflounder.wordpress.com/2018/08/31/creating-privacy-preferences-policy-control-profiles-for-macos/)
	* [MacOS host monitoring - the open source way - Michael George(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/s30-macos-host-monitoring-the-open-source-way-michael-george)
		* MacOS host monitoring - the open source way, I will talk about a example piece of malware(Handbrake/Proton) and how you can use open source tooling detection tooling to do detection and light forensics. Since I will be talking about the handbrake malware, I will also be sharing some of the TTPs the malware used if you want to find this activity in your fleet.
	* **101**
		* [Capturing the moment in your log: how to identify a problem - hoakley(2019)](https://eclecticlight.co/2019/09/17/capturing-the-moment-in-your-log-how-to-identify-a-problem/)
		* [A Guide to macOS Threat Hunting and Incident Response - Phil Stokes](https://assets.sentinelone.com/c/sentinal-one-mac-os-?)
	* **Articles/Writeups**
		* [Working with TrustedBSD in Mac OS X - Alexander Stavonin(2013)](https://sysdev.me/trusted-bsd-in-osx/)
		* [Hunting for Bad Apples – Part 1 - Richie Cyrus(2018)](https://securityneversleeps.net/2018/06/25/hunting-for-bad-apples-part-1/)
		* [Malware Hunting on macOS | A Practical Guide - PHil Stokes(2019)](https://www.sentinelone.com/blog/malware-hunting-macos-practical-guide/)
		* [macOS Post Summary - Action Dan(2020)](https://lockboxx.blogspot.com/2020/06/macos-post-summary.html)
			* " This post is going to be a collection of my previous individual posts researching macOS security specifics. I realized I did a bunch of these posts over the span of several years and hadn't tagged them all the same, so I wanted to collect them for new readers in a summary of sorts. For those new readers, this is mostly a collection of my 100-level forensics series, my 200-level red team series, and a few one-off posts around the OS. Those two series were essentially month long deep dives where I approached the macOS operating system from different perspectives. Those series had a few years in between them, so some of the information may be dated, but I hope people find this helpful!"
		* [Mac system extensions for threat detection: Part 1 - Will Yu](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-1)
			* [Part 2](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-2)
			* [Part 3](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-3)
			* In part 1 of this series, we’ll go over some of the frameworks accessible by kernel extensions that provide information about file system, process, and network events. These frameworks include the Mandatory Access Control Framework, the KAuth framework, and the IP/socket filter frameworks. We won't do a deep dive into each one of these frameworks specifically, as there have been many other posts and guides [0](https://www.synack.com/blog/monitoring-process-creation-via-the-kernel-part-i/) [1](https://www.apriorit.com/dev-blog/411-mac-os-x-kauth-listeners) [2](https://reverse.put.as/2014/10/03/can-i-suid-a-trustedbsd-policy-module-to-control-suid-binaries-execution/) [3](https://developer.apple.com/library/archive/technotes/tn2127/_index.html) [4](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) regarding how to use these frameworks. Instead, we’ll recap and review each of these frameworks, then in [part 2](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-2) we’ll cover some valuable tips and tricks we can use inside the kernel extensions framework that will no longer be available in the new SystemExtensions framework starting in macOS 10.15. And finally, in [part 3](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-3) of the series, we’ll cover the new SystemExtensions framework and the features it provides to third-party developers.
		* [Job(s) Bless Us!Privileged Operations on macOS - Julia Vaschenko(OBTSv3.0)](https://objectivebythesea.com/v3/talks/OBTS_v3_jVashchenko.pdf)
		* [Low-Level Process Hunting on macos - themittenmac](https://themittenmac.com/low-level-process-hunting-on-macos/)
		* [The TrueTree Concept - Jaron Bradley](https://themittenmac.com/the-truetree-concept/)
		* [Low-Level Process Hunting on macOS - Jaron Bradley(2020)](https://objective-see.com/blog/blog_0x4A.html)
		* [Hypothesis-driven MacOS Threat Hunting - Plug(Derpcon2020)](https://www.youtube.com/watch?v=o1rQfLI1pWo&list=PLCXnHhr5mRLzgWG8852x2E_ihkBM3pvxf&index=9)
			* "MacOS is a popular operating system deployed across many organizations. Few commercial tools exist that provide proper event visibility in MacOS. Often, these tools are expensive and some lack important monitoring features. However, open-source offers a great selection of tools that can be deployed to kick start a MacOS Threat Hunting Program. In this talk, we will simplify threat hunting and present a technique to create a reliable and useful hunt hypothesis. With only a few open-source tools we will provide and guide the audience on a repeatable methodology to hunt for threats in MacOs or any other OS."
		* [20 Common Tools & Techniques Used by macOS Threat Actors & Malware - Phil Stokes(2021)](https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/)
		* [Threat Hunting and Mitigation in `*Nix`/macOS Environments. (Please comment and tell me what I'm missing. This is initial work) - hartescout(2021)](https://0x00sec.org/t/threat-hunting-and-mitigation-in-nix-macos-environments-please-comment-and-tell-me-what-im-missing-this-is-initial-work/25446)
	* **Talks & Presentations**
		* ["MacDoored" Bradley, OBTS v1.0](https://www.youtube.com/watch?v=ObiSt_RYOOM)
			* [Slides](https://themittenmac.com/publication_docs/OBTS_v1_Bradley.pdf)
		* [When Macs Come Under ATT&CK - Richie Cyrus(OBTSv1.0)](https://www.youtube.com/watch?v=X99QKMCVOBc)
			* This talk will discuss common tactics, techniques and procedures used by attackers on MacOS systems, as well as methods to detect adversary activity. We will take a look at known malware, mapping the techniques utilized to the MITRE ATT&CK framework. Attendees will leave equipped to begin hunting for evil lurking within their MacOS fleet.
		* [Comparing apples to Apple - Adam Mathis(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/stable-37-comparing-apples-to-apple-adam-mathis)
			* Many defenders have hard fought experience finding evil on Windows systems, but stare blankly when handed a Mac. You know all the ways PowerShell can own a box, but how about AppleScript? This practical talk will give defenders a primer in finding adversarial activity on macOS using the TTPs they know and love from other platforms as a reference point.
		* [When Macs Come Under ATT&CK - Richie Cyrus(Derbycon2018)](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-01-when-macs-come-under-attck-richie-cyrus)
		* [Investigating Macs at the Speed of Compromise - Tim Crothers(BSides Augusta2019)](https://www.youtube.com/watch?v=o88k_0tDINo&list=PLEJJRQNh3v_PF6cecq0ES2w25JtoG631g&index=12)
		* [Grafting Apple Tree’s: Building a useful process tree - Jaron Bradley(ObjectiveByTheSea v3 2020)](https://themittenmac.com/wp-content/uploads/2020/03/OBTS_V3_Bradley.pdf)
		* [Post Infection Analysis on macOS Hosts - Cedric Owens(A Conference for Defense/ACoD(2020))](https://www.youtube.com/watch?v=u2bvLyuF0HQ)
			* This talk covers post infection analysis as well as some simple yet effective detections for macOS hosts in an enterprise. I will discuss different macOS system artifacts that are useful for investigators, how to query these artifacts, common persistence locations, browser history/ data, log data, network information, process information, and other important pieces of information that defenders can leverage to aid during investigations.
	* **Papers**
		* [Logs Unite! Forensic Analysis Of Apple Unified Logs - Sarah Edwards(2017)](https://papers.put.as/papers/macosx/2017/LogsUnite.pdf)
	* **Tools**
		* [Venator](https://github.com/richiercyrus/Venator)
			* Venator is a python tool used to gather data for proactive detection of malicious activity on macOS devices.
			* [Blogpost - Richie Cyrus(2019)](https://posts.specterops.io/introducing-venator-a-macos-tool-for-proactive-detection-34055a017e56)
			* [Cleaning the Apple Orchard Using Venator to Detect macOS Compromise - Richie Cyrus(BSides Charm 2019)]
				* Various solutions exist to detect malicious activity on macOS. However, they are not intended for enterprise use or involve installation of an agent. This session will introduce and demonstrate how to detect malicious macOS activity using the tool Venator. Venator is a python based macOS tool designed to provide defenders with the data to proactively identify malicious macOS activity at scale.
		* [TrueTree](https://github.com/themittenmac/TrueTree)
			* TrueTree is more than just a pstree command for macOS. It is used to display a process tree for current running processes while using a hierarchy built on additoinal pids that can be collected from the operating system. The standard process tree on macOS that can be built with traditional pids and ppids is less than helpful on macOS due to all the XPC communication at play. The vast majority of processes end up having a parent process of launchd. TrueTree however displays a process tree that is meant to be useful to incident responders, threat hunters, researchers, and everything in between!
			* [Blogpost](https://themittenmac.com/the-truetree-concept/)
		* [macOS-ATTACK-DATASET](https://github.com/sbousseaden/macOS-ATTACK-DATASET)
			* JSON DATASET for macOS mapped to MITRE ATT&CK Techniques and Tactics recorded using Elastic Endpoint Security for macOS.
		* [tccprofile](https://github.com/carlashley/tccprofile)
* **Windows**<a name="thwin"></a>
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
		* **Tools**
			* [ARTHIR](https://github.com/MalwareArchaeology/ARTHIR)
				* ATT&CK Remote Threat Hunting Incident Response (ARTHIR) is an update to the popular KANSA framework. ARTHIR works differently than KANSA in that you can create output with your ARTHIR module and then the results are pulled back to the launching host. KANSA only pulled console output back which limited its capabilities. KANSA was unable to execute binary utilities and tools such as LOGMD remotely and pull reports back. ARTHIR can run scripts as KANSA does, but also binary utilities and tools, making ARTHIR much more flexible than KANSA.
	* **Active Directory**
		* **101**
			* [Monitoring Active Directory for Signs of Compromise - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
				* Applies To: Windows Server 2016, Windows Server 2012 R2, Windows Server 2012
			* [Appendix L: Events to Monitor - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
				* The following table lists events that you should monitor in your environment, according to the recommendations provided in [Monitoring Active Directory for Signs of Compromise](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise).
		* **Articles/Writeups**
			* [Domain controllers required ports: Use PowerShell to check if they are listening - Nirmal Sharma(2017)](https://techgenix.com/domain-controllers-required-ports/)
			* [Detecting Kerberoasting activity using Azure Security Center - Moti Bani(2018)](https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/)
			* [Detecting Attackers in a Windows Active Directory Network - Mark Gamache(2017)](https://markgamache.blogspot.com/2017/08/detecting-attackers-in-windows-active.html)
			* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts - Roberto Rodriguez(2018)](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
			* [The only PowerShell Command you will ever need to find out who did what in Active Directory - Przemyslaw Klys(2019)](https://evotec.xyz/the-only-powershell-command-you-will-ever-need-to-find-out-who-did-what-in-active-directory/)
			* [Using Active Directory Replication Metadata for hunting purposes - Huy(2020)](https://web.archive.org/web/20210301212444/https://security-tzu.com/2020/11/09/active-directory-replication-metadata-for-forensics-purposes/)
			* [ Inside Microsoft Threat Protection: Solving cross-domain security incidents through the power of correlation analytics - Defender365 Team(2020)](https://www.microsoft.com/security/blog/2020/07/29/inside-microsoft-threat-protection-solving-cross-domain-security-incidents-through-the-power-of-correlation-analytics/)
			* [Hunting for Skeleton Key Implants - Riccardo Ancarani(2021](https://riccardoancarani.github.io/2020-08-08-hunting-for-skeleton-keys/)
			* [Velociraptor vs. PrintNightmare - Matthew Green, Mike Cohen(2021)](https://velociraptor.velocidex.com/velociraptor-vs-printnightmare-6cc38c5b3d14?gi=2365674c61a2)
			* [Detecting PetitPotam AD CS and other Domain Controller Account Takeovers - Mehmet Ergene(2021)](https://posts.bluraven.io/detecting-petitpotam-and-other-domain-controller-account-takeovers-d3364bd9ee0a)
		* **Talks/Presentations/Videos**
			* [Detecting the Elusive Active Directory Threat Hunting - Sean Metcalf(BSidesCharm2017)](https://www.youtube.com/watch?v=9Uo7V9OUaUw)
				* Attacks are rarely detected even after months of activity. What are defenders missing and how could an attack by detected? This talk covers effective methods to detect attacker activity using the features built into Windows and how to optimize a detection strategy. The primary focus is on what knobs can be turned and what buttons can be pushed to better detect attacks. One of the latest tools in the offensive toolkit is ""Kerberoast"" which involves cracking service account passwords offline without admin rights. This attack technique is covered at length including the latest methods to extract and crack the passwords. Furthermore, this talk describes a new detection method the presenter developed. The attacker's playbook evolves quickly, defenders need to stay up to speed on the latest attack methods and ways to detect them. This presentation will help you better understand what events really matter and how to better leverage Windows features to track, limit, and detect attacks.
				* [Slides](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)
		* **Tools**
			* [WatchAD](https://github.com/0Kee-Team/WatchAD)
				* After Collecting event logs and kerberos traffic on all domain controllers, WatchAD can detect a variety of known or unknown threats through features matching, Kerberos protocol analysis, historical behaviors, sensitive operations, honeypot accounts and so on. The WatchAD rules cover the many common AD attacks.
		* **AMSI**
			* [Antimalware Scan Interface Detection Optics Analysis Methodology: Identification and Analysis of AMSI for WMI - Matt Graeber(2019)](https://posts.specterops.io/antimalware-scan-interface-detection-optics-analysis-methodology-858c37c38383?gi=cb4c7a775a96)
	* **Audit Policy**
		* **Articles/Writeup**
			* [Audit User/Device Claims - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-device-claims)
				* "Audit User/Device Claims allows you to audit user and device claims information in the account’s logon token. Events in this subcategory are generated on the computer on which a logon session is created. For an interactive logon, the security audit event is generated on the computer that the user logged on to. For a network logon, such as accessing a shared folder on the network, the security audit event is generated on the computer hosting the resource."
		* **Tools**
			* [Audix](https://github.com/littl3field/Audix)
				* Audix is a PowerShell tool to quickly configure the Windows Event Audit Policies for security monitoring 
			* [PSGumshoe](https://github.com/PSGumshoe/PSGumshoe)
				* PSGumshoe is a Windows PowerShell module for the collection of OS and domain artifacts for the purposes of performing live response, hunt, and forensics. The module focuses on being as forensically sound as possible using existing Windows APIs to achieve the collection of information from the target host.
			* [Windows-auditing-mindmap](https://github.com/mdecrevoisier/Windows-auditing-mindmap)
				* Set of Mindmaps providing a detailed overview of the different #Windows auditing capacities and event log files.
	* **Autoruns**
		* [How to Use Autoruns to Detect and Remove Malware on Windows - Neil Fox(2021)](https://www.varonis.com/blog/how-to-use-autoruns/)
	* **Azure**
		* **Articles/Writeups**
			* [Identifying Threat Hunting opportunities in your data - shainw](https://techcommunity.microsoft.com/t5/azure-sentinel/identifying-threat-hunting-opportunities-in-your-data/ba-p/915721)
	* **Binaries**
		* [Import hashing (aka imphashes) - hacker0ni(2020)](https://hackerspot.net/2020/11/24/import-hashing-aka-imphashes/)
	* **BITS**
		* **Articles/Writeups**
			* [Background Intelligent Transfer Protocol - TH Team(2019)](https://medium.com/@threathuntingteam/background-intelligent-transfer-protocol-ab81cd900aa7)
			* [Back in a Bit: Attacker Use of the Windows Background Intelligent Transfer Service - David Via, Scott Runnels(2021)](https://www.fireeye.com/blog/threat-research/2021/03/attacker-use-of-windows-background-intelligent-transfer-service.html)
			* [Hunting for Suspicious Usage of Background Intelligent Transfer Service (BITS) - Menasec(2021)](https://blog.menasec.net/2021/05/hunting-for-suspicious-usage-of.html)
	* **Browser Extensions**
		* **Articles/Writeups**
			* [Chrome Extensions: Bypassing your security - Pablo Delgado(2017)](https://www.syspanda.com/index.php/2017/11/02/chrome-extensions-bypassing-security/)
				* Hunting Chrome extensions in Win AD environment with Sysmon and ELK.
	* **cmd.exe**
		* [Windows Command-Line Obfuscation - @Wietze(2021)](https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation)
	* **Camera & Mic**
		* [Can You Track Processes Accessing the Camera and Microphone on Windows 10? - Zachary Stanford(2020)](https://dfir.pubpub.org/pub/nm5b39ae/release/1)
	* **Credential Access**
		* **Articles/Writeups**
			* [How to Detect Overpass-The-Hash Attacks - Jeff Warren](https://blog.stealthbits.com/how-to-detect-overpass-the-hash-attacks/)
			* [Hunting for Credentials Dumping in Windows Environment - Teymur Kheirhabaro(ZeroNights2017)](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
			* [Tales of a Threat Hunter 1: Detecting Mimikatz & other Suspicious LSASS Access - Part 1 - @darkQuassar(2017)(https://www.eideon.com/2017-09-09-THL01-Mimikatz/)
			* [Deception in Depth - LSASS Injection - spookysec(2021)](https://blog.spookysec.net/DnD-LSASS-Injection/)
			https://risksense.com/blog/hidden-gems-in-windows-the-hunt-is-on/
			* [Fantastic Windows Logon types and Where to Find Credentials in Them - Chirag Salva, Anas Jamal(2021)](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
		* **Papers**
			* [A Process is No One: Hunting for Token Manipulation - Jared Atkinson, Robby Winchester(2017)](https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation-wp.pdf)
				*  In this paper, we will outline how we view hunting through our five step approach to perform hypothesis driven hunting. In addition, we will walk through a case study detecting Access Token Manipulation, highlighting the actions performed at each step of the process. At the conclusion of the paper, the reader should better understand hunting, our five-step hypothesis process, and how to apply it to real world scenarios.
	* **COM**
		* **Articles/Writeups**
			* [Hunting COM Objects - Charles Hamilton](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html)
			* [Hunting COM Objects (Part Two) - Brett Hawkins](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects-part-two.html)
			* [Falcon Friday - Remote Services: Distributed Component Object Model](https://github.com/FalconForceTeam/FalconFriday/blob/master/Lateral%20Movement/T1021-WIN-002.md)
	* **CSharp**
		* [Interesting DFIR traces of .NET CLR Usage Logs - menasec.net](https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html)
	* **DLLs**
		* [What is normal? Profiling System32 binaries to detect DLL Search Order Hijacking - Michael Haag, Shane Welcher(2021)](https://redcanary.com/blog/system32-binaries/)
		* [Hunting for Evidence of DLL Side-Loading With PowerShell and Sysmon - John Dwyer(2021)](https://securityintelligence.com/posts/hunting-evidence-dll-side-loading-powershell-sysmon/)
			* [Windows Feature Hunter](https://github.com/xforcered/WFH)
	* **Drivers**
		* [Detecting and Hunting for the Malicious NetFilter Driver - Michael Gough(2021)](https://research.nccgroup.com/2021/07/16/detecting-and-hunting-for-the-malicious-netfilter-driver/)
	* **Event Logs**
		* **Articles/Writeups**
			* [Windows 10, version 21H1, Windows 10, version 20H2 and Windows 10, version 2004 required Windows diagnostic events and fields - docs.ms](https://docs.microsoft.com/en-gb/windows/privacy/required-windows-diagnostic-data-events-and-fields-2004)
				* `It's just a little bit of telemetry to help them diagnose Windows...`
			
			* [Linking Event Messages and Resource DLLs - Andreas Schuster(2010)](https://computer.forensikblog.de/en/2010/10/linking-event-messages-and-resource-dlls.html)
			* [Maintaining Persistence and Password Hash Dumping using Meterpreter and Mimikatz - ](https://tranquilsec.com/meterpreter-mimikatz/)
			* [How to Recover Corrupted EVTX Log Files and Extract Information - Paula Januszkiewicz(2020)](https://cqureacademy.com/blog/hacks/how-to-recover-corrupted-evtx-log-files-and-extract-information)
		* **Talks/Presentations/Videos**
			* [What Event Logs? Part 1: Attacker Tricks to Remove Event Logs - Matt Bromiley(SANS DFIR 2018)](https://www.youtube.com/watch?v=7JIftAw8wQY)
				* In part 1 of this series, SANS instructor and incident responder Matt Bromiley focuses on techniques, old and new, that attackers are using to neutralize event logs as a recording mechanism. Ranging from clearing of logs to surgical, specific event removal, in this webcast we will discuss how the attackers are doing what they're doing, and the forensic techniques we can use to detect their methods. There has been a lot of discussions lately about attackers' ability to fool the system into not writing event logs - but are our attackers truly staying hidden when they do this? Let's find out!
			* [What Event Logs Part 2 Lateral Movement without Event Logs - Matt Bromiley(SANS DFIR 2018)](https://www.youtube.com/watch?v=H8ybADELHzk)
				* In part 2 of this series, SANS instructor and incident responder Matt Bromiley will discuss techniques to identify lateral movement when Windows Event Logs are not present. Sometimes logs roll without preservation, and sometimes attackers remove them from infected systems. Despite this, there are still multiple artifacts we can rely on to identify where our attackers came from, and where they went. In this webcast, we'll discuss the techniques and artifacts to identify this activity.
		* **Tools**
			* [Search-Event.ps1](https://github.com/Ben0xA/PowerShellScripts/blob/main/Search-Event.ps1)
			* [windows-basic-event-logs Mindmap](https://github.com/christophetd/hunting-mindmaps/blob/master/pdf/windows-basic-event-logs.pdf)
	* **Execution & Executables**
		* **Articles/Blogposts/Writeups**
			* [Did It Execute? - Mary Singh(2013)](https://www.fireeye.com/blog/threat-research/2013/08/execute.html)
			* [Case studies in Rich Header analysis and hunting - Jeff White(2018)](http://ropgadget.com/posts/richheader_hunting.html)
			* [Wanted: Process Command Lines - Oddvar Moe(2020)](https://www.trustedsec.com/blog/wanted-process-command-lines/)
			* [Static Detection of Portable Executable Files - Winternl(2020)](https://winternl.com/static-detection-of-portable-executable-files/)
		* **Talks/Presentations/Videos**
	* **FileSystem**
		* OSQuery
		* **Articles/Blogposts/Writeups**
			* [Complete Guide to Windows File System Auditing - Jeff Peters(2021)](https://www.varonis.com/blog/windows-file-system-auditing/)
	* **File Downloads**
		* **Articles/Blogposts/Writeups**
			* [Downloads and the Mark-of-the-Web - ericlaw(2016)](https://textslashplain.com/2016/04/04/downloads-and-the-mark-of-the-web/)
	* **Hidden Desktops**
		* [HiddenDesktopViewer](https://github.com/AgigoNoTana/HiddenDesktopViewer)
			* This tool reveals hidden desktops and investigate processes/threads utilizing hidden desktops
	* **HTML Smuggling**
		* **Articles/Blogposts/Writeups**
			* [Detecting HTML smuggling attacks using Sysmon and Zone.Identifier files - @securityjosh(2021)](https://securityjosh.github.io/2021/01/27/Detect-HTML-Smuggling-Sysmon.html)
			* [Detecting Initial Access: HTML Smuggling and ISO Images — Part 2 - Mehmet Ergene(2021)](https://posts.bluraven.io/detecting-initial-access-html-smuggling-and-iso-images-part-2-f8dd600430e2)
	* **In-Memory**
		* **101**
			* [memory-hunting Mindmap](https://github.com/christophetd/hunting-mindmaps/blob/master/pdf/memory-hunting.pdf)
		* **Articles/Blogposts/Writeups**
			* [HeapWalk function - docs.ms](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapwalk)
				* Enumerates the memory blocks in the specified heap.			
			* [Understanding and Evading Get-InjectedThread - XPNSec(2018)](https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/)
			* [Hook Heaps and Live Free - Arash Parsa(2021)](https://www.arashparsa.com/hook-heaps-and-live-free/)
		* **Talks/Presentations/Videos**
			* [Hunting for Memory-Resident Malware - Joe Desimone(Derbycon2017)](https://archive.org/details/DerbyCon7/S21-Hunting-for-Memory-Resident-Malware-Joe-Desimone.mp4)
				* Once a staple of nation state level adversaries, memory-resident malware techniques have become ubiquitous even for lowly criminal activity. With their ability to evade endpoint protection products, it is critical for defenders to understand and defend against these techniques. In this talk, I will describe both common and advanced stealth malware techniques which evade today's hunt tools and methodologies. Attendees will learn about adversary stealth and understand ways to detect some of these methods. New code for rapidly hunting for these techniques across your enterprise will be released.
			* [Gargoyle Hunting In-Depth — Aliz Hammond(Infosec In the City(2020)](https://www.youtube.com/watch?v=T73GK1Y8jLU)
				* Detecting certain user-mode code-hiding techniques, such as Josh Lospinoso's 'Gargoyle', is almost impossible from user-space. In this talk, I will examine Gargoyle, and explain how it can be detected from kernel mode. I will first walk through using WinDbg to locate hidden code and then write a Volatility plugin to turn this process into a practical method of detecting real-world attacks — in the process, adding a reliable method of differentiating these from legitimate behavior.
		* **Tools**
			* [GetInjectedThreads.cs](https://github.com/Apr4h/GetInjectedThreads)
				* C# Implementation of Jared Atkinson's Get-InjectedThread.ps1
			* [Memhunter](https://github.com/marcosd4h/memhunter)
				* "The tool is a standalone binary that, upon execution, deploys itself as a windows service. Once running as a service, memhunter starts the collection of ETW events that might indicate code injection attacks. The live stream of collected data events is feed into memory inspection scanners that use detection heuristics to down select the potential attacks. The entire detection process does not require human intervention, neither memory dumps, and it can be performed by the tool itself at scale."
			* [Moneta](https://github.com/forrest-orr/moneta)
				* Moneta is a live usermode memory analysis tool for Windows with the capability to detect malware IOCs 
			* [PE-sieve](https://github.com/hasherezade/pe-sieve)
				*  PE-sieve is a tool that helps to detect malware running on the system, as well as to collect the potentially malicious material for further analysis. Recognizes and dumps variety of implants within the scanned process: replaced/injected PEs, shellcodes, hooks, and other in-memory patches. Detects inline hooks, Process Hollowing, Process Doppelgänging, Reflective DLL Injection, etc.
			* [hollows_hunter](https://github.com/hasherezade/hollows_hunter)
				* Scans all running processes. Recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).
	* **ISO Files**
		* **Articles/Writeups**
			* [Threat Thursday - Evading Defenses with ISO files like NOBELIUM - Jorge Orchilles(2021)](https://www.scythe.io/library/threat-thursday-evading-defenses-with-iso-files-like-nobelium)
	* **Kernel-related**
		* **101**
			* [4656(S, F): A handle to an object was requested. - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4656)
				* "This event indicates that specific access was requested for an object. The object could be a file system, kernel, or registry object, or a file system object on removable storage or a device.  If access was declined, a Failure event is generated.  This event generates only if the object’s SACL has the required ACE to handle the use of specific access rights.  This event shows that access was requested, and the results of the request, but it doesn’t show that the operation was performed. To see that the operation was performed, check “4663(S): An attempt was made to access an object.”"
		* **Articles/Writeups**
			* [Shellcode Detection Using Real-Time Kernel Monitoring - Alonso Candado()](https://www.countercraftsec.com/blog/post/shellcode-detection-using-realtime-kernel-monitoring/)
			* [Detecting EDR Bypass: Malicious Drivers(Kernel Callbacks) - Mehmet Ergene(2021)](https://posts.bluraven.io/detecting-edr-bypass-malicious-drivers-kernel-callbacks-f5e6bf8f7481)
	* **Lateral Movement**
		* **Articles/Writeups**
			* [Threat Hunting for PsExec, Open-Source Clones, and Other Lateral Movement Tools - Tony Lambert(2018)](https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/)
			* [Digging Into Sysinternals: PsExec - Matt B(2016)](https://medium.com/@bromiley/digging-into-sysinternals-psexec-64c783bace2b#.htmvaklhy)
		* **Talks/Presentations/Videos**
			* [Spotting Lateral Movement with Endpoint Data - Tony Lambert(BSides Augusta2019)](https://www.youtube.com/watch?v=rqMBMA5W_OM&list=PLEJJRQNh3v_PF6cecq0ES2w25JtoG631g&index=26)
		* **Tools**
			* [kethash](https://github.com/cyberark/ketshash)
				* A little tool for detecting suspicious privileged NTLM connections, in particular Pass-The-Hash attack, based on event viewer logs.
	* **LoLBins**
		* **Articles/Writeups**
			* [Background Intelligent Transfer Protocol - TH Team](https://medium.com/@threathuntingteam/background-intelligent-transfer-protocol-ab81cd900aa7)
			* [Hidden in plain sight? - @casheeew(BlackHoodie2018)](https://blackhoodie.re/assets/archive/hidden_in_plain_sight_blackhoodie.pdf)
			* [FalconFriday — Detecting suspicious code compilation and Certutil — 0xFF02 - Olaf Hartong(2020)](https://medium.com/falconforce/falconfriday-detecting-certutil-and-suspicious-code-compilation-0xff02-cfe8fb5e159e)
	* **.NET**
		* **Articles/Writeups**
			* [Using .NET GUIDs to Hunt .NET Malware - Brian Wallace(2015)](https://www.virusbulletin.com/virusbulletin/2015/06/using-net-guids-help-hunt-malware/)
			* [Interesting DFIR traces of .NET CLR Usage Logs - menasec.net](https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html)
			* [Deep Dive: .NET Malware — Peeling Back the Layers - John Ferrell(2018)](https://blog.huntresslabs.com/deep-dive-net-malware-peeling-back-the-layers-37ae63b475e0?gi=ddb4cb82c2b3)
			* [Using Windows Antimalware Scan Interface in .NET - Gérald Barré(2020)](https://www.meziantou.net/using-windows-antimalware-scan-interface-in-dotnet.htm)
			* [Detecting attacks leveraging the .NET Framework - Zac Brown, Shane Welcher(2020)](https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/)
			* [Hunting For In-Memory .NET Attacks - Joe Desimone(2017)](https://www.elastic.co/blog/hunting-memory-net-attacks)
			* [Hunting for SILENTTRINITY - Wee-Jing Chung(2019)](https://blog.f-secure.com/hunting-for-silenttrinity/)
				* SILENTTRINITY (byt3bl33d3r, 2018) is a recently released post-exploitation agent powered by IronPython and C#. This blog post will delve into how it works and techniques for detection.
			* [Analysis: Abuse of .NET features for compiling malicious programs - Karen Victor and Matthew Fernandez(2020)](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/analysis-abuse-of-net-features-for-compiling-malicious-programs)
			* [CIMplant Part 1: Detection of a C# Implementation of WMImplant - FortyNorthSecurity(2021)](https://fortynorthsecurity.com/blog/cimplant-part-1-detections/)
			* [Hiding Your .NET – ETW - Adam Chester(2020)](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)
		* **Tools**
			* [ClrGuard](https://github.com/endgameinc/ClrGuard)
				* ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes. ClrGuard leverages a simple appInit DLL (ClrHook32/64.dll) in order to load into all CLR/.NET processes. From there, it performs an in-line hook of security critical functions. Currently, the only implemented hook is on the native LoadImage() function. When events are observed, they are sent over a named pipe to a monitoring process for further introspection and mitigation decision.
			* [Sniper](https://github.com/dmchell/Sniper)
				* A simple proof of concept for detecting use of Cobalt Strike's execute-assembly
	* **Named Pipes**
		* **Articles/Writeups**
			* [Stealthy Peer-to-peer C&C over SMB pipes - Raphael Mudge(2013)](https://blog.cobaltstrike.com/2013/12/06/stealthy-peer-to-peer-cc-over-smb-pipes/)
			* [Detecting Namedpipe Pivoting using Sysmon - Menasec(2019)](https://blog.menasec.net/2019/04/detecting-namedpipe-pivoting-using.html)
			* [Detecting Cobalt Strike Default Modules via Named Pipe Analysis - Riccardo Ancarani(2020)](https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis)
			* [Detecting known DLL hijacking and named pipe token impersonation attacks with Sysmon - xnand(2020)](https://labs.jumpsec.com/detecting-known-dll-hijacking-and-named-pipe-token-impersonation-attacks-with-sysmon/)	
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
	* **PowerShell**
		* **Articles/Writeups**
			* [Hunting for AMSI bypasses - Wee-Jing Chun(2019)](https://blog.f-secure.com/hunting-for-amsi-bypasses/)
			* [Revoke -­‐ Obfuscation: PowerShell Obfuscation Detection Using Science](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf)
			* [Attack and Defense Around PowerShell Event Logging - Mina Hao(2019)](https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging)
				* Blogpost discussing logging mechanisms in PowerShell up to v6.
			* [Greater Visibility Through PowerShell Logging - Matthew Dunwoody(2016)](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
			* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
				* a PowerShell Module for Threat Hunting via Windows Event Logs
			* [Securing PowerShell in the Enterprise - Australian Cyber Security Center(2020)](https://www.cyber.gov.au/publications/securing-powershell-in-the-enterprise)
				* This document describes a maturity framework for PowerShell in a way that balances the security and business requirements of organisations. This maturity framework will enable organisations to take incremental steps towards securing PowerShell across their environment; Appendix E - Strings for log analysis
			* [From PowerShell to P0W3rH3LL – Auditing PowerShell - ingmar.koecher(2018)](https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html)
			* [Uncovering Indicators of Compromise (IoC) Using PowerShell, Event Logs, and a Traditional Monitoring Tool](https://www.sans.org/reading-room/whitepapers/critical/uncovering-indicators-compromise-ioc-powershell-event-logs-traditional-monitoring-tool-36352)
			* [Detecting Offensive PowerShell Attack Tools - adsecurity.org](https://adsecurity.org/?p=2604)
			* [Attack and Defense Around PowerShell Event Logging - Mina Hao(2019)](https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging)
				* This document dwells upon security features of the logging function of major versions of PowerShell, as well as attack means, ideas, and techniques against each version of the event viewer.
			* [Detecting Modern PowerShell Attacks with SIEM - Justin Henderson](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1511980157.pdf)
			* [Detecting AMSI Bypass - Ionize(2020)](https://ionize.com.au/detecting-amsi-bypass/)
			* [PowerShell Security: Is itEnough? - Timothy Hoffman](https://www.sans.org/reading-room/whitepapers/microsoft/powershell-security-enough-38815)
				* "This paper aims to analyze a PowerShell-based attack campaign and evaluate each security feature in its ability to effectively prevent or detect the attacksindividually and collectively.  These results will in no way be all inclusive, as technology is ever-changing, andnewmethods are emergingto counteract current security measures"
			* [Threat Hunting AMSI Bypasses - netbiosX(2021)](https://pentestlaboratories.com/2021/06/01/threat-hunting-amsi-bypasses/()
		* **Talks/Presentations/Videos**
			* [Hunting for PowerShell Abuse - Teymur Kheirkhabarov(Offzone2019)](https://www.youtube.com/watch?v=_zDdf0GGqdA&list=PL0xCSYnG_iTuNQV9RrCLHdnZgthISKxP4&index=4&t=0s)
				* [Slides](https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse)
				* In the presentation author is going to demostrate an approaches for detection of PowerShell abuses based on different event sources like native Windows logging capabilities as well as usage of additional tools, like Sysmon or EDR solutions. How to collect traces of using PowerShell, how to filter out false positives, and how to find evidence of malicious uses among the remaining after filtering volume of events — all these questions will be answered in the talk for present and future threat hunters.
			* [Tracking Activity and Abuse of PowerShell - Carlos Perez(PSConEU 2019)](https://www.youtube.com/watch?v=O-80e7z4THo)
				* [Slides](https://github.com/darkoperator/Presentations/blob/master/PSConfEU%202019%20Tracking%20PowerShell%20Usage.pdf)
			* [Investigating PowerShell Attacks - Ryan Kazanciyan, Matt Hastings(BHUSA2014)](https://www.youtube.com/watch?v=zUbTM9N7V7w)
				* [Paper](https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks-WP.pdf)
				* This presentation will focus on common attack patterns performed through PowerShell - such as lateral movement, remote command execution, reconnaissance, file transfer, and establishing persistence - and the sources of evidence they leave behind. We'll demonstrate how to collect and interpret these forensic artifacts, both on individual hosts and at scale across the enterprise. Throughout the presentation, we'll include examples from real-world incidents and recommendations on how to limit exposure to these attacks."
			* [Catching the Guerrilla: Powershell Counterinsurgency - Aaron Sawyer(CircleCityCon2019)](https://www.irongeek.com/i.php?page=videos/circlecitycon2019/track-3-06-catching-the-guerrilla-powershell-counterinsurgency-aaron-sawyer)
				* For too long attackers have leveraged the built-in APIs and tooling on Windows systems against us. It's time the tables are turned! Those APIs were made for Sys Admins and defenders... and we're taking them back! **We're building a framework of response tools for defenders to wrestle control from threat actors without the risk of production outages.** This talk will focus on techniques to turn the limited and traditional black-and-white incident response options into a full-color spectrum of alternatives for defending your turf. Attendees will walk away with ideas on how to leverage existing third-party Powershell scripts to stop intruders in their tracks and are encouraged to offer use cases that will produce more tools in the future.
		* **Tooling**
			* [AMSIDetection](https://github.com/countercept/AMSIDetection)
			* [Kansa](https://github.com/davehull/Kansa)
				* A modular incident response framework in Powershell. It's been tested in PSv2 / .NET 2 and later and works mostly without issue. It uses Powershell Remoting to run user contributed, ahem, user contri- buted modules across hosts in an enterprise to collect data for use during incident response, breach hunts, or for building an environmental baseline.
			* [AmsiPatchDetection](https://github.com/IonizeCbr/AmsiPatchDetection)
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
			* [Engineering Process Injection Detections - Part 1: Research - Jonathan Johnson(2020)](https://posts.specterops.io/engineering-process-injection-detections-part-1-research-951e96ad3c85)
				* [Code](https://github.com/jsecurity101/Detecting-Process-Injection-Techniques)
			* [How to Design Abnormal Child Processes Rules without Telemetry - Menasec(2021)](https://blog.menasec.net/2021/01/how-to-design-abnormal-child-processes.html)
			* [Parent PID Spoofing (Stage 2) Ataware Ransomware – Part 0x3 - @securityinbits](https://www.securityinbits.com/malware-analysis/parent-pid-spoofing-stage-2-ataware-ransomware-part-3/)
			* [Detecting Parent PID Spoofing - Noora Hyvärinen(2018)](https://blog.f-secure.com/detecting-parent-pid-spoofing/)
		* **Talks/Presentations/Videos**
			* [Tricking modern endpoint security products - Michel Coene(SANS2020)](https://www.youtube.com/watch?v=xmNpS9mbwEc)
				* The current endpoint monitoring capabilities we have available to us are unprecedented. Many tools and our self/community-built detection rules rely on parent-child relationships and command-line arguments to detect malicious activity taking place on a system. There are, however, ways the adversaries can get around these detections. During this presentation, we'll talk about the following techniques and how we can detect them: Parent-child relationships spoofing; Command-line arguments spoofing; Process injection; Process hollowing
		* **Tools**
			* [PE-Sieve](https://github.com/hasherezade/pe-sieve)
				* [..]tool that helps to detect malware running on the system, as well as to collect the potentially malicious material for further analysis. Recognizes and dumps variety of implants within the scanned process: replaced/injected PEs, shellcodes, hooks, and other in-memory patches. Detects inline hooks, Process Hollowing, Process Doppelgänging, Reflective DLL Injection, etc.
			* [hollows_hunter](https://github.com/hasherezade/hollows_hunter)
				* Scans all running processes. Recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).
			* [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
				* Looks for threads that were created as a result of code injection.
			* [spoofchecker.py](https://github.com/WingsOfDoom/spoofchecker.py)
			* [ppid-spoofing](https://github.com/countercept/ppid-spoofing)
	* **SACLs**
		* [Detecting Windows Endpoint Compromise with SACLs - Dane Stuckey(2018)](https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950)
	* **ShimCache**
		* **Articles/Writeups**
			* [Is Windows ShimCache a threat hunting goldmine? - Tim Bandos](https://www.helpnetsecurity.com/2018/07/10/windows-shimcache-threat-hunting/)
	* **Services**
		* [Services: Windows 10 Services(ss64)](https://ss64.com/nt/syntax-services.html)
			* A list of the default services in Windows 10 (build 1903).
		* [Investigating a Suspicious Service - Chris Basnett(2021)](https://www.mdsec.co.uk/2021/07/investigating-a-suspicious-service/)
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
	* **Registry**
		* **Articles/Writeups**			
		* **Tools**
			* [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
			* [reg_hunter](https://github.com/theflakes/reg_hunter)
				* Blueteam operational triage registry hunting/forensic tool.
			* [Registry_Monitor](https://github.com/zelon88/Registry_Monitor)
				* A Windows script to monitor registry hives for modifications & notify you when modifications have occured. 
	* **Tokens**
		* **Articles/Writeups**
			* [Introduction to Windows tokens for security practitioners - Will Burgess(2020)](https://www.elastic.co/blog/introduction-to-windows-tokens-for-security-practitioners)
			* [Hunting for Privilege Escalation Done with Invoke-TokenManipulation - @malwarenailed(2018)](https://malwarenailed.blogspot.com/2018/08/hunting-for-privilege-escalation-using.html)
			* [Token Manipulation - NetbiosX](https://pentestlab.blog/2017/04/03/token-manipulation/)
			* [Primary Access Token Manipulation - @spotheplanet](https://www.ired.team/offensive-security/privilege-escalation/t1134-access-token-manipulation)
		* **Papers**
			* [A Process is No One: Hunting for Token Manipulation - Jared Atkinson, Robby Winchester](https://www.irongeek.com/i.php?page=videos/derbycon8/stable-01-a-process-is-no-one-hunting-for-token-manipulation-jared-atkinson-robby-winchester)
				* [Paper](https://www.specterops.io/assets/resources/A_Process_is_No_One.pdf)
				* Hunting has become a very popular term and discipline in information security, but there are many different definitions and perspectives surrounding the practice. In this paper, we will outline how we view hunting through our five step approach to perform hypothesis driven hunting. In addition, we will walk through a case study detecting Access Token Manipulation, highlighting the actions performed at each step of the process. At the conclusion of the paper, the reader should better understand hunting, our five-step hypothesis process, and how to apply it to real world scenarios
		* **Talks & Presentations**
			* [Detecting Access Token Manipulation - William Burgess(BHUSA2020)](https://www.youtube.com/watch?v=RMVyYvt0bLY)
				* This presentation aims to demystify how access tokens work in Windows environments and show how attackers abuse legitimate Windows functionality to move laterally and compromise entire Active Directory domains. Most importantly, it will cover how to catch attackers in the act, and at scale, across enterprises. 
	* **WMI**
		* **Articles/Writeups**
			* [Investigating WMI Attacks - Chad Tilbury(2019)](https://www.sans.org/blog/investigating-wmi-attacks/)
		* **Talks & Presentations**
	* **Talks & Presentations**
	* **Tools**
		* [BLUESPAWN](https://github.com/ION28/BLUESPAWN)
			* BLUESPAWN is an active defense and endpoint detection and response tool which means it can be used by defenders to quickly detect, identify, and eliminate malicious activity and malware across a network.
		* [CimSweep](https://github.com/PowerShellMafia/CimSweep)
			* CimSweep is a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows. CimSweep may also be used to engage in offensive reconnaisance without the need to drop any payload to disk. 
* **Cloud**<a name="cloud"></a>
	* **AWS**<a name="aws"></a>
		* **Articles/Writeups**
		* **Talks & Presentations**
			* [Actionable threat hunting in AWS (SEC339) - Chris Farris, Suman Koduri(AWS re:Invent 2019)](https://www.youtube.com/watch?v=kNtiskRtfeY)
				* Learn how WarnerMedia leveraged Amazon GuardDuty, AWS CloudTrail, and its own serverless inventory tool (Antiope) to root out cloud vulnerabilities, insecure behavior, and potential account compromise activities across a large number of accounts. We cover how WarnerMedia centralizes and automates its security tooling, offer detailed Splunk queries for GuardDuty and CloudTrail, and discuss how Antiope is used for vulnerability hunting. We cover the scaling issues incurred during a large enterprise merger. Leave this session with a strategy and an actionable set of detections for finding potential data breaches and account compromises.
				* [Blogpost](https://www.chrisfarris.com/post/reinvent2019-sec339/)
	* **Azure**<a name="azure"></a>
	* **GCP**<a name="gcp"></a>
* **Simulation & Testing**<a name="simulation"></a>
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
	* **Tools**
		* **Data Sets**
			* [Mordor](https://github.com/Cyb3rWard0g/mordor)
				* The Mordor project provides pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files for easy consumption. The pre-recorded data is categorized by platforms, adversary groups, tactics and techniques defined by the Mitre ATT&CK Framework. The pre-recorded data represents not only specific known malicious events but additional context/events that occur around it. This is done on purpose so that you can test creative correlations across diverse data sources, enhancing your detection strategy and potentially reducing the number of false positives in your own environment.
* **Cobalt Strike**<a name="cs"></a>
	* **101**
		* [Cobalt Strike Staging and Extracting Configuration Information - @FranticTyping](https://blog.securehat.co.uk/cobaltstrike/extracting-config-from-cobaltstrike-stager-shellcode)
		* [The art and science  of detecting Cobalt Strike - Nick Mavis(2020)](https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/095/031/original/Talos_Cobalt_Strike.pdf)
		* [Anatomy of Cobalt Strike’s DLL Stager - (Maxime Thebaut(2021)](https://blog.nviso.eu/2021/04/26/anatomy-of-cobalt-strike-dll-stagers/)
		* [Guide to Named Pipes and Hunting for Cobalt Strike Pipes - svchOst(2021)](https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575)
		* [Cobalt Strike and Tradecraft - Hausec(2021)](https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/)
	* **Articles/Blogposts/Writeups**
		* [Analysing Fileless Malware: Cobalt Strike Beacon - @paulsec4(2020](https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon/)
		* [Striking Back at Retired Cobalt Strike: A look at a legacy vulnerability - NCCGroup(2020](https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike-a-look-at-a-legacy-vulnerability/)
		* [Getting the Bacon from the Beacon - Kareem Hamdan, Lucas Miller(2020)](https://www.crowdstrike.com/blog/getting-the-bacon-from-cobalt-strike-beacon/)
			* "This blog discusses CrowdStrike’s research and testing of Cobalt Strike’s Beacon in an isolated Active Directory domain to identify host-based indicators generated from the use of this tool. This blog also enumerates and provides an explanation of host-based artifacts generated as a result of executing specific built-in Beacon commands. The artifacts can be used to create detection and prevention signatures in Windows environments, aiding in the positive identification of remnants of Beacon execution."		
		* [Detecting Cobalt Strike with memory signatures - Joe Desimone(2021](https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures)
		* [How to detect CobaltStrike Command & Control communication - Bogdan Vennyk](https://underdefense.com/how-to-detect-cobaltstrike-command-control-communication/)
		* [Cobalt Strike Hunting — simple PCAP and Beacon Analysis - Michael Koczwara(2021)](https://michaelkoczwara.medium.com/cobalt-strike-hunting-simple-pcap-and-beacon-analysis-f51c36ce6811)
		* [Cobalt Strike Hunting — DLL Hijacking/Attack Analysis - Michael Koczwara(2021)](https://michaelkoczwara.medium.com/cobalt-strike-hunting-dll-hijacking-attack-analysis-ffbf8fd66a4e)
		* [Detecting C&C Malleable Profiles - Lee Kirkpatrick(2021)](https://community.rsa.com/t5/netwitness-blog/detecting-c-amp-c-malleable-profiles/ba-p/607072)
	* **Talks/Presentations/Videos**
	* **Tools**
		* [Sniper](https://github.com/dmchell/Sniper)
			* A simple proof of concept for detecting use of Cobalt Strike's execute-assembly 
		* [CobaltStrikeScan](https://github.com/Apr4h/CobaltStrikeScan)
			* Scan files or process memory for CobaltStrike beacons and parse their configuration
		* [CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
			* Python parser for CobaltStrike Beacon's configuration
		* [CobaltStrikeDetected](https://github.com/huoji120/CobaltStrikeDetected)
		* [1768 K - Didier Stevens](https://blog.didierstevens.com/2020/11/07/1768-k/)
			* This tool decodes and dumps the configuration of Cobalt Strike beacons.
	


### Threat Analysis
* **Tools**
	* [Danger-Zone](https://github.com/woj-ciech/Danger-zone)
		* Correlate data between domains, IPs and email addresses, present it as a graph and store everything into Elasticsearch and JSON files.


### Data Storage & Analysis Stacks<a name="stacks"></a>
* **ELK Stack**<a name="elk"></a>
	* **101**
		* [Introduction to ELK Stack: A primer for beginners - Elastic.co](https://www.elastic.co/webinars/introduction-to-elk-stack-a-primer-for-beginners)
		* [Introduction to logging with the ELK Stack - Elastic.co](https://www.elastic.co/webinars/introduction-elk-stack)
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
* **Splunk**<a name="splunk"></a>
* **Unsorted**
	* **Articles/Writeups**
		* [Hunting Red Team Empire C2 Infrastructure](http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html)
		* [Hunting in Memory](https://www.endgame.com/blog/technical-blog/hunting-memory)
		* [Taking Hunting to the Next Level Hunting in Memory - Jared Atkinson 2017](https://www.youtube.com/watch?v=3RUMShnJq_I)
	* **Talks & Presentations**
		* [Utilizing SysInternal Tools for IT Pros](http://www.microsoftvirtualacademy.com/training-courses/utilizing-sysinternals-tools-for-it-pros#fbid=1IKsqgyvnWp)
	* [Bootsy](https://github.com/IndustryBestPractice/Bootsy)
		* Designed to be installed on a fresh install of raspbian on a raspberry pi, by combining Respounder (Responder detection) and Artillery (port and service spoofing) for network deception, this tool allows you to detect an attacker on the network quickly by weeding out general noisy alerts with only those that matter.
