# Forensics & Incident Response


## Table of Contents
- [Incident Response](#ir)
- [Anti-Forensics](#anti-f)
- [General Forensics - Agnostic](#general-f)
- [Android Forensics](#af)
- [Browser Forensics](#browser)
- [Firmware Forensics](#firmware)
- [iOS Forensics](#ios)
- [Linux Forensics](#linux)
- [Memory Forensics](#memory)
- [Network Forensics](#network)
- [OS X Forensics](#osx)
- [Windows Forensics](#windows)
- [PDF Forensics](#pdf)
- [Image Forensics](#photo)


#### Sort

* [Forensics: Monitor Active Directory Privileged Groups with PowerShell - Ashley McGlone](https://blogs.technet.microsoft.com/ashleymcglone/2014/12/17/forensics-monitor-active-directory-privileged-groups-with-powershell/)
https://zeltser.com/security-incident-questionnaire-cheat-sheet/
https://zeltser.com/security-incident-survey-cheat-sheet/
https://zeltser.com/security-incident-log-review-checklist/
* [Touch Screen Lexicon Forensics (TextHarvester/WaitList.dat) - Barnaby Skeggs](https://b2dfir.blogspot.com/2016/10/touch-screen-lexicon-forensics.html?m=1)
* Sort sections alphabetically
* Update ToC
* [Planning for Compromise - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/planning-for-compromise)
* [ADTimeline](https://github.com/ANSSI-FR/ADTimeline)
	* PowerShell script creating a timeline of Active Directory changes with replication metadata
* [Strategies to Mitigate Cyber Security Incidents - Mitigation Details - Australian Cyber Security Center](https://www.cyber.gov.au/publications/strategies-to-mitigate-cyber-security-incidents-mitigation-details)
* [Digging Up the Past: Windows Registry Forensics Revisited - David Via](https://www.fireeye.com/blog/threat-research/2019/01/digging-up-the-past-windows-registry-forensics-revisited.html)
* [National Incident Management System -USA](https://www.fema.gov/national-incident-management-system)
* [Investigating CloudTrail Logs](https://medium.com/starting-up-security/investigating-cloudtrail-logs-c2ecdf578911)
* [pagerduty Incident Response](https://response.pagerduty.com/)
	* This documentation covers parts of the PagerDuty Incident Response process. It is a cut-down version of our internal documentation, used at PagerDuty for any major incidents, and to prepare new employees for on-call responsibilities. It provides information not only on preparing for an incident, but also what to do during and after. It is intended to be used by on-call practitioners and those involved in an operational incident response process (or those wishing to enact a formal incident response process). See the about page for more information on what this documentation is and why it exists.
* [Security Breach 101 - Ryan McGeehan](https://medium.com/starting-up-security/security-breach-101-b0f7897c027c)
* [Security Breach 102 - Ryan McGeehan](https://medium.com/starting-up-security/security-breach-102-d5fc88c5660f)
* [Learning From A Year of Security Breaches - Ryan McGeehan](https://medium.com/starting-up-security/learning-from-a-year-of-security-breaches-ed036ea05d9b)
* [Investigating CloudTrail Logs - ](https://medium.com/starting-up-security/investigating-cloudtrail-logs-c2ecdf578911)
* [Who Fixes That Bug? - Part One: Them! - Ryan McGeehan](https://medium.com/starting-up-security/who-fixes-that-bug-d44f9a7939f2)
https://medium.com/starting-up-security/who-fixes-that-bug-f17d48443e21
https://www.sans.org/score/law-enforcement-faq/
https://www.sans.org/score/incident-forms/
* [Extracting Bitlocker Keys from a TPM - Denis Andzakovic](https://pulsesecurity.co.nz/articles/TPM-sniffing)


DFIR
	https://github.com/yampelo/beagle
	https://medium.com/@forensic_matt/opcode-and-task-enumeration-and-shell-items-bd4ff0b548a3
	https://www.linkedin.com/pulse/invoke-liveresponse-matthew-green
	https://github.com/mgreen27/Powershell-IR
	https://docs.velociraptor.velocidex.com/
	https://www.andreafortuna.org/2019/06/12/windows-security-event-logs-my-own-cheatsheet/
	https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx
	https://www.crowdstrike.com/blog/automating-mac-forensic-triage/
	https://www.irongeek.com/i.php?page=videos/bsidescleveland2019/bsides-cleveland-c-04-incident-response-on-macos-thomas-reed
	https://github.com/certsocietegenerale/IRM/tree/master/EN
	https://www.incidentresponse.com/playbooks/

https://docs.microsoft.com/en-us/office365/securitycompliance/siem-server-integration

* [The only PowerShell Command you will ever need to find out who did what in Active Directory - Przemyslaw Klys](https://evotec.xyz/the-only-powershell-command-you-will-ever-need-to-find-out-who-did-what-in-active-directory/)


* [Regipy: Automating registry forensics with python - Martin Korman](https://medium.com/dfir-dudes/regipy-automating-registry-forensics-with-python-b170a1e2b474)
* [regipy](https://github.com/mkorman90/regipy)
	* Regipy is an os independent python library for parsing offline registry hives

Cloud IR
	* https://www.sans.org/reading-room/whitepapers/cloud/digital-forensic-analysis-amazon-linux-ec2-instances-38235
	* https://www.sans.org/reading-room/whitepapers/incident/paper/36902
	* https://www.blackhat.com/docs/us-16/materials/us-16-Krug-Hardening-AWS-Environments-And-Automating-Incident-Response-For-AWS-Compromises-wp.pdf
	* https://aws.amazon.com/blogs/publicsector/building-a-cloud-specific-incident-response-plan/
	* https://www.amazon.com/Incident-Response-Strategic-Handling-Security/dp/1578702569
	* http://threatresponse-derbycon.s3-website-us-west-2.amazonaws.com/#/step-1
	* https://cloud.gov/docs/ops/security-ir/
	* https://www.slideshare.net/AmazonWebServices/incident-response-in-the-cloud-sid319-reinvent-2017
	* https://www.slideshare.net/AmazonWebServices/incident-response-in-the-cloud-sid319-reinvent-2017
	* https://www.youtube.com/watch?v=Y9cAHxd0kW4

* [Cleaning the Apple Orchard - Using Venator to Detect macOS Compromise - Richie Cyrus(BSides Charm2019)](http://www.irongeek.com/i.php?page=videos/bsidescharm2019/1-02-cleaning-the-apple-orchard-using-venator-to-detect-macos-compromise-richie-cyrus)
	* Various solutions exist to detect malicious activity on macOS. However, they are not intended for enterprise use or involve installation of an agent. This session will introduce and demonstrate how to detect malicious macOS activity using the tool Venator. Venator is a python based macOS tool designed to provide defenders with the data to proactively identify malicious macOS activity at scale.


https://www.youtube.com/watch?v=YGJaj6_3dGA

https://aboutdfir.com/
https://forensixchange.com/posts/19_08_03_usb_storage_forensics_1/
* [HAWK 1.1.4](https://www.powershellgallery.com/packages/HAWK/1.1.4)
	* The Hawk module has been designed to ease the burden on O365 administrators who are performing a forensic analysis in their organization. It accelerates the gathering of data from multiple sources in the service. It does NOT take the place of a human reviewing the data generated and is simply here to make data gathering easier.

https://github.com/giMini/PowerMemory

* [Sysmon - DFIR](https://github.com/MHaggis/sysmon-dfir)
	* A curated list of resources for learning about deploying, managing and hunting with Microsoft Sysmon. Contains presentations, deployment methods, configuration file examples, blogs and additional github repositories.

* [Alerting and Detection Strategy Framework - palantir](https://medium.com/palantir/alerting-and-detection-strategy-framework-52dc33722df2)
* [Deobfuscating Emotet’s powershell payload - MalFind](https://malfind.com/index.php/2018/07/23/deobfuscating-emotets-powershell-payload/)
* [Windows 10 Notification WAL database - malwaremaloney](https://malwaremaloney.blogspot.com/2018/08/windows-10-notification-wal-database.html?m=1)

* [Hacking Exposed Daily Blog #440: Windows 10 Notifications Database](http://www.hecfblog.com/2018/08/daily-blog-440-windows-10-notifications.html)


* [Data recovery on dead micro SD card - HDD Recovery Services](https://www.youtube.com/watch?v=jjB6wliyE_Y&feature=youtu.be)

* [Digital Forensics Tips&Tricks: How to Detect an Intruder-driven Group Policy Changes - volnodumcev](https://habr.com/en/post/444048/)

* [SQLite-Parser](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser)
	* Script to recover deleted entries in an SQLite database

* [Python Parser to Recover Deleted SQLite Database Data - az4n6](
https://az4n6.blogspot.com/2013/11/python-parser-to-recover-deleted-sqlite.html)
https://medium.com/@sroberts/introduction-to-dfir-d35d5de4c180
https://github.com/demisto/COPS
https://blog.1234n6.com/2018/10/available-artifacts-evidence-of.html
https://www.incidentresponse.com/playbooks/
https://windowsir.blogspot.com/2019/05/evtxecmd.html


https://cert.societegenerale.com/en/publications.html

* [Maltrail](https://github.com/stamparm/maltrail)
	* Maltrail is a malicious traffic detection system, utilizing publicly available (black)lists containing malicious and/or generally suspicious trails, along with static trails compiled from various AV reports and custom user defined lists, where trail can be anything from domain name (e.g. zvpprsensinaix.com for Banjori malware), URL (e.g. http://109.162.38.120/harsh02.exe for known malicious executable), IP address (e.g. 185.130.5.231 for known attacker) or HTTP User-Agent header value (e.g. sqlmap for automatic SQL injection and database takeover tool). Also, it uses (optional) advanced heuristic mechanisms that can help in discovery of unknown threats (e.g. new malware).

#### End Sort








--------------
### <a name="ir"></a>Incident Response
* **101**
	* Better security --> Mean time to detect & Mean time to respond
	* [Introduction to DFIR](https://sroberts.github.io/2016/01/11/introduction-to-dfir-the-beginning/)
	* [Computer Security Incident Handling Guide - NIST](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
	* [Basics of Incident Handling - Josh Rickard](https://msadministrator.github.io/presentations/basics-of-incident-handling.html)
	* [Introduction to DFIR - Scott J Roberts](https://medium.com/@sroberts/introduction-to-dfir-d35d5de4c180)
	* [The Incident Response Hierarchy of Needs](https://github.com/swannman/ircapabilities)
		* The Incident Response Hierarchy is modeled after [Maslow's Hierarchy of Needs](https://github.com/swannman/ircapabilities). It describes the capabilities that organizations must build to defend their business assets.
* **Articles/Papers/Talks/Writeups**
	* [No Easy Breach: Challenges and Lessons Learned from an Epic Investigation](https://archive.org/details/No_Easy_Breach#)
	* [An Incident Handling Process for Small and Medium Businesses  - SANS 2007](https://www.sans.org/reading-room/whitepapers/incident/incident-handling-process-small-medium-businesses-1791)
	* [Handler Diaries - Another Hunting Post(DFIR)](http://blog.handlerdiaries.com/?p=775)
		* Good post on not only knowing the layout, but knowing expected behaviours.
	* [Triaging Malware Incidents](http://journeyintoir.blogspot.com/2013/09/triaging-malware-incidents.html)
		* Good writeup/blogpost from Journey into Incidence Response
	* [Commercial Spyware - Detecting the Undetectable](https://www.blackhat.com/docs/us-15/materials/us-15-Dalman-Commercial-Spyware-Detecting-The-Undetectable-wp.pdf)
	* [Fraud detection and forensics on telco networks - Hack.lu 2016](https://www.youtube.com/watch?v=09EAWT_F1ZA&app=desktop)
	* [Investigating PowerShell Attacks - Ryan Kazanciyan and Matt Hastings - DEFCON22](https://www.youtube.com/watch?v=qF06PFcezLs)
		* This presentation will focus on common attack patterns performed through PowerShell - such as lateral movement, remote command execution, reconnaissance, file transfer, etc. - and the sources of evidence they leave behind. We'll demonstrate how to collect and interpret these forensic artifacts, both on individual hosts and at scale across the enterprise. Throughout the presentation, we'll include examples from real-world incidents and recommendations on how to limit exposure to these attacks.
	* [SANS Institute Security Consensus Operational Readiness Evaluation](https://www.sans.org/media/score/checklists/LinuxCheatsheet_2.pdf)
	* **Windows**
		* [Know your Windows Processes or Die Trying](https://sysforensics.org/2014/01/know-your-windows-processes.html)
			* Excellent quick reference on Windows proccesses with a focus on Win7. Good resource.
		* [License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)
		* [Windows Program Automatic Startup Locations](http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)			
		* [Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)
		* [Spotting the Adversary with Windows Event Log Monitoring - NSA](http://cryptome.org/2014/01/nsa-windows-event.pdf)
			* NSA 70-page writeup on windows event log monitoring
		* [Ways to Identify Malware on a System Ryan Irving](http://www.irongeek.com/i.php?page=videos/bsidestampa2015/201-ways-to-identify-malware-on-a-system-ryan-irving)
* **General**
	* [IRM (Incident Response Methodologies)](https://github.com/certsocietegenerale/IRM)
		* CERT Societe Generale provides easy to use operational incident best practices. These cheat sheets are dedicated to incident handling and cover multiple fields in which a CERT team can be involved. One IRM exists for each security incident we're used to dealing with.
* **Methodologies/Playbooks**
	* [incidentresponse.com playbooks](https://www.incidentresponse.com/playbooks/)
	* [Using a “Playbook” Model to Organize Your Information Security Monitoring Strategy - cisco](https://blogs.cisco.com/security/using-a-playbook-model-to-organize-your-information-security-monitoring-strategy)
	* [Univeristy of Florida IR Playbooks](http://www.cst.ucf.edu/about/information-security-office/incident-response/)
* **Tools**
	* [binwally](https://github.com/bmaia/binwally)
		* Binary and Directory tree comparison tool using the Fuzzy Hashing concept (ssdeep)
	* [IRMA - Incident Response & Malware Analysis](http://irma.quarkslab.com/index.html)
		* IRMA intends to be an open-source platform designed to help identifying and analyzing malicious files.  However, today's defense is not only about learning about a file, but it is also getting a fine overview of the incident you dealt with: where / when a malicious file has been seen, who submitted a hash, where a hash has been noticed, which anti-virus detects it, ...  An important value with IRMA comes from you keep control over where goes / who gets your data. Once you install IRMA on your network, your data stays on your network.  Each submitted files is analyzed in various ways. For now, we focus our efforts on multiple anti-virus engines, but we are working on other "probes" (feel free to submit your own).	
	* [aws_ir](https://github.com/ThreatResponse/aws_ir)
		* Python installable command line utility for mitigation of instance and key compromises.
	* [MIG: Mozilla InvestiGator](https://http://mig.mozilla.org/)
		* Mozilla's real-time digital forensics and investigation platform.
	* [Fully Integrated Defense Operation (FIDO)](https://github.com/Netflix/Fido)
		* FIDO is an orchestration layer used to automate the incident response process by evaluating, assessing and responding to malware. FIDO’s primary purpose is to handle the heavy manual effort needed to evaluate threats coming from today's security stack and the large number of alerts generated by them. As an orchestration platform FIDO can make using your existing security tools more efficient and accurate by heavily reducing the manual effort needed to detect, notify and respond to attacks against a network.
	* [Invoke-IR](http://www.invoke-ir.com/)
* **Miscellaneous**
	* [Human Hunting](http://www.irongeek.com/i.php?page=videos/bsidessf2015/108-human-hunting-sean-gillespie) 
		* Much of what appears to be happening in information security seems to be focused on replacing humans with magic boxes and automation rather than providing tools to augment human capabilities. However, when we look at good physical security we see technology is being used to augment human capabilities rather than simply replace them. The adversary is human so we are ultimately looking for human directed behaviors. If analysts don't know how to go looking for evil without automated detection tools then they are not going to be able to effectively evaluate if the detection tools are working properly or if the deployment was properly engineered. An over reliance on automated detection also puts organizations in a position of paying protection money if they want to remain secure. We should be spending more resources on honing analyst hunting skills to find human adversaries rather than purchasing more automated defenses for human adversaries to bypass.
* **Training**
	* [ENISA CERT Exercises and Training](http://www.enisa.europa.eu/activities/cert/support/exercise)
		* ENISA CERT Exercises and training material was introduced in 2008, in 2012 and 2013 it was complemented with new exercise scenarios containing essential material for success in the CERT community and in the field of information security. In this page you will find the ENISA CERT Exercise material, containing Handbook for teachers, Toolset for students and Virtual Image to support hands on training sessions.
* **Malware Management Framework** (Originally called 'Sniper Forensics')
	* [Malware Management Framework - Sniper Forensics Toolkit](http://sniperforensicstoolkit.squarespace.com/malwaremanagementframework/)
	* [The Malware Management Framework](https://malwarearchaeology.squarespace.com/mmf/)
		* The Malware Reporting Standard](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/55220280e4b0170ec8b526b6/1428292224531/Malware+Reporting+Standard+vApril+2015.pdf)
		* [BSidesLV Presentation](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/552200afe4b0e4ad5008b943/1428291802554/Malware+Mgmt+Framework+v2.0.pdf)
	* [Sniper Forensics](https://digital-forensics.sans.org/summit-archives/2010/2-newell-spiderlabs-sniper-forensics.pdf)
		* Pg10 and onward
		* [Link](https://sniperforensicstoolkit.squarespace.com/storage/logging/Windows%20Logging%20Cheat%20Sheet%20v1.1.pdf)
)
	* [Sniper Forensics, Memory Analysis, and Malware Detection - windowsir.blogspot](https://windowsir.blogspot.com/2013/11/sniper-forensics-memory-analysis-and.html)
	* Unrelated but highly relevant: [LogMD](https://www.imfsecurity.com/why-log-md/)


--------------
### <a name="anti-f">Anti-Forensics</a>
* **101**
* **Articles/Talks/Writeups**
	* [Destroying Evidence Before Its Evidence](https://www.youtube.com/watch?v=lqBVAcxpwio&spfreload=1)
	* [And That's How I Lost My Other Eye...Explorations in Data Destruction](https://www.youtube.com/watch?v=-bpX8YvNg6Y)
	* [An Anti-Forensics Primer - Jason Andress](http://www.irongeek.com/i.php?page=videos/derbycon3/s216-an-anti-forensics-primer-jason-andress)
	* This talk will cover the basics of anti-forensics, the tools and techniques that can be used to make life harder for computer forensic examiners. We will cover some of the basic methods that are used (disk wiping, time stomping, encryption, etc…) and talk about which of these methods might actually work and which are easily surmounted with common forensic tools.
	* [Forensics Impossible: Self-Destructing Thumb Drives - Brandon Wilson](https://www.youtube.com/watch?v=NRMqwc5YEu4)
	* [Anti-Forensics and Anti-Anti-Forensics Attacks - Michael Perkins](https://www.youtube.com/watch?v=J4x8Hz6_hq0)
		* Everyone's heard the claim: Security through obscurity is no security at all. Challenging this claim is the entire field of steganography itself - the art of hiding things in plain sight. Most people know you can hide a text file inside a photograph, or embed a photograph inside an MP3. But how does this work under the hood? What's new in the stego field?  This talk will explore how various techniques employed by older steganographic tools work and will discuss a new technique developed by the speaker which embodies both data hiding and data enciphering properties by encoding data inside NTFS volumes. A new tool will be released during this talk that will allow attendees to both encode and decode data with this new scheme.
		* Slides: [Slides(link)](http://www.slideshare.net/the_netlocksmith/defcon-20-antiforensics-and-antiantiforensics)
	* [Beyond The CPU:Defeating Hardware Based RAM Acquisition](https://www.blackhat.com/presentations/bh-dc-07/Rutkowska/Presentation/bh-dc-07-Rutkowska-up.pdf)
	* [Hardware Backdooring is Practical** -Jonathan Brossard](https://www.youtube.com/watch?v=umBruM-wFUw)
	* [Hiding the breadcrumbs: Forensics and anti-forensics on SAP systems - Juan Perez-Etchegoyen](http://www.irongeek.com/i.php?page=videos/derbycon4/t508-hiding-the-breadcrumbs-forensics-and-anti-forensics-on-sap-systems-juan-perez-etchegoyen)
		* The largest organizations in the world rely on SAP platforms to run their critical processes and keep their business crown jewels: financial information, customer data, intellectual property, credit cards, human resources salaries, sensitive materials, suppliers and more. Everything is there and attackers know it. For several years at Onapsis we have been researching on how cyber-criminals might be able to break into ERP systems in order to help organizations better protect themselves. This has enabled us to gain a unique expertise on which are the most critical attack vectors and what kind of traces they leave (and don’t) over the victim’s SAP platforms. SAP systems need to be ready for Forensic Analysis, so the big question is: Are your systems prepared to retain the attackers breadcrumbs in the event of an attack? Join us and learn how to do a forensic analysis of an SAP system, looking for traces of a security breach We will also show novel techniques being used by attackers to avoid being detected during post attack forensic investigations. Vulnerabilities related to anti-forensic techniques will be presented together with their mitigation. **NEW** New attacks never presented before will be shown. JAVA, ABAP and BO systems will be covered.
	* [Anti-Forensics for the Louise - Derbycon - int0x80 (of Dual Core)](https://www.youtube.com/watch?v=-HK1JHR7LIM	)
* **Android & iOS**
	* [Incident Response for Android and iOS - NowSecure](https://github.com/nowsecure/mobile-incident-response/tree/master/en)
		* This book will prepare enterprises and practitioners for the inevitable increase in mobile compromise. We will use step-by-step tutorials, guiding the reader from setting up a mobile IR practice all the way through continuous monitoring of mobile devices.
* **General**
* **Papers**
	* [Secure Deletion of Data from Magnetic and Solid-State Memory](http://static.usenix.org/publications/library/proceedings/sec96/full_papers/gutmann)
	* [Hiding Data in Hard-Drive's Service Areas](http://recover.co.il/SA-cover/SA-cover.pdf)
		* In this paper we will demonstrate how spinning hard-drives’ serv ice areas 1 can be used to hide data from the operating-system (or any software using the standard OS’s API or the standard ATA commands to access the hard- drive)
* **Tools**
	* [usbkill](https://github.com/stemid/usbkill)
		* A tool that shuts down your computer if USB devices change, for example if you unplug or plug-in a device. 
	* [CleanAfterMe](https://www.nirsoft.net/utils/clean_after_me.html )
		* CleanAfterMe allows you to easily clean files and Registry entries that are automatically created by the Windows operating system during your regular computer work. With CleanAfterMe, you can clean the cookies/history/cache/passwords of Internet Explorer, the 'Recent' folder, the Registry entries that record the last opened files, the temporary folder of Windows, the event logs, the Recycle Bin, and more.

* **Miscellaneous**














----------------
### <a name="general-f"></a> General Forensics(Systems Agnostic - as much as one can be)
* **101**
* **Reference**
	* [File Signature Table](http://www.garykessler.net/library/file_sigs.html)
		* This table of file signatures (aka "magic numbers") is a continuing work-in-progress. I have found little information on this in a single place, with the exception of the table in Forensic Computing: A Practitioner's Guide by T. Sammes & B. Jenkinson (Springer, 2000); that was my inspiration to start this list in 2002.
* **Articles & Writeups**
	* [Chromebook Forensics](http://www.dataforensics.org/google-chromebook-forensics/)
	* [Forensics on Amazon’s EC2](https://sysforensics.org/2014/10/forensics-in-the-amazon-cloud-ec2.html)
* **Talks & Presentations**
	* [Less is More, Exploring Code/Process-less Techniques and Other Weird Machine Methods to Hide Code (and How to Detect Them)](https://cansecwest.com/slides/2014/less%20is%20more3.pptx)
	* [Forensic Imager Tools: You don't have the Evidence - Shmoocon 2014](https://www.youtube.com/watch?v=zYYCv21I-1I)*
	* [Attrition Forensics](http://2014.video.sector.ca/video/110334184)
* **Papers**
* **Tools**
	* [binwally](https://github.com/bmaia/binwally)
		* Binary and Directory tree comparison tool using the Fuzzy Hashing concept (ssdeep)
	* [SSDeep](http://ssdeep.sourceforge.net/)
		* ssdeep is a program for computing context triggered piecewise hashes (CTPH). Also called fuzzy hashes, CTPH can match inputs that have homologies. Such inputs have sequences of identical bytes in the same order, although bytes in between these sequences may be different in both content and length. 
	* [Xmount](https://www.pinguin.lu/xmount)
		* What is xmount? xmount allows you to convert on-the-fly between multiple input and output harddisk image types. xmount creates a virtual file system using FUSE (Filesystem in Userspace) that contains a virtual representation of the input image. The virtual representation can be in raw DD, DMG, VHD, VirtualBox's virtual disk file format or in VmWare's VMDK file format. Input images can be raw DD, EWF (Expert Witness Compression Format) or AFF (Advanced Forensic Format) files. In addition, xmount also supports virtual write access to the output files that is redirected to a cache file. This makes it possible to boot acquired harddisk images using QEMU, KVM, VirtualBox, VmWare or alike.
	* [PEview](http://wjradburn.com/software/)
		* PEview provides a quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files. This PE/COFF file viewer displays header, section, directory, import table, export table, and resource information within EXE, DLL, OBJ, LIB, DBG, and other file types.
* **Training**
	* [Automating DFIR - How to series on programming libtsk with python Part 1 - ](http://hackingexposedcomputerforensicsblog.blogspot.com/2015/02/automating-dfir-how-to-series-on.html)
	* [Automating DFIR - How to series on programming libtsk with python Part 2](http://hackingexposedcomputerforensicsblog.blogspot.com/2015/02/automating-dfir-how-to-series-on_19.html)
	* [Automating DFIR - How to series on programming libtsk with python Part 3](http://www.hecfblog.com/2015/02/automating-dfir-how-to-series-on_21.html)
* **Miscellaneous**
	* [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit)
		* The Sleuth Kit is an open source forensic toolkit for analyzing Microsoft and UNIX file systems and disks. The Sleuth Kit enables investigators to identify and recover evidence from images acquired during incident response or from live systems. The Sleuth Kit is open source, which allows investigators to verify the actions of the tool or customize it to specific needs.  The Sleuth Kit uses code from the file system analysis tools of The Coroner's Toolkit (TCT) by Wietse Venema and Dan Farmer. The TCT code was modified for platform independence. In addition, support was added for the NTFS (see docs/ntfs.README) and FAT (see docs/fat.README) file systems. Previously, The Sleuth Kit was called The @stake Sleuth Kit (TASK). The Sleuth Kit is now independent of any commercial or academic organizations.









----------------------
### <a name="af">Android Forensics</a>
* **101**
	* [How to Perform a Physical Acquisition in Android Forensics?](https://infosecaddicts.com/perform-physical-acquisition-android-forensics/)
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
	* [wechat-dump](https://github.com/ppwwyyxx/wechat-dump)
		* Dump wechat messages from android. Right now it can dump messages in text-only mode, or generate a single-file html containing voice messages, images, emoji, etc.
	* [Androick](https://github.com/Flo354/Androick)
		* Androick is a python tool to help in forensics analysis on android. Put the package name, some options and the program will download automatically apk, datas, files permissions, manifest, databases and logs. It is easy to use and avoid all repetitive tasks!
* **Training**
	* [Android Forensics class - OpenSecurity Training](http://opensecuritytraining.info/AndroidForensics.html)
		* This class serves as a foundation for mobile digital forensics, forensics of Android operating systems, and penetration testing of Android applications.
* **Miscellaneous**
 



--------------
### <a name="browser"></a>Browser Forensics
* **101**
* **Articles/Papers/Talks/Writeups**
	* [Firefox private browsing forensics](http://www.magnetforensics.com/forensic-implications-of-a-person-using-firefoxs-private-browsing/)
	* [Google Chrome Forensics-SANS](https://digital-forensics.sans.org/blog/2010/01/21/google-chrome-forensics#)
* **General**
* **Tools**
	* **Chrome**
		* [Chrome Ragamuffin](https://github.com/cube0x8/chrome_ragamuffin)
			* Volatility plugin designed to extract useful information from Google Chrome's address space. The goal of this plugin is to make possible the analysis of a Google Chrome running instance. Starting from a memory dump, Chrome Ragamuffin can list which page was open on which tab and it is able to extract the DOM Tree in order to analyze the full page structure.
	* **Firefox**
		* [MozillaRecovery](https://github.com/gtfy/MozillaRecovery)
			* Recovers the master password of key3.db files, i.e. Thunderbird, Firefox
		* [MozillaRecovery](https://github.com/gtfy/MozillaRecovery)
			* Recovers the master password of key3.db files, i.e. Thunderbird, Firefox
		* [firefox_decrypt](https://github.com/unode/firefox_decrypt)
			* Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox/Thunderbird/Seabird) profiles
		* [firepwd.py](https://github.com/lclevy/firepwd)
			* firepwd.py, an open source tool to decrypt Mozilla protected passwords
		* [Firefed](https://github.com/numirias/firefed)
			* Firefed is a command-line tool to inspect Firefox profiles. It can extract saved passwords, preferences, addons, history and more. You may use it for forensic analysis, to audit your config for insecure settings or just to quickly extract some data without starting up the browser.
	* **Neutral**
		* [Extension Finder](https://github.com/brad-anton/extension_finder)
			* Python and PowerShell utilities for finding installed browser extensions, plug-ins and add-ons. Attempts to find installed browser extensions (sometimes called add-ons or plug-ins, depending on the browser).
* **Miscellaneous**



--------------
### <a name="firmware"></a>Firmware 
* [Firmware Forensics: Diffs, Timelines, ELFs and Backdoors](http://w00tsec.blogspot.com/2015/02/firmware-forensics-diffs-timelines-elfs.html)


--------------
####<a name="ios">iOS Forensics</a>
* **101**
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
* **Miscellaneous**
http://www.forensicswiki.org/wiki/Apple_iPhone

http://www.iosresearch.org/
* [iOSForensic](https://github.com/Flo354/iOSForensic)
	* iosForensic is a python tool to help in forensics analysis on iOS. It get files, logs, extract sqlite3 databases and uncompress .plist files in xml.
* [iOS Forensics Analyis(2012) SANS Whitepaper](https://www.sans.org/reading-room/whitepapers/forensics/forensic-analysis-ios-devices-34092)
* [iOS Forensic Investigative Methods Guide](http://www.zdziarski.com/blog/wp-content/uploads/2013/05/iOS-Forensic-Investigative-Methods.pdf)
* [The art of iOS and iCloud forensics](https://blog.elcomsoft.com/2017/11/the-art-of-ios-and-icloud-forensics/)





--------------
### <a name="linux">Linux Forensics</a>
* **101**
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
* **Miscellaneous**
	* [Santoku Linux How-Tos'](https://santoku-linux.com/howtos)



--------------
### <a name="memory"></a>Memory Forensics
* **101**
* **Articles/Papers/Talks/Writeups**
	* [How to Pull passwords from a memory dump](https://cyberarms.wordpress.com/2011/11/04/memory-forensics-how-to-pull-passwords-from-a-memory-dump/)
	* [Unmasking Careto through Memory Analysis - Andrew Case](http://2014.video.sector.ca/video/110388398)
* **General**
	* [Windows Memory Analysis Checklist](http://www.dumpanalysis.org/windows-memory-analysis-checklist)
	* [Mem forenics cheat sheet](http://forensicmethods.com/wp-content/uploads/2012/04/Memory-Forensics-Cheat-Sheet-v1.pdf)
* **Tools**
	* [lmg - Linux Memory Grabber](https://github.com/halpomeranz/lmg)
	* A script for dumping Linux memory and creating Volatility(TM) profiles.
	* [Detekt](https://github.com/botherder/detekt)
		* Detekt is a Python tool that relies on Yara, Volatility and Winpmem to scan the memory of a running Windows system (currently supporting Windows XP to Windows 8 both 32 and 64 bit and Windows 8.1 32bit). Detekt tries to detect the presence of pre-defined patterns that have been identified through the course of our research to be unique identifiers that indicate the presence of a given malware running on the computer. 
	* [Dshell](https://github.com/USArmyResearchLab/Dshell)
		* An extensible network forensic analysis framework. Enables rapid development of plugins to support the dissection of network packet captures. 
	* [LiME - Linux Memory Extractor](https://github.com/504ensicsLabs/LiME)
		* A Loadable Kernel Module (LKM) which allows for volatile memory acquisition from Linux and Linux-based devices, such as Android. This makes LiME unique as it is the first tool that allows for full memory captures on Android devices. It also minimizes its interaction between user and kernel space processes during acquisition, which allows it to produce memory captures that are more forensically sound than those of other tools designed for Linux memory acquisition.

		* Vortessence is a tool, whose aim is to partially automate memory forensics analysis. Vortessence is a project of the Security Engineering Lab of the Bern University of Applied Sciences.
* **Miscellaneous**
* **Volatility**
	* [Volatility](https://github.com/volatilityfoundation/volatility)
		* An advanced memory forensics framework
	* [VolUtility](https://github.com/kevthehermit/VolUtility)
		* Web Interface for Volatility Memory Analysis framework
	* [evolve](https://github.com/JamesHabben/evolve)
		* Web interface for the Volatility Memory Forensics Framework 
	* [Vortessence](https://github.com/vortessence/vortessence)





-----------------------
### <a name="network"></a> Network Forensics
* See also: Network Security Monitoring/Logging
* **101**
* **Articles/Papers/Talks/Writeups**
	* [Analyzing TNEF files](https://isc.sans.edu/diary/rss/23175)
	* [Finding Bad Guys with 35 million Flows, 2 Analysts, 5 Minutes and 0 Dollars](http://www.irongeek.com/i.php?page=videos/bsidesknoxville2015/103-finding-bad-guys-with-35-million-flows-2-analysts-5-minutes-and-0-dollars-russell-butturini)
		* There are a lot of proof of concepts out there for building open source networks forensics analysis environments. Taking them into production in an enterprise? Another story entirely. This talk will focus on my journey into constructing a large scale Netflow security analytics platform for a large healthcare management company's complex environment on no additional budget. Important points to be covered were technology considerations, scalability, and how to quickly break the collected data down to find malicious activity on the network with minimal effort.
* **Papers**
	* [Practical Comprehensive Bounds on Surreptitious Communication Over DNS](http://www.icir.org/vern/papers/covert-dns-usec13.pdf)
* **Tools**
* **Miscellaneous**
	* [Packet Capture Examples from "Practical Packet Analysis"](http://www.chrissanders.org/captures/)
	* [Transport Neutral Encapsulation Format - Wikipedia](https://en.wikipedia.org/wiki/Transport_Neutral_Encapsulation_Format)




----------------
### <a name="osx"></a> OS X Forensics
* **101**
* **Articles/Papers/Talks/Writeups**
	* [The Cider Press:Extracting Forensic Artifacts From Apple Continuity](https://www.sans.org/summit-archives/file/summit-archive-1498146226.pdf)
* **General**
* **Tools**
	* [osxcollector](https://github.com/Yelp/osxcollector)
		* OSXCollector is a forensic evidence collection & analysis toolkit for OSX.
	* [Mac OS X Keychain Forensic Tool](https://github.com/n0fate/chainbreaker)
		* The chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner. Master Key candidates can be extracted from volafox or volatility keychaindump module. Supports: Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra
	* [OS X Audiotr](https://github.com/jipegit/OSXAuditor)
		* OS X Auditor is a free Mac OS X computer forensics tool.
	* [OS X Forensics Generals](https://davidkoepi.wordpress.com/category/os-x-forensics-10-8/)
	* [OSX Lion User Interface Preservation Analysis](https://digital-forensics.sans.org/blog/2011/10/03/osx-lion-user-interface-preservation-analysis#)
	* [Knock Knock](https://github.com/synack/knockknock)
	* KnockKnock displays persistent items (scripts, commands, binaries, etc.), that are set to execute automatically on OS X
	* [Pac4Mac](https://github.com/sud0man/pac4mac)
		* Pac4Mac (Plug And Check for Mac OS X) is a portable Forensics framework (to launch from USB storage) allowing extraction and analysis session informations in highlighting the real risks in term of information leak (history, passwords, technical secrets, business secrets, ...). Pac4Mac can be used to check security of your Mac OS X system or to help you during forensics investigation.
* **Miscellaneous**





----------------
### <a name="windows">Windows Forensics</a>
* **101**
* **Articles/Papers/Talks/Writeups**
	* [How to parse Windows Eventlog](http://dfir-blog.com/2016/03/13/how-to-parse-windows-eventlog/)
	* [Techniques for fast windows forensics investigations](https://www.youtube.com/watch?v=eI4ceLgO_CE)
		* Look at sniper forensics, skip around, 18min has resources you want to grab for snapshots		
	* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
		* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it’s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What’s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."
	* [NVbit : Accessing Bitlocker volumes from linux](http://www.nvlabs.in/index.php?/archives/1-NVbit-Accessing-Bitlocker-volumes-from-linux.html)
* **Educational**
	* [Happy DPAPI!](http://blog.digital-forensics.it/2015/01/happy-dpapi.html)
* **General**
	* [SANS CHEAT SHEET- Windows Artifact Analysis](https://uk.sans.org/posters/windows_artifact_analysis.pdf)
* **Tools**
	* **Active Directory Focused**
		* [NTDSXtract - Active Directory Forensics Framework](http://www.ntdsxtract.com/)
			* Description from the page: This framework was developed by the author in order to provide the community with a solution to extract forensically important information from the main database of Microsoft Active Directory (NTDS.DIT).
		* [BTA - AD Security Audit Framework](https://bitbucket.org/iwseclabs/bta)
			* BTA is an open-source Active Directory security audit framework. Its goal is to help auditors harvest the information they need to answer such questions as:
				* Who has rights over a given object (computer, user account, etc.) ?
				* Who can read a given mailbox ?
				* Which are the accounts with domain admin rights ?
				* Who has extended rights (userForceChangePassword, SendAs, etc.) ?
				* What are the changes done on an AD between two points in time ?
	* **Artifact Collection**
		* [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector)
			* This tool collects different artefacts on live Windows and records the results in csv or json files. With the analyses of these artefacts, an early compromission can be detected.
			* [FastIR Collector on advanced threats](http://www.sekoia.fr/blog/wp-content/uploads/2015/10/FastIR-Collector-on-advanced-threats_v1.4.pdf)
		* [triage-ir](https://code.google.com/p/triage-ir/)
			* Triage: Incident Response automatically collect information from a system that needs basic triage functions performed upon it. The script allows for easy modification for customization to your needs, in an easy to comprehend and implement language. This tool uses a lot others to get its information. Eventually I hope to eliminate the need for them, but use them as verification. This tool requires you to download the Sysinternals Suite if you want full functionality to it.
		* [Rapier](https://code.google.com/p/rapier/)
			* RAPIER is a security tool built to facilitate first response procedures for incident handling. It is designed to acquire commonly requested information and samples during an information security event, incident, or investigation. RAPIER automates the entire process of data collection and delivers the results directly to the hands of a skilled security analyst 
	* **Autoruns**
		* [AutoRuns PowerShell Module](https://github.com/p0w3rsh3ll/AutoRuns)
			* AutoRuns module was designed to help do live incident response and enumerate autoruns artifacts that may be used by legitimate programs as well as malware to achieve persistence.
	* **DPAPI**
		* [DPAPIck](http://dpapick.com/)
			* This is a forensic tool to deal, in an offline way, with Microsoft Windows® protected data, using the DPAPI (Data Protection API
	* **File Systems**
		* [PowerForensics - PowerShell Digital Forensics](https://github.com/Invoke-IR/PowerForensics)
			* The purpose of PowerForensics is to provide an all inclusive framework for hard drive forensic analysis. PowerForensics currently supports NTFS and FAT file systems, and work has begun on Extended File System and HFS+ support.
	* **Memory Acquisition**
		* [Margarita Shotgun](https://github.com/ThreatResponse/margaritashotgun)
			* Python Remote Memory Aquisition
	* **Pre-Fetch**
		* [WinPrefetchView v1.25](http://www.nirsoft.net/utils/win_prefetch_view.html)
			* Each time that you run an application in your system, a Prefetch file which contains information about the files loaded by the application is created by Windows operating system. The information in the Prefetch file is used for optimizing the loading time of the application in the next time that you run it. WinPrefetchView is a small utility that reads the Prefetch files stored in your system and display the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot. 
	* **Powershell**
		* [Kansa -A Powershell incident response framework ](https://github.com/davehull/Kansa)
			* A modular incident response framework in Powershell. Note there's a bug that's currently cropping up in PowerShell version 2 systems, but version 3 and later should be fine
	* **Program Execution**
		* [Did it Execute? - Mandiant](https://www.mandiant.com/blog/execute/)
			* You found a malicious executable! Now you’ve got a crucial question to answer: did the file execute? We’ll discuss a few sources of evidence you can use to answer this question. In this post, we will focus on static or “dead drive” forensics on Windows systems. We will cover four main sources of evidence: Windows Prefetch, Registry, Log Files, and File Information.
		* [HowTo: Determine Program Execution](http://windowsir.blogspot.com/2013/07/howto-determine-program-execution.html)
	* **WMI Focused**
		* [PoSH-R2](https://github.com/WiredPulse/PoSh-R2)
			* PoSH-R2 is a set of Windows Management Instrumentation interface (WMI) scripts that investigators and forensic analysts can use to retrieve information from a compromised (or potentially compromised) Windows system. The scripts use WMI to pull this information from the operating system. Therefore, this script will need to be executed with a user that has the necessary privileges.
		* [WMI_Forensics](https://github.com/davidpany/WMI_Forensics)
			* This repository contains scripts used to find evidence in WMI repositories
* **Miscellaneous**
	* [Windows Attribute changer](http://www.petges.lu/home/)
	* [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
	* Code from "Taking Hunting to the Next Level: Hunting in Memory" presentation at SANS Threat Hunting Summit 2017 by Jared Atkinson and Joe Desimone



--------------
### <a name="pdf">PDF Forensics</a>
* **101**
* **Articles/Papers/Talks/Writeups**
	* [PDF Forensics](http://countuponsecurity.com/2014/09/22/malicious-documents-pdf-analysis-in-5-steps/)
* **General**
* **Tools**
	* [PDF Tools - Didier Stevens](http://blog.didierstevens.com/programs/pdf-tools/)
* **Miscellaneous**
	* [Didier Stevens Blog](https://blog.didierstevens.com/)
	* [Analyzing Malicious Documents Cheat Sheet](https://zeltser.com/analyzing-malicious-documents/)







--------------
###< a name="photo">Image Forensics</a>
* **101**
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
	* [Extensible Metadata Platform](https://en.wikipedia.org/wiki/Extensible_Metadata_Platform)
		* The Extensible Metadata Platform (XMP) is an ISO standard, originally created by Adobe Systems Inc., for the creation, processing and interchange of standardized and custom metadata for digital documents and data sets.
	* [jhead](http://www.sentex.net/~mwandel/jhead/)
		* Exif Jpeg header manipulation tool
	* [Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi)
* **Miscellaneous**





---------------------
### Steganography
* **101**
* **Articles/Papers/Talks/Writeups**
* **General**
	* [OpenPuff Steganography](http://embeddedsw.net/OpenPuff_Steganography_Home.html)
* **Tools**
	* [StegExpose](https://github.com/b3dk7/StegExpose)
		* StegExpose is a steganalysis tool specialized in detecting LSB (least significant bit) steganography in lossless images such as PNG and BMP. It has a command line interface and is designed to analyse images in bulk while providing reporting capabilities and customization which is comprehensible for non forensic experts. StegExpose rating algorithm is derived from an intelligent and thoroughly tested combination of pre-existing pixel based staganalysis methods including Sample Pairs by Dumitrescu (2003), RS Analysis by Fridrich (2001), Chi Square Attack by Westfeld (2000) and Primary Sets by Dumitrescu (2002). In addition to detecting the presence of steganography, StegExpose also features the quantitative steganalysis (determining the length of the hidden message). StegExpose is part of my MSc of a project at the School of Computing of the University of Kent, in Canterbury, UK.
* **Miscellaneous**








--------------
#### Bootkit Disk Forensics
* **101**
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
* **Miscellaneous**
* [Part 1](http://www.malwaretech.com/2015/02/bootkit-disk-forensics-part-1.html)
* [Part 2](http://www.malwaretech.com/2015/03/bootkit-disk-forensics-part-2.html)












