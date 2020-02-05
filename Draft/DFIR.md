# Forensics & Incident Response


## Table of Contents
- [Incident Response](#ir)
- [Anti-Forensics](#anti-f)
- [General Forensics - Agnostic](#general-f)
- [Browser Forensics](#browser)
- [Cloud Foreniscs](#cloud)
- [Firmware Forensics](#firmware)
- [Linux Forensics](#linux)
- [Memory Forensics](#memory)
- [Mobile Device Forensics](#mobile-f)
- [Network Forensics](#network)
- [OS X Forensics](#osx)
- [Windows Forensics](#windows)
- [PDF Forensics](#pdf)
- [Image Forensics](#photo)





#### Sort

* Sort sections alphabetically
* Update ToC

#### End Sort






--------------
### <a name="ir"></a>Incident Response
* **101**
	* Better security --> Mean time to detect & Mean time to respond
	* [Introduction to DFIR](https://sroberts.github.io/2016/01/11/introduction-to-dfir-the-beginning/)
	* [Computer Security Incident Handling Guide - NIST](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
	* [AboutDFIR.com](https://aboutdfir.com)
		* The Definitive Compendium Project Digital Forensics & Incident Response
	* [Basics of Incident Handling - Josh Rickard](https://msadministrator.github.io/presentations/basics-of-incident-handling.html)
	* [Introduction to DFIR - Scott J Roberts](https://medium.com/@sroberts/introduction-to-dfir-d35d5de4c180)
	* [The Incident Response Hierarchy of Needs](https://github.com/swannman/ircapabilities)
		* The Incident Response Hierarchy is modeled after [Maslow's Hierarchy of Needs](https://github.com/swannman/ircapabilities). It describes the capabilities that organizations must build to defend their business assets.
	* [SCORE: Law Enforcement FAQ - SANS(2004)](https://www.sans.org/score/law-enforcement-faq/)
		* If we are going to turn the tide against computer attacks, the entire information security community must cooperate more effectively than ever before. The private sector, government agencies, and law enforcement must cooperate in responding to computer attacks. Yet, many security personnel aren't familiar with how to engage law enforcement effectively. For example, when should you call local or national law enforcement to help handle a case? How can you develop communication channels with law enforcement? This FAQ addresses these questions and more, with the goal of helping to foster communication with the law enforcement community. This project was developed as part of the SANS Institute's Cyber Defense Initiative ® (CDI). Each year, SANS polls the security community for ideas about CDI collaborative projects we can all use to help improve our security. Volunteers from around the world pour enormous amounts of effort to bring these projects to fruition, including this FAQ.
* **Articles/Blogposts/Writeups**
	* [No Easy Breach: Challenges and Lessons Learned from an Epic Investigation](https://archive.org/details/No_Easy_Breach#)
	* [Handler Diaries - Another Hunting Post(DFIR)](http://blog.handlerdiaries.com/?p=775)
		* Good post on not only knowing the layout, but knowing expected behaviours.
	* [Triaging Malware Incidents](http://journeyintoir.blogspot.com/2013/09/triaging-malware-incidents.html)
		* Good writeup/blogpost from Journey into Incidence Response
	* [SANS Institute Security Consensus Operational Readiness Evaluation](https://www.sans.org/media/score/checklists/LinuxCheatsheet_2.pdf)
	* [Security Breach 101 - Ryan McGeehan](https://medium.com/starting-up-security/security-breach-101-b0f7897c027c)
	* [Security Breach 102 - Ryan McGeehan](https://medium.com/starting-up-security/security-breach-102-d5fc88c5660f)
	* [Learning From A Year of Security Breaches - Ryan McGeehan](https://medium.com/starting-up-security/learning-from-a-year-of-security-breaches-ed036ea05d9b)
	* [VirusTotal is not an Incident Responder - Matt Benton](https://medium.com/maverislabs/virustotal-is-not-an-incident-responder-80a6bb687eb9)
		* This post is designed for both Defenders and fellow Red Teamers. For Defenders, I hope to shed some light on how attackers can manipulate VirusTotal’s URL link scanning to provide clean responses. For Red Teamers, this is just information to add to the toolkit on how to emulate an adversary and challenge Defenders to not make all decisions based on a VirusTotal response.
	* **Cloud**
		* [Scalable infrastructure for investigations and incident response - MSRC Team(2019)](https://msrc-blog.microsoft.com/2019/08/30/scalable-infrastructure-for-investigations-and-incident-response/)
		* [Digital Forensic Analysis of Amazon Linux EC2 Instances - Ken Hartman(2018)](https://www.sans.org/reading-room/whitepapers/cloud/digital-forensic-analysis-amazon-linux-ec2-instances-38235)
		* [Incident Response in Amazon EC2: First Responders Guide to Security Incidents in the Cloud - Tom Arnold(2016)](https://www.sans.org/reading-room/whitepapers/incident/paper/36902)
			* As Head of Digital Forensics for Payment Software Company Inc. (“PSC”), a company that focuses exclusively on Clients that accept or process payments,1 we’ve responded to sites operating within cloud environments, most notably Amazon EC2.
		* [Hardening AWS Environments and Automating Incident Response for AWS Compromises - Andrew Krug, Alex McCormack, Joel Ferrier, Jeff Parr](https://www.blackhat.com/docs/us-16/materials/us-16-Krug-Hardening-AWS-Environments-And-Automating-Incident-Response-For-AWS-Compromises-wp.pdf)
		* [Building a Cloud-Specific Incident Response Plan - AWS Security Team(2017)](https://aws.amazon.com/blogs/publicsector/building-a-cloud-specific-incident-response-plan/)
		* [Hardening AWS Environments and Automating Incident Response - Andrew Krug, Alex McCormack](http://threatresponse-derbycon.s3-website-us-west-2.amazonaws.com/#/step-1)
		* [Incident Response in the Cloud - Jim Jennis, Conrad Fernandes(re:Invent 2017)](https://www.slideshare.net/AmazonWebServices/incident-response-in-the-cloud-sid319-reinvent-2017)
			* In this session, we walk you through a hypothetical incident response managed on AWS. Learn how to apply existing best practices as well as how to leverage the unique security visibility, control, and automation that AWS provides. We cover how to set up your AWS environment to prevent a security event and how to build a cloud-specific incident response plan so that your organization is prepared before a security event occurs. This session also covers specific environment recovery steps available on AWS.
		* [Hardening AWS Environments and Automating Incident Response for AWS Compromises - Andrew Krug & Alex McCormack(BHUSA2016)](https://www.youtube.com/watch?v=Y9cAHxd0kW4)
	* Incident Response procedures differ in the cloud versus when performed in traditional, on-premise, environments. The cloud offers the ability to respond to an incident by programmatically collecting evidence and quarantining instances but with this programmatic ability comes the risk of a compromised API key. The risk of a compromised key can be mitigated but proper configuration and monitoring must be in place. The talk discusses the paradigm of Incident Response in the cloud and introduces tools to automate the collection of forensic evidence of a compromised host. It highlights the need to properly configure an AWS environment and provides a tool to aid the configuration process.
	* **Linux**
	* **OS X**
	* **Windows**
		* [Planning for Compromise - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/planning-for-compromise)
		* [Alerting and Detection Strategy Framework - palantir](https://medium.com/palantir/alerting-and-detection-strategy-framework-52dc33722df2)
		* [Know your Windows Processes or Die Trying](https://sysforensics.org/2014/01/know-your-windows-processes.html)
			* Excellent quick reference on Windows proccesses with a focus on Win7. Good resource.
		* [License to Kill: Malware Hunting with the Sysinternals Tools](http://channel9.msdn.com/Events/TechEd/NorthAmerica/2013/ATC-B308)
		* [Windows Program Automatic Startup Locations](http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/)			
		* [Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)
		* [Spotting the Adversary with Windows Event Log Monitoring - NSA](http://cryptome.org/2014/01/nsa-windows-event.pdf)
			* NSA 70-page writeup on windows event log monitoring
		* [Ways to Identify Malware on a System Ryan Irving](http://www.irongeek.com/i.php?page=videos/bsidestampa2015/201-ways-to-identify-malware-on-a-system-ryan-irving)
* **CheatSheets/Checklists**
	* [Initial Security Incident Questionnaire for Responders - Lenny Zeltser](https://zeltser.com/security-incident-questionnaire-cheat-sheet/)
	* [Security Incident Survey Cheat Sheet for Server Administrators - Lenny Zeltser](https://zeltser.com/security-incident-survey-cheat-sheet/)
	* [Critical Log Review Checklist for Security Incidents - Lenny Zeltser](https://zeltser.com/security-incident-log-review-checklist/)
	* [Digital Forensics and Incident Response - Jai Minton](https://www.jaiminton.com/cheatsheet/DFIR/#)
* **Documents**
	* [Sample Incident Handling Forms - SANS](https://www.sans.org/score/incident-forms/)
* **Methodologies/Playbooks**
	* [incidentresponse.com playbooks](https://www.incidentresponse.com/playbooks/)
	* [Using a “Playbook” Model to Organize Your Information Security Monitoring Strategy - cisco](https://blogs.cisco.com/security/using-a-playbook-model-to-organize-your-information-security-monitoring-strategy)
	* [Univeristy of Florida IR Playbooks](http://www.cst.ucf.edu/about/information-security-office/incident-response/)
	* [pagerduty Incident Response](https://response.pagerduty.com/)
		* This documentation covers parts of the PagerDuty Incident Response process. It is a cut-down version of our internal documentation, used at PagerDuty for any major incidents, and to prepare new employees for on-call responsibilities. It provides information not only on preparing for an incident, but also what to do during and after. It is intended to be used by on-call practitioners and those involved in an operational incident response process (or those wishing to enact a formal incident response process). See the about page for more information on what this documentation is and why it exists.
	* [Strategies to Mitigate Cyber Security Incidents - Mitigation Details - Australian Cyber Security Center](https://www.cyber.gov.au/publications/strategies-to-mitigate-cyber-security-incidents-mitigation-details)
	* [National Incident Management System -USA](https://www.fema.gov/national-incident-management-system)
	* [IRM (Incident Response Methodologies)](https://github.com/certsocietegenerale/IRM)
		* CERT Societe Generale provides easy to use operational incident best practices. These cheat sheets are dedicated to incident handling and cover multiple fields in which a CERT team can be involved. One IRM exists for each security incident we're used to dealing with.
	* [Security Incident Response Guide - Cloud.gov](https://cloud.gov/docs/ops/security-ir/)
		* This document outlines cloud.gov’s internal process for responding to security incidents. It outlines roles and responsibilities during and after incidents, and it lays out the steps we’ll take to resolve them.
* **Papers**
	* [An Incident Handling Process for Small and Medium Businesses  - SANS 2007](https://www.sans.org/reading-room/whitepapers/incident/incident-handling-process-small-medium-businesses-1791)
* **Platforms**
	* [TheHive](https://github.com/TheHive-Project/TheHive)
		* TheHive is a scalable 4-in-1 open source and free Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly. It is the perfect companion for MISP. You can synchronize it with one or multiple MISP instances to start investigations out of MISP events. You can also export an investigation's results as a MISP event to help your peers and partners detect and react to attacks you've dealt with. Additionally, when TheHive is used in conjunction with Cortex, security analysts and researchers can easily analyze hundred of observables at once using more than 100 analyzers, contain an incident or eradicate malware thanks to Cortex responders.
	* [INCIDENTS](https://github.com/veeral-patel/incidents)
		* INCIDENTS is a web-based, actively maintained case management tool for incident response, just like TheHive. You can use INCIDENTS whether you're investigating a malware infection, a phishing campaign, insider abuse, an application vulnerability, a denial-of-service attempt, or any other kind of security incident.
* **Prioritization**
	* [Determining Incident Priority - Michael Churchman PagerDuty Blog(2017)](https://www.pagerduty.com/blog/determining-incident-priority/)
* **Talks & Videos**
	* **Cloud**
		* [GSuite Digital Forensics and Incident Response - Megan Roddie(BSides SanAntonio)](https://www.youtube.com/watch?v=pGn95-L8_sA&feature=youtu.be)
			* With the current standard of companies transitioning to the cloud, digital forensic investigators and incident responders are facing new, unknown territory. As a starting point of talking about cloud DFIR, this talk aims to provide a real-life case study of what it is like to respond to an incident in GSuite, Google’s cloud business suite. The goal is that by reviewing this case study the audience will not only learn about GSuite DFIR but also begin to think about how this extends to all cloud environments.
	* **OS X**
		* [Incident response on macOS - Thomas Reed](https://www.irongeek.com/i.php?page=videos/bsidescleveland2019/bsides-cleveland-c-04-incident-response-on-macos-thomas-reed)
			* This talk will provide details about how to do incident response on macOS, which is something that is not well-understood except by a relatively small number of Mac-knowledgeable experts. Examples will be given using real-world malware and tools.
	* [Fraud detection and forensics on telco networks - Hack.lu 2016](https://www.youtube.com/watch?v=09EAWT_F1ZA&app=desktop)
	* [Commercial Spyware - Detecting the Undetectable](https://www.blackhat.com/docs/us-15/materials/us-15-Dalman-Commercial-Spyware-Detecting-The-Undetectable-wp.pdf)
	* [Investigating PowerShell Attacks - Ryan Kazanciyan and Matt Hastings - DEFCON22](https://www.youtube.com/watch?v=qF06PFcezLs)
		* This presentation will focus on common attack patterns performed through PowerShell - such as lateral movement, remote command execution, reconnaissance, file transfer, etc. - and the sources of evidence they leave behind. We'll demonstrate how to collect and interpret these forensic artifacts, both on individual hosts and at scale across the enterprise. Throughout the presentation, we'll include examples from real-world incidents and recommendations on how to limit exposure to these attacks.
	* [Lend me your IR's! - Matt Scheurer(Hack3rCon X)](https://www.youtube.com/watch?v=tsEWcoPFfbs&list=PLpYLcKpNrG2Xw4q9tMReG9W3o4igr7nYz&index=8&t=0s)
		* Have you ever felt compelled to tip your cap to a malicious threat actor? Protecting systems and networks as a tech defender means withstanding a constant barrage of unsophisticated attacks from automated tools, botnets, crawlers, exploit kits, phish kits, and script kiddies; oh my! Once in a while we encounter attacks worthy of style points for creativity or new twists on old attack techniques. This talk features live demo reenactments from some advanced attacks the presenter investigated. These live demos showcase technical deep dives of the underpinnings from both the attacker and investigator sides of these attacks. Attendee key takeaways are strategies, freely available tools, and techniques helpful during incident response investigations.
		* [Slides](https://www.slideshare.net/cerkah/hack3rcon-x-lend-me-your-irs)
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
	* [Beyond The CPU:Defeating Hardware Based RAM Acquisition](https://www.blackhat.com/presentations/bh-dc-07/Rutkowska/Presentation/bh-dc-07-Rutkowska-up.pdf)
	* [Deceiving blue teams using anti-forensic techniques - Adam Ziaja](https://blog.redteam.pl/2020/01/deceiving-blue-teams-anti-forensic.html)
* **Android & iOS**
	* [Incident Response for Android and iOS - NowSecure](https://github.com/nowsecure/mobile-incident-response/tree/master/en)
		* This book will prepare enterprises and practitioners for the inevitable increase in mobile compromise. We will use step-by-step tutorials, guiding the reader from setting up a mobile IR practice all the way through continuous monitoring of mobile devices.
* **General**
* **Papers**
	* [Secure Deletion of Data from Magnetic and Solid-State Memory](http://static.usenix.org/publications/library/proceedings/sec96/full_papers/gutmann)
	* [Hiding Data in Hard-Drive's Service Areas](http://recover.co.il/SA-cover/SA-cover.pdf)
		* In this paper we will demonstrate how spinning hard-drives’ serv ice areas 1 can be used to hide data from the operating-system (or any software using the standard OS’s API or the standard ATA commands to access the hard- drive)
* **Talks/Presentations/Videos**
	* [Anti-Forensics for the Louise - Derbycon - int0x80 (of Dual Core)](https://www.youtube.com/watch?v=-HK1JHR7LIM)
	* [Hardware Backdooring is Practical** -Jonathan Brossard](https://www.youtube.com/watch?v=umBruM-wFUw)
	* [Hiding the breadcrumbs: Forensics and anti-forensics on SAP systems - Juan Perez-Etchegoyen](http://www.irongeek.com/i.php?page=videos/derbycon4/t508-hiding-the-breadcrumbs-forensics-and-anti-forensics-on-sap-systems-juan-perez-etchegoyen)
		* The largest organizations in the world rely on SAP platforms to run their critical processes and keep their business crown jewels: financial information, customer data, intellectual property, credit cards, human resources salaries, sensitive materials, suppliers and more. Everything is there and attackers know it. For several years at Onapsis we have been researching on how cyber-criminals might be able to break into ERP systems in order to help organizations better protect themselves. This has enabled us to gain a unique expertise on which are the most critical attack vectors and what kind of traces they leave (and don’t) over the victim’s SAP platforms. SAP systems need to be ready for Forensic Analysis, so the big question is: Are your systems prepared to retain the attackers breadcrumbs in the event of an attack? Join us and learn how to do a forensic analysis of an SAP system, looking for traces of a security breach We will also show novel techniques being used by attackers to avoid being detected during post attack forensic investigations. Vulnerabilities related to anti-forensic techniques will be presented together with their mitigation. **NEW** New attacks never presented before will be shown. JAVA, ABAP and BO systems will be covered.
	* [Forensics Impossible: Self-Destructing Thumb Drives - Brandon Wilson](https://www.youtube.com/watch?v=NRMqwc5YEu4)
	* [Anti-Forensics and Anti-Anti-Forensics Attacks - Michael Perkins](https://www.youtube.com/watch?v=J4x8Hz6_hq0)
		* Everyone's heard the claim: Security through obscurity is no security at all. Challenging this claim is the entire field of steganography itself - the art of hiding things in plain sight. Most people know you can hide a text file inside a photograph, or embed a photograph inside an MP3. But how does this work under the hood? What's new in the stego field?  This talk will explore how various techniques employed by older steganographic tools work and will discuss a new technique developed by the speaker which embodies both data hiding and data enciphering properties by encoding data inside NTFS volumes. A new tool will be released during this talk that will allow attendees to both encode and decode data with this new scheme.
		* Slides: [Slides(link)](http://www.slideshare.net/the_netlocksmith/defcon-20-antiforensics-and-antiantiforensics)
	* [Destroying Evidence Before Its Evidence](https://www.youtube.com/watch?v=lqBVAcxpwio&spfreload=1)
	* [And That's How I Lost My Other Eye...Explorations in Data Destruction](https://www.youtube.com/watch?v=-bpX8YvNg6Y)
	* [An Anti-Forensics Primer - Jason Andress](http://www.irongeek.com/i.php?page=videos/derbycon3/s216-an-anti-forensics-primer-jason-andress)
	* This talk will cover the basics of anti-forensics, the tools and techniques that can be used to make life harder for computer forensic examiners. We will cover some of the basic methods that are used (disk wiping, time stomping, encryption, etc…) and talk about which of these methods might actually work and which are easily surmounted with common forensic tools.
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
	* **SQLite**
		* [Python Parser to Recover Deleted SQLite Database Data - az4n6](https://az4n6.blogspot.com/2013/11/python-parser-to-recover-deleted-sqlite.html))
		* [SQLite-Parser](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser)
			* Script to recover deleted entries in an SQLite database
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
		* [firefox_decrypt](https://github.com/unode/firefox_decrypt)
			* Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox/Thunderbird/Seabird) profiles
		* [firepwd.py](https://github.com/lclevy/firepwd)
			* firepwd.py, an open source tool to decrypt Mozilla protected passwords
		* [Firefed](https://github.com/numirias/firefed)
			* Firefed is a command-line tool to inspect Firefox profiles. It can extract saved passwords, preferences, addons, history and more. You may use it for forensic analysis, to audit your config for insecure settings or just to quickly extract some data without starting up the browser.
	* **Neutral**
		* [Extension Finder](https://github.com/brad-anton/extension_finder)
			* Python and PowerShell utilities for finding installed browser extensions, plug-ins and add-ons. Attempts to find installed browser extensions (sometimes called add-ons or plug-ins, depending on the browser).
		* [Hindsight](https://github.com/obsidianforensics/hindsight)
			* Hindsight is a free tool for analyzing web artifacts. It started with the browsing history of the Google Chrome web browser and has expanded to support other Chromium-based applications (with more to come!). Hindsight can parse a number of different types of web artifacts, including URLs, download history, cache records, bookmarks, autofill records, saved passwords, preferences, browser extensions, HTTP cookies, and Local Storage records (HTML5 cookies). Once the data is extracted from each file, it is correlated with data from other history files and placed in a timeline.
* **Miscellaneous**


--------------
####<a name="cloud">Cloud Forensics</a>
* **101**
* **Articles/Blogposts/Writeups**
	* **AWS**
		* [Investigating CloudTrail Logs](https://medium.com/starting-up-security/investigating-cloudtrail-logs-c2ecdf578911)
	* **Azure**
		* [Acquiring a VHD to Investigate - MSRC Team](https://msrc-blog.microsoft.com/2019/09/03/acquiring-a-vhd-to-investigate/)
	* **GCP**
* **Presentations/Talks/Videos**
* **Tools**
* **Miscellaneous**



--------------
### <a name="firmware"></a>Firmware 
* [Firmware Forensics: Diffs, Timelines, ELFs and Backdoors](http://w00tsec.blogspot.com/2015/02/firmware-forensics-diffs-timelines-elfs.html)



--------------
### <a name="linux">Linux Forensics</a>
* **101**
* **Articles/Blogposts/Writeups**
* **Presentations/Talks/Videos**
* **Tools**
	* **USB**
		* [usbrip](https://github.com/snovvcrash/usbrip)
			* usbrip is a small piece of software written in pure Python 3 (using some external modules, see Dependencies/pip) which analyzes Linux log data (journalctl output or /var/log/syslog* and /var/log/messages* files, depending on the distro) for constructing USB event history tables. Such tables may contain the following columns: "Connected" (date & time), "Host", "VID" (vendor ID), "PID" (product ID), "Product", "Manufacturer", "Serial Number", "Port" and "Disconnected" (date & time).
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


--------------
### <a name="mobile">Mobile Device(Android/iOS) Forensics</a>
* **101**
	* **Android**
	* **iOS**
		* [Apple iPhone - Forensics Wiki](http://www.forensicswiki.org/wiki/Apple_iPhone)	
* **Articles/Blogposts/Writeups**
	* **Both/Neutral**
		* [A technical look at Phone Extraction - Privacy International(2019)](https://privacyinternational.org/long-read/3256/technical-look-phone-extraction)
	* **Android**
	* **iOS**
		* [The art of iOS and iCloud forensics](https://blog.elcomsoft.com/2017/11/the-art-of-ios-and-icloud-forensics/)
* **Papers**
	* **Android**
	* **iOS**
		* [iOS Forensics Analyis(2012) SANS Whitepaper](https://www.sans.org/reading-room/whitepapers/forensics/forensic-analysis-ios-devices-34092)
		* [iOS Forensic Investigative Methods Guide](http://www.zdziarski.com/blog/wp-content/uploads/2013/05/iOS-Forensic-Investigative-Methods.pdf)
* **Presentations/Talks/Videos**
* **Tools**
	* **Android**
	* **iOS**
		* [iOSForensic](https://github.com/Flo354/iOSForensic)
			* iosForensic is a python tool to help in forensics analysis on iOS. It get files, logs, extract sqlite3 databases and uncompress .plist files in xml.








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
	* [Bundle(OS X) - Wikipedia](https://en.wikipedia.org/wiki/Bundle_(macOS)#macOS_application_bundles)
	* [Loadable Kernel Module - Wikipedia](https://en.wikipedia.org/wiki/Loadable_kernel_module)
	* [Kernel Extension Overview - Apple](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html)
	* [What are Kexts? - MacBreaker](http://www.macbreaker.com/2012/01/what-are-kexts.html)
	* [Property List - Wikipedia](https://en.wikipedia.org/wiki/Property_list#Mac_OS_X)
* **Articles/Blogposts/Writeups**
	* [The Cider Press:Extracting Forensic Artifacts From Apple Continuity](https://www.sans.org/summit-archives/file/summit-archive-1498146226.pdf)
	* [Mac OS X Live Forensics 101 - Action Dan](https://lockboxx.blogspot.com/2014/03/mac-os-x-live-forensics-101.html)
* **General**
* **Papers**
* **Presentations/Talks/Videos**
	* [Cleaning the Apple Orchard - Using Venator to Detect macOS Compromise - Richie Cyrus(BSides Charm2019)](http://www.irongeek.com/i.php?page=videos/bsidescharm2019/1-02-cleaning-the-apple-orchard-using-venator-to-detect-macos-compromise-richie-cyrus)
		* Various solutions exist to detect malicious activity on macOS. However, they are not intended for enterprise use or involve installation of an agent. This session will introduce and demonstrate how to detect malicious macOS activity using the tool Venator. Venator is a python based macOS tool designed to provide defenders with the data to proactively identify malicious macOS activity at scale.
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
	* [AutoMacTC: Automating Mac Forensic Triage - CrowdStrike](https://github.com/CrowdStrike/automactc)
		* This is a modular forensic triage collection framework designed to access various forensic artifacts on macOS, parse them, and present them in formats viable for analysis. The output may provide valuable insights for incident response in a macOS environment. Automactc can be run against a live system or dead disk (as a mounted volume.)
		* [Article](https://www.crowdstrike.com/blog/automating-mac-forensic-triage/)
* **Miscellaneous**







----------------
### <a name="windows">Windows Forensics</a>
* **101**
* **Articles/Blogposts/Writeups**
	* **Active Directory**
		* [The only PowerShell Command you will ever need to find out who did what in Active Directory - Przemyslaw Klys](https://evotec.xyz/the-only-powershell-command-you-will-ever-need-to-find-out-who-did-what-in-active-directory/)
		* [Forensics: Monitor Active Directory Privileged Groups with PowerShell - Ashley McGlone](https://blogs.technet.microsoft.com/ashleymcglone/2014/12/17/forensics-monitor-active-directory-privileged-groups-with-powershell/)
		* [Digital Forensics Tips&Tricks: How to Detect an Intruder-driven Group Policy Changes - volnodumcev](https://habr.com/en/post/444048/)
	* **Bitlocker**
		* [Extracting Bitlocker Keys from a TPM - Denis Andzakovic](https://pulsesecurity.co.nz/articles/TPM-sniffing)
		* [NVbit : Accessing Bitlocker volumes from linux](http://www.nvlabs.in/index.php?/archives/1-NVbit-Accessing-Bitlocker-volumes-from-linux.html)
	* **Disk Forensics**
		* [Invoke-LiveResponse](https://github.com/mgreen27/Invoke-LiveResponse)
			* The current scope of Invoke-LiveResponse is a live response tool for targeted collection. There are two main modes of use in Invoke-LiveResponse and both are configured by a variety of command line switches.
			* [Article](https://www.linkedin.com/pulse/invoke-liveresponse-matthew-green/)
	* **Event Log**
		* [How to parse Windows Eventlog](http://dfir-blog.com/2016/03/13/how-to-parse-windows-eventlog/)
		* [Windows Security Event Logs: my own cheatsheet - Andrea Fortuna](https://www.andreafortuna.org/2019/06/12/windows-security-event-logs-my-own-cheatsheet/)
		* [Windows Security Log Events - UltimateWindowsSecurity](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx)
	* **Event Tracing**
		* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
			* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it’s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What’s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."
	* **Evidence of Execution**
		* [Available Artifacts - Evidence of Execution - Adam Harrison(2019)](https://blog.1234n6.com/2018/10/available-artifacts-evidence-of.html)
		* [HowTo: Determine Program Execution - Harlan Carvey(2013)](http://windowsir.blogspot.com/2013/07/howto-determine-program-execution.html)
		* [Forensic Artifacts: evidences of program execution on Windows systems - Andrea Fortuna(2018)](https://www.andreafortuna.org/2018/05/23/forensic-artifacts-evidences-of-program-execution-on-windows-systems/)
		* [It Is All About Program Execution - Corey Harrell(2014)](http://journeyintoir.blogspot.com/2014/01/it-is-all-about-program-execution.html)
		* [Did It Execute? - Mary Singh](https://www.fireeye.com/blog/threat-research/2013/08/execute.html)
	* **Notification DB**
		* [Hacking Exposed Daily Blog #440: Windows 10 Notifications Database](http://www.hecfblog.com/2018/08/daily-blog-440-windows-10-notifications.html)
		* [Windows 10 Notification WAL database - malwaremaloney](https://malwaremaloney.blogspot.com/2018/08/windows-10-notification-wal-database.html?m=1)
	* **O365**
		* [Security Information and Event Management (SIEM) server integration with Microsoft 365 services and applications - docs.ms](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/siem-server-integration)
			* Is your organization using or planning to get a Security Information and Event Management (SIEM) server? You might be wondering how it integrates with Microsoft 365 or Office 365. This article provides a list of resources you can use to integrate your SIEM server with Microsoft 365 services and applications.
	* **Registry**
		* [Digging Up the Past: Windows Registry Forensics Revisited - David Via](https://www.fireeye.com/blog/threat-research/2019/01/digging-up-the-past-windows-registry-forensics-revisited.html)
	* **Touch-Screen**
		* [Touch Screen Lexicon Forensics (TextHarvester/WaitList.dat) - Barnaby Skeggs](https://b2dfir.blogspot.com/2016/10/touch-screen-lexicon-forensics.html)
	* **USB**
		* [USB storage forensics in Win10 #1 - Events -Forensics Exchange](https://forensixchange.com/posts/19_08_03_usb_storage_forensics_1/)
* **Educational**
	* [Happy DPAPI!](http://blog.digital-forensics.it/2015/01/happy-dpapi.html)
	* [WINDOWS REGISTRY AUDITING CHEAT SHEET - Win 7/Win 2008 or later - Malware Archaelogy](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a00963153450a8779b23489/1509987890282/Windows+Registry+Auditing+Cheat+Sheet+ver+Nov+2017.pdf)
* **General**
	* [SANS CHEAT SHEET- Windows Artifact Analysis](https://uk.sans.org/posters/windows_artifact_analysis.pdf)
* **Sysmon**
	* **Articles/Blogposts/Writeups**
		* [Sysmon - DFIR](https://github.com/MHaggis/sysmon-dfir)
			* A curated list of resources for learning about deploying, managing and hunting with Microsoft Sysmon. Contains presentations, deployment methods, configuration file examples, blogs and additional github repositories.
		* [Getting Started With Sysmon - John Strand(BHIS)](https://www.blackhillsinfosec.com/getting-started-with-sysmon/)
		* [Building A Perfect Sysmon Configuration File - Paula(CQURE)](https://cqureacademy.com/blog/server-monitoring/sysmon-configuration-file)
		* [Working With Sysmon Configurations Like a Pro Through Better Tooling - Matt Graeber](https://posts.specterops.io/working-with-sysmon-configurations-like-a-pro-through-better-tooling-be7ad7f99a47)
	* **Talks/Presentations/Videos**
		* [Advanced Incident Detection and Threat Hunting using Sysmon (and Splunk) - Tom Ueltschi](https://www.youtube.com/watch?v=vv_VXntQTpE)
			* This presentation will give an overview and detailed examples on how to use the free Sysinternals tool SYSMON to greatly improve host-based incident detection and enable threat hunting approaches.
			* [Slides](http://security-research.dyndns.org/pub/slides/FIRST-TC-2018/FIRST-TC-2018_Tom-Ueltschi_Sysmon_PUBLIC.pdf)
	* **Tools**
		* [sysmon-config | A Sysmon configuration file for everybody to fork - SwiftonSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
			* Sysmon configuration file template with default high-quality event tracing
* **Talks/Presentations/Videos**
	* [Techniques for fast windows forensics investigations](https://www.youtube.com/watch?v=eI4ceLgO_CE)
		* Look at sniper forensics, skip around, 18min has resources you want to grab for snapshots		
* **Tools**
	* **Active Directory Focused**
		* [NTDSXtract - Active Directory Forensics Framework](http://www.ntdsxtract.com/)
			* Description from the page: This framework was developed by the author in order to provide the community with a solution to extract forensically important information from the main database of Microsoft Active Directory (NTDS.DIT).
		* [ADTimeline](https://github.com/ANSSI-FR/ADTimeline)
			* PowerShell script creating a timeline of Active Directory changes with replication metadata
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
	* **Event Log**
		* [Introducing EvtxECmd!! - Eric Zimmerman](https://binaryforay.blogspot.com/2019/04/introducing-evtxecmd.html)
		* [EvtxECmd - Harlan Carvey](https://windowsir.blogspot.com/2019/05/evtxecmd.html)
		* [Opcode And Task Enumeration. and shell items? - Matthew Seyer](https://medium.com/@forensic_matt/opcode-and-task-enumeration-and-shell-items-bd4ff0b548a3)
	* **ETW**
		* [Windows Insight: The Windows Telemetry ETW Monitor - Aleksandar Milenkoski](https://insinuator.net/2020/01/windows-insight-the-windows-telemetry-etw-monitor/)
			* The Windows Insight repository now hosts the Windows Telemetry ETW Monitor framework. The framework monitors and reports on Windows Telemetry ETW (Event Tracing for Windows) activities – ETW activities for providing data to Windows Telemetry. It consists of two components:
		* [Windows Insight](https://github.com/ernw/Windows-Insight)
			* The content of this repository aims to assist efforts on analysing inner working principles, functionalities, and properties of the Microsoft Windows operating system. This repository stores relevant documentation as well as executable files needed for conducting analysis studies.
	* **File Systems**
		* [PowerForensics - PowerShell Digital Forensics](https://github.com/Invoke-IR/PowerForensics)
			* The purpose of PowerForensics is to provide an all inclusive framework for hard drive forensic analysis. PowerForensics currently supports NTFS and FAT file systems, and work has begun on Extended File System and HFS+ support.
		* [Introducing KAPE – Kroll Artifact Parser and Extractor - Eric Zimmerman](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape)
		* [Introduction to KAPE - 13Cubed](https://www.youtube.com/watch?v=L9H1uj2HSb8)
			* This 13Cubed episode covers an exciting new tool from Kroll and Eric Zimmerman called KAPE. From the developer, KAPE is an efficient and highly configurable triage program that will target essentially any device or storage location, find forensically useful artifacts, and parse them within a few minutes.
		* [Triage Collection and Timeline Analysis with KAPE - Mari DeGrazia](https://www.youtube.com/watch?v=iYyWZSNBNcw)
			* As hard drive sizes get larger and larger, conducting full disk forensics is becoming a thing of the past. Why spend hours analyzing a disk image when you can analyze a handful of core Windows artifacts to build your case in a matter of minutes. In this webcast, learn how to use the free tool KAPE to collect key operating system files from a live system or a forensic image. Once the data is collected, KAPE can be leveraged to parse various artifacts and build a mini-timeline. In addition, learn how to customize KAPE by writing your own custom modules for your workflow.
	* **Memory Acquisition**
		* [Margarita Shotgun](https://github.com/ThreatResponse/margaritashotgun)
			* Python Remote Memory Aquisition
	* **Notifications DB**
	* **Office365**
		* [HAWK 1.1.4](https://www.powershellgallery.com/packages/HAWK/1.1.4)
			* The Hawk module has been designed to ease the burden on O365 administrators who are performing a forensic analysis in their organization. It accelerates the gathering of data from multiple sources in the service. It does NOT take the place of a human reviewing the data generated and is simply here to make data gathering easier.
	* **Pre-Fetch**
		* [WinPrefetchView v1.25](http://www.nirsoft.net/utils/win_prefetch_view.html)
			* Each time that you run an application in your system, a Prefetch file which contains information about the files loaded by the application is created by Windows operating system. The information in the Prefetch file is used for optimizing the loading time of the application in the next time that you run it. WinPrefetchView is a small utility that reads the Prefetch files stored in your system and display the information stored in them. By looking in these files, you can learn which files every application is using, and which files are loaded on Windows boot. 
	* **Powershell**
		* [Kansa -A Powershell incident response framework ](https://github.com/davehull/Kansa)
			* A modular incident response framework in Powershell. Note there's a bug that's currently cropping up in PowerShell version 2 systems, but version 3 and later should be fine
		* [Meerkat](https://github.com/TonyPhipps/Meerkat)
			* Meerkat is collection of PowerShell modules designed for artifact gathering and reconnaisance of Windows-based endpoints. Use cases include incident response triage, threat hunting, baseline monitoring, snapshot comparisons, and more.
	* **Program Execution**
		* [Did it Execute? - Mandiant](https://www.mandiant.com/blog/execute/)
			* You found a malicious executable! Now you’ve got a crucial question to answer: did the file execute? We’ll discuss a few sources of evidence you can use to answer this question. In this post, we will focus on static or “dead drive” forensics on Windows systems. We will cover four main sources of evidence: Windows Prefetch, Registry, Log Files, and File Information.
		* [HowTo: Determine Program Execution](http://windowsir.blogspot.com/2013/07/howto-determine-program-execution.html)
	* **Recycle Bin**
		* [Rifiuti2](https://abelcheung.github.io/rifiuti2/)
			* Rifiuti2 analyse recycle bin files from Windows. Analysis of Windows recycle bin is usually carried out during Windows computer forensics. Rifiuti2 can extract file deletion time, original path and size of deleted files. For more ancient versions of Windows, it can also check whether deleted items were not in recycle bin anymore (that is, either restored or permanently purged).
	* **Registry**
		* [Regipy: Automating registry forensics with python - Martin Korman](https://medium.com/dfir-dudes/regipy-automating-registry-forensics-with-python-b170a1e2b474)
		* [regipy](https://github.com/mkorman90/regipy)
			* Regipy is an os independent python library for parsing offline registry hives
	* **WMI Focused**
		* [PoSH-R2](https://github.com/WiredPulse/PoSh-R2)
			* PoSH-R2 is a set of Windows Management Instrumentation interface (WMI) scripts that investigators and forensic analysts can use to retrieve information from a compromised (or potentially compromised) Windows system. The scripts use WMI to pull this information from the operating system. Therefore, this script will need to be executed with a user that has the necessary privileges.
		* [WMI_Forensics](https://github.com/davidpany/WMI_Forensics)
			* This repository contains scripts used to find evidence in WMI repositories
* **Miscellaneous**
	* [Windows Attribute changer](http://www.petges.lu/home/)
	* [Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
		* Code from "Taking Hunting to the Next Level: Hunting in Memory" presentation at SANS Threat Hunting Summit 2017 by Jared Atkinson and Joe Desimone
	* [Beagle](https://github.com/yampelo/beagle)
		* Beagle is an incident response and digital forensics tool which transforms data sources and logs into graphs. Supported data sources include FireEye HX Triages, Windows EVTX files, SysMon logs and Raw Windows memory images. The resulting Graphs can be sent to graph databases such as Neo4J or DGraph, or they can be kept locally as Python NetworkX objects. Beagle can be used directly as a python library, or through a provided web interface.



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
### <a name="sd">SD card Forensics</a>
* **101**
* **Articles/Blogposts/Writeups**
* **General**
* **Papers**
* **Talks & Videos**
	* [Data recovery on dead micro SD card - HDD Recovery Services](https://www.youtube.com/watch?v=jjB6wliyE_Y&feature=youtu.be)
* **Tools**
* **Miscellaneous**




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
	* [Bootkit Disk Forensics – Part 1 - MalwareTech](http://www.malwaretech.com/2015/02/bootkit-disk-forensics-part-1.html)
		* [Part 2](http://www.malwaretech.com/2015/03/bootkit-disk-forensics-part-2.html)
* **General**
* **Tools**
* **Miscellaneous**













