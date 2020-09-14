------------------------------------------------------------------------------------------------------------------------------
## Table of Contents
- [101/Basics](#101basics)
- [I Want to...]()
	- [Not Get Hacked](#ngh)
	- [(Personal)](#personal)
		- [Create an Asset Inventory](#assetinventory)
		- [Track all my Assets](#assettrack)
		- [Create a Basic Security Plan](#secplan)
		- [Create a Basic Security Strategy](#secstrat)
	- [Corp/Enterprise Environment](#org)
		- [Create an Asset Inventory](#assetinventory)
		- [Track all my Assets](#assettrack)
		- [Categorize All Assets/Define Asset Groups](#assetcategorize)
		- [Create an Asset Lifecycle for each](#assetlifecycle)
		- [Create a Basic Security Plan](#secplan)
		- [Create a Basic Security Strategy](#secstrat)
		- [Implement some Basic Security Plan](#secplanimp)
		- [Create a Basic Security Policy](#secpol)
		- [Create a Security Awareness Program For My Org](#secaware)
		- [Create a Security Baseline For My Environment](#secbaseline)
		- [Measure an Organization's Baseline Security Posture](#secmeasure)
		- [Create a Running Tracker of My Org's Security](#secbaselinetracker)
		- [Identify Means of Improving My Organization's Baseline Security Posture](#secbaselineimprove)
		- [Implement a Vulnerability Management Program Within My Organization](#vulnmgmt)
		- [Control Means of Software Execution on Org Owned Devices](#softexec)
		- [Mitigate Phishing at Scale](#phishscale)
- [Specific Technical Defenses](#techdef)
		- [101 Level Stuff/Concepts](#101def)
			- [Access Controls](#acls)
			- [Application Execution Control](#appexeccontrol)
			- [Application Monitoring & Logging](#appmonlog)
			- [Firewalls](#firewalls)
			- [Malicious Devices](#maldevice)
			- [System Monitoring & Logging](#sysmonlog)
		- [Blue Team Tactics & Strategies](#antired)
			- []()
		- [Attack Surface Analysis & Reduction](#asa)
			- []()
		- [Linux](#linux)
			- []()
		- [macOS](#macos)
			- []()
		- [Windows](#windows)
			- [Impement Application Execution Control](#appexecwin)
			- []()
			- []()
			- []()
			- []()
		- [Databases](#dbsec)
		- [Networks](#networks)
			- [SSH](#ssh)
		- [Mitigate Phishing Attacks](#phishing)
		- [Mitigate Ransomware Attacks](#ransomware)
		- [For Journalists](#journalists)
		- [For Individuals Leaking Sensitive Information](#leaks)
		- []()
- [General Hardening/Securing](#hardening)
	- [101](#101hard)
	- [Hardening Cloud Services/SaaS](#cloudservices)
	- [Linux](#hardlin)
	- [Hardening macOS](#hardmacos)
	- [Hardening Windows](#hardwin)
	- [Hardening Web Applications](#hardweb)
- []()
------------------------------------------------------------------------------------------------------------------------------

* **To-Do**
	* User Awareness training
	* Objective-See Tools
	* Cred defense
	* SPA 
	* Ransomware
	* Fix ToC more.


------------------------------------------------------------------------------------------------------------------------------
### <a name="101basics"></a> 101/Basics
* **101**
	* [Center for Internet Security](https://www.cisecurity.org/)
		* [CIS Top 20 Controls](https://www.cisecurity.org/controls/cis-controls-list/)
		* [CIS Benchmark Guides](https://www.cisecurity.org/cis-benchmarks/)
		* [AuditScripts - CIS Critical Security Controls](https://www.auditscripts.com/free-resources/critical-security-controls/)












































------------------------------------------------------------------------------------------------------------------------------
### <a name="personal"></a> I Want to...(Personal)
* **Create an Asset Inventory**<a name="assetinventoryp"></a>
* **Track all my Assets**<a name="assettrackp"></a>
* **Create a Basic Security Plan**<a name="secplanp"></a>
* **Create a Basic Security Strategy**<a name="secstratp"></a>














































------------------------------------------------------------------------------------------------------------------------------
### <a name="org"></a> I Want to...(Enterprise/Organization)
* **Create an Asset Inventory**<a name="assetinventorye"></a>
* **Categorize All Assets/Define Asset Groups**<a name="assetcategorize"></a>
* **Track all my Assets**<a name="assettracke"></a>
* **Create an Asset Lifecycle For Each**<a name="assetlifecycle"></a>
* **Create a Basic Security Plan**<a name="secplane"></a>
* **Create a Basic Security Strategy**<a name="secstrate"></a>
* **Create a Basic Security Policy**<a name="secpol"></a>
* **Create a Security Awareness Program For My Org**<a name="secaware"></a>
* **Create a Security Baseline For My Environment**<a name="secbaseline"></a>
	* **Tech/User-Profiling**
		* **Articles/Blogposts/Writeups**
			* [Browser fingerprints for a more secure web - Julien Sobrier & Ping Yan(OWASP AppSecCali2019)](https://www.youtube.com/watch?v=P_nYYsaVi1w&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=30&t=0s)
			* [Stealthier Attacks and Smarter Defending with TLS Fingerprinting - Lee Brotherston(SecTor2015)](http://2015.video.sector.ca/video/144175700)
				* [Slides from Derbycon for the same talk](https://www.slideshare.net/LeeBrotherston/tls-fingerprinting-stealthier-attacking-smarter-defending-derbycon)
			* [Moloch + Suricata + JA3 - Anton](https://haveyousecured.blogspot.com/2018/10/moloch-suricata-ja3.html)
				* Inspired by the awesome Derbycon talk by John Althouse I wanted to give JA3 a try. After some Googling around the easiest way seemed like installing Moloch which has JA3 support baked in. This post is just a brief overview how to set this up and start exploring JA3 hashes. As a bonus, I also configured Suricata support for Moloch.
		* **Talks/Presentations/Videos**
			* [Baselining Behavior Tradecraft through Simulations - Dave Kennedy(WWHF19)](https://www.youtube.com/watch?v=DgxZ8ssuI_o)
				* With the adoption of endpoint detection and response tools as well as a higher focus on behavior detection within organizations, when simulating an adversary it's important to understand the systems you are targeting. This talk will focus on the next evolution of red teaming and how defeating defenders will take more work and effort. This is a good thing! It's also proof that working together (red and blue) collectively, we can make our security programs more robust in defending against attacks. This talk will dive into actual simulations where defenders have caught us as well as ways that we have circumvented even some of the best detection programs out there today. Let's dive into baselining behavior and refining our tradecraft to evade detection and how we can use that to make blue better.
	* **Web Browser Extensions**
		* **Articles/Blogposts/Writeups**
			* [Finding Browser Extensions To Hunt Evil! - Brad Antoniewicz](https://umbrella.cisco.com/blog/2016/06/16/finding-browser-extensions-find-evil/)
		* **Tools**
			* [Inventory-BrowserExts - keyboardcrunch](https://github.com/keyboardcrunch/Inventory-BrowserExts)
				* This script can inventory Firefox and/or Chrome extensions for each user from a list of machines. It returns all the information back in a csv file and prints to console a breakdown of that information.
* **Measure an Organization's Baseline Security Posture**<a name="secmeasure"></a>
* **Create a Running Tracker of My Org's Security**<a name="secbaselinetracker"></a>
* **Identify Means of Improving My Organization's Baseline Security Posture**<a name="secbaselineimprove"></a>
* **Implement a Vulnerability Management Program Within My Organization**<a name="vulnmgmt"></a>
	* **101**
    	* [US-CERT VulnMGMT FAQ](https://www.us-cert.gov/cdm/capabilities/vuln)
    	* [The Five Stages of Vulnerability Management(tripwire)](https://www.tripwire.com/state-of-security/vulnerability-management/the-five-stages-of-vulnerability-management/)
    	* [Implementing a Vulnerability Management Process - SANS](https://www.sans.org/reading-room/whitepapers/threats/implementing-vulnerability-management-process-34180)
		* [CISO Mind Map and Vulnerability Management Maturity Model - SANS(2020)](https://www.sans.org/security-resources/posters/leadership/ciso-mind-map-vulnerability-management-maturity-model-205?utm_medium=Email&utm_source=Webcast+115900&utm_content=703043+Webcast+115900+poster&utm_campaign=MGT516)
    	* [Building a Model for Endpoint Security Maturity](https://www.tripwire.com/state-of-security/vulnerability-management/building-a-model-for-endpoint-security-maturity/)
	* **Articles/Blogposts/Writeups**
		* [Vulnerability Management Program Best Practices – Irfahn Khimji](https://www.tripwire.com/state-of-security/vulnerability-management/vulnerability-management-program-best-practices-part-1/)
		* [The Five Stages of Vulnerability Management - Irfahn Khimji](https://www.tripwire.com/state-of-security/vulnerability-management/the-five-stages-of-vulnerability-management/)
		* [Who Fixes That Bug? - Part One: Them! - Ryan McGeehan](https://medium.com/starting-up-security/who-fixes-that-bug-d44f9a7939f2)
			* [Part 2](https://medium.com/starting-up-security/who-fixes-that-bug-f17d48443e21)
	* **Identifying Assets**
		* **Local Networks**
			* [PowerShell: Documenting your environment by running systeminfo on all Domain-Computers - Patrick Gruenauer](https://sid-500.com/2017/08/09/powershell-documenting-your-environment-by-running-systeminfo-on-all-domain-computers/)
			* [A Faster Way to Identify High Risk Windows Assets - Scott Sutherland](https://blog.netspi.com/a-faster-way-to-identify-high-risk-windows-assets/)
				* "In this blog I took a quick look at how common Active Directory mining techniques used by the pentest community can also be used by the blue teams to reduce the time it takes to identify high risk Windows systems in their environments."
		* **Cloud**
			* [Lyft Cartography: Automating Security Visibility and Democratization - Sacha Faust(BSidesSF2019)](https://www.youtube.com/watch?v=ZukUmZSKSek)
				* Lyft Security Intelligence team mission is to "Empower the company to make informed and automated security decisions." To achieve our mission, we invested in our cartography capabilities that aim at keeping track of our assets but most importantly, the relationship and interaction between them. The talk provides insight on an intelligence service solution implemented by Lyft Security Intelligence team to tackle knowledge consolidation and improve decision making. Attendees of this session will be introduced to the platform we implemented along with a broad set of scenarios that allow us to burndown security debt, detect assumptions drift, and enable teams to explore their service and environment. Furthermore, Lyft will release the platform to the open source community as part of the conference and provide details on how it can be extended to adapt to each need.
			* [Overcoming the old ways of working with DevSecOps - Culture, Data, Graph, and Query - Erkang Zheng(2019)](https://www.slideshare.net/ErkangZheng/overcoming-the-old-ways-of-working-with-devsecops-culture-data-graph-and-query)
	* **Measuring Maturity**
		* Vulnerability Management Maturity Models – Trip Wire: https://traviswhitney.com/2016/05/02/vulnerability-management-maturity-models-trip-wire/
		* Capability Maturity Model(Wikipedia): https://en.wikipedia.org/wiki/Capability_Maturity_Model
	* **Nessus**
		* [Nessus v2 xml report format - Alex Leonov](https://avleonov.com/2016/08/02/nessus-v2-xml-report-format/)
		* [Parsing Nessus v2 XML reports with python - Alex Leonov](https://avleonov.com/2017/01/25/parsing-nessus-v2-xml-reports-with-python/)
		* [Read .nessus file into Excel (with Power Query) - Johan Moritz](https://www.verifyit.nl/wp/?p=175591)
		* [Nessus v2 File Format - Tenable](https://static.tenable.com/documentation/nessus_v2_file_format.pdf)
		* [Have you configured Nessus to betray you? - ShorebreakSecurity](https://www.shorebreaksecurity.com/blog/have-you-configured-nessus-to-betray-you/)
			* Stealing Nessus Auth creds through fake auth
	* **Talks & Presentations**
    	* [Securing Vendor Webapps - A Vulnerability Assessment on HELK - IppSec](https://www.youtube.com/watch?v=2OWtEymBQfA)
    		* IppSec gives his methodology for performing vulnerability assesments against web applications. Good for understanding mindset, process, and workflow.
		* [SANS Webcast: Beyond Scanning Delivering Impact Driven Vulnerability Assessments - Matthew Toussain](https://www.youtube.com/watch?v=-ObkJ03UcN0)
		* [Practical Approach to Automate the Discovery & Eradication of Open-Source Software Vulnerabilitie - Aladdin Almubayed](https://www.youtube.com/watch?v=ks9J0uZGMh0&list=PLH15HpR5qRsWrfkjwFSI256x1u2Zy49VI&index=1)
			* Over the last decade, there has been steady growth in the adoption of open-source components in modern web applications. Although this is generally a good trend for the industry, there are potential risks stemming from this practice that requires careful attention. In this talk, we will describe a simple but pragmatic approach to identifying and eliminating open-source vulnerabilities in Netflix applications at scale.
		* [Network gravity: Exploiring a enterprise network - Casey Martin(BSides Tampa2020)](https://www.irongeek.com/i.php?page=videos/bsidestampa2020/track-d-01-network-gravity-exploiring-a-enterprise-network-casey-martin)
			*  Enterprise networks are often complex, hard to understand, and worst of all - undocumented. Few organizations have network diagrams and asset management systems and even fewer organizations have those that are effective and up to date. Leveraging an organization's SIEM or logging solution, network diagrams and asset inventories can be extrapolated from this data through the 'gravity' of the network. Similar to our solar system and galaxy, even if you cannot confirm or physically see an object, you can measure the forces of gravity it exerts on the observable objects around it that we do know about. For example, unconfirmed endpoints can be enumerated by the authentication activity they register on known domain controllers. The inferred list of endpoints and their network addresses can begin to map out logical networks. The unpolished list of logical networks can be mapped against known egress points to identify physical networks and potentially identify undiscovered egress points and the technologies that exist at the egress points. As more objects are extrapolated and inferred, the more accurate the model of your enterprise network will become. Through this iterative and repeatable process, network diagrams and asset inventories can be drafted, further explored, refined, and ultimately managed. Even the weakest of observable forces can create fingerprints that security professionals can leverage to more effectively become guardians of the galaxy.
		* [We detected a severe vulnerability, why is nobody listening? An Introduction to Product Management](https://www.youtube.com/watch?v=nz9duF9JeBc&list=PL7D3STHEa66TbZwq9w3S2qWzoJeNo3YYN&index=11)
			* Have you ever wondered why one of your high-priority vulnerabilities got rejected or delayed even though you thought it was foolish of your company not to implement it in a timely fashion? You probably got slowed down or stopped by the gatekeepers to engineering resources namely product management. However, what product management entails and what the goals of product management are, is rarely explained. I lead a group of product managers in a medical software company, and it is my job to decide which projects make it into the engineering/R&D backlog and which ones are being delayed or even eliminated. I will share the decision-making process and critical questions that need to be answered by any project to make it onto the shortlist. In this presentation, I will provide a view of product management from the inside. Once everybody understands what product management is, what product managers do, why he or she does it, and what his or her decision process is, we can improve the chances of critical IT projects or vulnerability fixes to be completed on time. I believe that together we can build better and more secure products when we understand each other's motivators and goals.
		* [The Art of Vulnerability Management - Alexandra Nassar, Harshil Parikh(OWASP AppSecCali 2019)](https://www.youtube.com/watch?v=EkyY1q2-JBI&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=44)
			* To summarize, in this talk we will discuss the pain points that most organizations face in getting traction to vulnerability remediation, how we decided to tackle the challenge, the solution we built and how we drove accountability to improve metrics. We will talk about the key decisions we made that the audience can relate to and improve their own vulnerability management program. Finally, we will show templates of our Jira boards, metrics and charts that helped in measuring success of the program.
	* **Papers**
		* [Implementing a Vulnerability Management Process - Tom Palmaers(SANS2013)](https://www.sans.org/reading-room/whitepapers/threats/paper/34180)
		* [Building a VulnerabilityManagement Program: A project management approach - Wylie Shanks(2015)](https://www.sans.org/reading-room/whitepapers/projectmanagement/building-vulnerability-management-program-project-management-approach-35932)
    		* Abstract: This paper examines the critical role of project management in building a successful vulnerability management program. This paper outlines how organizational risk and regulatory compliance needs can be addressed through a "Plan-Do-Check-Act" approach to a vulnerability management program.
	* **CVSS-related**
    	* [Towards Improving CVSS - CMU SEI](https://resources.sei.cmu.edu/asset_files/WhitePaper/2018_019_001_538372.pdf)
    	* [When CVSS Fits and When it Doesn’t(NCC Group)](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/may/when-cvss-fits-and-when-it-doesnt/)
    	* [Don’t Substitute CVSS for Risk: Scoring System Inflates Importance of CVE-2017-3735](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/dont-substitute-cvss-for-risk-scoring-system-inflates-importance-of-cve-2017-3735/)
    	* [Microsoft Exploitability Index](https://www.microsoft.com/en-us/msrc/exploitability-index)
		* [Towards Improving CVSS - J.M. Spring, E. Hatleback, A. Householder, A. Manion, D. Shick - CMU](https://resources.sei.cmu.edu/asset_files/WhitePaper/2018_019_001_538372.pdf)
	* **Tools**
		* [Vuls](https://github.com/future-architect/vuls)
			* Agent-less vulnerability scanner for Linux, FreeBSD, Container Image, Running Container, WordPress, Programming language libraries, Network devices 
		* [ArcherySec](https://github.com/archerysec/archerysec)
			* Centralize Vulnerability Assessment and Management for DevSecOps Team
		* [Scumblr](https://github.com/Netflix-Skunkworks/Scumblr)
			* Web framework that allows performing periodic syncs of data sources and performing analysis on the identified results
		* [Predator](https://github.com/s0md3v/Predator)
			* Predator is a prototype web application designed to demonstrate anti-crawling, anti-automation & bot detection techniques. It can be used a honeypot, anti-crawling system or a false positive test bed for vulnerability scanners.
		* [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)
			* DefectDojo is a security program and vulnerability management tool. DefectDojo allows you to manage your application security program, maintain product and application information, schedule scans, triage vulnerabilities and push findings into defect trackers. Consolidate your findings into one source of truth with DefectDojo.

* **Control Means of Software Execution on Org Owned Devices**<a name="softexec"></a>
	* **101**
		* [Guide to Application Whitelisting - NIST Special Publication 800 - 167](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-167.pdf)
	* **Linux**
	* **macOS**
		* **Tools**
			* [Santa](https://github.com/google/santa)
				* Santa is a binary whitelisting/blacklisting system for macOS. It consists of a kernel extension that monitors for executions, a userland daemon that makes execution decisions based on the contents of a SQLite database, a GUI agent that notifies the user in case of a block decision and a command-line utility for managing the system and synchronizing the database with a server.
				* [Docs](https://github.com/google/santa/tree/master/Docs)
	* **Windows**











































------------------------------------------------------------------------------------------------------------------------------
### <a name="techdef"></a>Specific Technical Defenses
* **101 Level Stuff/Concepts**<a name="101def"></a>
* **Access Controls**<a name="acls"></a>
* **Application Execution Control**<a name="appexeccontrol"></a>
* **Application Monitoring & Logging**<a name="appmonlog"></a>
* **Firewalls**<a name="firewalls"></a>
	* **101**
	<Fixme>
	* **Implementation**
		* **Linux**
			* [OpenSnitch](https://github.com/evilsocket/opensnitch)
				* OpenSnitch is a GNU/Linux port of the Little Snitch application firewall
		* **macOS**
			* Littlesnitch
			* LuLu
		* **Windows**
			* [simplewall](https://github.com/henrypp/simplewall)
				* Simple tool to configure Windows Filtering Platform (WFP) which can configure network activity on your computer. The lightweight application is less than a megabyte, and it is compatible with Windows Vista and higher operating systems. You can download either the installer or portable version. For correct working, need administrator rights.

	* **Management**
		* [Assimilator](https://github.com/videlanicolas/assimilator)
			* The first restful API to control all firewall brands. Configure any firewall with restful API calls, no more manual rule configuration. Centralize all your firewalls into one API.
* **Malicious Devices**<a name="maldevice"></a>
* **System Monitoring & Logging**<a name="sysmonlog"></a>







































------------------------------------------------------------------------------------------------------------------------------
### <a name="btts"></a>Blue Team Tactics & Strategies
* **General Concepts**
	* **Zero-Trust Model**
		* **101**
			* [Build Security Into Your Network’s DNA: The Zero Trust Network Architecture - John Kindervag(2010)](http://www.virtualstarmedia.com/downloads/Forrester_zero_trust_DNA.pdf)
			 * [NIST SP 800-207: Zero Trust Architecture(2020)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
		* **Articles/Blogposts/Writeups**
			* [Zero trust architecture design principles - UK NSC](https://github.com/ukncsc/zero-trust-architecture/)
				* [Blogpost](https://www.ncsc.gov.uk/blog-post/zero-trust-architecture-design-principles)
				* Principles to help you design and deploy a zero trust architecture
			* [Exploring The Zero Trust Model - securethelogs.com(2019)](https://securethelogs.com/2019/06/25/exploring-the-zero-trust-model/)
			* [Exploring The Zero Trust Model - securethelogs(2019``)](https://securethelogs.com/2019/06/25/exploring-the-zero-trust-model/)
			* [Awesome Zero trust](https://github.com/pomerium/awesome-zero-trust/blob/master/README.md)
		* **Papers**
			* Google BeyondCorp Series
				1. [BeyondCorp: A New Approach to Enterprise Security - Rory Ward, Betsy Beyer(2014)](https://research.google.com/pubs/pub43231.html)
				2. [BeyondCorp: Design to Deployment at Google - Barclay Osborn, Justin McWilliams, Betsy Beyer, Max Saltonstall(2016)](https://research.google.com/pubs/pub44860.html)
				3. [BeyondCorp: The Access Proxy - Batz Spear, Betsy (Adrienne Elizabeth) Beyer, Luca Cittadini, Max Saltonstall(2016)](https://research.google.com/pubs/pub45728.html)
				4. [Migrating to BeyondCorp: Maintaining Productivity While Improving Security - Betsy (Adrienne Elizabeth) Beyer, Colin McCormick Beske, Jeff Peck, Max Saltonstall(2017)](https://research.google.com/pubs/pub46134.html)
				5. [BeyondCorp: The User Experience - Victor Manuel Escobedo, Filip Zyzniewski, Betsy (Adrienne Elizabeth) Beyer, Max Saltonstall(2017)](https://research.google.com/pubs/pub46366.html)
				6. [BeyondCorp 6: Building a Healthy Fleet(2018) - Michael Janosko, Hunter King, Betsy (Adrienne Elizabeth) Beyer, Max Saltonstall(2018)](https://ai.google/research/pubs/pub47356)
		* **Talks/Presentations/Videos**
			* [Towards Zero Trust at GitLab.com - Kathy Wang, Philippe Lafoucrière(Cloud Next '19)](https://www.youtube.com/watch?v=eDVHIfVSdIo&feature=youtu.be&list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf)
* **Articles/Blogposts/Writeups**
	* [Removing Backdoors – Powershell Empire Edition - n00py(2017)](https://www.n00py.io/2017/01/removing-backdoors-powershell-empire-edition/)
	* [Sysinternals Sysmon suspicious activity guide - blogs.technet](https://blogs.technet.microsoft.com/motiba/2017/12/07/sysinternals-sysmon-suspicious-activity-guide/)
* **Talks/Presentations/Videos**
	* [NSA TAO Chief on Disrupting Nation State Hackers - Rob Joyce(USENIX ENIGMA2016)](https://www.youtube.com/watch?v=bDJb8WOJYdA&feature=youtu.be&list=PLKb9-P1fRHxhSmCy5OaYZ5spcY8v3Pbaf)
		* From his role as the Chief of NSA's Tailored Access Operation, home of the hackers at NSA, Mr. Joyce will talk about the security practices and capabilities that most effectively frustrate people seeking to exploit networks.
	* [So you want to beat the Red Team - Cameron Moore - Bsides Philly 2016](https://www.youtube.com/watch?list=PLNhlcxQZJSm8IHSE1JzvAH2oUty_yXQHT&v=BYazrXR_DFI&index=10&app=desktop)
	* [DIY Blue Teaming - Vyrus(ShellCon2018)](https://www.youtube.com/watch?v=9i7GA4Z2vcM&list=PL7D3STHEa66TbZwq9w3S2qWzoJeNo3YYN)
		* "White hat", "black hat", "corporate", "criminal", no matter the context, "red" or offensive security practitioners tend to build their own tools in order to be successful. Weather it's to avoid paying high costs for "enterprise" level solutions, prototype new concepts, or simply "glue" solutions together that are otherwise not designed to play well with others, the accomplished attacker is also a tool smith. "What about the blue team!?" This talk aims to address just that by providing practical solutions to defender tasks that include but are not limited to: IPS/IDS, malware detection and defense, forensics, system hardening, and practical and expedient reverse engineering techniques.
	* [Using an Expanded Cyber Kill Chain Model to Increase Attack Resiliency - Sean Malone - BHUSA16](https://www.youtube.com/watch?v=1Dz12M7u-S8)
		* We'll review what actions are taken in each phase, and what's necessary for the adversary to move from one phase to the next. We'll discuss multiple types of controls that you can implement today in your enterprise to frustrate the adversary's plan at each stage, to avoid needing to declare "game over" just because an adversary has gained access to the internal network. The primary limiting factor of the traditional Cyber Kill Chain is that it ends with Stage 7: Actions on Objectives, conveying that once the adversary reaches this stage and has access to a system on the internal network, the defending victim has already lost. In reality, there should be multiple layers of security zones on the internal network, to protect the most critical assets. The adversary often has to move through numerous additional phases in order to access and manipulate specific systems to achieve his objective. By increasing the time and effort required to move through these stages, we decrease the likelihood of the adversary causing material damage to the enterprise. 
		* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Malone-Using-An-Expanded-Cyber-Kill-Chain-Model-To-Increase-Attack-Resiliency.pdf)
	* [Finding a Domain's Worth of Malware - Jeff McJunkin(WWHF19)](https://www.youtube.com/watch?v=DgxZ8ssuI_o)
		* Are you tired of demonstrations of products that take months or years to get effective data from? How many products have you seen half-implemented (but fully paid for!) that didn’t ever deliver any real value to your organization? Here, I’ll discuss multiple free products that you can use next week to find evil inside your organization. Some techniques will find less advanced adversaries, and some will trip up even some of the most advanced ones - but they’ll all deliver value in less than a week of implementation, and I’ll discuss how you can integrate them and find the malware you already have in your environment. “Assume breach”...then find it!
* **Tools**
	* [NorkNork - Tool for identifying Empire persistence payloads](https://github.com/n00py/NorkNork)



















































------------------------------------------------------------------------------------------------------------------------------
### <a name="asa"></a>Attack Surface Analysis & Reduction
* **Monitoring**
	* **Tools**
		* [Intrigue-core](https://github.com/intrigueio/intrigue-core)
			* Intrigue-core is a framework for automated attack surface discovery. 








































------------------------------------------------------------------------------------------------------------------------------
### <a name="linux"></a>Linux










































------------------------------------------------------------------------------------------------------------------------------
### <a name="macOS"></a>macOS














































------------------------------------------------------------------------------------------------------------------------------
### <a name="windows"></a>Windows
* **Impement Application Execution Control**<a name="appexecwin"></a>



































------------------------------------------------------------------------------------------------------------------------------
### <a name="dbsec"></a> Databases(SQL/NoSQL)
* **Specific**
	* **Mongo**
		* [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)














------------------------------------------------------------------------------------------------------------------------------
### <a name="networks"></a>Computer Networks
* **General**<a name="netgen"></a>
	* **Talks & Presentations**
		* [Defending the Enterprise Against Network Infrastructure Attacks  - Paul Coggin - Troopers15](https://www.youtube.com/watch?v=K0X3RDf5XK8)
* **ACLs**<a name="acl"></a>
	* **Tools**
		* [Capirca](https://github.com/google/capirca)
			* Capirca is a tool designed to utilize common definitions of networks, services and high-level policy files to facilitate the development and manipulation of network access control lists (ACLs) for various platforms. It was developed by Google for internal use, and is now open source.
* **Single Packet Authorization**<a name="spa"></a>
	* **Articles/Blogposts/Writeups**
	* **Papers**
	* **Tools**
		* [DrawBridge](https://github.com/landhb/DrawBridge)
			* A layer 4 Single Packet Authentication (SPA) Module, used to conceal TCP ports on public facing machines and add an extra layer of security.
* **SSH**<a name="ssh"></a>
	* **Articles/Blogposts/Writeups**
		* [Scalable and secure access with SSH - Facebook](https://engineering.fb.com/production-engineering/scalable-and-secure-access-with-ssh/)
	* **Documents**
		* [Mozilla OpenSSH](https://infosec.mozilla.org/guidelines/openssh)
			* The goal of this document is to help operational teams with the configuration of OpenSSH server and client. All Mozilla sites and deployment should follow the recommendations below. The Enterprise Information Security (Infosec) team maintains this document as a reference guide.
		* [CERT-NZ SSH Hardening](https://github.com/certnz/ssh_hardening)
			* CERT NZ documentation for hardening SSH server and client configuration, and using hardware tokens to protect private keys
	* **Tools**
		* [ssh-audit](https://github.com/arthepsy/ssh-audit)
			* SSH server auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)











































------------------------------------------------------------------------------------------------------------------------------
### <a name="naphishing"></a>Mitigate Phishing Attacks
* **101**
	* See 'Phishing.md'
* **Articles/Blogposts/Writeups**
	* [Blocking Spam and Phishing on a Budget - Reid Huyssen](https://blog.sublimesecurity.com/blocking-spam-and-phishing-on-a-budget/)
	* [Catching phishing before they catch you](https://blog.0day.rocks/catching-phishing-using-certstream-97177f0d499a)
	* [Tracking Newly Registered Domains - SANS](https://isc.sans.edu/forums/diary/Tracking+Newly+Registered+Domains/23127/)
	* [When corporate communications look like a phish - William Tsing](https://blog.malwarebytes.com/business-2/2019/09/when-corporate-communications-look-like-a-phish/)
* **Tools**
	* [SwordPhish](https://github.com/Schillings/SwordPhish)
		* SwordPhish is a very simple but effective button that sits within the users Outlook toolbar. One click and the suspicious e-mail is instantly reported to your designated recipient (i.e your internal security team, or SoC) and contains all metadata required for investigation.
	* [Mercure](https://github.com/synhack/mercure)
		* Mercure is a tool for security managers who want to teach their colleagues about phishing.
	* [PPRT](https://github.com/MSAdministrator/PPRT)
		* This module is used to report phishing URLs to their WHOIS/RDAP abuse contact information.
	* [PhishingKitHunter](https://github.com/t4d/PhishingKitHunter)
		* PhishingKitHunter (or PKHunter) is a tool made for identifying phishing kits URLs used in phishing campains targeting your customers and using some of your own website files (as CSS, JS, ...). This tool - write in Python 3 - is based on the analysis of referer's URL which GET particular files on the legitimate website (as some style content) or redirect user after the phishing session. Log files (should) contains the referer URL where the user come from and where the phishing kit is deployed. PhishingKitHunter parse your logs file to identify particular and non-legitimate referers trying to get legitimate pages based on regular expressions you put into PhishingKitHunter's config file.
	* [Hunting-Newly-Registered-Domains](https://github.com/gfek/Hunting-New-Registered-Domains)
		* The hnrd.py is a python utility for finding and analysing potential phishing domains used in phishing campaigns targeting your customers. This utility is written in python (2.7 and 3) and is based on the analysis of the features below by consuming a free daily list provided by the Whoisds site.
	* [SwiftFilter](https://github.com/SwiftOnSecurity/SwiftFilter)
		* Exchange Transport rules using text matching and Regular Expressions to detect and enable response to basic phishing. Designed to augment EOP in Office 365.














































------------------------------------------------------------------------------------------------------------------------------
### <a name="ransomware"></a>Mitigate Ransomware Attacks
* **Tools**
	* [Decryptonite](https://github.com/DecryptoniteTeam/Decryptonite)
		* Decryptonite is a tool that uses heuristics and behavioural analysis to monitor for and stop ransomware.










































<<<<<<< HEAD
## Table of Contents
- [Defense & Hardening](#dfh)
	- [Access Control](#acl)
	- [AWS](#aws)
	-[Blue Team Tactics & Strategies](#antired)
	- [Application Whitelisting](#whitelist)
	- [Attack Surface Analysis/Reduction](#asa)
	- [General Hardening](#hardening)
	- [Google-related](#google)
	- [Journalist](#journalist)
	- [Leaks](#leaks)
	- [Linux/Unix](#linux)
	- [Malicious USBs](#malusb)
	-[Microsoft Azure](#azure)
	- [Network](#network)
	- [OS x](#osx)
	- [Phishing](#phishing)
	- [Ransomware](#)
	- [User Awareness training](#)
- [Windows](#windows)
	- [Active Directory](#active)
- [Vulnerability Management](#vulnmgmt)



------------------------------------------------------------------------------------------------------------------------------
### <a name="journalists"></a>For Journalists
	* [Information Security For Journalist book - Centre for Investigative Journalism](http://files.gendo.nl/Books/InfoSec_for_Journalists_V1.1.pdf)












































------------------------------------------------------------------------------------------------------------------------------
### <a name="leaks"></a>For Individuals Leaking Sensitive Information
* **Performing**
	* **Tools**	
* **Preventing**
	* **Talks/Presentations/Videos**
		* [You're Leaking Trade Secrets - Defcon22 Michael Schrenk](https://www.youtube.com/watch?v=JTd5TL6_zgY)
			* Networks don't need to be hacked for information to be compromised. This is particularly true for organizations that are trying to keep trade secrets. While we hear a lot about personal privacy, little is said in regard to organizational privacy. Organizations, in fact, leak information at a much greater rate than individuals, and usually do so with little fanfare. There are greater consequences for organizations when information is leaked because the secrets often fall into the hands of competitors. This talk uses a variety of real world examples to show how trade secrets are leaked online, and how organizational privacy is compromised by seemingly innocent use of The Internet.
	* **Tools**	
		* [AIL framework - Analysis Information Leak framework](https://github.com/CIRCL/AIL-framework)
			* AIL is a modular framework to analyse potential information leaks from unstructured data sources like pastes from Pastebin or similar services or unstructured data streams. AIL framework is flexible and can be extended to support other functionalities to mine sensitive information.
		* [git-secrets](https://github.com/awslabs/git-secrets)
			* Prevents you from committing passwords and other sensitive information to a git repository.
		* [keynuker](https://github.com/tleyden/keynuker)
			* KeyNuker scans public activity across all Github users in your Github organization(s) and proactively deletes any AWS keys that are accidentally leaked. It gets the list of AWS keys to scan by directly connecting to the AWS API.











































------------------------------------------------------------------------------------------------------------------------------
### <a name="harden"></a>General Hardening
* **101**
* **Hardening Cloud Services/SaaS**<a name="cloudservices"></a>
	* **Microsoft Azure** <a name="azure"></a> 
		* [Manage emergency-access administrative accounts in Azure AD - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-emergency-access)
		* [Securing privileged access for hybrid and cloud deployments in Azure AD - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-admin-roles-secure)
		* [How to require two-step verification for a user - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates)
		* [What is conditional access in Azure Active Directory? - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview)
		* [Detecting Kerberoasting activity using Azure Security Center - Moti Bani](https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/)
	* **G-Suite**
		* [Securing G Suite - Megan Roddie](https://blog.reconinfosec.com/securing-g-suite/)
	* **Gmail**
		* [Adding a security key to Gmail - techsolidarity.org](https://techsolidarity.org/resources/security_key_gmail.htm)
			* This guide is designed for regular humans. It will walk you through the steps of effectively protecting your Gmail account with a security key, without explaining in detail the reasons for each step.
* **Hardening Linux**<a name="hardlin"></a>
		* [Linux workstation security checklist](https://github.com/lfit/itpol/blob/master/linux-workstation-security.md)
		* [systemd service sandboxing and security hardening 101 - Daniel Aleksanderen](https://www.ctrl.blog/entry/systemd-service-hardening.html)
	* [LUNAR](https://github.com/lateralblast/lunar)
		* "This scripts generates a scored audit report of a Unix host's security. It is based on the CIS and other frameworks. Where possible there are references to the CIS and other benchmarks in the code documentation."
	* [Filenames and Pathnames in Shell: How to do it Correctly](https://www.dwheeler.com/essays/filenames-in-shell.html)
	* [Monit](https://mmonit.com/monit/)
		* Monit is a small Open Source utility for managing and monitoring Unix systems. Monit conducts automatic maintenance and repair and can execute meaningful causal actions in error situations.
	* [Red Hat Enterprise Linux 6 Security Guide](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/pdf/Security_Guide/Red_Hat_Enterprise_Linux-6-Security_Guide-en-US.pdf)
* **Hardening macOS**<a name="hardmacos"></a>
	* **General**
		* [macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
			*  A practical guide to securing macOS.
		* [Apple Platform Security Guide(Spring2020)](https://manuals.info.apple.com/MANUALS/1000/MA1902/en_US/apple-platform-security-guide.pdf)
	* **Talks/Presentations/Videos**
		* [Behind the scenes of iOS and Mac Security - Ivan Krstić(BHUSA 19)](https://www.youtube.com/watch?v=3byNNUReyvE)
			* The Find My feature in iOS 13 and macOS Catalina enables users to receive help from other nearby Apple devices in finding their lost Macs, while rigorously protecting the privacy of all participants. We will discuss our efficient elliptic curve key diversification system that derives short non-linkable public keys from a user’s keypair, and allows users to find their offline devices without divulging sensitive information to Apple.
		* [OS X Hardening: Securing a Large Global Mac Fleet - Greg Castle](https://www.usenix.org/conference/lisa13/os-x-hardening-securing-large-global-mac-fleet)

	* **Firewall**
		* [LuLu](https://github.com/objective-see/LuLu)
			* LuLu is the free open-source macOS firewall that aims to block unauthorized (outgoing) network traffic
	* **Tools**
		* [netman](https://github.com/iadgov/netman)
			* A userland network manager with monitoring and limiting capabilities for macOS.
		* [netfil](https://github.com/iadgov/netfil)
			* A kernel network manager with monitoring and limiting capabilities for macOS.
		* [OverSight](https://objective-see.com/products/oversight.html)
			* OverSight monitors a mac's mic and webcam, alerting the user when the internal mic is activated, or whenever a process accesses the webcam.

* **Hardening Windows**<a name="hardwin"></a>
<fixme>
	* **101**
	* **Guides**
		* [Windows 10 Hardening Checklist](https://github.com/0x6d69636b/windows_hardening)
		* [Windows 10 Security Checklist Starter Kit - itprotoday](https://www.itprotoday.com/industry-perspectives/windows-10-security-checklist-starter-kit)
		* [ERNW Repository of Hardening Guides](https://github.com/ernw/hardening)
			* This repository contains various hardening guides compiled by ERNW for various purposes. Most of those guides strive to provide a baseline level of hardening and may lack certain hardening options which could increase the security posture even more (but may have impact on operations or required operational effort).
		* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening/blob/master/README.md)
	* **Accounts & Credentials**
		* **General**
			* [MS Security Advisory 2871997](https://technet.microsoft.com/library/security/2871997)
				* Update to Improve Credentials Protection and Management
			* [Microsoft Security Advisory: Update to improve credentials protection and management: May 13, 2014 - support.ms](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a)
				* Disable WDigest storing credentials in memory
			* [Credentials Protection and Management - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
			* [Configuring Additional LSA Protection - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
			* [KB2871997 and Wdigest – Part 1](https://blogs.technet.microsoft.com/kfalde/2014/11/01/kb2871997-and-wdigest-part-1/)
			* [Poking Around With 2 lsass Protection Options - Cedric Owens](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)
			* [Configuring Additional LSA Protection - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
		* **Lockout**
			* [Account lockout duration - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration)
		* **Usage of**
			* [Blocking Remote Use of Local Accounts](https://blogs.technet.microsoft.com/secguide/2014/09/02/blocking-remote-use-of-local-accounts/)
		* **Tools**
			* [Invoke-HoneyCreds - Ben0xA](https://github.com/Ben0xA/PowerShellDefense)
				* Use Invoke-HoneyCreds to distribute fake cred throughout environment as "legit" service account and monitor for use of creds
			* [The CredDefense Toolkit - BlackHills](https://www.blackhillsinfosec.com/the-creddefense-toolkit/)
				* Credential and Red Teaming Defense for Windows Environments
		* **Credential/Device Guard**
			* [Overview of Device Guard in Windows Server 2016](https://blogs.technet.microsoft.com/datacentersecurity/2016/09/20/overview-of-device-guard-in-windows-server-2016/)
			* [Protect derived domain credentials with Windows Defender Credential Guard - docs.ms](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)
			* [Windows Defender Device Guard deployment guide - docs ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/device-guard-deployment-guide)
			* [Windows Defender Credential Guard: Requirements - docs.ms](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard-requirements)
			* [Windows 10 Device Guard and Credential Guard Demystified - blogs.technet](https://blogs.technet.microsoft.com/ash/2016/03/02/windows-10-device-guard-and-credential-guard-demystified/)
			* [Manage Windows Defender Credential Guard - docs.ms](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard-manage)
			* [Busy Admin’s Guide to Device Guard and Credential Guard - adaptiva](https://insights.adaptiva.com/2017/busy-admins-guide-device-guard-credential-guard/)
			* [Protect derived domain credentials with Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)
			* [Using a hypervisor to secure your desktop – Credential Guard in Windows 10 - blogs.msdn](https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/10/26/using-a-hypervisor-to-secure-your-desktop-credential-guard-in-windows-10/)
			* [Credential Guard lab companion - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/05/15/credential-guard-lab-companion/)
			* [DeviceGuardBypassMitigationRules](https://github.com/mattifestation/DeviceGuardBypassMitigationRules)
				* A reference Device Guard code integrity policy consisting of FilePublisher deny rules for published Device Guard configuration bypasses.
			* [Credential Guard - Say Good Bye to PtH/T (Pass The Hash/Ticket) Attacks - JunaidJan(social.technet.ms)](https://social.technet.microsoft.com/wiki/contents/articles/38015.credential-guard-say-good-bye-to-ptht-pass-the-hashticket-attacks.aspx)
			* [Verification of Windows New Security Features – LSA Protection Mode and Credential Guard - JPCERT](https://blogs.jpcert.or.jp/en/2016/10/verification-of-ad9d.html)
		* **Defeating Mimikatz**
			* [Preventing Mimikatz Attacks - Panagiotis Gkatziroulis](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)
		* **Golden/Silver Tickets**
			* [Defending against mimikatz](https://jimshaver.net/2016/02/14/defending-against-mimikatz/)
			* [Kerberos Golden Ticket: Mitigating pass the ticket on Active Directory](http://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
			* [Mitigating Kerberos Golden Tickets:](http://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
			* [Protection from Kerberos Golden Ticket: Mitigating pass the ticket on Active Directory CERT-EU 2014](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
			* [ Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory](https://adsecurity.org/?p=1515)
			* [Using SCOM to Detect Golden Tickets](https://blogs.technet.microsoft.com/nathangau/2017/03/08/using-scom-to-detect-golden-tickets/)
		* **Pass the Hash**
			* [Mitigating Pass-the-Hash Attacks and other credential Theft-version2](http://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf)
				* Official MS paper.
			* [Pass-the-Hash II:  Admin’s Revenge - Skip Duckwall & Chris Campbell](https://media.blackhat.com/us-13/US-13-Duckwall-Pass-the-Hash-Slides.pdf)
				* Protecting against Pass-The-Hash and other techniques
			* [Fixing Pass the Hash and Other Problems](http://www.scriptjunkie.us/2013/06/fixing-pass-the-hash-and-other-problems/)
			* [Pass the Hash Guidance](https://github.com/iadgov/Pass-the-Hash-Guidance)
				* Configuration guidance for implementing Pass-the-Hash mitigations. iadgov
		* **Tools**
			* [OpenPasswordFilter](https://github.com/jephthai/OpenPasswordFilter)
				* An open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords.
	* **ACE & DACLs**
		* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
			* A collection of tools to enumerate and analyse Windows DACLs
	* **DLL Hijacking**
		* [Detecting DLL Hijackingon Windows](http://digital-forensics.sans.org/blog/2015/03/25/detecting-dll-hijacking-on-windows/)
	* **Windows Firewall**
			* [Windows Firewall Hook Enumeration](https://www.nccgroup.com/en/blog/2015/01/windows-firewall-hook-enumeration/)
				* We’re going to look in detail at Microsoft Windows Firewall Hook drivers from Windows 2000, XP and 2003. This functionality was leveraged by the Derusbi family of malicious code to implement port-knocking like functionality. We’re going to discuss the problem we faced, the required reverse engineering to understand how these hooks could be identified and finally how the enumeration tool was developed.
	* **Privilege Escalation**
		* [The Effectiveness of Tools in Detecting the 'Maleficent Seven' Privileges in the Windows Environment](https://www.sans.org/reading-room/whitepapers/sysadmin/effectiveness-tools-detecting-039-maleficent-seven-039-privileges-windows-environment-38220)
	* **Scripts & PowerShell**
		* **AMSI**
			* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - labofapenetrationtester](http://www.labofapenetrationtester.com/2016/09/amsi.html)
		* **Windows Defender**
	* **Services**
* **Web Applications**<a name="hardweb"></a>
	* **Password Storage**
		<fixme>https://codahale.com/how-to-safely-store-a-password/
	* **Tools**
		* [Caja](https://developers.google.com/caja/)
			*  The Caja Compiler is a tool for making third party HTML, CSS and JavaScript safe to embed in your website. It enables rich interaction between the embedding page and the embedded applications. Caja uses an object-capability security model to allow for a wide range of flexible security policies, so that your website can effectively control what embedded third party code can do with user data.
* **Web Servers**<a name="hardwebserver"></a>
	* **101**
	* **SSL/TLS**
		* [Apache and Let's Encrypt Best Practices for Security - aaronhorler.com](https://aaronhorler.com/articles/apache.html)
		* [Security/Server Side TLS - Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS)
			* The goal of this document is to help operational teams with the configuration of TLS. All Mozilla websites and deployments should follow the recommendations below. Mozilla maintains this document as a reference guide for navigating the TLS landscape, as well as a configuration generator to assist system administrators. Changes are reviewed and merged by the Mozilla Operations Security and Enterprise Information Security teams.
		* [Hardening Your Web Server’s SSL Ciphers - Hynek Schlawack(2018)](https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/)
	* **Tools**
* **WAF** <a name="waf"></a>
	* **General**
		* [Practical Approach to Detecting and Preventing Web Application Attacks over HTTP2](https://www.sans.org/reading-room/whitepapers/protocols/practical-approach-detecting-preventing-web-application-attacks-http-2-36877)
		* [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
	* **NAXSI**
		* [naxsi](https://github.com/nbs-system/naxsi)
			* NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX
		* [naxsi wiki](https://github.com/nbs-system/naxsi/wiki)
	* **ModSecurity**
		* [ModSecurity](https://www.modsecurity.org/)
		* [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)


































































