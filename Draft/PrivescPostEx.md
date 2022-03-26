# Privilege Escalation & Post-Exploitation
----------------------------------------------------------------------
## Table of Contents
- Goal of this is page is to document and list tradecraft, and techniques
- The RedTeam page will contain all info on building tools, or creating payloads
- **For OS-Specific Tactics & Resources, See Following 3 Links:**
	- [Linux Post-Exploitation & Privilege Escalation](./PrivescPostExLin.md)
	- [macOS Post-Exploitation & Privilege Escalation](./PrivescPostExmac.md)
	- [Windows Post-Exploitation & Privilege Escalation](./PrivEscPostExWin.md)
- **Following Links are Platform Agnostic and Exist on This Page**
- [Hardware-based Privilege Escalation](#hardware)
	- [Writeups](#writeups)
	- [Tools](#hwtools)
- [Post-Exploitation General](#postex)
	- [Tactics](#Tactics)
		- [101](#101)
		- [Talks & Presentations](#ttalks)
		- [Anti-Blue](#ab)
		- [Attacking Disk-Encryption](#adk)
		- [CI/CD Systems](#acicd)
		- [Citrix](#citrix)
		- [Credential Dumping through Fake Services](#creds)
		- [Collection](#collect)
		- [Electron/JS Bridges](#elecjs)
		- [ENV Variables](#envv)
		- [File-Cloning](#file-clone)
		- [File-Extensions](#file-ext)
		- [HID Device-based Attack](#hida)
		- [IDN/Homograph Abuse](#idnha)
		- [Infra-As-Code(Iaac)](#iaac)
		- [IP-Obfuscation](#ipobf)
		- [Java](#java)
		- [Lateral Movement through 3rd-Party Services](#3rdlat)
		- [Local Phishing](#localphish)
		- [Mobile-Device-Management(MDM)](#mdm)
		- [Password Managers](#pm)
		- [Pass-the-Cookie](#ptc)
		- [Payload Keying](#pk)
		- [Persistence](#ps)
		- [Person-in-the-Middle](#pitm)
		- [Printers](#printer)
		- [Point-of-Sale Machines](#pos)
		- [Proxied Execution](#proxyexec)
		- [SAP](#sap)
		- [Shadow-Bunny](#sb)
		- [Virtual-Desktop-Infrastructure(VDI)](#vdi)
		- [Zip](#zip)
	- [Handling Shells](#handling-shells)
	- [Backdooring](#backdooring)
	- [Execution](#exec)
	- [Discovery](#disco)
	- [Exfiltration](#exfil)
	- [Persistence](#persist)
	- [Miscellaneous](#misc)
- [Pivoting & Tunneling](#pivot)
	- [Articles/Blogposts/Writeups](#pivot)
	- [Tools](#ptools)
- [Secured Environment Breakouts/Escapes](#secure-env)
----------------------------------------------------------------------






------------------------------------------------------------------------------------------------------------------------
### <a name="hardware">Hardware-based Privilege Escalation</a>
- **Writeups**<a name="writeups"></a>
	- **General**
		* [Windows DMA Attacks : Gaining SYSTEM shells using a generic patch](https://sysdream.com/news/lab/2017-12-22-windows-dma-attacks-gaining-system-shells-using-a-generic-patch/)
		* [Where there's a JTAG, there's a way: Obtaining full system access via USB](https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Where-theres-a-JTAG-theres-a-way.pdf)
		* [Snagging creds from locked machines - mubix](https://malicious.link/post/2016/snagging-creds-from-locked-machines/)
		* [Bash Bunny QuickCreds – Grab Creds from Locked Machines](https://www.doyler.net/security-not-included/bash-bunny-quickcreds)
		* [PoisonTap](https://github.com/samyk/poisontap)
			* Exploits locked/password protected computers over USB, drops persistent WebSocket-based backdoor, exposes internal router, and siphons cookies using Raspberry Pi Zero & Node.js.
	- **Rowhammer**
		* [Exploiting the DRAM rowhammer bug to gain kernel privileges](https://googleprojectzero.blogspot.com/2015/03/exploiting-dram-rowhammer-bug-to-gain.html)
		* [Row hammer - Wikipedia](https://en.wikipedia.org/wiki/Row_hammer)
		* [Another Flip in the Wall of Rowhammer Defenses](https://arxiv.org/abs/1710.00551)
		* [rowhammer.js](https://github.com/IAIK/rowhammerjs)
			* Rowhammer.js - A Remote Software-Induced Fault Attack in JavaScript
		* [Rowhammer.js: A Remote Software-Induced Fault Attack in JavaScript](https://link.springer.com/chapter/10.1007/978-3-319-40667-1_15)
		* [Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors](https://www.ece.cmu.edu/~safari/pubs/kim-isca14.pdf)
			* Abstract. Memory isolation is a key property of a reliable and secure computing system — an access to one memory ad- dress should not have unintended side e ects on data stored in other addresses. However, as DRAM process technology scales down to smaller dimensions, it becomes more diffcult to prevent DRAM cells from electrically interacting with each other. In this paper, we expose the vulnerability of commodity DRAM chips to disturbance errors. By reading from the same address in DRAM, we show that it is possible to corrupt data in nearby addresses. More specifically, activating the same row in DRAM corrupts data in nearby rows. We demonstrate this phenomenon on Intel and AMD systems using a malicious program that generates many DRAM accesses. We induce errors in most DRAM modules (110 out of 129) from three major DRAM manufacturers. From this we conclude that many deployed systems are likely to be at risk. We identify the root cause of disturbance errors as the repeated toggling of a DRAM row’s wordline, which stresses inter-cell coupling e ects that accelerate charge leakage from nearby rows. We provide an extensive characterization study of disturbance errors and their behavior using an FPGA-based testing plat- form. Among our key findings, we show that (i) it takes as few as 139K accesses to induce an error and (ii) up to one in every 1.7K cells is susceptible to errors. After examining var- ious potential ways of addressing the problem, we propose a low-overhead solution to prevent the errors.
- **Tools**<a name="hwtools"></a>
	* [Inception](https://github.com/carmaa/inception)
		* Inception is a physical memory manipulation and hacking tool exploiting PCI-based DMA. The tool can attack over FireWire, Thunderbolt, ExpressCard, PC Card and any other PCI/PCIe HW interfaces.
	* [PCILeech](https://github.com/ufrisk/pcileech)
		* PCILeech uses PCIe hardware devices to read and write from the target system memory. This is achieved by using DMA over PCIe. No drivers are needed on the target system.
	* [physmem](https://github.com/bazad/physmem)
		* physmem is a physical memory inspection tool and local privilege escalation targeting macOS up through 10.12.1. It exploits either CVE-2016-1825 or CVE-2016-7617 depending on the deployment target. These two vulnerabilities are nearly identical, and exploitation can be done exactly the same. They were patched in OS X El Capitan 10.11.5 and macOS Sierra 10.12.2, respectively.
	* [rowhammer-test](https://github.com/google/rowhammer-test)
		* Program for testing for the DRAM "rowhammer" problem
	* [Tools for "Another Flip in the Wall"](https://github.com/IAIK/flipfloyd)
-----------------------------------------------------------------------------------------------------------------------------------




































-----------------------------------------------------------------------------------------------------------------------------------
### <a name="postex-general">Post-Exploitation General</a>
* **Tactics**<a name="tactics"></a>
	- **101**<a name="101"></a>
		* [MITRE ATT&CK](https://attack.mitre.org/)
		* [Adversarial Post Ex - Lessons from the Pros](https://www.slideshare.net/sixdub/adversarial-post-ex-lessons-from-the-pros)
		* [Meta-Post Exploitation - Using Old, Lost, Forgotten Knowledge](https://www.blackhat.com/presentations/bh-usa-08/Smith_Ames/BH_US_08_Smith_Ames_Meta-Post_Exploitation.pdf)
		* [Operating in the Shadows - Carlos Perez - DerbyCon(2015)](https://www.youtube.com/watch?v=NXTr4bomAxk)
		* [File Server Triage on Red Team Engagements - harmj0y](http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/)
		* [Fundamentals of Post-Exploitation - Carlos Perez(2020)](https://www.trustedsec.com/wp-content/uploads/2020/01/011519-Tradecraft-1.pdf)
			* [Part 1](https://www.youtube.com/watch?v=Sm4HM0xLhvg&list=PLk-dPXV5k8SEVgW0q_pY200xscjxL_xfz&index=6)
			* [Part 2](https://www.youtube.com/watch?v=hWR2GzMQkRs&list=PLk-dPXV5k8SEVgW0q_pY200xscjxL_xfz&index=5)
			* [Part 3](https://www.youtube.com/watch?v=yh7fSLqVa9c&list=PLk-dPXV5k8SEVgW0q_pY200xscjxL_xfz&index=4)
			* [Part 4](https://www.youtube.com/watch?v=aAVkuPgkDKY&list=PLk-dPXV5k8SEVgW0q_pY200xscjxL_xfz&index=3)
	- **General Articles/Blogposts/Writeups**
		* [Combining Hadoop and MCollective for total network compromise - Security Shenanigans(2020)](https://infosecwriteups.com/combining-hadoop-and-mcollective-for-total-network-compromise-cda00429af27?gi=f831ca17a162)
	- **Talks & Presentations**<a name="ttalks"></a>
		* [Tactical Post Exploitation - Carlos Perez(Derbycon2011)](https://www.irongeek.com/i.php?page=videos/derbycon1/carlos-perez-darkoperator-tactical-post-exploitation)
			* The presentation will cover the techniques and methods used by penetration testers and hackers, how do they enumerate and perform their tasks once on a compromised system and how to detect the tell tales signs of their presence and actions. 
		* [Operating in the Shadows - Carlos Perez(Derbycon2015)](https://www.irongeek.com/i.php?page=videos/derbycon5/fix-me05-operating-in-the-shadows-carlos-perez)
			* This talk will focus detecting and avoiding detection on Windows based environments. Many defenders don't know what to look for and where to detect presence of an attacker in their network. Many pentesters do not even know what trail of cookie crumbs their action leave on a target network so as to recommend defenders how to better detect and mitigate. Also covered will be how to leave an even smaller footprint on the target network so as to minimize chance of detection on customer with proper security practices.
		* [Agentless Post-Exploitation - Raphael Mudge(2016)](https://www.youtube.com/watch?v=QbjuO5IlpBU)
			* "This presentation is a survey of techniques to conduct post-exploitation against a target without the use of malware."
		* [Living off the land: enterprise post-exploitation - Adam Reiser(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-3-19-living-off-the-land-enterprise-post-exploitation-adam-reiser)
			* You've compromised that initial server and gained a foothold in the target network: congratulations! But wait - the shadow file has no hashes but root, the ssh keys have strong passphrases, and all the interesting traffic is encrypted - there's nothing of value here! Or is there? In this talk, I will explore post-exploitation techniques for turning your compromised bastion hosts into active credential interceptors under a variety of blue team monitoring scenarios.
		* [Advancing Video Application Attacks with Video Interception, Recording, and Replay - Jason Ostrom, Arjun Sambamoorthy(2009)](https://www.youtube.com/watch?v=QcsQ6UzMJiU)
			* [Slides](https://www.defcon.org/images/defcon-17/dc-17-presentations/defcon-17-ostrom-sambamoorthy-video_application_attacks.pdf)
		* [Hacking Dumberly Redux - More Dumberer - Tim Medin(WWHF Hackin' Cast 2020)](https://www.youtube.com/watch?v=PYTm4F5AT38)
			* Tim Medin discusses the dumbest red team tricks and hacks encountered over the years. We are going to take the A out of APT (again), because so few attackers really need to use advanced techniques. We'll also discuss the simple defenses that make an attacker's life much more difficult.
	- **Anti-Blue**<a name="ab"></a>
		* [A few ideas to mess around with threat hunting, and EDR software (anti-threat hunting/anti-edr) - Hexacorn(2016)](http://www.hexacorn.com/blog/2016/12/12/a-few-ideas-to-mess-around-with-threat-hunting-and-edr-software-anti-threat-huntinganti-edr/)
		* [A few more Anti-BlueTeam ideas - Hexacorn(2018)](http://www.hexacorn.com/blog/2018/11/17/a-few-more-anti-blueteam-ideas/)
		* [Low Hanging Fruit Often Abused By Red Teams - Cedric Owens(2018)](https://medium.com/red-teaming-with-a-blue-team-mentality/low-hanging-fruit-often-abused-by-red-teams-b9a66026d89e)
	- **Attacking Disk-Encryption**<a name="adk"></a>
		* [Attacking encrypted systems with qemu and volatility - Diablohorn(2017)](https://diablohorn.com/2017/12/12/attacking-encrypted-systems-with-qemu-and-volatility/) 
		* [Attacking and Defending Full Disk Encryption - Tom Kopchak - BSides Cleveland2014](https://www.youtube.com/watch?v=-XLitSfOQ6U)
	- **CI/CD Systems**<a name="acicd"></a>
		- **General/Agnostic**
			* [10 real-world stories of how we’ve compromised CI/CD pipelines - Aaron Haymore, Iain Smart, Viktor Gazdag, Divya Natesan, Jennifer Fernick(2022)](https://research.nccgroup.com/2022/01/13/10-real-world-stories-of-how-weve-compromised-ci-cd-pipelines/)
			* [Pentesting Git source repositories - Guillaume Quéré(2020)](https://www.errno.fr/Attacking_source_repositories)
			* [“CI Knew There Would Be Bugs Here” — Exploring Continuous Integration Services as a Bug Bounty Hunter - Ed Overflow(2019)](https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/)
			* [Red Teaming DevOps - Jose Hernandez & Rod Soto(DEFCON RTV)](https://www.youtube.com/watch?v=PgzNib37g0M)
				* A set of practices in software development and information technology known as DevOps has become the leading reference for software development and IT operations that aim to provide continuous integration, delivery and software quality assurance. These practices have brought many advantages such as rapid development and delivery of software and system platforms, along with integration with cloud platforms. These new advantages come with a price and that price is the augmentation of attack surface. This presentation shows the different attack vectors in the CI/CD DevOps attack surface broken down by components and implications for those enterprises using DevOps practices. Specific attack tools along with methodology will be provided to showcase with proof of concepts how to apply read team methodology against DevOps practices.
		- **CircleCI**
			* [Shaking secrets out of CircleCI builds - insecure configuration and the threat of malicious pull requests - Nathan Davidson(2020)](https://nathandavison.com/blog/shaking-secrets-out-of-circleci-builds)
				* "In this writeup, I'm going to extend a little bit on the 'secrets in CI logs' research and go beyond looking for secrets that are already out there available in the public build logs, to detailing a way to force secrets to reveal themselves. To do this, I will be specifically focusing on the CircleCI platform, covering a potentially dangerous configuration state that can lead to secret disclosure with a little help from Github's open nature, and how to detect this as a researcher with nothing more than public read access to the Github repo and its CircleCI project's build logs."
		- **GitHub**
			* [GitDorker](https://github.com/obheda12/GitDorker)
				* A Python program to scrape secrets from GitHub through usage of a large repository of dorks.
			* [GitOops](https://github.com/ovotech/gitoops)
				* GitOops is a tool to help attackers and defenders identify lateral movement and privilege escalation paths in GitHub organizations by abusing CI/CD pipelines and GitHub access controls. It works by mapping relationships between a GitHub organization and its CI/CD jobs and environment variables.
		- **Gitlab**
			* [Abusing GitLab Runners - Nick Frichette(2020)](https://frichetten.com/blog/abusing-gitlab-runners/)
				* "While evaluating options for a small project at home I started looking into GitLab Runners to compliment my existing private GitLab instance. In this article I’d like to explain what Runners are, roughly how they work, and how you can abuse them on your next penetration test or red team engagement."
		- **Jenkins**
			* [Attacking Jenkins - msgpeek(2020)](https://msgpeek.net/blog/2020/02/attacking-jenkins/)
			* [Jenkins Attack Framework](https://github.com/Accenture/jenkins-attack-framework)
			* [Exploiting Jenkins build authorization - Asi Greenholts(2022)](https://medium.com/cider-sec/exploiting-jenkins-build-authorization-22bf72926072)
	- **Citrix**<a name="citrix"></a>
		* [Pwning A Pwned Citrix  - Acap4z(2020)](https://www.crummie5.club/pwning-a-pwned-citrix/)
	- **Credential Dumping through Fake Services**<a name="fakecreds"></a>
		* [Credential Dumping: Fake Services - Jeenali Kothari(2020)](https://www.hackingarticles.in/credential-dumping-fake-services/)
	- **Collection**<a name="collection"></a>
		- **Agnostic**
			* [localdataHog](https://github.com/ewilded/localdataHog)
				* String-based secret-searching tool (high entropy and regexes) based on truffleHog. The main difference is that whereas truffleHog was built with git repositories in mind, this tool is an attempt of applying truffleHog approach (potential secret searching leveraging both regular expressions and entropy calculation) against any data (although for it to be effective, data should not be encoded nor compressed).
			* [LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
				* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
			* [DumpsterDiver](https://github.com/securing/DumpsterDiver)
				* DumpsterDiver is a tool used to analyze big volumes of various file types in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. Additionally, it allows creating a simple search rules with basic conditions (e.g. reports only csv file including at least 10 email addresses). The main idea of this tool is to detect any potential secret leaks. You can watch it in action in the [demo video](https://vimeo.com/272944858) or [read about all its features in this article.](https://medium.com/@rzepsky/hunting-for-secrets-with-the-dumpsterdiver-93d38a9cd4c1)
			* [SharpCloud](https://github.com/chrismaddalena/SharpCloud)
				* SharpCloud is a simple C# utility for checking for the existence of credential files related to Amazon Web Services, Microsoft Azure, and Google Compute.
			* [Offensive Debugging: .NET Poops of Gold - Leron Gray(CactusCon10)](https://www.youtube.com/watch?v=O8JF_Y65vc0)
				* This talk will discuss finding the golden nuggets in .NET dumps using existing tools and provide scenarios in which exercising forensic skills can be a game-changer in offensive security operations. Additionally, this talk will demonstrate Turdshovel, a tool for quickly analyzing .NET dumps for objects of interest.
		- **Keyloggers**
			* [Notes on keyloggers - Action Dan(2021)](https://lockboxx.blogspot.com/2021/11/notes-on-keyloggers.html)
			* [HeraKeylogger](https://github.com/UndeadSec/HeraKeylogger)
				* Chrome Keylogger Extension
			* [Meltdown PoC for Reading Google Chrome Passwords](https://github.com/RealJTG/Meltdown)
		- **Slack**
			* [Slackhound](https://github.com/BojackThePillager/Slackhound)
				* Slackhound allows red and blue teams to perform fast reconnaissance on Slack workspaces/organizations to quickly search user profiles, locations, files, and other objects.
			* [SlackPirate](https://github.com/emtunc/SlackPirate)
				* Slack Enumeration and Extraction Tool - extract sensitive information from a Slack Workspace
		- **SSH-keys**
			* [Driftwood](https://github.com/trufflesecurity/driftwood)
				* Driftwood is a tool that can enable you to lookup whether a private key is used for things like TLS or as a GitHub SSH key for a user. Driftwood performs lookups with the computed public key, so the private key never leaves where you run the tool. Additionally it supports some basic password cracking for encrypted keys.
	- **Electron/JS Bridges**<a name="elecjs"></a>
		* [The JavaScript Bridge in Modern Desktop Applications - Parsia(2021)](https://parsiya.net/blog/2021-06-08-the-javascript-bridge-in-modern-desktop-applications/)
		* [electron-inject](https://github.com/tintinweb/electron-inject)
			* Inject javascript into closed source electron applications e.g. to enable developer tools for debugging.
	- **ENV Variables**<a name="envv"></a>
		* [Awesome list of secrets in environment variables](https://github.com/Puliczek/awesome-list-of-secrets-in-environment-variables)
	- **File-Cloning**<a name="file-clone"></a>
		* [MetaTwin](https://github.com/minisllc/metatwin)
			* [Blogpost](http://threatexpress.com/2017/10/metatwin-borrowing-microsoft-metadata-and-digital-signatures-to-hide-binaries/)
			* The project is designed as a file resource cloner. Metadata, including digital signature, is extracted from one file and injected into another. Note: Signatures are copied, but no longer valid.
	- **File-Extensions**<a name="file-ext"></a>
		* [Filesec.io](https://filesec.io/)
			* Stay up-to-date with the latest file extensions being used by attackers.
	- **HID Device-based Attack**<a name="hida"></a>
		* [The Human Interface Device (HID) Attack, aka USB Drive-By - CyberpointLLC](https://www.cyberpointllc.com/posts/cp-human-interface-device-attack.html)
	- **IDN/Homograph Abuse**<a name="idnha"></a>
		* [CVE-2021-42694](https://github.com/js-on/CVE-2021-42694)
			* Generate malicious files using recently published homoglyphic-attack (CVE-2021-42694)
		* [RTLO-attack](https://github.com/ctrlaltdev/RTLO-attack)
			* This is a really simple example on how to create a file with a unicode right to left ove rride character used to disguise the real extention of the file.  In this example I disguise my .sh file as a .jpg file.
			* [Blog](https://ctrlalt.dev/RTLO)
	- **Infra-As-Code(Iaac)**<a name="iaac"></a>
		- **General/Agnostic**
			* [Enterprise Offense: IT Operations [Part 1] - Post-Exploitation of Puppet and Ansible Servers - Tandy Bose](https://n0tty.github.io/2017/06/11/Enterprise-Offense-IT-Operations-Part-1/)
			* [MOSE (Master Of SErvers)](https://github.com/master-of-servers/mose)
				* MOSE is a post exploitation tool that enables security professionals with little or no experience with configuration management (CM) technologies to leverage them to compromise environments. CM tools, such as Puppet, Chef, Salt, and Ansible are used to provision systems in a uniform manner based on their function in a network. Upon successfully compromising a CM server, an attacker can use these tools to run commands on any and all systems that are in the CM server’s inventory. However, if the attacker does not have experience with these types of tools, there can be a very time-consuming learning curve. MOSE allows an operator to specify what they want to run without having to get bogged down in the details of how to write code specific to a proprietary CM tool. It also automatically incorporates the desired commands into existing code on the system, removing that burden from the user.
		- **Ansible**
		- **Chef**
			* [Cooking up shells with a compromised Chef server - Ryan Wendel(2017)](https://www.ryanwendel.com/2017/10/03/cooking-up-shells-with-a-compromised-chef-server/)
		- **Puppet**
			* [Puppet Assessment Techniques - Sebastian Funke(2020)](https://insinuator.net/2020/09/puppet-assessment-techniques/)
		- **Salt**
	- **IP-Obfuscation**<a name="ipobf"></a>
		* [IPFuscator](https://github.com/vysec/IPFuscator)
			* IPFuscation is a technique that allows for IP addresses to be represented in hexadecimal or decimal instead of the decimal encoding we are used to. IPFuscator allows us to easily convert to these alternative formats that are interpreted in the same way.
			* [Blogpost](https://vincentyiu.co.uk/ipfuscation/)
		* [Cuteit](https://github.com/D4Vinci/Cuteit)
			* A simple python tool to help you to social engineer, bypass whitelisting firewalls, potentially break regex rules for command line logging looking for IP addresses and obfuscate cleartext strings to C2 locations within the payload.
	- **Java**<a name="java"></a>
		* [Tool Release – shouganaiyo-loader: A Tool to Force JVM Attaches - Jeff Dileo(2021)](https://research.nccgroup.com/2021/12/29/tool-release-shouganaiyo-loader-a-tool-to-force-jvm-attaches/)
		* [shouganaiyo-loader: Forced Entry for Java Agents](https://github.com/nccgroup/shouganaiyo-loader)
			* shouganaiyo-loader is a cross-platform Frida-based Node.js command-line tool that forces Java processes to load a Java/JVMTI agent regardless of whether or not the JVM has disabled the agent attach API. 
	- **Lateral Movement through 3rd-Party Services**<a name="3rdlat"></a>
		* [Out of The Box - Lateral Movements - Kevin Dick, Steven F(2019)](https://threat.tevora.com/lateral-movement-whenhttps-threat-tevora-com-p-765ee696-b24a-4a53-aee6-6fd30ff342e8-powershell-is-locked-down/)
		* **Browser Pivoting**
			* [Browser Pivot for Chrome - ijustwannaredteam](https://ijustwannared.team/2019/03/11/browser-pivot-for-chrome/)
				* Today’s post is about Browser Pivoting with Chrome. For anyone unaware of Browser Pivoting, it’s a technique which essentially leverages an exploited system to gain access to the browser’s authenticated sessions. This is not a new technique, in fact, Raphael Mudge wrote about it in 2013. Detailed in the linked post, the Browser Pivot module for Cobalt Strike targets IE only, and as far as I know, cannot be used against Chrome. In this post we’re trying to achieve a similar result while taking a different approach – stealing the target’s Chrome profile in real time. Just a FYI, if you have the option to use Cobalt Strike’s Browser Pivot module instead, do so, it’s much cleaner.
			* [CursedChrome](https://github.com/mandatoryprogrammer/CursedChrome)
				* Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies, allowing you to browse sites as your victims. 
			* [Post-Exploitation: Abusing Chrome's debugging feature to observe and control browsing sessions remotely - wunderwuzzi(2020)](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
	- **Local Phishing**<a name="localphish"></a>
		* [Spoofing credential dialogs on macOS, Linux and Windows - wunderwuzzi(2021)](https://embracethered.com/blog/posts/2021/spoofing-credential-dialogs/)
	- **Mobile-Device-Management(MDM)**<a name="mdm"></a>
		* [Having Fun with Google MDM Solution - Ahmad Abolhadid(2021)](https://insinuator.net/2021/01/having-fun-with-google-mdm-solution/)
		* [MobileIron MDM Contains Static Key Allowing Account Enumeration - Matt Burch(2021)](https://www.optiv.com/insights/source-zero/blog/mobileiron-mdm-contains-static-key-allowing-account-enumeration)
		* [rustyIron](https://github.com/optiv/rustyIron)
			* This tool represents a communication framework for navigating MobileIron's MDM authentication methods, allowing for account enumeration, single-factor authentication attacks, and message decryption.
	- **Password Managers**<a name="pm"></a>
		* [CyberArkTools](https://github.com/jellever/CyberArkTools)
			* Some Python tooling to for example try to decrypt CyberArk .cred credential files
		* [Breaking LastPass: Instant Unlock of the Password Vault - Oleg Afonin(2020)](https://blog.elcomsoft.com/2020/04/breaking-lastpass-instant-unlock-of-the-password-vault/)
	- **Pass-the-Cookie**<a name="ptc"></a>
		* [Pass the Cookie and Pivot to the Clouds - wunderwuzzi](https://wunderwuzzi23.github.io/blog/passthecookie.html)
			* An adversary can pivot from a compromised host to Web Applications and Internet Services by stealing authentication cookies from browsers and related processes. At the same time this technique bypasses most multi-factor authentication protocols.
	- **Payload Keying**<a name="pk"></a>
		* [Breaking Detection with X86 ISA Specific Malware - Chris Hernandez(Disobey2020](https://www.youtube.com/watch?v=mXRWpWzaON4&list=PLLvAhAn5sGfiZKg9GTUzljNmuRupA8igX&index=3)
			* Detection evasion in most enterprise networks is a problem that attackers have to deal with. In the modern enterprise network a number of defenses can intercept and block, detonate or analyze your malware/agent before it even achieves execution on a target. But what if an attacker could create malware that was supported by the target machine and not supported by the sandbox or other detection tools? The idea of keyed malware is not new; however, this talk looks at keying malware to leverage x86 Instruction Set Architecture (ISA) features supported by specific Intel and AMD CPUs, instead of from a higher-level abstraction as has been done previously with malware keyed to the operating system. In this talk, I will demonstrate and showcase how x86 instruction set architecture (ISA) specific features that allow for sandbox detection and bypass in instances where the x86 ISA version is mismatched between the target environment and the analysis environment. I will discuss and demonstrate methods for implementing ISA detection bypass techniques into the malware development lifecycle. Additionally, I will discuss the ramifications of an ever growing instruction set for the enterprise defender.
	- **Persistence**<a name="ps"></a>
		* [An Encyclpwnia of Persistence - Skip Duckwall, Will Peteroy(Derbycon2013)](https://www.irongeek.com/i.php?page=videos/derbycon3/3208-an-encyclpwnia-of-persistence-skip-duckwall-will-peteroy)
			* "Description: While I was working on a Linux boot CD for Red Team operations I started researching various persistence techniques that were out there in “the real world”. Pretty soon a couple of pages of notes became a notebook full of information. Based on public information from incident reports, AV vendors, blogs, and con talks, I started trying to categorize the various techniques to make them easier to digest. One thing that immediately jumped out was that nobody had apparently tried to do this before. With help from another former Red Teamer, Will, we were able to categorize over 20 different ways that somebody could attain persistence. Our hope is that our talk will benefit both the folks who have to defend and those who provide threat emulation by providing details about real world persistence methods."
	- **Person-in-the-Middle**<a name="pitm"></a>
		* See 'Network Attacks' page.
	- **Printers**<a name="printer"></a>
		* See 'Network Attacks' page. Or Linux Post-Ex if you've already popped one.
	- **Point-of-Sale Machines**<a name="pos"></a>
		* [Breaking Credit Card Tokenization Without Cryptanalysis - Tim MalcomVetter(Derbycon2016)](https://www.irongeek.com/i.php?page=videos/derbycon6/110-breaking-credit-card-tokenization-without-cryptanalysis-tim-malcomvetter)
			* Credit Card Tokenization is a very popular antidote to costly and time-consuming PCI regulations, but are all implementations equally secure? Early studies on tokenization focused on the cryptanalysis of the token generation process, especially when early implementations sought to create 16 digit numeric tokens to satisfy constraints in legacy commerce systems. Fast forward to 2016, most of those problems do not exist today; however, anecdotes from consulting with Fortune 500s suggest other insecure properties not involving crypto can vary and emerge in tokenization systems. This talk will dig into several sanitized examples from consulting engagements which reduce ?PCI Compliant? Credit Card Tokenization from ?silver bullet? to ?speed bump? status when big-picture security controls are missing. Specifically: abusing separation of duties by rogue partial insiders via public APIs commonly found in e-commerce applications; discovery of accidental side channels of critical information flow, such as timing analysis or response differentiation, which can be abused to reveal full PANs (primary account numbers); whether DevOps cultures could promote rogue admins abusing tokenization presentation logic implemented in JavaScript; and for good measure: some common programming defects which at best render tokenization pointless, and at worst could allow for a breach. With each example, we?ll look at potential solutions.
	- **Proxied Execution**<a name="proxyexec"></a>
		* [Running programs via Proxy & jumping on a EDR-bypass trampoline, Part 2 - Hexacorn(2017)](http://www.hexacorn.com/blog/2017/10/04/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline-part-2/)
	- **SAP**<a name="sap"></a>
		* [PowerSAP](https://github.com/airbus-seclab/powersap)
			* PowerSAP is a simple powershell re-implementation of popular & effective techniques of all public tools such as Bizploit, Metasploit auxiliary modules, or python scripts available on the Internet. This re-implementation does not contain any new or undisclosed vulnerability.
		* [RFCpwn](https://github.com/icryo/RFCpwn)
			* An SAP enumeration and exploitation toolkit using SAP RFC calls
		https://warroom.rsmus.com/sap-recon-cve-2020-6287/
		https://github.com/carlospolop/hacktricks/pull/29/commits/b003ef83d8fba4cbe941215f5a1bd07eb435ec4e?short_path=c605337#diff-c605337b642ce1648e442d4b6b69042e682b9c3448b46e0e129be4927d5405f7
	- **Shadow-Bunny**<a name="sb"></a>
		* [Beware of the Shadowbunny - Using virtual machines to persist and evade detections - wunderwuzzi(2020)](https://embracethered.com/blog/shadowbunny.html)
		* [Welcome the Shadowbunny - Johann Rehberger(BSidesSG2020)](https://www.youtube.com/watch?v=deGrbmTkRjQ)
			* [Slides](https://embracethered.com/blog/downloads/Shadowbunny_BSides_Singapore_2020.pptx)
			* In this talk we will explore usage of virtual machines for lateral movement. There are multiple reasons why you should add this technique to your red teaming knowledge-base and skill set. We also highlight how we can build better detection for catching VM misuse. A Shadowbunny is basically a virtual machine (VM) instance that is deployed by an adversary on a target host to pivot and provide persistence and at the same time evade detection. During red teaming operations the Shadowbunny technique has been used by the presenter multiple teams over the last couple of years. The VM itself does not have any security monitoring and is entirely attacker controlled.
		* [IceRat evades antivirus by running PHP on Java VM - Karsten Hahn](https://www.gdatasoftware.com/blog/icerat-evades-antivirus-by-using-jphp)
	- **Virtual-Desktop-Infrastructure(VDI)**<a name="vdi"></a>
		* [Hacking VDI, Recon and Attack Methods - Patrick Coble(Derbycon2017](https://www.irongeek.com/i.php?page=videos/derbycon7/s32-hacking-vdi-recon-and-attack-methods-patrick-coble)
			* VDI Deployments are in over 90% of all the Fortune 1000 companies and are used in almost all industry verticals, but are they secure? The goal of most VDI deployments is to centrally deliver applications and/or desktops to users internally and externally, but in many cases their basic security recommendations haven't fully deployed, allowing an attacker to gain access. This talk will review the basic design of the top two solution providers, Citrix and VMware. We will go over these solutions strengths and weaknesses and learn how to quickly identify server roles and pivot. We will also examine all the major attack points and their defensive counters. If you or if you have a client that has a VDI Deployment you don't want to miss this talk.
	* **Vulnerability Scanners**
		* [Lying in Wait: Discovering and Exploiting Weaknesses in Automated Discovery Actions - Timothy Wright, Jacob Griffith(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/2-07-lying-in-wait-discovering-and-exploiting-weaknesses-in-automated-discovery-actions-timothy-wright-jacob-griffith)
			* Many IT administration systems on the market today implement some form of automated discovery process for identifying and cataloging new devices attached to the network. These discovery services often use valid credentials to access the devices for credentialed reviews/scans to improve the accuracy of the reporting. To make matters worse, these credentials are often elevated on the network and potentially whitelisted from any deception or endpoint protection suites.In this talk, we will outline several ways to abuse these services to gain legitimate credentials for a given network. Specifically, our research focused on a couple common security and management systems, but the implications are widespread. Research and tools to be released at con to help red teams demo risk.
	- **Zip**<a name="zip"></a>
		* [Critical .zip vulnerabilities? - Zip Slip and ZipperDown - LiveOverflow(2018](https://www.youtube.com/watch?v=Ry_yb5Oipq0)
			* What is going on with .zip files. What is this new critical vulnerability that seems to affect everything? ... old is new again.
		* [evilarc](https://github.com/ptoomey3/evilarc)
			* Create tar/zip archives that can exploit directory traversal vulnerabilities
- **Things**<a name="things"></a>
	- **Handling Shells**<a name="handling-shells"></a>
		* [penelope](https://github.com/brightio/penelope)
			* Penelope is an advanced shell handler. Its main aim is to replace netcat as shell catcher during exploiting RCE vulnerabilities. It works on Linux and macOS and the only requirement is Python >= 3.6. It is a single script, it needs no installation or any 3rd party dependency and hopefully it will stay that way.
		* [Alveare](https://github.com/roccomuso/alveare)
			* Multi-client, multi-threaded reverse shell handler written in Node.js. Alveare (hive in italian) lets you listen for incoming reverse connection, list them, handle and bind the sockets. It's an easy to use tool, useful to handle reverse shells and remote processes.
- **Backdooring**<a name="backdooring"></a>
	- **Articles/Blogposts/Writeups**
		* [Hide meterpreter shellcode in executable - Emeric Nasi(2014)](http://blog.sevagas.com/?Hide-meterpreter-shellcode-in-executable)
		* [Backdooring Plugins - AverageJoe(2018)](https://www.gironsec.com/blog/2018/03/backdooring-plugins/)
		* [Backdooring Torrents - GIronSec(2019)](https://www.gironsec.com/blog/wp-content/uploads/2019/06/Backdooring-Torrents.pdf)
		* [[Backdoor 101] Backdooring PE File by Adding New Section Header - Capt Meelo(2018)](https://captmeelo.com/exploitdev/osceprep/2018/07/16/backdoor101-part1.html)
		* [Introduction to Manual Backdooring - abatchy17](https://www.exploit-db.com/docs/english/42061-introduction-to-manual-backdooring.pdf)
		* [Undetectable backdooring PE file - Haider Mahmood(2017)](https://haiderm.com/undetectable-backdooring-pe-file/)
		* [Backdooring PE File - rottenbeef(2019)](https://r0ttenbeef.github.io/backdooring-pe-file/)
		* [Distribution of malicious JAR appended to MSI files signed by third parties - Bernardo.Quintero(2019)](https://blog.virustotal.com/2019/01/distribution-of-malicious-jar-appended.html)
		* [Jar Files: Analysis and Modifications - 0xdf(2020)](https://0xdf.gitlab.io/2020/08/08/jar-files-analysis-and-modifications.html)
	- **Talks/Presentations/Videos**
	- **Tools**
		* [PympMyBinary](https://github.com/BrunoMCBraga/PympMyBinary)
			* Python tool to infect binaries(Win32/64) with shellcode.
* **Execution**<a name="exec"></a>
	* **Tools**
		* [Shellpaste](https://github.com/andrew-morris/shellpaste)
			* Tiny snippet of code that pulls ASCII shellcode from pastebin and executes it. The purpose of this is to have a minimal amount of benign code so AV doesn't freak out, then it pulls down the evil stuff. People have been doing this kind of stuff for years so I take no credit for the concept. That being said, this code (or similar code) works surprisingly often during pentests when conventional malware fails.
	* **Payloads**
		* [Staged vs Stageless Handlers - OJ Reeves(2013)](https://buffered.io/posts/staged-vs-stageless-handlers/)
		* [Staged Payloads – What Pen Testers Should Know - Raphael Mudge(2013)]
		* [Deep Dive Into Stageless Meterpreter Payloads - OJ Reeves(2015)](https://blog.rapid7.com/2015/03/25/stageless-meterpreter-payloads/)
		* [Payload Types in the Metasploit Framework - offensive-security](https://www.offensive-security.com/metasploit-unleashed/payload-types/)
- **Discovery**<a name="disco"></a>
	- **Browsers**
		- **Articles/Blogposts/Writeups**
			* [The Curious case of Firefox’s DevTools Storage - phl4nk(2020)](https://phl4nk.wordpress.com/2020/04/24/the-curious-case-of-firefoxs-devtools-storage/)
				* TL;DR – Firefox stores Dev tool console data permanently (unless manually deleted). Use the script to decompress the stored data and recover any potential goodies (mainly from devs running scripts in the console).
			* [DevToolReader](https://github.com/phl4nk/devtoolreader)
				* Parses Indexeddb files - used to extract devtools console history 
			* [Retrieving Data from Thunderbird and Firefox - VIVI(2020)](https://thevivi.net/2020/09/06/retrieving-data-from-thunderbird-and-firefox/)
			* [Cookie Crimes and the new Microsoft Edge Browser - Wunderwuzzi(2020](https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/)
			* [Post-Exploitation: Abusing Chrome's debugging feature to observe and control browsing sessions remotely - Wunderwuzzi(2020)](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
			* [Hands in the Cookie Jar: Dumping Cookies with Chromium’s Remote Debugger Port - Justin Bui(2020](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
			* [Abusing Google Chrome extension syncing for data exfiltration and C&C - Bojan(SANS 2021)](https://isc.sans.edu/forums/diary/Abusing+Google+Chrome+extension+syncing+for+data+exfiltration+and+CC/27066/)
		* **Tools**
			* [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)
				* EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible. 
			* [gowitness](https://github.com/sensepost/gowitness)
				* a golang, web screenshot utility using Chrome Headless 
			* [WitnessMe](https://github.com/byt3bl33d3r/WitnessMe)
				* Web Inventory tool, takes screenshots of webpages using Pyppeteer (headless Chrome/Chromium) and provides some extra bells & whistles to make life easier.
			* [Firepwd.py](https://github.com/lclevy/firepwd)
				* Firepwd.py, an open source tool to decrypt Mozilla protected passwords
			* [ThunderFox](https://github.com/V1V1/SharpScribbles)
				* Retrieve saved credentials from Thunderbird and Firefox.
			* [ChromeTools](https://github.com/bats3c/ChromeTools)
				* A collection of tools to abuse chrome browser
			* [firefox-cookiemonster](https://github.com/wunderwuzzi23/firefox-cookiemonster)
				* Connect to Firefox debug port and issue a Javascript command to grab cookies
			* [comfortably-run](https://github.com/mandatoryprogrammer/comfortably-run)
				* A CLI tool which can be used to inject JavaScript into arbitrary Chrome origins via the Chrome DevTools Protocol
			* [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut)
				* Interact with Chromium-based browsers' debug port to view open tabs, installed extensions, and cookies 
	* **File Discovery**
		* [localdataHog](https://github.com/ewilded/localdataHog)
			* String-based secret-searching tool (high entropy and regexes) based on truffleHog.
	* **Packet Sniffing**
		* See Network_Attacks.md
	* **Finding your external IP:**
		* Curl any of the following addresses: `ident.me, ifconfig.me or whatsmyip.akamai.com`
		* [Determine Public IP from CLI](http://askubuntu.com/questions/95910/command-for-determining-my-public-ip)
	* **Virtual Machine Detection(VM Dection)**
		* [How to determine Linux guest VM virtualization technology](https://www.cyberciti.biz/faq/linux-determine-virtualization-technology-command/)
		* **Virtualbox**
			* [VirtualBox Detection Via WQL Queries](http://waleedassar.blogspot.com/)
			* [Bypassing VirtualBox Process Hardening on Windows](https://googleprojectzero.blogspot.com/2017/08/bypassing-virtualbox-process-hardening.html)
			* [VBoxHardenedLoader](https://github.com/hfiref0x/VBoxHardenedLoader)
				* VirtualBox VM detection mitigation loader
* **Exfiltration**<a name="exfil"></a>
	* **Egress Testing**
		* [Egress Testing using PowerShell](http://www.labofapenetrationtester.com/2014/04/egress-testing-using-powershell.html)
		* [Egress Buster Reverse Shell](https://www.trustedsec.com/files/egress_buster_revshell.zip)
			* Egress Buster Reverse Shell – Brute force egress ports until one if found and execute a reverse shell(from trustedsec)
		* [Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess)
			* Egress-Assess is a tool used to test egress data detection capabilities
	* **File Transfer**
		* **Articles/Blogposts/Writeups**
			* [File transfer skills in the red team post penetration test - xax007](https://www.exploit-db.com/docs/english/46515-file-transfer-skills-in-the-red-team-post-penetration-test.pdf)
			* [(Almost) All The Ways to File Transfer - PenTest-Duck](https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65)
		* **Platform-Neutral**
			* [Updog](https://github.com/sc0tfree/updog)
				* Updog is a replacement for Python's SimpleHTTPServer. It allows uploading and downloading via HTTP/S, can set ad hoc SSL certificates and use http basic auth.
			* [ffsend](https://github.com/timvisee/ffsend)
				* Easily and securely share files and directories from the command line through a safe, private and encrypted link using a single simple command. Files are shared using the Send service and may be up to 1GB (2.5GB authenticated). Others are able to download these files with this tool, or through their web browser.
* **Persistence**<a name="persist"></a>
	* [List of low-level attacks/persistence techniques.  HIGHLY RECOMMENDED!](http://timeglider.com/timeline/5ca2daa6078caaf4)
	* [How to Remotely Control Your PC (Even When it Crashes)](https://www.howtogeek.com/56538/how-to-remotely-control-your-pc-even-when-it-crashes/)
	* **Backdooring X**
		* [Introduction to Manual Backdooring - abatchy17](http://www.abatchy.com/2017/05/introduction-to-manual-backdooring_24.html)
		* [Backdooring PE-File (with ASLR) - hansesecure.de](https://hansesecure.de/2018/06/backdooring-pe-file-with-aslr/?lang=en)
			* Simple codecave
		* [An Introduction to Backdooring Operating Systems for Fun and trolling - Defcon22](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20video%20and%20slides/DEF%20CON%2022%20Hacking%20Conference%20Presentation%20By%20Nemus%20-%20An%20Introduction%20to%20Back%20Dooring%20Operating%20Systems%20for%20Fun%20and%20Trolling%20-%20Video%20and%20Slides.m4v)
	* **Building a backdoored Binary**
		* [Pybuild](https://www.trustedsec.com/files/pybuild.zip)
			* PyBuild is a tool for automating the pyinstaller method for compiling python code into an executable. This works on Windows, Linux, and OSX (pe and elf formats)(From trustedsec)
	* **PYTHONPATH**
		* [I'm In Your $PYTHONPATH, Backdooring Your Python Programs](http://www.ikotler.org/InYourPythonPath.pdf)
		* [Pyekaboo](https://github.com/SafeBreach-Labs/pyekaboo)
			* Pyekaboo is a proof-of-concept program that is able to to hijack/hook/proxy Python module(s) thanks to $PYTHONPATH variable. It's like "DLL Search Order Hijacking" for Python.
* **Miscellaneous**<a name="misc"></a>
	* **Redis**
		* [Redis post-exploitation - Pavel Toporkov(ZeroNights18)](https://www.youtube.com/watch?v=Jmv-0PnoJ6c&feature=share)
			* We will overview the techniques of redis post-exploitation and present new ones. In the course of the talk, you will also find out what to do if a pentester or adversary has obtained access to redis.
	- **Tools to help generate payloads**
		* [How to use msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
		* [msfpc](https://github.com/g0tmi1k/mpc)
			* A quick way to generate various "basic" Meterpreter payloads via msfvenom (part of the Metasploit framework).
		* [Unicorn](https://github.com/trustedsec/unicorn)
			* Magic Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.
* **Unsorted**
	* [portia](https://github.com/SpiderLabs/portia)
		* Portia aims to automate a number of techniques commonly performed on internal network penetration tests after a low privileged account has been compromised.
	* [JVM Post-Exploitation One-Liners](https://gist.github.com/frohoff/a976928e3c1dc7c359f8)
	* [Oneliner-izer](https://github.com/csvoss/onelinerizer)
		* Convert any Python file into a single line of code which has the same functionality.
-----------------------------------------------------------------------------------------------------------------------------------

					




























		
		
		
		
		

		
		
		
		
		
		
		

-----------------------------------------------------------------------------------------------------------------------------------
### <a name="Pivoting">Pivoting & Tunneling</a>
- **Articles/Blogposts/Writeups**<a name="pivot"></a>
	* [A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/#corporate-http-proxy-as-a-way-out)
	* [Pivoting into a network using PLINK and FPipe](http://exploit.co.il/hacking/pivoting-into-a-network-using-plink-and-fpipe/)
	* [Pillage the Village Redux w/ Ed Skoudis & John Strand - SANS](https://www.youtube.com/watch?v=n2nptntIsn4)
	* [Browser Pivot for Chrome - cplsec](https://ijustwannared.team/2019/03/11/browser-pivot-for-chrome/)
	* [Browser Pivoting (Get past two-factor auth) - blog.cobalstrike](https://blog.cobaltstrike.com/2013/09/26/browser-pivoting-get-past-two-factor-auth/)
	* [Windows Domains, Pivot & Profit - Fuzzynop](http://www.fuzzysecurity.com/tutorials/25.html)
   	* Hola! In this write-up we will be looking at different ways to move laterally when compromising a Windows domain. This post is by no means exhaustive but it should cover some of the more basic techniques and thought processes.
	* [Performing port-proxying and port-forwarding on Windows - Wunderwuzzi(2020)](https://embracethered.com/blog/posts/2020/windows-port-forward/)
	* [On how to access (protected) networks - s3cur3th1ssh1t(2021)](https://s3cur3th1ssh1t.github.io/On-how-to-access-protected-networks/)
	* [Overview of network pivoting and tunneling - Alexandre Zanni(2021)](https://blog.raw.pm/en/state-of-the-art-of-network-pivoting-in-2019/)
	- **Bash**
		* [More on Using Bash's Built-in /dev/tcp File (TCP/IP)](http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip)
	- **Metasploit**
		* [Portfwd - Pivot from within meterpreter](http://www.offensive-security.com/metasploit-unleashed/Portfwd)
		* [Reverse SSL backdoor with socat and metasploit (and proxies)](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)
	- **SSH**
		* [Pivoting Ssh Reverse Tunnel Gateway](http://blog.oneiroi.co.uk/linux/pivoting-ssh-reverse-tunnel-gateway/)
		* [SSH Gymnastics and Tunneling with ProxyChains](http://magikh0e.ihtb.org/pubPapers/ssh_gymnastics_tunneling.html)
		* [SSH Cheat Sheet - pentestmonkey](http://pentestmonkey.net/cheat-sheet/ssh-cheat-sheet)
		* [proxychains-ng](https://github.com/rofl0r/proxychains-ng)
			* proxychains ng (new generation) - a preloader which hooks calls to sockets in dynamically linked programs and redirects it through one or more socks/http proxies. continuation of the unmaintained proxychains project. the sf.net page is currently not updated, use releases from github release page instead.
		* [Using sshuttle in daily work - Huiming Teo](http://teohm.com/blog/using-sshuttle-in-daily-work/)
		* [Proxyjump, the SSH option you probably never heard of - Khris Tolbert(2020)](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464)
	- **VPN**
		* [How VPN Pivoting Works (with Source Code) - cs](https://blog.cobaltstrike.com/2014/10/14/how-vpn-pivoting-works-with-source-code/)
		* [Universal TUN/TAP device driver. - kernel.org](https://www.kernel.org/pub/linux/kernel/people/marcelo/linux-2.4/Documentation/networking/tuntap.txt)
		* [Tun/Tap interface tutorial - backreference](http://backreference.org/2010/03/26/tuntap-interface-tutorial/)
		* [Responder and Layer 2 Pivots - cplsec](https://ijustwannared.team/2017/05/27/responder-and-layer-2-pivots/)
		* [simpletun](https://github.com/gregnietsky/simpletun)
			* Example program for tap driver VPN
	- **WMIC**
		* [The Grammar of WMIC](https://isc.sans.edu/diary/The+Grammar+of+WMIC/2376)
		* [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
		* [Windows Security Center: Fooling WMI Consumers](https://www.opswat.com/blog/windows-security-center-fooling-wmi-consumers)
- **Tools**<a name="ptools"></a>
	- **Multiple-Protocols**<a name="multip"></a>
		* [Socat](http://www.dest-unreach.org/socat/)
			* socat is a relay for bidirectional data transfer between two independent data channels. Each of these data channels may be a file, pipe, device (serial line etc. or a pseudo terminal), a socket (UNIX, IP4, IP6 - raw, UDP, TCP), an SSL socket, proxy CONNECT connection, a file descriptor (stdin etc.), the GNU line editor (readline), a program, or a combination of two of these.  These modes include generation of "listening" sockets, named pipes, and pseudo terminals.
			* [Examples of use](http://www.dest-unreach.org/socat/doc/socat.html#EXAMPLES)
			* [Socat Cheatsheet](http://www.blackbytes.info/2012/07/socat-cheatsheet/)
		* [XFLTReaT](https://github.com/earthquake/XFLTReaT)
			* XFLTReaT tunnelling framework
		* [gost](https://github.com/ginuerzh/gost/blob/master/README_en.md)
			* GO Simple Tunnel - a simple tunnel written in golang
	- **Discovery**
		* [nextnet](https://github.com/hdm/nextnet)
			* nextnet is a pivot point discovery tool written in Go.
	- **DNS**
		* [ThunderDNS: How it works - fbkcs.ru](https://blog.fbkcs.ru/en/traffic-at-the-end-of-the-tunnel-or-dns-in-pentest/)
	- **HTTP/HTTPS**
		* [SharpSocks](https://github.com/nettitude/SharpSocks)
			* Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
		* [Chisel](https://github.com/jpillora/chisel)
			* Chisel is a fast TCP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network. 
		* [SharpChisel](https://github.com/shantanu561993/SharpChisel)
			* C# Wrapper of Chisel from https://github.com/jpillora/chisel
		* [Crowbar](https://github.com/q3k/crowbar)
			* Crowbar is an EXPERIMENTAL tool that allows you to establish a secure circuit with your existing encrypting TCP endpoints (an OpenVPN setup, an SSH server for forwarding...) when your network connection is limited by a Web proxy that only allows basic port 80 HTTP connectivity.  Crowbar will tunnel TCP connections over an HTTP session using only GET and POST requests. This is in contrast to most tunneling systems that reuse the CONNECT verb. It also provides basic authentication to make sure nobody who stumbles upon the server steals your proxy to order drugs from Silkroad.
		* [A Black Path Toward The Sun(ABPTTS)](https://github.com/nccgroup/ABPTTS)
			* ABPTTS uses a Python client script and a web application server page/package[1] to tunnel TCP traffic over an HTTP/HTTPS connection to a web application server. In other words, anywhere that one could deploy a web shell, one should now be able to establish a full TCP tunnel. This permits making RDP, interactive SSH, Meterpreter, and other connections through the web application server.
		* [pivotnacci](https://github.com/blackarrowsec/pivotnacci)
			* Pivot into the internal network by deploying HTTP agents. Pivotnacci allows you to create a socks server which communicates with HTTP agents
		* [graftcp](https://github.com/hmgle/graftcp)
			* graftcp can redirect the TCP connection made by the given program [application, script, shell, etc.] to SOCKS5 or HTTP proxy.
		* [Tunna](https://github.com/SECFORCE/Tunna)
			* Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments.
		* [YARP/Yet Another Reverse Proxy](https://github.com/microsoft/reverse-proxy)
			* YARP is a reverse proxy toolkit for building fast proxy servers in .NET using the infrastructure from ASP.NET and .NET. The key differentiator for YARP is that it's been designed to be easily customized and tweaked to match the specific needs of each deployment scenario.
	- **HTTP2**
		* [gTunnel](https://github.com/hotnops/gtunnel)
			* A TCP tunneling suite built with golang and gRPC. gTunnel can manage multiple forward and reverse tunnels that are all carried over a single TCP/HTTP2 connection. I wanted to learn a new language, so I picked go and gRPC. Client executables have been tested on windows and linux.
	- **ICMP**
		* [Hans - IP over ICMP - hans](http://code.gerade.org/hans/)
			* [Source](https://sourceforge.net/projects/hanstunnel/files/source/)
			* Hans makes it possible to tunnel IPv4 through ICMP echo packets, so you could call it a ping tunnel. This can be useful when you find yourself in the situation that your Internet access is firewalled, but pings are allowed.
		* [icmptx](https://github.com/jakkarth/icmptx)
			*  ICMPTX is a program that allows a user with root privledges to create a virtual network link between two computers, encapsulating data inside of ICMP packets.
	- **PowerShell**
		* [PowerShellDSCLateralMovement.ps1](https://gist.github.com/mattifestation/bae509f38e46547cf211949991f81092)
	- **RDP**
		* [rdp2tcp](https://github.com/V-E-O/rdp2tcp)
			* rdp2tcp: open tcp tunnel through remote desktop connection.
		* [Socks Over RDP / Socks Over Citrix](https://github.com/nccgroup/SocksOverRDP)
			* This tool adds the capability of a SOCKS proxy to Terminal Services (or Remote Desktop Services) and Citrix (XenApp/XenDesktop). It uses Dynamic Virtual Channel that enables us to communicate over an open RDP/Citrix connection without the need to open a new socket, connection or a port on a firewall.
		* [Socks Over RDP - Balazs Bucsay(2020)](https://research.nccgroup.com/2020/05/06/tool-release-socks-over-rdp/)
		* [Using DVC to tunnel arbitrary connections inside of RDP - Guillaume Quéré(2020](https://www.errno.fr/RDPTunneling.html)
	- **SMB**
		* [Piper](https://github.com/p3nt4/Piper)
			* Creates a local or remote port forwarding through named pipes.
		* [flatpipes](https://github.com/dxflatline/flatpipes)
			* A TCP proxy over named pipes. Originally created for maintaining a meterpreter session over 445 for less network alarms.
		* [Invoke-PipeShell](https://github.com/threatexpress/invoke-pipeshell)
			* This script demonstrates a remote command shell running over an SMB Named Pipe. The shell is interactive PowerShell or single PowerShell commands
		* [Invoke-Piper](https://github.com/p3nt4/Invoke-Piper)
			* Forward local or remote tcp ports through SMB pipes.
	- **SSH**
		* [SSHDog](https://github.com/Matir/sshdog)
			* SSHDog is your go-anywhere lightweight SSH server. Written in Go, it aims to be a portable SSH server that you can drop on a system and use for remote access without any additional configuration.	
		* [MeterSSH](https://github.com/trustedsec/meterssh)
			* MeterSSH is a way to take shellcode, inject it into memory then tunnel whatever port you want to over SSH to mask any type of communications as a normal SSH connection. The way it works is by injecting shellcode into memory, then wrapping a port spawned (meterpeter in this case) by the shellcode over SSH back to the attackers machine. Then connecting with meterpreter's listener to localhost will communicate through the SSH proxy, to the victim through the SSH tunnel. All communications are relayed through the SSH tunnel and not through the network.
		* [powermole](https://github.com/yutanicorp/powermolecli)
			* This program will let you perform port forwarding, redirect internet traffic, and transfer files to, and issue commands on, a host without making a direct connection (ie. via one or more intermediate hosts), which would undoubtedly compromise your privacy. This solution can only work when you or your peers own one or more hosts as this program communicates with SSH servers. This program can be viewed as a multi-versatile wrapper around SSH with the ProxyJump directive enabled. Powermole creates automatically a ssh/scp configuration file to enable key-based authentication with the intermediate hosts.
	- **SOCKS/TCP/UDP**
		* [RFC1928: SOCKS Protocol Version 5](https://tools.ietf.org/html/RFC1928)
		* [SOCKS: A protocol for TCP proxy across firewalls](https://www.openssh.com/txt/socks4.protocol) 
		* [shootback](https://github.com/aploium/shootback)
			* shootback is a reverse TCP tunnel let you access target behind NAT or firewall
		* [ssf - Secure Socket Funneling](https://github.com/securesocketfunneling/ssf)
			* Network tool and toolkit. It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS tunnel to a remote computer. SSF is cross platform (Windows, Linux, OSX) and comes as standalone executables.
		* [PowerCat](https://github.com/secabstraction/PowerCat)
			* A PowerShell TCP/IP swiss army knife that works with Netcat & Ncat
		* [Udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel)
			* A Tunnel which tunnels UDP via FakeTCP/UDP/ICMP Traffic by using Raw Socket, helps you Bypass UDP FireWalls(or Unstable UDP Environment). Its Encrypted, Anti-Replay and Multiplexed. It also acts as a Connection Stabilizer.)
		* [reGeorg](https://github.com/sensepost/reGeorg)
			* The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
		* [redsocks – transparent TCP-to-proxy redirector](https://github.com/darkk/redsocks)
			* This tool allows you to redirect any TCP connection to SOCKS or HTTPS proxy using your firewall, so redirection may be system-wide or network-wide.
		* [ligolo](https://github.com/sysdream/ligolo)
			* Ligolo is a simple and lightweight tool for establishing SOCKS5 or TCP tunnels from a reverse connection in complete safety (TLS certificate with elliptical curve). It is comparable to Meterpreter with Autoroute + Socks4a, but more stable and faster.
		* [proxychains-windows](https://github.com/shunf4/proxychains-windows)
			* Windows and Cygwin port of proxychains, based on MinHook and DLL Injection
		* [rpivot](https://github.com/klsecservices/rpivot)
			* This tool is Python 2.6-2.7 compatible and has no dependencies beyond the standard library. It has client-server architecture. Just run the client on the machine you want to tunnel the traffic through. Server should be started on pentester's machine and listen to incoming connections from the client.
		* [Secure Socket Funneling](https://github.com/securesocketfunneling/ssf)
			* Secure Socket Funneling (SSF) is a network tool and toolkit. It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS tunnel to a remote computer. SSF is cross platform (Windows, Linux, OSX) and comes as standalone executables.
		* [Socks5](https://github.com/ThrDev/Socks5)
			* A full-fledged high-performance socks5 proxy server written in C#. Plugin support included.
	- **VNC**
		* [Invoke-Vnc](https://github.com/klsecservices/Invoke-Vnc)
			* Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.
		* [jsmpeg-vnc](https://github.com/phoboslab/jsmpeg-vnc)
			* A low latency, high framerate screen sharing server for Windows and client for browsers
	- **VPN**
		* [ligolo-ng](https://github.com/tnpitsecurity/ligolo-ng)
			* An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface.
	- **WMI**
		* [PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)
			* PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement.
			* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)
-----------------------------------------------------------------------------------------------------------------------------------





















-----------------------------------------------------------------------------------------------------------------------------------
### Secured Environment Breakouts/Escapes
- **Secured Environment Escape**<a name="secure-env"></a>
	* **101**
		* [Sandboxes from a pen tester’s view - Rahul Kashyap](http://www.irongeek.com/i.php?page=videos/derbycon3/4303-sandboxes-from-a-pen-tester-s-view-rahul-kashyap)
			* Description: In this talk we’ll do an architectural decomposition of application sandboxing technology from a security perspective. We look at various popular sandboxes such as Google Chrome, Adobe ReaderX, Sandboxie amongst others and discuss the limitations of each technology and it’s implementation. Further, we discuss in depth with live exploits how to break out of each category of sandbox by leveraging various kernel and user mode exploits – something that future malware could leverage. Some of these exploit vectors have not been discussed widely and awareness is important.
	- **Adobe Sandbox**
		* [Adobe Sandbox: When the Broker is Broken - Peter Vreugdenhill](https://cansecwest.com/slides/2013/Adobe%20Sandbox.pdf)
	- **chroot**
		* [chw00t: chroot escape tool](https://github.com/earthquake/chw00t)
		* [Breaking Out of a Chroot Jail Using PERL](http://pentestmonkey.net/blog/chroot-breakout-perl)
	- **Breaking out of Contained Linux Shells**
		* [Escaping Restricted Linux Shells - SANS](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells#)
		* [Breaking out of rbash using scp - pentestmonkey](http://pentestmonkey.net/blog/rbash-scp)
		* [Escape From SHELLcatraz - Breaking Out of Restricted Unix Shells - knaps](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells)
		* [How to break out of restricted shells with tcpdump - Oiver Matula](https://insinuator.net/2019/07/how-to-break-out-of-restricted-shells-with-tcpdump/)
	- **Python Sandbox**
		* [Escaping a Python sandbox with a memory corruption bug](https://hackernoon.com/python-sandbox-escape-via-a-memory-corruption-bug-19dde4d5fea5)
		* [Breaking out of secured Python environments](http://tomforb.es/breaking-out-of-secured-python-environments)
		* [Sandboxed Execution Environment ](http://pythonhosted.org/python-see)
		* [Documentation](http://pythonhosted.org/python-see)
			* Sandboxed Execution Environment (SEE) is a framework for building test automation in secured Environments.  The Sandboxes, provided via libvirt, are customizable allowing high degree of flexibility. Different type of Hypervisors (Qemu, VirtualBox, LXC) can be employed to run the Test Environments.
		* [Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)
	- **ssh**
		* [ssh environment - circumvention of restricted shells](http://www.opennet.ru/base/netsoft/1025195882_355.txt.html)
	- **Windows**
		* [Windows Desktop Breakout](https://www.gracefulsecurity.com/windows-desktop-breakout/)
		* [Kiosk/POS Breakout Keys in Windows - TrustedSec](https://www.trustedsec.com/2015/04/kioskpos-breakout-keys-in-windows/)
		* [menu2eng.txt - How To Break Out of Restricted Shells and Menus, v2.3(1999)](https://packetstormsecurity.com/files/14914/menu2eng.txt.html)
		* [Kiosk Escapes Pt 2 - Ft. Microsoft Edge!! - H4cklife](https://h4cklife.org/posts/kiosk-escapes-pt-2/)
			* TL/DR: Microsoft Edge brings up Windows Explorer when you navigate to C:\ in the URL; Win+x can be used to access the start menu when shortcut keys are limited
			* An excellent whitepaper detailing methods for breaking out of virtually any kind of restricted shell or menu you might come across.
		* [Breaking Typical Windows Hardening Implementations - Oddvar Moe(2020)](https://www.trustedsec.com/blog/breaking-typical-windows-hardening-implementations/)
	- **VDI**
		* [Breaking Out! of Applications Deployed via Terminal Services, Citrix, and Kiosks](https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/)
		* [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
		* [Pentests in restricted VDI environments - Viatcheslav Zhilin](https://www.tarlogic.com/en/blog/pentests-in-restricted-vdi-environments/)
	- **VirtualMachine**
		* [Exploiting the Hyper-V IDE Emulator to Escape the Virtual Machine - Joe Bialek](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_08_BlackHatUSA/BHUSA19_Exploiting_the_Hyper-V_IDE_Emulator_to_Escape_the_Virtual_Machine.pdf)
		* [L1TF (Foreshadow) VM guest to host memory read PoC](https://github.com/gregvish/l1tf-poc)
			* This is a PoC for CVE-2018-3646. This is a vulnerability that enables malicious/compromised VM guests to read host machine physical memory. The vulnerability is exploitable on most Intel CPUs that support VT-x and EPT (extended page tables). This includes all Intel Core iX CPUs. This PoC works only on 64 bit x86-64 systems (host and guest).
-----------------------------------------------------------------------------------------------------------------------------------



