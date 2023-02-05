# Attacking & Securing Active Directory

---------------------------------------------------------------------------------------------------------------------------------
## Table of Contents
- [Active Directory](#active-directory)
- [Attacking AD 101](#adatk101)
- [AD Technologies](#adt)
- [Attacking AD/Specific Techniques](#adattack)
- [Securing & Hardening Active Directory](#ADsecure) - ToDo
------------------------------------


------------------------------------
- [Active Directory Technologies(and how to abuse them)](#ADtech)<a name="adt"></a>
	- [AD Certificate Services](#adcs)
	- [ADFS](#adfs)
	- [AdminSD](#adminsd)
	- [AutoDiscover](#autodiscover)
	- [DACLs](#dacl)
	- [DNS](#dns)
	- [Domain Trusts](#domain-trusts)
	- [Fax & Printer](#faxprinter)
	- [Forests](#forests)
	- [Groups](#groups)
	- [Group Managed Service Accounts(GMSA)](#gmsa)
	- [Group Policy](#grouppolicy)
	- [IPv6](#ipv6)
	- [Kerberos](#kerberos)
		- [Krbtgt](#krbtgt)
	- [KMS](#kms)
	- [LDAP](#ldap) 
	- [Local Admin Password Solution](#laps)
	- [Lync](#lync)
	- [MachineAccountQuota](#maqt)
	- [MS-SAMR](#mssamr)
	- [MS-SQL](#mssql)
	- [NTLM](#ntlm)
	- [Organizational Units](#ous)
	- [Read-Only Domain Controllers](#rodc)
	- [Red Forest](#redforest)
	- [Security Identifiers (SIDs)](#sids)
	- [Service Principal Names](#spn)
	- [System Center Configuration Manager(SCCM)](#sccm)
	- [Volume Shadow Copy](#vsc)
	- [WSUS](#wsus)
	- [MS Exchange](#msexchange)
------------------------------------


------------------------------------
- [Attacking AD/Specific Techniques](#adattack)<a name="ada"></a>
	- [Attack Paths](#attackpaths)
	- [BloodHound](#bloodhound)
	- [Abusing ACEs & ACLs](#aces) - FIX
	- [Across Trusts and Domains](#crosspriv) - FIX
	- [Certificate Services](#certattack)
	- [Coerced Authentication](#coercedauth)
	- [Credential Attacks](#adcred)
	- [DCShadow](#dcshadow)
	- [DCSync](#dcsync)
	- [NetSync](#netsync)
	- [Defense Evasion](#addefev)
	- [Discovery/Reconnaissance](#discorecon)
		- []()
		- []()
		- [Hunting Users](#huntingusers)
	- [FreeIPA (Attacking)](#freeipa)
	- [Forest Attacks](#aforest)
	- [Group Managed Services (Attacking)](#gmsaa)
	- [Group Membership Abuse](#groupabuse)
	- [Internal Monologue Attack](#ilm)
	- [Lateral Movement](#adlate)
		- []()
		- []()
	- [Machine Account Quota (Attacking/Using)](#maq)
	- [MSCACHE](#mcache)
	- [NTLM `*`](#ntlmattack)
		- [Downgrade](#ntlmdowngrade)
		- [Leak](#ntlmleak)
		- [Relay](#ntlmrelay)
	- [Attacking OUs](#aou)
	- [Pass-the-`*`](#pth)
		- []()
		- []()
	- [Persistence](#adpersist)
		- []()
		- []()
	- [Printers & Faxes (Attacking)](#pfa)
	- [Privilege Escalation](#adprivesc) - FIX
		- []()
		- []()
		- [Machine Accounts](#macs)
		- [sAMAccountName](#samaccountname)
		- [Shadow Admin](#shadowadmin)
	- [RDP (Attacking](#rdp)
	- [Volume Shadow Service](#shadowvuln)
	- [Sharepoint](#sharepoint)
	- [Skeleton Key](#skey)
	- [SQL Server (Attacking)](#sqlservera)
	- [Trusts (Attacking)](#trustsa)
	- [WSUS](#wsusa)
- [Kerberos-Based Attacks](#kerb-based)
	- [AS-REP Roasting](#asreproasting)
	- [AS-REQ Roasting](#asreqroasting)
	- [Kerberos Delegation](#kerbdelegate)
	- [Encryption Downgrade](#kerb-enc-down)
	- [FAST](#fast)
	- [Kebreroasting](#kerberoasting)
	- [PKINITMustiness](#pkinitmustiness)
	- Tickets
		- [Silver Ticket](#silver-ticket)
		- [Golden Ticket](#golden-ticket)
		- [Diamond Ticket](#diamond-ticket)
		- [Saphire Ticket](#saphire-ticket)
- [AD Vulnerabilities(CVEs)](#advulns)
---------------------------------------------------------------------------------------------------------------------------------


---------------------------------------------------------------------------------------------------------------------------------
### <a name="active-directory"></a>Active Directory
* **Looking for Azure? Check the Cloud page**
* **101**
	* [What is Active Directory Domain Services and how does it work?](https://serverfault.com/questions/402580/what-is-active-directory-domain-services-and-how-does-it-work#)
	* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them - Sean Metcalf](https://adsecurity.org/?p=1684)
	* [What is Active Directory Red Forest Design? - social.technet.ms](https://social.technet.microsoft.com/wiki/contents/articles/37509.what-is-active-directory-red-forest-design.aspx)
	* [Presentations by Sean Metcalf(ADSecurity.org)](https://adsecurity.org/?page_id=1352)
	* [Top 16 Active Directory Vulnerabilities - InfosecMatter(2020)](https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/)
	* [Service overview and network port requirements for Windows - docs.ms](https://docs.microsoft.com/en-my/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)
	* **Paid Courses**
		* [Attacking and Defending Active Directory - Nikhil Mittal](https://www.pentesteracademy.com/course?id=47)
	* **Cheat-Sheets**
		* [Active Directory Cheat Sheet](https://github.com/punishell/ADCheatSheet)
			* Domain Demolition with Frank Castle and Powershell.
		* [Active Directory Exploitation Cheat Sheet - buftas](https://github.com/buftas/Active-Directory-Exploitation-Cheat-Sheet)
			* A cheat sheet that contains common enumeration and attack methods for Windows Active Directory.
		* [Orange Cyberdefense mindmaps](https://orange-cyberdefense.github.io/ocd-mindmaps/)
	* **Articles/Blogposts/Writeups**
		* [Beyond Domain Admins – Domain Controller & AD Administration - ADSecurity.org](https://adsecurity.org/?p=3700)
			* This post provides information on how Active Directory is typically administered and the associated roles & rights.
		* [Setting up Samba as a Domain Member](https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member)
		* [DS Restore Mode Password Maintenance - techcommunity.microsoft(2009)](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ds-restore-mode-password-maintenance/ba-p/396102)
	* **Talks/Videos**
		* [Beyond the MCSE: Active Directory for the Security Professional - Sean Metcalf(BHUSA 2016)](https://www.youtube.com/watch?v=2w1cesS7pGY)
			* Active Directory (AD) is leveraged by 95% of the Fortune 1000 companies for its directory, authentication, and management capabilities. This means tSMBhat both Red and Blue teams need to have a better understanding of Active Directory, it's security, how it's attacked, and how best to align defenses. This presentation covers key Active Directory components which are critical for security professionals to know in order to defend AD. Properly securing the enterprise means identifying and leveraging appropriate defensive technologies. The provided information is immediately useful and actionable in order to help organizations better secure their enterprise resources against attackers. Highlighted are areas attackers go after including some recently patched vulnerabilities and the exploited weaknesses. This includes the critical Kerberos vulnerability (MS14-068), Group Policy Man-in-the-Middle (MS15-011 & MS15-014) and how they take advantages of AD communication.
	* **Attacking101**<a name="adatk101"></a>
		* **Articles/Blogposts/Writeups**
			* [Active Directory Security Workshop: A Red and Blue Guide to Popular AD Attacks - `@_theViVi`(AfricaHackon2019)](https://thevivi.net/wp-content/uploads/2019/08/theVIVI-AD-Security-Workshop_AfricaHackon2019.pdf)
			* [Active Directory Kill Chain Attack & Defense - infosecn1nja](https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md)
				* This document was designed to be a useful, informational asset for those looking to understand the specific tactics, techniques, and procedures (TTPs) attackers are leveraging to compromise active directory and guidance to mitigation, detection, and prevention. And understand Active Directory Kill Chain Attack and Modern Post Exploitation Adversary Tradecraft Activity.
			* [Penetration Testing Active Directory, Part I - Hausec](https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/)
				* [Part II](https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/)
			* [Active Directory Attacks - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
			* [Pen Testing Active Directory Series - Andy Green](https://blog.varonis.com/binge-read-pen-testing-active-directory-series/)
			* [Active Directory Fundamentals (Part 1)- Basic Concepts - Scarred Monk(2021)](https://rootdse.org/posts/active-directory-basics-1/)
				* [(Part 2) - AD Objects](https://rootdse.org/posts/active-directory-basics-2/)
				* [(Part 3)- Group Policies](https://rootdse.org/posts/active-directory-basics-3/)
				* [(Part 4)- NTDS.DIT, LDAP, Schema, Attributes](https://rootdse.org/posts/active-directory-basics-4/)
		* **Talks/Videos**
			* [Abusing Active Directory in Post-Exploitation - Carlos Perez(Derbycon4)](https://www.irongeek.com/i.php?page=videos/derbycon4/t105-abusing-active-directory-in-post-exploitation-carlos-perez)
				* Windows APIs are often a blackbox with poor documentation, taking input and spewing output with little visibility on what actually happens in the background. By reverse engineering (and abusing) some of these seemingly benign APIs, we can effectively manipulate Windows into performing stealthy custom attacks using previously unknown persistent and injection techniques. In this talk, we’ll get Windows to play with itself nonstop while revealing 0day persistence, previously unknown DLL injection techniques, and Windows API tips and tricks. To top it all off, a custom HTTP beaconing backdoor will be released leveraging the newly released persistence and injection techniques. So much Windows abuse, so little time.
			* [Red vs Blue: Modern Active Directory Attacks & Defense - Sean Metcalf(Defcon23)](https://www.youtube.com/watch?v=rknpKIxT7NM)
				* Kerberos “Golden Tickets” were unveiled by Alva “Skip” Duckwall & Benjamin Delpy in 2014 during their Black Hat USA presentation. Around this time, Active Directory (AD) admins all over the world felt a great disturbance in the Force. Golden Tickets are the ultimate method for persistent, forever AD admin rights to a network since they are valid Kerberos tickets and can’t be detected, right? This talk explores the latest Active Directory attack vectors and describes how Golden Ticket usage can be detected. When forged Kerberos tickets are used in AD, there are some interesting artifacts that can be identified. Yes, despite what you may have read on the internet, there are ways to detect Golden & Silver Ticket usage. Skip the fluff and dive right into the technical detail describing the latest methods for gaining and maintaining administrative access in Active Directory, including some sneaky AD persistence methods. Also covered are traditional security measures that work (and ones that don’t) as well as the mitigation strategies that disrupts the attacker’s preferred game-plan. Prepare to go beyond “Pass-the-Hash” and down the rabbit hole.
			* [Red Vs. Blue: Modern Active Directory Attacks, Detection, And Protection - Sean Metcalf(BHUSA15)](https://www.youtube.com/watch?v=b6GUXerE9Ac)
				* Kerberos "Golden Tickets" were unveiled by Alva "Skip" Duckwall & Benjamin Delpy in 2014 during their Black Hat USA presentation. Around this time, Active Directory (AD) admins all over the world felt a great disturbance in the Force. Golden Tickets are the ultimate method for persistent, forever AD admin rights to a network since they are valid Kerberos tickets and can't be detected, right? The news is filled with reports of breached companies and government agencies with little detail on the attack vectors and mitigation. This briefing discusses in detail the latest attack methods for gaining and maintaining administrative access in Active Directory. Also covered are traditional defensive security measures that work (and ones that don't) as well as the mitigation strategies that can keep your company's name off the front page. Prepare to go beyond "Pass-the-Hash" and down the rabbit hole. This talk explores the latest Active Directory attack vectors and describes how Golden Ticket usage can be detected. When forged Kerberos tickets are used in AD, there are some interesting artifacts that can be identified. Yes, despite what you may have read on the internet, there are ways to detect Golden & Silver Ticket usage!
			* [Beyond the MCSE: Red Teaming Active Directory - Sean Metcalf(Defcon24)](https://www.youtube.com/watch?v=tEfwmReo1Hk)
				* Active Directory (AD) is leveraged by 95% of the Fortune 1000 companies for its directory, authentication, and management capabilities, so why do red teams barely scratch the surface when it comes to leveraging the data it contains? This talk skips over the standard intro to Active Directory fluff and dives right into the compelling offensive information useful to a Red Teamer, such as quickly identifying target systems and accounts. AD can yield a wealth of information if you know the right questions to ask. This presentation ventures into areas many didn't know existed and leverages capability to quietly identify interesting accounts & systems, identify organizations the target company does business with regularly, build target lists without making a sound, abuse misconfigurations/existing trusts, and quickly discover the most interesting shares and their location. PowerShell examples and AD defense evasion techniques are provided throughout the talk.Let's go beyond the MCSE and take a different perspective on the standard AD recon and attack tactics.
			* [Offensive Active Directory with Powershell - harmj0y(Troopers2016)](https://www.youtube.com/watch?v=cXWtu-qalSs)
			* [Hacking without Domain Admin - Tim Medin, Mike Saunders(2019)](https://www.sans.org/webcasts/110998)
				* Tim and Mike will show you tools and techniques to find vulnerabilities and demonstrate risk, without using Domain Administrator (DA) access. DA access is the goal for many penetration tests and red teams, but it is misguided. DA is a tool, not a destination. Sometimes, a penetration tester or red team will be unable to obtain this access, but it does not mean that the test is without value.
			* [Demystifying Common Active Directory Attacks - Venkatraman K(BSides Delhi2020)](https://www.youtube.com/watch?v=BwS-FnUih7c)
				* [Slides](https://www.youtube.com/redirect?event=video_description&v=BwS-FnUih7c&q=https%3A%2F%2Fdrive.google.com%2Ffile%2Fd%2F1HyOjJVSjxxyAEmMMK6jCIdpb2sn_NtSw%2Fview&redir_token=QUFFLUhqbXZjSVJUZXhZSGlHR1Rpd0FJcVZWdXlFQXJuQXxBQ3Jtc0tuVzRYM3RJaTRNTU85bFBaZ3BkdmUwejloTkoxV3F2TXd6ZEZ5dmVIWGZJQ0tsMXRDaWhzbHR4V2JlTkVNMDFBbVgxZG1kWHpDZEd4RnNHZjFONVlUMnB5Y1hjZ1pDemcwMG90VlBxWEhVdWN4X2FpWQ%3D%3D)
				* #ActiveDirectory is used by more than 90% of Fortune 1000 companies, the all-pervasive #AD is the focal point for adversaries. This paper would demonstrate the common attack scenarios in an Active Directory environment that can be witnessed in an #Infrastructure Assessment. Some of the attacks would be briefed along with #wireshark, to understand the packet flow.The presentation begins with briefing basics of #Kerberos Authentication such Key Distribution Center, Ticket Granting Ticket , Ticket Granting Service etc. and their role in authentication flow. This presentation would give insights about the active directory attacks which include: AS-REP Roasting attack; Kerberoasting attack; Kerberos Golden Ticket attack; Kerberos Silver Ticket attack; DCSync Attack; DCShadow Attack
* **Active Directory Attributes & Technologies**<a name="ADtech"></a>
	* **Active Directory Service Interaces**
		* **101**
			* [Active Directory Service Interfaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)
		* **Articles/Blogposts/Writeups**
			* [Use the PowerShell [adsiSearcher] Type Accelerator to Search Active Directory - ScriptingGuy(2010)](https://devblogs.microsoft.com/scripting/use-the-powershell-adsisearcher-type-accelerator-to-search-active-directory/)
			* [Managing Active Directory objects with ADSI Edit - Huy Kha(2020)](https://identityandsecuritydotcom.files.wordpress.com/2020/10/adsi_edit.pdf)
			* [Tools, Techniques, and Grimmie?: Experimenting w/ Offensive ADSI - Grimmie(2021)](https://grimmie.net/tools-techniques-and-grimmie-experimenting-w-offensive-adsi/)
			* [Search Active Directory using ADSISearcher Filters - Alkane Solutions(2021)](https://www.alkanesolutions.co.uk/2021/03/03/search-active-directory-using-adsisearcher-filters/)
		* **Talks/Videos**
		* **Tools**
			* [AdsiPS](https://github.com/lazywinadmin/AdsiPS)
				* PowerShell module to interact with Active Directory using ADSI and the `System.DirectoryServices` namespace (.NET Framework).
	* **AD Permissions/Rights**
		* **101**
			* [Extended Rights Reference - docs.ms](https://docs.microsoft.com/en-us/previous-versions/tn-archive/ff405676(v=msdn.10))
				* This page lists all the extended rights available for delegation in Active Directory. These rights have been categorized according to the object (such as the user account object) that the right applies to; each listing includes the extended right name, a brief description, and the object GUID required when writing a script to delegate that right.
	- **Account Logon History**
		* [Get All AD Users Logon History with their Logged on Computers (with IPs)& OUs](https://gallery.technet.microsoft.com/scriptcenter/Get-All-AD-Users-Logon-9e721a89)
			* This script will list the AD users logon information with their logged on computers by inspecting the Kerberos TGT Request Events(EventID 4768) from domain controllers. Not Only User account Name is fetched, but also users OU path and Computer Accounts are retrieved. You can also list the history of last logged on users. In Environment where Exchange Servers are used, the exchange servers authentication request for users will also be logged since it also uses EventID (4768) to for TGT Request. You can also export the result to CSV file format. Powershell version 3.0 is needed to use the script.
	- **AD Certificate Services**<a name="adcs"></a>
		- **Articles/Blogposts/Writeups**
			* [Active Directory Domain Services - Learning.MS](https://learn.microsoft.com/en-us/training/paths/active-directory-domain-services/)
		- **Tools**
			- **Detection**
				* [Invoke-Leghorn](https://github.com/RemiEscourrou/Invoke-Leghorn)
					* Standalone powershell script to detect potential PKI abuse
				* [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit)
					* PowerShell toolkit for auditing Active Directory Certificate Services (AD CS).
	* **ADFS**<a name="adfs"></a>
		* **101**
			* [Active Directory Federation Services - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services)
				* This document contains a list of all of the documentation areas for AD FS for Windows Server 2016, 2012 R2, and 2012.
			* [Active Directory Federation Services - Wikipedia](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services)
			* [What is ADFS (Active Directory Federation Services)? - Serverfault.com(2017)](https://serverfault.com/questions/708669/what-is-adfs-active-directory-federation-services)
		* **Articles/Blogposts/Writeups**
			* [Using PowerShell to Identify Federated Domains](https://blog.netspi.com/using-powershell-identify-federated-domains/)
			* [Sniffing and replaying ADFS claims with Fiddler! - Paula Januszkiewicz](https://cqureacademy.com/blog/replaying-adfs-claims-with-fiddler)
		* **Talks/Presentations/Videos**
			* [Attacking ADFS Endpoints with PowerShell - Karl Fosaaen(Derbycon 2016)](https://www.youtube.com/watch?v=oTyLdAUjw30)
				* Active Directory Federation Services (ADFS) has become increasingly popular in the last few years. As a penetration tester, I'm seeing organizations opening themselves up to attacks on ADFS endpoints across the Internet. Manually completing attacks against these endpoints can be tedious. The current native Microsoft management tools are handy, but what if we weaponized them. During this talk, I will show you how to identify domains that support ADFS, confirm email addresses for users of the domain, and help you guess passwords for those users. We'll cover how you can set up your own hosted ADFS domain (on the cheap), and use it to attack other federated domains. On top of that, we'll show you how you can wrap all of the native functionality with PowerShell to automate your attacks. This talk should give penetration testers an overview on how they can start leveraging ADFS endpoints during a penetration test.
	* **AdminSDHolder**<a name="adminsd"></a>
		* **101**
			* [Reference Material | Understanding Privileged Accounts and the AdminSDHolder - Specopssoft.com](https://specopssoft.com/support-docs/specops-password-reset/reference-material/understanding-privileged-accounts-and-the-adminsdholder/)
			* [Five common questions about AdminSdHolder and SDProp - blogs.technet](https://blogs.technet.microsoft.com/askds/2009/05/07/five-common-questions-about-adminsdholder-and-sdprop/)
			* [AdminSDHolder, Protected Groups and SDPROP - John Policelli - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)#id0250006)
		* **Articles/Blogposts/Writeups**
			* [Sneaky Active Directory Persistence #15: Leverage AdminSDHolder & SDProp to (Re)Gain Domain Admin Rights](https://adsecurity.org/?p=1906)
			* [Persistence Using Adminsdholder And Sdprop](https://blog.stealthbits.com/persistence-using-adminsdholder-and-sdprop/)
	* **ATA/ATP**<a name="ATA"></a>
		* [ATA Suspicious Activity Playbook - technet.ms](https://gallery.technet.microsoft.com/ATA-Playbook-ef0a8e38)
	- **AutoDiscover**<a name="autodiscover"></a>
		* [Autodiscover for Exchange - docs.ms](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/autodiscover-for-exchange)
		* [All your emails belong to us: exploiting vulnerable email clients via domain name collision - Ilya Nesterov, Maxim Goncharov(BlackHatAsia2017)](https://www.blackhat.com/docs/asia-17/materials/asia-17-Nesterov-All-Your-Emails-Belong-To-Us-Exploiting-Vulnerable-Email-Clients-Via-Domain-Name-Collision-wp.pdf)
			* The Autodiscover HTTP Service Protocol provides a way for Autodiscover clients to find Autodiscover servers. This protocol extends the Domain Name System (DNS) and directory services to make the location and settings of mail servers available to clients. In this paper, we take a closer look at the Autodiscover protocol and identify its threat model. We analyse Autodiscover client implementations in two mobile built-in email clients to discover flaws which allow remote attackers to collect user credentials through domain name collision. We discover how many clients have vulnerable implementations by collecting and analysing HTTP request information received by our servers, registered with specially crafted domain names. We make our analysis based on on data we collect from 25 different domains. Our dataset contains information on about 11,720,559 requests and we observe 9,726,028 requests containing authentication information. We identify 2473 different email clients which use vulnerable Autodiscover client implementation. Finally we propose different mitigation techniques for users, enterprises, and application developers to improve their email clients.	
		* [Autodiscovering the Great Leak - Amit Serper(2021)](https://www.akamai.com/blog/security/autodiscovering-the-great-leak)
	- **(Discretionary)Access Control Lists**<a name="dacl">
		- **101**
			* [Active Directory Access Control List – Attacks and Defense - Microsoft Advanced Threat Analytics Team(2018)](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/active-directory-access-control-list-8211-attacks-and-defense/ba-p/250315)
			* [Permissions: A Primer, or: DACL, SACL, Owner, SID and ACE Explained - Helge Klein(2021)](https://helgeklein.com/blog/permissions-a-primer-or-dacl-sacl-owner-sid-and-ace-explained/)
		* **Articles/Blogposts/Writeups**
			* [Abusing Active Directory ACLs/ACEs - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
			* [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
			* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
			* [Viewing Service ACLs - rohnspowershellblog(2013)](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/)
			* [Modifying Service ACLs - rohnspowershellblog(2014)](https://rohnspowershellblog.wordpress.com/2013/04/13/modifying-service-acls/)
				* In my [last post](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/), I showed an early version of a function to get the Discretionary Access Control List (DACL) of a Windows service. In this post, I’m going to show a newer version of that function, along with a function to change the DACL, and a helper function to create Access Control Entries (ACEs). The source code is quite a bit longer, so I’m not going to walk through each bit of code. What I will do is give a brief overview of each of the three functions, along with some examples of how to use them. I’ll also mention where I plan to take the functions in the future. I’ll include the source code of the functions as they currently stand at the end of the post. Included in the source code is comment based help for each of the three functions.
			* [The Unintended Risks of Trusting Active Directory - harmj0y](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)
			* [Exploiting Weak Active Directory Permissions With Powersploit - Jeff Warren(2017](https://blog.stealthbits.com/exploiting-weak-active-directory-permissions-with-powersploit/)
			* [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
			* [Scanning for Active Directory Privileges & Privileged Accounts - Sean Metcalf(2017)](https://adsecurity.org/?p=3658)
			* [Active Directory Access Control List – Attacks and Defense](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Active-Directory-Access-Control-List-8211-Attacks-and-Defense/ba-p/250315)
			* [Escalating privileges with ACLs in Active Directory - Rindert Kramer and Dirk-jan Mollema(2018)](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
			    * During internal penetration tests, it happens quite often that we manage to obtain Domain Administrative access within a few hours. Contributing to this are insufficient system hardening and the use of insecure Active Directory defaults. In such scenarios publicly available tools help in finding and exploiting these issues and often result in obtaining domain administrative privileges. This blogpost describes a scenario where our standard attack methods did not work and where we had to dig deeper in order to gain high privileges in the domain. We describe more advanced privilege escalation attacks using Access Control Lists and introduce a new tool called Invoke-Aclpwn and an extension to ntlmrelayx that automate the steps for this advanced attack.
			* [AD Privilege Escalation Exploit: The Overlooked ACL - David Rowe](https://www.secframe.com/blog/ad-privilege-escalation-the-overlooked-acl)
			* [ACE to RCE - Justin Perdok(2020)](https://sensepost.com/blog/2020/ace-to-rce/)
				* "tl;dr: In this writeup I am going to describe how to abuse a GenericWrite ACE misconfiguration in Active Directory to run arbitrary executables."
			* [How to Exploit Active Directory ACL Attack Paths Through LDAP Relaying Attacks - Adam Crosser(2021)](https://www.praetorian.com/blog/how-to-exploit-active-directory-acl-attack-paths-through-ldap-relaying-attacks/)
		* **Talks & Presentations**
			* [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
    		* [Here Be Dragons: The Unexplored Land of Active Directory ACLs -  Andy Robbins & Will Schroeder & Rohan Vazarkar(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t101-here-be-dragons-the-unexplored-land-of-active-directory-acls-andy-robbins-will-schroeder-rohan-vazarkar)
    			* During internal penetration tests and red team assessments, Active Directory remains a key arena for gaining initial access, performing lateral movement, escalating rights, and accessing/exfiltrating sensitive data. Over the years, a completely untapped landscape has existed just below the surface in the form of Active Directory object control relationships. Organizational staff come and go, applications deploy and alter Access Control Entries (ACEs), eventually creating an entire ecosystem of policy exceptions and forgotten privileges. Historically, Access Control Lists (ACLs) have been notoriously difficult and frustrating to analyze both defensively and offensively, something we hope to change. In this talk, we will clearly define the Active Directory ACL attack taxonomy, demonstrate analysis using BloodHound, and explain how to abuse misconfigured ACEs with several new PowerView cmdlets. We will cover real world examples of ACL-only attack paths we have identified on real assessments, discuss opsec considerations associated with these attacks, and provide statistics regarding the immense number of attack paths that open up once you introduce object control relations in the BloodHound attack graph (spoiler alert: it's a LOT). We hope you will leave this talk inspired and ready to add ACL-based attacks to your arsenal, and to defensively audit ACLs at scale in your AD domain.
		* **Tools**
			* [Invoke-ACLpwn](https://github.com/fox-it/Invoke-ACLPwn)
    			* Invoke-ACLpwn is a tool that automates the discovery and pwnage of ACLs in Active Directory that are unsafe configured.
			* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
				* A collection of tools to enumerate and analyse Windows DACLs
			* [DAMP - The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.](https://github.com/HarmJ0y/DAMP)
				* This project contains several files that implement host-based security descriptor "backdoors" that facilitate the abuse of various remotely accessible services for arbitrary trustees/security principals. tl;dr - this grants users/groups (local, domain, or 'well-known' like 'Everyone') of an attacker's choosing the ability to perform specific administrative actions on a modified host without needing membership in the local administrators group. Note: to implement these backdoors, you need the right to change the security descriptor information for the targeted service, which in stock configurations nearly always means membership in the local administrators group.
			* [AD ACL Scanner](https://github.com/canix1/ADACLScanner)
				* Repo for ADACLScan.ps1 - Your number one script for ACL's in Active Directory
			* [Adalanche: Active Directory ACL Visualizer and Explorer](https://github.com/lkarlslund/adalanche)
				* Adalanche gives instant results, showing you what permissions users and groups have in an Active Directory. It is useful for visualizing and exploring who can take over accounts, machines or the entire domain, and can be used to find and show misconfigurations.
			* [Aced](https://github.com/garrettfoster13/aced)
				* Aced is a tool to parse and resolve a single targeted Active Directory principal's DACL. Aced will identify interesting inbound access allowed privileges against the targeted account, resolve the SIDS of the inbound permissions, and present that data to the operator. Additionally, the logging features of pyldapsearch have been integrated with Aced to log the targeted principal's LDAP attributes locally which can then be parsed by pyldapsearch's companion tool BOFHound to ingest the collected data into BloodHound.
	* **DNS**<a name="dns"></a>
		* **Articles/Blogposts/Writeups**
			* [AD Zone Transfers as a user - mubix(2013)](http://carnal0wnage.attackresearch.com/2013/10/ad-zone-transfers-as-user.html)
			* [Abusing DNSAdmins privilege for escalation in Active Directory(2017](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
			* [Feature, not bug: DNSAdmin to DC compromise in one line - Shay Ber(2017)](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
			* [Feature, not bug: DNSAdmin to DC compromise in one line - Shay Ber(2017)](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
			* [Abusing DNSAdmins privilege for escalation in Active Directory - Nikil Mittal(2017)](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
			* [From DNSAdmins to Domain Admin, When DNSAdmins is More than Just DNS Administration - ADSecurity(2018)](https://adsecurity.org/?p=4064)			
			* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - Kevin Robertson(2018)](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)
			* [ADIDNS Revisited – WPAD, GQBL, and More - Kevin Robertson(2018)](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/)
			* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema(2019)](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
				* Zone transfers are a classical way of performing reconnaissance in networks (or even from the internet). They require an insecurely configured DNS server that allows anonymous users to transfer all records and gather information about host in the network. What not many people know however is that if Active Directory integrated DNS is used, any user can query all the DNS records by default. This blog introduces a tool to do this and describes a method to do this even for records normal users don’t have read rights for.
			* [Compiling a DLL using MingGW - mubix](https://malicious.link/post/2020/compiling-a-dll-using-mingw/)
				* Compiling a DLL using MingGW to pull of the DNSAdmins attack
			* [DNS Peer-to-Peer Command and Control with ADIDNS - Elad Shamir(2020)](https://shenaniganslabs.io/2020/04/14/Internal-DNS-C2.html)
		* **Tools**
			* [DnsCache](https://github.com/malcomvetter/DnsCache)
				* This is a reference example for how to call the Windows API to enumerate cached DNS records in the Windows resolver. Proof of concept or pattern only.
			* [adidnsdump](https://github.com/dirkjanm/adidnsdump)
				* By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones, similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.
				* [Blogpost](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
	* **Domain Trusts**<a name="domain-trusts"></a>
		* **101**
			* [Primary and Trusted Domains - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secmgmt/primary-and-trusted-domains)
			* [Active Directory Domains and Trust - giritharan.com](https://giritharan.com/active-directory-domains-and-trust/)
			* [Active Directory Trusts - Ace Fekay(2018)](https://blogs.msmvps.com/acefekay/2016/11/02/active-directory-trusts/)
			* [Windows and Domain Trusts - Steve Syfuhs(2020)](https://syfuhs.net/windows-and-domain-trusts)
		* **Articles/Blogposts/Writeups**
			* [Domain Trusts: Why You Should Care](http://www.harmj0y.net/blog/redteaming/domain-trusts-why-you-should-care/)
			* [Trusts You Might Have Missed](http://www.harmj0y.net/blog/redteaming/trusts-you-might-have-missed/)
			* [A Guide to Attacking Domain Trusts - harmj0y](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
			* [Domain Trusts: We’re Not Done Yet - harmj0y](http://www.harmj0y.net/blog/redteaming/domain-trusts-were-not-done-yet/)
			* [The Trustpocalypse - harmj0y](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
			* [Subverting Trust in Windows - Matt Graeber](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
			* [A Guide to Attacking Domain Trusts - harmj0y](https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944)
			* [Trust Direction: An Enabler for Active Directory Enumeration and Trust Exploitation - BOHOPS](https://bohops.com/2017/12/02/trust-direction-an-enabler-for-active-directory-enumeration-and-trust-exploitation/)
		* **Presentations/Talks/Videos**
			* [Auditing Domain Trust Relationships - Will Schroeder(PowerShell ConferenceEU 2018)](https://www.youtube.com/watch?v=KRqZIu9MuNk&feature=youtu.be)
		* **Tools**
- **Fax & Printer Stuff**
	- **Articles/Blogposts/Writeups**
		* [AD information in printers - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-information-in-printers)
	- **Faxhell**
		* [Faxing Your Way to SYSTEM — Part Two - Yarden Shafir & Alex Ionescu(2020)](https://windows-internals.com/faxing-your-way-to-system/)
		* [faxhell ("Fax Shell")](https://github.com/ionescu007/faxhell)
			* A Bind Shell Using the Fax Service and a DLL Hijack
	- **LDAP-based**
		https://medium.com/r3d-buck3t/pwning-printers-with-ldap-pass-back-attack-a0d8fa495210
	- **NetNTLM to Silver Ticket**
		* [From Printers to Silver Tickets - EvilMog(DefconSafeMode)](https://www.youtube.com/watch?v=M9htSTug9TQ)
		* [NetNTLMtoSilverTicket writeup](https://github.com/NotMedic/NetNTLMtoSilverTicket)
	- **PrinterBug**
	- **PrintDemon**
		* [PrintDemon: Print Spooler Privilege Escalation, Persistence & Stealth (CVE-2020-1048 & more) - Yarden Shafir & Alex Ionescu(2020)](https://windows-internals.com/printdemon-cve-2020-1048/)
		* [PrintDemon (CVE-2020-1048)](https://github.com/ionescu007/PrintDemon)
			* PrintDemon is a PoC for a series of issues in the Windows Print Spooler service, as well as potetial misuses of the functionality.
		* [Invoke-PrintDemon](https://github.com/BC-SECURITY/Invoke-PrintDemon)
			* This is an PowerShell Empire launcher PoC using PrintDemon and Faxhell. The module has the Faxhell DLL already embedded which leverages CVE-2020-1048 for privilege escalation. The vulnerability allows an unprivileged user to gain system-level privileges and is based on @ionescu007 PoC.
	- **PrinterNightmare**
		* [Windows Print Spooler Remote Code Execution Vulnerability CVE-2021-1675 - msrc.ms](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)
		* [Windows Print Spooler Remote Code Execution Vulnerability CVE-2021-34527 - msrc.ms](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
		* [Demystifying The PrintNightmare Vulnerability - shlomo Zarinkhou, Haim Nachmias, Oren Biderman, Doron Vazgiel(2022)](https://blog.sygnia.co/demystifying-the-print-nightmare-vulnerability)
		* [DeployPrinterNightmare](https://github.com/Flangvik/DeployPrinterNightmare)
			* C# tool for installing a shared network printer abusing the PrinterNightmare bug to allow other network machines easy privesc!
	- **Talks/Presentations/Videos**
- **Forests**<a name="forests"></a>
	- **101**
		* [How Domain and Forest Trusts Work - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10))
	- **Articles/Blogposts/Writeups**
	- **Presentations/Talks/Videos**
- **Groups**<a name="groups"></a>
	- **101**		
		* [Active Directory Security Groups - docs.ms](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
			* "Learn about default Active Directory security groups, group scope, and group functions."
		* [Active Directory Security Groups - docs.ms](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)
			* This reference topic for the IT professional describes the default Active Directory security groups.
		* [How-to: Understand the different types of Active Directory group.  - SS64](https://ss64.com/nt/syntax-groups.html)
	- **Articles/Blogposts/Writeups**
		* [Active Directory security groups: What they are and how they improve security - Matthew Vinton(2022)](https://blog.quest.com/active-directory-security-groups-what-they-are-and-how-they-improve-security/)
		* [Top 6 Active Directory Security Groups Best Practices - DNSStuff(2019)](https://www.dnsstuff.com/active-directory-security-groups)
- **Group Managed Service Accounts(GMSA)**<a name="gmsa"></a>
	- **101**
		* [Group Managed Service Accounts Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
	- **Articles/Blogposts/Writeups**
		* [Attacking Active Directory Group Managed Service Accounts (GMSAs) - Sean Metcalf(2020)](https://adsecurity.org/?p=4367)
		* [NTLM Relaying for gMSA Passwords - Cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
		* [Kerberoasting: AES Encryption, Protected User Group and Group MSA  - dev2null](https://dev-2null.github.io/Kerberoasting-AES-Encryption-Protected-Users-Group-and-gMSA/)
	- **Tools**
		* [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
			* Reads the password blob from a GMSA account using LDAP, and parses the values into hashes for re-use.
- **Group Policy**<a name="grouppolicy"></a>	
	- **101**
		* [Group Policy - Wikipedia](https://en.wikipedia.org/wiki/Group_Policy)
		* [Group Policy Overview - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v%3Dws.11))
		* [Group Policy Architecture - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-architecture)
		* [GPPrefs - Store passwords using reversible encryption - docs.ms](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)
	- **Articles/Blogposts/Writeups**
		* [Abusing GPO Permissions - harmj0y](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
		* [Sneaky Active Directory Persistence #17: Group Policy](https://adsecurity.org/?p=2716)
		* [A Red Teamer’s Guide to GPOs and OUs](https://wald0.com/?p=179)
		* [File templates for GPO Abuse](https://github.com/rasta-mouse/GPO-Abuse)
		* [GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
		* [Local Group Enumeration - harmj0y](http://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
		* [Where My Admins At? (GPO Edition) - harmj0y](http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/)
		* [Bypassing Group Policy Proxy Settings Using The Windows Registry - Scriptmonkey](http://blog.scriptmonkey.eu/bypassing-group-policy-using-the-windows-registry/)
		* [Local Admin Acces and Group Policy Don't Mix - Oddvar Moe(2019)](https://www.trustedsec.com/blog/local-admin-access-and-group-policy-dont-mix/)
		* [Weaponizing Group Policy Objects Access - Jason Lang(2020)](https://www.trustedsec.com/blog/weaponizing-group-policy-objects-access/)
		* [Bypass Windows 10 User Group Policy (and more) with this One Weird Trick - David Wells(2020)](https://medium.com/tenable-techblog/bypass-windows-10-user-group-policy-and-more-with-this-one-weird-trick-552d4bc5cc1b)
		* [Abusing Group Policy Caching - decoder.cloud(2020)](https://decoder.cloud/2020/09/23/abusing-group-policy-caching/)
		* [OUs and GPOs and WMI Filters, Oh My! - RastaMouse(2022)](https://rastamouse.me/ous-and-gpos-and-wmi-filters-oh-my/)
		* [Using GPResult Command to Check Applied GPOs and RSoP Data - WindowsOSHub(2021)](http://woshub.com/diagnose-group-policies-issues-with-gpresult/)
	- **Talks & Presentations**
		* [Get-GPTrashFire - Mike Loss(BSides Canberra2018)](https://www.youtube.com/watch?v=JfyiWspXpQo)
			* Identifying and Abusing Vulnerable Configurations in MS AD Group Policy
			* [Slides](https://github.com/l0ss/Get-GPTrashfire)
	- **Tools**
		* [Grouper](https://github.com/l0ss/Grouper)
			* Grouper is a slightly wobbly PowerShell module designed for pentesters and redteamers (although probably also useful for sysadmins) which sifts through the (usually very noisy) XML output from the Get-GPOReport cmdlet (part of Microsoft's Group Policy module) and identifies all the settings defined in Group Policy Objects (GPOs) that might prove useful to someone trying to do something fun/evil.
		* [Grouper2](https://github.com/l0ss/Grouper2)
			* Grouper2 is a tool for pentesters to help find security-related misconfigurations in Active Directory Group Policy. It might also be useful for other people doing other stuff, but it is explicitly NOT meant to be an audit tool. If you want to check your policy configs against some particular standard, you probably want Microsoft's Security and Compliance Toolkit, not Grouper or Grouper2.
		* [SharpGPO-RemoteAccessPolicies](https://github.com/mwrlabs/SharpGPO-RemoteAccessPolicies)
			* A C# tool for enumerating remote access policies through group policy.
		* [Get-GPTrashFire](https://github.com/l0ss/Get-GPTrashfire/blob/master/Get-GPTrashFire.pdf)
			* Identifiying and Abusing Vulnerable Configuraitons in MS AD Group Policy
		* [SharpGPOAbuse](https://github.com/mwrlabs/SharpGPOAbuse)
			* [Blogpost](https://labs.f-secure.com/tools/sharpgpoabuse)
			* SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO. [Blogpost](https://labs.mwrinfosecurity.com/tools/sharpgpoabuse)
		* [PowerGPOAbuse](https://github.com/rootSySdk/PowerGPOAbuse)
			* Powershell version of SharpGPOAbuse for those who can't compile or if their C2 can't execute .NET Assembly straightly from memory. Highly inspired by the original C# version and the amazing PowerView.
		* [GetVulnerableGPO](https://github.com/gpoguy/GetVulnerableGPO)
    		* PowerShell script to find 'vulnerable' security-related GPOs that should be hardended
		* [Policy Plus](https://github.com/Fleex255/PolicyPlus)
			* Local Group Policy Editor plus more, for all Windows editions.
- **IPv6**
	* [Guidance for configuring IPv6 in Windows for advanced users - docs.ms](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows)
- **Kerberos**<a name="kerberos"></a>
	- **101**
		* [Kerberos (I): How does Kerberos work? – Theory - Eloy Perez](https://www.tarlogic.com/en/blog/how-kerberos-works/)
		* [Kerberos (II): How to attack Kerberos? - Eloy Perez](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
			* In this article about Kerberos, a few attacks against the protocol will be shown. In order to refresh the concepts behind the following attacks, it is recommended to check the [first part](https://www.tarlogic.com/en/blog/how-kerberos-works/) of this series which covers Kerberos theory.		* [Kerberos Attacks Questions - social.technet.ms](https://social.technet.microsoft.com/Forums/en-US/d8e19263-e4f9-49d5-b940-026b0769420a/kerberos-attacks-questions)
		* [Explain like I’m 5: Kerberos - Lynn Roots](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
		* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall, Benjamin Delpy(BHUSA 2015)](https://www.youtube.com/watch?v=lJQn06QLwEw)
			* Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions.
		* [Kerberos Attacks Questions - social.technet.ms](https://social.technet.microsoft.com/Forums/en-US/d8e19263-e4f9-49d5-b940-026b0769420a/kerberos-attacks-questions?forum=winserversecurity)
		* [Kerberos and Windows Security: Kerberos on Windows - Robert Broeckelman(2018)](https://medium.com/@robert.broeckelmann/kerberos-and-windows-security-kerberos-on-windows-3bc021bc9630)
		* [Kerberos and Attacks 101 - Tim Medin(WWHF2019)](https://www.youtube.com/watch?v=9lOFpUA25Nk)
			* Want to understand how Kerberos works? Would you like to understand modern Kerberos attacks? If so, then join Tim Medin as he walks you through how to attack Kerberos with ticket attacks and Kerberoasting. We'll cover the basics of Kerberos authentication and then show you how the trust model can be exploited for persistence, pivoting, and privilege escalation.
		- [Why is krbtgt a thing? - Chad Duffey(2019)](https://web.archive.org/web/20201203130144/https://www.chadduffey.com/2019/06/why-is-krbtgt-a-thing.html)
		* [Kerberos & Attacks 101 - Tim Medin & BHIS(2020)](https://www.youtube.com/watch?v=IBeUz7zMN24)
		* [Understanding how Kerberos works, but also WHY it works the way it does - ATTL4S(2021)](https://www.youtube.com/watch?v=4LDpb1R3Ghg)
		* [Why is Kerberos Terrible? - Steve Syfuhs(2018)](https://syfuhs.net/2018/12/31/why-is-kerberos-terrible/)
		* [(Ab)using Kerberos from Linux - Calum Boal(2020)](https://www.onsecurity.co.uk/blog/abusing-kerberos-from-linux)
			* This post aims to provide an overview of tooling available to perform common Kerberos abuse techniques from Linux. While this blog will not go into great detail about how the attacks which utilize these techniques work, references will be provided to high-quality blog posts detailing common Kerberos attacks.
	- **Overviews**
		* [Kerberos & Attacks 101 - Tim Medin(2020)](https://www.youtube.com/watch?v=IBeUz7zMN24)
			* Want to understand how Kerberos works? Would you like to understand modern Kerberos attacks? If so, then join Tim Medin as he walks you through how to attack Kerberos with ticket attacks and Kerberoasting. We'll cover the basics of Kerberos authentication and then show you how the trust model can be exploited for persistence, pivoting, and privilege escalation.
		* [Kerberos Survival Guide - MS Technet](https://social.technet.microsoft.com/wiki/contents/articles/4209.kerberos-survival-guide.aspx)
		* [Kerberosity Killed the Domain: An Offensive Kerberos Overview - Ryan Hausknecht(2020)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
	- **Articles/Blogposts/Writeups**
		* [How To Attack Kerberos 101 - m0chan](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
		* [Kerberos, Active Directory’s Secret Decoder Ring - Sean Metcalf](https://adsecurity.org/?p=227)
		* [Credential cache - MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html)
		* [Kerberos Authentication problems – Service Principal Name (SPN) issues – Part 1 - blogs.technet](https://blogs.technet.microsoft.com/askds/2008/05/29/kerberos-authentication-problems-service-principal-name-spn-issues-part-1/)
		* [Security Focus: Analysing 'Account is sensitive and cannot be delegated' for Privileged Accounts - Ian Fann(2015)](https://blogs.technet.microsoft.com/poshchap/2015/05/01/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts/)
		* [Delegating like a boss: Abusing Kerberos Delegation in Active Directory - Kevin Murphy](https://www.guidepointsecurity.com/2019/09/04/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)
		    * I wanted to write a post that could serve as a (relatively) quick reference for how to abuse the various types of Kerberos delegation that you may find in an Active Directory environment during a penetration test or red team engagement.
		* [Kerberos Tickets on Linux Red Teams - Trevor Haskell(2020)](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)   
		* [Kerberos Double-Hop Workarounds - slayerlabs.com(2020)](https://posts.slayerlabs.com/double-hop/)
	- **Talks/Presentations/Videos**
		* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall and Benjamin Delpy(BHUSA 2014)](https://www.youtube.com/watch?v=lJQn06QLwEw)
			* "Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions. Prepare to have all your assumptions about Kerberos challenged!"
			* [Slides](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It-wp.pdf)
		* [Et tu - Kerberos? - Christopher Campbell(Derbycon2014)](https://www.irongeek.com/i.php?page=videos/derbycon4/t109-et-tu-kerberos-christopher-campbell)
			* For over a decade we have been told that Kerberos is the answer to Microsoft’s authentication woes and now we know that isn’t the case. The problems with LM and NTLM are widely known- but the problems with Kerberos have only recently surfaced. In this talk we will look back at previous failures in order to look forward. We will take a look at what recent problems in Kerberos mean to your enterprise and ways you could possibly mitigate them. Attacks such as Spoofed-PAC- Pass-the-Hash- Golden Ticket- Pass-the-Ticket and Over-Pass-the-Ticket will be explained. Unfortunately- we don’t really know what is next – only that what we have now is broken.
		* [Attacking Microsoft Kerberos: Kicking the Guard Dog of Hades - Tim Medin(Derbycon2014)](https://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin)
			* Kerberos- besides having three heads and guarding the gates of hell- protects services on Microsoft Windows Domains. Its use is increasing due to the growing number of attacks targeting NTLM authentication. Attacking Kerberos to access Windows resources represents the next generation of attacks on Windows authentication.In this talk Tim will discuss his research on new attacks against Kerberos- including a way to attack the credentials of a remote service without sending traffic to the service as well as rewriting tickets to access systems.He will also examine potential countermeasures against Kerberos attacks with suggestions for mitigating the most common weaknesses in Windows Kerberos deployments.
			* [Attacking Kerberos: Kicking the Guard Dog of Hades - Tim Medin(2014)`https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf1`
		* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws - Exumbraops.com(2016)](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
			* [Slides](https://static1.squarespace.com/static/557377e6e4b0976301e02e0f/t/574a0008f85082d3b6ba88a8/1464467468683/Layer1+2016+-+Janjua+-+Kerberos+Party+Tricks+-+Weaponizing+Kerberos+Protocol+Flaws.pdf)
		* [Return From The Underworld - The Future Of Red Team Kerberos - Jim Shaver, Mitchell Hennigan(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t107-return-from-the-underworld-the-future-of-red-team-kerberos-jim-shaver-mitchell-hennigan)
			* This talk discusses Kerberos Key derivation, cracking and the future of Kerberos, kerberoasting and NTLM. Also discusses the possibilities for increased knowledge around Kerberos in the security community.
		* [Return From The Underworld - The Future Of Red Team Kerberos - Jim Shaver & Mitchell Hennigan(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t107-return-from-the-underworld-the-future-of-red-team-kerberos-jim-shaver-mitchell-hennigan)
- **LDAP**<a name="ldap"></a>
	- **101**<a name="ldap101"></a>
		* [Everything I wanted to know about #ActiveDirectory LDAP - Podalirius(2022)](https://www.youtube.com/watch?v=gD8IF0qYURI)
			* Most of modern enterprise networks heavily rely on Microsoft Windows Active Directory to create managed domains of machines. These AD domains take advantage of network protocols and services to work properly, such as Kerberos, SMB, DNS, LDAP, etc … In this talk, we will deep dive into Microsoft’s Active Directory LDAP to give you an overview of concepts, exploitation techniques and tools to interact with it.
	- **General**
		* [LDAP Swiss Army Knife - Moritz Bechler](https://www.exploit-db.com/docs/english/46986-ldap-swiss-army-knife.pdf)
		* [Fun with LDAP and Kerberos: Attacking AD from non-Windows machines - Ronnie Flathers(TR19)](https://www.youtube.com/watch?v=2Xfd962QfPs)
			* [Slides](https://speakerdeck.com/ropnop/fun-with-ldap-and-kerberos-troopers-19)
		* [Faster Domain Escalation using LDAP - Scott Sutherland](https://blog.netspi.com/faster-domain-escalation-using-ldap/)
		* [LDAP Injection Cheat Sheet, Attack Examples & Protection - Checkmarx](https://www.checkmarx.com/knowledge/knowledgebase/LDAP)
	- **C2**
		* [LDAPFragger: Command and Control over LDAP attributes - Rindert Kramer(2020)](https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/)
		* [LDAPFragger](https://github.com/fox-it/LDAPFragger)
			* LDAPFragger is a Command and Control tool that enables attackers to route Cobalt Strike beacon data over LDAP using user attributes.
		* [LDAP shell](https://github.com/PShlyundin/ldap_shell)
		* [LDAPShell](https://github.com/XiaoliChan/LDAPShell)
	- **Injection**
	- **LDAP Recon**<a name="ldaprecon"></a>
		- **101**
			* [An Introduction to Manual Active Directory Querying with Dsquery and Ldapsearch - Hope Walker(2021)](https://posts.specterops.io/an-introduction-to-manual-active-directory-querying-with-dsquery-and-ldapsearch-84943c13d7eb)
			* [LDAPSearch Reference - mubix(2022)](https://malicious.link/post/2022/ldapsearch-reference/)
		- **Queries**
			* [Useful LDAP queries for Windows Active Directory pentesting - Podalirius(2021)](https://podalirius.net/en/articles/useful-ldap-queries-for-windows-active-directory-pentesting/)
			* [Fortalice BOFHound Release - Granularize Your Active Directory Reconnaissance Game - Adam Brown(2022)](https://www.fortalicesolutions.com/posts/bofhound-granularize-your-active-directory-reconnaissance-game)
		- **Filters**
			* [LDAP Filters - ldap.com](https://ldap.com/ldap-filters/)
			* [How to write LDAP search filters - Atlassian](https://confluence.atlassian.com/kb/how-to-write-ldap-search-filters-792496933.html)
			* [Active Directory: LDAP Syntax Filters - technet.ms](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)
		- **Tools**
			* [LDAP Nom Nom](https://github.com/lkarlslund/ldapnomnom)
				* Anonymously bruteforce Active Directory usernames from Domain Controllers by abusing LDAP Ping requests (cLDAP)
				* [6.3.3.2 Domain Controller Response to an LDAP Ping - docs.ms](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3d71aefb-787e-4d14-9a8a-a70def9e1f6c)
			* [SharpLdapWhoami](https://github.com/bugch3ck/SharpLdapWhoami)
			* [msldap](https://msldap.readthedocs.io/en/latest/index.html)
			* [SilentHound](https://github.com/layer8secure/SilentHound)
				* Quietly enumerate an Active Directory Domain via LDAP parsing users, admins, groups, etc.
			* [pyladpsearch](https://github.com/fortalice/pyldapsearch)
				* This is designed to be a python "port" of the ldapsearch BOF by TrustedSec, which is a part of this repo. pyldapsearch allows you to execute LDAP queries from Linux in a fashion similar to that of the aforementioned BOF. Its output format closely mimics that of the BOF and all query output will automatically be logged to the user's home directory in .pyldapsearch/logs, which can ingested by bofhound.
			* [ADE - ActiveDirectoryEnum](https://github.com/CasperGN/ActiveDirectoryEnumeration)
				* Enumerate AD through LDAP with a collection of helpfull scripts being bundled
			* [ldsview](https://github.com/kgoins/ldsview)
				* Offline search tool for LDAP directory dumps in LDIF format.
			* [LDAP Password Hunter](https://github.com/oldboy21/LDAP-Password-Hunter)
				* LDAP Password Hunter is a tool which wraps features of getTGT.py (Impacket) and ldapsearch in order to look up for password stored in LDAP database. Impacket getTGT.py script is used in order to authenticate the domain account used for enumeration and save its TGT kerberos ticket. TGT ticket is then exported in KRB5CCNAME variable which is used by ldapsearch script to authenticate and obtain TGS kerberos tickets for each domain/DC LDAP-Password-Hunter is ran for. Basing on the CN=Schema,CN=Configuration export results a custom list of attributes is built and filtered in order to identify a big query which might contains interesting results. Results are shown and saved in a sqlite3 database.
			* [TruffleSnout](https://github.com/dsnezhkov/TruffleSnout)
				* Iterative AD discovery toolkit for offensive operators. Situational awareness and targeted low noise enumeration. Preference for OpSec.
			* [Domain Enumeration Tool](https://github.com/ZeroPointSecurity/Domain-Enumeration-Tool)
				* [Blogpost](https://offensivedefence.co.uk/posts/domain-enumeration-tool/)
				* Perform Windows domain enumeration via LDAP
			* [ADReaper](https://github.com/AidenPearce369/ADReaper)
				* ADReaper is a tool written in Golang which enumerates an Active Directory environment with LDAP queries within few seconds
			* [Get-UserSession](https://github.com/YossiSassi/Get-UserSession)
				* Queries user sessions for the entire domain (Interactive/RDP etc), allowing you to query a user and see all his logged on sessions, whether Active or Disconnected
			* [ADHuntTool](https://github.com/Mr-Un1k0d3r/ADHuntTool)
				* official report for the AdHuntTool. C# Script used for Red Team. It can be used by Cobalt Strike execute-assembly or as standalone executable.
			* [go-windapsearch](https://github.com/ropnop/go-windapsearch)
				* windapsearch is a tool to assist in Active Directory Domain enumeration through LDAP queries. It contains several modules to enumerate users, groups, computers, as well as perform searching and unauthenticated information gathering.
	- **LDAP Relaying**<a name="ldaprelay"></a>
		- **Articles**
			* [LDAP relays for initial foothold in dire situations - @SAERXCIT(2022)](https://offsec.almond.consulting/ldap-relays-for-initial-foothold-in-dire-situations.html)
				* "This article will present 3 “new” LDAP relays implemented in Impacket's ntlmrelayx.py tool, “new” in quotation marks because none of the techniques presented here are new, all are based on the work of other researchers who found the techniques/vulnerabilities, but a domain account was needed to exploit them. The "new" part is their implementation in the context of an LDAP relay so that they're exploitable from a black box situation without an account, with the ultimate goal of making it easier for the pentester to obtain the first domain account in a hardened environment. "
			* [Bypassing LDAP Channel Binding with StartTLS - @lowercase_drm(2022)](https://offsec.almond.consulting/bypassing-ldap-channel-binding-with-starttls.html)
			* [LDAP Relay - PentestEverything](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/adversary-in-the-middle/ldap-relay)
			* [Obtaining LAPS Passwords Through LDAP Relaying Attacks - Adam Crosser(2020)](https://www.praetorian.com/blog/obtaining-laps-passwords-through-ldap-relaying-attacks/)
			* [I’m bringing relaying back: A comprehensive guide on relaying anno 2022 - Jean-Francois Maes(2022)](https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/)
			* [We Love Relaying Credentials: A Technical Guide to Relaying Credentials Everywhere - Leandro Cuozzo(2022)](https://www.secureauth.com/blog/we-love-relaying-credentials-a-technical-guide-to-relaying-credentials-everywhere/)
		- **Tools**
			* [Impacket]()
			* [ntlmrelayx]()
			* [LDAP Relay Scan](https://github.com/zyn3rgy/LdapRelayScan)
				* A tool to check Domain Controllers for LDAP server protections regarding the relay of NTLM authentication. If you're interested in the specifics of the error-based enumeration, see below. For details regarding what can be done when you identify a lack of LDAP protections, see the references section.
	- **Request Signing**<a name="ldapsign"></a>
		- **Articles/Blogposts/Writeups**
			* [Are you using LDAP over SSL/TLS? - Kurt Roggen(2018)](https://kurtroggen.wordpress.com/2018/08/03/are-you-using-ldap-over-ssl-tls/)
			* [Step by Step: Enforce Require LDAP Signing on domain controllers. Part 1 - Amine Tahri(2019)](https://azurecloudai.blog/2019/08/03/step-by-step-enforce-require-ldap-signing-on-domain-controllers-part-1/)
				* [Part 2](https://azurecloudai.blog/2019/08/04/step-by-step-enforce-require-ldap-signing-on-domain-controllers-part-2/)
			* [Four commands to help you track down insecure LDAP Bindings before March 2020 - Przemyslaw Klys](https://evotec.xyz/four-commands-to-help-you-track-down-insecure-ldap-bindings-before-march-2020/)		
		- **Tools**
			* [LdapSignCheck](https://github.com/cube0x0/LdapSignCheck)
				* Beacon Object File to scan a Domain Controller to see if LdapEnforceChannelBinding or LdapServerIntegrity has been modified to mitigate against relaying attacks.
			* [ldap-scanner](https://github.com/GoSecure/ldap-scanner)
				* Checks for signature requirements over LDAP. The script will establish a connection to the target host(s) and request authentication without signature capability. If this is accepted, it means that the target hosts allows unsigned LDAP sessions and NTLM relay attacks are possible to this LDAP service (whenever signing is not requested by the client).
	- **Talks & Presentations**
		* [Fun with LDAP and Kerberos: Attacking AD from non-Windows machines - Ronnie Flathers(Troopers19)](https://www.youtube.com/watch?v=2Xfd962QfPs)
			* [Slides](https://speakerdeck.com/ropnop/fun-with-ldap-and-kerberos-troopers-19)
			* You don’t need Windows to talk to Windows. This talk will explain and walk through various techniques to (ab)use LDAP and Kerberos from non-Windows machines to perform reconnaissance, gain footholds, and maintain persistence, with an emphasis on explaining how the attacks and protocols work. This talk will walk through some lesser known tools and techniques for doing reconnaissance and enumeration in AD environments, as well as gaining an initial foothold, and using credentials in different, stealthier ways (i.e. Kerberos). While tools like Bloodhound, CrackMapExec and Deathstar have made footholds and paths to DA very easy and automated, this talk will instead discuss how tools like this work “under-the-hood” and will stress living off the land with default tools and manual recon and exploitation. After discussing some of the technologies and protocols that make up Active Directory Domain Services, I’ll explain how to interact with these using Linux tools and Python. You don’t need a Windows foothold to talk Windows - everything will be done straight from Linux using DNS, LDAP, Heimdal Kerberos, Samba and Python Impacket.
	- **Tools**
		* [eLdap-Ldap-Search-and-Filter](https://github.com/EmreOvunc/eLdap-Ldap-Search-and-Filter)
			* eLdap is a tool that helps users searching and filtering queries in Ldap environment.
		* [ADCollector](https://github.com/dev-2null/ADCollector)
			* ADCollector is a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors. It will give you a basic understanding of the configuration/deployment of the environment as a starting point.
		* [DumpLDAP](https://github.com/dcsync/adtools)
			* DumpLDAP dumps an LDAP server to json. This allows for offline exploration and better network opsec.
		* [ldap2json](https://github.com/p0dalirius/ldap2json)
			* The ldap2json script allows you to extract the whole LDAP content of a Windows domain into a JSON file.
		* [LDAP Monitor](https://github.com/p0dalirius/LDAPmonitor)
			* Monitor creation, deletion and changes to LDAP objects live during your pentest or system administration!
		* [LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump)
			* In an Active Directory domain, a lot of interesting information can be retrieved via LDAP by any authenticated user (or machine). This makes LDAP an interesting protocol for gathering information in the recon phase of a pentest of an internal network. A problem is that data from LDAP often is not available in an easy to read format. ldapdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via LDAP and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files.
		* [windapsearch](https://github.com/ropnop/windapsearch)
			* windapsearch is a Python script to help enumerate users, groups and computers from a Windows domain through LDAP queries. By default, Windows Domain Controllers support basic LDAP operations through port 389/tcp. With any valid domain account (regardless of privileges), it is possible to perform LDAP queries against a domain controller for any AD related information. You can always use a tool like ldapsearch to perform custom LDAP queries against a Domain Controller. I found myself running different LDAP commands over and over again, and it was difficult to memorize all the custom LDAP queries. So this tool was born to help automate some of the most useful LDAP queries a pentester would want to perform in an AD environment.
		* [msldap](https://github.com/skelsec/msldap)
			* [Documentation](https://msldap.readthedocs.io/en/latest/)
			* LDAP library for MS AD	
- **KMS**<a name="kms"></a>
	- **Tools**
		* [py-kms](https://github.com/SystemRage/py-kms)
			* py-kms is a port of node-kms created by cyrozap, which is a port of either the C#, C++, or .NET implementations of KMS Emulator. The original version was written by CODYQX4 and is derived from the reverse-engineered code of Microsoft's official KMS.
- **LAPS**<a name="laps"></a>
	- **101**
		* [Local Administrator Password Solution - docs.ms](https://docs.microsoft.com/en-us/previous-versions/mt227395(v=msdn.10)?redirectedfrom=MSDN)
	- **Articles/Blogposts/Writeups**
		* [Running LAPS with PowerView - harmj0y](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
		* [RastaMouse LAPS Part 1 & 2](https://rastamouse.me/tags/laps/)
		* [Mise en place d'une Backdoor LAPS via modification de l'attribut SearchFlags avec DCShadow - Gregory Lucand](https://adds-security.blogspot.com/2018/08/mise-en-place-dune-backdoor-laps-via.html)
		* [Malicious use of Microsoft LAPS - akijos](https://akijosberryblog.wordpress.com/2019/01/01/malicious-use-of-microsoft-laps/)
		* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon - adsecurity.org](https://adsecurity.org/?p=3164)
		* [Running LAPS Around Cleartext Passwords - Karl Fosaaen](https://blog.netspi.com/running-laps-around-cleartext-passwords/)
	- **Tools**
		* [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
			* Tool to audit and attack LAPS environments
		* [Crackmapexec-LAPS](https://github.com/T3KX/Crackmapexec-LAPS)
- **Lync**<a name="lync"></a>
	* [LyncSniper](https://github.com/mdsecresearch/LyncSniper)
		* A tool for penetration testing Skype for Business and Lync deployments
		* [Blogpost/Writeup](https://www.mdsec.co.uk/2017/04/penetration-testing-skype-for-business-exploiting-the-missing-lync/)
	* [LyncSmash](https://github.com/nyxgeek/lyncsmash)
		* a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
		* [Talk](https://www.youtube.com/watch?v=v0NTaCFk6VI)
		* [Slides](https://github.com/nyxgeek/lyncsmash/blob/master/DerbyCon%20Files/TheWeakestLync.pdf)
- **MachineAccountQuota**<a name="maqt"></a>
	- **101**
		* [MS-DS-Machine-Account-Quota attribute - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)
	- **Articles/Blogposts/Writeups**
		* The number of computer accounts that a user is allowed to create in a domain.
		* [MachineAccountQuota is USEFUL Sometimes: Exploiting One of Active Directory’s Oddest Settings - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)
		* [MachineAccountQuota Transitive Quota: 110 Accounts and Beyond - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-transitive-quota/)
		* [PowerMAD](https://github.com/Kevin-Robertson/Powermad)
			* PowerShell MachineAccountQuota and DNS exploit tools
			* [Blogpost](https://blog.netspi.com/exploiting-adidns/)
- **MS-SAMR**<a name="mssamr"></a>
	* [[MS-SAMR]: Security Account Manager (SAM) Remote Protocol (Client-to-Server) - docs.ms](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380)
		* Specifies the Security Account Manager (SAM) Remote Protocol, which supports management functionality for an account store or directory containing users and groups. The goal of the protocol is to enable IT administrators and users to manage users, groups, and computers.
	* [[MS-WKST]: Workstation Service Remote Protocol - docs.ms](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/5bb08058-bc36-4d3c-abeb-b132228281b7)
		* Specifies the Workstation Service Remote Protocol, which remotely queries and configures certain aspects of a Server Message Block network redirector on a remote computer.
- **MS SQL Server**<a name="mssql"></a>
	- **Articles/Blogposts/Writeups**
		* [Hacking SQL Server on Scale with PowerShell - Secure360 2017](https://www.slideshare.net/nullbind/2017-secure360-hacking-sql-server-on-scale-with-powershell)
		* [Using SQL Server for attacking a Forest Trust](http://www.labofapenetrationtester.com/2017/03/using-sql-server-for-attacking-forest-trust.html)
		* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki)
			* [2018 Blackhat USA Arsenal Presentation](https://www.youtube.com/watch?reload=9&v=UX_tBJQtqW0&feature=youtu.be)
		* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server! - Annti Rantasaari(2013)](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
- **Read-Only Domain Controllers**<a name="rodc"></a>
	- **101**
		* [Read-Only DCs and the Active Directory Schema - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema)
			* Windows Server 2008 introduces a new type of domain controller, the Read-only Domain Controller (RODC). This provides a domain controller for use at branch offices where a full domain controller cannot be placed. The intent is to allow users in the branch offices to logon and perform tasks like file/printer sharing even when there is no network connectivity to hub sites.
	- **Articles/Blogposts/Writeups**
		* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)
- **Red Forest**<a name="redforest"></a>
	- **101**
		* [Improving security by protecting elevated-privilege accounts at Microsoft - microsoft.com(2019)](https://www.microsoft.com/en-us/itshowcase/improving-security-by-protecting-elevated-privilege-accounts-at-microsoft)
		* [Active Directory Red Forest Design aka Enhanced Security Administrative Environment (ESAE) - social.technet](https://social.technet.microsoft.com/wiki/contents/articles/37509.active-directory-red-forest-design-aka-enhanced-security-administrative-environment-esae.aspx)
	- **Articles/Blogposts/Writeups**
		* [Privileged Access Workstations - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/privileged-access-workstations)
		* [Planting the Red Forest: Improving AD on the Road to ESAE - Katie Knowles](https://www.f-secure.com/us-en/consulting/our-thinking/planting-the-red-forest-improving-ad-on-the-road-to-esae)
		* [What is Microsoft ESAE and Red Forest - David Rowe](https://www.secframe.com/blog/what-is-microsoft-esae-and-red-forest)
	- **Talks/Presentations/Videos**
		* [From Workstation to Domain Admin: Why Secure Administration Isn't Secure and How to Fix It - Sean Metcalf(BHUSA2018)]()
			* [Slides](https://adsecurity.org/wp-content/uploads/2018/08/us-18-Metcalf-From-Workstation-To-Domain-Admin-Why-Secure-Administration-Isnt-Secure-Final.pdf)
		* [Attack and defend Microsoft Enhanced Security Administrative Environment - Hao Wang, Yothin Rodanant(Troopers2018)](https://www.youtube.com/watch?v=0AUValgPTUs)
			* [Slides](https://download.ernw-insight.de/troopers/tr18/slides/TR18_AD_Attack-and-Defend-Microsoft-Enhanced-Security.pdf)
			* Microsoft Enhanced Security Administrative Environment (ESAE) known as “Red Forest” has become a very popular architecture solution to enhance the security of Active Directory. Can ESAE be used to completely prevent cyber attackers from compromising Active Directory? In this talk, we will demonstrate the commonly overlooked techniques that can be used to obtain domain dominance within ESAE.
		* [Tiered Administrative Model - ESAE - Active Directory Red Forest Architecture - Russel Smith(2018)](https://www.youtube.com/watch?v=t4I2saNpoFE)
		* [Understanding “Red Forest”: The 3-Tier Enhanced Security Admin Environment (ESAE) and Alternative Ways to Protect Privileged Credentials - ultimatewindowsecurity.com](https://www.ultimatewindowssecurity.com/webinars/register.aspx?id=1409)
- **Security Identifiers**<a name="sids"></a>
	* [Security Identifiers - docs.ms](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows)
		* This article describes how security identifiers (SIDs) work with accounts and groups in the Windows Server operating system.
- **Service Principal Names**<a name="spn"></a>
	* **101**
		* [Service Principal Names - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)
		* [Service Principal Names - docs.ms(older documentation)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961723(v=technet.10))
		* [Register a Service Principal Name for Kerberos Connections - docs.ms](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-2017)
	- **Articles/Blogposts/Writeups**
		* [Active Directory Pentest Recon Part 1: SPN Scanning aka Mining Kerberos Service Principal Names - Sean Metcalf](https://adsecurity.org/?p=230)
		* [SPN Discovery - pentestlab.blog](https://pentestlab.blog/2018/06/04/spn-discovery/)
		* [Service Principal Name (SPN) - hackndo](https://en.hackndo.com/service-principal-name-spn/)
		* [SPNs - adsecurity.org](https://adsecurity.org/?page_id=183)
			* This page is a comprehensive reference (as comprehensive as possible) for Active Directory Service Principal Names (SPNs). As I discover more SPNs, they will be added.
		* [Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe - social.technet.ms.com)](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx)
		* See: [Kerberoasting](#kerberoasting)
- **System Center Configuration Manager**<a name="sccm"></a>
    * [Targeted Workstation Compromise with SCCM - enigma0x3(2015)](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/)
        * [LM Hash and NT Hash - AD Shot Gyan(2012)](http://www.adshotgyan.com/2012/02/lm-hash-and-nt-hash.html)
	* [Using SCCM to violate best practices - cr0n1c(2016)](https://cr0n1c.wordpress.com/2016/01/27/using-sccm-to-violate-best-practices/)
----------------------------------------









----------------------------------------
### <a name="adattack"></a>Attack Active Directory/Specific Techniques
- **Attack Path Writeups/Samples**<a name="attackpaths"></a>
	- **Articles/Blogposts/Writeups**
		* [Domain Penetration Testing: Using BloodHound, Crackmapexec, & Mimikatz to get Domain Admin - Hausec(2017)](https://hausec.com/2017/10/21/domain-penetration-testing-using-bloodhound-crackmapexec-mimikatz-to-get-domain-admin/)
		* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher(2018)](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
		* [No Shells Required - a Walkthrough on Using Impacket and Kerberos to Delegate Your Way to DA  - redxorblue(2019)](http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html)
		* [The Attack Path Management Manifesto - Andy Robbins(2021)](https://posts.specterops.io/the-attack-path-management-manifesto-3a3b117f5e5)
		* [Who Let the ARPs Out? - From ARP Spoof to Domain Compromise - Joe Minicucci(2021)](https://blog.joeminicucci.com/2021/who-let-the-arps-out-from-arp-spoof-to-domain-compromise)
		* [From Default Printer Credentials to Domain Admin - Olivier Laflamme(2021)](https://boschko.ca/printer-to-domain-admin/)
		* [PKINIT FTW - Chaining Shadow Credentials and ADCS Template Abuse - Matthew Creel(2020)](https://www.fortalicesolutions.com/posts/pkinit-ftw-chaining-shadow-credentials-and-adcs-template-abuse)
		* [Admin’s Nightmare: Combining HiveNightmare/SeriousSAM and AD CS Attack Path’s for Profit - Steve Borosh(2021)](https://www.blackhillsinfosec.com/admins-nightmare-combining-hivenightmare-serioussam-and-ad-cs-attack-paths-for-profit/)
		* [Domain Compromise via DC Print Server and Kerberos Delegation - spotheplanet](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
		* [PetitPotam – NTLM Relay to AD CS - NetbiosX(2021)](https://pentestlab.blog/2021/09/14/petitpotam-ntlm-relay-to-ad-cs/)
		* [Certifried combined with KrbRelayUp - tothi](https://gist.github.com/tothi/f89a37127f2233352d74eef6c748ca25)
			* Certifried combined with KrbRelayUp: non-privileged domain user to Domain Admin without adding/pre-owning computer accounts
		- Cisco Call Manager
			* [SeeYouCM-Thief: Exploiting common misconfigurations in Cisco phone systems - Justin Bollinger(2022)](https://www.trustedsec.com/blog/seeyoucm-thief-exploiting-common-misconfigurations-in-cisco-phone-systems/)
			* [Unauthenticated Dumping of Usernames via Cisco Unified Call Manager (CUCM) - n00py(2022)](https://www.n00py.io/2022/01/unauthenticated-dumping-of-usernames-via-cisco-unified-call-manager-cucm/)
			* [iCULeak.py](https://github.com/llt4l/iCULeak.py)
	- **Talks/Presentations/Videos**
		* [ Building the DeathStar: getting Domain Admin with a push of a button (a.k.a. how I almost automated myself out of a job) - Marcello Salvati(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t109-building-the-deathstar-getting-domain-admin-with-a-push-of-a-button-aka-how-i-almost-automated-myself-out-of-a-job-marcello-salvati)
			* Ever since the advent of tools like PowerSploit, Empire, Bloodhound and CrackMapExec pentesting Active Directory has become a pretty straight forward and repetitive process for 95% of all the environments that I get dropped into. This begs the question: can the process of going from an unprivileged domain user to Domain Admin be automated? Well obviously, since this talk is a thing, the answer is yes! Introducing the DeathStar: a Python script that leverages Empire 2.0's RESTful API to automate the entire AD pentesting process from elevating domain rights, spreading laterally and hunting down those pesky Domain Admins! This talk will mainly focus on how DeathStar works under the hood, how to properly defend against it and the most common AD misconfigurations/vulnerabilities that I see in almost every environment which allow for this script to be so effective. It will then conclude with live demos of the tool in action (which hopefully will not fail miserably) and some final considerations from yours truly. 
		* [Icebreaker - From internal jumpbox to domain admin in one command - Dan McInerney(BSidesSLC2018)](https://www.youtube.com/watch?v=ahvn-L70VYc&list=PLqVzh0_XpLfTHHo8f8Xz8BfUG8B5S-iPJ&index=4)
			* Icebreaker automates 5 different internal network attacks to gain access to plaintext and hashed credentials from Active Directory environments. Whenever hashed credentials are found Icebreaker will automatically attempt to crack them. After successfully performing the network attacks Icebreaker can kick off the tools Empire and DeathStar to automate the process of escalating privileges all the way to domain admin without any user interaction. This talk will discuss how and why all 5 of these network attacks work as well as how DeathStar uses the found credentials to escalate privileges.
		* [[Attack]tive Directory: Compromising a Network in 20 Minutes Through Active Directory - Ryan Hausnecht(2021)](https://www.youtube.com/watch?v=MIt-tIjMr08)
- **Abusing ACEs & ACLs**<a name="aces"></a>
	- **Articles/Blogposts/Writeups**
	- **Talks/Presentations/Videos**
	- **Tools**
- **Across Trusts and Domains**<a name="crosspriv"></a>
	- **Articles/Blogposts/Writeups**
	- **Talks/Presentations/Videos**
	- **Tools**
- **Certificate Services (Attacking)**<a name="certattack"></a>
	- **Articles/Blogposts/Writeups**
		* [Supply in the Request Shenanigans - Carl Sorqvist(2020)](https://blog.qdsecurity.se/2020/09/04/supply-in-the-request-shenanigans/)
		* [Certified Pre-Owned: Abusing Active Directory Certificate Services - Will Schroeder, Lee Christensen(2021)](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
			* [Blogpost](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
		* [KB5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services (AD CS) - support.ms(2021)](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
		* [Certificate Services (AD-CS) - thehacker.recipes](https://www.thehacker.recipes/ad/movement/ad-cs)
		* [Microsoft ADCS – Abusing PKI in Active Directory Environment - Jean Marsault(2021)](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/)
		* [NTLM relaying to AD CS - On certificates, printers and a little hippo  - Dirk-jan Mollema(2021)](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
		* [AD CS relay attack - practical guide - @exandroiddev(2021)](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)
		* [Active Directory Certificate Services (ADCS - PKI) domain admin vulnerability - Bojan Zdrnja(2021)](https://isc.sans.edu/diary/27668)
		* [From Stranger to DA // Using PetitPotam to NTLM relay to Domain Administrator - Ben Bidmead(2021)](https://blog.truesec.com/2021/08/05/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory/)
		* [Abusing Weak ACL on Certificate Templates - daem0nc0re(2021)](https://github.com/daem0nc0re/Abusing_Weak_ACL_on_Certificate_Templates)
		* [NTLM relaying to AD CS - On certificates, printers and a little hippo - Dirk-jan Mollema(2021)](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
		* [Golden Certificate - NetbiosX(2022)](https://pentestlab.blog/2021/11/15/golden-certificate/)
		* [AD CS: weaponizing the ESC7 attack - Kurosh Dabbagh(2022)](https://www.tarlogic.com/blog/ad-cs-esc7-attack/)
		* [ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate - spotheplanet(2022)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate)
		* [AD CS: from ManageCA to RCE - Pablo Martínez, Kurosh Dabbagh](https://www.tarlogic.com/blog/ad-cs-manageca-rce/)
		* [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) - Oliver Lyak(2022)](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
		* [Living off the land, AD CS style - Ceri Coburn(2022)](https://www.pentestpartners.com/security-blog/living-off-the-land-ad-cs-style/)
		* [Skidaddle Skideldi - I just pwnd your PKI - LuemmelSec(2022)](https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/)
	- **Talks/Presentations/Videos**
		* [Abusing Active Directory Certificate Services as a beacon operator - Flangvik(2021)](https://www.youtube.com/watch?v=W9pUCVxe59Q)
		* [AD CS means “Active Directory is Cheese (Swiss)” - Jake Hildreth(BSidesCharm(2022)](https://www.youtube.com/watch?v=TVIej2N-sYo)
	- **Tools**
		- **Attacking**
			* https://github.com/SammyKrosoft/CertReq.Inf
			* [Certipy](https://github.com/ly4k/Certipy)
				* [Certipy 2.0: BloodHound, New Escalations, Shadow Credentials, Golden Certificates, and more! - Oliver Lyak(2022)](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6)
				* Certipy is an offensive tool for enumerating and abusing Active Directory Certificate Services (AD CS).
			* [PetitPotam](https://github.com/topotam/PetitPotam)
				* PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw function.
			* [Certify](https://github.com/GhostPack/Certify)
			* [Certipy](https://github.com/ly4k/Certipy)
			* [ForgeCert](https://github.com/GhostPack/ForgeCert)
			* [pyForgeCert](https://github.com/Ridter/pyForgeCert)
				* pyForgeCert is a Python equivalent of the ForgeCert.
			* [PKINITtools](https://github.com/dirkjanm/PKINITtools)
				* Tools for Kerberos PKINIT and relaying to AD CS 
			* [ADCSPwn](https://github.com/bats3c/ADCSPwn)
				* A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts (Petitpotam) and relaying to the certificate service.
			* [EfsPotaot](https://github.com/zcgonvh/EfsPotato)
				*  Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability). 
			* LoLBin to trigger relayable NTLM auth over RPC: (Antonio Cocomazzi)
				* `rpcping -s 10.0.0.35 -e 9997 /a connect /u NTLM`
			* [WebClient Service Scanner](https://github.com/Hackndo/WebclientServiceScanner)
				* Python tool to Check running WebClient services on multiple targets based on @leechristensen 
		
		- **Detection**
			* [Invoke-Leghorn](https://github.com/RemiEscourrou/Invoke-Leghorn)
				* Standalone powershell script to detect potential PKI abuse
			* [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit)
				* PowerShell toolkit for auditing Active Directory Certificate Services (AD CS).
- **Coerced Authentication**<a name="coercedauth"></a>
	* Microsoft does not consider coerced authentications as security vulnerability.
	- **Articles/Blogposts/Writeups**
		* [Starting WebClient Service Programmatically - James Forshaw(2015)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)
		* [Windows Coerced Authentication Methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
			* This repository contains a list of many methods to coerce a windows machine to authenticate to an attacker-controlled machine. 
		* [Coercing NTLM Authentication from SCCM - Chris Thompson(2022)](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
		* [MS-FSRVP abuse (ShadowCoerce) - TheHackerRecipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp)
		* [From RpcView to PetitPotam - itm4n(2021)](https://itm4n.github.io/from-rpcview-to-petitpotam/)
		* [Chasing the Silver Petit Potam to Domain Admin - Andy Gil(2022)](https://blog.zsec.uk/chasing-the-silver-petit-potam/)
		* [Dropping Files on a Domain Controller Using CVE-2021-43893 - Jake Baines(2022)](https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/)
		* [From RPC to RCE - Workstation Takeover via RBCD and MS-RPChoose-Your-Own-Adventure - gladiatx0r](https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb#rpc-to-rce-steps)
	- **Talks/Presentations/Videos**
		* [Coercions and Relays - The First Cred is the Deepest with Gabriel Prud'homme(BHIS2022)](https://www.youtube.com/watch?v=b0lLxLJKaRs)
			* "In this 1.5-HOUR, Black Hills Information Security (BHIS) webcast, Gabriel Prud'homme will cover network protocol poisoning, relays, and abuses. Learn how to use Responder, Ntlmrelayx, and Mitm6. From PetitPotam to WebDAV remote and local privilege escalation, and much more. "
	- **Tools**
		* [Coercer](https://github.com/p0dalirius/Coercer)
		* [PetitPotam](https://github.com/topotam/PetitPotam)
		* [Server Service Authentication Coerce Vulnerability](https://github.com/akamai/akamai-security-research/tree/main/cve-2022-30216)
			* [CVE-2022-30216 - Authentication coercion of the Windows “Server” service - Akamai Security Research(2022](https://www.akamai.com/blog/security/authentication-coercion-windows-server-service)
			* This is the git repository for the PoC of the srvsvc auth coerce vulnerability (CVE-2022-30216).
		* [CheeseOunce](https://github.com/evilashz/CheeseOunce)
			* This Simple POC make windows machines auth to another via MS-EVEN.
		* [PetitPotam Python](https://github.com/ly4k/PetitPotam)
		* [SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers)
			* Collection of remote authentication triggers coded in C# using MIDL compiler for avoiding 3rd party dependencies.
		* [MSSQL Analysis Services - Coerced Authentication](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)
		* [ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce)
			* MS-FSRVP coercion abuse PoC
		* [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce)
			* PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot (found by @xct_de) methods.
		* [cornershot](https://github.com/zeronetworks/cornershot)
			* ID network accessibility using RPC Co-erced auth
		* [SpoolSample](https://github.com/leechristensen/SpoolSample)
- **Credential Attacks**<a name="adcred"></a>
	- **101**
		* [Cached and Stored Credentials Technical Overview - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v=ws.11))
			* This topic for the IT professional describes how credentials are formed in Windows and how the operating system manages them. Applies To: Windows Vista, Windows Server 2008, Windows 7, Windows 8.1, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2012, Windows 8
		* [Credentials Processes in Windows Authentication - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)
			* This reference topic for the IT professional describes how Windows authentication processes credentials. Applies To: Windows Server (Semi-Annual Channel), Windows Server 2016
		* [Cached Credentials: Important Facts That You Cannot Miss - CQURE](https://cqureacademy.com/blog/windows-internals/cached-credentials-important-facts)
		* [Security Focus: Analysing 'Account is sensitive and cannot be delegated' for Privileged Accounts - Ian Farr(MSFT2015)](https://blogs.technet.microsoft.com/poshchap/2015/05/01/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts/)
			* There are a number of configuration options we recommend for securing high privileged accounts. One of them, enabling 'Account is sensitive and cannot be delegated', ensures that an account’s credentials cannot be forwarded to other computers or services on the network by a trusted application. 
		* [Protected Users Security Group - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn466518(v%3Dws.11))
		* AD DS: Fine-Grained Password Policies - docs.ms - `https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc770394(v=ws.10)`
		* [Clearing cached/saved Windows credentials - University of Waterloo](https://uwaterloo.teamdynamix.com/TDClient/1804/Portal/KB/ArticleDet?ID=69756)
		* [Protect derived domain credentials with Windows Defender Credential Guard - docs.ms](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
		* [KB2871997 and Wdigest - Part 1 - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/kfalde/kb2871997-and-wdigest-part-1)
		* [Network security: LAN Manager authentication level - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)
			* Describes the best practices, location, values, policy management and security considerations for the Network security: LAN Manager authentication level security policy setting. This policy setting determines which challenge or response authentication protocol is used for network logons.
	- **General Articles**
		* [Windows authentication attacks part 2 – kerberos - Ahmed Sultan(2020](https://blog.redforce.io/windows-authentication-attacks-part-2-kerberos/)
		* [Cleartext Shenanigans: Gifting User Passwords to Adversaries With NPPSPY - Dray Agha(2022)](https://www.huntress.com/blog/cleartext-shenanigans-gifting-user-passwords-to-adversaries-with-nppspy)
		* [Auto-Dumping Domain Credentials using SPNs, PowerShell Remoting, and Mimikatz - Scott Sutherland](https://blog.netspi.com/auto-dumping-domain-credentials-using-spns-powershell-remoting-and-mimikatz/)
		* [Password Hunting with Machine Learning in Active Directory - HunniCyber](https://blog.hunniccyber.com/password-hunting-with-ml-in-active-directory/)
			* tdlr: Situation: - Passwords embedded in files on fileshares lead to compromise. Complication: - It is hard to tell what is a password. Resolution: - Use SharpML to scan.
	- **Auth Providers**
		* [Network Provider: Sneaky alternative to extract credentials - Michael Schneider(2022)](https://www.scip.ch/en/?labs.20220217)
	- **Brute-Force Attacks**
		* [Security Advisory: Targeting AD FS With External Brute-Force Attacks - Yaron Zinar](https://www.preempt.com/blog/security-advisory-targeting-ad-fs-with-external-brute-force-attacks/)
	- **Cached Credentials**
		* [Cached Credentials: Important Facts That You Cannot Miss - Paula@Cqure](https://cqureacademy.com/blog/hacks/cached-credentials-important-facts)
	- **Dumping NTDS.dit**<a name="ntdsdit"></a>
		* **101**
			* [How the Data Store Works - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772829(v=ws.10)?redirectedfrom=MSDN#w2k3tr_adstr_how_jddq)
		* **Articles/Blogposts/Writeups**
			* [Volume Shadow Copy NTDS.dit Domain Hashes Remotely - Part 1  - mubix(2013)](https://malicious.link/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/)
			* [How Attackers Pull the Active Directory Database (NTDS.dit) from a Domain Controller - ADSecurity(2014)](https://adsecurity.org/?p=451)
			* [Obtaining NTDS.Dit Using In-Built Windows Commands - Cyberis(2014)](https://www.cyberis.co.uk/2014/02/obtaining-ntdsdit-using-in-built.html)
			* [Using Domain Controller Account Passwords To HashDump Domains - Mubix(2015)](https://room362.blogspot.com/2015/09/using-domain-controller-account.html)
			* [How Attackers Dump Active Directory Database Credentials - adsecurity.org(2016](https://adsecurity.org/?p=2398)
			* [Practice ntds.dit File Part 2: Extracting Hashes - Didier Stevens(2016)](https://blog.didierstevens.com/2016/07/13/practice-ntds-dit-file-part-2-extracting-hashes/)
			* [Extracting Hashes and Domain Info From ntds.dit - ropnop(2017)](https://blog.ropnop.com/extracting-hashes-and-domain-info-from-ntds-dit/)
			* [Dumping Domain Password Hashes - Pentestlab.blog(2018)](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
			* [Remotely dump "Active Directory Domain Controller" machine user database using web shell - Indishell(2018)](http://www.mannulinux.org/2018/12/remotely-dump-active-directory-domain.html)
			* [Credential Dumping: NTDS.dit - Yashika Dir(2020)](https://www.hackingarticles.in/credential-dumping-ntds-dit/)
			* [Extracting Password Hashes From The Ntds.dit File - Jeff Warren(2022)](https://blog.stealthbits.com/extracting-password-hashes-from-the-ntds-dit-file/)	
		- **Tools**
			* [adXtract](https://github.com/LordNem/adXtract)
			* [DIT Snapshot Viewer](https://github.com/yosqueoy/ditsnap)
				* DIT Snapshot Viewer is an inspection tool for Active Directory database, ntds.dit. This tool connects to ESE (Extensible Storage Engine) and reads tables/records including hidden objects by low level C API. The tool can extract ntds.dit file without stopping lsass.exe. When Active Directory Service is running, lsass.exe locks the file and does not allow to access to it. The snapshot wizard copies ntds.dit using VSS (Volume Shadow Copy Service) even if the file is exclusively locked. As copying ntds.dit may cause data inconsistency in ESE DB, the wizard automatically runs esentutil /repair command to fix the inconsistency.
			* [NTDSXtract - Active Directory Forensics Framework](http://www.ntdsxtract.com/)
				* This framework was developed by the author in order to provide the community with a solution to extract forensically important information from the main database of Microsoft Active Directory (NTDS.DIT).
			* [NTDSDumpEx](https://github.com/zcgonvh/NTDSDumpEx)
				* NTDS.dit offline dumper with non-elevated
			* [NTDS-Extraction-Tools](https://github.com/robemmerson/NTDS-Extractions-Tools)
				* Automated scripts that use an older version of libesedb (2014-04-06) to extract large NTDS.dit files
			* [gosecretsdump](https://github.com/C-Sto/gosecretsdump)
				* This is a conversion of the impacket secretsdump module into golang. It's not very good, but it is quite fast. Please let me know if you find bugs, I'll try and fix where I can - bonus points if you can provide sample .dit files for me to bash against.
	- **Empty Passwords**
		* [Abusing empty passwords during your next red teaming engagement - Tijme Gommers, Jules Adriaens](https://northwave-security.com/abusing-empty-passwords-during-your-next-red-teaming-engagement/)
	- **Internal Monologue**
		* see "Internal Monologue" from main ToC.
	- **Local Account Passwords**
		* [Attacking Local Account Passwords - Jeff Warren(2017)](https://blog.stealthbits.com/attacking-local-account-passwords/)
		* [Brute Forcing Admin Passwords with UAC - Mark Mo(2019)](https://medium.com/@markmotig/brute-forcing-admin-passwords-with-uac-e711c551ad7e)
	- **MSCACHE**
		* [Credential Dumping: Domain Cache Credential - Raj Chandel(2020)](https://www.hackingarticles.in/credential-dumping-domain-cache-credential/)
		* [mscache](https://github.com/QAX-A-Team/mscache)
			* a tool to manipulate dcc(domain cached credentials) in windows registry, based mainly on the work of mimikatz and impacket
	- **MFA-Related**
		* [Multi-Factor Mixup: Who Were You Again? - Okta](https://www.okta.com/security-blog/2018/08/multi-factor-authentication-microsoft-adfs-vulnerability/)
			* A weakness in the Microsoft ADFS protocol for integration with MFA products allows a second factor for one account to be used for second-factor authentication to all other accounts in an organization.
	- **Net-NTLM**
		* [Places of Interest in Stealing NetNTLM Hashes - osandamalith.com](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
		* [Live off the Land and Crack the NTLMSSP Protocol - Mike Gualteieri(2020)](https://www.mike-gualtieri.com/posts/live-off-the-land-and-crack-the-ntlmssp-protocol)
	- **NetNTLMtoSilverTicket**
		* [SpoolSample -> NetNTLMv1 -> NTLM -> Silver Ticket](https://github.com/NotMedic/NetNTLMtoSilverTicket/)
			* This technique has been alluded to by others, but I haven't seen anything cohesive out there. Below we'll walk through the steps of obtaining NetNTLMv1 Challenge/Response authentication, cracking those to NTLM Hashes, and using that NTLM Hash to sign a Kerberos Silver ticket. This will work on networks where "LAN Manager authentication level" is set to 2 or less. This is a fairly common scenario in older, larger Windows deployments. It should not work on Windows 10 / Server 2016 or newer.
	- **NPLogonNotify function**
		* [NPLogonNotify function - docs.ms](https://learn.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify)
		* [NPPSpy](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy)
			* Simple (but fully working) code for NPLogonNotify(). The function obtains logon data, including cleartext password.
	- **Offline-based**
		* [Active Directory Offline Hash Dump and Forensic Analysis - Csaba Barta(2011)](https://web.archive.org/web/20131008171714/http://www.ntdsxtract.com/downloads/ActiveDirectoryOfflineHashDumpAndForensics.pdf)
		* [Offline Attacks on Active Directory - Michael Grafnetter](https://cqureacademy.com/cqure-labs/cqlabs-dsinternals-powershell-module)
			* This lab will guide you through some of the most interesting features of the [DSInternals PowerShell Module](https://github.com/MichaelGrafnetter/DSInternals), which was featured at [Black Hat Europe 2019](https://www.blackhat.com/eu-19/arsenal/schedule/index.html#dsinternals-powershell-module-17807) and is also included in FireEye’s Commando VM. This open-source toolset exposes many internal and undocumented security-related features of Active Directory (AD), but we will primarily focus on its state-of-the-art offline database access capabilities. In the course of this lab, you will learn how to perform Active Directory password audits, offline password resets and group membership changes, or SID history injection.
	- **Password Spraying**
		- **Articles/Blogposts/Writeups**
		- **Talks/Presentations/Videos**
			* [Quietly Password Spraying ADFS using FireProx | Mike Fletch(2022)](https://www.youtube.com/watch?v=eZh9HDWmYIQ)
				* Microsoft Active Directory Federation Services is a great authentication portal that is commonly overlooked by defenders. By rotating IP addresses with FireProx, you can quietly password spray ADFS to gain access to a Microsoft tenant and maybe even the configured Relying Party trusts!	
		- **Tools**
			* [smartbrute](https://github.com/ShutdownRepo/smartbrute)
				* The smart password spraying and bruteforcing tool for Active Directory Domain Services.
			* [keimpx](https://github.com/nccgroup/keimpx)
				* keimpx is an open source tool, released under the Apache License 2.0. It can be used to quickly check for valid credentials across a network over SMB. C
			* [Invoke-CleverSpray](https://github.com/wavestone-cdt/Invoke-CleverSpray)
				 * Password Spraying Script detecting current and previous passwords of Active Directory User by @flelievre
			* [Talon](https://github.com/optiv/Talon)
				 * Talon is a tool designed to perform automated password guessing attacks while remaining undetected. Talon can enumerate a list of users to identify which users are valid, using Kerberos. Talon can also perform a password guessing attack against the Kerberos and LDAPS (LDAP Secure) services. Talon can either use a single domain controller or multiple ones to perform these attacks, randomizing each attempt, between the domain controllers and services (LDAP or Kerberos).
			* [aad-sso-enum-brute-spray](https://github.com/treebuilder/aad-sso-enum-brute-spray)
				* POC of SecureWorks' recent Azure Active Directory password brute-forcing vuln
			* [msprobe](https://github.com/puzzlepeaches/msprobe)
				* The tool will used a list of common subdomains associated with your target apex domain to attempt to discover valid instances of on-prem Microsoft solutions. Screenshots of the tool in action are below:
			* [ADFSpray](https://github.com/xFreed0m/ADFSpray/blob/master/README.md)
				* ADFSpray is a python3 tool to perform password spray attack against Microsoft ADFS. ALWAYS VERIFY THE LOCKOUT POLICY TO PREVENT LOCKING USERS.
			* [ShadowSpray](https://github.com/Dec0ne/ShadowSpray)
				* A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
	- **RDP**
		* [Abusing RDP’s Remote Credential Guard with Rubeus PTT - Ceri Coburn(2020)](https://www.pentestpartners.com/security-blog/abusing-rdps-remote-credential-guard-with-rubeus-ptt/)
	- **Relayed Credentials**
		* See `NTLM Relay`
		* [Playing with Relayed Credentials - SecureAuth](https://www.secureauth.com/blog/playing-relayed-credentials)
	- **Reversible Encryption/Fine Grained Password Policies**
		* [Targeted Plaintext Downgrades with PowerView - harmj0y](http://www.harmj0y.net/blog/redteaming/targeted-plaintext-downgrades-with-powerview/)
	- **SCCM**
		* [Exploring SCCM by Unobfuscating Network Access Accounts - Adam Chester(2022)](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)
		* [SCCMwtf](https://github.com/xpn/sccmwtf)
		* [The Phantom Credentials of SCCM: Why the NAA Won’t Die - Duane Michael(2022)](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
	- **Tickets**
		* [Stop Touching Lsass!!- Joshua Prager(2019](https://web.archive.org/web/20201126045005/https://bouj33boy.com/stop-touching-lsass/)
		* [Credential theft without admin or touching LSASS with Kekeo by abusing CredSSP / TSPKG (RDP SSO) - Clement Notin(2019)](https://clement.notin.org/blog/2019/07/03/credential-theft-without-admin-or-touching-lsass-with-kekeo-by-abusing-credssp-tspkg-rdp-sso/)
			* If you have compromised a Windows host, and cannot or do not want to, dump clear-text passwords using traditional techniques (e.g. mimikatz’s sekurlsa::logonpasswords, or LSASS dumping), you should check out the credential delegations settings. If enabled, it allows to obtain clear-text passwords without touching the LSASS process or even without having administrator rights (limited to the current user’s password then)!
	- **Presentations/Talks/Videos**
		* [Credential Assessment: Mapping Privilege Escalation at Scale - Matt Weeks(Hack.lu 2016)](https://www.youtube.com/watch?v=tXx6RB0raEY)
			* In countless intrusions from large retail giants to oil companies, attackers have progressed from initial access to complete network compromise. In the aftermath, much ink is spilt and products are sold on how the attackers first obtained access and how the malware they used could or could not have been detected, while little attention is given to the credentials they found that turned their access on a single-system into thousands more. This process, while critical for offensive operations, is often complex, involving many links in the escalation chain composed of obtaining credentials on system A that grant access to system B and credentials later used on system B that grant further access, etc. We’ll show how to identify and combat such credential exposure at scale with the framework we developed. We comprehensively identify exposed credentials and automatically construct the compromise chains to identify maximal access and privileges gained, useful for either offensive or defensive purposes.
		* [When Everyone's Dog is Named Fluffy: Abusing the Brand New Security Questions in Windows 10 to Gain Domain-Wide Persistence - Magal Baz, Tom Sela(BHEU18)](https://www.youtube.com/watch?v=hZdnIlQgPPQ)
			* [Slides](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Baz-When-Everyones-Dog-Is-Named-Fluffy.pdf)
	- **Tools**
		- Fake Logon Screens
			* [FakeLogonScreen](https://github.com/bitsadmin/fakelogonscreen0)
				* FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user's password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk.
			* [SharpLocker](https://github.com/Pickfordmatt/SharpLocker)	
				* SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike. It is written in C# to allow for direct execution via memory injection using techniques such as execute-assembly found in Cobalt Strike or others, this method prevents the executable from ever touching disk. It is NOT intended to be compilled and run locally on a device.
		* [Gosecretsdump](https://github.com/c-sto/gosecretsdump)
			* This is a conversion of the impacket secretsdump module into golang. It's not very good, but it is quite fast. Please let me know if you find bugs, I'll try and fix where I can - bonus points if you can provide sample .dit files for me to bash against.
		* [DomainPasswordTest](https://github.com/rvazarkar/DomainPasswordTest)
			* Tests AD passwords while respecting Bad Password Count
		* [serviceFu](https://github.com/securifera/serviceFu)
			* Automates credential skimming from service accounts in Windows Registry using Mimikatz lsadump::secrets. The use case for this tool is when you have administrative rights across certain computers in a domain but do not have any clear-text credentials. ServiceFu will remotely connect to target computers, check if any credentialed services are present, download the system and security registry hive, and decrypt clear-text credentials for the domain service account.
- **DCShadow**<a name="dcshadow"></a>
	* **101**
		* [Active Directory: What can make your million dollar SIEM go blind? - Vincent Le Toux, Benjamin Delpy](https://www.youtube.com/watch?v=KILnU4FhQbc)
			* [Slides](https://www.dropbox.com/s/baypdb6glmvp0j9/Buehat%20IL%20v2.3.pdf)]
		* [DCShadow](https://www.dcshadow.com/)
			* DCShadow is a new feature in mimikatz located in the lsadump module. It simulates the behavior of a Domain Controller (using protocols like RPC used only by DC) to inject its own data, bypassing most of the common security controls and including your SIEM. It shares some similarities with the DCSync attack (already present in the lsadump module of mimikatz).
		* [DCShadow explained: A technical deep dive into the latest AD attack technique - Luc Delsalle](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)
		* [What is DCShadow? - Stealthbits](https://attack.stealthbits.com/how-dcshadow-persistence-attack-works)
	* **Articles/Blogposts/Writeups**	
		* [DCShadow - Minimal permissions, Active Directory Deception, Shadowception and more - Nikhil Mittal](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)
		* [DCShadow: Attacking Active Directory with Rogue DCs - Jeff Warren](https://blog.stealthbits.com/dcshadow-attacking-active-directory-with-rogue-dcs/)
		* [Silently turn off Active Directory Auditing using DCShadow - Nikhil Mittal](http://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html)
		* [Creating Persistence With Dcshadow](https://blog.stealthbits.com/creating-persistence-with-dcshadow/)
	* **Tools**
		* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- **DCSync Attack**<a name="dcsync"></a>
	- **101**
		* [What is DCSync? An Introduction - Lee Berg](https://blog.stealthbits.com/what-is-dcsync/)
		* [[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)
		* [A primer on DCSync attack and detection - Chirag Savla](https://www.alteredsecurity.com/post/a-primer-on-dcsync-attack-and-detection)
		* [DCSync Attack - Haboob Team](https://dl.packetstormsecurity.net/papers/general/ad-dcsync.pdf)
	- **Articles/Blogposts/Writeups**	
		* [DCSync - Yojimbo Security](https://yojimbosecurity.ninja/dcsync/)
		* [DCSync: Dump Password Hashes from Domain Controller - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
		* [Mimikatz DCSync Usage, Exploitation, and Detection - Sean Metcalf](https://adsecurity.org/?p=1729)
		* [Mimikatz and DCSync and ExtraSids, Oh My - harmj0y](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)
		* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)
		* [Extracting User Password Data with Mimikatz DCSync - Jeff Warren](https://blog.stealthbits.com/extracting-user-password-data-with-mimikatz-dcsync/)
	- **Tools**
		* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- **NetSync Attack**<a name="netsync"></a>
	- **101**
		* [The Tale of the Lost, but not Forgotten, Undocumented NetSync: Part 1 - Andrew Schwartz](https://www.trustedsec.com/blog/the-tale-of-the-lost-but-not-forgotten-undocumented-netsync-part-1/)
			* [Part 2](https://www.trustedsec.com/blog/the-tale-of-the-lost-but-not-forgotten-undocumented-netsync-part-2/)
		* [netsync - thehacker.recipes](https://tools.thehacker.recipes/mimikatz/modules/lsadump/netsync)
		* [Are You Seeing What I Am Netsyncing? Analyzing Netsync Activity with Security Onion 2 - Wes Lambert(2020)](https://blog.securityonion.net/2020/10/are-you-seeing-what-i-am-netsyncing.html)
- **Defense Evasion**<a name="addefev"></a>
	* [Evading Microsoft ATA for Active Directory Domination - Nikhil Mittal](https://www.youtube.com/watch?v=bHkv63-1GBY)
		* Microsoft Advanced Threat Analytics (ATA) is a defense platform which reads information from multiple sources like traffic for certain protocols to the Domain Controller, Windows Event Logs and SIEM events. The information thus collected is used to detect Reconnaissance, Credentials replay, Lateral movement, Persistence attacks etc. Well known attacks like Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Golden Ticket, Directory services replication, Brute-force, Skeleton key etc. can be detected using ATA. 
	* [Red Team Techniques for Evading, Bypassing & Disabling MS - Chris Thompson]
		* Windows Defender Advanced Threat Protection is now available for all Blue Teams to utilize within Windows 10 Enterprise and Server 2012/16, which includes detection of post breach tools, tactics and techniques commonly used by Red Teams, as well as behavior analytics. 
		* [Slides](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
- **Discovery & Reconnaissance**<a name="discorecon"></a>
	- **Articles/Blogposts/Writeups**
		* [Targeted Active Directory Host Enumeration - Carlos Perez(2020)](https://www.trustedsec.com/blog/targeted-active-directory-host-enumeration/)
		* [Enumerating Windows Domains with rpcclient through SocksProxy == Bypassing Command Line Logging - @spotheplanet](https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging)
		* [Active Directory Discovery with a Mac - itsafeature(2018)](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
		* [Red Teaming - Enumeration - Monish Kumar(2021)](https://aidenpearce369.github.io/offsec/redteam-enumeration/)
		* [Finding Buried Treasure in Server Message Block (SMB) - David Fletcher(2021)](https://www.blackhillsinfosec.com/finding-buried-treasure-in-server-message-block-smb/)
		* [Attacking and Remediating Excessive Network Share Permissions in Active Directory Environments - Scott Sutherland(2022)](https://www.netspi.com/blog/technical/network-penetration-testing/network-share-permissions-powerhuntshares/)

		* [Active Directory Firewall Ports – Let’s Try To Make This Simple - Ace Fekay(2011)](https://blogs.msmvps.com/acefekay/2011/11/01/active-directory-firewall-ports-let-s-try-to-make-this-simple/)
		* [Automating the Empire with the Death Star: getting Domain Admin with a push of a button](https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html)
		* [Active Directory Pentest Recon Part 1: SPN Scanning aka Mining Kerberos Service Principal Names](https://adsecurity.org/?p=230)
		* [Active Directory Recon Without Admin Rights - adsecurity](https://adsecurity.org/?p=2535)
		- **adcli**
			* [adcli info - Fedora documentation](https://fedoraproject.org/wiki/QA:Testcase_adcli_info)
			* [adcli info forest - Fedora documentation](https://fedoraproject.org/wiki/QA:Testcase_adcli_info_forest)
		- **ADModule**
			* [Using ActiveDirectory module for Domain Enumeration from PowerShell Constrained Language Mode - Nikhil Mittal](http://www.labofapenetrationtester.com/2018/10/domain-enumeration-from-PowerShell-CLM.html)
		- **DNS**
			* [AD Zone Transfers as a user - mubix](https://malicious.link/post/2013/ad-zone-transfers-as-a-user/)
		- **File Shares**
			* [Accessing Internal Fileshares through Exchange ActiveSync - Adam Rutherford and David Chismon](https://labs.mwrinfosecurity.com/blog/accessing-internal-fileshares-through-exchange-activesync)
		- **GPOs**
			* [Enumerating remote access policies through GPO - William Knowles, Jon Cave](https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/)
		- **Hunting Users**<a name="huntingusers"></a>
			- **Articles/Blogposts/Writeups**
				* [Scanning for Active Directory Privileges & Privileged Accounts - Sean Metcalf(2017)](https://adsecurity.org/?p=3658)
				* [Derivative Local Admin - sixdub](http://www.sixdub.net/?p=591)
				* [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths)
					* Control paths in Active Directory are an aggregation of "control relations" between entities of the domain (users, computers, groups, GPO, containers, etc.) which can be visualized as graphs (such as above) and whose purpose is to answer questions like "Who can get 'Domain Admins' privileges ?" or "What resources can a user control ?" and even "Who can read the CEO's emails ?".
				* [5 Ways to Find Systems Running Domain Admin Processes - Scott Sutherland](https://blog.netspi.com/5-ways-to-find-systems-running-domain-admin-processes/)
				* [Attack Methods for Gaining Domain Admin Rights in Active Directory](https://adsecurity.org/?p"active=2362)
				* [Nodal Analysis of Domain Trusts – Maximizing the Win!](http://www.sixdub.net/?p=285)
				* [Derivative Local Admin - sixdub](https://web.archive.org/web/20170606071124/https://www.sixdub.net/?p=591)
				* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
				* [How Attackers Dump Active Directory Database Credentials](https://adsecurity.org/?p=2398)
				* [“I Hunt Sys Admins”](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)
				* [Gaining Domain Admin from Outside Active Directory - markitzeroday](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
			- **Talks/Videos**
				* [I Hunt Sys Admins - Will Schroeder/@harmj0y(Shmoocon 2015)](https://www.youtube.com/watch?v=yhuXbkY3s0E)
				* [I Hunt Sysadmins 2.0 - slides](http://www.slideshare.net/harmj0y/i-hunt-sys-admins-20)
					* It covers various ways to hunt for users in Windows domains, including using PowerView.
				* [Requiem For An Admin, Walter Legowski (@SadProcessor) - BSides Amsterdam 2017](https://www.youtube.com/watch?v=uMg18TvLAcE&index=3&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
					* Orchestrating BloodHound and Empire for Automated AD Post-Exploitation. Lateral Movement and Privilege Escalation are two of the main steps in the Active Directory attacker kill- chain. Applying the 'assume breach' mentality, more and more companies are asking for red-teaming type of assessments, and security researcher have therefor developed a wide range of open-source tools to assist them during these engagements. Out of these, two have quickly gained a solid reputation: PowerShell Empire and BloodHound (Both by @Harmj0y & ex-ATD Crew). In this Session, I will be presenting DogStrike, a new tool (PowerShell Modules) made to interface Empire & BloodHound, allowing penetration testers to merge their Empire infrastructure into the bloodhound graph database. Doing so allows the operator to request a bloodhound path that is 'Agent Aware', and makes it possible to automate the entire kill chain, from initial foothold to DA - or any desired part of an attacker's routine. Presentation will be demo-driven. Code for the module will be made public after the presentation. Automation of Active Directory post-exploitation is going to happen sooner than you might think. (Other tools are being released with the same goal). Is it a good thing? Is it a bad thing? If I do not run out of time, I would like to finish the presentation by opening the discussion with the audience and see what the consequences of automated post- exploitation could mean, from the red, the blue or any other point of view... : DeathStar by @Byt3Bl33d3r | GoFetch by @TalTheMaor.
			- **Tools**
				* [Check-LocalAdminHash](https://github.com/dafthack/Check-LocalAdminHash)
					* Check-LocalAdminHash is a PowerShell tool that attempts to authenticate to multiple hosts over either WMI or SMB using a password hash to determine if the provided credential is a local administrator. It's useful if you obtain a password hash for a user and want to see where they are local admin on a network.
					* [Blogpost](https://www.blackhillsinfosec.com/check-localadminhash-exfiltrating-all-powershell-history/)
				* [hunter](https://github.com/fdiskyou/hunter)
					* (l)user hunter using WinAPI calls only
				* [icebreaker](https://github.com/DanMcInerney/icebreaker)
					* Automates network attacks against Active Directory to deliver you piping hot plaintext credentials when you're inside the network but outside of the Active Directory environment. Performs 5 different network attacks for plaintext credentials as well as hashes. Autocracks hashes found with JohnTheRipper and the top 10 million most common passwords.
				* [Invoke-HostRecon](https://github.com/dafthack/HostRecon)
					* This function runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.
				* [DeathStar](https://github.com/byt3bl33d3r/DeathStar)
					* DeathStar is a Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory  environments using a variety of techinques.
				* [ANGRYPUPPY](https://github.com/vysec/ANGRYPUPPY)
					* Bloodhound Attack Path Execution for Cobalt Strike
				* [GoFetch](https://github.com/GoFetchAD/GoFetch)
					* GoFetch is a tool to automatically exercise an attack plan generated by the BloodHound application.  GoFetch first loads a path of local admin users and computers generated by BloodHound and converts it to its own attack plan format. Once the attack plan is ready, GoFetch advances towards the destination according to plan step by step, by successively applying remote code execution techniques and compromising credentials with Mimikatz.
				* [DogWhisperer - BloodHound Cypher Cheat Sheet (v2)](https://github.com/SadProcessor/Cheats/blob/master/DogWhispererV2.md)
				* [DomainTrustExplorer](https://github.com/sixdub/DomainTrustExplorer)
					* Python script for analyis of the "Trust.csv" file generated by Veil PowerView. Provides graph based analysis and output.
				* [SharpSniper](https://github.com/HunnicCyber/SharpSniper)
					*  Find specific users in active directory via their username and logon IP address 
				* [Get-UserSession](https://github.com/YossiSassi/Get-UserSession)
					* Queries user sessions for the entire domain (Interactive/RDP etc), allowing you to query a user and see all his logged on sessions, whether Active or Disconnected
				* [SamrSearch](https://github.com/knightswd/SamrSearch)
					* SamrSearch can get user info and group info with MS-SAMR.like net user aaa /domain and net group aaa /domain
		- **LDAP**
			* [Gathering AD Data with the Active Directory PowerShell Module - ADSecurity.com](https://adsecurity.org/?p=3719)
			*  Low Privilege Active Directory Enumeration from a non-Domain Joined Host - matt](https://www.attackdebris.com/?p=470)
			* [LDAPFragger: Bypassing network restrictions using LDAP attributes - Rindert Kramer](https://research.nccgroup.com/2020/03/19/ldapfragger-bypassing-network-restrictions-using-ldap-attributes/)
			* [Domain Goodness – How I Learned to LOVE AD Explorer - Sally Vandeven](https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/)
			* [Getting around Active Directory search size limit via ldapsearch - Fabio Martelli](https://www.tirasa.net/en/blog/getting-around-active-directory-search)
		- **Local Machine**
			* [HostEnum](https://github.com/threatexpress/red-team-scripts)
				* A PowerShell v2.0 compatible script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain, it can also perform limited domain enumeration with the -Domain switch. However, domain enumeration is significantly limited with the intention that PowerView or BoodHound could also be used.
		- **Passwords**
			* [NtdsAudit](https://github.com/Dionach/NtdsAudit)
				* NtdsAudit is an application to assist in auditing Active Directory databases. It provides some useful statistics relating to accounts and passwords. It can also be used to dump password hashes for later cracking.
		- **PowerShell**
			* [Active Directory Enumeration with PowerShell - Haboob Team](https://dl.packetstormsecurity.net/papers/general/activedir-enumerate.pdf)
			* [Active Directory Enumeration with PowerShell - Haboob](https://www.exploit-db.com/docs/english/46990-active-directory-enumeration-with-powershell.pdf)
				* Nowadays, most of the environments are using Active Directory to manage their networks and resources. And over the past years, the attackers have been focused to abuse and attack the Active Directory environments using different techniques and methodologies. So in this research paper, we are going to use the power of the PowerShell to enumerate the resources of the Active Directory, like enumerating the domains, users, groups, ACL, GPOs, domain trusts also hunting the users and the domain admins. With this valuable information, we can increase our attack surface to abuse the AD like Privilege escalation, lateral movements and persistence and so on.
		- **SMB**
		- **SPNs**<a name="spndisco"></a>
			* [Service Principal Names - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/AD/service-principal-names)
			* [SPNs - adsecurity.org](https://adsecurity.org/?page_id=183)
				* This page is a comprehensive reference (as comprehensive as possible) for Active Directory Service Principal Names (SPNs). As I discover more SPNs, they will be added.
			* [Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe - social.technet.ms.com)](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx)
			* [Service Principal Name (SPN) - hackndo](https://en.hackndo.com/service-principal-name-spn/)
			* [SPN Discovery - NetbiosX(2018)](https://pentestlab.blog/2018/06/04/spn-discovery/)
			* [Discovering Service Accounts Without Using Privileges - Jeff Warren](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
		- **User Enum**
			* [Kerberos Domain Username Enumeration - matt](https://www.attackdebris.com/?p=311)
			* [New Metasploit Module: Microsoft Remote Desktop Web Access Authentication Timing Attack - Matt Mathur](https://raxis.com/blog/rd-web-access-vulnerability)
	- **Talks**
		* [Vibing Your Way Through an Enterprise: How Attackers are Becoming More Sneaky - Matthew Eidelberg(GrrCon2018)](https://www.irongeek.com/i.php?page=videos/grrcon2018/grrcon-2018-augusta09-vibing-your-way-through-an-enterprise-how-attackers-are-becoming-more-sneaky-matthew-eidelberg)
		* [Vibe](https://github.com/Tylous/Vibe)
			* Vibe is a tool designed to preform post-ex lateral movement techniques while remaining undetected by network detection tools including Threat Hunting appliances. Vibe works by pulling down all information about a domain, allowing users to perform the same domain net commands offline. Vibe also enumerates additional information that is not typically shown in these queries. Vibe also provides the ability to scan systems to see what shares are available and what privileges the account used, has access to. Vibe also provides the ability to enumerate user’s currently logged into systems, as well as, who has been logged in, while remaining undetected.
	- **Tools**
		- **Lolbins**
			* [ADModule](https://github.com/samratashok/ADModule)
				* Microsoft signed DLL for the ActiveDirectory PowerShell module
		- **3rd-Party All-in-Ones/Multi-Purpose**
			* [EDD](https://github.com/FortyNorthSecurity/EDD)
				* [Meet EDD - He Helps Enumerate Domain Data - FortyNorth(2021)](https://fortynorthsecurity.com/blog/meet-edd-he-helps-enumerate-domain-data/)
				* Enumerate Domain Data is designed to be similar to PowerView but in .NET. PowerView is essentially the ultimate domain enumeration tool, and we wanted a .NET implementation that we worked on ourselves. This tool was largely put together by viewing implementations of different functionality across a wide range of existing projects and combining them into EDD.
		- **BloodHound**<a name="bloodhound"></a>
			- **101**
				* [Introducing BloodHound](https://wald0.com/?p=68)
				* [Bloodhound 2.2 - A Tool for Many Tradecrafts - Andy Gill](https://blog.zsec.uk/bloodhound-101/)
				* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
					* BloodHound is a single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a PowerShell ingestor. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.
			- **Articles/Blogposts/Writeups**
				* [BloodHound and the Adversary Resilience Model](https://docs.google.com/presentation/d/14tHNBCavg-HfM7aoeEbGnyhVQusfwOjOyQE1_wXVs9o/mobilepresent#slide=id.g35f391192_00)
				* [Introducing the Adversary Resilience Methodology — Part One - Andy Robbins](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
				* [Introducing the Adversary Resilience Methodology — Part Two - Andy Robbins](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
				* [Exploring Users With Multiple Accounts In BloodHound - Alain Homewood(2020)](https://insomniasec.com/blog/bloodhound-shared-accounts)
			- **Historical Posts**
				* [Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win. - JohnLaTwC](https://github.com/JohnLaTwC/Shared/blob/master/Defenders%20think%20in%20lists.%20Attackers%20think%20in%20graphs.%20As%20long%20as%20this%20is%20true%2C%20attackers%20win.md)
				* [Automated Derivative Administrator Search - wald0](https://wald0.com/?p=14)
				* [BloodHound 1.3 – The ACL Attack Path Update - wald0](https://wald0.com/?p=112)	
				* [BloodHound 1.4: The Object Properties Update - CptJesus](https://blog.cptjesus.com/posts/bloodhoundobjectproperties)
				* [SharpHound: Target Selection and API Usage](https://blog.cptjesus.com/posts/sharphoundtargeting)	
				* [BloodHound 1.5: The Container Update](https://blog.cptjesus.com/posts/bloodhound15)
				* [A Red Teamer’s Guide to GPOs and OUs - wald0](https://wald0.com/?p=179)
				* [BloodHound 2.0 - CptJesus](https://blog.cptjesus.com/posts/bloodhound20)
				* [BloodHound 2.1: The Fix Broken Stuff Update - Rohan Vazarkar](https://posts.specterops.io/bloodhound-2-1-the-fix-broken-stuff-update-4d28ff732b1)
			- **Talks/Presentations/Videos**
				* [Six Degrees of Global Admin – Andy Robbins & Rohan Vazarkar (SO-CON 2020)](https://www.youtube.com/watch?v=gAConW5P5uU&list=PLJK0fZNGiFU-2vFpjnt96j_VSuQVTkAnO&index=15)
					* In 2016 we released BloodHound, which helps attackers and defenders alike identify and execute or eliminate attack paths in Active Directory. Since then, BloodHound's collection and analysis capabilities have been limited to Active Directory and domain-joined Windows systems. Now, we are proud to announce the release of BloodHound 4.0, which expands BloodHound's capabilities outside on-prem Active Directory into Azure. In this talk, we will demonstrate real attack paths we've observed in customer environments, go over BloodHound's updated GUI, and explain Azure attack primitives now tracked by BloodHound.
			- **Using**
				* [BloodHound: Intro to Cypher - CptJesus](https://blog.cptjesus.com/posts/introtocypher)
				* [The Dog Whisperer's Handbook: A Hacker's Guide to the BloodHound Galaxy - @SadProcessor](https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf)
					* [Blogpost](https://insinuator.net/2018/11/the-dog-whisperers-handbook/)
				* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
				* [Lay of the Land with BloodHound](http://threat.tevora.com/lay-of-the-land-with-bloodhound/)
				* [Bloodhound walkthrough. A Tool for Many Tradecrafts - Andy Gill](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)
					* A walkthrough on how to set up and use BloodHound
				* [BloodHound From Red to Blue - Mathieu Saulnier(BSides Charm2019)](https://www.youtube.com/watch?v=UWY772iIq_Y)
				* [BloodHound Tips and Tricks - Riccardo Ancarani](https://blog.riccardoancarani.it/bloodhound-tips-and-tricks/)
				* [Advanced BloodHound Usage](https://github.com/CompassSecurity/BloodHoundQueries)
					* This project contains: Custom BloodHound Queries we often use to see important things in BloodHound; Custom Neo4j Queries we use to extract data directly from the Neo4j browser console; BloodHoundLoader script, which allows to make batch modifications to the BloodHound data
			- **Internals**
				* [BloodHound Inner Workings & Limitations – Part 1: User Rights Enumeration Through SAMR & GPOLocalGroup - Sven Defatsch(2022)](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-1/)
				* [Part 2: Session Enumeration Through NetWkstaUserEnum & NetSessionEnum](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-2/)
				* [Part 3: Session Enumeration Through Remote Registry & Summary](https://blog.compass-security.com/2022/05/bloodhound-inner-workings-part-3/)
			- **Neo4j**
				* [Neo4j Cypher Refcard 3.5](https://neo4j.com/docs/cypher-refcard/current/)
			- **Ingestors**
				* [BloodHound.py](https://github.com/fox-it/BloodHound.py)
					* A Python based ingestor for BloodHound
				* [SharpHound](https://github.com/BloodHoundAD/SharpHound)
					* Official Ingestor.
				* [ADExplorerSnapshot.py](https://github.com/c3c/ADExplorerSnapshot.py)
					* ADExplorerSnapshot.py is an AD Explorer snapshot parser. It is made as an ingestor for BloodHound, and also supports full-object dumping to NDJSON.
			- **Custom Queries**
				- **Articles/Blogposts/Writeups**
					* [BloodHound Part II - gkourgkoutas.net(2021)](https://gkourgkoutas.net/posts/bloodhound-part-2/)
					* [BloodHound Cypher Cheatsheet - Hausec(2019)](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
					* [Bloodhound Cheatsheet – Custom Queries, Neo4j, etc. - Harley(2022)](https://infinitelogins.com/2022/01/28/bloodhound-cheatsheet-custom-queries-neo4j-lookups/)
				- **Collections**
					* [BloodHound-Tools Custom Queries](https://github.com/CompassSecurity/BloodHoundQueries#custom-bloodhound-queries)
					* [BloodHound Custom Queries - Hausec](https://github.com/hausec/Bloodhound-Custom-Queries)
					* [BloodHound Custom Queries - ZephrFish](https://github.com/ZephrFish/Bloodhound-CustomQueries)
					* [Handy-BloodHound-Cypher-Queries - mgeeky](https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md)
			- **API**
				* [CypherDog](https://github.com/SadProcessor/CypherDog)
					* PowerShell Cmdlets to interact with BloodHound Data via Neo4j REST API
			- **Large Datasets**
				* [ChopHound](https://github.com/bitsadmin/chophound/)
					* Some scripts for dealing with any challenges that might arise when importing (large) JSON datasets into BloodHound.
					* [Dealing with large BloodHound datasets - bitsadmin(2022)](https://blog.bitsadmin.com/blog/dealing-with-large-bloodhound-datasets)
			- **Extension**
				* [Visualizing BloodHound Data with PowerBI — Part 1 - Andy Robbins](https://posts.specterops.io/visualizing-bloodhound-data-with-powerbi-part-1-ba8ea4908422)
					* [Visualizing BloodHound Data with PowerBI — Part 2 - Andy Robbins](https://posts.specterops.io/visualizing-bloodhound-data-with-powerbi-part-2-3e1c521fb7ae)
				* [Extending BloodHound: Track and Visualize Your Compromise](https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise/)
					* Customizing BloodHound's UI and taking advantage of Custom Queries to document a compromise, find collateral spread of 	owned nodes, and visualize deltas in privilege gains.
				* [Extending BloodHound Part 1 - GPOs and User Right Assignment - Riccardo Ancarani](https://riccardoancarani.github.io/2020-02-06-extending-bloodhound-pt1/)
				* [Cypheroth](https://github.com/seajaysec/cypheroth)
					* Automated, extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets.
				* [Plumhound](https://github.com/DefensiveOrigins/PlumHound)
					* Released as Proof of Concept for Blue and Purple teams to more effectively use BloodHoundAD in continual security life-cycles by utilizing the BloodHoundAD pathfinding engine to identify Active Directory security vulnerabilities resulting from business operations, procedures, policies and legacy service operations. PlumHound operates by wrapping BloodHoundAD's powerhouse graphical Neo4J backend cypher queries into operations-consumable reports. Analyzing the output of PlumHound can steer security teams in identifying and hardening common Active Directory configuration vulnerabilities and oversights.
				* [GoodHound](https://github.com/idnahacks/GoodHound)
					* GoodHound operationalises Bloodhound by determining the busiest paths to high value targets and creating actionable output to prioritise remediation of attack paths.
				* [Bloodhound-Portable](https://github.com/freeload101/Bloodhound-Portable)
					* BloodHound Portable for Windows (You can run this without local admin. No Administrator required)
				* [CrackHound](https://github.com/trustedsec/CrackHound)
					* CrackHound is a way to introduce plain-text passwords into BloodHound. This allows you to upload all your cracked hashes to the Neo4j database and use it for reporting purposes (csv exports) or path finding in BloodHound using custom queries.
				* [MacHound](https://github.com/XMCyber/MacHound)
					* [Introducing MacHound: A Solution to MacOS Active Directory-Based Attacks - Rony Munitz(2020)](https://www.xmcyber.com/introducing-machound-a-solution-to-macos-active-directory-based-attacks/)
					* MacHound is an extension to the Bloodhound audting tool allowing collecting and ingesting of Active Directory relationships on MacOS hosts. MacHound collects information about logged-in users, and administrative group members on Mac machines and ingest the information into the Bloodhound database. In addition to using the HasSession and AdminTo edges, MacHound adds three new edges to the Bloodhound database: CanSSH - entity allowed to SSH to host; CanVNC - entity allowed to VNC to host; CanAE - entity allowed to execute AppleEvent scripts on host
					* [Introducing MacHound: A Solution to MacOS Active Directory based Attacks - Rony Munitz(2021)](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
				* [ImproHound](https://github.com/improsec/ImproHound)
					* ImproHound is a dotnet standalone win x64 exe with GUI. To use ImproHound, you must run SharpHound to collect the necessary data from the AD. You will then upload the data to your BloodHound installation. ImproHound will connect to the underlying Neo4j database of BloodHound. In ImproHound, you will categorize the AD into tiers via the OU structure, and ImproHound will identify the AD relations that enable AD objects to compromise an object of a higher (closer to zero) tier and save the tiering violations in a csv file.
					* [ImproHound - Identify AD tiering violations - Jonas Bülow Knudsen](https://improsec.com/tech-blog/improhound-identify-ad-tiering-violations)
					* [DC 29 Adversary Village - Jonas - Tool Demo ImproHound - Identify AD tiering violations](https://www.youtube.com/watch?v=MTsPTI7OoqM)
				* [BloodHound-Tools](https://github.com/zeronetworks/BloodHound-Tools)
					* Bloodhound is the defacto standard that both blue and red security teams use to find lateral movement and privilege escalation paths that can potentially be exploited inside an enterprise environment. A typical environment can yield millions of paths, representing almost endless opportunities for red teams to attack and creating a seemingly insurmountable number of attack vectors for blue teams to tackle. However, a critical dimension that Bloodhound ignores, namely network access, could hold the key to shutting down excessive lateral movement. This repository contains tools that integrate with Bloodhound’s database in order to reflect network access, for the benefit of both red and blue teams.
				* [ShotHound](https://github.com/zeronetworks/BloodHound-Tools/tree/main/ShotHound)
					* ShotHound is a standalone script that integrates with BloodHound's Neo4j database and [CornerShot](https://github.com/zeronetworks/cornershot). It allows security teams to validate logical paths discovered by BloodHound against physical network access.
				* [Fox and the Hound](https://github.com/chrismaddalena/Fox)
					* A companion tool for BloodHound offering Active Directory statistics and number crunching
				* [FoxTerrier](https://github.com/AssuranceMaladieSec/FoxTerrier)
					* [FoxTerrier : On the trail of vulnerable Active Directory objects and a report - Alice Climent-Pommeret(2021)](https://assurancemaladiesec.github.io/foxterrier-on-the-trail/)
					* Python tool to find vulnerable AD object and generate a csv report
				* [Max](https://github.com/knavesec/Max)
					* [Intro Blogpost](https://whynotsecurity.com/blog/max/)
					* [Max2(blogpost)](https://whynotsecurity.com/blog/max2/)
					* Maximizing BloodHound with a simple suite of tools
				* [Ransomulator](https://github.com/zeronetworks/BloodHound-Tools/tree/main/Ransomulator)
					* "Ransomulator is a ransom simulator for BloodHound database. It can be used to measure a network resilience for ransomare infections, and identify "weak links" in the network."		
		- **ADFS**
			* [Carnivore](https://github.com/nccgroup/Carnivore)
				* [Tool Release – Carnivore: Microsoft External Assessment Tool - Chris Nevin(2020)](https://research.nccgroup.com/2020/12/03/tool-release-carnivore-microsoft-external-assessment-tool/)
		- **File Shares**<a name="fileshares"></a>
			 * [FindUncommonShares.py](https://github.com/p0dalirius/FindUncommonShares)
			 	* FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains. 
			* [Snaffler](https://github.com/SnaffCon/Snaffler)
				* Snaffler is a tool for pentesters and red teamers to help find delicious candy needles (creds mostly, but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment).
			* [SharpML](https://github.com/HunnicCyber/SharpML)
				* SharpML is C# and Python based tool that performs a number of operations with a view to mining file shares, querying Active Directory for users, dropping an ML model and associated rules, perfoming Active Directory authentication checks, with a view to automating the process of hunting for passwords in file shares by feeding the mined data into the ML model.
			* [PowerHuntShares](https://github.com/NetSPI/PowerHuntShares)
				* PowerHuntShares is an audit script designed in inventory, analyze, and report excessive privileges configured on Active Directory domains.
			* [MAN-SPIDER](https://github.com/blacklanternsecurity/MANSPIDER)
				* Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
		- **Kebreros Username Identification**
			* [Kerberos Domain Username Enumeration - matt](https://www.attackdebris.com/?p=311)
		- **LDAP**
			* See "LDAP Recon"
		- **PowerShell**
			* [AdEnumerator](https://github.com/chango77747/AdEnumerator)
				* Active Directory enumeration from non-domain system. Powershell script
			* [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
				* AD PowerShell Recon Scripts
			* [AdsiPS](https://github.com/lazywinadmin/AdsiPS)
				* PowerShell module to interact with Active Directory using ADSI and the `System.DirectoryServices` namespace (.NET Framework).
			* [Check-LocalAdminHash & Exfiltrating All PowerShell History - Beau Bullock](https://www.blackhillsinfosec.com/check-localadminhash-exfiltrating-all-powershell-history/)
				* Check-LocalAdminHash is a new PowerShell script that can check a password hash against multiple hosts to determine if it’s a valid administrative credential. It also has the ability to exfiltrate all PowerShell PSReadline console history files from every profile on every system that the credential provided is an administrator of.
			* [Check-LocalAdminHash](https://github.com/dafthack/Check-LocalAdminHash)
				* Check-LocalAdminHash is a PowerShell tool that attempts to authenticate to multiple hosts over either WMI or SMB using a password hash to determine if the provided credential is a local administrator. It's useful if you obtain a password hash for a user and want to see where they are local admin on a network. It is essentially a Frankenstein of two of my favorite tools along with some of my own code. It utilizes Kevin Robertson's (@kevin_robertson) Invoke-TheHash project for the credential checking portion. Additionally, the script utilizes modules from PowerView by Will Schroeder (@harmj0y) and Matt Graeber (@mattifestation) to enumerate domain computers to find targets for testing admin access against.
		- **RPC**
			* [RpcGetWinVersion.py](https://github.com/airbus-cyber/CyberSecRessources/blob/master/RpcGetWinVersion/RpcGetWinVersion.py)
		- **LDAP/RPC**
			* [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
			* [PywerView](https://github.com/the-useless-one/pywerview)
				* A (partial) Python rewriting of PowerSploit's PowerView.
			* [Powerview.py](https://github.com/aniqfakhrul/powerview.py)
				* This repository has nothing related to the existing PowerView.py project that is already publicly available. This is only meant for my personal learning purpose and would like to share the efforts with everyone interested. This project will be supported by the collaborators from time to time, so don't worry.
			* [The PowerView PowerUsage Series #1 - harmjoy](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-1/)
				* [Part #2](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-2/)
				* [Part #3](https://posts.specterops.io/the-powerview-powerusage-series-3-f46089b3cc43)
				* [Part #4](https://posts.specterops.io/the-powerview-powerusage-series-4-e8d408c15c95)
				* [Part #5](https://posts.specterops.io/the-powerview-powerusage-series-5-7ca3ebb23927)
		- **Miscellaneous Tools(unsorted)**
			* [ActiveReign](https://github.com/m8r0wn/ActiveReign)
				* A Network Enumeration and Attack Toolset
			* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
				* A swiss army knife for pentesting networks
			* [Windows Vault Password Dumper](http://www.oxid.it/downloads/vaultdump.txt)
				* The following code shows how to use native undocumented functions of Windows Vault API to enumerate and extract credentials stored by Microsoft Windows Vault. The code has been successfully tested on Windows7 and Windows8 operating systems.
			* [knit_brute.sh](https://gist.github.com/ropnop/8711392d5e1d9a0ba533705f7f4f455f)
				* A quick tool to bruteforce an AD user's password by requesting TGTs from the Domain Controller with 'kinit'
			* [BTA](https://bitbucket.org/iwseclabs/bta)
				* BTA is an open-source Active Directory security a5udit framework.
			* [WinPwn](https://github.com/SecureThisShit/WinPwn)
			    * Automation for internal Windows Penetrationtest / AD-Security
			* [Wireless_Query](https://github.com/gobiasinfosec/Wireless_Query)
				* Query Active Directory for Workstations and then Pull their Wireless Network Passwords. This tool is designed to pull a list of machines from AD and then use psexec to pull their wireless network passwords. This should be run with either a DOMAIN or WORKSTATION Admin account.
			* [Find AD users with empty password using PowerShell](https://4sysops.com/archives/find-ad-users-with-empty-password-passwd_notreqd-flag-using-powershell/)
			* [ACLight](https://github.com/cyberark/ACLight)
				* The tool queries the Active Directory (AD) for its objects' ACLs and then filters and analyzes the sensitive permissions of each one. The result is a list of domain privileged accounts in the network (from the advanced ACLs perspective of the AD). You can run the scan with just any regular user (could be non-privileged user) and it automatically scans all the domains of the scanned network forest.
			* [zBang](https://github.com/cyberark/zBang)
				* zBang is a special risk assessment tool that detects potential privileged account threats in the scanned network.
				* [Blogpost](https://www.cyberark.com/threat-research-blog/the-big-zbang-theory-a-new-open-source-tool/)
			* [ADCollector](https://github.com/dev-2null/ADCollector)
				* A lightweight tool that enumerates the Active Directory environment to identify possible attack vectors
			* [jackdaw](https://github.com/skelsec/jackdaw)
				* Jackdaw is here to collect all information in your domain, store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
- **FreeIPA**<a name="afreeipa"></a>
	* [Building a FreeIPA Lab - n0pe_sled(2019](https://posts.specterops.io/building-a-freeipa-lab-17f3f52cd8d9)
	* [Attacking FreeIPA: Part I Authentication - n0pe_sled(2019-2020)](https://posts.specterops.io/attacking-freeipa-part-i-authentication-77e73d837d6a)
		* [Part II Enumeration](https://posts.specterops.io/attacking-freeipa-part-ii-enumeration-ad27224371e1)
		* [Part III: Finding A Path](https://posts.specterops.io/attacking-freeipa-part-iii-finding-a-path-677405b5b95e)
		* [Part IV: CVE-2020–10747](https://posts.specterops.io/attacking-freeipa-part-iii-finding-a-path-677405b5b95e)
- **Forest Attacks**<a name="aforest"></a>
	- **Articles/Blogposts/Writeups**
		* [How NOT to use the PAM trust - Leveraging Shadow Principals for Cross Forest Attacks - Nikhil Mittal](http://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)
- **Group Managed Service Account Attacks**<a name="gmsaa"></a>
	* [Introducing the Golden GMSA Attack - Yuval Gordon(2022)](https://www.semperis.com/blog/golden-gmsa-attack/)
	* [GoldenGMSA](https://github.com/Semperis/GoldenGMSA#usage)
		* GolenGMSA tool for working with GMSA passwords 
- **Group Membership Abuse**<a name="groupabuse"></a>	
	- **Articles/Blogposts/Writeups**
		* [A Pentester’s Guide to Group Scoping - harmj0y](http://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)
		* [Poc’ing Beyond Domain Admin - Part 1 - cube0x0](https://cube0x0.github.io/Pocing-Beyond-DA/)
- **Group Policies**<a name="groupa"></a>
	* [Group Policies Going Rogue - Eran Shimony(2020)](https://www.cyberark.com/resources/threat-research-blog/group-policies-going-rogue)
		* "GPSVC exposes all domain-joined Windows machines to an escalation of privileges (EoP) vulnerability. By running gpudate.exe, you can escalate into a privileged user via a file-manipulation attack."
- **Internal Monologue**<a name="ilm"></a>
	- **101**
		* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue/)
	        * In secure environments, where Mimikatz should not be executed, an adversary can perform an Internal Monologue Attack, in which they invoke a local procedure call to the NTLM authentication package (MSV1_0) from a user-mode application through SSPI to calculate a NetNTLM response in the context of the logged on user, after performing an extended NetNTLM downgrade.
	- **Articles/Blogposts/Writeups**
		* [Retrieving NTLM Hashes without touching LSASS: the “Internal Monologue” Attack - Andrea Fortuna(2018)](https://www.andreafortuna.org/2018/03/26/retrieving-ntlm-hashes-without-touching-lsass-the-internal-monologue-attack/)
		* [Getting user credentials is not only admin’s privilege - Anton Sapozhnikov(Syscan14)](https://infocon.org/consSyScan/SyScan%202014%20Singapore/SyScan%202014%20presentations/SyScan2014_AntonSapozhnikov_GettingUserCredentialsisnotonlyAdminsPrivilege.pdf)
		* [Stealing Hashes without Admin via Internal Monologue - Practical Exploitation(mubix@hak5)](https://www.youtube.com/watch?v=Q8IRcO0s-fU)
		* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
		* [Hunt for the gMSA secrets - Dr Nestori Syynimaa(2022)](https://o365blog.com/post/gmsa/)
		* [Introducing the Golden GMSA Attack - Yuval Gordon(2022)](https://www.semperis.com/blog/golden-gmsa-attack/)
	- **Tools**
		* [selfhash](https://github.com/snowytoxa/selfhash)
			* Selfhash allows you to get password hashes of the current user. This tool doesn't requere high privileges i.e. SYSTEM, but on another hand it returns NTLM Challenge Response, so you could crack it later.
- **Kerberos-based Attacks**<a name="kerb-based"></a>
	- **Talks/Presentations/Videos**
		* [Attacking Microsoft Kerberos: Kicking the Guard Dog of Hades - Tim Medin(DerbyCon4)](https://www.youtube.com/watch?v=PUyhlN-E5MU)
	- **ASREPRoast**<a name="asreproast"></a>
		- **101**
			* [Roasting AS-REPs - harmj0y](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
				* tl;dr – if you can enumerate any accounts in a Windows domain that don’t require Kerberos preauthentication, you can now easily request a piece of encrypted information for said accounts and efficiently crack the material offline, revealing the user’s password.
			* [LayerOne2016 - Kerberos Party Tricks (Geoffrey Janjua) (No sound!)](https://www.youtube.com/watch?v=qcfdPdqbk5U)
				* [Slides](https://static1.squarespace.com/static/557377e6e4b0976301e02e0f/t/574a0008f85082d3b6ba88a8/1464467468683/Layer1+2016+-+Janjua+-+Kerberos+Party+Tricks+-+Weaponizing+Kerberos+Protocol+Flaws.pdf)
				* [Toolkit](http://www.exumbraops.com/s/krbtrickstar.gz)
			* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws - Geoffrey Janjua(2016)](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
			* [Attacking Active Directory - AS-REP Roasting - Conda(2020)](https://www.youtube.com/watch?v=EVdwnBFtUtQ)
		- **Informational**
				* [Roasting AS-REPs - harmj0y](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
				* [IOC differences between Kerberoasting and AS-REP Roasting - Jonathan Johnson(2019)](https://medium.com/@jsecurity101/ioc-differences-between-kerberoasting-and-as-rep-roasting-4ae179cdf9ec)
				* [AS_REP Roasting - hackndo(2020)](https://en.hackndo.com/kerberos-asrep-roasting/)
				* [Roasting your way to DA - Build-Break-Defend-Fix - Andy Gill(2020)](https://blog.zsec.uk/path2da-pt2/)
					* Dive into both Kerberoasting and ASREP Roasting, looking at how they work, how to introduce them into an environment and how to fix them or where possible monitor and defend against them.
				* [Everything about Service Principals, Applications, and API Permissions - m365guy(2021)](https://m365internals.com/2021/07/24/everything-about-service-principals-applications-and-api-permissions/)
			- **How-Tos**
				* [AS-REP Roasting - @spottheplanet](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
				* [Kerberos AD Attacks - More Roasting with AS-REP - Adam Chester(2017)](https://blog.xpnsec.com/kerberos-attacks-part-2/)
				* [AS-REP Roasting – Cracking User Account Password - akijos(2018)](https://akijosberryblog.wordpress.com/2018/01/17/as-rep-roasting-cracking-user-account-password/)
				* [Cracking Active Directory Passwords with AS-REP Roasting - Jeff Warren(2019)](https://blog.stealthbits.com/cracking-active-directory-passwords-with-as-rep-roasting/)
				* [AS-REP Roasting - Pavandeep Singh(2020)](https://www.hackingarticles.in/as-rep-roasting/)
				* [ASREP Roasting - AkimboCore(2020)](https://www.akimbocore.com/article/asrep-roasting/)
			- **Tools**
				* [Rubeus](https://github.com/GhostPack/Rubeus)
					* Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpy's Kekeo project (CC BY-NC-SA 4.0 license) and Vincent LE TOUX's MakeMeEnterpriseAdmin project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.
	- **AS-REQ Roasting**<a name="asreqroasting"></a>
		- **101**
			* [ASREQRoast - From MITM to hash - Magnus Stubman(2019)](https://dumpco.re/blog/asreqroast)
		- **Articles**
			* [New Attack Paths? AS Requested Service Tickets - Charlie Clark(2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
		- **Tools**
			* [RoastInTheMiddle](https://github.com/0xe7/RoastInTheMiddle)
				* Roast in the Middle is a rough proof of concept (not attack-ready) that implements a man-in-the-middle ARP spoof to intercept AS-REQ's to modify and replay to perform a Kerberoast attack.
			* [RITM](https://github.com/Tw1sm/RITM)
				* This is a Python implementation of the man-in-the-middle attack described by Charlie Clark (@exploitph) in his post, `New Attack Paths? AS Requested Service Tickets`, and demonstrated in his proof-of-concept, `Roast in the Middle`.
- **Delegation**<a name="kerb-delegate"></a>
	* [You Do (Not) Understand Kerberos Delegation](https://www.youtube.com/watch?v=p9QFdITuvgU&list=PLwb6et4T42wwlxffjq9-F3KVDNDi9gQFs&index=6)
		* Slides - `https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos.pdf`
	- **Constrained-Delegation**<a name="constrained"></a>
		- **101**
			* [Kerberos Constrained Delegation Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
				* This overview topic for the IT professional describes new capabilities for Kerberos constrained delegation in Windows Server 2012 R2 and Windows Server 2012. Applies To: Windows Server (Semi-Annual Channel), Windows Server 2016
			* [What is Kerberos Delegation? An Overview of Kerberos Delegation - Kevin Joyce(2020)](https://blog.stealthbits.com/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/)
			* [Kerberos Constrained Delegation - AWS](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_key_concepts_kerberos.html)
		- **Articles/Blogposts/Writeups**
			* [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
			* [From Kekeo to Rubeus](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
			* [S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
			* [Kerberos Delegation, Spns And More...](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
			* [Kerberos Authentication: A Wrap Up - 0xcsandker(2017)](https://csandker.io/2017/09/12/KerberosAuthenticationAWrapUp.html)
			* [Kerberos Delegation: A Wrap Up - 0xcsandker(2020)](https://csandker.io/2020/02/10/KerberosDelegationAWrapUp.html)
			* [Kerberos Delegation: A Reference Overview - 0xcsandker(2020)](https://csandker.io/2020/02/15/KerberosDelegationAReferenceOverview.html)
			* [Kerberos Delegation - hackndo(2020)](https://en.hackndo.com/constrained-unconstrained-delegation/)
			* [SPN-jacking: An Edge Case in WriteSPN Abuse - Elad Shamir(2022)](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
				* Suppose an attacker compromises an account set for Constrained Delegation but doesn’t have the SeEnableDelegation privilege. The attacker won’t be able to change the constraints (msDS-AllowedToDelegateTo). However, if the attacker has WriteSPN rights over the account associated with the target SPN, as well as over another computer/service account, the attacker can temporarily hijack the SPN (a technique called SPN-jacking), assign it to the other computer/server, and perform a full S4U attack to compromise it.
			* [Abusing Kerberos Constrained Delegation without Protocol Transition - snovvcrash(2022)](https://snovvcrash.rocks/2022/03/06/abusing-kcd-without-protocol-transition.html)
			* [Constrained Delegation Considerations for Lateral Movement - Sergio Lazaro(2022)](https://sensepost.com/blog/2022/constrained-delegation-considerations-for-lateral-movement/)
			* [Active Directory – Delegation Based Attacks - floreaiulian(2022)](https://securitycafe.ro/2022/05/16/active-directory-delegation-based-attacks-2/)
			* [Delegate to KRBTGT service - skyblue.team(2022)](https://skyblue.team/posts/delegate-krbtgt/)
		- **Talks & Presentations**
			* [Delegate to the Top Abusing Kerberos for Arbitrary Impersonations and RCE - Matan Hart(BHASIA 17)](https://www.youtube.com/watch?v=orkFcTqClIE)
			* [Delegating Kerberos To Bypass Kerberos Delegation Limitation by Charlie Bromberg(InsomniHack2022)](https://www.youtube.com/watch?v=byykEId3FUs)
		- **Tools**
			* [Blank Space](https://github.com/jbaines-r7/blankspace)
				* Proof of Concept for EFSRPC Arbitrary File Upload (CVE-2021-43893)
			* [Lab S4U2Self Abuse](https://github.com/OtterHacker/LabS4U2Self)
				* This lab aims to provide a safe environment to test the S4U2Self abuse exploit
	- **Resource Based Constrained-Delegation**<a name="rbcd"></a>
		- **Articles/Blogposts/Writeups**
			* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory - Elad Shamir(2019)](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
				* Back in March 2018, I embarked on an arguably pointless crusade to prove that the TrustedToAuthForDelegation attribute was meaningless, and that “protocol transition” can be achieved without it. I believed that security wise, once constrained delegation was enabled (msDS-AllowedToDelegateTo was not null), it did not matter whether it was configured to use “Kerberos only” or “any authentication protocol”.  I started the journey with Benjamin Delpy’s (@gentilkiwi) help modifying Kekeo to support a certain attack that involved invoking S4U2Proxy with a silver ticket without a PAC, and we had partial success, but the final TGS turned out to be unusable. Ever since then, I kept coming back to it, trying to solve the problem with different approaches but did not have much success. Until I finally accepted defeat, and ironically then the solution came up, along with several other interesting abuse cases and new attack techniques.
			* [A Case Study in Wagging the Dog: Computer Takeover - harmj0y](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/)
			* [Kerberos Delegation, SPNs and More... - Alberto Solino(2017)](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
				* In this blog post, I will cover some findings (and still remaining open questions) around the Kerberos Constrained Delegation feature in Windows as well as Service Principal Name (SPN) filtering that might be useful when considering using/testing this technology.
			* [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation - Dirk-jan Mollema](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
				* After my in-depth post last month about unconstrained delegation, this post will discuss a different type of Kerberos delegation: resource-based constrained delegation. The content in this post is based on Elad Shamir’s Kerberos research and combined with my own NTLM research to present an attack that can get code execution as SYSTEM on any Windows computer in Active Directory without any credentials, if you are in the same network segment. This is another example of insecure Active Directory default abuse, and not any kind of new exploit.
			* [Kerberos Resource-Based Constrained Delegation: When an Image Change Leads to a Privilege Escalation - Matt Lewis(2019)](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)
				* [Change-Lockscreen](https://github.com/nccgroup/Change-Lockscreen)
			* [Kerberos Resource-Based Constrained Delegation: When an Image Change Leads to a Privilege Escalation - Daniel López Jiménez and Simone Salucci(2019)](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/august/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)
			* [DirectAccess and Kerberos Resource-based Constrained Delegation - Paul van der Haas(2020)](https://sensepost.com/blog/2020/directaccess-and-kerberos-resource-based-constrained-delegation/)
			* [From RPC to RCE - Workstation Takeover via RBCD and MS-RPChoose-Your-Own-Adventure - gladiatx0r](https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb#rpc-to-rce-steps)
			* [Chaining multiple techniques and tools for domain takeover using RBCD - Sergio Lazaro(2020)](https://sensepost.com/blog/2020/chaining-multiple-techniques-and-tools-for-domain-takeover-using-rbcd/)
			* [Abusing Kerberos Resource-Based Constrained Delegation](https://github.com/tothi/rbcd-attack)
				* This repo is about a practical attack against Kerberos Resource-Based Constrained Delegation in a Windows Active Directory Domain.
			* [Resource Based Constrained Delegation - PentestLabBlog(2021)](https://pentestlab.blog/2021/10/18/resource-based-constrained-delegation/)
			* [Exploiting RBCD Using a Normal User Account* - James Forshaw(2022)](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
		- **Tools**
			* [Get-RBCD-Threaded](https://github.com/FatRodzianko/Get-RBCD-Threaded)
				* Tool to discover Resource-Based Constrained Delegation attack paths in Active Directory Environments
			* [SharpAllowedToAct](https://github.com/pkb1s/SharpAllowedToAct)
				* Computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
			* [PowerMAD](https://github.com/Kevin-Robertson/Powermad)
				* PowerShell MachineAccountQuota and DNS exploit tools
				* [Blogpost](https://blog.netspi.com/exploiting-adidns/)
	- **Unconstrained Delegation**<a name="unconstrained"></a>
		- **101**
			* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain) - Sean Metcalf(2015)](https://adsecurity.org/?p=1667)
		- **Articles/Blogposts/Writeups**
			* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain)](https://adsecurity.org/?p=1667)
			* [Unconstrained Delegation Permissions](https://blog.stealthbits.com/unconstrained-delegation-permissions/)
			* [Trust? Years to earn, seconds to break](https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/)
			* [Getting Domain Admin with Kerberos Unconstrained Delegation - Nikhil Mittal(2016)](http://www.labofapenetrationtester.com/2016/02/getting-domain-admin-with-kerberos-unconstrained-delegation.html)
			* [Domain Controller Print Server + Unconstrained Kerberos Delegation = Pwned Active Directory Forest - adsecurity.org](https://adsecurity.org/?p=4056)
			* [Abusing Users Configured with Unconstrained Delegation - ](https://exploit.ph/user-constrained-delegation.html)
			* [“Relaying” Kerberos - Having fun with unconstrained delegation  - Dirk-jan Mollema(2019)](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
			* [Unconstrained Delegation - Pentesterlab(2022)](https://pentestlab.blog/2022/03/21/unconstrained-delegation/)
		- **Talks & Presentations**
			* [Red vs Blue: Modern Active Directory Attacks Detection and Protection - Sean Metcalf(BHUSA2015)](https://www.youtube.com/watch?v=b6GUXerE9Ac)
				* [Slides](https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection.pdf)
				* [Paper](https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf)
			* [The Unintended Risks of Trusting Active Directory - Lee Christensen, Will Schroeder, Matt Nel(Derbycon 2018)](https://www.youtube.com/watch?v=-bcWZQCLk_4)
				* Your crown jewels are locked in a database, the system is patched, utilizes modern endpoint security software, and permissions are carefully controlled and locked down. Once this system is joined to Active Directory, however, does that static trust model remain the same? Or has the number of attack paths to your data increased by an order of magnitude? We’ve spent the last year exploring the access control model of Active Directory and recently broadened our focus to include security descriptor misconfigurations/backdoor opportunities at the host level. We soon realized that the post-exploitation “attack surface” of Windows hosts spans well beyond what we originally realized, and that host misconfigurations can sometimes have a profound effect on the security of every other host in the forest. This talk will explore a number of lesser-known Active Directory and host-based permission settings that can be abused in concert for remote access, privilege escalation, or persistence. We will show how targeted host modifications (or existing misconfigurations) can facilitate complex Active Directory attack chains with far-reaching effects on other systems and services in the forest, and can allow new AD attack paths to be built without modifying Active Directory itself.
		    * [Slides](https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory)
		- **Tools**
			* [SpoolSample -> NetNTLMv1 -> NTLM -> Silver Ticket](https://github.com/NotMedic/NetNTLMtoSilverTicket)
				* This technique has been alluded to by others, but I haven't seen anything cohesive out there. Below we'll walk through the steps of obtaining NetNTLMv1 Challenge/Response authentication, cracking those to NTLM Hashes, and using that NTLM Hash to sign a Kerberos Silver ticket. This will work on networks where "LAN Manager authentication level" is set to 2 or less. This is a fairly common scenario in older, larger Windows deployments. It should not work on Windows 10 / Server 2016 or newer.
			* [SpoolerScanner](https://github.com/vletoux/SpoolerScanner)
				* Check if the spooler (MS-RPRN) is remotely available with powershell/c#
			* [SpoolSample](https://github.com/leechristensen/SpoolSample)
		    	* PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. This is possible via other protocols as well.
			* [krbrelayx](https://github.com/dirkjanm/krbrelayx)
				* Kerberos unconstrained delegation abuse toolkit 
		- **Mitigation**
			* [ADV190006 | Guidance to mitigate unconstrained delegation vulnerabilities portal.msrc](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006)
	- **Encryption Downgrade**<a name="kerb-enc-down"></a>
		* [Downgrading Kerberos Encryption & Why It Doesn’t Work In Server 2019 - vbsscrub(2021)](https://vbscrub.com/2021/12/04/downgrading-kerberos-encryption-amp-why-it-doesnt-work-in-server-2019/)
	- **FAST**<a name="fast"></a>
		* Kerberos Armoring (Flexible Authentication Secure Tunneling (FAST)) - docs.ms - `https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831747(v=ws.11)#kerberos-armoring-flexible-authentication-secure-tunneling-fast`
			* Flexible Authentication Secure Tunneling (FAST) provides a protected channel between the Kerberos client and the KDC. FAST is implemented as Kerberos armoring in Windows Server 2012, and it is only available for authentication service (AS) and ticket-granting service (TGS) exchanges.
		* [I Wanna Go Fast, Really Fast, like (Kerberos) FAST - Andrew Schwartz(2022)](https://www.trustedsec.com/blog/i-wanna-go-fast-really-fast-like-kerberos-fast/)
	- **Kerberoasting**<a name="kerberoast">
		- **101**
			* [Deep Dive into Kerberoasting Attack - Raj Chandel(2020)](https://www.hackingarticles.in/deep-dive-into-kerberoasting-attack/)
		- **Articles/Blogposts/Writeups**
			* [Kerberoasting - Part 1 - mubix(2016](https://room362.com/post/2016/kerberoast-pt1/)
			* [Kerberoasting - Part 2 - mubix](https://room362.com/post/2016/kerberoast-pt2/)
			* [Kerberoasting - Part 3 - mubix](https://room362.com/post/2016/kerberoast-pt3/)
			* [Kerberoasting - Pixis](https://en.hackndo.com/kerberoasting/)
			* [Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain - adsecurity.org](https://adsecurity.org/?p=2293)
			* [Kerberoasting Without Mimikatz - Will Schroeder](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
			* [Mimikatz 2.0 - Brute-Forcing Service Account Passwords ](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Brute-Forcing_Service_Account_Passwords.html)
			* If everything about that ticket-generation operation is valid except for the NTLM hash, then accessing the web application will result in a failure. However, this will not cause a failed logon to appear in the Windows® event log. It will also not increment the count of failed logon attempts for the service account. Therefore, the result is an ability to perform brute-force (or, more realistically, dictionary-based) password checks for such a service account, without locking it out or generating suspicious event log entries. 
			* [kerberos, kerberoast and golden tickets - leonjza](https://leonjza.github.io/blog/2016/01/09/kerberos-kerberoast-and-golden-tickets/)
			* [Extracting Service Account Passwords with Kerberoasting - Jeff Warren](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
			* [Cracking Service Account Passwords with Kerberoasting](https://www.cyberark.com/blog/cracking-service-account-passwords-kerberoasting/)
			* [Targeted Kerberoasting - harmj0y](https://www.harmj0y.net/blog/activedirectory/targeted-kerberoasting/)
			* [Kerberoast PW list for cracking passwords with complexity requirements](https://gist.github.com/edermi/f8b143b11dc020b854178d3809cf91b5)
			* [kerberos, kerberoast and golden tickets - leonzja](https://leonjza.github.io/blog/2016/01/09/kerberos-kerberoast-and-golden-tickets/)
			* [Kerberoast - pentestlab.blog](https://pentestlab.blog/2018/06/12/kerberoast/)
			* [A Toast to Kerberoast - Derek Banks](https://www.blackhillsinfosec.com/a-toast-to-kerberoast/)
			* [Kerberoasting, exploiting unpatched systems – a day in the life of a Red Teamer - Chetan Nayak](http://niiconsulting.com/checkmate/2018/05/kerberoasting-exploiting-unpatched-systems-a-day-in-the-life-of-a-red-teamer/)
			* [Discovering Service Accounts Without Using Privileges - Jeff Warren](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
			* [Kerberoasting and SharpRoast output parsing! - grumpy-sec](https://grumpy-sec.blogspot.com/2018/08/kerberoasting-and-sharproast-output.html)
			* [AS_REP Roasting vs Kerberoasting - LuemmelSec(2020)](https://luemmelsec.github.io/Kerberoasting-VS-AS-REP-Roasting/)
			* [Kerberoasting without SPNs - Arseniy Sharoglazov(2020)](https://swarm.ptsecurity.com/kerberoasting-without-spns/)
			* [Kerberoasting and Pass the Ticket Attack Using Linux - Raj Chandel(2020)](https://www.hackingarticles.in/kerberoasting-and-pass-the-ticket-attack-using-linux/)
			* [Kerberoast with OpSec - m365guy(2021)](https://m365internals.com/2021/11/08/kerberoast-with-opsec/)
			* [Lessons in Disabling RC4 in Active Directory - Steve Syfuhs(2022](https://syfuhs.net/lessons-in-disabling-rc4-in-active-directory)		
		- **Talks/Presentations/Videos**
			* [Attacking Kerberos: Kicking the Guard Dog of Hades - Tim Medin](https://www.youtube.com/watch?v=HHJWfG9b0-E)
				* Kerberos, besides having three heads and guarding the gates of hell, protects services on Microsoft Windows Domains. Its use is increasing due to the growing number of attacks targeting NTLM authentication. Attacking Kerberos to access Windows resources represents the next generation of attacks on Windows authentication.In this talk Tim will discuss his research on new attacks against Kerberos- including a way to attack the credentials of a remote service without sending traffic to the service as well as rewriting tickets to access systems.He will also examine potential countermeasures against Kerberos attacks with suggestions for mitigating the most common weaknesses in Windows Kerberos deployments.
			* [Demo of kerberoasting on EvilCorp Derbycon6](https://adsecurity.org/wp-content/uploads/2016/09/DerbyCon6-2016-AttackingEvilCorp-Anatomy-of-a-Corporate-Hack-Demo-4-kerberoast.mp4)
			* [Attacking EvilCorp Anatomy of a Corporate Hack - Sean Metcalf, Will Schroeder](https://www.youtube.com/watch?v=nJSMJyRNvlM&feature=youtu.be&t=16)
				* [Slides](https://adsecurity.org/wp-content/uploads/2016/09/DerbyCon6-2016-AttackingEvilCorp-Anatomy-of-a-Corporate-Hack-Presented.pdf)
			* [Kerberos & Attacks 101 - Tim Medin(SANS Webcast)](https://www.youtube.com/watch?v=LmbP-XD1SC8)
			    * Want to understand how Kerberos works? Would you like to understand modern Kerberos attacks? If so, then join Tim Medin as he walks you through how to attack Kerberos with ticket attacks and Kerberoasting. Well cover the basics of Kerberos authentication and then show you how the trust model can be exploited for persistence, pivoting, and privilege escalation.
			* [Kerberoasting Revisited - Will Schroeder(Derbycon2019)](https://www.youtube.com/watch?v=yrMGRhyoyGs)
				* Kerberoasting has become the red team'?'s best friend over the past several years, with various tools being built to support this technique. However, by failing to understand a fundamental detail concerning account encryption support, we haven'?'t understood the entire picture. This talk will revisit our favorite TTP, bringing a deeper understanding to how the attack works, what we?ve been missing, and what new tooling and approaches to kerberoasting exist.
		- **Tools**
			* [kerberoast](https://github.com/skelsec/kerberoast)
				* Kerberos attack toolkit -pure python- 
			* KerberOPSEC](https://github.com/Luct0r/KerberOPSEC)
				* OPSEC safe Kerberoasting in C#
			* [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
				* targetedKerberoast is a Python script that can, like many others (e.g. GetUserSPNs.py), print "kerberoast" hashes for user accounts that have a SPN set. This tool brings the following additional feature: for each user without SPNs, it tries to set one (abuse of a write permission on the servicePrincipalName attribute), print the "kerberoast" hash, and delete the temporary SPN set for that operation. This is called targeted Kerberoasting. This tool can be used against all users of a domain, or supplied in a list, or one user supplied in the CLI.
			* [kerberoast](https://github.com/nidem/kerberoast)
				* Kerberoast is a series of tools for attacking MS Kerberos implementations.
			* [tgscrack](https://github.com/leechristensen/tgscrack)
		   		* Kerberos TGS_REP cracker written in Golang
	- **Krbtgt**<a name="krbtgt"></a>
		* [KRBTGT Account Password Reset Scripts now available for customers - Tim Rains(2015)](https://www.microsoft.com/security/blog/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/)
		* [The Secret Life of Krbtgt - Christopher Campbell(Defcon24)](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20video%20and%20slides/DEF%20CON%2022%20Hacking%20Conference%20Presentation%20By%20Christopher%20Campbell%20-%20The%20Secret%20Life%20of%20Krbtgt%20-%20Video%20and%20Slides.m4v)
			* [Slides](https://www.defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf)
	- **noPAC**<a name="nopac"></a>
		- **Articles/Blogposts/Writeups**
			* [CVE-2021-42287/CVE-2021-42278 Weaponisation - exploit.ph(2021)](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
			* [Domain Escalation – sAMAccountName Spoofing - pentestlab.blog(2022)](https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/)
		- **Tools**
			* [noPac - Ridter](https://github.com/Ridter/noPac)
				* Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
			* [noPac - cube0x0](https://github.com/cube0x0/noPac)
				* CVE-2021-42287/CVE-2021-42278 Scanner & Exploiter. Yet another low effort domain user to domain admin exploit.
			* [Invoke-noPac.ps1](https://gist.github.com/S3cur3Th1sSh1t/0ed2fb0b5ae485b68cbc50e89581baa6)
			* [noPac - ricardojba](https://github.com/ricardojba/noPac)
			* [Invoke-noPac](https://github.com/ricardojba/Invoke-noPac)
	- **Relaying Kerberos**<a name="kerbrelay"></a>
		- **Articles/Blogposts/Writeups**
			* [Using Kerberos for Authentication Relay Attacks - James Forshaw(2021)](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
				* "This blog post is a summary of some research I've been doing into relaying Kerberos authentication in Windows domain environments. To keep this blog shorter I am going to assume you have a working knowledge of Windows network authentication, and specifically Kerberos and NTLM. For a quick primer on Kerberos see [this page](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb366abf13) which is part of Microsoft's Kerberos extension documentation or you can always read [RFC4120](https://www.rfc-editor.org/rfc/rfc4120.txt)."
			* [Windows Exploitation Tricks: Relaying DCOM Authentication - James Forshaw(2021)](https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html)
				* "In my previous blog post I discussed the possibility of relaying Kerberos authentication from a DCOM connection. I was originally going to provide a more in-depth explanation of how that works, but as it's quite involved I thought it was worthy of its own blog post. This is primarily a technique to get relay authentication from another user on the same machine and forward that to a network service such as LDAP. You could use this to escalate privileges on a host using a technique similar to a blog post from Shenanigans Labs but removing the requirement for the WebDAV service. Let's get straight to it."
			* [Relaying Kerberos over DNS using krbrelayx and mitm6  - Dirk-jan Mollema(2022)](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
			* [Defending the Three Headed Relay - Andrew Schwartz, Charlie Clark, Jonny Johnson(2022)](https://exploit.ph/defending-the-three-headed-relay.html)
				* "During this blog post we will take a look into Kerberos Relay, break out the different attack paths one could take, and talk about the different defensive opportunities tied to this activity and other activities leading up to Kerberos Relay or after."
		- **Talks/Presentations/Videos**
			* [Taking Kerberos To The Next Level - James Forshaw(BlackHat2022)](https://i.blackhat.com/USA-22/Wednesday/US-22-Forshaw-Taking-Kerberos-To-The-Next-Level.pdf)
			* [These are my Principals... if you don't like them, I have others - James Forshaw(OffensiveCon2022)](https://raw.githubusercontent.com/tyranid/infosec-presentations/master/OffensiveCon/2022/This%20are%20my%20principals.pdf)
		- Tools
			* [KrbRelay](https://github.com/cube0x0/KrbRelay)
				* Framework for Kerberos relaying
			* [Negoexrelayx](https://github.com/morRubin/NegoExRelay)
				* Toolkit for abusing Kerberos PKU2U and NegoEx. Requires impacket It is recommended to install impacket from git directly to have the latest version available.
	- **Tickets**
		- **Silver Tickets**<a name="silver-ticket"></a>
			- **101**
				* [Silver ticket (in short) - Chad Duffey(2019)](https://www.chadduffey.com/2019/06/silver-ticket-in-short.html)
				* [How Attackers Use Kerberos Silver Tickets to Exploit Systems - ADSecurity.org(2011)](https://adsecurity.org/?p=2011)
			- **Articles/Blogposts/Writeups**
				* [Sneaky Active Directory Persistence #16: Computer Accounts & Domain Controller Silver Tickets - adsecurity](https://adsecurity.org/?p=2753)
				* [Impersonating Service Accounts with Silver Tickets - stealthbits](https://blog.stealthbits.com/impersonating-service-accounts-with-silver-tickets)
				* [Mimikatz 2.0 - Silver Ticket Walkthrough](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Silver_Ticket_Walkthrough.html)
				* [Kerberos attacks 3-Silver Ticket - Karim Habeeb(2021)](https://nored0x.github.io/red-teaming/Kerberos-Attacks-Silver-Ticket/)
				* [SpoolSample -> NetNTLMv1 -> NTLM -> Silver Ticket - NotMedic](https://github.com/NotMedic/NetNTLMtoSilverTicket)
			- **Talks/Presentations/Videos**
		- **Gold Tickets**<a name="golden-ticket"></a>
			- **101**
				* [Golden Ticket - ldapwiki](http://ldapwiki.com/wiki/Golden%20Ticket)
				* [Golden Ticket - Pentestlab(2018)](https://pentestlab.blog/2018/04/09/golden-ticket/)
				* [Kerberos Golden Tickets are Now More Golden - ADSecurity.org](https://adsecurity.org/?p=1640)
				* [mimikatz - golden ticket - Balazs Bucsay(2014)](http://rycon.hu/papers/goldenticket.html)
			- **Articles/Blogposts/Writeups**
				* [Domain Persistence: Golden Ticket Attack - Raj Chandel(2020)](https://www.hackingarticles.in/*domain-persistence-golden-ticket-attack/)
				* [Complete Domain Compromise with Golden Tickets - stealthbits](https://blog.stealthbits.com/complete-domain-compromise-with-golden-tickets/)
				* [Pass-the-(Golden)-Ticket with WMIC](https://blog.cobaltstrike.com/2015/01/07/pass-the-golden-ticket-with-wmic/)
				* [Kerberos Golden Tickets are Now More Golden - ADSecurity.org](https://adsecurity.org/?p=1640)
				* [Mimikatz 2.0 - Golden Ticket Walkthrough - Ben Lincoln](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html)
			- **Talks/Presentations/Videos**
				* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall, Benjamin Delpy(BHUSA 2015)](https://www.youtube.com/watch?v=lJQn06QLwEw)
					* Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions.
				* [Advanced Targeted Attack. PoC Golden Ticket Attack - BSides Tampa 17](https://www.irongeek.com/i.php?page=videos/bsidestampa2017/102-advanced-targeted-attack-andy-thompson)
		- **Diamond Tickets**<a name="diamond-ticket"></a>
			* [A Diamond (Ticket) in the Ruff - Charlie Clark, Andrew Schwartz(2022)](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)
			* [Diamond Ticket - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/diamond-ticket)
			* [Diamond Tickets - thehacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond)
				* Golden and Silver Tickets can usually be detected by probes that monitor the service ticket requests (KRB_TGS_REQ) that have no corresponding TGT requests (KRB_AS_REQ). Those types of tickets also feature forged PACs that sometimes fail at mimicking real ones, thus increasing their detection rates. Diamond tickets can be a useful alternative in the way they simply request a normal ticket, decrypt the PAC, modify it, recalculate the signatures and encrypt it again. It requires knowledge of the target service long-term key (can be the krbtgt for a TGT, or a target service for a Service Ticket).
		- **Saphire Tickets**<a name="saphire-ticket"></a>
			* [Saphire Tickets - thehacker.recipes(2022)](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire)
				* Sapphire tickets are similar to Diamond Tickets in the way the ticket is not forged, but instead based on a legitimate one obtained after a request. The difference lays in how the PAC is modified. The Diamond Ticket approach modifies the legitimate PAC to add some privileged groups (or replace it with a fully-forged one). In the Sapphire ticket approach, the PAC of another powerful user is obtained through an S4U2Self+u2u trick. This PAC then replaces the one featured in the legitimate ticket. The resulting ticket is an assembly of legitimate elements, and follows a standard ticket request, which makes it then most difficult silver/golden ticket variant to detect.
	- **Tools**
		* [Rubeus](https://github.com/GhostPack/Rubeus)
		* [Cerbero](https://github.com/zer1t0/cerbero)
			* Kerberos protocol attacker. Tool to perform several tasks related with Kerberos protocol in an Active Directory pentest. (Written in Rust)
		* [kekeo](https://github.com/gentilkiwi/kekeo)
			* A little toolbox to play with Microsoft Kerberos in C
		* [PyKEK](https://github.com/bidord/pykek)
			* PyKEK (Python Kerberos Exploitation Kit), a python library to manipulate KRB5-related data. (Still in development)
		* [Kerberom](https://github.com/Fist0urs/kerberom)
			* Kerberom is a tool aimed to retrieve ARC4-HMAC'ed encrypted Tickets Granting Service (TGS) of accounts having a Service Principal Name (SPN) within an Active Directory
		* [Kerbrute - ropnop](https://github.com/ropnop/kerbrute)
			* A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication
		* [kerbrute - Tarlogic](https://github.com/TarlogicSecurity/kerbrute)
			* An script to perform kerberos bruteforcing by using the Impacket library.
		* [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py)
			* This script will convert kirbi files (commonly used by mimikatz) into ccache files used by impacket, and vice-versa.
- **Lateral Movement**<a name="adlate"></a>
	- **Articles/Blogposts/Writeups**
	- **DCOM**
	- **Internal Phishing**
	- **GPO**
	- **MS-SQL**
		* [MSSQL Lateral Movement - David Cash(2021)](https://research.nccgroup.com/2021/01/21/mssql-lateral-movement/)
			* [Squeak](https://github.com/nccgroup/nccfsas/tree/main/Tools/Squeak)
	- **Pass-the-`*`**
		- **101**
		- **Cache**
			* [Tweet by Benjamin Delpy(2014)](https://twitter.com/gentilkiwi/status/536489791735750656?lang=en&source=post_page---------------------------)
			* [Pass-the-Cache to Domain Compromise - Jamie Shaw](https://medium.com/@jamie.shaw/pass-the-cache-to-domain-compromise-320b6e2ff7da)
				* This post is going to go over a very quick domain compromise by abusing cached Kerberos tickets discovered on a Linux-based jump-box within a Windows domain environment. In essence, we were able to steal cached credentials from a Linux host and use them on a Window-based system to escalate our privileges to domain administrator level.
		- **Hash**
			* For this kind of attack and related ones, check out the Network Attacks page, under Pass-the-Hash.
			* [Pass-the-Hash Web Style - SANS(2013)](https://pen-testing.sans.org/blog/2013/04/05/pass-the-hash-web-style)
			* [Pass the Hash - hackndo](https://en.hackndo.com/pass-the-hash/)
			* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - harmj0y](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
			* [Windows Credential Guard & Mimikatz - nviso(2018)](https://blog.nviso.be/2018/01/09/windows-credential-guard-mimikatz/)
			* [Wendel's Small Hacking Tricks - The Annoying NT_STATUS_INVALID_WORKSTATION](https://www.trustwave.com/Resources/SpiderLabs-Blog/Wendel-s-Small-Hacking-Tricks---The-Annoying-NT_STATUS_INVALID_WORKSTATION-/)
			* [Passing the hash with native RDP client (mstsc.exe) - Michael Eder(2018)](https://michael-eder.net/post/2018/native_rdp_pass_the_hash/)
				* TL;DR: If the remote server allows Restricted Admin login, it is possible to login via RDP by passing the hash using the native 	Windows RDP client mstsc.exe. (You’ll need mimikatz or something else to inject the hash into the process)
			* [Pass-The-Hash with RDP in 2019 - shellz.club](https://shellz.club/pass-the-hash-with-rdp-in-2019/)
			* [Alternative ways to Pass the Hash (PtH) - n00py(2020)](https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/)
			* [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)
				* Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB services are accessed through .NET TCPClient connections. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
		- **Over-Pass-the-Hash**
			- **Articles/Blogposts/Writeups**
				* [Overpass-the-hash - Benjamin Delpy(2014)](http://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
				* [Lateral Movement: Over Pass the Hash - Pavandeep Singh(2020)](https://www.hackingarticles.in/lateral-movement-over-pass-the-hash/)
				* [Play with Hashes — Over Pass The Hash Attack - Nairuz Abulhul(2022)](https://medium.com/r3d-buck3t/play-with-hashes-over-pass-the-hash-attack-2030b900562d)
				* [Over Pass the Hash/Pass the Key - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/over-pass-the-hash-pass-the-key)
			- **Articles/Blogposts/Writeups**
				* [Overpass the hash - Chad Duffey(2019)](https://www.chadduffey.com/2019/06/overpass-the-hash.html)
				* [Lateral Movement: Over Pass the Hash - Pavandeep Singh(2020)](https://www.hackingarticles.in/lateral-movement-over-pass-the-hash/)
		- **Tickets**
			* [How To Pass the Ticket Through SSH Tunnels](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
			* [Pass-the-ticket - ldapwiki](http://ldapwiki.com/wiki/Pass-the-ticket)
			* [Silver & Golden Tickets - hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/)
			* [Lateral Movement: Pass the Ticket Attack - Pavandeep Singh(2020)](https://www.hackingarticles.in/lateral-movement-pass-the-ticket-attack/)
			- **Silver**
				* See ['Silver-Tickets'](#silver-ticket)
			- **Golden**
				* See ['Golden-Tickets'](#golden-ticket)
	- **RDP**
	- **RPC**
	- **SCCM**
	- **Scheduled Tasks**
	- **Service Creation/Modification**
	- **SMB**
	- **SSH**
	- **WinRM**
	- **WMI**
		* [Lateral Movement: WMI - Pavandeep Singh(2020)](https://www.hackingarticles.in/lateral-movement-wmi/)
	- **Tools**
		- **CrackMapExec**
			* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
				* [Lateral Moment on Active Directory: CrackMapExec - Yashika Dhir(2020)](https://www.hackingarticles.in/lateral-moment-on-active-directory-crackmapexec/)
		- **Impacket**
			* [Impacket Deep Dives Vol. 1: Command Execution - Kyle Mistele(2021)](https://kylemistele.medium.com/impacket-deep-dives-vol-1-command-execution-abb0144a351d)
- **(Attacking the) Machine-Account Quota**<a name="maq"></a>
	- **101**
		* [MS-DS-Machine-Account-Quota attribute - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)
			* The number of computer accounts that a user is allowed to create in a domain.
	- **Articles/Blogposts/Writeups**
		* [MachineAccountQuota is USEFUL Sometimes: Exploiting One of Active Directory’s Oddest Settings - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)
- **MS-Cache**<a name="mscache"></a>
	- **101**
		* [Interactive logon: Number of previous logons to cache (in case domain controller is not available) - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj852209(v=ws.11)?redirectedfrom=MSDN)
			* This security policy reference topic for the IT professional describes the best practices, location, values, policy management and security considerations for this policy setting. Applies To: Windows Server 2003, Windows Vista, Windows XP, Windows Server 2008, Windows 7, Windows 8.1, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2012, Windows 8
		* [(Win10)Interactive logon: Number of previous logons to cache (in case domain controller is not available) - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available)
			* Describes the best practices, location, values, policy management and security considerations for the Interactive logon: Number of previous logons to cache (in case domain controller is not available) security policy setting. Applies To: Win10
		* [Cached domain logon information - support.ms](https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information)
	- **Articles/Blogposts/Writeups**
		* [MSCash Hash Primer for Pentesters - webstersprodigy.com(2014)](https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/)
		* [Cracking MS-CACHE v2 hashes using GPU - Security.StackExchange](https://security.stackexchange.com/questions/30889/cracking-ms-cache-v2-hashes-using-gpu)
		* [Interactive logon: Number of previous logons to cache (in case domain controller is not available - UltimateWindowsSecurity](https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=ILNumPrev)
	- **Tools**
		* [passlib.hash.msdcc2 - Windows’ Domain Cached Credentials v2](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.msdcc2.html)
			* This class implements the DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer to cache and verify remote credentials when the relevant server is unavailable. It is known by a number of other names, including “mscache2” and “mscash2” (Microsoft CAched haSH). It replaces the weaker msdcc v1 hash used by previous releases of Windows. Security wise it is not particularly weak, but due to its use of the username as a salt, it should probably not be used for anything but verifying existing cached credentials.
- **NTLM-focused Attacks**<a name="ntlmattack"></a>
	- **Overview of attacks against NTLM**
		* [Practical Attacks against NTLMv1 - Esteban Rodriguez(2022)](https://www.trustedsec.com/blog/practical-attacks-against-ntlmv1/)
	- **NTLM Downgrade**
		* [NTLMv1 vs NTLMv2: Digging into an NTLM Downgrade Attack - Adam Crosser(2022)](https://www.praetorian.com/blog/ntlmv1-vs-ntlmv2/)
		* [SpoolSample -> NetNTLMv1 -> NTLM -> Silver Ticket Writeup](https://github.com/NotMedic/NetNTLMtoSilverTicket)
		* [NTLMv1_Downgrade.md](https://gist.github.com/S3cur3Th1sSh1t/0c017018c2000b1d5eddf2d6a194b7bb)
	- **NTLM Reflection**
		* **101**
			* [Windows: DCOM DCE/RPC Local NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=325&redir=1)
			* [Windows: Local WebDAV NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=222&redir=1)
		* **Articles/Blogposts/Writeups**
	- **NTLM over QUIC**
		* [NTLMquic - Adam Chester(2022)](https://blog.xpnsec.com/ntlmquic/)
	- **NTLM Relay**<a name="ntlmrelay"></a>
		* See `Coerced Auth`
		- **101**
			* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes) - byt3bl33d3r(2017)](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
			* [NTLM Relay - Pixis](https://en.hackndo.com/ntlm-relay/)
			* [Relaying 101 - LuemmelSec(2021)](https://luemmelsec.github.io/Relaying-101/)
			* [NTLM Relaying - thehacker.recipes(2022)](https://www.thehacker.recipes/ad/movement/ntlm/relay)
			* [I’m bringing relaying back: A comprehensive guide on relaying anno 2022 - Jean-Francois Maes(2022)](https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/)

		- **Articles/Blogposts/Writeups**
			* [Server Message Block: SMB Relay Attack (Attack That Always Works) - CQURE Academy](https://cqureacademy.com/blog/penetration-testing/smb-relay-attack)
			* [An SMB Relay Race – How To Exploit LLMNR and SMB Message Signing for Fun and Profit - Jordan Drysdale](https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/)
			* [Effective NTLM / SMB Relaying - mubix(2014)](https://malicious.link/post/2014/effective-ntlm-smb-relaying/)
			* [SMB Relay with Snarf - Jeff Dimmock(2016)](https://bluescreenofjeff.com/2016-02-19-smb-relay-with-snarfjs-making-the-most-of-your-mitm/)
			* [Pwning with Responder – A Pentester’s Guide](https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/)
			* [Relaying credentials everywhere with ntlmrelayx](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/)		
			* [Responder with NTLM relay and Empire - chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/execution/responder-with-ntlm-relay-and-empire.html)
			* [Playing with Relayed Credentials - @agsolino(2018)](https://www.secureauth.com/blog/playing-relayed-credentials)
			* [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
				* Earlier this week, Microsoft issued patches for CVE-2019-1040, which is a vulnerability that allows for bypassing of NTLM relay mitigations. The vulnerability was discovered by Marina Simakov and Yaron Zinar (as well as several others credited in the Microsoft advisory), and they published a technical write-up about the vulnerability here. The short version is that this vulnerability allows for bypassing of the Message Integrity Code in NTLM authentication. The impact of this however, is quite big if combined with the Printer Bug discovered by Lee Christensen and some of my own research that builds forth on the Kerberos research of Elad Shamir. Using a combination of these vulnerabilities, it is possible to relay SMB authentication to LDAP. This allows for Remote code execution as SYSTEM on any unpatched Windows server or workstation (even those that are in different Active Directory forests), and for instant escalation to Domain Admin via any unpatched Exchange server (unless Exchange permissions were reduced in the domain). The most important takeaway of this post is that you should apply the June 2019 patches as soon as possible.
				* [CVE-2019-1040 scanner](https://github.com/fox-it/cve-2019-1040-scanner)
			* [What is old is new again: The Relay Attack - @0xdeaddood, @agsolino(2020)](https://www.secureauth.com/blog/what-old-new-again-relay-attack)
				* The purpose of this blog post is to present a new approach to ntlmrelayx.py allowing multi-relay attacks, that means, using just a single connection to attack several targets. On top of this, we added the capability of relaying connections for specific target users.
			* [SMB Relay - cheatsheet(2019)](https://aas-s3curity.gitbook.io/cheatsheet/internalpentest/active-directory/exploitation/exploit-without-account/smb-relay)
				* This page deals with gaining code execution relaying NTLMv1/2 hashes in a very effective manner.
			* [NTLM relay of ADWS (WCF) connections with Impacket - Clement Notin(2020)](https://clement.notin.org/blog/2020/11/16/ntlm-relay-of-adws-connections-with-impacket/)
			* [Relaying Potatoes: Another Unexpected Privilege Escalation Vulnerability in Windows RPC Protocol - Antonio Cocomazzi(2021)](https://www.sentinelone.com/labs/relaying-potatoes-another-unexpected-privilege-escalation-vulnerability-in-windows-rpc-protocol/)
			* [NTLMRelay2Self](https://github.com/med0x2e/NTLMRelay2Self)
				* "Just a walkthrough of how to escalate privileges locally by forcing the system you landed initial access on to reflectively authenticate over HTTP to itself and forward the received connection to an HTTP listener (ntlmrelayx) configured to relay to DC servers over LDAP/LDAPs for either setting shadow credentials or configuring RBCD. This would result in a valid kerberos TGT ticket that can be used to obtain a TGS for a service (HOST/CIFS) using S4U2Self by impersonating a user with local administrator access to the host (domain admin ..etc), or alternatively, it's also possible to retrieve the machine account's NTLM hash with getnthash.py and then create a silver ticket. Lastly, use the TGS or silver ticket to spawn a system (session 0) process, this can be achieved by simply using WMIExec or alternatively using SCMUACBypass script to rely on kerberos for auth to interact with the SCM and create a service in the context of SYSTEM."
			* [Relaying to ADFS Attacks - Michael Crosser(2022)](https://www.praetorian.com/blog/relaying-to-adfs-attacks/)

		- **Talks**
			* [Relaying Credentials has Never Been Easier - Marina Simakov(DEFCON27)](https://www.youtube.com/watch?v=vIISsfLh4iM)
				* Active Directory has always been a popular target for attackers, with a constant rise in attack tools attempting to compromise and abuse the main secrets storage of the organization. One of the weakest spots in Active Directory environments lies in the design of one of the oldest authentication protocols – NTLM, which is a constant source of newly discovered vulnerabilities. From CVE-2015-0005, to the recent LDAPS Relay vulnerability, it is clear why this protocol is one of the attackers’ favorites. Although there are offered mitigations such as server signing, protecting the entire domain from NTLM relay is virtually impossible. If it weren’t bad enough already, we will present several new ways to abuse this infamous authentication protocol, including a new critical zero-day vulnerability we have discovered which enables to perform NTLM Relay and take over any machine in the domain, even with the strictest security configuration, while bypassing all of today's offered mitigations. Furthermore, we will present why the risks of this protocol are not limited to the boundaries of the on-premises environment and show another vulnerability which allows to bypass various AD-FS restrictions in order to take over cloud resources as well.
			* [Relaying to Greatness: Windows Privilege Escalation by abusing the RPC/DCOM protocols - Antonio Cocomazzi, Andrea Pierini(BlueHatIL2022)](https://www.youtube.com/watch?v=vfb-bH_HaW4)
				* NTLM “Relaying” is a well known replay attack for Windows systems in which the attacker performs a man in the middle and acts on behalf of the victim while communicating with a remote server by altering the network packets. In recent years, all of the research and mitigations have been done on the most used protocols which use NTLM as an authentication mechanism like SMB, LDAP, HTTP... What about RPC? RPC is a protocol heavily used internally by Windows systems for inter process communication and to support all the COM/DCOM protocol. In this talk, we will uncover this unexplored attack surface and demonstrate a novel way of performing NTLM relay attacks based on the RPC/DCOM protocols. Within this talk, we will show our tool to exploit this vulnerability and enable further scenarios of exploitation especially in Active Directory environments: the RemotePotato0. This changes the approach of attacking Windows servers in which multiple users are logged on. RemotePotato0 will allow stealing and relaying authentications to remote privileged resources even from an unprivileged user thus allowing to achieve privilege escalation and to break the multi-user security model of Windows systems.
		- **Tools**
			* [Responder](https://github.com/lgandx/Responder)
				* IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner and NTLMv1/2 Relay.
			* [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
				* .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers 
			* [pretender](https://github.com/RedTeamPentesting/pretender)
				* pretender is a tool developed by RedTeam Pentesting to obtain machine-in-the-middle positions via spoofed local name resolution and DHCPv6 DNS takeover attacks. pretender primarily targets Windows hosts, as it is intended to be used for relaying attacks but can be deployed on Linux, Windows and all other platforms Go supports. Name resolution queries can be answered with arbitrary IPs for situations where the relaying tool runs on a different host than pretender. It is designed to work with tools such as Impacket's ntlmrelayx.py and krbrelayx that handle the incoming connections for relaying attacks or hash dumping.
			* [ADFSRelay](https://github.com/praetorian-inc/ADFSRelay)
				* This repository includes two utilities NTLMParse and ADFSRelay. NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS. We have also released a blog post discussing ADFS relaying attacks in more detail.
			* [RemotePotato0](https://github.com/antonioCoco/RemotePotato0)
				* "It abuses the DCOM activation service and trigger an NTLM authentication of any user currently logged on in the target machine. It is required that a privileged user is logged on the same machine (e.g. a Domain Admin user). Once the NTLM type1 is triggered we setup a cross protocol relay server that receive the privileged type1 message and relay it to a third resource by unpacking the RPC protocol and packing the authentication over HTTP. On the receiving end you can setup a further relay node (eg. ntlmrelayx) or relay directly to a privileged resource."
		- **Mitigation**
			* Enforce SMB Signing.
			* [How to enable SMB signing in Windows NT - support.ms](https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt)
			* [All You Need To Know About Windows SMB Signing - Lavanya Rathnam(2018)](http://techgenix.com/windows-smb-signing/)
- **(OUs) Attacking**<a name="aou"></a>
	- **Articles/Blogposts/Writeups**
		* [OU having a laugh? - Petros Koutroumpis](https://labs.f-secure.com/blog/ou-having-a-laugh/)
			* tl;dr When we have permission to modify an OU, we can modify its gpLink attribute in order to compromise any computer or user that belongs to that OU or its child OUs.
	- **Talks/Presentations/Videos**
		* [OU having a laugh? - Petros Koutroumpis(RedTeamVillage2020)](https://www.youtube.com/watch?v=un2EbYjp3Zg&list=PLruly0ngXhPHlQ0ebMbB3XuKVJPq3B0qS&index=21&t=0s)
- **Persistence**<a name="adpersist"></a>
	- **Articles/Blogposts/Writeups**
		* [Command and Control Using Active Directory - harmj0y](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
		* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP) - adsecurity.org](https://adsecurity.org/?p=1760)
	- **Presentations/Talks/Videos**
		* [Catch Me if You Can - Eduardo Arriols(DefconSafeMode RTV2020](https://www.youtube.com/watch?v=IrX5uVCgUGM&list=PLruly0ngXhPHlQ0ebMbB3XuKVJPq3B0qS&index=24&t=0s)
			* The presentation will show, from a technical point of view, how to deploy backdoors to guarantee access to an organization. Initially, a brief review about types of persistance, locations where it can be deploy and common aspects to be taken into account will be carried out, to then go on to describe all the details that allow a Red Team to guarantee access to the entity without the organization being able to detect it or being able to expel the attacker before the attacker re-enters using another alternative persistence.
		* [The Active Directory Botnet - Ty Miller, Paul Kalinin(BHUSA 17)](https://www.blackhat.com/docs/us-17/wednesday/us-17-Miller-The-Active-Directory-Botnet.pdf)
	- **ACLs & Security Descriptors**
		* [An ACE in the Hole: Stealthy Host Persistence via Security Descriptors - Lee Christensen & Matt Nelson & Will Schroeder(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/t105-an-ace-in-the-hole-stealthy-host-persistence-via-security-descriptors-lee-christensen-matt-nelson-will-schroeder)
			* Attackers and information security professionals are increasingly looking at security descriptors and their ACLs, but most previous work has focused on escalation opportunities based on ACL implementation flaws and misconfigurations. However, the nefarious use of security descriptors as a persistence mechanism is rarely mentioned. Just like with Active Directory ACLs, it's often difficult to determine whether a specific security descriptor was set intentionally by an IT administrator, intentionally set by an attacker, or inadvertently set by an IT administrator via a third-party installation program. This uncertainty decreases the likelihood of attackers being discovered, granting attackers a great opportunity to persist on a host and in a network. We’ll dive deep into ACLs/DACLs/SACLs/ACEs/Security Descriptors and more, giving you the background to grasp the capabilities we’re talking about. Then we’ll describe dive into several case studies that demonstrate how attackers can use securable object takeover primitives to maliciously backdoor host-based security descriptors for the purposes of persistence, including, “gold image” backdooring, subverting DCOM application permissions, and more. We’ll conclude with an exhaustive overview of the deployment and detections of host-based security descriptor backdoors. All along the way we’ll be releasing new tooling to enumerate, exploit, and analyze host-based security descriptors.
		* [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors - Andy Robbins, Will Schroeder(BHUSA2017)](https://www.youtube.com/watch?v=ys1LZ1MzIxE)
			* [Slides](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-2018.pdf)
			* [Paper](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
			* Active Directory (AD) object discretionary access control lists (DACLs) are an untapped offensive landscape, often overlooked by attackers and defenders alike. The control relationships between AD objects align perfectly with the "attackers think in graphs" philosophy and expose an entire class of previously unseen control edges, dramatically expanding the number of paths to complete domain compromise.
	- **AdminSDHolder**
		* [Sneaky Active Directory Persistence #15: Leverage AdminSDHolder & SDProp to (Re)Gain Domain Admin Rights](https://adsecurity.org/?p=1906)
		* [Persistence Using Adminsdholder And Sdprop](https://blog.stealthbits.com/persistence-using-adminsdholder-and-sdprop/)
		* [Domain Persistence AdminSDHolder - Raj Chandel(2020)](https://www.hackingarticles.in/domain-persistence-adminsdholder/)
		* [Domain Persistence – AdminSDHolder - NetbiosX(2022)](https://pentestlab.blog/2022/01/04/domain-persistence-adminsdholder/)
	- **DCShadow**
		* [Creating Persistence With Dcshadow](https://blog.stealthbits.com/creating-persistence-with-dcshadow/)
		* [Domain Persistence: DC Shadow Attack - Raj Chandel(2020)](https://www.hackingarticles.in/domain-persistence-dc-shadow-attack/)
	- **Directory Services Restore Mode**
		* [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
		* [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)
	- **gMSA-related**
		* [Active Directory persistence through userAccountControl manipulation - Joe Dibley(2020)](https://stealthbits.com/blog/server-untrust-account/)
	- **Group Policy Object**
		* [Sneaky Active Directory Persistence #17: Group Policy](https://adsecurity.org/?p=2716)
	- **Machine Accounts**
		* [Domain Persistence – Machine Account - NetbiosX(2022)](https://pentestlab.blog/2022/01/17/domain-persistence-machine-account/)
	- **Managed By**
		* [Hiding in the shadows at Members attribute - thesecurityblogger.com(2019)](https://www.thesecurityblogger.com/hiding-in-the-shadows-at-members-attribute/)
	- **msDS-KeyCredentialLink/Shadow Creds**
		* [Shadow Credentials - NetbiosX(2022)](https://pentestlab.blog/2022/02/07/shadow-credentials/)
	- **SeEnableDelegationPrivilege**
		* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
		* [SeEnableDelegationPrivilege Active Directory Backdoor](https://www.youtube.com/watch?v=OiqaO9RHskU)
	- **Security Support Provider**
		* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760)
	- **SID History**
		* [Sneaky Active Directory Persistence #14: SID History](https://adsecurity.org/?p=1772)
	- **Tickets**
		- **101**
			* [Detecting Lateral Movements in Windows Infrastructure - CERT-EU(2017)](https://cert.europa.eu/static/WhitePapers/CERT-EU_SWP_17-002_Lateral_Movements.pdf)
			* [Kerberos & KRBTGT: Active Directory’s Domain Kerberos Service Account - ADSecurity.org](https://adsecurity.org/?p=483)
			* [Maximum lifetime for user ticket - docs.ms](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket)
			* [Silver and Golden Tickets for Pentesters - henpeebin(2021)](https://henpeebin.com/kevin/blog/silver-and-golden-tickets-for-pentesters.html)
		- **Silver Ticket**
			* See ['Silver Tickets'](#silver-ticket)
		- **Golden Tickets**
			* See ['Saphire Tickets'](#golden-ticket)
		- **Diamond Tickets**
			* See ['Diamond Tickets'](#diamond-ticket)
		- **Saphire Tickets**
			* See ['Saphire Tickets'](#saphire-ticket)
	- **Skeleton Keys**
		* [Unlocking All The Doors To Active Directory With The Skeleton Key Attack](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)
		* [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
		* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)
	- **SPNs/Kerberoast**
		* [Sneaky Persistence Active Directory Trick #18: Dropping SPNs on Admin Accounts for Later Kerberoasting - Sean Metcalf(2017)](https://adsecurity.org/?p=3466)
- **Printers & Faxes (Attacking)**<a name="pfa"></a>
	- **Articles/Blogposts/Writeups**
		* [Hacking Printers Wiki](http://hacking-printers.net/wiki/index.php/Main_Page)
			* This is the Hacking Printers Wiki, an open approach to share knowledge on printer (in)security.
	- **Talks/Presentations/Videos**
		* [From Printer to Pwned: Leveraging Multifunction Printers During Penetration Testing - Deral Heiland(Defcon18)](https://www.youtube.com/watch?v=bAgMUXtxNa8)
			* [BSides Cleveland Version](https://www.irongeek.com/i.php?page=videos/bsidescleveland2014/plunder-pillage-and-print-the-art-of-leverage-multifunction-printers-during-penetration-testing-deral-heiland)
			* [Slides](https://defcon.org/images/defcon-19/dc-19-presentations/Heiland/DEFCON-19-Heiland-Printer-To-Pwnd.pdf)
			* In this presentation we go beyond the common printer issues and focus on harvesting data from multifunction printer (MFP) that can be leveraged to gain access to other core network systems. By taking advantage of poor printer security and vulnerabilities during penetration testing we are able to harvest a wealth of information from MFP devices including usernames, email addresses, and authentication information including SMB, Email, LDAP passwords. Leveraging this information we have successful gained administrative access into core systems including email servers, file servers and Active directory domains on multiple occasions. We will also explore MFP device vulnerabilities including authentication bypass, information leakage flaws. Tying this altogether we will discuss the development of an automated process for harvesting the information from MFP devices with the updated release of our tool 'PRAEDA'.
	- **BYoVPD**
		* [Bring Your Own Print Driver Vulnerability - Jacob Baines(Defcon29)](https://www.youtube.com/watch?v=vdesswZYz-8)
			* What can you do, as an attacker, when you find yourself as a low privileged Windows user with no path to SYSTEM? Install a vulnerable print driver! In this talk, you'll learn how to introduce vulnerable print drivers to a fully patched system. Then, using three examples, you'll learn how to use the vulnerable drivers to escalate to SYSTEM.
		* [Concealed Position](https://github.com/jacob-baines/concealed_position)
			* Concealed Position is a local privilege escalation attack against Windows using the concept of "Bring Your Own Vulnerability". Specifically, Concealed Position (CP) uses the as designed package point and print logic in Windows that allows a low privilege user to stage and install printer drivers. CP specifically installs drivers with known vulnerabilities which are then exploited to escalate to SYSTEM. Concealed Position was first presented at DEF CON 29.
	- **Evil Printer**
		- [Evil Printer: How to Hack Windows Machines with Printing Protocol - Zhipeng Huo, Chuanda Ding(Defcon28)](https://www.youtube.com/watch?v=be2jOZM8Whs)
		* [Slides](https://media.defcon.org/DEF%20CON%2028/DEF%20CON%20Safe%20Mode%20presentations/DEF%20CON%20Safe%20Mode%20-%20Zhipeng-Huo%20and%20Chuanda-Ding%20-%20Evil%20Printer%20How%20to%20Hack%20Windows%20Machines%20with%20Printing%20Protocol.pdf)
			* In this talk, we will walk you through an incredibly fun bug we have discovered in printer spooler service. It can be exploited both locally and remotely, escapes sandbox, executes arbitrary code, and also elevates to SYSTEM. While Microsoft managed to develop the most restrictive sandbox for Microsoft Edge, this bug easily goes through it like it's a sieve. We will talk in detail the implementation of this ancient service, the method we used to discover and exploit the bug, and also throw in some tips and tricks for logic bugs in between.
	- **'Passback' attack**
		* [Anatomy of a Pass-Back-Attack: Intercepting Authentication Credentials Stored in Multifunction Printers - Deral (PercX) Heiland, Michael (omi) Belton](http://foofus.net/goons/percx/praeda/pass-back-attack.pdf)
		* [OpenLDAP for LDAP Plain Text Password Capture  - Danny Rappleyea(2015)](https://www.digitalreplica.org/articles/openldap-for-ldap-plain-text-password-capture/)
		* [Snatching Domain Creds from Unexpected Places. - True Demon(2019)](https://www.devilsec.io/2019/04/29/hacking-printers-for-profit/)
	- **Persistence**
		* [printjacker](https://github.com/RedSection/printjacker)
			* Printjacker is a post-exploitation tool that creates a persistence mechanism by overwriting Printconfig.dll with a shellcode injector. The persistence mechanism can be invoked via executing wmic printer list command with any user. The shellcode will be executed with SYSTEM privileges.
	- **PrintNightmare**
		- **Articles**
			* [Demystifying The PrintNightmare Vulnerability - Shlomo Zarinkhou, Haim Nachmias, Oren Biderman, Doron Vazgiel(2021)](https://blog.sygnia.co/demystifying-the-print-nightmare-vulnerability)
			* [PrintNightmare - NetbiosX(2021)](https://pentestlab.blog/2021/08/17/domain-escalation-printnightmare/)
			https://twitter.com/gentilkiwi/status/1420069224106577927
			* [Playing with PrintNightmare - 0xdf(2021)](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html)
		- **Tools**
			* [PrintNightmare exploit](https://github.com/outflanknl/PrintNightmare)
				* Reflective Dll implementation of the PrintNightmare PoC by Cornelis de Plaa (@Cneelis). The exploit was originally created by Zhiniang Peng (@edwardzpeng) & Xuefeng Li (@lxf02942370).
			* [CVE-2021-1675(PrintNightmare)](https://github.com/sailay1996/PrintNightmare-LPE)
				* system shell poc for CVE-2021-1675 (Windows Print Spooler Elevation of Privilege)
			* [ItWasAllADream](https://github.com/byt3bl33d3r/ItWasAllADream)
				* A PrintNightmare (CVE-2021-34527) Python Scanner. Scan entire subnets for hosts vulnerable to the PrintNightmare RCE
			* [PrintNightmare](https://github.com/ly4k/PrintNightmare)
				* Python implementation for PrintNightmare (CVE-2021-1675 / CVE-2021-34527) using standard Impacket.
			* [PrintNightmare - Windows Print Spooler RCE/LPE Vulnerability (CVE-2021-34527, CVE-2021-1675)](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527)
			* [CVE-2021-34527 - PrintNightmare LPE (PowerShell)](https://github.com/JohnHammond/CVE-2021-34527)
			* https://github.com/AndrewTrube/CVE-2021-1675
	- **PrintSpoofer**
		- **Articles**
			* [PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019 - itm4n(2020)](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
		- **Tools**
			* [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
	- **PrintSpooler**
		- **Articles**
			* [Windows Print Spooler Patch Bypass Re-Enables Persistent Backdoor - Simon Zuckerbraun(2020)](https://www.zerodayinitiative.com/blog/2020/8/11/windows-print-spooler-patch-bypass-re-enables-persistent-backdoor)
			* [PrintDemon: Print Spooler Privilege Escalation, Persistence & Stealth (CVE-2020-1048 & more) - Yarden Shafir, Alex Ionescu(2020)](https://windows-internals.com/printdemon-cve-2020-1048/)
			* [PrintDemon](https://github.com/ionescu007/PrintDemon)
				* PrintDemon is a PoC for a series of issues in the Windows Print Spooler service, as well as potetial misuses of the functionality.
			* [CVE-2020-1337 – PrintDemon is dead, long live PrintDemon! - voidsec(2020)](https://voidsec.com/cve-2020-1337-printdemon-is-dead-long-live-printdemon/)
				* [Security Advisory: MSRPC Printer Spooler Relay (CVE-2021-1678) - Eyal Karni, Alex Ionescu(2021)](https://www.crowdstrike.com/blog/cve-2021-1678-printer-spooler-relay-security-advisory/)
				* [Spooler Service Abuse - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printers-spooler-service-abuse)
		- **Tools**
			* [Print Spooler Research Tools](https://github.com/SafeBreach-Labs/Spooler)
				* The repository contains the tools we developed during our Print Spooler research which we presented in Black Hat USA 2020 and DEFCON28 Safe Mode ("A Decade After Stuxnet's Printer Vulnerability: Printing is still the Stairway to Heaven".)
	- **SpoolFool / CVE-2022-21999**
		* [SpoolFool: Windows Print Spooler Privilege Escalation (CVE-2022-21999) - Oliver Lyak(2022)](https://research.ifcr.dk/spoolfool-windows-print-spooler-privilege-escalation-cve-2022-22718-bf7752b68d81)
	- **Tools**
		* [SpoolSploit](https://github.com/BeetleChunks/SpoolSploit)
			*  A collection of Windows print spooler exploits containerized with other utilities for practical exploitation. 
- **Privilege Escalation**<a name="adprivesc"></a>
	- **Collections**
		* [A Years Worth of Active Directory Privilege Escalation - Felix Aeppli(2021)](https://blog.compass-security.com/2021/12/a-years-worth-of-active-directory-privilege-escalation/)
	- **Aiming for DA**
		* [Windows Privilege Escalation Part 2: Domain Admin Privileges - Scott Sutherland(2009)](https://www.netspi.com/blog/technical/network-penetration-testing/windows-privilege-escalation-part-2-domain-admin-privileges/)
		* [Post-Exploitation in Windows: From Local Admin To Domain Admin (efficiently) - pentestmonkey](http://pentestmonkey.net/uncategorized/from-local-admin-to-domain-admin))
		* [Scenario-based pen-testing: From zero to domain admin with no missing patches required - Georgia Weidman](https://www.computerworld.com/article/2843632/scenario-based-pen-testing-from-zero-to-domain-admin-with-no-missing-patches-required.html)
		* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
		* [Exploiting Active Directory Administrator Insecurities - Sean Metcalf(Defcon26)](https://adsecurity.org/wp-content/uploads/2018/08/2018-DEFCON-ExploitingADAdministratorInsecurities-Metcalf.pdf)
		* [Attack Methods for Gaining Domain Admin Rights in Active Directory - adsecurity](https://adsecurity.org/?p=2362)
		* [Gaining Domain Admin from Outside Active Directory - markitzeroday.com](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
		* [Paving The Way to DA - Complete Post (Pt 1,2 & 3) - Andy Gil(2021)](https://blog.zsec.uk/paving-2-da-wholeset/)
	- **Aiming for Enterprise Admin**
		* [Elevated Domain Admins to Enterprise Admins - Vincent Letoux](https://raw.githubusercontent.com/vletoux/MakeMeEnterpriseAdmin/master/MakeMeEnterpriseAdmin.ps1)
	- **ACEs/ACLs/DACLs**
		* [DACL Permissions Overwrite Privilege Escalation (CVE-2019-0841) - Nabeel Ahmed(2019)](https://krbtgt.pw/dacl-permissions-overwrite-privilege-escalation-cve-2019-0841/)
			* This vulnerability allows low privileged users to hijack file that are owned by NT AUTHORITY\SYSTEM by overwriting permissions on the targeted file. Successful exploitation results in "Full Control" permissions for the low privileged user.
		* [Microsoft Exchange – ACL - NetbiosX](https://pentestlab.blog/2019/09/12/microsoft-exchange-acl/)
		* [RACE Minimal Rights and ACE for Active Directory Dominance - Nikhil Mittal(Defcon27)](https://www.youtube.com/watch?v=M7Z5h6reGc4)
			* [Slides](https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20presentations/DEFCON-27-Nikhil-Mittal-RACE-Minimal-Rights-and-ACE-for-Active-Directory-Dominance.pdf)
			* [Blogpost](http://www.labofapenetrationtester.com/2019/08/race.html)
			* 'It is possible to execute interesting persistence and on-demand privilege escalation attacks against Windows machines by only modifying ACLs of various objects. We will need administrator privileges initially. '
	- **Airstrike**
		* [Airstrike Attack - FDE bypass and EoP on domain joined Windows workstations (CVE-2021-28316) - Matthew Johnson(2021)](https://shenaniganslabs.io/2021/04/13/Airstrike.html)
	- **BackupOperatorToDA**
		* [The Backup Operators Guide to the Galaxy - Dave Mayer(2019)](https://www.inguardians.com/the-backup-operators-guide-to-the-galaxy/presentations/)
		* [From Backup Operator To Domain Admin](https://github.com/mpgn/BackupOperatorToDA)
			* From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
	- **Certificates**
		* [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) - Oliver Lyak(2022)](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
	- **DNSAdmins / CVE-2021-40469**
		* [Windows DNS Server Remote Code Execution Vulnerability - CVE-2021-40469](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40469)
		* [Feature, not bug: DNSAdmin to DC compromise in one line - Shay Ber(2017)](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
		* [Abusing DNSAdmins privilege for escalation in Active Directory - Nikhil Mittal(2017)](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
		* [Windows Privilege Escalation: DNSAdmins to Domain Admins - Server Level DLL Injection - Abhinav Gyawali(2019)](https://www.abhizer.com/windows-privilege-escalation-dnsadmin-to-domaincontroller/)
		* [Escalating Privileges with DNSAdmins Group - Nairuz Abulhul(2021)](https://medium.com/r3d-buck3t/escalating-privileges-with-dnsadmins-group-active-directory-6f7adbc7005b)
		* [From DnsAdmins to SYSTEM to Domain Compromise - spotheplanet(2021)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)
		* [dns-exe-persistance](https://github.com/dim0x69/dns-exe-persistance)
			* sample plugin dll for windows DNS server: ServerLevelPluginDll
	- **Exploits**
		* [Gone to the Dogs - Elad Shamir](https://shenaniganslabs.io/2019/08/08/Lock-Screen-LPE.html)
			* Win10 PrivEsc Domain Joined
		* [CVE-2018-8340: Multi-Factor Mixup: Who Were You Again? - Andrew Lee](https://www.okta.com/security-blog/2018/08/multi-factor-authentication-microsoft-adfs-vulnerability)
			* A weakness in the Microsoft ADFS protocol for integration with MFA products allows a second factor for one account to be used for second-factor authentication to all other accounts in an organization.
		* [MS CVE-2018-8340](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8340)
		* [CVE-2020-0665 | Active Directory Elevation of Privilege Vulnerability - portal.msrc](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0665)
		* [WSUS Attacks Part 2: CVE-2020-1013 a Windows 10 Local Privilege Escalation 1-Day - Maxime Nadeau(2020)](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
		* [CVE-2020-1472 | Netlogon Elevation of Privilege Vulnerability - msrc](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472)
			* An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network.
	- **Forced Prompt**
		* [SharpLoginPrompt - Success and a Curious Case - Intruder()](https://www.redteam.cafe/phishing/sharploginprompt-success-and-a-curious-case)
		* [Sharp Login Prompt](https://github.com/shantanu561993/SharpLoginPrompt)
			* This Program creates a login prompt to gather username and password of the current user. This project allows red team to phish username and password of the current user without touching lsass and having adminitrator credentials on the system.
	- **Group Policy**
			* [How to own any windows network with group policy hijacking attacks](https://labs.mwrinfosecurity.com/blog/2015/04/02/how-to-own-any-windows-network-with-group-policy-hijacking-attacks/)
	- **IIS Passwords**
		* [Decrypting IIS Passwords to Break Out of the DMZ: Part 1 - Scott Sutherland(2014)](https://www.netspi.com/blog/technical/network-penetration-testing/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/)
			* [Part 2](https://www.netspi.com/blog/technical/network-penetration-testing/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/)
	- **KrbRelayUp**
		* [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
			* .. a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings).
		* [KrbRelay with RBCD Privilege Escalation HOWTO - tothi](https://gist.github.com/tothi/bf6c59d6de5d0c9710f23dae5750c4b9)
	- **LDAP-based**
		https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html
		* [BloodyAD](https://github.com/CravateRouge/bloodyAD)
			* This tool can perform specific LDAP/SAMR calls to a domain controller in order to perform AD privesc. bloodyAD supports authentication using cleartext passwords, pass-the-hash, pass-the-ticket or certificates and binds to LDAP services of a domain controller to perform AD privesc. It is designed to be used transparently with a SOCKS proxy.
	- **Machine-Accounts**
		* [Pass the Hash with Machine$ Accounts - spotheplanet(2019](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts)
			* This lab looks at leveraging machine account NTLM password hashes or more specifically - how they can be used in pass the hash attacks to gain additional privileges, depending on which groups the machine is a member of (ideally administrators/domain administrators).
		* [Domain Escalation – Machine Accounts - NetbiosX(2022)](https://pentestlab.blog/2022/02/01/machine-accounts/)
	- **SAMAccountName Spoofing / CVE-2021-42278/2021-42287**<a name="samaccountname"></a>
		* [Active Directory Domain Services Elevation of Privilege Vulnerability - CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
		* [Active Directory Domain Services Elevation of Privilege Vulnerability - CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
		* [KB5008102—Active Directory Security Accounts Manager hardening changes (CVE-2021-42278) - support.ms](https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e)
		* [Exploit samAccountName spoofing with Kerberos - Fabian Bader(2021)](https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/)
		* [CVE-2021-42287/CVE-2021-42278 Weaponisation - exploit.ph(2021)](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
		* [Exploiting the CVE-2021-42278 (sAMAccountName spoofing) and CVE-2021-42287 (deceiving the KDC) Active Directory vulnerabilities - Krishnamoorthi Gopal(2022)](https://4sysops.com/archives/exploiting-the-cve-2021-42278-samaccountname-spoofing-and-cve-2021-42287-deceiving-the-kdc-active-directory-vulnerabilities/)
		* [sAMAccountName Spoofing - NetbiosX(2022)](https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/)
		* [sAMAccountName spoofing - thehacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
		* [noPac](https://github.com/cube0x0/noPac)
			* CVE-2021-42287/CVE-2021-42278 Scanner & Exploiter. Yet another low effort domain user to domain admin exploit.
		* [sam-the-admin](https://github.com/WazeHell/sam-the-admin)
	- **Printer-related**
		- See ['Fax & Printer'](#fax)
	- **NetNTLM->Silver Ticket**
		* [From Printers to Silver Tickets - EvilMog(DefconSafeMode)](https://www.youtube.com/watch?v=M9htSTug9TQ)
		* [NetNTLMtoSilverTicket writeup](https://github.com/NotMedic/NetNTLMtoSilverTicket)
	- **NTLM Relay**
		* See ['NTLM Relay'](#ntlm-relay)
	- **PKINITMustiness**<a name="pkinitmustiness"></a>
		* [pkinitmustiness - kekeo github wiki](https://github.com/gentilkiwi/kekeo/wiki/pkinitmustiness)
			* "PKINIT Mustiness is the opposite of PKINIT Freshness (https://datatracker.ietf.org/doc/draft-ietf-kitten-pkinit-freshness). It abuses the way Kerberos authenticates users with smartcard/token, by generating AS-REQ challenges for future usages... without needing access to the user secret in this future to decrypt AS-REP."
		* [You (dis)liked mimikatz? Wait for kekeo - Benjamin Delpy(BlueHat IL 2019)](https://www.youtube.com/watch?v=sROKCsXdVDg)
			* Slides - https://msrnd-cdn-stor.azureedge.net/bluehat/bluehatil/2019/assets/doc/You%20(dis)iked%20mimikatz%20Wait%20for%20kekeo.pdf
			* For years, you’ve tried to fight mimikatz, first to understand it, and maybe fight it again. This little kiwi fruit shaped program has given you a hard time, extracted your password, stolen your credentials, played with your nerves and certificates... But our friends in New Zealand know it best: there are many different kiwis... and perhaps the fruit is the most lucrative, but it's not the most sadistic. The kiwi animal may not fly, and it remains complex to build it from source, its effects are not less devastating...I will introduce "kekeo", the little animal brother of mimikatz. If you enjoyed playing with Kerberos, ASN1, security providers..., then you'll love adopting this furry, sweet animal. From its birth with MS14-068 to cleartext passwords without local administrator rights, you'll know everything about this animal. This talk will embed CredSSP and TSSP with cleartext credential, explore a little bit about PKINITMustiness and the RSA-on-the-fly for Kerberos with PKI!
	- **(Priv)Exchange**
		* [Issue 2186: Exchange: AD Schema Misconfiguration Elevation of Privilege - James Forshaw](https://bugs.chromium.org/p/project-zero/issues/detail?id=2186)
			* "The msExchStorageGroup schema class added during Exchange installation can be used to create almost any AD object including users, groups or domain trusts leading to elevation of privilege."
		* [PrivExchange : One Hop away from Domain Admin - ](https://www.c0d3xpl0it.com/2019/02/privexchange-one-hop-away-from-domain-admin.html)
		* [Abusing Exchange: One API call away from Domain Admin - Dirk-jan Mollema(2019)](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
		* [PrivExchange](https://github.com/dirkjanm/PrivExchange)
			* Exchange your privileges for Domain Admin privs by abusing Exchange
		* [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
			* This repository provides a few techniques and scripts regarding the impact of Microsoft Exchange deployment on Active Directory security.
		* [Exploiting PrivExchange - chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
			* expansion and demo of how to use the PrivExchange exploit
		* [PowerPriv](https://github.com/G0ldenGunSec/PowerPriv)
			* A powershell implementation of PrivExchange by `@_dirkjan` (original code found here: https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py) Useful for environments on which you cannot run python-based applications, have user credentials, or do not want to drop files to disk. Will cause the target exchange server system account to attempt to authenticate to a system of your choice.
	- **Shadow Credentials**
		* [No-Fix Local Privilege Escalation Using KrbRelay With Shadow Credentials - Matthew David(2022)](https://icyguider.github.io/2022/05/19/NoFix-LPE-Using-KrbRelay-With-Shadow-Credentials.html)
		- **Tools**
			* [ADAPE-Script](https://github.com/hausec/ADAPE-Script)
		    	* Active Directory Assessment and Privilege Escalation Script
	- **Shadow Admins(ACLs)**<a name="shadowadmin"></a>
		* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most - Asaf Hecht](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
		* [ACLight](https://github.com/cyberark/ACLight)
			* ACLight is a tool for discovering privileged accounts through advanced ACLs analysis (objects’ ACLs - Access Lists, aka DACL\ACEs). It includes the discovery of Shadow Admins in the scanned network.
	- **(NTLM)SMB Relay**
		* See `Network_Attacks.md`
		* [Redirect to SMB - Cylance SPEAR](https://blog.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf)
	- **Skeleton Key**<a name="skeleton"></a>
		* See ['Skeleton Key Attack'](#skey)
	- **Specific Vulnerabilities**<a name="adprivvulns"></a>
- **RDP**
	* [Attacking RDP from Inside: How we abused named pipes for smart-card hijacking, unauthorized file system access to client machines and more - Gabriel Sztejnworcel(2022)](https://www.cyberark.com/resources/threat-research-blog/attacking-rdp-from-inside)
- **Volume Shadow Service (Attacking)**<a name="shadowvuln"></a>
	* [Vshadow: Abusing the Volume Shadow Service for Evasion, Persistence, and Active Directory Database Extraction - BOHOPS(2018)](https://bohops.com/2018/02/10/vshadow-abusing-the-volume-shadow-service-for-evasion-persistence-and-active-directory-database-extraction/)
- **Sharepoint (Attacking**
	- **Articles/Blogposts/Writeups**
		* [The Lone Sharepoint - Acap4z(2021)](https://www.crummie5.club/the-lone-sharepoint/)
		* [CVE-2021-26420: Remote Code Execution in SharePoint via Workflow Compilation - ZDI(2021)](https://www.thezdi.com/blog/2021/10/5/cve-2021-26420-remote-code-execution-in-sharepoint-via-workflow-compilation)
		* [New Wine in Old Bottle - Microsoft Sharepoint Post-Auth Deserialization RCE (CVE-2022-29108) - Nguyễn Tiến Giang (Jang) (2022)](https://www.starlabs.sg/blog/2022/05-new-wine-in-old-bottle-microsoft-sharepoint-post-auth-deserialization-rce-cve-2022-29108/)
- **Skeleton Key Attack**<a name="skey"></a>
	- **101**
		* [Active Directory Domain Controller Skeleton Key Malware & Mimikatz - ADSecurity](https://adsecurity.org/?p=1255)
		* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)
		* [Skeleton Key Malware Analysis - SecureWorks](https://www.secureworks.com/research/skeleton-key-malware-analysis)
	- **Articles/Blogposts/Writeups**
		* [Unlocking All The Doors To Active Directory With The Skeleton Key Attack](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)
		* [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
- **SQL Server (Attacking)**
	- **101**
	- **Articles/Blogposts/Writeups**
		* [Pentesting MSSQL - Microsoft SQL Server - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
		* [MSSQL Lateral Movement - David Cash(2021)](https://research.nccgroup.com/2021/01/21/mssql-lateral-movement/)
		* [Attacking SQL Server CLR Assemblies Webinar - NetSPI](https://www.youtube.com/watch?v=A_hZHwisRxc)
			* During this webinar we’ll review how to create, import, export, and modify CLR assemblies in SQL Server with the goal of privilege escalation, OS command execution, and persistence. Scott will also share a few PowerUpSQL functions that can be used to execute the CLR attacks on a larger scale in Active Directory environments.
		* [Attacking Modern Environments with MS-SQL Servers - Firestone65(2021)](https://www.offsec-journey.com/post/attacking-ms-sql-servers)
		* [SQL Server UNC Path Injection Cheatsheet](https://gist.github.com/nullbind/7dfca2a6309a4209b5aeef181b676c6e)
	- **Tools**
		* [SQLRecon](https://github.com/skahwah/SQLRecon/)
			* A C# MS-SQL toolkit designed for offensive reconnaissance and post-exploitation. For detailed usage information on each technique, refer to the wiki.
		* [Squeak](https://github.com/nccgroup/nccfsas/tree/main/Tools/Squeak)
		* [msdat](https://github.com/quentinhardy/msdat)
			* MSDAT (Microsoft SQL Database Attacking Tool) is an open source penetration testing tool that tests the security of Microsoft SQL Databases remotely.
		* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- **Trusts**<a name="trustsa"></a>
	- **101**
		* [Primary and Trusted Domains - docs.ms](https://docs.microsoft.com/en-us/windows/win32/secmgmt/primary-and-trusted-domains)
	- **Articles/Blogposts/Writeups** 
		* [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
		* [It's All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)
		* [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work)
		* [The Forest Is Under Control. Taking over the entire Active Directory forest](https://hackmag.com/security/ad-forest/)
		* [Not A Security Bou* **Read-Only Domain Controllers**
		* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)
		* Not a Security Boundary: Breaking Forest Trusts](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)
		* [Pentesting Active Directory Forests](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
		* [Active Directory forest trusts part 1 - How does SID filtering work? - Dirk-jan Mollema(2018)](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
		* [Active Directory forest trusts part 2 - Trust transitivity and finding a trust bypass - Dirk-jan Mollema(2021)](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/)
		* [The Trustpocalypse](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
	- **Talks/Presentations/Videos**
		* [Trusts you might have missed - Will Schroeder(44con2019)](https://www.youtube.com/watch?v=XZqvhOxavdI)
			* Red teams have been abusing Windows domain trusts for years with great success, but the topic is still under-represented in public infosec discussions. While the community has started to talk more about Active Directory exploitation, there isn’t much information out there discussing domain trusts from an offensive perspective. This talk aims to demystify domain trusts and show how they can be enumerated and abused during the course of an engagement. I’ll conclude with a complex demo showing how to enumerate, visualize, and abuse the trust relationships in an example environment, leading to total domain takeover without throwing a single exploit.
	- **Tools**
		* [Forest Trust Tools](https://github.com/dirkjanm/forest-trust-tools)
			* These are Proof of Concept tools for playing with forest trusts and cross-realm kerberos tickets. For getftST.py you will need to apply the kerberosv5.patch to your local impacket install (I recommend running this in a virtualenv or pipenv).
- **WSUS**<a name="wsusa"></a>
	- **Articles/Blogposts/Writeups**
		* [Leveraging WSUS – Part One - @cpl3h(2018)](https://ijustwannared.team/2018/10/15/leveraging-wsus-part-one/)
		* [WSUS Attacks Part 1: Introducing PyWSUS - Julien Pineault(2020)](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/)
	- **Tools**
		* [PyWSUS](https://github.com/GoSecure/pywsus)
			* Standalone implementation of a part of the WSUS spec. Built for offensive security purposes.
	- **WSUSPect**
		* [WSUSPect - Compromising the Windows Enterprise via Windows Update - Paul Stone, Alex Chapman - BHUS15](https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf)
			* [Blogpost](https://www.contextis.com/en/resources/white-papers/wsuspect-compromising-the-windows-enterprise-via-windows-update))
			* [Slides](https://www.contextis.com/media/downloads/WSUSuspect_Presentation.pdf)
		* [WSuspect Proxy](https://github.com/ctxis/wsuspect-proxy)
			* WSUSpect Proxy - a tool for MITM'ing insecure WSUS connections
	- **WSUSpendu**
		* [WSUSpendu: How to Hang WSUS Clients - Romain Coltel & Yves Le Provost(BHUSA2017)](https://www.youtube.com/watch?v=2M8ux6ESIAs)
			* [Slides](https://www.blackhat.com/docs/us-17/wednesday/us-17-Coltel-WSUSpendu-Use-WSUS-To-Hang-Its-Clients.pdf)
			* [Paper](https://www.blackhat.com/docs/us-17/wednesday/us-17-Coltel-WSUSpendu-Use-WSUS-To-Hang-Its-Clients-wp.pdf)
			* [SSTIC 2017 Version of the Talk](https://www.youtube.com/watch?v=2M8ux6ESIAs)
			* We will present a new approach, allowing you to circumvent limitations and control the targeted network from the very WSUS server you own. By extension, this approach may serve as a basis for an air gap attack for disconnected networks. 
		* [WSUSpendu](https://github.com/AlsidOfficial/WSUSpendu)
			* Implement WSUSpendu attack

	
	
	

--------------------------------------------------------------------------------------------------------------------------------

	
























----------------------------------------------------------------------------------------------------------------------------------
### <a name="email"></a>Email/Microsoft Exchange
* **Look at the phishing page**
	* [Link to the Phishing page - Markdown](./Phishing.md)
	* [Link to the Phishing page - HTML](./Phishing.html)
* **Articles/Blogposts/Writeups**
	* [Microsoft Exchange – Password Spraying - pentestlab.blog](https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/)
	* [Microsoft Exchange – Domain Escalation - pentestlab.blog](https://pentestlab.blog/2019/09/04/microsoft-exchange-domain-escalation/)
	* [Microsoft Exchange – Mailbox Post Compromise - NetbiosX](https://pentestlab.blog/2019/09/11/microsoft-exchange-mailbox-post-compromise/)
* **Privilege Escalation (ab)using**
	* [Abusing Exchange: One API call away from Domain Admin - dirkjanm.io](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
	* [Red Teaming Made Easy with Exchange Privilege Escalation and PowerPriv - RedXORBlue](http://blog.redxorblue.com/2019/01/red-teaming-made-easy-with-exchange.html)
* **Tools**
	* [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
		* This repository provides a few techniques and scripts regarding the impact of Microsoft Exchange deployment on Active Directory security. This is a side project of [AD-Control-Paths](https://github.com/ANSSI-FR/AD-control-paths), an AD permissions auditing project to which I recently added some Exchange-related modules.
	* [PrivExchange](https://github.com/dirkjanm/PrivExchange)
	* [Exploiting PrivExchange - chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
		* expansion and demo of how to use the PrivExchange exploit
	* [MailSniper](https://github.com/dafthack/MailSniper)
		* MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an Exchange administrator to search the mailboxes of every user in a domain. MailSniper also includes additional modules for password spraying, enumerating users/domains, gathering the Global Address List from OWA and EWS, and checking mailbox permissions for every Exchange user at an organization.
	* [PowerPriv](https://github.com/G0ldenGunSec/PowerPriv)
		* A powershell implementation of PrivExchange by `@_dirkjan` (original code found here: https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py) Useful for environments on which you cannot run python-based applications, have user credentials, or do not want to drop files to disk. Will cause the target exchange server system account to attempt to authenticate to a system of your choice.
	* [exchange_hunter2](https://github.com/aslarchergore/exchange_hunter2)
		* This script uses a valid credential, a DC IP and Hostname to log into the DC over LDAP and query the LDAP server for the wherabouts of the Microsoft Exchange servers in the environment.






















































<Fixme> properly sort out
----------------------------------------------------------------------------------------------------------------------------------
### <a name="ADsecure"></a>Hardening & Securing Active Directory
* **101**
	* [Ping Castle Methodology](https://www.pingcastle.com/methodology/)
		* Here is exposed the 4 steps of the PingCastle methodology which has been designed based on our experience putting hundreds of domains under control.
	* [What would a real hacker do to your Active Directory](https://www.youtube.com/watch?v=DH3v8bO-NCs)
	* [Securing Microsoft Active Directory Federation Server (ADFS)](https://adsecurity.org/?p=3782)
	* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening/blob/master/README.md)
	* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them - adsecurity](https://adsecurity.org/?p=1684)
	* [Beyond Domain Admins – Domain Controller & AD Administration - ADSecurity.org](https://adsecurity.org/?p=3700)
		* This post provides information on how Active Directory is typically administered and the associated roles & rights.
* **Adversary Resilience Methodology**<a name=""></a>
	* [Introducing the Adversary Resilience Methodology — Part One - specterops](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
	* [Introducing the Adversary Resilience Methodology — Part Two](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
	* [BloodHound and the Adversary Resilience Model](https://docs.google.com/presentation/d/14tHNBCavg-HfM7aoeEbGnyhVQusfwOjOyQE1_wXVs9o/mobilepresent#slide=id.g35f391192_00)
* **Awareness**<a name=""></a>
	* [NtdsAudit](https://github.com/Dionach/NtdsAudit)
		* NtdsAudit is an application to assist in auditing Active Directory databases. It provides some useful statistics relating to accounts and passwords. It can also be used to dump password hashes for later cracking.
	* [Grouper](https://github.com/l0ss/Grouper)
		* Grouper is a slightly wobbly PowerShell module designed for pentesters and redteamers (although probably also useful for sysadmins) which sifts through the (usually very noisy) XML output from the Get-GPOReport cmdlet (part of Microsoft's Group Policy module) and identifies all the settings defined in Group Policy Objects (GPOs) that might prove useful to someone trying to do something fun/evil.
* **Bloodhound**<a name=""></a>
	* **101**
		* [A walkthrough on how to set up and use BloodHound - Andy Gill(2019)](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)
	* **Articles/Blogposts/Writeups**
		* [Blue Hands On Bloodhound - SadProcessor](https://insinuator.net/2019/10/blue-hands-on-bloodhound/)
	* **Talks/Presentations/Videos**
		* [BloodHound From Red to Blue - Mathieu Saulnier(BSides Charm2019)](https://www.youtube.com/watch?v=UWY772iIq_Y)
	* **Tools**
		* [Cypheroth](https://github.com/seajaysec/cypheroth)
			* Automated, extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets.
* **Building/Designing Infrastructure**<a name=""></a>
	* [How to Build Super Secure Active Directory Infrastructur* - BlackHills](https://www.blackhillsinfosec.com/build-super-secure-active-directory-infrastructure/)
	* [Active Directory Design Best Practices](https://krva.blogspot.com/2008/04/ad-design-best-practices.html)
* **Deceiving Attackers**<a name=""></a>
	* [Weaponizing Active Directory - David Fletcher](https://www.youtube.com/watch?v=vLWGJ3f3-gI&feature=youtu.be)
		* This webcast covers basic techniques to catch attackers attempting lateral movement and privilege escalation within your environment with the goal of reducing that Mean Time to Detect (MTTD) metric. Using tactical deception, we will lay out strategies to increase the odds that an attacker will give away their presence early after initial compromise.
		* [Creating Honey Credentials with LSA Secrets - Scot Berner](https://www.trustedsec.com/blog/creating-honey-credentials-with-lsa-secrets/)	
* **Domain Controllers/Admins**<a name=""></a>
	* [Securing Domain Controllers to Improve Active Directory Security - adsecurity.org](https://adsecurity.org/?p=3377)
	* [Protecting Privileged Domain Accounts: Network Authentication In-Depth](https://digital-forensics.sans.org/blog/2012/09/18/protecting-privileged-domain-accounts-network-authentication-in-depth)
	* [Active Directory: Real Defense for Domain Admins](https://www.irongeek.com/i.php?page=videos/derbycon4/t213-active-directory-real-defense-for-domain-admins-jason-lang)
		* Did your AD recently get owned on a pentest? It’s always fun to see an unknown entry show up in your Domain Admins group (#fail). Come learn how to truly protect your organization’s IT crown jewels from some of the most popular AD attacks. If you’re stuck trying to figure out what to do with null sessions, pass the hash techniques, or protecting your Domain Admins, then you will want to be here.
	* [Security WatchLock Up Your Domain Controllers - Steve Riley - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc160936(v=msdn.10))
	* [Securing Active Directory Administrative Groups and Accounts - docs.ms(2009)](https://docs.microsoft.com/en-us/previous-versions/tn-archive/cc700835(v%3dtechnet.10))
	* [Designing RODCs in the Perimeter Network - docs.ms(2012)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd728028(v%3dws.10))
* **Enhanced Security Administrative Environment(ESAE)/Red Foreset**<a name=""></a>
	* **ESAE**
		* [Understanding “Red Forest”: The 3-Tier Enhanced Security Admin Environment (ESAE) and Alternative Ways to Protect Privileged Credentials - ultimatewindowsecurity](https://www.ultimatewindowssecurity.com/webinars/register.aspx?id=1409)
		* [Active Directory - ESAE Model - Huy Kha](https://www.slideshare.net/HuyKha2/active-directory-esae-model-149736364)
	* **Red Forest**
		* [What is Active Directory Red Forest Design? - social.technet.ms](https://social.technet.microsoft.com/wiki/contents/articles/37509.what-is-active-directory-red-forest-design.aspx)
		* [Planting the Red Forest: Improving AD on the Road to ESAE - Jacques Louw and Katie Knowles](https://www.mwrinfosecurity.com/our-thinking/planting-the-red-forest-improving-ad-on-the-road-to-esae/)
		* [How Microsoft Red Forest improves Active Directory Security - Bryan Patton](https://www.quest.com/community/quest/microsoft-platform-management/b/microsoft-platform-management-blog/posts/how-microsoft-red-forest-improves-active-directory-security)
* **AppLocker**<a name=""></a>
	* **101**
		* [AppLocker - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
			* This topic provides a description of AppLocker and can help you decide if your organization can benefit from deploying AppLocker application control policies. AppLocker helps you control which apps and files users can run. These include executable files, scripts, Windows Installer files, dynamic-link libraries (DLLs), packaged apps, and packaged app installers.
		* [What Is AppLocker? - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)
		* [AppLocker design guide - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-design-guide)
		* [AppLocker deployment guide - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-deployment-guide)
		* [AppLocker technical reference - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-technical-reference)
		* [Security considerations for AppLocker - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/security-considerations-for-applocker)
		* [Requirements to use AppLocker - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/requirements-to-use-applocker)
		* [Administer AppLocker - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/administer-applocker)
		* [How AppLocker works - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/how-applocker-works-techref)
	* **Articles/Blogposts/Writeups**
		* [Getting Started With AppLocker - John Strand(2019)](https://www.blackhillsinfosec.com/getting-started-with-applocker/)
		* [Script Rules in AppLocker - technet](https://technet.microsoft.com/en-us/library/ee460958.aspx)
		* [DLL Rules in AppLocker](https://technet.microsoft.com/en-us/library/ee460947.aspx)
		* [Application Whitelisting Using Microsoft AppLocker](https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)
		* [Harden Windows with AppLocker – based on Case study Part 1 - oddvar.moe](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
		* [Harden Windows with AppLocker – based on Case study part 2 - oddvar.moe](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
		* [AppLocker Case study: How insecure is it really? Part 1 oddvar.moe](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-1/)
		* AppLocker Case study: How insecure is it really? Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
	* **Talks/Presentations/Videos**
		* [Implementing Sysmon and Applocker - BHIS(2019)](https://www.youtube.com/watch?v=9qsP5h033Qk)
		* [How, Why, and Best Reasons to implement AppLocker - BHIS(2019)](https://www.youtube.com/watch?v=vV7oh_B9f1U)
		* [SteelCon 2019: Built-In Appl. Whitelisting With Windows Defender Application Control - Chris Truncer(SteelCon19)](https://www.youtube.com/watch?v=DQth-gVXRS0&list=PLmfJypsykTLXk1QHj6PqiD7q7Z-WEj31U&index=20)	
* **Auditing Account Passwords/Privileges**<a name=""></a>
	* [Account lockout threshold - technet](https://technet.microsoft.com/en-us/library/hh994574.aspx)
	* [Password Policy - technet](https://technet.microsoft.com/en-us/library/hh994572.aspx)
	* [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
		* As a part of ensuring that they've created a secure environment Windows administrators often need to know what kind of accesses specific users or groups have to resources including files, directories, Registry keys, global objects and Windows services. AccessChk quickly answers these questions with an intuitive interface and output.
* **Guarded Fabric/Shielded VMs**<a name=""></a>
	* [Guarded fabric and shielded VMs](https://docs.microsoft.com/en-us/windows-server/virtualization/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms-top-node)
	* [Shielded VMs – additional considerations when running a guarded fabric - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/04/21/shielded-vms-additional-considerations-when-running-a-guarded-fabric/)
	* [Shielded VMs: A conceptual review of the components and steps necessary to deploy a guarded fabric](https://blogs.technet.microsoft.com/datacentersecurity/2017/03/14/shielded-vms-a-conceptual-review-of-the-components-and-steps-necessary-to-deploy-a-guarded-fabric/)
	* [Step-by-step: Quick reference guide to deploying guarded hosts](https://blogs.technet.microsoft.com/datacentersecurity/2016/06/08/step-by-step-quick-reference-guide-to-deploying-guarded-hosts/)
	* [Step by Step – Configuring Guarded Hosts with Virtual Machine Manager 2016 - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2016/03/21/configuring-guarded-hosts-with-virtual-machine-manager-2016/)
	* [Guarded Fabric Deployment Guide for Windows Server 2016](https://gallery.technet.microsoft.com/Shielded-VMs-and-Guarded-98d2b045)
	* [Step by Step – Configuring Key Protection for the Host Guardian Service in Windows Server 2016](https://blogs.technet.microsoft.com/datacentersecurity/2016/03/28/configuring-key-protection-service-for-host-guardian-service-in-windows-server-2016/)
	* [Why use shielded VMs for your privileged access workstation (PAW) solution?](https://blogs.technet.microsoft.com/datacentersecurity/2017/11/29/why-use-shielded-vms-for-your-privileged-access-workstation-paw-solution/)
	* [Frequently Asked Questions About HGS Certificates](https://blogs.technet.microsoft.com/datacentersecurity/2017/10/09/frequently-asked-questions-about-hgs-certificates/)
	* [Join Host Guardian Servers to an existing bastion forest](https://blogs.technet.microsoft.com/datacentersecurity/2017/03/07/join-host-guardian-servers-to-an-existing-bastion-forest/)
	* [Step by Step: Shielding existing VMs without VMM - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2016/09/01/step-by-step-shielding-existing-vms-without-vmm/)
	* [Step-by-step: Quick reference guide to deploying guarded hosts](https://blogs.technet.microsoft.com/datacentersecurity/2016/06/08/step-by-step-quick-reference-guide-to-deploying-guarded-hosts/)
	* [Step by Step – Shielded VM Recovery - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2016/06/07/step-by-step-shielded-vm-recovery/)
* **Group Policy**<a name=""></a>
	* [The 10 Windows group policy settings you need to get right](http://www.infoworld.com/article/2609578/security/the-10-windows-group-policy-settings-you-need-to-get-right.html?page=2)
	* [Group Policy for WSUS - grouppolicy.biz](http://www.grouppolicy.biz/2011/06/best-practices-group-policy-for-wsus/)
	* [GPO Best Policies - grouppolicy.biz](http://www.grouppolicy.biz/best-practices/)
	* [Securing Windows with Group Policy Josh - Rickard - Derbycon7](https://www.youtube.com/watch?v=Upeaa2rgozk&index=66&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
	* [Guidance on Deployment of MS15-011 and MS15-014 - blogs.technet](https://blogs.technet.microsoft.com/askpfeplat/2015/02/22/guidance-on-deployment-of-ms15-011-and-ms15-014/)
	* [MS15-011 & MS15-014: Hardening Group Policy - blogs.technet](https://blogs.technet.microsoft.com/srd/2015/02/10/ms15-011-ms15-014-hardening-group-policy/)
* **Hardening**<a name=""></a>
	* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
		*  A curated list of awesome Security Hardening techniques for Windows.
	* [Threats and Countermeasures Guide: Security Settings in Windows Server 2008 R2 and Windows 7 - technet](https://technet.microsoft.com/en-us/library/hh125921.aspx)
	* [Harden windows IP Stack](https://www.reddit.com/r/netsec/comments/2sg80a/how_to_harden_windowsiis_ssltls_configuration/)
	* [Secure Host Baseline](https://github.com/iadgov/Secure-Host-Baseline)
		* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
	* [Second section good resource for hardening windows](http://labs.bitdefender.com/2014/11/do-your-bit-to-limit-cryptowall/)
	* [Secure-Host-Baseline](https://github.com/iadgov/Secure-Host-Baseline)
		* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
	* [Network access: Restrict clients allowed to make remote calls to SAM - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls)
		* The Network access: Restrict clients allowed to make remote calls to SAM security policy setting controls which users can enumerate users and groups in the local Security Accounts Manager (SAM) database and Active Directory. The setting was first supported by Windows 10 version 1607 and Windows Server 2016 (RTM) and can be configured on earlier Windows client and server operating systems by installing updates from the KB articles listed in Applies to section of this topic.
	* [SAMRi10 - Hardening SAM Remote Access in Windows 10/Server 2016](https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b#content)
		* "SAMRi10" tool is a short PowerShell (PS) script which alters remote SAM access default permissions on Windows 10 & Windows Server 2016. This hardening process prevents attackers from easily getting some valuable recon information to move laterally within their victim's network.
	* [Enable Attack surface reduction - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction)
		* Attack surface reduction is a feature that is part of Windows Defender Exploit Guard. It helps prevent actions and apps that are typically used by exploit-seeking malware to infect machines.
	* [Windows Defender Exploit Guard: Reduce the attack surface against next-generation malware](https://cloudblogs.microsoft.com/microsoftsecure/2017/10/23/windows-defender-exploit-guard-reduce-the-attack-surface-against-next-generation-malware/?source=mmpc)
	* [LogonTracer](https://github.com/JPCERTCC/LogonTracer)
		* Investigate malicious Windows logon by visualizing and analyzing Windows event log
	* [Software Restriction Policies - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies)
		* This topic for the IT professional describes Software Restriction Policies (SRP) in Windows Server 2012 and Windows 8, and provides links to technical information about SRP beginning with Windows Server 2003.
	* [Detecting Lateral Movement through Tracking Event Logs - JPCERTCC](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)
	* [Detecting Lateral Movements in Windows Infrastructure - CERT-EU](http://cert.europa.eu/static/WhitePapers/CERT-EU_SWP_17-002_Lateral_Movements.pdf)
	* [Designing a Multilayered, In-Depth Defense Approach to AD Security - Quest.com](https://www.quest.com/docs/designing-a-multilayered-in-depth-defense-approach-to-ad-security-white-paper-22453.pdf)
		* There are a number of configuration options we recommend for securing high privileged accounts. One of them, enabling 'Account is sensitive and cannot be delegated', ensures that an account’s credentials cannot be forwarded to other computers or services on the network by a trusted application.
	* [New features in Active Directory Domain Services in Windows Server 2012, Part 11: Kerberos Armoring (FAST) - Sander Berkouwer](https://dirteam.com/sander/2012/09/05/new-features-in-active-directory-domain-services-in-windows-server-2012-part-11-kerberos-armoring-fast/)
	* [Protect your enterprise data using Windows Information Protection (WIP) - docs.ms](https://docs.microsoft.com/en-us/windows/security/information-protection/windows-information-protection/protect-enterprise-data-using-wip)
* **Just Enough Administration (JEA)**<a name=""></a>
	* [Just Enough Administration - docs.ms](https://docs.microsoft.com/en-us/powershell/jea/overview)
	* [Just Enough Administration: Windows PowerShell security controls help protect enterprise data - msdn](https://msdn.microsoft.com/en-us/library/dn896648.aspx)
	* [JEA Pre-requisites](https://docs.microsoft.com/en-us/powershell/jea/prerequisites)
	* [JEA Role Capabilities](https://docs.microsoft.com/en-us/powershell/jea/role-capabilities)
	* [JEA Session Configurations](https://docs.microsoft.com/en-us/powershell/jea/session-configurations)
	* [Registering JEA Configurations](https://docs.microsoft.com/en-us/powershell/jea/register-jea)
	* [Using JEA](https://docs.microsoft.com/en-us/powershell/jea/using-jea)
	* [JEA Security Considerations](https://docs.microsoft.com/en-us/powershell/jea/security-considerations)
	* [Auditing and Reporting on JEA](https://docs.microsoft.com/en-us/powershell/jea/audit-and-report)
	* [Just Enough Administration Samples and Resources](https://github.com/PowerShell/JEA)
		* Just Enough Administration (JEA) is a PowerShell security technology that provides a role based access control platform for anything that can be managed with PowerShell. It enables authorized users to run specific commands in an elevated context on a remote machine, complete with full PowerShell transcription and logging. JEA is included in PowerShell version 5 and higher on Windows 10 and Windows Server 2016, and older OSes with the Windows Management Framework updates.
* **KRBTGT**<a name=""></a>
	* [Kerberos & KRBTGT: Active Directory’s Domain Kerberos Service Account - adsecurity.org](https://adsecurity.org/?p=483)
	* [KRBTGT Account Password Reset Scripts now available for customers - Tim Rains(Ms.com)](https://www.microsoft.com/security/blog/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/)
	* [AD Forest Recovery - Resetting the krbtgt password - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password)
	* [PowerShell Script To Reset The KrbTgt Account Password/Keys For Both RWDCs And RODCs - Jorge](https://jorgequestforknowledge.wordpress.com/2020/04/06/powershell-script-to-reset-the-krbtgt-account-password-keys-for-both-rwdcs-and-rodcs-update-5/)
* **LLMNR/NBNS**<a name=""></a>
	* [Conveigh](https://github.com/Kevin-Robertson/Conveigh)
		* Conveigh is a Windows PowerShell LLMNR/NBNS spoofer detection tool. LLMNR/NBNS requests sent by Conveigh are not legitimate requests to any enabled LLMNR/NBNS services. The requests will not result in name resolution in the event that a spoofer is present.
	* [Respounder](https://github.com/codeexpress/respounder)
		* Respounder sends LLMNR name resolution requests for made-up hostnames that do not exist. In a normal non-adversarial network we do not expect such names to resolve. However, a responder, if present in the network, will resolve such queries and therefore will be forced to reveal itself.
	* [asker](https://github.com/eavalenzuela/asker)
		* This tool takes a list of known-bogus local hostnames, and sends out LLMNR requests for them every 5-25 legitimate LLMNR requests from other hosts. This is intended for use by a blue team who wants to catch a red team or attacker using Responder, who either does not target-select carefully enough, or falls for the bogus hostnames which should be tailored to the environment (e.g. if there is a DC named "addc1", you might want to add "adddc1" to the list.
* **Local Administrator Password Solution**<a name=""></a>
	* **101**
		* [Local Administrator Password Solution - technet](https://technet.microsoft.com/en-us/mt227395.aspx)
			* The "Local Administrator Password Solution" (LAPS) provides a centralized storage of secrets/passwords in Active Directory (AD) - without additional computers. Each organization’s domain administrators determine which users, such as helpdesk admins, are authorized to read the passwords.
		* [Introduction to Microsoft LAPS (Local Administrator Password Solution) - 4sysops)](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
	* **Articles/Blogposts/Writeups**
		* [Auditing Access to LAPS Passwords in Active Directory - Russell Smith](https://www.petri.com/auditing-access-to-laps-passwords-in-active-directory)
		* [Microsoft security advisory: Local Administrator Password Solution](https://support.microsoft.com/en-us/help/3062591/microsoft-security-advisory-local-administrator-password-solution-laps)
		* [Set up Microsoft LAPS (Local Administrator Password Solution) in Active Directory]((https://4sysops.com/archives/set-up-microsoft-laps-local-administrator-password-solution-in-active-directory/)
		* [FAQs for Microsoft Local Administrator Password Solution (LAPS) - Part 1 - 4sysops](https://4sysops.com/archives/faqs-for-microsoft-local-administrator-password-solution-laps/)
			* [Part 2](https://4sysops.com/archives/part-2-faqs-for-microsoft-local-administrator-password-solution-laps/)
	* **Talks/Presentations/Videos**
* **NTLM**<a name="ntlm"></a>
	- **101**
	- **Articles/Blogposts/Writeups**
		* [Using security policies to restrict NTLM traffic - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/jj865668(v=ws.10))
- **Organizational Units**<a name="ous"></a>
	* [Creating an Organizational Unit Design - docs.ms](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-an-organizational-unit-design)
	* [About organizational units in Active Directory - kb.iu.edu](https://kb.iu.edu/d/atvu)
* **Office Documents/Macros/DDE/Flavor-of-the-week**<a name="macros"></a>
	* [Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields](https://technet.microsoft.com/library/security/4053440)
	* [Disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b)
	* [New feature in Office 2016 can block macros and help prevent infection (2016)](https://cloudblogs.microsoft.com/microsoftsecure/2016/03/22/new-feature-in-office-2016-can-block-macros-and-help-prevent-infection/?source=mmpc)
	* [Block or unblock external content in Office documents - support.office](https://support.office.com/en-us/article/block-or-unblock-external-content-in-office-documents-10204ae0-0621-411f-b0d6-575b0847a795)
	* [CIRClean](http://circl.lu/projects/CIRCLean/#technical-details)
		* CIRCLean is an independent hardware solution to clean documents from untrusted (obtained) USB keys / USB sticks. The device automatically converts untrusted documents into a readable but disarmed format and stores these clean files on a trusted (user owned) USB key/stick.
		* [Github](https://github.com/CIRCL/Circlean)
	* [Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields - docs.ms](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440)
* **Passwords**<a name="adpasswords"></a>
	* **Articles/Blogposts/Writeups**
		* [Active Directory Password Blacklisting - Leeren Chang(2018)](https://engineeringblog.yelp.com/2018/04/ad-password-blacklisting.html)
		* [Azure AD and ADFS best practices: Defending against password spray attacks](https://cloudblogs.microsoft.com/enterprisemobility/2018/03/05/azure-ad-and-adfs-best-practices-defending-against-password-spray-attacks/)
		* [Detect Password Spraying With Windows Event Log Correlation](https://www.ziemba.ninja/?p=66)
		* [Managing Domain Password Policy in the Active Directory - WindowsOSHub](http://woshub.com/password-policy-active-directory/)
		* [Configuring Password Policies with Windows Server 2016 - Mukhatar Jafari](https://www.wikigain.com/configuring-password-policies-with-windows-server-2016/)
		* [Password Policy - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy)
	* **Talks/Presentations/Videos**
	* **Tools**
		* [Domain Password Audit Tool (DPAT)](https://github.com/clr2of8/DPAT)
			* This is a python script that will generate password use statistics from password hashes dumped from a domain controller and a password crack file such as hashcat.potfile generated from the Hashcat tool during password cracking. The report is an HTML report with clickable links.
			* [Tutorial Video & Demo](https://www.blackhillsinfosec.com/webcast-demo-domain-password-audit-tool/)
* **Privileged Access Workstation**<a name="paw"></a>
	* **What Is**
		* [Privileged Access Workstation(PAW) - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/10/13/privileged-access-workstationpaw/)
		* [How Microsoft IT used Windows 10 and Windows Server 2016 to implement privileged access workstations](https://myignite.microsoft.com/sessions/54896)
			* As part of the security strategy to protect administrative privilege, Microsoft recommends using a dedicated machine, referred to as PAW (privileged access workstation), for administrative tasks; and using a separate device for the usual productivity tasks such as Outlook and Internet browsing. This can be costly for the company to acquire machines just for server administrative tasks, and inconvenient for the admins to carry multiple machines. In this session, we show you how MSIT uses shielded VMs on the new release of Windows client to implement a PAW.
	* **Documentation**
		* [The Active Directory 2016 PAM Trust: how it works, and why it should come with a safety advisory](https://blogs.technet.microsoft.com/389thoughts/2017/06/19/ad-2016-pam-trust-how-it-works-and-safety-advisory/)
	* **Setup**
		* [PAW host buildout - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/10/17/paw-host-buildout/)
		* [How to deploy a VM template for PAW - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/11/01/how-to-create-a-vm-template-for-paw/)
		* [Windows Server 2016: Set Up Privileged Access Management](https://www.petri.com/windows-server-2016-set-privileged-access-management)
	* **Reference**
		* [Securing Privileged Access Reference Material - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material)	
		* [Securing Privileged Access Reference Material - MS(github)](https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/identity/securing-privileged-access/securing-privileged-access-reference-material.md)
* **PowerShell**<a name="PowerShell"></a>
	* **Articles/Blogposts/Writeups**
		* [PowerShell ♥ the Blue Team](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)
		* [Powershell Security at Enterprise Customers - blogs.msdn](https://blogs.msdn.microsoft.com/daviddasneves/2017/05/25/powershell-security-at-enterprise-customers/)
		* [More Detecting Obfuscated PowerShell](http://www.leeholmes.com/blog/2016/10/22/more-detecting-obfuscated-powershell/)
		* [Detecting and Preventing PowerShell Downgrade Attacks - leeholmes](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)
		* [Creating a Secure Environment using PowerShell Desired State Configuration - blogs.ms](https://blogs.msdn.microsoft.com/powershell/2014/07/21/creating-a-secure-environment-using-powershell-desired-state-configuration/)
		* [Securing PowerShell in the Enterprise - Australian Cyber Security Center(2020)](https://www.cyber.gov.au/publications/securing-powershell-in-the-enterprise)
			* This document describes a maturity framework for PowerShell in a way that balances the security and business requirements of organisations. This maturity framework will enable organisations to take incremental steps towards securing PowerShell across their environment.
	* **Talks & Presentations**
		* [Hijacking .NET to Defend PowerShell - Amanda Rousseau(BSidesSF 2017)](https://www.youtube.com/watch?v=YXjIVuX6zQk)
		* [Automating security with PowerShell, Jaap Brasser (@Jaap_Brasser)](https://www.youtube.com/watch?v=WOC8vC2KoNs&index=12&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
			* There is no doubt that security has been in the spotlight over the last few years, recent events have been responsible for the increased demand for better and more secure systems. Security was often treated as an afterthought or something that could be implemented ‘later’. In this session, we will go over some best practices, using existing tools and frameworks to help you set up a more secure environment and to get a grasp of what is happening in your environment. We will leverage your existing automation skills to secure and automate these workflows. Expect a session with a lot of demos and resources that can directly be implemented.
	* **Tools**
		* [Revoke-Obfuscation - tool](https://github.com/danielbohannon/Revoke-Obfuscation)
			* PowerShell v3.0+ compatible PowerShell obfuscation detection framework.
		* [Revoke Obfuscation PowerShell Obfuscation Detection And Evasion Using Science Lee Holmes Daniel - Derbycon7 - talk](https://www.youtube.com/watch?v=7XnkDsOZM3Y&index=16&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
		* [PSRecon](https://github.com/gfoss/PSRecon/)
			* PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
* **Services**<a name=""></a>
	* [How to Allow Non-Admin Users to Start/Stop Windows Service - woshub.com](http://woshub.com/set-permissions-on-windows-service/)
* **SMB**<a name="smb"></a>
	* [SMB Security Best Practices - US CERT](https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices)
	* [SMB Packet Signing](https://technet.microsoft.com/en-us/library/cc180803.aspx)
	* [Secure SMB Connections](http://techgenix.com/secure-smb-connections/)
	* [Microsoft Security Advisory: Update to improve credentials protection and management: May 13, 2014](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a)		* [Require SMB Security Signatures - technet.ms](https://technet.microsoft.com/en-us/library/cc731957.aspx)
	* [SMB 3.0 (Because 3 > 2) - David Kruse](http://www.snia.org/sites/default/orig/SDC2012/presentations/Revisions/DavidKruse-SMB_3_0_Because_3-2_v2_Revision.pdf)
* **Unwanted Admins**<a name=""></a>
	* [Where have all the Domain Admins gone? Rooting out Unwanted Domain Administrators - Rob VandenBrink](https://isc.sans.edu/diary/Where+have+all+the+Domain+Admins+gone%3F++Rooting+out+Unwanted+Domain+Administrators/24874)
* **USB Detection**<a name=""></a>
	* [BEAMGUN](https://github.com/JLospinoso/beamgun)
		* A rogue-USB-device defeat program for Windows.
	* [How to Analyze USB Device History in Windows - magnetforensics.com](https://www.magnetforensics.com/computer-forensics/how-to-analyze-usb-device-history-in-windows/)
	* [How to track down USB flash drive usage with Windows 10's Event Viewer - techrepublic](https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/)
* **Tools**<a name=""></a>
	* [Artillery](https://github.com/BinaryDefense/artillery)
		* Artillery is a combination of a honeypot, monitoring tool, and alerting system. Eventually this will evolve into a hardening monitoring platform as well to detect insecure configurations from nix systems.
	* [zBang](https://github.com/cyberark/zBang)
		* zBang is a special risk assessment tool that detects potential privileged account threats in the scanned network.
		* [Blogpost](https://www.cyberark.com/threat-research-blog/the-big-zbang-theory-a-new-open-source-tool/)
* **Visualization/Tracking/Reporting**<a name=""></a>
	* General
		* [Userline](https://github.com/THIBER-ORG/userline)
			* This tool automates the process of creating logon relations from MS Windows Security Events by showing a graphical relation among users domains, source and destination logons as well as session duration.
		* [VOYEUR](https://github.com/silverhack/voyeur)
			* VOYEUR's main purpose is to automate several tasks of an Active Directory build review or security assessment. Also, the tool is able to create a fast (and pretty) Active Directory report. The tool is developed entirely in PowerShell (a powerful scripting language) without dependencies like Microsoft Remote Administration tools. (Just .Net Framework 2.0 and Office Excel if you want a useful and pretty report). The generated report is a perfect starting point for well-established forensic, incident response team, security consultants or security researchers who want to quickly analyze threats in Active Directory Services.
* **WMI**<a name=""></a>
	* **General**
		* [Managing WMI security - technet](https://technet.microsoft.com/en-us/library/cc731011(v=ws.11).aspx)
		* [Maintaining WMI Security - msdn](https://msdn.microsoft.com/en-us/library/aa392291(v=vs.85).aspx)
		* [Simple WMI Trace Viewer in PowerShell](https://chentiangemalc.wordpress.com/2017/03/24/simple-wmi-trace-viewer-in-powershell/)
		* [An Insider’s Guide to Using WMI Events and PowerShell](https://blogs.technet.microsoft.com/heyscriptingguy/2012/06/08/an-insiders-guide-to-using-wmi-events-and-powershell/)
	* **Tools**
		* [Uproot](https://github.com/Invoke-IR/Uproot)
			* Uproot is a Host Based Intrusion Detection System (HIDS) that leverages Permanent Windows Management Instrumentation (WMI) Event Susbcriptions to detect malicious activity on a network. For more details on WMI Event Subscriptions please see the WMIEventing Module
		* [WMIEvent](https://github.com/Invoke-IR/WMIEvent)
			* A PowerShell module to abstract the complexities of Permanent WMI Event Subscriptions
* **Advanced Threat Analytics**<a name=""></a>
	* **101**
		* [ATA Architecture - docs.ms(2019)](https://docs.microsoft.com/en-us/advanced-threat-analytics/ata-architecture)
		* [ATA readiness roadmap - docs.ms](https://docs.microsoft.com/en-us/advanced-threat-analytics/ata-resources)
	* **Articles/Blogposts/Writeups**
		* [Working with Suspicious Activities - docs.ms(2018)](https://docs.microsoft.com/en-us/advanced-threat-analytics/working-with-suspicious-activities)
			* This article explains the basics of how to work with Advanced Threat Analytics.
		* [Advanced Threat Analytics suspicious activity guide - docs.ms(2019)](https://docs.microsoft.com/en-us/advanced-threat-analytics/suspicious-activity-guide)
		* [ATA Console: Sensitive Groups ](https://docs.microsoft.com/en-us/advanced-threat-analytics/working-with-ata-console#sensitive-groups)
			* The following list of groups are considered Sensitive by ATA. Any entity that is a member of these groups is considered sensitive:
		* [Best Practices for Securing Advanced Threat Analytics - techcommunity.ms](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Best-Practices-for-Securing-Advanced-Threat-Analytics/ba-p/249848)
		* [Microsoft Advanced Threat Analytics – My best practices - Oddvar Moe](https://msitpros.com/?p=3509)
	* **Talks/Presentations/Videos**
* **Advanced Threat Protection**<a name=""></a>
	* **101**
		* [What's new in Windows Server 2019 - docs.ms](https://docs.microsoft.com/en-us/windows-server/get-started-19/whats-new-19)
		* [Microsoft Defender Advanced Threat Protection - ms](https://www.microsoft.com/en-us/microsoft-365/windows/microsoft-defender-atp)
			* Microsoft Defender Advanced Threat Protection (ATP) is a unified platform for preventative protection, post-breach detection, automated investigation, and response.
	* **Articles/Blogposts/Writeups**
		* [Detecting reflective DLL loading with Windows Defender ATP - cloudblogs.ms](https://cloudblogs.microsoft.com/microsoftsecure/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/)
		* [WindowsDefenderATP-Hunting-Queries - MS's Github](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries)
		* Sample queries for Advanced hunting in Windows Defender ATP
		* [WindowsDefenderATP-Hunting-Queries](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries)
			* This repo contains sample queries for Advanced hunting on Windows Defender Advanced Threat Protection. With these sample queries, you can start to experience Advanced hunting, including the types of data that it covers and the query language it supports. You can also explore a variety of attack techniques and how they may be surfaced through Advanced hunting.
		* [Onboard non-Windows machines(ATP) - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/configure-endpoints-non-windows-windows-defender-advanced-threat-protection)
	* **Talks/Presentations/Videos**
* **Auditing Processes**<a name=""></a>
	* [Know your Windows Processes or Die Trying - sysforensics](https://sysforensics.org/2014/01/know-your-windows-processes/)
	* [TaskExplorer](https://objective-see.com/products/taskexplorer.html)
		* Explore all the tasks (processes) running on your Mac with TaskExplorer.
* **Baselining**<a name=""></a>
	* [Measure Boot Performance with the Windows Assessment and Deployment Toolkit](https://blogs.technet.microsoft.com/mspfe/2012/09/19/measure-boot-performance-with-the-windows-assessment-and-deployment-toolkit/)
	* [Securing Windows Workstations: Developing a Secure Baseline](https://adsecurity.org/?p=3299)
	* [Evaluate Fast Startup Using the Assessment Toolkit](https://docs.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-1)
	* [Windows Performance Toolkit Reference](http://msdn.microsoft.com/en-us/library/windows/hardware/hh162945.aspx)
	* [The Malware Management Framework](https://www.malwarearchaeology.com/mmf/)
	* [Securing Windows Workstations: Developing a Secure Baselineadsecurity.org](https://adsecurity.org/?p=3299)
	* [ADRecon](https://github.com/sense-of-security/ADRecon)
		* ADRecon is a tool which extracts various artifacts (as highlighted below) out of an AD environment in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis. The report can provide a holistic picture of the current state of the target AD environment.  It can be run from any workstation that is connected to the environment, even hosts that are not domain members. Furthermore, the tool can be executed in the context of a non-privileged (i.e. standard domain user) accounts. Fine Grained Password Policy, LAPS and BitLocker may require Privileged user accounts. The tool will use Microsoft Remote Server Administration Tools (RSAT) if available, otherwise it will communicate with the Domain Controller using LDAP. 
* **CMD.exe Analysis**<a name=""></a>
	* [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
		* Cmd.exe Command Obfuscation Generator & Detection Test Harness
* **Credential Guard**<a name=""></a>
	* [Protect derived domain credentials with Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)
	* [Using a hypervisor to secure your desktop – Credential Guard in Windows 10 - blogs.msdn](https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/10/26/using-a-hypervisor-to-secure-your-desktop-credential-guard-in-windows-10/)
	* [Credential Guard lab companion - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/05/15/credential-guard-lab-companion/)
* **Device Guard**<a name=""></a>
	* [Device Guard and Credential Guard hardware readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337)
	* [Introduction to Windows Defender Device Guard: virtualization-based security and Windows Defender Application Control - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies)
	* [Requirements and deployment planning guidelines for Windows Defender Device Guard - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/requirements-and-deployment-planning-guidelines-for-device-guard#hardware-firmware-and-software-requirements-for-device-guard)
	* [Driver compatibility with Device Guard in Windows 10 - docs.ms](https://blogs.msdn.microsoft.com/windows_hardware_certification/2015/05/22/driver-compatibility-with-device-guard-in-windows-10/)
* **Defender Application Control**<a name=""></a>
	* [Planning and getting started on the Windows Defender Application Control deployment process - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-deployment-guide)
		* This topic provides a roadmap for planning and getting started on the Windows Defender Application Control (WDAC) deployment process, with links to topics that provide additional detail. Planning for WDAC deployment involves looking at both the end-user and the IT pro impact of your choices.
* **Event Log & Monitoring**<a name=""></a>
	* **General**
		* [Windows Security Log Events - ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
		* [Windows Event Logs Zero to Hero Nate Guagenti Adam Swan - Bloomcon2017](https://www.youtube.com/watch?v=H3t_kHQG1Js)
		* [Auditing Security Events - WCF - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/auditing-security-events)
		* [PowerShell – Everything you wanted to know about Event Logs and then some - Przemyslaw Klys](https://evotec.xyz/powershell-everything-you-wanted-to-know-about-event-logs/)
	* **Event Forwarding**
		* [Windows Event Forwarding Guidance](https://github.com/palantir/windows-event-forwarding) 
			* Over the past few years, Palantir has a maintained an internal Windows Event Forwarding (WEF) pipeline for generating and centrally collecting logs of forensic and security value from Microsoft Windows hosts. Once these events are collected and indexed, alerting and detection strategies (ADS) can be constructed not only on high-fidelity security events (e.g. log deletion), but also for deviations from normalcy, such as unusual service account access, access to sensitive filesystem or registry locations, or installation of malware persistence. The goal of this project is to provide the necessary building blocks for organizations to rapidly evaluate and deploy WEF to a production environment, and centralize public efforts to improve WEF subscriptions and encourage adoption. While WEF has become more popular in recent years, it is still dramatically underrepresented in the community, and it is our hope that this project may encourage others to adopt it for incident detection and response purposes. We acknowledge the efforts that Microsoft, IAD, and other contributors have made to this space and wish to thank them for providing many of the subscriptions, ideas, and techniques that will be covered in this post.
	* **Tools**
		* [DCSYNCMonitor](https://github.com/shellster/DCSYNCMonitor)
			* Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.
		* [EventLogParser](https://github.com/djhohnstein/EventLogParser)
			* Parse PowerShell and Security event logs for sensitive information.
* **Firewall**<a name=""></a>
	* **Articles/Blogposts/Writeups**
		* [Endpoint Isolation with the Windows Firewall - Dane Stuckey](https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb)
	* **Talks/Presentations/Videos**
		* [Demystifying the Windows Firewall – Learn how to irritate attackers without crippling your network - Jessica Payne(MSDN)](https://channel9.msdn.com/Events/Ignite/New-Zealand-2016/M377)
* **General Hardening**<a name=""></a>
	* **General**
		* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
			* A curated list of awesome Security Hardening techniques for Windows.
	* **Documentation**
		* [Introducing the security configuration framework: A prioritized guide to hardening Windows 10 - Chris Jackson(MS)](https://www.microsoft.com/security/blog/2019/04/11/introducing-the-security-configuration-framework-a-prioritized-guide-to-hardening-windows-10/)
		* [Windows security baselines - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
	* **Guides**
		* [Enable Attack surface reduction(Win10)- docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction)
		* [Harden windows IP Stack](https://www.reddit.com/r/netsec/comments/2sg80a/how_to_harden_windowsiis_ssltls_configuration/)
		* [Secure Host Baseline](https://github.com/iadgov/Secure-Host-Baseline)
			* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
		* [Windows Server guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=149b9032665345ba890ba51d3bf0d519&fl=4&uid=150127534&nid=244%20281088008)
		* [End user device (EUD) security guidance - NCSC.gov.uk](https://www.ncsc.gov.uk/collection/end-user-device-security/platform-specific-guidance/eud-security-guidance-windows-10-1809)
			* Guidance for organisations deploying a range of end user device platforms as part of a remote working solution
	* **Educational/Informative**
		* [The Evolution of Protected Processes – Part 1: Pass-the-Hash Mitigations in Windows 8.1](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)
		* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.crowdstrike.com/blog/evolution-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and/) 
		* [Protected Processes Part 3: Windows PKI Internals (Signing Levels, Scenarios, Signers, Root Keys, EKUs & Runtime Signers)](https://www.crowdstrike.com/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)
		* [Mitigate threats by using Windows 10 security features](https://docs.microsoft.com/en-us/windows/threat-protection/overview-of-threat-mitigations-in-windows-10)
* **.NET Instrumentation**<a name=""></a>
	* [ClrGuard](https://github.com/endgameinc/ClrGuard)
		* ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes. ClrGuard leverages a simple appInit DLL (ClrHook32/64.dll) in order to load into all CLR/.NET processes. From there, it performs an in-line hook of security critical functions. Currently, the only implemented hook is on the native LoadImage() function. When events are observed, they are sent over a named pipe to a monitoring process for further introspection and mitigation decision.
* **Powershell**<a name=""></a>
	* **Analysis**
		* [Powershell Download Cradles - Matthew Green](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)
		* [pOWershell obFUsCation - N1CFURY](https://n1cfury.com/ps-obfuscation/)
		* [PowerShell Injection Hunter: Security Auditing for PowerShell Scripts - blogs.msdn](https://blogs.msdn.microsoft.com/powershell/2018/08/03/powershell-injection-hunter-security-auditing-for-powershell-scripts/)
	* **Logging**
	* **Talks/Presentations**
		* [Defending against PowerShell attacks - in theory, and in practice by Lee holmes](https://www.youtube.com/watch?v=M5bkHUQy-JA&feature=youtu.be)
* **Service Accounts**<a name=""></a>
	* [Service Account best practices Part 1: Choosing a Service Account](https://4sysops.com/archives/service-account-best-practices-part-1-choosing-a-service-account/)
		* In this article you will learn the fundamentals of Windows service accounts. Specifically, we discover the options and best practices concerning the selection of a service account for a particular service application.
	* [Service Account best practices - Part 2: Least Privilege implementation](https://4sysops.com/archives/service-account-best-practices-part-2-least-privilege-implementation/)
		* In this article you will learn some best-practice suggestions for using service applications according to the IT security rule of least privilege.
	* [Best Practice: Securing Windows Service Accounts and Privileged Access – Part 1 - SecurIT360](https://www.securit360.com/blog/best-practice-service-accounts/)
	* [Best Practice: Securing Windows Service Accounts and Privileged Access – Part 2 - SecurIT360](https://www.securit360.com/blog/best-practice-service-accounts-p2/)
	* [Securing Windows Service Accounts (Part 1) - Derek Meiber(2013)](http://techgenix.com/securing-windows-service-accounts-part1/)

