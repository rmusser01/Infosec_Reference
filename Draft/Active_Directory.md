# Attacking & Securing Active Directory


- [Active Directory](#active-directory)
- [Attacking AD 101](#adatk101)

| [Active Directory Technologies](#ADtech) | [Attacking AD](#adattack) |
|---	|---	|
| [ADFS](#adfs) | [Hunting Users](#huntingusers) |
| [AdminSD](#adminsd) | [DCShadow](#dcshadow) |
| [Advanced Threat Analytics](#ata) | [DCSync](#dcsync) |
| [Advanced Threat Protection](#atp) | [Kerberos Delegation](#) |
| [DACLs](#dacl) | [Kebreroasting](#kerberoasting) |
| [DNS](#dns) | [Pass-the-`*`](#pth) |
| [Domain Trusts](#domain-trusts) | [Shadow Admin](#shadowadmin) |
| [Forests](#forests) | [Skeleton Key](#skeleton) |
| [Group Policy](#grouppolicy) | [AD Vulnerabilities(CVEs)](#advulns) |
| [Kerberos](#kerberos) | [Defense Evasion](#addefev) |
| [LDAP](#ldap) | [Collection](#adcollect) |
| [Local Admin Password Solution](#laps) | [Credential Attacks](#adcred) |
| [Lync](#lync) | [Persistence](#adpersist) |
| [MS-SQL](#mssql) | [Privilege Escalation](#adprivesc) |
| [NTLM](#ntlm) | [Reconnaissance](#adrecon) |
| [Read-Only Domain Controllers](#rodc) |   |
| [Red Forest](#redforest) |   	|
| [Service Principal Names](#spn) |   	|
| [System Center Configuration Manager](#sccm) |   	|
| [Domain Trusts](#trusts) |   	|
| [WSUS](#wsus) |   	|
|   	|   	|


---------------------------------------------------------------------------------------------------------------------------------
### <a name="active-directory"></a>Active Directory
* **101**
	* [What is Active Directory Domain Services and how does it work?](https://serverfault.com/questions/402580/what-is-active-directory-domain-services-and-how-does-it-work#)
	* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them - Sean Metcalf](https://adsecurity.org/?p=1684)
	* [What is Active Directory Red Forest Design? - social.technet.ms](https://social.technet.microsoft.com/wiki/contents/articles/37509.what-is-active-directory-red-forest-design.aspx)
	* [Presentations by Sean Metcalf(ADSecurity.org)](https://adsecurity.org/?page_id=1352)
	* **Paid Courses**
		* [Attacking and Defending Active Directory - Nikhil Mittal](https://www.pentesteracademy.com/course?id=47)
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
		* **Talks/Videos**
			* [Offensive Active Directory with Powershell - harmj0y(Troopers2016)](https://www.youtube.com/watch?v=cXWtu-qalSs)
			* [Abusing Active Directory in Post-Exploitation - Carlos Perez(Derbycon4)](https://www.irongeek.com/i.php?page=videos/derbycon4/t105-abusing-active-directory-in-post-exploitation-carlos-perez)
				* Windows APIs are often a blackbox with poor documentation, taking input and spewing output with little visibility on what actually happens in the background. By reverse engineering (and abusing) some of these seemingly benign APIs, we can effectively manipulate Windows into performing stealthy custom attacks using previously unknown persistent and injection techniques. In this talk, we’ll get Windows to play with itself nonstop while revealing 0day persistence, previously unknown DLL injection techniques, and Windows API tips and tricks. To top it all off, a custom HTTP beaconing backdoor will be released leveraging the newly released persistence and injection techniques. So much Windows abuse, so little time.
			* [Beyond the MCSE: Red Teaming Active Directory - Sean Metcalf](https://www.youtube.com/watch?v=tEfwmReo1Hk)
			* [Red vs Blue: Modern Active Directory Attacks & Defense - Sean Metcalf(Defcon23)](https://www.youtube.com/watch?v=rknpKIxT7NM)
			* [Red Vs. Blue: Modern Active Directory Attacks, Detection, And Protection - Sean Metcalf(BHUSA15)](https://www.youtube.com/watch?v=b6GUXerE9Ac)
				* Kerberos "Golden Tickets" were unveiled by Alva "Skip" Duckwall & Benjamin Delpy in 2014 during their Black Hat USA presentation. Around this time, Active Directory (AD) admins all over the world felt a great disturbance in the Force. Golden Tickets are the ultimate method for persistent, forever AD admin rights to a network since they are valid Kerberos tickets and can't be detected, right? The news is filled with reports of breached companies and government agencies with little detail on the attack vectors and mitigation. This briefing discusses in detail the latest attack methods for gaining and maintaining administrative access in Active Directory. Also covered are traditional defensive security measures that work (and ones that don't) as well as the mitigation strategies that can keep your company's name off the front page. Prepare to go beyond "Pass-the-Hash" and down the rabbit hole. This talk explores the latest Active Directory attack vectors and describes how Golden Ticket usage can be detected. When forged Kerberos tickets are used in AD, there are some interesting artifacts that can be identified. Yes, despite what you may have read on the internet, there are ways to detect Golden & Silver Ticket usage!
* **Active Directory Attributes & Technologies**<a name="ADtech"></a>
	* **Active Directory Service Interaces**
		* **101**
			* [Active Directory Service Interfaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)
		* **Articles/Blogposts/Writeups**
		* **Talks/Videos**
		* **Tools**
			* [AdsiPS](https://github.com/lazywinadmin/AdsiPS)
				* PowerShell module to interact with Active Directory using ADSI and the `System.DirectoryServices` namespace (.NET Framework).
	* **AD Permissions/Rights**
		* **101**
			* [Extended Rights Reference - docs.ms](https://docs.microsoft.com/en-us/previous-versions/tn-archive/ff405676(v=msdn.10))
				* This page lists all the extended rights available for delegation in Active Directory. These rights have been categorized according to the object (such as the user account object) that the right applies to; each listing includes the extended right name, a brief description, and the object GUID required when writing a script to delegate that right.
	* **Groups**
		* **101**
			* [Active Directory Security Groups - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11))
	* **Account Logon History**
		* [Get All AD Users Logon History with their Logged on Computers (with IPs)& OUs](https://gallery.technet.microsoft.com/scriptcenter/Get-All-AD-Users-Logon-9e721a89)
			* This script will list the AD users logon information with their logged on computers by inspecting the Kerberos TGT Request Events(EventID 4768) from domain controllers. Not Only User account Name is fetched, but also users OU path and Computer Accounts are retrieved. You can also list the history of last logged on users. In Environment where Exchange Servers are used, the exchange servers authentication request for users will also be logged since it also uses EventID (4768) to for TGT Request. You can also export the result to CSV file format. Powershell version 3.0 is needed to use the script.
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
	* **ATA**<a name="ATA"></a>
		* [ATA Suspicious Activity Playbook - technet.ms](https://gallery.technet.microsoft.com/ATA-Playbook-ef0a8e38)
	* **(Discretionary)Access Control Lists**<a name="dacl">
		* **Articles/Blogposts/Writeups**
			* [Here Be Dragons The Unexplored Land of Active Directory ACLs - Andy Robbins, Will Schroeder, Rohan(Derbycon7)](https://www.youtube.com/watch?v=bHuetBOeOOQ)
			* [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
			* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
			* [The Unintended Risks of Trusting Active Directory](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)
			* [Exploiting Weak Active Directory Permissions With Powersploit](https://blog.stealthbits.com/exploiting-weak-active-directory-permissions-with-powersploit/)
			* [Abusing Active Directory Permissions with PowerView](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
			* [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
			* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
			* [Active Directory Access Control List – Attacks and Defense](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Active-Directory-Access-Control-List-8211-Attacks-and-Defense/ba-p/250315)
			* [Abusing Active Directory ACLs/ACEs - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
			* [Escalating privileges with ACLs in Active Directory - Rindert Kramer and Dirk-jan Mollema(Fox-IT)](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
			    * During internal penetration tests, it happens quite often that we manage to obtain Domain Administrative access within a few hours. Contributing to this are insufficient system hardening and the use of insecure Active Directory defaults. In such scenarios publicly available tools help in finding and exploiting these issues and often result in obtaining domain administrative privileges. This blogpost describes a scenario where our standard attack methods did not work and where we had to dig deeper in order to gain high privileges in the domain. We describe more advanced privilege escalation attacks using Access Control Lists and introduce a new tool called Invoke-Aclpwn and an extension to ntlmrelayx that automate the steps for this advanced attack.
			* [Viewing Service ACLs - rohnspowershellblog(2013)](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/)
			* [Modifying Service ACLs - rohnspowershellblog(2014)](https://rohnspowershellblog.wordpress.com/2013/04/13/modifying-service-acls/)
				* In my [last post](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/), I showed an early version of a function to get the Discretionary Access Control List (DACL) of a Windows service. In this post, I’m going to show a newer version of that function, along with a function to change the DACL, and a helper function to create Access Control Entries (ACEs). The source code is quite a bit longer, so I’m not going to walk through each bit of code. What I will do is give a brief overview of each of the three functions, along with some examples of how to use them. I’ll also mention where I plan to take the functions in the future. I’ll include the source code of the functions as they currently stand at the end of the post. Included in the source code is comment based help for each of the three functions.
			* [AD Privilege Escalation Exploit: The Overlooked ACL - David Rowe](https://www.secframe.com/blog/ad-privilege-escalation-the-overlooked-acl)
		* **Talks & Presentations**
			* [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
			* [Invoke-ACLpwn](https://github.com/fox-it/Invoke-ACLPwn)
    			* Invoke-ACLpwn is a tool that automates the discovery and pwnage of ACLs in Active Directory that are unsafe configured.
		* **Tools**
			* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
				* A collection of tools to enumerate and analyse Windows DACLs
			* [DAMP - The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.](https://github.com/HarmJ0y/DAMP)
				* This project contains several files that implement host-based security descriptor "backdoors" that facilitate the abuse of various remotely accessible services for arbitrary trustees/security principals. tl;dr - this grants users/groups (local, domain, or 'well-known' like 'Everyone') of an attacker's choosing the ability to perform specific administrative actions on a modified host without needing membership in the local administrators group. Note: to implement these backdoors, you need the right to change the security descriptor information for the targeted service, which in stock configurations nearly always means membership in the local administrators group.
	* **DNS**<a name="dns"></a>
		* **Articles/Blogposts/Writeups**
			* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
			* [From DNSAdmins to Domain Admin, When DNSAdmins is More than Just DNS Administration](https://adsecurity.org/?p=4064)
			* [AD Zone Transfers as a user - mubix](http://carnal0wnage.attackresearch.com/2013/10/ad-zone-transfers-as-user.html)
			* [Feature, not bug: DNSAdmin to DC compromise in one line - Shay Ber](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
			* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
				* Zone transfers are a classical way of performing reconnaissance in networks (or even from the internet). They require an insecurely configured DNS server that allows anonymous users to transfer all records and gather information about host in the network. What not many people know however is that if Active Directory integrated DNS is used, any user can query all the DNS records by default. This blog introduces a tool to do this and describes a method to do this even for records normal users don’t have read rights for.
			* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - Kevin Robertson](https://blog.netspi.com/exploiting-adidns/)
			* [Compiling a DLL using MingGW - mubix](https://malicious.link/post/2020/compiling-a-dll-using-mingw/)
				* Compiling a DLL using MingGW to pull of the DNSAdmins attack
			* [Feature, not bug: DNSAdmin to DC compromise in one line - Shay Ber(2017)](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)
			* [Abusing DNSAdmins privilege for escalation in Active Directory - Nikil Mittal(2017)](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
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
		* **Articles/Blogposts/Writeups**
			* [Domain Trusts: Why You Should Care](http://www.harmj0y.net/blog/redteaming/domain-trusts-why-you-should-care/)
			* [Trusts You Might Have Missed](http://www.harmj0y.net/blog/redteaming/trusts-you-might-have-missed/)
			* [A Guide to Attacking Domain Trusts - harmj0y](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
			* [Domain Trusts: We’re Not Done Yet - harmj0y](http://www.harmj0y.net/blog/redteaming/domain-trusts-were-not-done-yet/)
			* [The Trustpocalypse - harmj0y](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
			* [Subverting Trust in Windows - Matt Graeber](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
			* [A Guide to Attacking Domain Trusts - harmj0y](https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944)
			* [Trust Direction: An Enabler for Active Directory Enumeration and Trust Exploitation - BOHOPS](https://bohops.com/2017/12/02/trust-direction-an-enabler-for-active-directory-enumeration-and-trust-exploitation/)
		* **Tools**
	* **Forests**<a name="forests"></a>
		* **101**
			* [How Domain and Forest Trusts Work - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10))
		* **Articles/Blogposts/Writeups**
			* [How NOT to use the PAM trust - Leveraging Shadow Principals for Cross Forest Attacks - Nikhil Mittal](http://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)
	* **Internal Monologue**<a name="ilm"></a>
		* **101**
			* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue/)
		        * In secure environments, where Mimikatz should not be executed, an adversary can perform an Internal Monologue Attack, in which they invoke a local procedure call to the NTLM authentication package (MSV1_0) from a user-mode application through SSPI to calculate a NetNTLM response in the context of the logged on user, after performing an extended NetNTLM downgrade.
		* **Articles/Blogposts/Writeups**
			* [Retrieving NTLM Hashes without touching LSASS: the “Internal Monologue” Attack - Andrea Fortuna(2018)](https://www.andreafortuna.org/2018/03/26/retrieving-ntlm-hashes-without-touching-lsass-the-internal-monologue-attack/)
			* [Getting user credentials is not only admin’s privilege - Anton Sapozhnikov(Syscan14)](https://infocon.org/cons/SyScan/SyScan%202014%20Singapore/SyScan%202014%20presentations/SyScan2014_AntonSapozhnikov_GettingUserCredentialsisnotonlyAdminsPrivilege.pdf)
			* [Stealing Hashes without Admin via Internal Monologue - Practical Exploitation(mubix@hak5)](https://www.youtube.com/watch?v=Q8IRcO0s-fU)
		* **Tools**
			* [selfhash](https://github.com/snowytoxa/selfhash)
				* Selfhash allows you to get password hashes of the current user. This tool doesn't requere high privileges i.e. SYSTEM, but on another hand it returns NTLM Challenge Response, so you could crack it later.
	* **Groups**
		* **101**		
			* [Active Directory Security Groups - docs.ms](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)
				* This reference topic for the IT professional describes the default Active Directory security groups.
			* [How-to: Understand the different types of Active Directory group.  - SS64](https://ss64.com/nt/syntax-groups.html)
		* **Articles/Blogposts/Writeups**
			* [A Pentester’s Guide to Group Scoping - harmj0y](http://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)
	* **Group Policy**<a name="grouppolicy"></a>
		* **101**
			* [Group Policy - Wikipedia](https://en.wikipedia.org/wiki/Group_Policy)
			* [Group Policy Overview - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v%3Dws.11))
			* [Group Policy Architecture - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-architecture)
		* **Articles/Blogposts/Writeups**
			* [Abusing GPO Permissions - harmj0y](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
			* [Sneaky Active Directory Persistence #17: Group Policy](https://adsecurity.org/?p=2716)
			* [A Red Teamer’s Guide to GPOs and OUs](https://wald0.com/?p=179)
			* [File templates for GPO Abuse](https://github.com/rasta-mouse/GPO-Abuse)
			* [GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
			* [Local Group Enumeration - harmj0y](http://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
			* [Where My Admins At? (GPO Edition) - harmj0y](http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/)
			* [Bypassing Group Policy Proxy Settings Using The Windows Registry - Scriptmonkey](http://blog.scriptmonkey.eu/bypassing-group-policy-using-the-windows-registry/)
			* [Local Admin Acces and Group Policy Don't Mix - Oddvar Moe(2019)](https://www.trustedsec.com/blog/local-admin-access-and-group-policy-dont-mix/)
		* **Talks & Presentations**
			* [Get-GPTrashFire - Mike Loss(BSides Canberra2018)](https://www.youtube.com/watch?v=JfyiWspXpQo)
				* Identifying and Abusing Vulnerable Configurations in MS AD Group Policy
				* [Slides](https://github.com/l0ss/Get-GPTrashfire)
		 **Tools**
			* [Grouper](https://github.com/l0ss/Grouper)
				* Grouper is a slightly wobbly PowerShell module designed for pentesters and redteamers (although probably also useful for sysadmins) which sifts through the (usually very noisy) XML output from the Get-GPOReport cmdlet (part of Microsoft's Group Policy module) and identifies all the settings defined in Group Policy Objects (GPOs) that might prove useful to someone trying to do something fun/evil.
			* [Grouper2](https://github.com/l0ss/Grouper2)
				* Grouper2 is a tool for pentesters to help find security-related misconfigurations in Active Directory Group Policy. It might also be useful for other people doing other stuff, but it is explicitly NOT meant to be an audit tool. If you want to check your policy configs against some particular standard, you probably want Microsoft's Security and Compliance Toolkit, not Grouper or Grouper2.
			* [SharpGPO-RemoteAccessPolicies](https://github.com/mwrlabs/SharpGPO-RemoteAccessPolicies)
				* A C# tool for enumerating remote access policies through group policy.
			* [Get-GPTrashFire](https://github.com/l0ss/Get-GPTrashfire/blob/master/Get-GPTrashFire.pdf)
				* Identifiying and Abusing Vulnerable Configuraitons in MS AD Group Policy
			* [SharpGPOAbuse](https://github.com/mwrlabs/SharpGPOAbuse)
				* SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO. [Blogpost](https://labs.mwrinfosecurity.com/tools/sharpgpoabuse)
			* [GetVulnerableGPO](https://github.com/gpoguy/GetVulnerableGPO)
    			* PowerShell script to find 'vulnerable' security-related GPOs that should be hardended
			* [Policy Plus](https://github.com/Fleex255/PolicyPlus)
				* Local Group Policy Editor plus more, for all Windows editions.
	* **Kerberos**<a name="kerberos"></a>
		* **101**
			* [Kerberos (I): How does Kerberos work? – Theory - Eloy Perez](https://www.tarlogic.com/en/blog/how-kerberos-works/)
			* [Kerberos (II): How to attack Kerberos? - Eloy Perez](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
				* In this article about Kerberos, a few attacks against the protocol will be shown. In order to refresh the concepts behind the following attacks, it is recommended to check the [first part](https://www.tarlogic.com/en/blog/how-kerberos-works/) of this series which covers Kerberos theory.		* [Kerberos Attacks Questions - social.technet.ms](https://social.technet.microsoft.com/Forums/en-US/d8e19263-e4f9-49d5-b940-026b0769420a/kerberos-attacks-questions)
			* [Explain like I’m 5: Kerberos - Lynn Roots](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
			* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall, Benjamin Delpy(BHUSA 2015)](https://www.youtube.com/watch?v=lJQn06QLwEw)
				* Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions.
			* [Kerberos Attacks Questions - social.technet.ms](https://social.technet.microsoft.com/Forums/en-US/d8e19263-e4f9-49d5-b940-026b0769420a/kerberos-attacks-questions?forum=winserversecurity)
			* [Kerberos and Attacks 101 - Tim Medin(WWHF2019)](https://www.youtube.com/watch?v=9lOFpUA25Nk)
				* Want to understand how Kerberos works? Would you like to understand modern Kerberos attacks? If so, then join Tim Medin as he walks you through how to attack Kerberos with ticket attacks and Kerberoasting. We'll cover the basics of Kerberos authentication and then show you how the trust model can be exploited for persistence, pivoting, and privilege escalation.
		* **Articles/Writeups**
			* [How To Attack Kerberos 101 - m0chan](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
			* [Kerberos, Active Directory’s Secret Decoder Ring - Sean Metcalf](https://adsecurity.org/?p=227)
			* [Credential cache - MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html)
			* [Kerberos Authentication problems – Service Principal Name (SPN) issues – Part 1 - blogs.technet](https://blogs.technet.microsoft.com/askds/2008/05/29/kerberos-authentication-problems-service-principal-name-spn-issues-part-1/)
			* [Security Focus: Analysing 'Account is sensitive and cannot be delegated' for Privileged Accounts - Ian Fann(2015)](https://blogs.technet.microsoft.com/poshchap/2015/05/01/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts/)
			* [Delegating like a boss: Abusing Kerberos Delegation in Active Directory - Kevin Murphy](https://www.guidepointsecurity.com/2019/09/04/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)
			    * I wanted to write a post that could serve as a (relatively) quick reference for how to abuse the various types of Kerberos delegation that you may find in an Active Directory environment during a penetration test or red team engagement.
			* [Kerberos Tickets on Linux Red Teams - Trevor Haskell(2020)](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)   
		* **Talks & Presentations**
			* [Attacking Microsoft Kerberos: Kicking the Guard Dog of Hades](https://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin)
				* Kerberos- besides having three heads and guarding the gates of hell- protects services on Microsoft Windows Domains. Its use is increasing due to the growing number of attacks targeting NTLM authentication. Attacking Kerberos to access Windows resources represents the next generation of attacks on Windows authentication.In this talk Tim will discuss his research on new attacks against Kerberos- including a way to attack the credentials of a remote service without sending traffic to the service as well as rewriting tickets to access systems.He will also examine potential countermeasures against Kerberos attacks with suggestions for mitigating the most common weaknesses in Windows Kerberos deployments.
			* [Et tu - Kerberos?](https://www.irongeek.com/i.php?page=videos/derbycon4/t109-et-tu-kerberos-christopher-campbell)
				* For over a decade we have been told that Kerberos is the answer to Microsoft’s authentication woes and now we know that isn’t the case. The problems with LM and NTLM are widely known- but the problems with Kerberos have only recently surfaced. In this talk we will look back at previous failures in order to look forward. We will take a look at what recent problems in Kerberos mean to your enterprise and ways you could possibly mitigate them. Attacks such as Spoofed-PAC- Pass-the-Hash- Golden Ticket- Pass-the-Ticket and Over-Pass-the-Ticket will be explained. Unfortunately- we don’t really know what is next – only that what we have now is broken.
			* [Attacking Kerberos: Kicking the Guard Dog of Hades](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf)
			* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws - Exumbraops.com](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
			* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall and Benjamin Delpy(BHUSA 2014)](https://www.youtube.com/watch?v=lJQn06QLwEw)
				* "Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions. Prepare to have all your assumptions about Kerberos challenged!"
				* [Slides](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It-wp.pdf)
			* [Return From The Underworld - The Future Of Red Team Kerberos - Jim Shaver & Mitchell Hennigan](https://www.irongeek.com/i.php?page=videos/derbycon7/t107-return-from-the-underworld-the-future-of-red-team-kerberos-jim-shaver-mitchell-hennigan)
			* [You (dis)liked mimikatz? Wait for kekeo - Benjamin Delpy(BlueHat IL 2019)](https://www.youtube.com/watch?v=sROKCsXdVDg&feature=youtu.be)
		* **Tools**
			* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws - Geoffrey Janja](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
				* [Slides](https://static1.squarespace.com/static/557377e6e4b0976301e02e0f/t/574a0008f85082d3b6ba88a8/1464467468683/Layer1+2016+-+Janjua+-+Kerberos+Party+Tricks+-+Weaponizing+Kerberos+Protocol+Flaws.pdf)
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
	* **LDAP**<a name="ldap"></a>
		* **Articles/Writeups**
			* [LDAP Swiss Army Knife - Moritz Bechler](https://www.exploit-db.com/docs/english/46986-ldap-swiss-army-knife.pdf)
			* [Fun with LDAP and Kerberos: Attacking AD from non-Windows machines - Ronnie Flathers(TR19)](https://www.youtube.com/watch?v=2Xfd962QfPs)
				* [Slides](https://speakerdeck.com/ropnop/fun-with-ldap-and-kerberos-troopers-19)
			* [Faster Domain Escalation using LDAP - Scott Sutherland](https://blog.netspi.com/faster-domain-escalation-using-ldap/)
			* [LDAP Injection Cheat Sheet, Attack Examples & Protection - Checkmarx](https://www.checkmarx.com/knowledge/knowledgebase/LDAP)
		* **Talks & Presentations**
			* [Fun with LDAP and Kerberos: Attacking AD from non-Windows machines - Ronnie Flathers(Troopers19)](https://www.youtube.com/watch?v=2Xfd962QfPs)
				* [Slides](https://speakerdeck.com/ropnop/fun-with-ldap-and-kerberos-troopers-19)
				* You don’t need Windows to talk to Windows. This talk will explain and walk through various techniques to (ab)use LDAP and Kerberos from non-Windows machines to perform reconnaissance, gain footholds, and maintain persistence, with an emphasis on explaining how the attacks and protocols work. This talk will walk through some lesser known tools and techniques for doing reconnaissance and enumeration in AD environments, as well as gaining an initial foothold, and using credentials in different, stealthier ways (i.e. Kerberos). While tools like Bloodhound, CrackMapExec and Deathstar have made footholds and paths to DA very easy and automated, this talk will instead discuss how tools like this work “under-the-hood” and will stress living off the land with default tools and manual recon and exploitation. After discussing some of the technologies and protocols that make up Active Directory Domain Services, I’ll explain how to interact with these using Linux tools and Python. You don’t need a Windows foothold to talk Windows - everything will be done straight from Linux using DNS, LDAP, Heimdal Kerberos, Samba and Python Impacket.
		* **Tools**
			* [LDAPDomainDump](https://github.com/dirkjanm/ldapdomaindump)
				* In an Active Directory domain, a lot of interesting information can be retrieved via LDAP by any authenticated user (or machine). This makes LDAP an interesting protocol for gathering information in the recon phase of a pentest of an internal network. A problem is that data from LDAP often is not available in an easy to read format. ldapdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via LDAP and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files.
			* [windapsearch](https://github.com/ropnop/windapsearch)
				* windapsearch is a Python script to help enumerate users, groups and computers from a Windows domain through LDAP queries. By default, Windows Domain Controllers support basic LDAP operations through port 389/tcp. With any valid domain account (regardless of privileges), it is possible to perform LDAP queries against a domain controller for any AD related information. You can always use a tool like ldapsearch to perform custom LDAP queries against a Domain Controller. I found myself running different LDAP commands over and over again, and it was difficult to memorize all the custom LDAP queries. So this tool was born to help automate some of the most useful LDAP queries a pentester would want to perform in an AD environment.
			* [msldap](https://github.com/skelsec/msldap)
				* [Documentation](https://msldap.readthedocs.io/en/latest/)
				* LDAP library for MS AD	
	* **LAPS**<a name="laps"></a>
		* **101**
			* [Local Administrator Password Solution - docs.ms](https://docs.microsoft.com/en-us/previous-versions/mt227395(v=msdn.10)?redirectedfrom=MSDN)
		* **Articles/Blogposts/Writeups**
			* [Running LAPS with PowerView - harmj0y](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
			* [RastaMouse LAPS Part 1 & 2](https://rastamouse.me/tags/laps/)
			* [Mise en place d'une Backdoor LAPS via modification de l'attribut SearchFlags avec DCShadow - Gregory Lucand](https://adds-security.blogspot.com/2018/08/mise-en-place-dune-backdoor-laps-via.html)
			* [Malicious use of Microsoft LAPS - akijos](https://akijosberryblog.wordpress.com/2019/01/01/malicious-use-of-microsoft-laps/)
			* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon - adsecurity.org](https://adsecurity.org/?p=3164)
			* [Running LAPS Around Cleartext Passwords - Karl Fosaaen](https://blog.netspi.com/running-laps-around-cleartext-passwords/)
		* **Tools**
			* [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
				* Tool to audit and attack LAPS environments
	* **Lync**<a name="lync"></a>
		* [LyncSniper](https://github.com/mdsecresearch/LyncSniper)
			* A tool for penetration testing Skype for Business and Lync deployments
			* [Blogpost/Writeup](https://www.mdsec.co.uk/2017/04/penetration-testing-skype-for-business-exploiting-the-missing-lync/)
		* [LyncSmash](https://github.com/nyxgeek/lyncsmash)
			* a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
			* [Talk](https://www.youtube.com/watch?v=v0NTaCFk6VI)
			* [Slides](https://github.com/nyxgeek/lyncsmash/blob/master/DerbyCon%20Files/TheWeakestLync.pdf)
	* **MachineAccountQuota**
		* [MS-DS-Machine-Account-Quota attribute - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)
			* The number of computer accounts that a user is allowed to create in a domain.
		* [MachineAccountQuota is USEFUL Sometimes: Exploiting One of Active Directory’s Oddest Settings - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)
		* [MachineAccountQuota Transitive Quota: 110 Accounts and Beyond - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-transitive-quota/)
		* [PowerMAD](https://github.com/Kevin-Robertson/Powermad)
			* PowerShell MachineAccountQuota and DNS exploit tools
			* [Blogpost](https://blog.netspi.com/exploiting-adidns/)
	* **MS SQL Server**<a name="mssql"></a>
			* [Hacking SQL Server on Scale with PowerShell - Secure360 2017](https://www.slideshare.net/nullbind/2017-secure360-hacking-sql-server-on-scale-with-powershell)
			* [Using SQL Server for attacking a Forest Trust](http://www.labofapenetrationtester.com/2017/03/using-sql-server-for-attacking-forest-trust.html)
			* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki)
				* [2018 Blackhat USA Arsenal Presentation](https://www.youtube.com/watch?reload=9&v=UX_tBJQtqW0&feature=youtu.be)
			* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server! - Annti Rantasaari(2013)](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
	* **NTLM Reflection**
		* **101**
			* [Windows: DCOM DCE/RPC Local NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=325&redir=1)
			* [Windows: Local WebDAV NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=222&redir=1)
		* **Articles/Blogposts/Writeups**
	* **NTLM Relay**<a name="ntlm"></a>
		* **Articles/Blogposts/Writeups**
			* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes) - byt3bl33d3r](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
			* [NTLM Relay - Pixis](https://en.hackndo.com/ntlm-relay/)
			* [Playing with Relayed Credentials - @agsolino(2018)](https://www.secureauth.com/blog/playing-relayed-credentials)
			* [Server Message Block: SMB Relay Attack (Attack That Always Works) - CQURE Academy](https://cqureacademy.com/blog/penetration-testing/smb-relay-attack)
			* [An SMB Relay Race – How To Exploit LLMNR and SMB Message Signing for Fun and Profit - Jordan Drysdale](https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/)
			* [Effective NTLM / SMB Relaying - mubix](https://malicious.link/post/2014/effective-ntlm-smb-relaying/)
			* [SMB Relay with Snarf - Jeff Dimmock](https://bluescreenofjeff.com/2016-02-19-smb-relay-with-snarfjs-making-the-most-of-your-mitm/)
			* [Pwning with Responder – A Pentester’s Guide](https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/)	
			* [Relaying credentials everywhere with ntlmrelayx](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/)		
			* [Responder with NTLM relay and Empire - chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/execution/responder-with-ntlm-relay-and-empire.html)
			* [What is old is new again: The Relay Attack - @0xdeaddood, @agsolino(2020)](https://www.secureauth.com/blog/what-old-new-again-relay-attack)
				* The purpose of this blog post is to present a new approach to ntlmrelayx.py allowing multi-relay attacks, that means, using just a single connection to attack several targets. On top of this, we added the capability of relaying connections for specific target users.
			* [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
				* Earlier this week, Microsoft issued patches for CVE-2019-1040, which is a vulnerability that allows for bypassing of NTLM relay mitigations. The vulnerability was discovered by Marina Simakov and Yaron Zinar (as well as several others credited in the Microsoft advisory), and they published a technical write-up about the vulnerability here. The short version is that this vulnerability allows for bypassing of the Message Integrity Code in NTLM authentication. The impact of this however, is quite big if combined with the Printer Bug discovered by Lee Christensen and some of my own research that builds forth on the Kerberos research of Elad Shamir. Using a combination of these vulnerabilities, it is possible to relay SMB authentication to LDAP. This allows for Remote code execution as SYSTEM on any unpatched Windows server or workstation (even those that are in different Active Directory forests), and for instant escalation to Domain Admin via any unpatched Exchange server (unless Exchange permissions were reduced in the domain). The most important takeaway of this post is that you should apply the June 2019 patches as soon as possible.
				* [CVE-2019-1040 scanner](https://github.com/fox-it/cve-2019-1040-scanner)
		* **Mitigation**
			* Enforce SMB Signing.
			* [How to enable SMB signing in Windows NT - support.ms](https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt)
			* [All You Need To Know About Windows SMB Signing - Lavanya Rathnam(2018)](http://techgenix.com/windows-smb-signing/)
	* **Read-Only Domain Controllers**<a name="rodc"></a>
		* **101**
			* [Read-Only DCs and the Active Directory Schema - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema)
				* Windows Server 2008 introduces a new type of domain controller, the Read-only Domain Controller (RODC). This provides a domain controller for use at branch offices where a full domain controller cannot be placed. The intent is to allow users in the branch offices to logon and perform tasks like file/printer sharing even when there is no network connectivity to hub sites.
		* **Articles/Blogposts/Writeups**
			* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)
	* **Red Forest**<a name="redforest"></a>
		* **101**
			* [Improving security by protecting elevated-privilege accounts at Microsoft - microsoft.com(2019)](https://www.microsoft.com/en-us/itshowcase/improving-security-by-protecting-elevated-privilege-accounts-at-microsoft)
			* [Active Directory Red Forest Design aka Enhanced Security Administrative Environment (ESAE) - social.technet](https://social.technet.microsoft.com/wiki/contents/articles/37509.active-directory-red-forest-design-aka-enhanced-security-administrative-environment-esae.aspx)
		* **Articles/Blogposts/Writeups**
			* [Privileged Access Workstations - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/privileged-access-workstations)
			* [Planting the Red Forest: Improving AD on the Road to ESAE - Katie Knowles](https://www.f-secure.com/us-en/consulting/our-thinking/planting-the-red-forest-improving-ad-on-the-road-to-esae)
			* [What is Microsoft ESAE and Red Forest - David Rowe](https://www.secframe.com/blog/what-is-microsoft-esae-and-red-forest)
		* **Talks/Presentations/Videos**
			* [Attack and defend Microsoft Enhanced Security Administrative Environment - Hao Wang, Yothin Rodanant(Troopers2018)](https://www.youtube.com/watch?v=0AUValgPTUs)
				* [Slides](https://download.ernw-insight.de/troopers/tr18/slides/TR18_AD_Attack-and-Defend-Microsoft-Enhanced-Security.pdf)
				* Microsoft Enhanced Security Administrative Environment (ESAE) known as “Red Forest” has become a very popular architecture solution to enhance the security of Active Directory. Can ESAE be used to completely prevent cyber attackers from compromising Active Directory? In this talk, we will demonstrate the commonly overlooked techniques that can be used to obtain domain dominance within ESAE.
			* [Tiered Administrative Model - ESAE - Active Directory Red Forest Architecture - Russel Smith(2018)](https://www.youtube.com/watch?v=t4I2saNpoFE)
			* [Understanding “Red Forest”: The 3-Tier Enhanced Security Admin Environment (ESAE) and Alternative Ways to Protect Privileged Credentials - ultimatewindowsecurity.com](https://www.ultimatewindowssecurity.com/webinars/register.aspx?id=1409)
	* **Service Principal Names**<a name="spn"></a>
		* **101**
			* [Service Principal Names - docs.ms](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)
			* [Service Principal Names - docs.ms(older documentation)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961723(v=technet.10))
			* [Register a Service Principal Name for Kerberos Connections - docs.ms](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-2017)
		* **Articles/Blogposts/Writeups**
			* [Active Directory Pentest Recon Part 1: SPN Scanning aka Mining Kerberos Service Principal Names - Sean Metcalf](https://adsecurity.org/?p=230)
			* [SPN Discovery - pentestlab.blog](https://pentestlab.blog/2018/06/04/spn-discovery/)
			* [Service Principal Name (SPN) - hackndo](https://en.hackndo.com/service-principal-name-spn/)
		* See: [Kerberoasting](#kerberoasting)
	* **System Center Configuration Manager**<a name="sccm"></a>
	    * [Targeted Workstation Compromise with SCCM - enigma0x3](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/)
	        * [LM Hash and NT Hash - AD Shot Gyan](http://www.adshotgyan.com/2012/02/lm-hash-and-nt-hash.html)
		* [Using SCCM to violate best practices - cr0n1c](https://cr0n1c.wordpress.com/2016/01/27/using-sccm-to-violate-best-practices/)
	* **Trusts**<a name="trusts"></a>
		* **101**
		* **Articles/Blogposts/Writeups** 
			* [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
			* [It's All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)
			* [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work)
			* [The Forest Is Under Control. Taking over the entire Active Directory forest](https://hackmag.com/security/ad-forest/)
			* [Not A Security Bou* **Read-Only Domain Controllers**
			* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)
			* Not a Security Boundary: Breaking Forest Trusts](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)
			* [Pentesting Active Directory Forests](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
			* [Active Directory forest trusts part 1 - How does SID filtering work? - Dirk-jan Mollema](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
			* [The Trustpocalypse](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
		* **WSUS**<a name="wsus"></a>
			* [WSUSPect - Compromising the Windows Enterprise via Windows Update - Paul Stone, Alex Chapman - BHUS15](https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf)
				* [Blogpost](https://www.contextis.com/en/resources/white-papers/wsuspect-compromising-the-windows-enterprise-via-windows-update))
				* [Slides](https://www.contextis.com/media/downloads/WSUSuspect_Presentation.pdf)
			* [WSuspect Proxy](https://github.com/ctxis/wsuspect-proxy)
				* WSUSpect Proxy - a tool for MITM'ing insecure WSUS connections
			* [WSUSpendu](https://github.com/AlsidOfficial/WSUSpendu)
				* Implement WSUSpendu attack
* **Attack(s/ing)**<a name="adattack"></a>a
	* **Hunting Users**<a name="huntingusers"></a>
		* **Articles/Blogposts/Writeups**
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
		* **Talks/Videos**
			* [I Hunt Sys Admins - Will Schroeder/@harmj0y(Shmoocon 2015)](https://www.youtube.com/watch?v=yhuXbkY3s0E)
			* [I Hunt Sysadmins 2.0 - slides](http://www.slideshare.net/harmj0y/i-hunt-sys-admins-20)
				* It covers various ways to hunt for users in Windows domains, including using PowerView.
			* [Requiem For An Admin, Walter Legowski (@SadProcessor) - BSides Amsterdam 2017](https://www.youtube.com/watch?v=uMg18TvLAcE&index=3&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
				* Orchestrating BloodHound and Empire for Automated AD Post-Exploitation. Lateral Movement and Privilege Escalation are two of the main steps in the Active Directory attacker kill- chain. Applying the 'assume breach' mentality, more and more companies are asking for red-teaming type of assessments, and security researcher have therefor developed a wide range of open-source tools to assist them during these engagements. Out of these, two have quickly gained a solid reputation: PowerShell Empire and BloodHound (Both by @Harmj0y & ex-ATD Crew). In this Session, I will be presenting DogStrike, a new tool (PowerShell Modules) made to interface Empire & BloodHound, allowing penetration testers to merge their Empire infrastructure into the bloodhound graph database. Doing so allows the operator to request a bloodhound path that is 'Agent Aware', and makes it possible to automate the entire kill chain, from initial foothold to DA - or any desired part of an attacker's routine. Presentation will be demo-driven. Code for the module will be made public after the presentation. Automation of Active Directory post-exploitation is going to happen sooner than you might think. (Other tools are being released with the same goal). Is it a good thing? Is it a bad thing? If I do not run out of time, I would like to finish the presentation by opening the discussion with the audience and see what the consequences of automated post- exploitation could mean, from the red, the blue or any other point of view... : DeathStar by @Byt3Bl33d3r | GoFetch by @TalTheMaor.
		* **Tools**
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
	* **DCShadow**<a name="dcshadow"></a>
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
	* **DCSync Attack**<a name="dcsync"></a>
		* **101**
			* [What is DCSync? An Introduction - Lee Berg](https://blog.stealthbits.com/what-is-dcsync/)
			* [[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol - docs.ms](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)
		* **Articles/Blogposts/Writeups**	
			* [DCSync - Yojimbo Security](https://yojimbosecurity.ninja/dcsync/)
			* [DCSync: Dump Password Hashes from Domain Controller - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
			* [Mimikatz DCSync Usage, Exploitation, and Detection - Sean Metcalf](https://adsecurity.org/?p=1729)
			* [Mimikatz and DCSync and ExtraSids, Oh My - harmj0y](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)
			* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)
			* [Extracting User Password Data with Mimikatz DCSync - Jeff Warren](https://blog.stealthbits.com/extracting-user-password-data-with-mimikatz-dcsync/)
		* **Tools**
			* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
	* **Constrained-Delegation**<a name="constrained"></a>
		* **101**
			* [Kerberos Constrained Delegation Overview - docs.ms](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
				* This overview topic for the IT professional describes new capabilities for Kerberos constrained delegation in Windows Server 2012 R2 and Windows Server 2012. Applies To: Windows Server (Semi-Annual Channel), Windows Server 2016
			* [What is Kerberos Delegation? An Overview of Kerberos Delegation - Kevin Joyce(2020)](https://blog.stealthbits.com/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/)
			* [Kerberos Constrained Delegation - AWS](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_key_concepts_kerberos.html)
		* **Articles/Blogposts/Writeups**
			* [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
			* [From Kekeo to Rubeus](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
			* [S4U2Pwnage](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
			* [Kerberos Delegation, Spns And More...](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
			* [A Case Study in Wagging the Dog: Computer Takeover - harmj0y](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/)
			* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory - Elad Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
				* Back in March 2018, I embarked on an arguably pointless crusade to prove that the TrustedToAuthForDelegation attribute was meaningless, and that “protocol transition” can be achieved without it. I believed that security wise, once constrained delegation was enabled (msDS-AllowedToDelegateTo was not null), it did not matter whether it was configured to use “Kerberos only” or “any authentication protocol”.  I started the journey with Benjamin Delpy’s (@gentilkiwi) help modifying Kekeo to support a certain attack that involved invoking S4U2Proxy with a silver ticket without a PAC, and we had partial success, but the final TGS turned out to be unusable. Ever since then, I kept coming back to it, trying to solve the problem with different approaches but did not have much success. Until I finally accepted defeat, and ironically then the solution came up, along with several other interesting abuse cases and new attack techniques.
			* [Kerberos Delegation, SPNs and More... - Alberto Solino(2017)](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
				* In this blog post, I will cover some findings (and still remaining open questions) around the Kerberos Constrained Delegation feature in Windows as well as Service Principal Name (SPN) filtering that might be useful when considering using/testing this technology.
			* [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation - Dirk-jan Mollema](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
				* After my in-depth post last month about unconstrained delegation, this post will discuss a different type of Kerberos delegation: resource-based constrained delegation. The content in this post is based on Elad Shamir’s Kerberos research and combined with my own NTLM research to present an attack that can get code execution as SYSTEM on any Windows computer in Active Directory without any credentials, if you are in the same network segment. This is another example of insecure Active Directory default abuse, and not any kind of new exploit.
			* [Kerberos Resource-Based Constrained Delegation: When an Image Change Leads to a Privilege Escalation - Daniel López Jiménez and Simone Salucci](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/august/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)
		* **Talks & Presentations**
			* [Delegate to the Top Abusing Kerberos for Arbitrary Impersonations and RCE - Matan Hart(BHASIA 17)](https://www.youtube.com/watch?v=orkFcTqClIE)
	* **Unconstrained Delegation**<a name="unconstrained"></a>
		* **101**
			* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain) - Sean Metcalf(2015)](https://adsecurity.org/?p=1667)
		* **Articles/Blogposts/Writeups**
			* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain)](https://adsecurity.org/?p=1667)
			* [Unconstrained Delegation Permissions](https://blog.stealthbits.com/unconstrained-delegation-permissions/)
			* [Trust? Years to earn, seconds to break](https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/)
			* [Getting Domain Admin with Kerberos Unconstrained Delegation - Nikhil Mittal](http://www.labofapenetrationtester.com/2016/02/getting-domain-admin-with-kerberos-unconstrained-delegation.html)
			* [Domain Controller Print Server + Unconstrained Kerberos Delegation = Pwned Active Directory Forest - adsecurity.org](https://adsecurity.org/?p=4056)
			* [Abusing Users Configured with Unconstrained Delegation - ](https://exploit.ph/user-constrained-delegation.html)
			* [“Relaying” Kerberos - Having fun with unconstrained delegation  - Dirk-jan Mollema(2019)](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
		* **Talks & Presentations**
			* [Red vs Blue: Modern Active Directory Attacks Detection and Protection - Sean Metcalf](https://www.youtube.com/watch?v=b6GUXerE9Ac)
				* [Slides](https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection.pdf)
				* [Paper](https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf)
			* [The Unintended Risks of Trusting Active Directory - Lee Christensen, Will Schroeder, Matt Nel(Derbycon 2018)](https://www.youtube.com/watch?v=-bcWZQCLk_4)
			    * Your crown jewels are locked in a database, the system is patched, utilizes modern endpoint security software, and permissions are carefully controlled and locked down. Once this system is joined to Active Directory, however, does that static trust model remain the same? Or has the number of attack paths to your data increased by an order of magnitude? We’ve spent the last year exploring the access control model of Active Directory and recently broadened our focus to include security descriptor misconfigurations/backdoor opportunities at the host level. We soon realized that the post-exploitation “attack surface” of Windows hosts spans well beyond what we originally realized, and that host misconfigurations can sometimes have a profound effect on the security of every other host in the forest. This talk will explore a number of lesser-known Active Directory and host-based permission settings that can be abused in concert for remote access, privilege escalation, or persistence. We will show how targeted host modifications (or existing misconfigurations) can facilitate complex Active Directory attack chains with far-reaching effects on other systems and services in the forest, and can allow new AD attack paths to be built without modifying Active Directory itself.
			    * [Slides](https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory)
		* **Tools**
			* [SpoolSample -> NetNTLMv1 -> NTLM -> Silver Ticket](https://github.com/NotMedic/NetNTLMtoSilverTicket)
				* This technique has been alluded to by others, but I haven't seen anything cohesive out there. Below we'll walk through the steps of obtaining NetNTLMv1 Challenge/Response authentication, cracking those to NTLM Hashes, and using that NTLM Hash to sign a Kerberos Silver ticket. This will work on networks where "LAN Manager authentication level" is set to 2 or less. This is a fairly common scenario in older, larger Windows deployments. It should not work on Windows 10 / Server 2016 or newer.
			* [SpoolerScanner](https://github.com/vletoux/SpoolerScanner)
				* Check if the spooler (MS-RPRN) is remotely available with powershell/c#
			* [SpoolSample](https://github.com/leechristensen/SpoolSample)
			    * PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. This is possible via other protocols as well.
			* [krbrelayx](https://github.com/dirkjanm/krbrelayx)
				* Kerberos unconstrained delegation abuse toolkit 
		* **Mitigation**
			* [ADV190006 | Guidance to mitigate unconstrained delegation vulnerabilities portal.msrc](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006)
	* **Kerberoast(ing)**<a name="kerberoasting"></a>
		* **101**
			* 
		* **Articles/Blogposts/Writueps**
			* [Kerberoasting - Part 1 - mubix](https://room362.com/post/2016/kerberoast-pt1/)
			* [Kerberoasting - Part 2 - mubix](https://room362.com/post/2016/kerberoast-pt2/)
			* [Kerberoasting - Part 3 - mubix](https://room362.com/post/2016/kerberoast-pt3/)
			* [Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain - adsecurity.org](https://adsecurity.org/?p=2293)
			* [Kerberoasting Without Mimikatz - Will Schroeder](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
			* [Mimikatz 2.0 - Brute-Forcing Service Account Passwords ](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Brute-Forcing_Service_Account_Passwords.html)
				* If everything about that ticket-generation operation is valid except for the NTLM hash, then accessing the web application will result in a failure. However, this will not cause a failed logon to appear in the Windows® event log. It will also not increment the count of failed logon attempts for the service account. Therefore, the result is an ability to perform brute-force (or, more realistically, dictionary-based) password checks for such a service account, without locking it out or generating suspicious event log entries. 
			* [kerberos, kerberoast and golden tickets - leonjza](https://leonjza.github.io/blog/2016/01/09/kerberos-kerberoast-and-golden-tickets/)
			* [Extracting Service Account Passwords with Kerberoasting - Jeff Warren](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
			* [Cracking Service Account Passwords with Kerberoasting](https://www.cyberark.com/blog/cracking-service-account-passwords-kerberoasting/)
			* [Targeted Kerberoasting - harmj0y](http://www.harmj0y.net/blog/activedirectory/targeted-kerberoasting/)
			* [Kerberoast PW list for cracking passwords with complexity requirements](https://gist.github.com/edermi/f8b143b11dc020b854178d3809cf91b5)
			* [kerberos, kerberoast and golden tickets - leonzja](https://leonjza.github.io/blog/2016/01/09/kerberos-kerberoast-and-golden-tickets/)
			* [Kerberoast - pentestlab.blog](https://pentestlab.blog/2018/06/12/kerberoast/)
			* [A Toast to Kerberoast - Derek Banks](https://www.blackhillsinfosec.com/a-toast-to-kerberoast/)
			* [Kerberoasting, exploiting unpatched systems – a day in the life of a Red Teamer - Chetan Nayak](http://niiconsulting.com/checkmate/2018/05/kerberoasting-exploiting-unpatched-systems-a-day-in-the-life-of-a-red-teamer/)
			* [Discovering Service Accounts Without Using Privileges - Jeff Warren](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
			* [Kerberoasting - Pixis](https://en.hackndo.com/kerberoasting/)
			* [Kerberoasting and SharpRoast output parsing! - grumpy-sec](https://grumpy-sec.blogspot.com/2018/08/kerberoasting-and-sharproast-output.html)
		* **Talks & Presentations**
			* [Attacking Kerberos: Kicking the Guard Dog of Hades - Tim Medin](https://www.youtube.com/watch?v=HHJWfG9b0-E)
				* Kerberos, besides having three heads and guarding the gates of hell, protects services on Microsoft Windows Domains. Its use is increasing due to the growing number of attacks targeting NTLM authentication. Attacking Kerberos to access Windows resources represents the next generation of attacks on Windows authentication.In this talk Tim will discuss his research on new attacks against Kerberos- including a way to attack the credentials of a remote service without sending traffic to the service as well as rewriting tickets to access systems.He will also examine potential countermeasures against Kerberos attacks with suggestions for mitigating the most common weaknesses in Windows Kerberos deployments.
			* [Demo of kerberoasting on EvilCorp Derbycon6](https://adsecurity.org/wp-content/uploads/2016/09/DerbyCon6-2016-AttackingEvilCorp-Anatomy-of-a-Corporate-Hack-Demo-4-kerberoast.mp4)
			* [Attacking EvilCorp Anatomy of a Corporate Hack - Sean Metcalf, Will Schroeder](https://www.youtube.com/watch?v=nJSMJyRNvlM&feature=youtu.be&t=16)
				* [Slides](https://adsecurity.org/wp-content/uploads/2016/09/DerbyCon6-2016-AttackingEvilCorp-Anatomy-of-a-Corporate-Hack-Presented.pdf)
			* [Kerberos & Attacks 101 - Tim Medin(SANS Webcast)](https://www.youtube.com/watch?v=LmbP-XD1SC8)
			    * Want to understand how Kerberos works? Would you like to understand modern Kerberos attacks? If so, then join Tim Medin as he walks you through how to attack Kerberos with ticket attacks and Kerberoasting. Well cover the basics of Kerberos authentication and then show you how the trust model can be exploited for persistence, pivoting, and privilege escalation.
			* [Kerberoasting Revisited - Will Schroeder(Derbycon2019)](https://www.youtube.com/watch?v=yrMGRhyoyGs)
				* Kerberoasting has become the red team'?'s best friend over the past several years, with various tools being built to support this technique. However, by failing to understand a fundamental detail concerning account encryption support, we haven'?'t understood the entire picture. This talk will revisit our favorite TTP, bringing a deeper understanding to how the attack works, what we?ve been missing, and what new tooling and approaches to kerberoasting exist.
		* **Tools**
			* [kerberoast](https://github.com/nidem/kerberoast)
				* Kerberoast is a series of tools for attacking MS Kerberos implementations.
			* [tgscrack](https://github.com/leechristensen/tgscrack)
			   	* Kerberos TGS_REP cracker written in Golang
		* **AS-REP**
			* [Roasting AS-REPs - harmj0y](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
				* tl;dr – if you can enumerate any accounts in a Windows domain that don’t require Kerberos preauthentication, you can now easily request a piece of encrypted information for said accounts and efficiently crack the material offline, revealing the user’s password.
	* **Machine-Account Quota**
		* **101**
			* [MS-DS-Machine-Account-Quota attribute - docs.ms](https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)
				* The number of computer accounts that a user is allowed to create in a domain.
		* **Articles/Blogposts/Writeups**
			* [MachineAccountQuota is USEFUL Sometimes: Exploiting One of Active Directory’s Oddest Settings - Kevin Robertson(2019)](https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)
	* **MS-Cache**<a name="mscache"></a>
		* **101**
			* [Interactive logon: Number of previous logons to cache (in case domain controller is not available) - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj852209(v=ws.11)?redirectedfrom=MSDN)
				* This security policy reference topic for the IT professional describes the best practices, location, values, policy management and security considerations for this policy setting. Applies To: Windows Server 2003, Windows Vista, Windows XP, Windows Server 2008, Windows 7, Windows 8.1, Windows Server 2008 R2, Windows Server 2012 R2, Windows Server 2012, Windows 8
			* [(Win10)Interactive logon: Number of previous logons to cache (in case domain controller is not available) - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available)
				* Describes the best practices, location, values, policy management and security considerations for the Interactive logon: Number of previous logons to cache (in case domain controller is not available) security policy setting. Applies To: Win10
			* [Cached domain logon information - support.ms](https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information)
		* **Articles/Blogposts/Writeups**
			* [MSCash Hash Primer for Pentesters - webstersprodigy.com(2014)](https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/)
			* [Cracking MS-CACHE v2 hashes using GPU - Security.StackExchange](https://security.stackexchange.com/questions/30889/cracking-ms-cache-v2-hashes-using-gpu)
			* [Interactive logon: Number of previous logons to cache (in case domain controller is not available - UltimateWindowsSecurity](https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=ILNumPrev)
		* **Tools**
			* [passlib.hash.msdcc2 - Windows’ Domain Cached Credentials v2](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.msdcc2.html)
				* This class implements the DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer to cache and verify remote credentials when the relevant server is unavailable. It is known by a number of other names, including “mscache2” and “mscash2” (Microsoft CAched haSH). It replaces the weaker msdcc v1 hash used by previous releases of Windows. Security wise it is not particularly weak, but due to its use of the username as a salt, it should probably not be used for anything but verifying existing cached credentials.
	* **Pass-the-`*`**<a name="pth"></a>
		* **101**
		* **Cache**
			* [Tweet by Benjamin Delpy(2014)](https://twitter.com/gentilkiwi/status/536489791735750656?lang=en&source=post_page---------------------------)
			* [Pass-the-Cache to Domain Compromise - Jamie Shaw](https://medium.com/@jamie.shaw/pass-the-cache-to-domain-compromise-320b6e2ff7da)
				* This post is going to go over a very quick domain compromise by abusing cached Kerberos tickets discovered on a Linux-based jump-box within a Windows domain environment. In essence, we were able to steal cached credentials from a Linux host and use them on a Window-based system to escalate our privileges to domain administrator level.
		* **Hash**
			* For this kind of attack and related ones, check out the Network Attacks page, under Pass-the-Hash.
			* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - harmj0y](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
			* [Windows Credential Guard & Mimikatz - nviso](https://blog.nviso.be/2018/01/09/windows-credential-guard-mimikatz/)
			* [Wendel's Small Hacking Tricks - The Annoying NT_STATUS_INVALID_WORKSTATION](https://www.trustwave.com/Resources/SpiderLabs-Blog/Wendel-s-Small-Hacking-Tricks---The-Annoying-NT_STATUS_INVALID_WORKSTATION-/)
			* [Passing the hash with native RDP client (mstsc.exe)](https://michael-eder.net/post/2018/native_rdp_pass_the_hash/)
				* TL;DR: If the remote server allows Restricted Admin login, it is possible to login via RDP by passing the hash using the native 	Windows RDP client mstsc.exe. (You’ll need mimikatz or something else to inject the hash into the process)
			* [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)
				* Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB services are accessed through .NET TCPClient connections. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
			* [Pass-The-Hash with RDP in 2019 - shellz.club](https://shellz.club/pass-the-hash-with-rdp-in-2019/)
			* [Pass the Hash - hackndo](https://en.hackndo.com/pass-the-hash/)
			* [Pass-the-Hash Web Style - SANS](https://pen-testing.sans.org/blog/2013/04/05/pass-the-hash-web-style)
		* **Over-Pass-the-Hash**
			* [Overpass-the-hash - Benjamin Delpy](http://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
			* [AD Security – Overpass-the-Hash Scenario - Eli Shlomo](https://www.eshlomo.us/ad-security-overpass-the-hash-scenario/)
		* **Ticket**
			* [How To Pass the Ticket Through SSH Tunnels](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
			* [Pass-the-ticket - ldapwiki](http://ldapwiki.com/wiki/Pass-the-ticket)
			* [Silver & Golden Tickets - hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/)
			* **Silver**
				* [Sneaky Active Directory Persistence #16: Computer Accounts & Domain Controller Silver Tickets - adsecurity](https://adsecurity.org/?p=2753)
				* [Impersonating Service Accounts with Silver Tickets - stealthbits](https://blog.stealthbits.com/impersonating-service-accounts-with-silver-tickets)
				* [Mimikatz 2.0 - Silver Ticket Walkthrough](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Silver_Ticket_Walkthrough.html)
				* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
			* **Golden**
				* [Abusing Microsoft Kerberos: Sorry You Guys Don't Get It - Alva Duckwall, Benjamin Delpy(BHUSA 2015)](https://www.youtube.com/watch?v=lJQn06QLwEw)
					* Microsoft Active Directory uses Kerberos to handle authentication requests by default. However, if the domain is compromised, how bad can it really be? With the loss of the right hash, Kerberos can be completely compromised for years after the attacker gained access. Yes, it really is that bad. In this presentation Skip Duckwall, @passingthehash on twitter and Benjamin Delpy, @gentilkiwi on twitter and the author of Mimikatz, will demonstrate just how thoroughly compromised Kerberos can be under real world conditions.
				* [mimikatz - golden ticket](http://rycon.hu/papers/goldenticket.html)
				* [Golden Ticket - ldapwiki](http://ldapwiki.com/wiki/Golden%20Ticket)
				* [Advanced Targeted Attack. PoC Golden Ticket Attack - BSides Tampa 17](https://www.irongeek.com/i.php?page=videos/bsidestampa2017/102-advanced-targeted-attack-andy-thompson)
				* [Complete Domain Compromise with Golden Tickets - stealthbits](https://blog.stealthbits.com/complete-domain-compromise-with-golden-tickets/)
				* [Pass-the-(Golden)-Ticket with WMIC](https://blog.cobaltstrike.com/2015/01/07/pass-the-golden-ticket-with-wmic/)
				* [Kerberos Golden Tickets are Now More Golden - ADSecurity.org](https://adsecurity.org/?p=1640)
				* [Mimikatz 2.0 - Golden Ticket Walkthrough - Ben Lincoln](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html)
	* **Shadow Admins(ACLs)**<a name="shadowadmin"></a>
		* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most - Asaf Hecht](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
		* [ACLight](https://github.com/cyberark/ACLight)
			* ACLight is a tool for discovering privileged accounts through advanced ACLs analysis (objects’ ACLs - Access Lists, aka DACL\ACEs). It includes the discovery of Shadow Admins in the scanned network.
	* **(NTLM)SMB Relay**
		* See `Network_Attacks.md`
		* [Redirect to SMB - Cylance SPEAR](https://blog.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf)
	* **Skeleton Key**<a name="skeleton"></a>
		* [Active Directory Domain Controller Skeleton Key Malware & Mimikatz - ADSecurity](https://adsecurity.org/?p=1255)
		* [Skeleton Key Malware Analysis - SecureWorks](https://www.secureworks.com/research/skeleton-key-malware-analysis)
		* [Unlocking All The Doors To Active Directory With The Skeleton Key Attack](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)
		* [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
		* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)
	* **Specific Vulnerabilities**"<a name="advulns"></a>
		* **MS14-068**
			* **About**
				* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege](https://adsecurity.org/?p=525)
				* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege - adsecurity.org](https://adsecurity.org/?p=525)
				* [Kerberos Vulnerability in MS14-068 (KB3011780) Explained - adsecurity.org](https://adsecurity.org/?p=541)
				* [Detecting MS14-068 Kerberos Exploit Packets on the Wire aka How the PyKEK Exploit Works - adsecurity.org](https://adsecurity.org/?p=763)
				* [Exploiting MS14-068 Vulnerable Domain Controllers Successfully with the Python Kerberos Exploitation Kit (PyKEK) - adsecurity.org](https://adsecurity.org/?p=676)
				* [Digging into MS14-068, Exploitation and Defence - Ben Campbell, Jon Cave](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
			* **Exploiting**
				* [Digging into MS14-068, Exploitation and Defence](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
				* [From MS14-068 to Full Compromise - Stepy by Step - David Kennedy](https://www.trustedsec.com/2014/12/ms14-068-full-compromise-step-step/)
				* [Microsoft Security Bulletin MS14-068 - Critical - docs.ms](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068)
				* [Exploiting MS14-068 with PyKEK and Kali - Zach Grace](https://zachgrace.com/posts/exploiting-ms14-068/)
				* [Exploiting MS14-068 Vulnerable Domain Controllers Successfully with the Python Kerberos Exploitation Kit (PyKEK) - adsecurity.org](https://adsecurity.org/?p=676)
		* **MS15-011**
			* [Practically Exploiting MS15-014 and MS15-011 - MWR](https://labs.mwrinfosecurity.com/blog/practically-exploiting-ms15-014-and-ms15-011/)
			* [MS15-011 - Microsoft Windows Group Policy real exploitation via a SMB MiTM attack - coresecurity](https://www.coresecurity.com/blog/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack)
* **WIP**
	* **Defense Evasion**<a name="addefev"></a>
		* [Evading Microsoft ATA for Active Directory Domination - Nikhil Mittal](https://www.youtube.com/watch?v=bHkv63-1GBY)
			* Microsoft Advanced Threat Analytics (ATA) is a defense platform which reads information from multiple sources like traffic for certain protocols to the Domain Controller, Windows Event Logs and SIEM events. The information thus collected is used to detect Reconnaissance, Credentials replay, Lateral movement, Persistence attacks etc. Well known attacks like Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Golden Ticket, Directory services replication, Brute-force, Skeleton key etc. can be detected using ATA. 
		* [Red Team Techniques for Evading, Bypassing & Disabling MS - Chris Thompson]
			* Windows Defender Advanced Threat Protection is now available for all Blue Teams to utilize within Windows 10 Enterprise and Server 2012/16, which includes detection of post breach tools, tactics and techniques commonly used by Red Teams, as well as behavior analytics. 
			* [Slides](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
	* **Collection**<a name="adcollect"></a>
		* [Accessing Internal Fileshares through Exchange ActiveSync - Adam Rutherford and David Chismon](https://labs.mwrinfosecurity.com/blog/accessing-internal-fileshares-through-exchange-activesync)

	* **Persistence**<a name="adpersist"></a>
		* [The Active Directory Botnet - Ty Miller, Paul Kalinin(BHUSA 17)](https://www.blackhat.com/docs/us-17/wednesday/us-17-Miller-The-Active-Directory-Botnet.pdf)
		* [Command and Control Using Active Directory - harmj0y](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
		* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP) - adsecurity.org](https://adsecurity.org/?p=1760)
	* **Privilege Escalation**<a name="adprivesc"></a>
		* **ACEs/ACLs/DACLs**
			* [DACL Permissions Overwrite Privilege Escalation (CVE-2019-0841) - Nabeel Ahmed(2019)](https://krbtgt.pw/dacl-permissions-overwrite-privilege-escalation-cve-2019-0841/)
				* This vulnerability allows low privileged users to hijack file that are owned by NT AUTHORITY\SYSTEM by overwriting permissions on the targeted file. Successful exploitation results in "Full Control" permissions for the low privileged user.
			* [Microsoft Exchange – ACL - NetbiosX](https://pentestlab.blog/2019/09/12/microsoft-exchange-acl/)
		* **Aiming for DA**
			* [Post-Exploitation in Windows: From Local Admin To Domain Admin (efficiently) - pentestmonkey](http://pentestmonkey.net/uncategorized/from-local-admin-to-domain-admin))
			* [Scenario-based pen-testing: From zero to domain admin with no missing patches required - Georgia Weidman](https://www.computerworld.com/article/2843632/scenario-based-pen-testing-from-zero-to-domain-admin-with-no-missing-patches-required.html)
			* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
			* [Attack Methods for Gaining Domain Admin Rights in Active Directory - adsecurity](https://adsecurity.org/?p=2362)
			* [Gaining Domain Admin from Outside Active Directory - markitzeroday.com](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
		* **Group Policy**
			* [How to own any windows network with group policy hijacking attacks](https://labs.mwrinfosecurity.com/blog/2015/04/02/how-to-own-any-windows-network-with-group-policy-hijacking-attacks/)
		* **One-offs**
			* [Gone to the Dogs - Elad Shamir](https://shenaniganslabs.io/2019/08/08/Lock-Screen-LPE.html)
				* Win10 PrivEsc Domain Joined
			* [CVE-2018-8340: Multi-Factor Mixup: Who Were You Again? - Andrew Lee](https://www.okta.com/security-blog/2018/08/multi-factor-authentication-microsoft-adfs-vulnerability)
				* A weakness in the Microsoft ADFS protocol for integration with MFA products allows a second factor for one account to be used for second-factor authentication to all other accounts in an organization.
	* [MS CVE-2018-8340](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8340)
		* **Tools**
			* [ADAPE-Script](https://github.com/hausec/ADAPE-Script)
			    * Active Directory Assessment and Privilege Escalation Script
	* **Reconaissance**<a name="adrecon"></a>
		* **Articles/Blogposts/Presentations/Talks/Writeups**
			* [Active Directory Firewall Ports – Let’s Try To Make This Simple - Ace Fekay(2011)](https://blogs.msmvps.com/acefekay/2011/11/01/active-directory-firewall-ports-let-s-try-to-make-this-simple/)
			* [Automating the Empire with the Death Star: getting Domain Admin with a push of a button](https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html)
			* [Active Directory Pentest Recon Part 1: SPN Scanning aka Mining Kerberos Service Principal Names](https://adsecurity.org/?p=230)
			* [Active Directory Recon Without Admin Rights - adsecurity](https://adsecurity.org/?p=2535)
			* [Using ActiveDirectory module for Domain Enumeration from PowerShell Constrained Language Mode - Nikhil Mittal](http://www.labofapenetrationtester.com/2018/10/domain-enumeration-from-PowerShell-CLM.html)
			* [Kerberos Domain Username Enumeration - matt](https://www.attackdebris.com/?p=311)
			* [adcli info - Fedora documentation](https://fedoraproject.org/wiki/QA:Testcase_adcli_info)
			* [adcli info forest - Fedora documentation](https://fedoraproject.org/wiki/QA:Testcase_adcli_info_forest)
			* [AD Zone Transfers as a user - mubix](https://malicious.link/post/2013/ad-zone-transfers-as-a-user/)
			* [Gathering AD Data with the Active Directory PowerShell Module - ADSecurity.com](https://adsecurity.org/?p=3719)
			* [Enumerating remote access policies through GPO - William Knowles, Jon Cave](https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/)
		* **Tools**
			* **BloodHound**
				* **101**
					* [Introducing BloodHound](https://wald0.com/?p=68)
					* [Bloodhound 2.2 - A Tool for Many Tradecrafts - Andy Gill](https://blog.zsec.uk/bloodhound-101/)
				* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
					* BloodHound is a single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a PowerShell ingestor. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.
				* **Articles/Blogposts/Writeups**
					* [BloodHound and the Adversary Resilience Model](https://docs.google.com/presentation/d/14tHNBCavg-HfM7aoeEbGnyhVQusfwOjOyQE1_wXVs9o/mobilepresent#slide=id.g35f391192_00)
					* [Introducing the Adversary Resilience Methodology — Part One - Andy Robbins](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
					* [Introducing the Adversary Resilience Methodology — Part Two - Andy Robbins](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
				* **Historical Posts**
					* [Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win. - JohnLaTwC](https://github.com/JohnLaTwC/Shared/blob/master/Defenders%20think%20in%20lists.%20Attackers%20think%20in%20graphs.%20As%20long%20as%20this%20is%20true%2C%20attackers%20win.md)
					* [Automated Derivative Administrator Search - wald0](https://wald0.com/?p=14)
					* [BloodHound 1.3 – The ACL Attack Path Update - wald0](https://wald0.com/?p=112)	
					* [BloodHound 1.4: The Object Properties Update - CptJesus](https://blog.cptjesus.com/posts/bloodhoundobjectproperties)
					* [SharpHound: Target Selection and API Usage](https://blog.cptjesus.com/posts/sharphoundtargeting)	
					* [BloodHound 1.5: The Container Update](https://blog.cptjesus.com/posts/bloodhound15)
					* [A Red Teamer’s Guide to GPOs and OUs - wald0](https://wald0.com/?p=179)
					* [BloodHound 2.0 - CptJesus](https://blog.cptjesus.com/posts/bloodhound20)
					* [BloodHound 2.1: The Fix Broken Stuff Update - Rohan Vazarkar](https://posts.specterops.io/bloodhound-2-1-the-fix-broken-stuff-update-4d28ff732b1)
				* **Using**
					* [BloodHound: Intro to Cypher - CptJesus](https://blog.cptjesus.com/posts/introtocypher)
					* [The Dog Whisperer's Handbook: A Hacker's Guide to the BloodHound Galaxy - @SadProcessor](https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf)
						* [Blogpost](https://insinuator.net/2018/11/the-dog-whisperers-handbook/)
					* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
					* [Lay of the Land with BloodHound](http://threat.tevora.com/lay-of-the-land-with-bloodhound/)
					* [Bloodhound walkthrough. A Tool for Many Tradecrafts - Andy Gill](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)
						* A walkthrough on how to set up and use BloodHound
					* [BloodHound From Red to Blue - Mathieu Saulnier(BSides Charm2019)](https://www.youtube.com/watch?v=UWY772iIq_Y)
					* [BloodHound Tips and Tricks - Riccardo Ancarani](https://blog.riccardoancarani.it/bloodhound-tips-and-tricks/)
				* **Neo4j**
					* [Neo4j Cypher Refcard 3.5](https://neo4j.com/docs/cypher-refcard/current/)
				* **Extending Functionality**
					* [Visualizing BloodHound Data with PowerBI — Part 1 - Andy Robbins](https://posts.specterops.io/visualizing-bloodhound-data-with-powerbi-part-1-ba8ea4908422)
					* [Visualizing BloodHound Data with PowerBI — Part 2 - Andy Robbins](https://posts.specterops.io/visualizing-bloodhound-data-with-powerbi-part-2-3e1c521fb7ae)
					* [Extending BloodHound: Track and Visualize Your Compromise](https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise/)
						* Customizing BloodHound's UI and taking advantage of Custom Queries to document a compromise, find collateral spread of 	owned nodes, and visualize deltas in privilege gains.
					* [Extending BloodHound Part 1 - GPOs and User Right Assignment - Riccardo Ancarani](https://riccardoancarani.github.io/2020-02-06-extending-bloodhound-pt1/)
					* [Cypheroth](https://github.com/seajaysec/cypheroth)
						* Automated, extensible toolset that runs cypher queries against Bloodhound's Neo4j backend and saves output to spreadsheets.
					* [Plumhound](https://github.com/DefensiveOrigins/PlumHound)
						* Released as Proof of Concept for Blue and Purple teams to more effectively use BloodHoundAD in continual security life-cycles by utilizing the BloodHoundAD pathfinding engine to identify Active Directory security vulnerabilities resulting from business operations, procedures, policies and legacy service operations. PlumHound operates by wrapping BloodHoundAD's powerhouse graphical Neo4J backend cypher queries into operations-consumable reports. Analyzing the output of PlumHound can steer security teams in identifying and hardening common Active Directory configuration vulnerabilities and oversights.
				* **Ingestors**
					* [BloodHound.py](https://github.com/fox-it/BloodHound.py)
						* A Python based ingestor for BloodHound
				* **API**
					* [CypherDog](https://github.com/SadProcessor/CypherDog)
						* PowerShell Cmdlets to interact with BloodHound Data via Neo4j REST API
			* **Domain Reconaissance**
				* [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
				* [PywerView](https://github.com/the-useless-one/pywerview)
					* A (partial) Python rewriting of PowerSploit's PowerView.
				* [The PowerView PowerUsage Series #1 - harmjoy](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-1/)
					* [Part #2](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-2/)
					* [Part #3](https://posts.specterops.io/the-powerview-powerusage-series-3-f46089b3cc43)
					* [Part #4](https://posts.specterops.io/the-powerview-powerusage-series-4-e8d408c15c95)
					* [Part #5](https://posts.specterops.io/the-powerview-powerusage-series-5-7ca3ebb23927)
				* [goddi](https://github.com/NetSPI/goddi)
					* goddi (go dump domain info) dumps Active Directory domain information
				* [ADRecon](https://github.com/adrecon/ADRecon)
					* ADRecon is a tool which extracts and combines various artefacts (as highlighted below) out of an AD environment. The information can be presented in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis and provide a holistic picture of the current state of the target AD environment. The tool is useful to various classes of security professionals like auditors, DFIR, students, administrators, etc. It can also be an invaluable post-exploitation tool for a penetration tester. It can be run from any workstation that is connected to the environment, even hosts that are not domain members. Furthermore, the tool can be executed in the context of a non-privileged (i.e. standard domain user) account. Fine Grained Password Policy, LAPS and BitLocker may require Privileged user accounts. The tool will use Microsoft Remote Server Administration Tools (RSAT) if available, otherwise it will communicate with the Domain Controller using LDAP.
				* [AdEnumerator](https://github.com/chango77747/AdEnumerator)
					* Active Directory enumeration from non-domain system. Powershell script
				* [Orchard](https://github.com/its-a-feature/Orchard)
					* Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS' JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web.
				* [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
					* AD PowerShell Recon Scripts
				* [ADCollector](https://github.com/dev-2null/ADCollector)
					* A lightweight tool that enumerates the Active Directory environment to identify possible attack vectors
				* [AdsiPS](https://github.com/lazywinadmin/AdsiPS)
					* PowerShell module to interact with Active Directory using ADSI and the `System.DirectoryServices` namespace (.NET Framework).
				* [jackdaw](https://github.com/skelsec/jackdaw)
					* Jackdaw is here to collect all information in your domain, store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
			* **Local Machine**
				* [HostEnum](https://github.com/threatexpress/red-team-scripts)
					* A PowerShell v2.0 compatible script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain, it can also perform limited domain enumeration with the -Domain switch. However, domain enumeration is significantly limited with the intention that PowerView or BoodHound could also be used.
			* **Passwords**
				* [NtdsAudit](https://github.com/Dionach/NtdsAudit)
					* NtdsAudit is an application to assist in auditing Active Directory databases. It provides some useful statistics relating to accounts and passwords. It can also be used to dump password hashes for later cracking.
			* **Service Principal Name(SPN) Scanning**
				* [Service Principal Names - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/AD/service-principal-names)
				* [SPNs - adsecurity.org](https://adsecurity.org/?page_id=183)
					* This page is a comprehensive reference (as comprehensive as possible) for Active Directory Service Principal Names (SPNs). As I discover more SPNs, they will be added.
				* [Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe - social.technet.ms.com)](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx)
				* [SPN Discovery - pentestlab.blog](https://pentestlab.blog/2018/06/04/spn-discovery/)
				* [Discovering Service Accounts Without Using Privileges - Jeff Warren](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)
		* **Miscellaneous Tools**
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
			* [Check-LocalAdminHash & Exfiltrating All PowerShell History - Beau Bullock](https://www.blackhillsinfosec.com/check-localadminhash-exfiltrating-all-powershell-history/)
				* Check-LocalAdminHash is a new PowerShell script that can check a password hash against multiple hosts to determine if it’s a valid administrative credential. It also has the ability to exfiltrate all PowerShell PSReadline console history files from every profile on every system that the credential provided is an administrator of.
			* [Check-LocalAdminHash](https://github.com/dafthack/Check-LocalAdminHash)
				* Check-LocalAdminHash is a PowerShell tool that attempts to authenticate to multiple hosts over either WMI or SMB using a password hash to determine if the provided credential is a local administrator. It's useful if you obtain a password hash for a user and want to see where they are local admin on a network. It is essentially a Frankenstein of two of my favorite tools along with some of my own code. It utilizes Kevin Robertson's (@kevin_robertson) Invoke-TheHash project for the credential checking portion. Additionally, the script utilizes modules from PowerView by Will Schroeder (@harmj0y) and Matt Graeber (@mattifestation) to enumerate domain computers to find targets for testing admin access against.
			* [Wireless_Query](https://github.com/gobiasinfosec/Wireless_Query)
				* Query Active Directory for Workstations and then Pull their Wireless Network Passwords. This tool is designed to pull a list of machines from AD and then use psexec to pull their wireless network passwords. This should be run with either a DOMAIN or WORKSTATION Admin account.
			* [Find AD users with empty password using PowerShell](https://4sysops.com/archives/find-ad-users-with-empty-password-passwd_notreqd-flag-using-powershell/)
			* [ACLight](https://github.com/cyberark/ACLight)
				* The tool queries the Active Directory (AD) for its objects' ACLs and then filters and analyzes the sensitive permissions of each one. The result is a list of domain privileged accounts in the network (from the advanced ACLs perspective of the AD). You can run the scan with just any regular user (could be non-privileged user) and it automatically scans all the domains of the scanned network forest.
			* [zBang](https://github.com/cyberark/zBang)
				* zBang is a special risk assessment tool that detects potential privileged account threats in the scanned network.
				* [Blogpost](https://www.cyberark.com/threat-research-blog/the-big-zbang-theory-a-new-open-source-tool/)



















-------------
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
	* [Abusing Exchange: One API call away from Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
	* [Exploiting PrivExchange - chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
		* expansion and demo of how to use the PrivExchange exploit
	* [MailSniper](https://github.com/dafthack/MailSniper)
		* MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an Exchange administrator to search the mailboxes of every user in a domain. MailSniper also includes additional modules for password spraying, enumerating users/domains, gathering the Global Address List from OWA and EWS, and checking mailbox permissions for every Exchange user at an organization.
	* [PowerPriv](https://github.com/G0ldenGunSec/PowerPriv)
		* A powershell implementation of PrivExchange by `@_dirkjan` (original code found here: https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py) Useful for environments on which you cannot run python-based applications, have user credentials, or do not want to drop files to disk. Will cause the target exchange server system account to attempt to authenticate to a system of your choice.
	* [exchange_hunter2](https://github.com/aslarchergore/exchange_hunter2)
		* This script uses a valid credential, a DC IP and Hostname to log into the DC over LDAP and query the LDAP server for the wherabouts of the Microsoft Exchange servers in the environment.
