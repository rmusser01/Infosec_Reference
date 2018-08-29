# Defense

## In Progress

## Table of Contents
- [Amazon S3](#s3)
- [Application Whitelisting](#whitelist)
- [AppSec](#appsec)
- [Attack Surface Analysis/Reduction](#asa)
- [Auditing Account Passwords/Privileges](#aapp)
- [Auditing Processes](#ap)
- [Baselining](#baseline)
- [Hardening](#harden)
- [Leaks](#leak)
- [Linux/Unix](#linux)
- [Malicious USB](#malusb)
- [Network](#network)
- [OS X](#osx)
- [Phishing](#phishing)
- [Ransomware](#ransom)
- [User Awareness Training](#uat)
- [Web](#web)
- [WAF(#waf)
- [Windows](#windows)
- [Powershell](#powershell)



------------------
### Sort

* **To-Do**
	* User Awareness training
	* Objective-See Tools
	* Cred defense
	* SPA 
	* Azure stuff
	* AWS Stuff
	* GCP Stuff
\


* [Introducing the Adversary Resilience Methodology — Part One - specterops](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
* [Introducing the Adversary Resilience Methodology — Part Two](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
* [Using an Expanded Cyber Kill Chain Model to Increase Attack Resiliency - Sean Malone - BHUSA16](https://www.youtube.com/watch?v=1Dz12M7u-S8)
	* We'll review what actions are taken in each phase, and what's necessary for the adversary to move from one phase to the next. We'll discuss multiple types of controls that you can implement today in your enterprise to frustrate the adversary's plan at each stage, to avoid needing to declare "game over" just because an adversary has gained access to the internal network. The primary limiting factor of the traditional Cyber Kill Chain is that it ends with Stage 7: Actions on Objectives, conveying that once the adversary reaches this stage and has access to a system on the internal network, the defending victim has already lost. In reality, there should be multiple layers of security zones on the internal network, to protect the most critical assets. The adversary often has to move through numerous additional phases in order to access and manipulate specific systems to achieve his objective. By increasing the time and effort required to move through these stages, we decrease the likelihood of the adversary causing material damage to the enterprise. 
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Malone-Using-An-Expanded-Cyber-Kill-Chain-Model-To-Increase-Attack-Resiliency.pdf)


https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls

https://www.auditscripts.com/free-resources/critical-security-controls/

* [Windows ISV Software Security Defenses - msdn](https://msdn.microsoft.com/en-us/library/bb430720.aspx)
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/ee791851(v=ws.11)

* [DevSec Hardening Framework](https://github.com/dev-sec)

* [A Linux Auditd rule set mapped to MITRE's Attack Framework](https://github.com/bfuzzy/auditd-attack)


### End Sort


* **Access Control** <a name="acl"></a>
	* [Capirca](https://github.com/google/capirca)
		* Capirca is a tool designed to utilize common definitions of networks, services and high-level policy files to facilitate the development and manipulation of network access control lists (ACLs) for various platforms. It was developed by Google for internal use, and is now open source.
* **Amazon AWS** <a name="aws"></a>
	* **AWS**
	* **S3**
		* [Amazon S3 Bucket Public Access Considerations](https://aws.amazon.com/articles/5050)
* **Anti-Redteam Tactics** <a name="antired"></a>
	* [So you want to beat the Red Team - sCameron Moore - Bsides Philly 2016](https://www.youtube.com/watch?list=PLNhlcxQZJSm8IHSE1JzvAH2oUty_yXQHT&v=BYazrXR_DFI&index=10&app=desktop) 
	* [NorkNork - Tool for identifying Empire persistence payloads](https://github.com/n00py/NorkNork)
	* [Removing Backdoors – Powershell Empire Edition - n00py](https://www.n00py.io/2017/01/removing-backdoors-powershell-empire-edition/)
	* [ketshash](https://github.com/cyberark/ketshash)
		* A little tool for detecting suspicious privileged NTLM connections, in particular Pass-The-Hash attack, based on event viewer logs.
	* [Sysinternals Sysmon suspicious activity guide - blogs.technet](https://blogs.technet.microsoft.com/motiba/2017/12/07/sysinternals-sysmon-suspicious-activity-guide/)
	* [Using an Expanded Cyber Kill Chain Model to Increase Attack Resiliency - Sean Malone - BHUSA16](https://www.youtube.com/watch?v=1Dz12M7u-S8)
		* We'll review what actions are taken in each phase, and what's necessary for the adversary to move from one phase to the next. We'll discuss multiple types of controls that you can implement today in your enterprise to frustrate the adversary's plan at each stage, to avoid needing to declare "game over" just because an adversary has gained access to the internal network. The primary limiting factor of the traditional Cyber Kill Chain is that it ends with Stage 7: Actions on Objectives, conveying that once the adversary reaches this stage and has access to a system on the internal network, the defending victim has already lost. In reality, there should be multiple layers of security zones on the internal network, to protect the most critical assets. The adversary often has to move through numerous additional phases in order to access and manipulate specific systems to achieve his objective. By increasing the time and effort required to move through these stages, we decrease the likelihood of the adversary causing material damage to the enterprise. 
		* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Malone-Using-An-Expanded-Cyber-Kill-Chain-Model-To-Increase-Attack-Resiliency.pdf)
	* [PE-sieve](https://github.com/hasherezade/pe-sieve)
		* PE-sieve scans a given process, searching for the modules containing in-memory code modifications. When found, it dumps the modified PE.
	* [ClrGuard](https://github.com/endgameinc/ClrGuard)
		* ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes. ClrGuard leverages a simple appInit DLL (ClrHook32/64.dll) in order to load into all CLR/.NET processes. From there, it performs an in-line hook of security critical functions. Currently, the only implemented hook is on the native LoadImage() function. When events are observed, they are sent over a named pipe to a monitoring process for further introspection and mitigation decision.
* **Application Whitelisting** <a name="whitelist"></a>
* [Guide to Application Whitelisting - NIST Special Publication 800 - 167](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-167.pdf)
* **Attack Surface Analysis/Reduction** <a name="asa"></a>
	* **General**
		* [Intrigue-core](https://github.com/intrigueio/intrigue-core)
			* Intrigue-core is a framework for automated attack surface discovery. 
* **(General)Auditing Account Passwords/Privileges** <a name="aapp"></a>
* **(General)Auditing Processes** <a name="ap"></a>
	* [ESA-Process-Maturity](https://github.com/Brockway/ESA-Process-Maturity)
		* Tools to measure the maturity of Enterprise Security Architecture processes
	* [Command line process auditing](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
* **(General) Baselining**<a name="baseline"></a>
* **Certificates (X.509)** <a name="certificates"></a>
	* [Certificate Transparency](https://www.certificate-transparency.org/)
		* [What is Certificate Transparency?](https://www.certificate-transparency.org/what-is-ct)
* **Firewalls** <a name="firewall"></a>
	* [Assimilator](https://github.com/videlanicolas/assimilator)
		* The first restful API to control all firewall brands. Configure any firewall with restful API calls, no more manual rule configuration. Centralize all your firewalls into one API.
	* [simplewall](https://github.com/henrypp/simplewall)
		* Simple tool to configure Windows Filtering Platform (WFP) which can configure network activity on your computer. The lightweight application is less than a megabyte, and it is compatible with Windows Vista and higher operating systems. You can download either the installer or portable version. For correct working, need administrator rights.
* **(General) Hardening** <a name="hardening"></a>
	* **101**
	* **Browsers**
	* **Guides**
		* [ERNW Repository of Hardening Guides](https://github.com/ernw/hardening)
		* [OWASP Secure Configuration Guide](https://www.owasp.org/index.php/Secure_Configuration_Guide)
		* [PHP Secure Configuration Checker](https://github.com/sektioneins/pcc)
		* [Security + DevOps Automatic Server Hardening - dev-sec.io](http://dev-sec.io/)
			* Open Source Automated Hardening Framework
		* [YubiKey-Guide](https://github.com/drduh/YubiKey-Guide)
			* This is a practical guide to using YubiKey as a SmartCard for storing GPG encryption and signing keys.
	* **SSH**
		* [ssh-audit](https://github.com/arthepsy/ssh-audit)
			* SSH server auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)
		* [Mozilla's OpenSSH Configuration guide](https://wiki.mozilla.org/Security/Guidelines/OpenSSH)
		* [CERT-NZ SSH Hardening](https://github.com/certnz/ssh_hardening)
			* CERT NZ documentation for hardening SSH server and client configuration, and using hardware tokens to protect private keys
	* **Linux**
		* [Linux workstation security checklist](https://github.com/lfit/itpol/blob/master/linux-workstation-security.md)
	* **OS X**
		* [OS X Hardening: Securing a Large Global Mac Fleet - Greg Castle](https://www.usenix.org/conference/lisa13/os-x-hardening-securing-large-global-mac-fleet)
* **Google** <a name="google"></a>
	* **G-Suite**
		* [Securing G Suite - Megan Roddie](https://blog.reconinfosec.com/securing-g-suite/)
	* **Gmail**
		* [Adding a security key to Gmail - techsolidarity.org](https://techsolidarity.org/resources/security_key_gmail.htm)
			* This guide is designed for regular humans. It will walk you through the steps of effectively protecting your Gmail account with a security key, without explaining in detail the reasons for each step.
* **Journalist**<a name="journalist"></a>
	* [Information Security For Journalist book - Centre for Investigative Journalism](http://files.gendo.nl/Books/InfoSec_for_Journalists_V1.1.pdf)
* **Leaks** <a name="leaks"></a>
	* [AIL framework - Analysis Information Leak framework](https://github.com/CIRCL/AIL-framework)
		* AIL is a modular framework to analyse potential information leaks from unstructured data sources like pastes from Pastebin or similar services or unstructured data streams. AIL framework is flexible and can be extended to support other functionalities to mine sensitive information.
	* [git-secrets](https://github.com/awslabs/git-secrets)
		* Prevents you from committing passwords and other sensitive information to a git repository.
	* [keynuker](https://github.com/tleyden/keynuker)
		* KeyNuker scans public activity across all Github users in your Github organization(s) and proactively deletes any AWS keys that are accidentally leaked. It gets the list of AWS keys to scan by directly connecting to the AWS API.
	* [You're Leaking Trade Secrets - Defcon22 Michael Schrenk](https://www.youtube.com/watch?v=JTd5TL6_zgY)
		* Networks don't need to be hacked for information to be compromised. This is particularly true for organizations that are trying to keep trade secrets. While we hear a lot about personal privacy, little is said in regard to organizational privacy. Organizations, in fact, leak information at a much greater rate than individuals, and usually do so with little fanfare. There are greater consequences for organizations when information is leaked because the secrets often fall into the hands of competitors. This talk uses a variety of real world examples to show how trade secrets are leaked online, and how organizational privacy is compromised by seemingly innocent use of The Internet.
* **Linux/Unix** <a name="linux"></a>
	* [LUNAR](https://github.com/lateralblast/lunar)
		* A UNIX security auditing tool based on several security frameworks
	* [Filenames and Pathnames in Shell: How to do it Correctly](https://www.dwheeler.com/essays/filenames-in-shell.html)
	* [Monit](https://mmonit.com/monit/)
		* Monit is a small Open Source utility for managing and monitoring Unix systems. Monit conducts automatic maintenance and repair and can execute meaningful causal actions in error situations.
	* [Red Hat Enterprise Linux 6 Security Guide](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/pdf/Security_Guide/Red_Hat_Enterprise_Linux-6-Security_Guide-en-US.pdf)
* **Malicious USBs** <a name="malusb"></a>
* **Microsoft Azure** <a name="azure"></a> 
	* [Manage emergency-access administrative accounts in Azure AD - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-emergency-access)
	* [Securing privileged access for hybrid and cloud deployments in Azure AD - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-admin-roles-secure)
	* [How to require two-step verification for a user - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates)
* **Network** <a name="network"></a>
	* **Talks & Presentations**
		* [Defending the Enterprise Against Network Infrastructure Attacks  - Paul Coggin - Troopers15](https://www.youtube.com/watch?v=K0X3RDf5XK8)
	* **Tools**
		* [DrawBridge](https://github.com/landhb/DrawBridge)
			* A layer 4 Single Packet Authentication (SPA) Module, used to conceal TCP ports on public facing machines and add an extra layer of security.
* **OS X**<a name="osx"></a>
	* **General**
		* [macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
			*  A practical guide to securing macOS.
	* **Tools**
		* [netman](https://github.com/iadgov/netman)
			* A userland network manager with monitoring and limiting capabilities for macOS.
		* [netfil](https://github.com/iadgov/netfil)
			* A kernel network manager with monitoring and limiting capabilities for macOS.
		* [OverSight](https://objective-see.com/products/oversight.html)
			* OverSight monitors a mac's mic and webcam, alerting the user when the internal mic is activated, or whenever a process accesses the webcam.
		* [LuLu](https://github.com/objective-see/LuLu)
			* LuLu is the free open-source macOS firewall that aims to block unauthorized (outgoing) network traffic
		* [Santa](https://github.com/google/santa)
			* Santa is a binary whitelisting/blacklisting system for macOS. It consists of a kernel extension that monitors for executions, a userland daemon that makes execution decisions based on the contents of a SQLite database, a GUI agent that notifies the user in case of a block decision and a command-line utility for managing the system and synchronizing the database with a server.
			* [Docs](https://github.com/google/santa/tree/master/Docs)
* **Phishing** <a name="phishing"></a>
	* [Mercure](https://github.com/synhack/mercure)
		* Mercure is a tool for security managers who want to teach their colleagues about phishing.
	* [PPRT](https://github.com/MSAdministrator/PPRT)
		* This module is used to report phishing URLs to their WHOIS/RDAP abuse contact information.
	* [PhishingKitHunter](https://github.com/t4d/PhishingKitHunter)
		* PhishingKitHunter (or PKHunter) is a tool made for identifying phishing kits URLs used in phishing campains targeting your customers and using some of your own website files (as CSS, JS, ...). This tool - write in Python 3 - is based on the analysis of referer's URL which GET particular files on the legitimate website (as some style content) or redirect user after the phishing session. Log files (should) contains the referer URL where the user come from and where the phishing kit is deployed. PhishingKitHunter parse your logs file to identify particular and non-legitimate referers trying to get legitimate pages based on regular expressions you put into PhishingKitHunter's config file.
	* [Catching phishing before they catch you](https://blog.0day.rocks/catching-phishing-using-certstream-97177f0d499a)
	* [Tracking Newly Registered Domains - SANS](https://isc.sans.edu/forums/diary/Tracking+Newly+Registered+Domains/23127/)
	* [Hunting-Newly-Registered-Domains](https://github.com/gfek/Hunting-New-Registered-Domains)
		* The hnrd.py is a python utility for finding and analysing potential phishing domains used in phishing campaigns targeting your customers. This utility is written in python (2.7 and 3) and is based on the analysis of the features below by consuming a free daily list provided by the Whoisds site.
	* [SwiftFilter](https://github.com/SwiftOnSecurity/SwiftFilter)
		* Exchange Transport rules using text matching and Regular Expressions to detect and enable response to basic phishing. Designed to augment EOP in Office 365.
* **Ransomware** <a name="ransomware"></a>
	* [Decryptonite](https://github.com/DecryptoniteTeam/Decryptonite)
		* Decryptonite is a tool that uses heuristics and behavioural analysis to monitor for and stop ransomware.
* **User Awareness Training** <a name="uat"></a>
* **Web**
	* [Practical Approach to Detecting and Preventing Web Application Attacks over HTTP2](https://www.sans.org/reading-room/whitepapers/protocols/practical-approach-detecting-preventing-web-application-attacks-http-2-36877)
	* [AWS Lambda - IAM Access Key Disabler](https://github.com/te-papa/aws-key-disabler)
		* The AWS Key disabler is a Lambda Function that disables AWS IAM User Access Keys after a set amount of time in order to reduce the risk associated with old access keys.
	* [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
	* [The Open Guide to Amazon Web Services](https://github.com/open-guides/og-aws)
		* A lot of information on AWS is already written. Most people learn AWS by reading a blog or a “getting started guide” and referring to the standard AWS references. Nonetheless, trustworthy and practical information and recommendations aren’t easy to come by. AWS’s own documentation is a great but sprawling resource few have time to read fully, and it doesn’t include anything but official facts, so omits experiences of engineers. The information in blogs or Stack Overflow is also not consistently up to date. This guide is by and for engineers who use AWS. It aims to be a useful, living reference that consolidates links, tips, gotchas, and best practices. It arose from discussion and editing over beers by several engineers who have used AWS extensively.
* **WAF** <a name="waf"></a>
	* **NAXSI**
		* [naxsi](https://github.com/nbs-system/naxsi)
			* NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX
		* [naxsi wiki](https://github.com/nbs-system/naxsi/wiki)
	* **ModSecurity**
		* [ModSecurity](https://www.modsecurity.org/)
		* [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)
* **Windows** <a name="windows"></a>
	* **General**
		* [Windows Firewall Hook Enumeration](https://www.nccgroup.com/en/blog/2015/01/windows-firewall-hook-enumeration/)
			* We’re going to look in detail at Microsoft Windows Firewall Hook drivers from Windows 2000, XP and 2003. This functionality was leveraged by the Derusbi family of malicious code to implement port-knocking like functionality. We’re going to discuss the problem we faced, the required reverse engineering to understand how these hooks could be identified and finally how the enumeration tool was developed.
		* [Detecting DLL Hijackingon Windows](http://digital-forensics.sans.org/blog/2015/03/25/detecting-dll-hijacking-on-windows/)
		* [The Effectiveness of Tools in Detecting the 'Maleficent Seven' Privileges in the Windows Environment](https://www.sans.org/reading-room/whitepapers/sysadmin/effectiveness-tools-detecting-039-maleficent-seven-039-privileges-windows-environment-38220)
		* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
			* A collection of tools to enumerate and analyse Windows DACLs
		* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - labofapenetrationtester](http://www.labofapenetrationtester.com/2016/09/amsi.html)
	* **Account Credentials** 
		* **General**
			* [Blocking Remote Use of Local Accounts](https://blogs.technet.microsoft.com/secguide/2014/09/02/blocking-remote-use-of-local-accounts/)
			* [MS Security Advisory 2871997](https://technet.microsoft.com/library/security/2871997)
				* Update to Improve Credentials Protection and Management
			* [Invoke-HoneyCreds - Ben0xA](https://github.com/Ben0xA/PowerShellDefense)
				* Use Invoke-HoneyCreds to distribute fake cred throughout environment as "legit" service account and monitor for use of creds
			* [The CredDefense Toolkit - BlackHills](https://www.blackhillsinfosec.com/the-creddefense-toolkit/)
				* Credential and Red Teaming Defense for Windows Environments
			* [KB2871997 and Wdigest – Part 1](https://blogs.technet.microsoft.com/kfalde/2014/11/01/kb2871997-and-wdigest-part-1/)
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
	* **Active Directory**
		* [What would a real hacker do to your Active Directory](https://www.youtube.com/watch?v=DH3v8bO-NCs)
		* [Securing Microsoft Active Directory Federation Server (ADFS)](https://adsecurity.org/?p=3782)
		* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening/blob/master/README.md)
		* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them - adsecurity](https://adsecurity.org/?p=1684)
		* **Awareness**
			* [NtdsAudit](https://github.com/Dionach/NtdsAudit)
				* NtdsAudit is an application to assist in auditing Active Directory databases. It provides some useful statistics relating to accounts and passwords. It can also be used to dump password hashes for later cracking.
			* [Grouper](https://github.com/l0ss/Grouper)
				* Grouper is a slightly wobbly PowerShell module designed for pentesters and redteamers (although probably also useful for sysadmins) which sifts through the (usually very noisy) XML output from the Get-GPOReport cmdlet (part of Microsoft's Group Policy module) and identifies all the settings defined in Group Policy Objects (GPOs) that might prove useful to someone trying to do something fun/evil.
		* **Building/Designing Infrastructure**
			* [How to Build Super Secure Active Directory Infrastructure* - BlackHills](https://www.blackhillsinfosec.com/build-super-secure-active-directory-infrastructure/)
			* [Active Directory Design Best Practices](https://krva.blogspot.com/2008/04/ad-design-best-practices.html)
		* **Domain Controllers/Admins**
			* [Securing Domain Controllers to Improve Active Directory Security - adsecurity.org](https://adsecurity.org/?p=3377)
			* [Protecting Privileged Domain Accounts: Network Authentication In-Depth](https://digital-forensics.sans.org/blog/2012/09/18/protecting-privileged-domain-accounts-network-authentication-in-depth)
			* [Active Directory: Real Defense for Domain Admins](https://www.irongeek.com/i.php?page=videos/derbycon4/t213-active-directory-real-defense-for-domain-admins-jason-lang)
				* Did your AD recently get owned on a pentest? It’s always fun to see an unknown entry show up in your Domain Admins group (#fail). Come learn how to truly protect your organization’s IT crown jewels from some of the most popular AD attacks. If you’re stuck trying to figure out what to do with null sessions, pass the hash techniques, or protecting your Domain Admins, then you will want to be here.
		* **AppLocker**
			* [Script Rules in AppLocker - technet](https://technet.microsoft.com/en-us/library/ee460958.aspx)
			* [DLL Rules in AppLocker](https://technet.microsoft.com/en-us/library/ee460947.aspx)
			* [Application Whitelisting Using Microsoft AppLocker](https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)
			* [Harden Windows with AppLocker – based on Case study Part 1 - oddvar.moe](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
			* [Harden Windows with AppLocker – based on Case study part 2 - oddvar.moe](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
		* **Auditing Account Passwords/Privileges**
			* [Account lockout threshold - technet](https://technet.microsoft.com/en-us/library/hh994574.aspx)
			* [Password Policy - technet](https://technet.microsoft.com/en-us/library/hh994572.aspx)
			* [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
				* As a part of ensuring that they've created a secure environment Windows administrators often need to know what kind of accesses specific users or groups have to resources including files, directories, Registry keys, global objects and Windows services. AccessChk quickly answers these questions with an intuitive interface and output.
		* **Guarded Fabric/Shielded VMs**
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
		* **Group Policy**
			* [The 10 Windows group policy settings you need to get right](http://www.infoworld.com/article/2609578/security/the-10-windows-group-policy-settings-you-need-to-get-right.html?page=2)
			* [Group Policy for WSUS - grouppolicy.biz](http://www.grouppolicy.biz/2011/06/best-practices-group-policy-for-wsus/)
			* [GPO Best Policies - grouppolicy.biz](http://www.grouppolicy.biz/best-practices/)
			* [Securing Windows with Group Policy Josh - Rickard - Derbycon7](https://www.youtube.com/watch?v=Upeaa2rgozk&index=66&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
			* [Guidance on Deployment of MS15-011 and MS15-014 - blogs.technet](https://blogs.technet.microsoft.com/askpfeplat/2015/02/22/guidance-on-deployment-of-ms15-011-and-ms15-014/)
			* [MS15-011 & MS15-014: Hardening Group Policy - blogs.technet](https://blogs.technet.microsoft.com/srd/2015/02/10/ms15-011-ms15-014-hardening-group-policy/)
		* **Hardening**
			* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
				*  A curated list of awesome Security Hardening techniques for Windows.
			* [Threats and Countermeasures Guide: Security Settings in Windows Server 2008 R2 and Windows 7 - technet](https://technet.microsoft.com/en-us/library/hh125921.aspx)
			* [Harden windows IP Stack](https://www.reddit.com/r/netsec/comments/2sg80a/how_to_harden_windowsiis_ssltls_configuration/)
			* [Secure Host Baseline](https://github.com/iadgov/Secure-Host-Baseline)
				* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
			* [Second section good resource for hardening windows](http://labs.bitdefender.com/2014/11/do-your-bit-to-limit-cryptowall/)
			* [Secure-Host-Baseline](https://github.com/iadgov/Secure-Host-Baseline)
				* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
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
		* **Just Enough Administration (JEA)**
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
		* **LLMNR/NBNS**
			* [Conveigh](https://github.com/Kevin-Robertson/Conveigh)
				* Conveigh is a Windows PowerShell LLMNR/NBNS spoofer detection tool. LLMNR/NBNS requests sent by Conveigh are not legitimate requests to any enabled LLMNR/NBNS services. The requests will not result in name resolution in the event that a spoofer is present.
			* [Respounder](https://github.com/codeexpress/respounder)
				* Respounder sends LLMNR name resolution requests for made-up hostnames that do not exist. In a normal non-adversarial network we do not expect such names to resolve. However, a responder, if present in the network, will resolve such queries and therefore will be forced to reveal itself.
			* [asker](https://github.com/eavalenzuela/asker)
				* This tool takes a list of known-bogus local hostnames, and sends out LLMNR requests for them every 5-25 legitimate LLMNR requests from other hosts. This is intended for use by a blue team who wants to catch a red team or attacker using Responder, who either does not target-select carefully enough, or falls for the bogus hostnames which should be tailored to the environment (e.g. if there is a DC named "addc1", you might want to add "adddc1" to the list.
		* **Local Administrator Password Solution**
			* [Microsoft security advisory: Local Administrator Password Solution](https://support.microsoft.com/en-us/help/3062591/microsoft-security-advisory-local-administrator-password-solution-laps)
			* [Local Administrator Password Solution - technet](https://technet.microsoft.com/en-us/mt227395.aspx)
				* The "Local Administrator Password Solution" (LAPS) provides a centralized storage of secrets/passwords in Active Directory (AD) - without additional computers. Each organization’s domain administrators determine which users, such as helpdesk admins, are authorized to read the passwords.
			* [Introduction to Microsoft LAPS (Local Administrator Password Solution)](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
			* [Set up Microsoft LAPS (Local Administrator Password Solution) in Active Directory](Introduction to Microsoft LAPS (Local Administrator Password Solution) - 4sysops)(https://4sysops.com/archives/set-up-microsoft-laps-local-administrator-password-solution-in-active-directory/)
			* [FAQs for Microsoft Local Administrator Password Solution (LAPS) - Part 1 - 4sysops](https://4sysops.com/archives/faqs-for-microsoft-local-administrator-password-solution-laps/)
			* [FAQs for Microsoft Local Administrator Password Solution (LAPS) - Part 2 - 4sysops](https://4sysops.com/archives/part-2-faqs-for-microsoft-local-administrator-password-solution-laps/)
		* **Office Documents/Macros/DDE/Flavor-of-the-week**
			* [Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields](https://technet.microsoft.com/library/security/4053440)
			* [Disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b)
			* [New feature in Office 2016 can block macros and help prevent infection (2016)](https://cloudblogs.microsoft.com/microsoftsecure/2016/03/22/new-feature-in-office-2016-can-block-macros-and-help-prevent-infection/?source=mmpc)
			* [Block or unblock external content in Office documents - support.office](https://support.office.com/en-us/article/block-or-unblock-external-content-in-office-documents-10204ae0-0621-411f-b0d6-575b0847a795)
			* [CIRClean](http://circl.lu/projects/CIRCLean/#technical-details)
				* CIRCLean is an independent hardware solution to clean documents from untrusted (obtained) USB keys / USB sticks. The device automatically converts untrusted documents into a readable but disarmed format and stores these clean files on a trusted (user owned) USB key/stick.
				* [Github](https://github.com/CIRCL/Circlean)
			* [Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields - docs.ms](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440)
		* **Passwords**
			* [Domain Password Audit Tool (DPAT)](https://github.com/clr2of8/DPAT)
				* This is a python script that will generate password use statistics from password hashes dumped from a domain controller and a password crack file such as hashcat.potfile generated from the Hashcat tool during password cracking. The report is an HTML report with clickable links.
				* [Tutorial Video & Demo](https://www.blackhillsinfosec.com/webcast-demo-domain-password-audit-tool/)
			* [Azure AD and ADFS best practices: Defending against password spray attacks](https://cloudblogs.microsoft.com/enterprisemobility/2018/03/05/azure-ad-and-adfs-best-practices-defending-against-password-spray-attacks/)
			* [Detect Password Spraying With Windows Event Log Correlation](https://www.ziemba.ninja/?p=66)
		* **Privileged Access Workstation**
			* [How Microsoft IT used Windows 10 and Windows Server 2016 to implement privileged access workstations](https://myignite.microsoft.com/sessions/54896)
			* As part of the security strategy to protect administrative privilege, Microsoft recommends using a dedicated machine, referred to as PAW (privileged access workstation), for administrative tasks; and using a separate device for the usual productivity tasks such as Outlook and Internet browsing. This can be costly for the company to acquire machines just for server administrative tasks, and inconvenient for the admins to carry multiple machines. In this session, we show you how MSIT uses shielded VMs on the new release of Windows client to implement a PAW.
			* [Privileged Access Workstation(PAW) - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/10/13/privileged-access-workstationpaw/)
			* [PAW host buildout - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/10/17/paw-host-buildout/)
			* [How to deploy a VM template for PAW - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/11/01/how-to-create-a-vm-template-for-paw/)
		* **PowerShell**
			* [Automating security with PowerShell, Jaap Brasser (@Jaap_Brasser)](https://www.youtube.com/watch?v=WOC8vC2KoNs&index=12&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
				* There is no doubt that security has been in the spotlight over the last few years, recent events have been responsible for the increased demand for better and more secure systems. Security was often treated as an afterthought or something that could be implemented ‘later’. In this session, we will go over some best practices, using existing tools and frameworks to help you set up a more secure environment and to get a grasp of what is happening in your environment. We will leverage your existing automation skills to secure and automate these workflows. Expect a session with a lot of demos and resources that can directly be implemented.
				* [PowerShell ♥ the Blue Team](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)
			* [Powershell Security at Enterprise Customers - blogs.msdn](https://blogs.msdn.microsoft.com/daviddasneves/2017/05/25/powershell-security-at-enterprise-customers/)
			* [More Detecting Obfuscated PowerShell](http://www.leeholmes.com/blog/2016/10/22/more-detecting-obfuscated-powershell/)
			* [Revoke-Obfuscation - tool](https://github.com/danielbohannon/Revoke-Obfuscation)
				* PowerShell v3.0+ compatible PowerShell obfuscation detection framework.
			* [Revoke Obfuscation PowerShell Obfuscation Detection And Evasion Using Science Lee Holmes Daniel - Derbycon7 - talk](https://www.youtube.com/watch?v=7XnkDsOZM3Y&index=16&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
			* [PSRecon](https://github.com/gfoss/PSRecon/)
				* 🚀 PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
			* [Detecting and Preventing PowerShell Downgrade Attacks - leeholmes](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)
		* **SMB**
			* [SMB Security Best Practices - US CERT](https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices)
			* [SMB Packet Signing](https://technet.microsoft.com/en-us/library/cc180803.aspx)
			* [Secure SMB Connections](http://techgenix.com/secure-smb-connections/)
			* [Microsoft Security Advisory: Update to improve credentials protection and management: May 13, 2014](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a)
			* [Require SMB Security Signatures - technet.ms](https://technet.microsoft.com/en-us/library/cc731957.aspx)
			* [SMB 3.0 (Because 3 > 2) - David Kruse](http://www.snia.org/sites/default/orig/SDC2012/presentations/Revisions/DavidKruse-SMB_3_0_Because_3-2_v2_Revision.pdf)
		* **USB Detection**
			* [BEAMGUN](https://github.com/JLospinoso/beamgun)
				* A rogue-USB-device defeat program for Windows.
		* **Tools**
			* [Artillery](https://github.com/BinaryDefense/artillery)
				* Artillery is a combination of a honeypot, monitoring tool, and alerting system. Eventually this will evolve into a hardening monitoring platform as well to detect insecure configurations from nix systems.
		* **Visualization/Tracking/Reporting**
			* General
				* [Userline](https://github.com/THIBER-ORG/userline)
					* This tool automates the process of creating logon relations from MS Windows Security Events by showing a graphical relation among users domains, source and destination logons as well as session duration.
				* [VOYEUR](https://github.com/silverhack/voyeur)
					* VOYEUR's main purpose is to automate several tasks of an Active Directory build review or security assessment. Also, the tool is able to create a fast (and pretty) Active Directory report. The tool is developed entirely in PowerShell (a powerful scripting language) without dependencies like Microsoft Remote Administration tools. (Just .Net Framework 2.0 and Office Excel if you want a useful and pretty report). The generated report is a perfect starting point for well-established forensic, incident response team, security consultants or security researchers who want to quickly analyze threats in Active Directory Services.
		* **WMI**
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
	* **Advanced Threat Protection**
		* [Detecting reflective DLL loading with Windows Defender ATP - cloudblogs.ms](https://cloudblogs.microsoft.com/microsoftsecure/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/)
		* [WindowsDefenderATP-Hunting-Queries - MS's Github](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries)
			* Sample queries for Advanced hunting in Windows Defender ATP
		* [WindowsDefenderATP-Hunting-Queries](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries)
			* This repo contains sample queries for Advanced hunting on Windows Defender Advanced Threat Protection. With these sample queries, you can start to experience Advanced hunting, including the types of data that it covers and the query language it supports. You can also explore a variety of attack techniques and how they may be surfaced through Advanced hunting.
		* [Onboard non-Windows machines(ATP) - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/configure-endpoints-non-windows-windows-defender-advanced-threat-protection)
	* **Auditing Processes**
		* [Know your Windows Processes or Die Trying - sysforensics](https://sysforensics.org/2014/01/know-your-windows-processes/)
		* [TaskExplorer](https://objective-see.com/products/taskexplorer.html)
			* Explore all the tasks (processes) running on your Mac with TaskExplorer.
	* **Baselining**
		* [Measure Boot Performance with the Windows Assessment and Deployment Toolkit](https://blogs.technet.microsoft.com/mspfe/2012/09/19/measure-boot-performance-with-the-windows-assessment-and-deployment-toolkit/)
		* [Securing Windows Workstations: Developing a Secure Baseline](https://adsecurity.org/?p=3299)
		* [Evaluate Fast Startup Using the Assessment Toolkit](https://docs.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-1)
		* [Windows Performance Toolkit Reference](http://msdn.microsoft.com/en-us/library/windows/hardware/hh162945.aspx)
		* [The Malware Management Framework](https://www.malwarearchaeology.com/mmf/)
		* [Securing Windows Workstations: Developing a Secure Baselineadsecurity.org](https://adsecurity.org/?p=3299)
		* [ADRecon](https://github.com/sense-of-security/ADRecon)
			* ADRecon is a tool which extracts various artifacts (as highlighted below) out of an AD environment in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis. The report can provide a holistic picture of the current state of the target AD environment.  It can be run from any workstation that is connected to the environment, even hosts that are not domain members. Furthermore, the tool can be executed in the context of a non-privileged (i.e. standard domain user) accounts. Fine Grained Password Policy, LAPS and BitLocker may require Privileged user accounts. The tool will use Microsoft Remote Server Administration Tools (RSAT) if available, otherwise it will communicate with the Domain Controller using LDAP. 
	* **CMD.exe Analysis**
		* [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
			* Cmd.exe Command Obfuscation Generator & Detection Test Harness
	* **Credential Guard**
		* [Protect derived domain credentials with Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)
		* [Using a hypervisor to secure your desktop – Credential Guard in Windows 10 - blogs.msdn](https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/10/26/using-a-hypervisor-to-secure-your-desktop-credential-guard-in-windows-10/)
		* [Credential Guard lab companion - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/05/15/credential-guard-lab-companion/)
	* **Device Guard**
		* [Device Guard and Credential Guard hardware readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337)
		* [Introduction to Windows Defender Device Guard: virtualization-based security and Windows Defender Application Control - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies)
		* [Requirements and deployment planning guidelines for Windows Defender Device Guard - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/requirements-and-deployment-planning-guidelines-for-device-guard#hardware-firmware-and-software-requirements-for-device-guard)
		* [Driver compatibility with Device Guard in Windows 10 - docs.ms](https://blogs.msdn.microsoft.com/windows_hardware_certification/2015/05/22/driver-compatibility-with-device-guard-in-windows-10/)
	* **Event Log & Monitoring**
		* **General**
			* [Windows Security Log Events - ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
			* [Windows Event Logs Zero to Hero Nate Guagenti Adam Swan - Bloomcon2017](https://www.youtube.com/watch?v=H3t_kHQG1Js)
			* [Auditing Security Events - WCF - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/auditing-security-events)
		* **Event Forwarding**
			* [Windows Event Forwarding Guidance](https://github.com/palantir/windows-event-forwarding) 
				* Over the past few years, Palantir has a maintained an internal Windows Event Forwarding (WEF) pipeline for generating and centrally collecting logs of forensic and security value from Microsoft Windows hosts. Once these events are collected and indexed, alerting and detection strategies (ADS) can be constructed not only on high-fidelity security events (e.g. log deletion), but also for deviations from normalcy, such as unusual service account access, access to sensitive filesystem or registry locations, or installation of malware persistence. The goal of this project is to provide the necessary building blocks for organizations to rapidly evaluate and deploy WEF to a production environment, and centralize public efforts to improve WEF subscriptions and encourage adoption. While WEF has become more popular in recent years, it is still dramatically underrepresented in the community, and it is our hope that this project may encourage others to adopt it for incident detection and response purposes. We acknowledge the efforts that Microsoft, IAD, and other contributors have made to this space and wish to thank them for providing many of the subscriptions, ideas, and techniques that will be covered in this post.
		* **Tools**
			* [DCSYNCMonitor](https://github.com/shellster/DCSYNCMonitor)
				* Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.
	* **Firewall**
		* [Endpoint Isolation with the Windows Firewall - Dane Stuckey](https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb)
	* **General Hardening**
		* **General**
			* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
				* A curated list of awesome Security Hardening techniques for Windows.
		* **Documentation**
		* **Guides**
			* [Enable Attack surface reduction(Win10)- docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction)
			* [Harden windows IP Stack](https://www.reddit.com/r/netsec/comments/2sg80a/how_to_harden_windowsiis_ssltls_configuration/)
			* [Secure Host Baseline](https://github.com/iadgov/Secure-Host-Baseline)
				* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
			* [Windows Server guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=149b9032665345ba890ba51d3bf0d519&fl=4&uid=150127534&nid=244%20281088008)
		* **Educational/Informative**
			* [The Evolution of Protected Processes – Part 1: Pass-the-Hash Mitigations in Windows 8.1](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)
			* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.crowdstrike.com/blog/evolution-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and/) 
			* [Protected Processes Part 3: Windows PKI Internals (Signing Levels, Scenarios, Signers, Root Keys, EKUs & Runtime Signers)](https://www.crowdstrike.com/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)
			* [Mitigate threats by using Windows 10 security features](https://docs.microsoft.com/en-us/windows/threat-protection/overview-of-threat-mitigations-in-windows-10)
	* **Powershell**
		* **Analysis**
			* [Powershell Download Cradles - Matthew Green](https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html)
			* [pOWershell obFUsCation - N1CFURY](https://n1cfury.com/ps-obfuscation/)
			* [PowerShell Injection Hunter: Security Auditing for PowerShell Scripts - blogs.msdn](https://blogs.msdn.microsoft.com/powershell/2018/08/03/powershell-injection-hunter-security-auditing-for-powershell-scripts/)
		* **Logging**
		* **Talks/Presentations**
			* [Defending against PowerShell attacks - in theory, and in practice by Lee holmes](https://www.youtube.com/watch?v=M5bkHUQy-JA&feature=youtu.be)
	* **Service Accounts**
		* [Service Account best practices Part 1: Choosing a Service Account](https://4sysops.com/archives/service-account-best-practices-part-1-choosing-a-service-account/)
			* In this article you will learn the fundamentals of Windows service accounts. Specifically, we discover the options and best practices concerning the selection of a service account for a particular service application.
		* [Service Account best practices - Part 2: Least Privilege implementation](https://4sysops.com/archives/service-account-best-practices-part-2-least-privilege-implementation/)
			* In this article you will learn some best-practice suggestions for using service applications according to the IT security rule of least privilege.
		* [Best Practice: Securing Windows Service Accounts and Privileged Access – Part 1 - SecurIT360](https://www.securit360.com/blog/best-practice-service-accounts/)
		* [Best Practice: Securing Windows Service Accounts and Privileged Access – Part 2 - SecurIT360](https://www.securit360.com/blog/best-practice-service-accounts-p2/)
