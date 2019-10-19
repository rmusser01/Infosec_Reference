# Defense


## Table of Contents

* **To-Do**
	* User Awareness training
	* Objective-See Tools
	* Cred defense
	* SPA 
	* Azure stuff
	* AWS Stuff
	* GCP Stuff



----------------------------
### Defense & Hardening
* **101**
	* [Center for Internet Security](https://www.cisecurity.org/)
		* [CIS Top 20 Controls](https://www.cisecurity.org/controls/cis-controls-list/)
		* [CIS Benchmark Guides](https://www.cisecurity.org/cis-benchmarks/)
		* [AuditScripts - CIS Critical Security Controls](https://www.auditscripts.com/free-resources/critical-security-controls/)
* **General Concepts**
	* **Zero-Trust Networks**
		* [BeyondCorp - Google](https://cloud.google.com/beyondcorp/)
		* [Securing Privileged Access Reference Material - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material)
* **Access Control** <a name="acl"></a>
	* [Capirca](https://github.com/google/capirca)
		* Capirca is a tool designed to utilize common definitions of networks, services and high-level policy files to facilitate the development and manipulation of network access control lists (ACLs) for various platforms. It was developed by Google for internal use, and is now open source.
* **Amazon AWS** <a name="aws"></a>
	* **AWS**
		* [The Open Guide to Amazon Web Services](https://github.com/open-guides/og-aws)
			* A lot of information on AWS is already written. Most people learn AWS by reading a blog or a “getting started guide” and referring to the standard AWS references. Nonetheless, trustworthy and practical information and recommendations aren’t easy to come by. AWS’s own documentation is a great but sprawling resource few have time to read fully, and it doesn’t include anything but official facts, so omits experiences of engineers. The information in blogs or Stack Overflow is also not consistently up to date. This guide is by and for engineers who use AWS. It aims to be a useful, living reference that consolidates links, tips, gotchas, and best practices. It arose from discussion and editing over beers by several engineers who have used AWS extensively.
	* **Lambda**
		* [AWS Lambda - IAM Access Key Disabler](https://github.com/te-papa/aws-key-disabler)
			* The AWS Key disabler is a Lambda Function that disables AWS IAM User Access Keys after a set amount of time in order to reduce the risk associated with old access keys.
	* **S3**
		* [Amazon S3 Bucket Public Access Considerations](https://aws.amazon.com/articles/5050)
* **Blue team Tactics** <a name="antired"></a>
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
	* [OpenSnitch](https://github.com/evilsocket/opensnitch)
		* OpenSnitch is a GNU/Linux port of the Little Snitch application firewall
* **(General) Hardening** <a name="hardening"></a>
	* **101**
		* [Why Does the Penetration Testing Team Hate Me? - Ryan Oberfelder](https://medium.com/@ryoberfelder/why-does-the-penetration-testing-team-hate-me-67a981c5e10c)
	* **Guides**
		* [ERNW Repository of Hardening Guides](https://github.com/ernw/hardening)
		* [OWASP Secure Configuration Guide](https://www.owasp.org/index.php/Secure_Configuration_Guide)
		* [PHP Secure Configuration Checker](https://github.com/sektioneins/pcc)
		* [Security + DevOps Automatic Server Hardening - dev-sec.io](http://dev-sec.io/)
			* Open Source Automated Hardening Framework
		* [YubiKey-Guide](https://github.com/drduh/YubiKey-Guide)
			* This is a practical guide to using YubiKey as a SmartCard for storing GPG encryption and signing keys.
	* **SSH**
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
	* [What is conditional access in Azure Active Directory? - docs.ms](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview)
	* [Detecting Kerberoasting activity using Azure Security Center - Moti Bani](https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/)
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
	* **Application Whitelisting**
		* [Santa](https://github.com/google/santa)
			* Santa is a binary whitelisting/blacklisting system for macOS. It consists of a kernel extension that monitors for executions, a userland daemon that makes execution decisions based on the contents of a SQLite database, a GUI agent that notifies the user in case of a block decision and a command-line utility for managing the system and synchronizing the database with a server.
			* [Docs](https://github.com/google/santa/tree/master/Docs)	* **Tools**
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
* **Phishing** <a name="phishing"></a>
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
* **Ransomware** <a name="ransomware"></a>
	* [Decryptonite](https://github.com/DecryptoniteTeam/Decryptonite)
		* Decryptonite is a tool that uses heuristics and behavioural analysis to monitor for and stop ransomware.
* **User Awareness Training** <a name="uat"></a>
* **Web Browsers**
	* **Extensions**
		* [Inventory-BrowserExts - keyboardcrunch](https://github.com/keyboardcrunch/Inventory-BrowserExts)
			* This script can inventory Firefox and/or Chrome extensions for each user from a list of machines. It returns all the information back in a csv file and prints to console a breakdown of that information.
	* **User-Profiling**
		* [Browser fingerprints for a more secure web - Julien Sobrier & Ping Yan(OWASP AppSecCali2019)](https://www.youtube.com/watch?v=P_nYYsaVi1w&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=30&t=0s)
* **Web Servers**
	* [Apache and Let's Encrypt Best Practices for Security - aaronhorler.com](https://aaronhorler.com/articles/apache.html)
	* [Security/Server Side TLS - Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS)
		* The goal of this document is to help operational teams with the configuration of TLS. All Mozilla websites and deployments should follow the recommendations below. Mozilla maintains this document as a reference guide for navigating the TLS landscape, as well as a configuration generator to assist system administrators. Changes are reviewed and merged by the Mozilla Operations Security and Enterprise Information Security teams.
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
* **Windows** <a name="windows"></a>
	* **General**
		* [Windows Firewall Hook Enumeration](https://www.nccgroup.com/en/blog/2015/01/windows-firewall-hook-enumeration/)
			* We’re going to look in detail at Microsoft Windows Firewall Hook drivers from Windows 2000, XP and 2003. This functionality was leveraged by the Derusbi family of malicious code to implement port-knocking like functionality. We’re going to discuss the problem we faced, the required reverse engineering to understand how these hooks could be identified and finally how the enumeration tool was developed.
		* [Detecting DLL Hijackingon Windows](http://digital-forensics.sans.org/blog/2015/03/25/detecting-dll-hijacking-on-windows/)
		* [The Effectiveness of Tools in Detecting the 'Maleficent Seven' Privileges in the Windows Environment](https://www.sans.org/reading-room/whitepapers/sysadmin/effectiveness-tools-detecting-039-maleficent-seven-039-privileges-windows-environment-38220)
		* [Windows DACL Enum Project](https://github.com/nccgroup/WindowsDACLEnumProject)
			* A collection of tools to enumerate and analyse Windows DACLs
		* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It - labofapenetrationtester](http://www.labofapenetrationtester.com/2016/09/amsi.html)
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
	* **Active Directory**
		* [What would a real hacker do to your Active Directory](https://www.youtube.com/watch?v=DH3v8bO-NCs)
		* [Securing Microsoft Active Directory Federation Server (ADFS)](https://adsecurity.org/?p=3782)
		* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening/blob/master/README.md)
		* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them - adsecurity](https://adsecurity.org/?p=1684)
		* [Beyond Domain Admins – Domain Controller & AD Administration - ADSecurity.org](https://adsecurity.org/?p=3700)
			* This post provides information on how Active Directory is typically administered and the associated roles & rights.
		* **Adversary Resilience Methodology**
			* [Introducing the Adversary Resilience Methodology — Part One - specterops](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
			* [Introducing the Adversary Resilience Methodology — Part Two](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
			* [BloodHound and the Adversary Resilience Model](https://docs.google.com/presentation/d/14tHNBCavg-HfM7aoeEbGnyhVQusfwOjOyQE1_wXVs9o/mobilepresent#slide=id.g35f391192_00)
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
		* **Enhanced Security Administrative Environment(ESAE)/Red Foreset**
			* **ESAE**
				* [Understanding “Red Forest”: The 3-Tier Enhanced Security Admin Environment (ESAE) and Alternative Ways to Protect Privileged Credentials - ultimatewindowsecurity](https://www.ultimatewindowssecurity.com/webinars/register.aspx?id=1409)
				* [Active Directory - ESAE Model - Huy Kha](https://www.slideshare.net/HuyKha2/active-directory-esae-model-149736364)
			* **Red Forest**
				* [What is Active Directory Red Forest Design? - social.technet.ms](https://social.technet.microsoft.com/wiki/contents/articles/37509.what-is-active-directory-red-forest-design.aspx)
				* [Planting the Red Forest: Improving AD on the Road to ESAE - Jacques Louw and Katie Knowles](https://www.mwrinfosecurity.com/our-thinking/planting-the-red-forest-improving-ad-on-the-road-to-esae/)
				* [How Microsoft Red Forest improves Active Directory Security - Bryan Patton](https://www.quest.com/community/quest/microsoft-platform-management/b/microsoft-platform-management-blog/posts/how-microsoft-red-forest-improves-active-directory-security)
		* **AppLocker**
			* [Script Rules in AppLocker - technet](https://technet.microsoft.com/en-us/library/ee460958.aspx)
			* [DLL Rules in AppLocker](https://technet.microsoft.com/en-us/library/ee460947.aspx)
			* [Application Whitelisting Using Microsoft AppLocker](https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)
			* [Harden Windows with AppLocker – based on Case study Part 1 - oddvar.moe](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
			* [Harden Windows with AppLocker – based on Case study part 2 - oddvar.moe](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
			* [AppLocker Case study: How insecure is it really? Part 1 oddvar.moe](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-1/)
			* AppLocker Case study: How insecure is it really? Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
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
		* **KRBTGT**
			* [Kerberos & KRBTGT: Active Directory’s Domain Kerberos Service Account - adsecurity.org](https://adsecurity.org/?p=483)
			* [KRBTGT Account Password Reset Scripts now available for customers - Tim Rains(Ms.com)](https://www.microsoft.com/security/blog/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/)
			* [AD Forest Recovery - Resetting the krbtgt password - docs.ms](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password)
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
		* **NTLM**
			* [Using security policies to restrict NTLM traffic - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/jj865668(v=ws.10))
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
		* **PowerShell**
			* **Articles/Blogposts/Writeups**
				* [PowerShell ♥ the Blue Team](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)
				* [Powershell Security at Enterprise Customers - blogs.msdn](https://blogs.msdn.microsoft.com/daviddasneves/2017/05/25/powershell-security-at-enterprise-customers/)
				* [More Detecting Obfuscated PowerShell](http://www.leeholmes.com/blog/2016/10/22/more-detecting-obfuscated-powershell/)
				* [Detecting and Preventing PowerShell Downgrade Attacks - leeholmes](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)
				* [Creating a Secure Environment using PowerShell Desired State Configuration - blogs.ms](https://blogs.msdn.microsoft.com/powershell/2014/07/21/creating-a-secure-environment-using-powershell-desired-state-configuration/)
			* **Talks & Presentations**
				* [Hijacking .NET to Defend PowerShell - Amanda Rousseau(BSidesSF 2017)](https://www.youtube.com/watch?v=YXjIVuX6zQk)
				* [Automating security with PowerShell, Jaap Brasser (@Jaap_Brasser)](https://www.youtube.com/watch?v=WOC8vC2KoNs&index=12&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
					* There is no doubt that security has been in the spotlight over the last few years, recent events have been responsible for the increased demand for better and more secure systems. Security was often treated as an afterthought or something that could be implemented ‘later’. In this session, we will go over some best practices, using existing tools and frameworks to help you set up a more secure environment and to get a grasp of what is happening in your environment. We will leverage your existing automation skills to secure and automate these workflows. Expect a session with a lot of demos and resources that can directly be implemented.
			* **Tools**
				* [Revoke-Obfuscation - tool](https://github.com/danielbohannon/Revoke-Obfuscation)
					* PowerShell v3.0+ compatible PowerShell obfuscation detection framework.
				* [Revoke Obfuscation PowerShell Obfuscation Detection And Evasion Using Science Lee Holmes Daniel - Derbycon7 - talk](https://www.youtube.com/watch?v=7XnkDsOZM3Y&index=16&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
				* [PSRecon](https://github.com/gfoss/PSRecon/)
					* 🚀 PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
		* **Services**
			* [How to Allow Non-Admin Users to Start/Stop Windows Service - woshub.com](http://woshub.com/set-permissions-on-windows-service/)
		* **SMB**
			* [SMB Security Best Practices - US CERT](https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices)
			* [SMB Packet Signing](https://technet.microsoft.com/en-us/library/cc180803.aspx)
			* [Secure SMB Connections](http://techgenix.com/secure-smb-connections/)
			* [Microsoft Security Advisory: Update to improve credentials protection and management: May 13, 2014](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a)
			* [Require SMB Security Signatures - technet.ms](https://technet.microsoft.com/en-us/library/cc731957.aspx)
			* [SMB 3.0 (Because 3 > 2) - David Kruse](http://www.snia.org/sites/default/orig/SDC2012/presentations/Revisions/DavidKruse-SMB_3_0_Because_3-2_v2_Revision.pdf)
		* **Unwanted Admins**
			* [Where have all the Domain Admins gone? Rooting out Unwanted Domain Administrators - Rob VandenBrink](https://isc.sans.edu/diary/Where+have+all+the+Domain+Admins+gone%3F++Rooting+out+Unwanted+Domain+Administrators/24874)
		* **USB Detection**
			* [BEAMGUN](https://github.com/JLospinoso/beamgun)
				* A rogue-USB-device defeat program for Windows.
			* [How to Analyze USB Device History in Windows - magnetforensics.com](https://www.magnetforensics.com/computer-forensics/how-to-analyze-usb-device-history-in-windows/)
			* [How to track down USB flash drive usage with Windows 10's Event Viewer - techrepublic](https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/)
		* **Tools**
			* [Artillery](https://github.com/BinaryDefense/artillery)
				* Artillery is a combination of a honeypot, monitoring tool, and alerting system. Eventually this will evolve into a hardening monitoring platform as well to detect insecure configurations from nix systems.
			* [zBang](https://github.com/cyberark/zBang)
				* zBang is a special risk assessment tool that detects potential privileged account threats in the scanned network.
				* [Blogpost](https://www.cyberark.com/threat-research-blog/the-big-zbang-theory-a-new-open-source-tool/)
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
	* **Advanced Threat Analytics**
		* [Best Practices for Securing Advanced Threat Analytics - techcommunity.ms](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Best-Practices-for-Securing-Advanced-Threat-Analytics/ba-p/249848)
		* [Microsoft Advanced Threat Analytics – My best practices - Oddvar Moe](https://msitpros.com/?p=3509)
		* [ATA readiness roadmap - docs.ms](https://docs.microsoft.com/en-us/advanced-threat-analytics/ata-resources)
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
	* **Defender Application Control**
		* [Planning and getting started on the Windows Defender Application Control deployment process - docs.ms](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-deployment-guide)
			* This topic provides a roadmap for planning and getting started on the Windows Defender Application Control (WDAC) deployment process, with links to topics that provide additional detail. Planning for WDAC deployment involves looking at both the end-user and the IT pro impact of your choices.
	* **Event Log & Monitoring**
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
	* **Firewall**
		* [Endpoint Isolation with the Windows Firewall - Dane Stuckey](https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb)
	* **General Hardening**
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
		* **Educational/Informative**
			* [The Evolution of Protected Processes – Part 1: Pass-the-Hash Mitigations in Windows 8.1](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)
			* [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.crowdstrike.com/blog/evolution-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and/) 
			* [Protected Processes Part 3: Windows PKI Internals (Signing Levels, Scenarios, Signers, Root Keys, EKUs & Runtime Signers)](https://www.crowdstrike.com/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)
			* [Mitigate threats by using Windows 10 security features](https://docs.microsoft.com/en-us/windows/threat-protection/overview-of-threat-mitigations-in-windows-10)
	* **.NET Instrumentation**
		* [ClrGuard](https://github.com/endgameinc/ClrGuard)
			* ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes. ClrGuard leverages a simple appInit DLL (ClrHook32/64.dll) in order to load into all CLR/.NET processes. From there, it performs an in-line hook of security critical functions. Currently, the only implemented hook is on the native LoadImage() function. When events are observed, they are sent over a named pipe to a monitoring process for further introspection and mitigation decision.
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
* **Vulnerability Management**
	* **101**
        * US-CERT VulnMGMT FAQ: https://www.us-cert.gov/cdm/capabilities/vuln
        * The Five Stages of Vulnerability Management(tripwire) - https://www.tripwire.com/state-of-security/vulnerability-management/the-five-stages-of-vulnerability-management/
        * SANS - Implementing a Vulnerability Management Process: https://www.sans.org/reading-room/whitepapers/threats/implementing-vulnerability-management-process-34180
        * Building a Model for Endpoint Security Maturity: https://www.tripwire.com/state-of-security/vulnerability-management/building-a-model-for-endpoint-security-maturity/
    * **Articles/Blogposts/Writeups**
	    * [Vulnerability Management Program Best Practices – Irfahn Khimji](https://www.tripwire.com/state-of-security/vulnerability-management/vulnerability-management-program-best-practices-part-1/)
		* [The Five Stages of Vulnerability Management - Irfahn Khimji](https://www.tripwire.com/state-of-security/vulnerability-management/the-five-stages-of-vulnerability-management/)
		* [Building a VulnerabilityManagement Program: A project management approach - Wylie Shanks(2015)](https://www.sans.org/reading-room/whitepapers/projectmanagement/building-vulnerability-management-program-project-management-approach-35932)
    		* Abstract: This paper examines the critical role of project management in building a successful vulnerability management program. This paper outlines how organizational risk and regulatory compliance needs can be addressed through a "Plan-Do-Check-Act" approach to a vulnerability management program.
	* **Identifying Assets**
		* [PowerShell: Documenting your environment by running systeminfo on all Domain-Computers - Patrick Gruenauer](https://sid-500.com/2017/08/09/powershell-documenting-your-environment-by-running-systeminfo-on-all-domain-computers/)
		* [A Faster Way to Identify High Risk Windows Assets - Scott Sutherland](https://blog.netspi.com/a-faster-way-to-identify-high-risk-windows-assets/)
			* "In this blog I took a quick look at how common Active Directory mining techniques used by the pentest community can also be used by the blue teams to reduce the time it takes to identify high risk Windows systems in their environments."
    * **Measuring Maturity**
        * Vulnerability Management Maturity Models – Trip Wire: https://traviswhitney.com/2016/05/02/vulnerability-management-maturity-models-trip-wire/
        * Capability Maturity Model(Wikipedia): https://en.wikipedia.org/wiki/Capability_Maturity_Model
    * **Nessus**
	    * [Nessus v2 xml report format - Alex Leonov](https://avleonov.com/2016/08/02/nessus-v2-xml-report-format/)
		* [Parsing Nessus v2 XML reports with python - Alex Leonov](https://avleonov.com/2017/01/25/parsing-nessus-v2-xml-reports-with-python/)
		* [Read .nessus file into Excel (with Power Query) - Johan Moritz](https://www.verifyit.nl/wp/?p=175591)
		* [Nessus v2 File Format - Tenable](https://static.tenable.com/documentation/nessus_v2_file_format.pdf)
    * **Talks & Presentations**
	    * [SANS Webcast: Beyond Scanning Delivering Impact Driven Vulnerability Assessments - Matthew Toussain](https://www.youtube.com/watch?v=-ObkJ03UcN0)
    * **CVSS-related**
        * Towards Improving CVSS - CMU SEI: https://resources.sei.cmu.edu/asset_files/WhitePaper/2018_019_001_538372.pdf
        * When CVSS Fits and When it Doesn’t(NCC Group): https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/may/when-cvss-fits-and-when-it-doesnt/
        * Don’t Substitute CVSS for Risk: Scoring System Inflates Importance of CVE-2017-3735: https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/dont-substitute-cvss-for-risk-scoring-system-inflates-importance-of-cve-2017-3735/
        * Microsoft Exploitability Index: https://www.microsoft.com/en-us/msrc/exploitability-index?rtc=1
		* [Towards Improving CVSS - J.M. Spring, E. Hatleback, A. Householder, A. Manion, D. Shick - CMU](https://resources.sei.cmu.edu/asset_files/WhitePaper/2018_019_001_538372.pdf)

### Sort

* [Windows ISV Software Security Defenses - msdn](https://msdn.microsoft.com/en-us/library/bb430720.aspx)
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/ee791851(v=ws.11)
* [DevSec Hardening Framework](https://github.com/dev-sec)

AuditD
	* [A Linux Auditd rule set mapped to MITRE's Attack Framework](https://github.com/bfuzzy/auditd-attack)
* [Disrupting the KillChain - Amanda Berlin](https://docs.google.com/spreadsheets/d/1J0swcA1Phb4mh-Pj8eR9ZEAIm5GEtz0UklP9YhVUbEY/edit#gid=0)

* [Assess your data potential with ATTACK Datamap - Olaf Hartong](https://medium.com/@olafhartong/assess-your-data-potential-with-att-ck-datamap-f44884cfed11)

* [Designing Security for Billions - Facebook](https://newsroom.fb.com/news/2019/01/designing-security-for-billions/)

* [Security Fun: Bloodhound, MS16-072 and GPO Discoverability - Darren Mar-Elia](https://sdmsoftware.com/group-policy-blog/security-related/security-fun-bloodhound-ms16-072-gpo-discoverability/)
* [BloodHound From Red to Blue - Mathieu Saulnier(BSides Charm2019)](https://www.youtube.com/watch?v=UWY772iIq_Y)

ATP
	* https://docs.microsoft.com/en-us/windows-server/get-started-19/whats-new-19
	* https://www.microsoft.com/en-us/WindowsForBusiness/windows-atp?ocid=docs-mssp-support-abovefoldlink
https://i.blackhat.com/USA-19/Thursday/us-19-Smith-Fantastic-Red-Team-Attacks-And-How-To-Find-Them.pdf

Active Directory
	* [Weaponizing Active Directory - David Fletcher](https://www.youtube.com/watch?v=vLWGJ3f3-gI&feature=youtu.be)
		* This webcast covers basic techniques to catch attackers attempting lateral movement and privilege escalation within your environment with the goal of reducing that Mean Time to Detect (MTTD) metric. Using tactical deception, we will lay out strategies to increase the odds that an attacker will give away their presence early after initial compromise.
	* [Improving the Security of Authentication in an AD DS Domain(2011) - Dan Holme, Jason Kellington, Danielle Ruest, Nelson Ruest](https://www.microsoftpressstore.com/articles/article.aspx?p=2224364&seqNum=2)
	* [Designing a Multilayered, In-Depth Defense Approach to AD Security - Quest.com](https://www.quest.com/docs/designing-a-multilayered-in-depth-defense-approach-to-ad-security-white-paper-22453.pdf)
	* [Get rid of accounts that use Kerberos Unconstrained Delegation - Willem Kasdorp(blogs.technet)](https://blogs.technet.microsoft.com/389thoughts/2017/04/18/get-rid-of-accounts-that-use-kerberos-unconstrained-delegation/)
	* [ADTIMELINE – Active Directory Forensics With Replication Metadata at the First Technical Colloqium](https://www.ssi.gouv.fr/en/actualite/adtimeline-active-directory-forensics-with-replication-metadata-at-the-first-technical-colloquium/)
	* [New features in Active Directory Domain Services in Windows Server 2012, Part 11: Kerberos Armoring (FAST) - Sander Berkouwer](https://dirteam.com/sander/2012/09/05/new-features-in-active-directory-domain-services-in-windows-server-2012-part-11-kerberos-armoring-fast/)
	* [ADSVS v1.0 - Improving the security of Active Directory - Huy Kha](https://www.slideshare.net/HuyKha2/adsvs-v10-improving-the-security-of-active-directory)
	* [Designing a Multilayered, In-Depth Defense Approach to AD Security - Quest](https://www.quest.com/docs/designing-a-multilayered-in-depth-defense-approach-to-ad-security-white-paper-22453.pdf)
	* [Protect your enterprise data using Windows Information Protection (WIP) - docs.ms](https://docs.microsoft.com/en-us/windows/security/information-protection/windows-information-protection/protect-enterprise-data-using-wip)
	* [Security WatchLock Up Your Domain Controllers - Steve Riley - docs.ms](https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc160936(v=msdn.10))
	* https://www.tarlogic.com/en/blog/how-to-attack-kerberos/
	* https://github.com/infosecn1nja/AD-Attack-Defense
	* https://www.youtube.com/watch?v=lJQn06QLwEw&app=desktop
	* https://decentsecurity.com/enterprise/#/real-world-wsus/
	* https://docs.microsoft.com/en-us/windows/client-management/mdm/
	* https://docs.microsoft.com/en-us/advanced-threat-analytics/working-with-suspicious-activities
	* https://docs.microsoft.com/en-us/advanced-threat-analytics/suspicious-activity-guide
	* https://docs.microsoft.com/en-us/advanced-threat-analytics/working-with-ata-console#sensitive-groups
	* https://docs.microsoft.com/en-us/advanced-threat-analytics/ata-architecture
	* http://www.irongeek.com/i.php?page=videos/grrcon2018/grrcon-2018-lovelace10-red-vs-blue-the-untold-chapter-aaron-herndon-thomas-somerville
	* https://www.pingcastle.com/methodology/
	* https://room362.blogspot.com/2015/09/using-domain-controller-account.html
	* https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
	* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a
	* http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html
	* https://blog.netspi.com/machineaccountquota-is-useful-sometimes/
	* https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/
	* https://github.com/Kevin-Robertson/Powermad
	* https://rohnspowershellblog.wordpress.com/2013/04/13/modifying-service-acls/
	* https://blog.netspi.com/exploiting-adidns/

* [New feature in Office 2016 can block macros and help prevent infection](https://web.archive.org/web/20180527161910/https://cloudblogs.microsoft.com/microsoftsecure/2016/03/22/new-feature-in-office-2016-can-block-macros-and-help-prevent-infection/?source=mmpc)
* [Defensive Coding Strategies for a High-Security Environment - Matt Graeber - PowerShell Conference EU 2017](https://www.youtube.com/watch?reload=9&v=O1lglnNTM18)
* [Windows 10 Security Checklist Starter Kit - itprotoday](https://www.itprotoday.com/industry-perspectives/windows-10-security-checklist-starter-kit)

* [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)

* [ERNW Repository of Hardening Guides](https://github.com/ernw/hardening)
	* This repository contains various hardening guides compiled by ERNW for various purposes. Most of those guides strive to provide a baseline level of hardening and may lack certain hardening options which could increase the security posture even more (but may have impact on operations or required operational effort).

* [Application Whitelist Auditor - 	airlockdigital](https://www.airlockdigital.com/application-whitelisting-auditor/)

* [iconSimple Software-Restriction Policy - iwrconsultancy](https://iwrconsultancy.co.uk/softwarepolicy)

* [Recon by Fire](https://github.com/HewlettPackard/reconbf)
	* Recon is a tool for reviewing the security configuration of a local system. It can detect existing issues, known-insecure settings, existing strange behaviour, and options for further hardening. Recon can be used in existing systems to find out which elements can be improved and can provide some information about why the change is recommended. It can also be used to scan prepared system images to verify that they contain the expected protection.

* [Stored passwords found all over the place after installing Windows in company networks :( - Sami Laiho](http://blog.win-fu.com/2017/08/stored-passwords-found-all-over-place.html)

* [Protect Yourself From Malicious PKI Administrator – Role Separation In PKI - Paula Januszkiewicz](https://cqureacademy.com/blog/securing-infrastructure/role-separation-pki)
* [Cost Effective Drone Detection - Alex Farrant](https://www.contextis.com/en/blog/cost-effective-drone-detection)

https://www.slideshare.net/HuyKha2/adsvs-v10-improving-the-security-of-active-directory
https://www.slideshare.net/HuyKha2/adstg-v20-guidance
https://www.slideshare.net/HuyKha2/iam-policy-ad
https://www.slideshare.net/HuyKha2/delegate-backup-important-stuff-in-active-directory
https://support.microsoft.com/en-us/help/4020089/windows-10-in-s-mode-faq
https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/All-your-creds-are-belong-to-us/ba-p/855124
* [Disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b)

* [Project Phinn](https://github.com/duo-labs/phinn)
	* A toolkit to generate an offline Chrome extension to detect phishing attacks using a bespoke convolutional neural network.
* [IsThisLegit?](https://github.com/duo-labs/isthislegit)
	* IsThisLegit is a dashboard and Chrome extension that makes it easy to receive, analyze, and respond to phishing reports.

* [How to grill Malicious Macros - SSTIC15 - Decalage](https://decalage.info/en/sstic15)
* [Applied Machine Learning: Defeating Modern Malicious Documents](https://www.youtube.com/embed/ZAuCEgA3itI?enablejsapi=1&modestbranding=1&disablekb=1&rel=0)
* [MacroMilter](https://github.com/sbidy/MacroMilter)
	* This python based milter (mail-filter) checks an incoming mail for suspicious VBA macro code in MS 20xx Office attachments (doc, xls, ppt ...).
* [MaliciousMacroBot](https://github.com/egaus/MaliciousMacroBot)

* [Hunting for evil: detect macros being executed - Pieter Ceelen](https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/)