# Defense

## In Progress

## Table of Contents
* [Amazon S3](#s3)
* [Application Whitelisting](#whitelist)
* [AppSec](#appsec)
* [Attack Surface Analysis/Reduction](#asa)
* [Auditing Account Passwords/Privileges](#aapp)
* [Auditing Processes](#ap)
* [Baselining](#baseline)
* [Hardening](#harden)
* [Leaks](#leak)
* [Linux/Unix](#linux)
* [Malicious USB](#malusb)
* [Network](#network)
* [OS X](#osx)
* [Ransomware](#ransom)
* [Web](#web)
* [WAF(#waf)
* [Windows](#windows)
* [Powershell](#powershell)

### Sort
* [limacharlie](https://github.com/refractionpoint/limacharlie)
	* Endpoint monitoring stack.

* [Aktaion: Open Source Tool For "Micro Behavior Based" Exploit Detection and Automated GPO Policy Generation](https://github.com/jzadeh/Aktaion)
	* Aktaion is a lightweight JVM based project for detecting exploits (and more generally attack behaviors). The project is meant to be a learning/teaching tool on how to blend multiple security signals and behaviors into an expressive framework for intrusion detection. The cool thing about the project is it provides an expressive mechanism to add high level IOCs (micro beahviors) such as timing behavior of a certain malware family.

https://blogs.technet.microsoft.com/srd/2015/02/10/ms15-011-ms15-014-hardening-group-policy/
* [Second section good resource for hardening windows](http://labs.bitdefender.com/2014/11/do-your-bit-to-limit-cryptowall/)
* [Windows ISV Software Security Defenses - msdn](https://msdn.microsoft.com/en-us/library/bb430720.aspx)
* [Common misconfigurations that lead to a breach - Justin Tharpe](https://www.youtube.com/watch?v=fI3mycr5cPg)
* [Mitigate threats by using Windows 10 security features](https://docs.microsoft.com/en-us/windows/threat-protection/overview-of-threat-mitigations-in-windows-10)
* [Real Incidents:Real Solutions - evil.plumbing](https://evil.plumbing/Current-version-June.pdf)
* [Securi-Tay 2017 - Advanced Attack Detection](https://www.youtube.com/watch?v=ihElrBBJQo8)
* [Windows Commands Abused by Attackers](http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html)
* [SANS Institute Security Consensus Operational Readiness Evaluation](https://www.sans.org/media/score/checklists/LinuxCheatsheet_2.pdf)
* [Windows Server guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=149b9032665345ba890ba51d3bf0d519&fl=4&uid=150127534&nid=244%20281088008)
* [Security Guide for Developers](https://github.com/FallibleInc/security-guide-for-developers)
* [Using an Expanded Cyber Kill Chain Model to Increase Attack Resiliency - Sean Malone - BHUSA16](https://www.youtube.com/watch?v=1Dz12M7u-S8)
	* We'll review what actions are taken in each phase, and what's necessary for the adversary to move from one phase to the next. We'll discuss multiple types of controls that you can implement today in your enterprise to frustrate the adversary's plan at each stage, to avoid needing to declare "game over" just because an adversary has gained access to the internal network. The primary limiting factor of the traditional Cyber Kill Chain is that it ends with Stage 7: Actions on Objectives, conveying that once the adversary reaches this stage and has access to a system on the internal network, the defending victim has already lost. In reality, there should be multiple layers of security zones on the internal network, to protect the most critical assets. The adversary often has to move through numerous additional phases in order to access and manipulate specific systems to achieve his objective. By increasing the time and effort required to move through these stages, we decrease the likelihood of the adversary causing material damage to the enterprise. 
	* [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Malone-Using-An-Expanded-Cyber-Kill-Chain-Model-To-Increase-Attack-Resiliency.pdf)




### End Sort


### <a name="s3"></a>Amazon S3
* [Amazon S3 Bucket Public Access Considerations](https://aws.amazon.com/articles/5050)


### <a name="whitelist"></a>Application Whitelisting
* [Guide to Application Whitelisting - NIST Special Publication 800 - 167](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-167.pdf)


### <a name="asa"></a>Attack Surface Analysis/Reduction
* **General**
	* [Intrigue-core](https://github.com/intrigueio/intrigue-core)
		* Intrigue-core is a framework for automated attack surface discovery. 


### <a name="aapp"></a>(General)Auditing Account Passwords/Privileges


----------------------
### <a name="ap"></a>(General)Auditing Processes

* [ESA-Process-Maturity](https://github.com/Brockway/ESA-Process-Maturity)
	* Tools to measure the maturity of Enterprise Security Architecture processes
* [Command line process auditing](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)

### <a name="baseline"></a>(General) Baselining


-----------------
### <a name="firewall"></a>Firewalls
* [Assimilator](https://github.com/videlanicolas/assimilator)
	* The first restful API to control all firewall brands. Configure any firewall with restful API calls, no more manual rule configuration. Centralize all your firewalls into one API.

-----------------
### <a name="hardening"></a>(General) Hardening
* [ERNW Repository of Hardening Guides](https://github.com/ernw/hardening)
* [OWASP Secure Configuration Guide](https://www.owasp.org/index.php/Secure_Configuration_Guide)
* [PHP Secure Configuration Checker](https://github.com/sektioneins/pcc)
* [Security + DevOps Automatic Server Hardening - dev-sec.io](http://dev-sec.io/)
	* Open Source Automated Hardening Framework
* [Mozilla's OpenSSH Configuration guide](https://wiki.mozilla.org/Security/Guidelines/OpenSSH)
* [Harden windows IP Stack](https://www.reddit.com/r/netsec/comments/2sg80a/how_to_harden_windowsiis_ssltls_configuration/)
* [Linux workstation security checklist](https://github.com/lfit/itpol/blob/master/linux-workstation-security.md)
* [Secure Host Baseline](https://github.com/iadgov/Secure-Host-Baseline)
	* Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. iadgov
* [OS X Hardening: Securing a Large Global Mac Fleet - Greg Castle](https://www.usenix.org/conference/lisa13/os-x-hardening-securing-large-global-mac-fleet)



----------------------
### <a name="journalist"></a>Journalist
* [Information Security For Journalist book - Centre for Investigative Journalism](http://files.gendo.nl/Books/InfoSec_for_Journalists_V1.1.pdf)


-----------------
### <a name="leaks"></a>Leaks
* General
	* [AIL framework - Analysis Information Leak framework](https://github.com/CIRCL/AIL-framework)
		* AIL is a modular framework to analyse potential information leaks from unstructured data sources like pastes from Pastebin or similar services or unstructured data streams. AIL framework is flexible and can be extended to support other functionalities to mine sensitive information.
	* [git-secrets](https://github.com/awslabs/git-secrets)
		* Prevents you from committing passwords and other sensitive information to a git repository.
	* [keynuker](https://github.com/tleyden/keynuker)
		* KeyNuker scans public activity across all Github users in your Github organization(s) and proactively deletes any AWS keys that are accidentally leaked. It gets the list of AWS keys to scan by directly connecting to the AWS API.

-----------------
### <a name="linux"></a>Linux/Unix

* [LUNAR](https://github.com/lateralblast/lunar)
	* A UNIX security auditing tool based on several security frameworks
* [Filenames and Pathnames in Shell: How to do it Correctly](https://www.dwheeler.com/essays/filenames-in-shell.html)
* [Monit](https://mmonit.com/monit/)
	* Monit is a small Open Source utility for managing and monitoring Unix systems. Monit conducts automatic maintenance and repair and can execute meaningful causal actions in error situations.
* [Red Hat Enterprise Linux 6 Security Guide](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/pdf/Security_Guide/Red_Hat_Enterprise_Linux-6-Security_Guide-en-US.pdf)


-----------------
### <a name="malusb"></a>Malicious USBs



-----------------
### <a name="network"></a>Network
* [Defending the Enterprise Against Network Infrastructure Attacks  - Paul Coggin - Troopers15](https://www.youtube.com/watch?v=K0X3RDf5XK8)



-----------------
### <a name="osx"></a>OS X
* **General**
* **Tools**
	* [netman](https://github.com/iadgov/netman)
		* A userland network manager with monitoring and limiting capabilities for macOS.
	* [netfil](https://github.com/iadgov/netfil)
		* A kernel network manager with monitoring and limiting capabilities for macOS.
	* [OverSight](https://objective-see.com/products/oversight.html)
		* OverSight monitors a mac's mic and webcam, alerting the user when the internal mic is activated, or whenever a process accesses the webcam.
	* [LuLu](https://github.com/objective-see/LuLu)
		* LuLu is the free open-source macOS firewall that aims to block unauthorized (outgoing) network traffic






-----------------
### <a name="ransomware"></a>Ransomware
* [Decryptonite](https://github.com/DecryptoniteTeam/Decryptonite)
	* Decryptonite is a tool that uses heuristics and behavioural analysis to monitor for and stop ransomware.

-----------------
### <a name="waf"></a>WAF
* **NAXSI**
	* [naxsi](https://github.com/nbs-system/naxsi)
		* NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX
	* [naxsi wiki](https://github.com/nbs-system/naxsi/wiki)
* **ModSecurity**
	* [ModSecurity](https://www.modsecurity.org/)
	* [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)


-----------------
### <a name="windows"></a>Windows
* **General**
	* [Windows Firewall Hook Enumeration](https://www.nccgroup.com/en/blog/2015/01/windows-firewall-hook-enumeration/)
		* We’re going to look in detail at Microsoft Windows Firewall Hook drivers from Windows 2000, XP and 2003. This functionality was leveraged by the Derusbi family of malicious code to implement port-knocking like functionality. We’re going to discuss the problem we faced, the required reverse engineering to understand how these hooks could be identified and finally how the enumeration tool was developed.
	* [Detecting DLL Hijackingon Windows](http://digital-forensics.sans.org/blog/2015/03/25/detecting-dll-hijacking-on-windows/)
	* [The Effectiveness of Tools in Detecting the 'Maleficent Seven' Privileges in the Windows Environment](https://www.sans.org/reading-room/whitepapers/sysadmin/effectiveness-tools-detecting-039-maleficent-seven-039-privileges-windows-environment-38220)
* **Account Credentials** 
	* **General**
		* [Blocking Remote Use of Local Accounts](https://blogs.technet.microsoft.com/secguide/2014/09/02/blocking-remote-use-of-local-accounts/)
		* [MS Security Advisory 2871997](https://technet.microsoft.com/library/security/2871997)
			* Update to Improve Credentials Protection and Management
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
	* **Golden/Silver Tickets**
		* [Defending against mimikatz](https://jimshaver.net/2016/02/14/defending-against-mimikatz/)
		* [Kerberos Golden Ticket: Mitigating pass the ticket on Active Directory](http://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
		* [Mitigating Kerberos Golden Tickets:](http://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
		* [Protection from Kerberos Golden Ticket: Mitigating pass the ticket on Active Directory CERT-EU 2014](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
	* **Pass the Hash**
		* [Mitigating Pass-the-Hash Attacks and other credential Theft-version2](http://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf)
			* Official MS paper.
		* [Pass-the-Hash II:  Admin’s Revenge - Skip Duckwall & Chris Campbell](https://media.blackhat.com/us-13/US-13-Duckwall-Pass-the-Hash-Slides.pdf)
			* Protecting against Pass-The-Hash and other techniques
		* [Fixing Pass the Hash and Other Problems](http://www.scriptjunkie.us/2013/06/fixing-pass-the-hash-and-other-problems/)
		* [Pass the Hash Guidance](https://github.com/iadgov/Pass-the-Hash-Guidance)
			*  Configuration guidance for implementing Pass-the-Hash mitigations. iadgov
* **Active Directory**
	* [What would a real hacker do to your Active Directory](https://www.youtube.com/watch?v=DH3v8bO-NCs)
	* [Securing Microsoft Active Directory Federation Server (ADFS)](https://adsecurity.org/?p=3782)
	* **Building/Designing Infrastructure**
		* [How to Build Super Secure Active Directory Infrastructure* - BlackHills](https://www.blackhillsinfosec.com/build-super-secure-active-directory-infrastructure/)
		* [Active Directory Design Best Practices](https://krva.blogspot.com/2008/04/ad-design-best-practices.html)
	* **Domain Controllers/Admins**
		* [Securing Domain Controllers to Improve Active Directory Security - adsecurity.org](https://adsecurity.org/?p=3377)
		* [Protecting Privileged Domain Accounts: Network Authentication In-Depth](https://digital-forensics.sans.org/blog/2012/09/18/protecting-privileged-domain-accounts-network-authentication-in-depth)
		* [Active Directory: Real Defense for Domain Admins](https://www.irongeek.com/i.php?page=videos/derbycon4/t213-active-directory-real-defense-for-domain-admins-jason-lang)
			* Did your AD recently get owned on a pentest? It’s always fun to see an unknown entry show up in your Domain Admins group (#fail). Come learn how to truly protect your organization’s IT crown jewels from some of the most popular AD attacks. If you’re stuck trying to figure out what to do with null sessions, pass the hash techniques, or protecting your Domain Admins, then you will want to be here.
* **Application Whitelisting**
	* [Script Rules in AppLocker - technet](https://technet.microsoft.com/en-us/library/ee460958.aspx)
	* [DLL Rules in AppLocker](https://technet.microsoft.com/en-us/library/ee460947.aspx)
	* [Application Whitelisting Using Microsoft AppLocker](https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)
* **Auditing Account Passwords/Privileges**
	* [Account lockout threshold - technet](https://technet.microsoft.com/en-us/library/hh994574.aspx)
	* [Password Policy - technet](https://technet.microsoft.com/en-us/library/hh994572.aspx)
	* [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
		* As a part of ensuring that they've created a secure environment Windows administrators often need to know what kind of accesses specific users or groups have to resources including files, directories, Registry keys, global objects and Windows services. AccessChk quickly answers these questions with an intuitive interface and output.
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
* **Credential Guard**
	* [Protect derived domain credentials with Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)
	* [Using a hypervisor to secure your desktop – Credential Guard in Windows 10 - blogs.msdn](https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/10/26/using-a-hypervisor-to-secure-your-desktop-credential-guard-in-windows-10/)
	* [Credential Guard lab companion - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/05/15/credential-guard-lab-companion/)
* **Device Guard**
	* [Device Guard and Credential Guard hardware readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337)
	* [Introduction to Windows Defender Device Guard: virtualization-based security and Windows Defender Application Control - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies)
	* [Requirements and deployment planning guidelines for Windows Defender Device Guard - docs.ms](https://docs.microsoft.com/en-us/windows/device-security/device-guard/requirements-and-deployment-planning-guidelines-for-device-guard#hardware-firmware-and-software-requirements-for-device-guard)
	* [Driver compatibility with Device Guard in Windows 10 - docs.ms](https://blogs.msdn.microsoft.com/windows_hardware_certification/2015/05/22/driver-compatibility-with-device-guard-in-windows-10/)
* **Event Log**
	* General
		* [Windows Event Logs Zero to Hero Nate Guagenti Adam Swan - Bloomcon2017](https://www.youtube.com/watch?v=H3t_kHQG1Js)
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
* **Hardening**
	* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
		*  A curated list of awesome Security Hardening techniques for Windows.
	* [Threats and Countermeasures Guide: Security Settings in Windows Server 2008 R2 and Windows 7 - technet](https://technet.microsoft.com/en-us/library/hh125921.aspx)
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
* **Privileged Access Workstation**
	* [How Microsoft IT used Windows 10 and Windows Server 2016 to implement privileged access workstations](https://myignite.microsoft.com/sessions/54896)
		* As part of the security strategy to protect administrative privilege, Microsoft recommends using a dedicated machine, referred to as PAW (privileged access workstation), for administrative tasks; and using a separate device for the usual productivity tasks such as Outlook and Internet browsing. This can be costly for the company to acquire machines just for server administrative tasks, and inconvenient for the admins to carry multiple machines. In this session, we show you how MSIT uses shielded VMs on the new release of Windows client to implement a PAW.
	* [Privileged Access Workstation(PAW) - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/10/13/privileged-access-workstationpaw/)
	* [PAW host buildout - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/10/17/paw-host-buildout/)
	* [How to deploy a VM template for PAW - blogs.technet](https://blogs.technet.microsoft.com/datacentersecurity/2017/11/01/how-to-create-a-vm-template-for-paw/)
* **SMB**
	* [SMB Packet Signing](https://technet.microsoft.com/en-us/library/cc180803.aspx)
	* [Secure SMB Connections](http://techgenix.com/secure-smb-connections/)
	* [Microsoft Security Advisory: Update to improve credentials protection and management: May 13, 2014](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a)
	* [Require SMB Security Signatures - technet.ms](https://technet.microsoft.com/en-us/library/cc731957.aspx)
	* [SMB 3.0 (Because 3 > 2) - David Kruse](http://www.snia.org/sites/default/orig/SDC2012/presentations/Revisions/DavidKruse-SMB_3_0_Because_3-2_v2_Revision.pdf)
* **USB Detection**
	* [BEAMGUN](https://github.com/JLospinoso/beamgun)
		* A rogue-USB-device defeat program for Windows.
* Visualization/Tracking/Reporting
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

-----------------
#### <a name="powershell"></a>PowerShell
* General
	* [PowerShell ♥ the Blue Team](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)
	* [Powershell Security at Enterprise Customers - blogs.msdn](https://blogs.msdn.microsoft.com/daviddasneves/2017/05/25/powershell-security-at-enterprise-customers/)
	* [More Detecting Obfuscated PowerShell](http://www.leeholmes.com/blog/2016/10/22/more-detecting-obfuscated-powershell/)
	* [Revoke-Obfuscation - tool](https://github.com/danielbohannon/Revoke-Obfuscation)
		* PowerShell v3.0+ compatible PowerShell obfuscation detection framework.
	* [Revoke Obfuscation PowerShell Obfuscation Detection And Evasion Using Science Lee Holmes Daniel - Derbycon7 - talk](https://www.youtube.com/watch?v=7XnkDsOZM3Y&index=16&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
	* [PSRecon](https://github.com/gfoss/PSRecon/)
		* 🚀 PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
	




