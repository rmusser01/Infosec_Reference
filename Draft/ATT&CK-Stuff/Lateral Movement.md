# Lateral Movement


[MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/wiki/Lateral_Movement)
* Lateral movement consists of techniques that enable an adversary to access and control remote systems on a network and could, but does not necessarily, include execution of tools on remote systems. The lateral movement techniques could allow an adversary to gather information from a system without needing additional tools, such as a remote access tool. 
* An adversary can use lateral movement for many purposes, including remote Execution of tools, pivoting to additional systems, access to specific information or files, access to additional credentials, or to cause an effect. The ability to remotely execute scripts or code can be a feature of adversary remote access tools, but adversaries may also reduce their tool footprint on the network by using legitimate credentials alongside inherent network and operating system functionality to remotely connect to systems. 
* Movement across a network from one system to another may be necessary to achieve an adversary’s goals. Thus lateral movement, and the techniques that lateral movement relies on, are often very important to an adversary's set of capabilities and part of a broader set of information and access dependencies that the adversary takes advantage of within a network. To understand intrinsic security dependencies, it is important to know the relationships between accounts and access privileges across all systems on a network. Lateral movement may not always be a requirement for an adversary. If an adversary can reach the goal with access to the initial system, then additional movement throughout a network may be unnecessary. 




## AppleScript
--------------------------
* [AppleScript - ATT&CK](https://attack.mitre.org/wiki/Technique/T1155)
* macOS and OS X applications send AppleEvent messages to each other for interprocess communications (IPC). These messages can be easily scripted with AppleScript for local or remote IPC. Osascript executes AppleScript and any other Open Scripting Architecture (OSA) language scripts. A list of OSA languages installed on a system can be found by using the osalang program. 
* AppleEvent messages can be sent independently or as part of a script. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely. 
*  Adversaries can use this to interact with open SSH connection, move to remote machines, and even present users with fake dialog boxes. These events cannot start applications remotely (they can start them locally though), but can interact with applications if they're already running remotely. Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via python Macro Malware Targets Macs. Scripts can be run from the command lie via `osascript /path/to/script` or `osascript -e "script here"`.



## Application Deployment Software
-------------------------------
Application Deployment Software
* [Application Deployment Software - ATT&CK](https://attack.mitre.org/wiki/Technique/T1017)
	* Adversaries may deploy malicious software to systems within a network using application deployment systems employed by enterprise administrators. The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment. Access to a network-wide or enterprise-wide software deployment system enables an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

#### Windows
* [Owning One To Rule Them All - Defcon20](https://www.trustedsec.com/files/Owning_One_Rule_All_v2.pdf)


## Exploitation of Vulnerability
-------------------------------
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
	* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.Technet MS14-068ADSecurity Detecting Forged Tickets




## Logon Scripts
-------------------------------
*  [Logon Scripts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1037)

#### OS X
* MITRE
	* Mac allows login and logoff hooks to be run as root whenever a specific user logs into or out of a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike startup items, a login hook executes as rootcreating login hook. There can only be one login hook at a time though. If adversaries can access these scripts, they can insert additional code to the script to execute their tools when a user logs in.
#### Windows
* MITRE
	* Windows allows logon scripts to be run whenever a specific user or group of users log into a system.TechNet Logon Scripts The scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. 
	* If adversaries can access these scripts, they may insert additional code into the logon script to execute their tools when a user logs in. This code can allow them to maintain persistence on a single system, if it is a local script, or to move laterally within a network, if the script is stored on a central server and pushed to many systems. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 
* [Setting up a Logon Script through Active Directory Users and Computers in Windows Server 2008](https://www.petri.com/setting-up-logon-script-through-active-directory-users-computers-windows-server-2008)
* [Assign User Logon Scripts - technet](https://technet.microsoft.com/en-us/library/cc770908(v=ws.11).aspx)
* [Use Startup, Shutdown, Logon, and Logoff Scripts - technet](https://technet.microsoft.com/en-us/library/cc753404(v=ws.11).aspx)
* [Logon Scripts - With VBScript](http://www.computerperformance.co.uk/Logon/logon_scripts.htm)
* In this section I will give you examples of how to build the VBScript to use in your logon script. 
* [Windows 7 Home: how to configure a logon script - superuser](https://superuser.com/questions/258641/windows-7-home-how-to-configure-a-logon-script)
* [How do I find out where login scripts live? - stackoverflow](https://stackoverflow.com/questions/663459/how-do-i-find-out-where-login-scripts-live)






## Pass the Hash
-------------------------------
* [Pass the Hash - ATT&CK](https://attack.mitre.org/wiki/Technique/T1075)
	* Pass the hash (PtH)Aorato PTH is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems. Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.NSA Spotting

#### Windows
* [Pass the hash attacks: Tools and Mitigation - 2010 SANS paper](https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283)
* [Pass the hash - Wikipedia](https://en.wikipedia.org/wiki/Pass_the_hash)
* [Performing Pass-the-Hash Attacks with Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* [Still Passing the Hash 15 Years Later](https://passing-the-hash.blogspot.com/)
	* Providing all the extra info that didn't make it into the BlackHat 2012 USA Presentation "Still Passing the Hash 15 Years Later? Using the Keys to the Kingdom to Access All Your Data" by Alva Lease 'Skip' Duckwall IV and Christopher Campbell.









## Pass the Ticket
-------------------------------
* [Pass the Ticket - ATT&CK](https://attack.mitre.org/wiki/Technique/T1097)
	* Pass the ticket (PtT)Aorato PTT is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system. 
	* In this technique, valid Kerberos tickets for Valid Accounts are captured by Credential Dumping. A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.ADSecurity AD Kerberos AttacksGentilKiwi Pass the Ticket 
	* Silver Tickets can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint).ADSecurity AD Kerberos Attacks 
	*  Golden Tickets can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.Campbell 2014

#### Windows
* [Mimikatz and Active Directory Kerberos Attacks ](https://adsecurity.org/?p=556)
* [The Secret Life of KRBTGT](https://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf)
* [Kerberos Golden Ticket Protection Mitigating Pass-the-Ticket on Active Directory - CERT-EU](https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf)
* [From Pass-the-Hash to Pass-the-Ticket with No Pain](http://resources.infosecinstitute.com/pass-hash-pass-ticket-no-pain/)
* [mimikatz - Golden Ticket](http://rycon.hu/papers/goldenticket.html)
* [THE GOLDEN TICKET ATTACK- A LOOK UNDER THE HOOD](http://cybersecology.com/wp-content/uploads/2016/05/Golden_Ticket-v1.13-Final.pdf)
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
* [The path to the Golden Ticket](https://countuponsecurity.com/tag/pass-the-ticket/)
* [How To Pass the Ticket Through SSH Tunnels](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)





## Remote Desktop Protocol(RDP)
-------------------------------
* [Remote Desktop Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1076)
	* Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).TechNet Remote Desktop Services There are other implementations and third-party tools that provide graphical access Remote Services similar to RDS. Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the Accessibility Features technique for Persistence.Alperovitch Malware

#### Windows
* [RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
* [RDP Man-in-The-Middle attack ](https://theevilbit.blogspot.com/2014/04/rdp-man-in-middle-attack.html)
* [ATTACKING RDP How to Eavesdrop on Poorly Secured RDP Connections - Adrian Vollmer 2017](https://www.exploit-db.com/docs/41621.pdf)
* [RDPY](https://github.com/citronneur/rdpy)
	* RDPY is a pure Python implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (client and server side). RDPY is built over the event driven network engine Twisted. RDPY support standard RDP security layer, RDP over SSL and NLA authentication (through ntlmv2 authentication protocol).
* [SSL “Man-In-The-Middle” attacks on RDP](https://web.archive.org/web/20161007044945/https://labs.portcullis.co.uk/blog/ssl-man-in-the-middle-attacks-on-rdp/)
* [rdps2rdp](https://github.com/DiabloHorn/rdps2rdp)
	* Decrypt MITM SSL RDP and save to pcap









## Remote File Copy
-------------------------------
* [Remote File Copy - ATT&CK](https://attack.mitre.org/wiki/Technique/T1105)
	* Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp. Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with Windows Admin Shares or Remote Desktop Protocol.





## Remote Services
-------------------------------
* [Remote Services - ATT&CK](https://attack.mitre.org/wiki/Technique/T1021)
	* An adversary may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user. 

#### Windows
* [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)





## Replication Through Removable Media
-------------------------------
* [Replication Through Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1091)
	* Adversaries may move to additional systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into another system and executes. This may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system.






## Shared Webroot
-------------------------------
* [Shared Webroot - ATT&CK](https://attack.mitre.org/wiki/Technique/T1051)
	* Adversaries may add malicious content to an internally accessible website through an open network file share that contains the website's webroot or Web content directory and then browse to that content with a Web browser to cause the server to execute the malicious content. The malicious content will typically run under the context and permissions of the Web server process, often resulting in local system or administrative privileges, depending on how the Web server is configured. This mechanism of shared access and remote execution could be used for lateral movement to the system running the Web server. For example, a Web server running PHP with an open network share could allow an adversary to upload a remote access tool and PHP script to execute the RAT on the system running the Web server when a specific page is visited.







## Taint Shared Content
-------------------------------
* [Taint Shared Content - ATT&CK](https://attack.mitre.org/wiki/Technique/T1080)
	* Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally. 
* [The Backdoor Factory](https://github.com/secretsquirrel/the-backdoor-factory)
* [Introduction to Manual Backdooring](https://www.exploit-db.com/docs/42061.pdf)



## Third-Party Software
-------------------------------
* [Third-party Software - ATT&CK](https://attack.mitre.org/wiki/Technique/T1072)
	* Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.). If an adversary gains access to these systems, then they may be able to execute code. 
	* Adversaries may gain access to and use third-party application deployment systems installed within an enterprise network. Access to a network-wide or enterprise-wide software deployment system enables an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints. 
	*  The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment.
* [Evilgrade](https://github.com/infobyte/evilgrade)
	* Evilgrade is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates. It comes with pre-made binaries (agents), a working default configuration for fast pentests, and has it's own WebServer and DNSServer modules. Easy to set up new settings, and has an autoconfiguration when new binary agents are set.




## Windows Admin Shares
-------------------------------
* [Windows Admin Shares - ATT&CK](https://attack.mitre.org/wiki/Technique/T1077)
	* Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMIN$, and IPC$. 
	* Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over server message block (SMB)Wikipedia SMB to interact with systems using remote procedure calls (RPCs),TechNet RPC transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task, Service Execution, and Windows Management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels.Microsoft Admin Shares 
	*  The Net utility can be used to connect to Windows admin shares on remote systems using `net use` commands with valid credentials.

#### Windows
* [What Is RPC? - technet](https://technet.microsoft.com/en-us/library/cc787851.aspx)
* [How to remove administrative shares in Windows Server 2008](https://support.microsoft.com/en-us/help/954422/how-to-remove-administrative-shares-in-windows-server-2008)
* [Net use - technet](https://technet.microsoft.com/en-us/bb490717.aspx)




## Windows Remote Management
-------------------------------
* [Windows Remote Management - ATT&CK](https://attack.mitre.org/wiki/Technique/T1028)
	* Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).Microsoft WinRM It may be called with the winrm command or by any number of programs such as PowerShell.Jacobsen 2014

#### Windows
* [Windows Remote Management - msdn](https://msdn.microsoft.com/en-us/library/aa384426)
* [Installation and Configuration for Windows Remote Management - msdn](https://msdn.microsoft.com/en-us/library/aa384372(v=vs.85).aspx)
* [winrm - go](https://github.com/masterzen/winrm)
	* Command-line tool and library for Windows remote command execution in Go
* [pywinrm](https://github.com/diyan/pywinrm)
	* Python library for Windows Remote Management (WinRM)
* [Using Credentials to Own Windows Boxes - Part 3 (WMI and WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
* [Exploiting Trusted Hosts in WinRM ](https://blog.netspi.com/exploiting-trusted-hosts-in-winrm/)
* [PowerShell PSRemoting Pwnage](https://pentestn00b.wordpress.com/2016/08/22/powershell-psremoting-pwnage/)
* [PowerShell Remoting for Penetration Testers ](https://lockboxx.blogspot.com/2015/07/powershell-remoting-for-penetration.html)




