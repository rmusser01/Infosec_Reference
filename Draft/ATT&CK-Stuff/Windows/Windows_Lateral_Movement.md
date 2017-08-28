Windows Lateral Movement




## Application Deployment Software
-------------------------------
[Application Deployment Software - ATT&CK](https://attack.mitre.org/wiki/Technique/T1017)




## Exploitation of Vulnerability
-------------------------------
[Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)





## Logon Scripts
-------------------------------
[Logon Scripts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1037)








## Pass the Hash
-------------------------------
[Pass the Hash - ATT&CK](https://attack.mitre.org/wiki/Technique/T1075)
* Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems. Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.

[Pass the hash attacks: Tools and Mitigation - 2010 SANS paper](https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283)





## Pass the Ticket
-------------------------------
[Pass the Ticket - ATT&CK](https://attack.mitre.org/wiki/Technique/T1097)
* Pass the ticket (PtT)1 is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system. In this technique, valid Kerberos tickets for Valid Accounts are captured by Credential Dumping. A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access. Silver Tickets can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint). Golden Tickets can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.

[ Mimikatz and Active Directory Kerberos Attacks ](https://adsecurity.org/?p=556)

[The Secret Life of KRBTGT](https://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf)

[Kerberos Golden Ticket Protection Mitigating Pass-the-Ticket on Active Directory - CERT-EU](https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf)






## Remote Desktop Protocol(RDP)
-------------------------------
[Remote Desktop Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1076)


[RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)





## Remote File Copy
-------------------------------
[Remote File Copy - ATT&CK](https://attack.mitre.org/wiki/Technique/T1105)
* Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp. 





## Remote Services
-------------------------------
[Remote Services - ATT&CK](https://attack.mitre.org/wiki/Technique/T1021)
* An adversary may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user. 





## Replication Through Removable Media
-------------------------------
[Replication Through Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1091)
* Adversaries may move to additional systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into another system and executes. This may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. 






## Shared Webroot
-------------------------------
[Shared Webroot - ATT&CK](https://attack.mitre.org/wiki/Technique/T1051)
* Adversaries may add malicious content to an internally accessible website through an open network file share that contains the website's webroot or Web content directory and then browse to that content with a Web browser to cause the server to execute the malicious content. The malicious content will typically run under the context and permissions of the Web server process, often resulting in local system or administrative privileges, depending on how the Web server is configured. This mechanism of shared access and remote execution could be used for lateral movement to the system running the Web server. For example, a Web server running PHP with an open network share could allow an adversary to upload a remote access tool and PHP script to execute the RAT on the system running the Web server when a specific page is visited. 







## Taint Shared Content
-------------------------------
[Taint Shared Content - ATT&CK](https://attack.mitre.org/wiki/Technique/T1080)
* Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally. 








## Third-Party Software
-------------------------------
[Third-party Software - ATT&CK](https://attack.mitre.org/wiki/Technique/T1072)






## Windows Admin Shares
-------------------------------
[Windows Admin Shares - ATT&CK](https://attack.mitre.org/wiki/Technique/T1077)
* Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMIN$, and IPC$. Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over server message block (SMB) to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task, Service Execution, and Windows Management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels. 

[What Is RPC? - technet](https://technet.microsoft.com/en-us/library/cc787851.aspx)

[How to remove administrative shares in Windows Server 2008](https://support.microsoft.com/en-us/help/954422/how-to-remove-administrative-shares-in-windows-server-2008)

[Net use - technet](https://technet.microsoft.com/en-us/bb490717.aspx)




## Windows Remote Management
-------------------------------
[Windows Remote Management - ATT&CK](https://attack.mitre.org/wiki/Technique/T1028)
* Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the winrm command or by any number of programs such as PowerShell.

[Windows Remote Management - msdn](https://msdn.microsoft.com/en-us/library/aa384426)






