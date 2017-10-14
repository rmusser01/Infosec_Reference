# Windows Collection







## Audio Capture
-------------------------------
[Audio Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1123)
* An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information. 



## Automated Collection
-------------------------------
[Automated Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1119)
* Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of Scripting to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. 




## Clipboard Data
-------------------------------
[Clipboard Data - ATT&CK](https://attack.mitre.org/wiki/Technique/T1115)
* Adversaries may collect data stored in the Windows clipboard from users copying information within or between applications. 

[About the Clipboard - msdn](https://msdn.microsoft.com/en-us/library/ms649012)



## Data Staged 
-------------------------------
[Data Staged - ATT&CK](https://attack.mitre.org/wiki/Technique/T1074)
* Collected data is staged in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Data Compressed or Data Encrypted. 



## Data from Local System
-------------------------------
[Data from Local System - ATT&CK](https://attack.mitre.org/wiki/Technique/T1005)

[LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.

[BrowserGatherer](https://github.com/sekirkity/BrowserGather)
* Fileless Extraction of Sensitive Browser Information with PowerShell

[SessionGopher](https://github.com/fireeye/SessionGopher)
* SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.

[CC_Checker](https://github.com/NetSPI/PS_CC_Checker)
* CC_Checker cracks credit card hashes with PowerShell.

[SearchForCC](https://github.com/eelsivart/SearchForCC)
* A collection of open source/common tools/scripts to perform a system memory dump and/or process memory dump on Windows-based PoS systems and search for unencrypted credit card track data.

[KeeFarce](https://github.com/denandz/KeeFarce)
* Extracts passwords from a KeePass 2.x database, directly from memory.

[KeeThief](https://github.com/HarmJ0y/KeeThief)
* Methods for attacking KeePass 2.X databases, including extracting of encryption key material from memory.



## Data from Network Shared Drive
-------------------------------
[Data from Network Shared Drive - ATT&CK](https://attack.mitre.org/wiki/Technique/T1039)
* Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. 



## Data from Removable Media
-------------------------------
[Data from Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1025)


## Email Collection
-------------------------------
[Email Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1114)
* Adversaries may target user email to collect sensitive information from a target.  Files containing email data can be acquired from a user's system, such as Outlook storage or cache files .pst and .ost.




## Input Capture
-------------------------------
[Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.

[Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))

[The Adventures of a KeyStroke: An in-depth look into Keyloggers on Windows](http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf)

[Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)




## Screen Capture
-------------------------------
[Screen Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1113)
* Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. 




## Video Capture
-------------------------------
[Video Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1125)
* An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files. 