## Linux Collection


------------------------------- 
## Automated Collection
[Automated Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1119)
* Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of Scripting to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. 

[LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.




------------------------------- 
## Clipboard Data
[Clipboard Data - ATT&CK](https://attack.mitre.org/wiki/Technique/T1115)
* Adversaries may collect data stored in the clipboard from users copying information within or between applications. 

[Access Unix Clipboard - StackOverflow](https://unix.stackexchange.com/questions/44204/access-unix-clipboard)
* If xclip is available: [Accessing clipboard in Linux terminal](http://www.nurkiewicz.com/2012/09/accessing-clipboard-in-linux-terminal.html)



------------------------------- 
## Data Staged
[Data Staged - ATT&CK](https://attack.mitre.org/wiki/Technique/T1074)
* Collected data is staged in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Data Compressed or Data Encrypted. 





------------------------------- 
## Data from Local System
[Data from Local System - ATT&CK](https://attack.mitre.org/wiki/Technique/T1005)
* Sensitive data can be collected from local system sources, such as the file system or databases of information residing on the system prior to Exfiltration. 

* /etc/passwd : Contains local Linux users.
* /etc/shadow : Contains local account password hashes.
* /etc/group : Contains local account groups.
* /etc/init.d/ : Contains service init script - worth a look to see whats installed.
* /etc/hostname : System hostname.
* /etc/network/interfaces : Network interfaces.
* /etc/resolv.conf : System DNS servers.
* /etc/profile : System environment variables.
* ~/.ssh/ : SSH keys.
* ~/.bash_history : Users bash history log.
* /var/log/ : Linux system log files are typically stored here.
* /var/adm/ : UNIX system log files are typically stored here.
* /var/log/apache2/access.log & /var/log/httpd/access.log : Apache access log file typical path.
* /etc/fstab : File system mounts. 
* [From: highoncoffee](https://highon.coffee/blog/linux-commands-cheat-sheet/#linux-interesting-files--dirs)








------------------------------- 
## Data from Network Shared Drive
[Data from Network Shared Drive](https://attack.mitre.org/wiki/Technique/T1039)
* ensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Adversaries may search network shares on computers they have compromised to find files of interest. Interactive command shells may be in use, and common functionality within cmd may be used to gather information. 






------------------------------- 
## Data from Removable Media
[Data from Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1025)
* Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. 





------------------------------- 
## Input Capture
[Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.
* Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes,1 but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider.2
* Keylogging is likely to be used to acquire credentials for new access opportunities when Credential Dumping efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.
* Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the initial compromise by exploitation of the externally facing web service.3 




------------------------------- 
## Screen Capture
[Screen Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1113)
* Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. 
* On Linux, there is the native command xwd.








