## Mac Discovery


------------------------------- 
## Account Discovery
[Account Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1087)
* Adversaries may attempt to get a listing of local system or domain accounts. 
* On Mac, groups can be enumerated through the groups and id commands. In mac specifically, dscl . list /Groups and dscacheutil -q group can also be used to enumerate groups and users. 










------------------------------- 
## Application Window Discovery
[Application Window Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1010)
* Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger. 











------------------------------- 
## File and Directory Discovery
[File and Directory Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1083)
* Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. 
















------------------------------- 
## Network Share Discovery
[Network Share Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1135)
* Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. 













------------------------------- 
## Permissions Groups Discovery
[Permissions Groups Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1069)
* Adversaries may attempt to find local system or domain-level groups and permissions settings. 













------------------------------- 
## Process Discovery
[Process Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1057)
* Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software running on systems within the network. 




















------------------------------- 
## Remote System Discovery
[Remote System Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1018)
* Adversaries will likely attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used. 


















------------------------------- 
## Security Software Discovery
[Security Software Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1063)
* Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules, anti-virus, and virtualization. These checks may be built into early-stage remote access tools. 
* It's becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software. 















------------------------------- 
## System Information Discovery
[System Information Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1082)
* An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. 















------------------------------- 
## System Network Configuration Discovery
[System Network Configuration Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1016)
* Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route. 
















------------------------------- 
## System Network Connections Discovery
[System Network Connections Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1049)
* Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 












------------------------------- 
## System Owner/User Discovery
[System Owner/User Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1033)
* On Mac, the currently logged in user can be identified with ***users***,***w***, and ****who****. 


