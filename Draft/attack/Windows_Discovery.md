# Windows_Discovery.md




## Account Discovery
-------------------------------
[Account Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1087)
* Adversaries may attempt to get a listing of local system or domain accounts. 
* Example commands that can acquire this information are net user, net group <groupname>, and net localgroup <groupname> using the Net utility or through use of dsquery. If adversaries attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system, System Owner/User Discovery may apply. 

[Net.exe reference](http://windowsitpro.com/windows/netexe-reference)

[Dsquery - technet](https://technet.microsoft.com/en-us/library/cc732952.aspx)



## Application Window Discovery
-------------------------------
[Application Window Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1010)
* Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger. 



## File and Directory Discovery
-------------------------------
[File and Directory Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1083)



## Network Service Scanning
-------------------------------
[Network Service Scanning - ATT&CK](https://attack.mitre.org/wiki/Technique/T1046)



## Network Share Discovery
-------------------------------
[Network Share Discovery - ATT&CK](Network Share Discovery)



## Peripheral Device Discovery
-------------------------------
[Peripheral Device Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1120)
* Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. The information may be used to enhance their awareness of the system and network environment or may be used for further actions. 



## Permission Groups Discovery
-------------------------------
[Permission Groups Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1069)
* Adversaries may attempt to find local system or domain-level groups and permissions settings. 
* Examples of commands that can list groups are net group /domain and net localgroup using the Net utility. 



## Process Discovery
-------------------------------
[Process Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1057)



## Query Registry
-------------------------------
[Query Registry - ATT&CK](https://attack.mitre.org/wiki/Technique/T1012)



## Remote System Discovery
-------------------------------
[Remote System Discovery](https://attack.mitre.org/wiki/Technique/T1018)
* Adversaries will likely attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used. 







