# Linux Discovery

-------------------------------
### Account Discovery
Account Discovery
* [Account Discovery - ATT&CK](https://attack.mitre.org/wikipediai/Technique/T1087)
	* Adversaries may attempt to get a listing of local system or domain accounts. 
	* On Linux, local users can be enumerated through the use of the /etc/passwd file which is world readable. Also, groups can be enumerated through the groups and id commands.





-------------------------------
### File and Directory Discovery
File and Directory Discovery
* [File and Directory Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1083)
	* Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. In Mac and Linux, this kind of discovery is accomplished with the ls, find, and locate commands.
* [find - ss64](https://ss64.com/bash/find.html)
* [Find Files in Linux, Using the Command Line - linode](https://www.linode.com/docs/tools-reference/tools/find-files-in-linux-using-the-command-line/)
* [25 simple examples of Linux find command - binarytides](http://www.binarytides.com/linux-find-command-examples/)
* [The locate Command - linfo](http://www.linfo.org/locate.html)




-------------------------------
## Permission Groups Discovery
Permissions Group Discovery
* [Permission Groups Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1069)
	* Adversaries may attempt to find local system or domain-level groups and permissions settings. On Linux, local groups can be enumerated with the `groups` command and domain groups via the `ldapsearch` command.
* [Linux / Unix: groups Command Examples](https://www.cyberciti.biz/faq/unix-linux-groups-command-examples-syntax-usage/)
* [Linux Users and Groups](https://www.linode.com/docs/tools-reference/linux-users-and-groups/)
* [Managing Group Access](http://www.yolinux.com/TUTORIALS/LinuxTutorialManagingGroups.html)
* [Using ldapsearch](https://www.centos.org/docs/5/html/CDS/ag/8.0/Finding_Directory_Entries-Using_ldapsearch.html)
* [LDAP Command-Line Tools](https://docs.oracle.com/cd/B10501_01/network.920/a96579/comtools.htm)
* [Querying an LDAP server from the command line with ldap-utils: ldapsearch, ldapadd, ldapmodify](http://www.vinidox.com/ldap/querying-an-ldap-server-from-the-command-line-with-ldap-utils-ldapsearch-ldapadd-ldapmodify/)



-------------------------------
## Process Discovery
Process Discovery
* [Process Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1057)
	* Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software running on systems within the network. In Mac and Linux, this is accomplished with the ps command.
* [ps manpage](https://linux.die.net/man/1/ps)
* [How To Use ps, kill, and nice to Manage Processes in Linux](https://www.digitalocean.com/community/tutorials/how-to-use-ps-kill-and-nice-to-manage-processes-in-linux)
* [30 Useful ‘ps Command’ Examples for Linux Process Monitoring](https://www.tecmint.com/ps-command-examples-for-linux-process-monitoring/)




-------------------------------
## Remote System Discovery
Remote System Discovery
* [Remote System Discovery](https://attack.mitre.org/wiki/Technique/T1018)
	* Adversaries will likely attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used. 
	*  Utilities such as "ping" and others can be used to gather information about remote systems.
* `ping`, `arp`, etc.







-------------------------------
## System Network Configuration Discovery
* [System Network Configuration Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1016)
	* Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.




-------------------------------
## System Network Connections Discovery
* [System Network Connections Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1049)
	* Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. In Mac and Linux, netstat and lsof can be used to list current connections. who -a and w can be used to show which users are currently logged in, similar to "net session". 







-------------------------------
## System Owner/User Discovery
Systems Owner/User Discovery 
* [System Owner/User Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1033)
	* Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. On Linux, the currently logged in user can be identified with w and who.




-------------------------------
## System Service Discovery
System Service Discovery
* [System Service Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1007)
* [Red Hat / CentOS: Check / List Running Services](https://www.cyberciti.biz/faq/check-running-services-in-rhel-redhat-fedora-centoslinux/)
* Ubuntu/Debian-based - `services --status-all`


-------------------------------
## System Time Discovery
System Time Discovery
* [System Time Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1124)
* `date` command









