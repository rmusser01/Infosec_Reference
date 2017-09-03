# Windows_Discovery.md

-------------------------------
### Account Discovery

[Account Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1087)
* Adversaries may attempt to get a listing of local system or domain accounts. 
* Example commands that can acquire this information are net user, net group <groupname>, and net localgroup <groupname> using the Net utility or through use of dsquery. If adversaries attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system, System Owner/User Discovery may apply. 

[Net.exe reference](http://windowsitpro.com/windows/netexe-reference)

[Dsquery - technet](https://technet.microsoft.com/en-us/library/cc732952.aspx)

[“I Hunt Sys Admins” - Harmjoy](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)

[Powerview | Powershell Mafia - Powersploit - Recon](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
* PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net *" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality. It also implements various useful metafunctions, including some custom-written user-hunting functions which will identify where on the network specific users are logged into. It can also check which machines on the domain the current user has local administrator access on. Several functions for the enumeration and abuse of domain trusts also exist. See function descriptions for appropriate usage and available options. For detailed output of underlying functionality, pass the -Verbose or -Debug flags.






-------------------------------
### Application Window Discovery

[Application Window Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1010)
* Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger. 

[Get Active Window on User Desktop - technet](https://gallery.technet.microsoft.com/scriptcenter/Get-Active-Window-on-User-352fa957)
* This script will tell you the application that user is currently using. This also called active window. This script replies on unmanaged dll, user32.dll, to get this information. It has a function called GetForegroundWindow() which returns the Windowhandle of the active process. 

[Get-Window](https://www.vexasoft.com/pages/get-window)
* Gets the application windows that are open on the local desktop. 

[Get Active Window titles of remote computer? - reddit](https://www.reddit.com/r/PowerShell/comments/2onpdm/get_active_window_titles_of_remote_computer/)

[How to get list of running applications using PowerShell or VBScript](https://stackoverflow.com/questions/191206/how-to-get-list-of-running-applications-using-powershell-or-vbscript)



-------------------------------
### File and Directory Discovery

[File and Directory Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1083)

[Microsoft DOS tree command](https://www.computerhope.com/treehlp.htm)
* Is present on MS DOS -> 10.

[dir - technet](https://technet.microsoft.com/en-us/library/cc755121(v=ws.11).aspx)
* Displays a list of a directory's files and subdirectories. If used without parameters, dir displays the disk's volume label and serial number, followed by a list of directories and files on the disk (including their names and the date and time each was last modified). For files, dir displays the name extension and the size in bytes. Dir also displays the total number of files and directories listed, their cumulative size, and the free space (in bytes) remaining on the disk.




-------------------------------
### Network Service Scanning

[Network Service Scanning - ATT&CK](https://attack.mitre.org/wiki/Technique/T1046)

[scanless](https://github.com/vesche/scanless)
* Command-line utility for using websites that can perform port scans on your behalf. Useful for early stages of a penetration test or if you'd like to run a port scan on a host and have it not come from your IP address.

[ms15-034.nse Script](https://github.com/pr4jwal/quick-scripts/blob/master/ms15-034.nse)



#### DNS:

[DNSRecon](https://github.com/darkoperator/dnsrecon)
* [Quick Reference Guide](http://pentestlab.wordpress.com/2012/11/13/dns-reconnaissance-dnsrecon/)

[dns-discovery](https://github.com/mafintosh/dns-discovery)
* Discovery peers in a distributed system using regular dns and multicast dns.

[Knockpy](https://github.com/guelfoweb/knock)
* Knockpy is a python tool designed to enumerate subdomains on a target domain through a wordlist. It is designed to scan for DNS zone transfer and to try to bypass the wildcard DNS record automatically if it is enabled.

[sub6](https://github.com/YasserGersy/sub6)
* subdomain take over detector and crawler

[enumall](https://github.com/Dhayalan96/enumall)
* Script to enumerate subdomains, leveraging recon-ng. Uses google scraping, bing scraping, baidu scraping, yahoo scarping, netcraft, and bruteforces to find subdomains. Plus resolves to IP.

[dns-parallel-prober](https://github.com/lorenzog/dns-parallel-prober)
* This script is a proof of concept for a parallelised domain name prober. It creates a queue of threads and tasks each one to probe a sub-domain of the given root domain. At every iteration step each dead thread is removed and the queue is replenished as necessary.

[Altdns](https://github.com/infosec-au/altdns)
* Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.

[AQUATONE](https://github.com/michenriksen/aquatone)
* AQUATONE is a set of tools for performing reconnaissance on domain names. It can discover subdomains on a given domain by using open sources as well as the more common subdomain dictionary brute force approach. After subdomain discovery, AQUATONE can then scan the hosts for common web ports and HTTP headers, HTML bodies and screenshots can be gathered and consolidated into a report for easy analysis of the attack surface.

[Sublist3r](https://github.com/aboul3la/Sublist3r)
* Fast subdomains enumeration tool for penetration testers

[DNS Recon](https://github.com/darkoperator/dnsrecon)

[DNS Dumpster](DNSdumpster.com is a free domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process.)

[TXTDNS](http://www.txdns.net/)
* TXDNS is a Win32 aggressive multithreaded DNS digger. Capable of placing, on the wire, thousands of DNS queries per minute. TXDNS main goal is to expose a domain namespace trough a number of techniques: Typos: Mised, doouble and transposde keystrokes; TLD/ccSLD rotation; Dictionary attack; Full Brute-force attack using alpha, numeric or alphanumeric charsets; Reverse grinding.

[DNSEnum](https://github.com/fwaeytens/dnsenum)
* Multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.


#### Email

[SIMPLYEMAIL](https://github.com/killswitch-GUI/SimplyEmail)
* What is the simple email recon tool? This tool was based off the work of theHarvester and kind of a port of the functionality. This was just an expansion of what was used to build theHarvester and will incorporate his work but allow users to easily build Modules for the Framework. Which I felt was desperately needed after building my first module for theHarvester.

[Swaks - Swiss Army Knife for SMTP](http://www.jetmore.org/john/code/swaks/)



#### Network Host/Service:

[Nmap](http://nmap.org/)
* Nmap ("Network Mapper") is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping). 

[Enumerator](https://pypi.python.org/pypi/enumerator/0.1.4)
* enumerator is a tool built to assist in automating the often tedious task of enumerating a target or list of targets during a penetration test.

[hostmap](https://github.com/jekil/hostmap)
* hostmap is a free, automatic, hostnames and virtual hosts discovery tool written in Ruby by Alessandro Tanasi

[Angry IP Scanner](http://angryip.org/)
* Angry IP Scanner (or simply ipscan) is an open-source and cross-platform network scanner designed to be fast and simple to use. It scans IP addresses and ports as well as has many other features. 

[UnicornScan](http://www.unicornscan.org/)
* Unicornscan is a new information gathering and correlation engine built for and by members of the security research and testing communities. It was designed to provide an engine that is Scalable, Accurate, Flexible, and Efficient. It is released for the community to use under the terms of the GPL license. 
* My note: Use this to mass scan networks. It’s faster than nmap at scanning large host lists and allows you to see live hosts quickly.

[hping](http://www.hping.org/)
* hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface is inspired to the ping(8) unix command, but hping isn't only able to send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode, the ability to send files between a covered channel, and many other features. 

[Unicornscan](http://www.unicornscan.org/)
* Unicornscan is a new information gathering and correlation engine built for and by members of the security research and testing communities. It was designed to provide an engine that is Scalable, Accurate, Flexible, and Efficient. It is released for the community to use under the terms of the GPL license. 

[Consul](https://github.com/hashicorp/consul)
* Consul is a tool for service discovery and configuration. Consul is distributed, highly available, and extremely scalable.

[CloudFail](https://github.com/m0rtem/CloudFail)
* CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by CloudFlare in the hopes of discovering the location of the server.

[discover - Kali Scripts](https://github.com/leebaird/discover)
* For use with Kali Linux - custom bash scripts used to automate various portions of a pentest.

[Firewalk](http://packetfactory.openwall.net/projects/firewalk/)
* Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a  given IP forwarding device will pass. Firewalk  works  by sending out TCP or UDP packets with a TTL one greater than the targeted gateway.  If the gateway allows the traffic, it will forward the packets to the next hop where they will expire and elicit an ICMP_TIME_EXCEEDED  message.  If the gateway hostdoes not allow the traffic, it will likely drop the packets on  the floor and we will see no response. To get  the  correct  IP  TTL that will result in expired packets one beyond the gateway we need  to  ramp  up  hop-counts.   We  do  this  in the same manner that traceroute works.  Once we have the gateway hopcount (at  that point the scan is said to be `bound`) we can begin our scan.

[CiscoRouter - tool](https://github.com/ajohnston9/ciscorouter)
* CiscoRouter is a tool for scanning Cisco-based routers over SSH. Rules can be created using accompanying CiscoRule application (see this repo) and stored in the "rules" directory.



#### SSH: 

[ssh-audit](https://github.com/arthepsy/ssh-audit)
* SSH server auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)




#### SQL:

[SQLMap](https://github.com/sqlmapproject/sqlmap)
* sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

[PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server](https://github.com/NetSPI/PowerUpSQL)
* The PowerUpSQL module includes functions that support SQL Server discovery, auditing for common weak configurations, and privilege escalation on scale. It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that could be used by administrators to quickly inventory the SQL Servers in their ADS domain.
* [Documentation](https TLS/SSL Vulnerabilities ://github.com/NetSPI/PowerUpSQL/wiki)
* [Overview of PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki/Overview-of-PowerUpSQL)







#### Netbios:

[NbtScan](http://www.unixwiz.net/tools/nbtscan.html)
* This is a command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network, and this is a first step in finding of open shares. It is based on the functionality of the standard Windows tool nbtstat, but it operates on a range of addresses instead of just one. I wrote this tool because the existing tools either didn't do what I wanted or ran only on the Windows platforms: mine runs on just about everything.



#### SMTP:


#### SNMP:

[Onesixtyone](http://www.phreedom.org/software/onesixtyone/)
* onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance. It can scan an entire class B network in under 13 minutes. It can be used to discover devices responding to well-known community names or to mount a dictionary attack against one or more SNMP devices.

[SNMPWALK](http://net-snmp.sourceforge.net/docs/man/snmpwalk.html)
*  snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests



#### SIP:

[sipvicious](https://github.com/EnableSecurity/sipvicious)




#### MISC:
[t50 - the fastest packet injector.](https://github.com/fredericopissarra/t50)
* T50 was designed to perform “Stress Testing”  on a variety of infra-structure
network devices (Version 2.45), using widely implemented protocols, and after
some requests it was was re-designed to extend the tests (as of Version 5.3),
covering some regular protocols (ICMP,  TCP  and  UDP),  some infra-structure
specific protocols (GRE,  IPSec  and  RSVP), and some routing protocols (RIP,
EIGRP and OSPF).

[gateway-finder](https://github.com/pentestmonkey/gateway-finder)
* Gateway-finder is a scapy script that will help you determine which of the systems on the local LAN has IP forwarding enabled and which can reach the Internet.

[a](https://github.com/fmtn/a)
* ActiveMQ CLI testing and message management

[OnionScan](https://github.com/s-rah/onionscan)
* [What OnionScan Scans for](https://github.com/s-rah/onionscan/blob/master/doc/what-is-scanned-for.md)






#### Web:

[WPScan](https://github.com/wpscanteam/wpscan)
* WPScan is a black box WordPress vulnerability scanner.

[WhatWeb](https://github.com/urbanadventurer/WhatWeb)
* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.

[webDisco](https://github.com/joeybelans/webDisco)
* Web discovery tool to capture screenshots from a list of hosts & vhosts.  Requests are made via IP address and vhosts to determine differences. Additionallty checks for common administrative interfaces and web server  misconfigurations.

[w3af](https://github.com/andresriancho/w3af)
* w3af: web application attack and audit framework, the open source web vulnerability scanner.






-------------------------------
## Network Share Discovery

[Network Share Discovery - ATT&CK](Network Share Discovery)


[Get-SmbShare](https://technet.microsoft.com/en-us/library/jj635704(v=wps.630).aspx)
* Retrieves the Server Message Block (SMB) shares on the computer.

[NetResView](http://www.nirsoft.net/utils/netresview.html)
* NetResView is a small utility that displays the list of all network resources (computers, disk shares, and printer shares) on your LAN. As opposed to "My Network Places" module of Windows, NetResView display all network resources from all domains/workgroups in one screen, and including admin/hidden shares. 

[List Shares in Windows w/ PowerShell](http://krypted.com/windows-server/list-shares-in-windows-w-powershell/)
* '''
The command, from PowerShell would be something similar to the following:

    get-WmiObject -class Win32_Share 

Assuming communication is working as intended, you can also query for the shares of other systems, by adding a -computer switch and specifying the host you’re listing shares on, as follows:

    get-WmiObject -class Win32_Share -computer dc1.krypted.com

One can also list shared printers with a little trickeration in the {} side of things:
get-WmiObject -list | where {$_.name -match “Printer”}
'''

[Can you use a powershell script to find all shares on servers? - serverfault](https://serverfault.com/questions/623710/can-you-use-a-powershell-script-to-find-all-shares-on-servers)

[Find shares with PowerShell where Everyone has Full Control permissions](https://4sysops.com/archives/find-shares-with-powershell-where-everyone-has-full-control-permissions/)

[Obtain a list of non-admin file shares from multiple Windows servers](https://stackoverflow.com/questions/33873961/obtain-a-list-of-non-admin-file-shares-from-multiple-windows-servers)

[Nmap NSE - smb-enum-shares](https://nmap.org/nsedoc/scripts/smb-enum-shares.html)
*  Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.  Running NetShareEnumAll will work anonymously against Windows 2000, and requires a user-level account on any other Windows version. Calling NetShareGetInfo requires an administrator account on all versions of Windows up to 2003, as well as Windows Vista and Windows 7, if UAC is turned down. Even if NetShareEnumAll is restricted, attempting to connect to a share will always reveal its existence. So, if NetShareEnumAll fails, a pre-generated list of shares, based on a large test network, are used. If any of those succeed, they are recorded. 







-------------------------------
## Peripheral Device Discovery

[Peripheral Device Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1120)
* Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. The information may be used to enhance their awareness of the system and network environment or may be used for further actions. 

[USBView](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/usbview)
* USBView (Universal Serial Bus Viewer, Usbview.exe) is a Windows graphical user interface application that enables you to browse all USB controllers and connected USB devices on your computer. USBView works on all versions of Windows.

[How to Analyze USB Device History in Windows](https://www.magnetforensics.com/computer-forensics/how-to-analyze-usb-device-history-in-windows/)

[USBDeview v2.71](http://www.nirsoft.net/utils/usb_devices_view.html)
* USBDeview is a small utility that lists all USB devices that currently connected to your computer, as well as all USB devices that you previously used. For each USB device, extended information is displayed: Device name/description, device type, serial number (for mass storage devices), the date/time that device was added, VendorID, ProductID, and more... 






-------------------------------
## Permission Groups Discovery

[Permission Groups Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1069)
* Adversaries may attempt to find local system or domain-level groups and permissions settings. 
* Examples of commands that can list groups are net group /domain and net localgroup using the Net utility. 


[Local Users and Groups overview - technet](https://technet.microsoft.com/en-us/library/cc770756(v=ws.11).aspx)

[Managing Permissions - technet](https://technet.microsoft.com/en-us/library/cc770962(v=ws.11).aspx)

[Windows: View “all” permissions of a specific user or group](https://superuser.com/questions/613160/windows-view-all-permissions-of-a-specific-user-or-group)

[BloodHound](https://github.com/BloodHoundAD/BloodHound)
* BloodHound is a single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a PowerShell ingestor. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.





-------------------------------
## Process Discovery

[Process Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1057)

[Get-Process - msdn](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-5.1)
* Gets the processes that are running on the local computer or a remote computer.

[Using the Get-Process Cmdlet - technet](https://technet.microsoft.com/en-us/library/ee176855.aspx)

[Windows PowerShell Examples Featuring Get-Process](https://www.reddit.com/r/netsec/comments/3goktw/obtaining_domain_administrator_credentials_in_17/)

[Linux “Top” command for Windows Powershell? - superuser](https://superuser.com/questions/176624/linux-top-command-for-windows-powershell)








-------------------------------
## Query Registry

[Query Registry - ATT&CK](https://attack.mitre.org/wiki/Technique/T1012)
* Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. The Registry contains a significant amount of information about the operating system, configuration, software, and security.1 Some of the information may help adversaries to further their operation within a network. 

[Windows Registry - Wikipedia](https://en.wikipedia.org/wiki/Windows_Registry)

[Reg - technet](https://technet.microsoft.com/en-us/library/cc732643.aspx)

[Reg query](https://technet.microsoft.com/en-us/library/cc742028(v=ws.11).aspx)

[How do I read values of registry keys? - superuser](https://superuser.com/questions/1117040/how-do-i-read-values-of-registry-keys)

[Using the Get-ItemProperty Cmdlet - technet](https://technet.microsoft.com/en-us/library/ee176852.aspx)

[Working with Registry Keys - ms docs](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/cookbooks/working-with-registry-keys?view=powershell-5.1)

[How can I get the value of a registry key from within a batch script? - stackoverflow](https://stackoverflow.com/questions/445167/how-can-i-get-the-value-of-a-registry-key-from-within-a-batch-script)






-------------------------------
## Remote System Discovery

[Remote System Discovery](https://attack.mitre.org/wiki/Technique/T1018)
* Adversaries will likely attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used. 

Check .hosts file for mappings ; C:\Windows\System32\Drivers\etc\hosts

[arp](https://technet.microsoft.com/en-us/library/cc940107.aspx)

[Port scan subnets with PSnmap for PowerShell](http://www.powershelladmin.com/wiki/Port_scan_subnets_with_PSnmap_for_PowerShell)

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
* PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net *" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.

[Invoke-HostEnum.ps1](https://github.com/minisllc/red-team-scripts/blob/master/Invoke-HostEnum.ps1)
* Performs local host and/or domain enumeration for situational awareness

[Network Situational Awareness with Empire](http://www.powershellempire.com/?page_id=289)


-------------------------------
## Security Software Discovery


[Security Software Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1063)
* Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules, anti-virus, and virtualization. These checks may be built into early-stage remote access tools. 

[Use Powershell to quickly find installed Software](https://blogs.technet.microsoft.com/heyscriptingguy/2011/11/13/use-powershell-to-quickly-find-installed-software/)

[Netsh AdvFirewall Firewall Commands - technet](https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx)
* netsh advfirewall monitor show firewall rule name=all dir=in

[Information about installed antivirus software on local or remote machines - gallery.technet](https://gallery.technet.microsoft.com/scriptcenter/Information-about-bf8b201f)
* Script is checking status of installed avtivirus software on local or remote machine(s).Script is using WMI query to get information of installed antivirus products.At the moment there is support for Windows XP SP3, Vista SP2, 7, 8, 8.1 and 10.

[Powershell : How to get Antivirus product details - stackoverflow](https://stackoverflow.com/questions/33649043/powershell-how-to-get-antivirus-product-details)

[Getting the installed Antivirus, AntiSpyware and Firewall software using Delphi and the WMI - 2011](https://theroadtodelphi.com/2011/02/18/getting-the-installed-antivirus-antispyware-and-firewall-software-using-delphi-and-the-wmi/)

[Listing Windows Firewall Rules Using Microsoft PowerShell](http://carlwebster.com/listing-windows-firewall-rules-using-microsoft-powershell/)

[Get-NetFirewallRule - technet](https://technet.microsoft.com/en-us/library/jj554860(v=wps.630).aspx)
* Retrieves firewall rules from the target computer.






-------------------------------
## System Information Discovery

[System Information Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1082)
* An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. 

[Systeminfo - technet](https://technet.microsoft.com/en-us/library/bb491007.aspx)
* Displays detailed configuration information about a computer and its operating system, including operating system configuration, security information, product ID, and hardware properties, such as RAM, disk space, and network cards.

[GetSystemInfo function - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724381(v=vs.85).aspx)
* Retrieves information about the current system.

[Use PowerShell to Quickly Find Installed Software - technet](https://blogs.technet.microsoft.com/heyscriptingguy/2011/11/13/use-powershell-to-quickly-find-installed-software/)

[How to use System Information (MSINFO32) command-line tool switches - ms support](https://support.microsoft.com/en-us/help/300887/how-to-use-system-information-msinfo32-command-line-tool-switches)

[How to view all your installed programs with one mighty PowerShell command](http://www.fixedbyvonnie.com/2014/07/view-installed-programs-one-powershell-command/)










-------------------------------
## System Network Configuration Discovery

[System Network Configuration Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1016)
* Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route. 

[Netstat - technet](https://technet.microsoft.com/en-us/library/bb490947.aspx)
* Displays active TCP connections, ports on which the computer is listening, Ethernet statistics, the IP routing table, IPv4 statistics (for the IP, ICMP, TCP, and UDP protocols), and IPv6 statistics (for the IPv6, ICMPv6, TCP over IPv6, and UDP over IPv6 protocols). Used without parameters, netstat displays active TCP connections.

[Listing Windows Firewall Rules Using Microsoft PowerShell](http://carlwebster.com/listing-windows-firewall-rules-using-microsoft-powershell/)

[Arp - technet](https://technet.microsoft.com/en-us/library/cc940107.aspx)
* Arp allows you to view and modify the ARP cache. 

[Route - technet](https://technet.microsoft.com/en-us/library/bb490991.aspx)
* Displays and modifies the entries in the local IP routing table. Used without parameters, route displays help.

[NetBIOS over TCP/IP - Wikipedia](https://en.wikipedia.org/wiki/NetBIOS_over_TCP/IP)

[Nbtstat - technet](https://technet.microsoft.com/en-us/library/cc940106.aspx)
* Nbtstat is designed to help troubleshoot NetBIOS name resolution problems. When a network is functioning normally, NetBIOS over TCP/IP (NetBT) resolves NetBIOS names to IP addresses. It does this through several options for NetBIOS name resolution, including local cache lookup, WINS server query, broadcast, LMHOSTS lookup, Hosts lookup, and DNS server query.

[Ipconfig](https://technet.microsoft.com/en-us/library/cc940124.aspx)
* IPConfig is a command-line tool that displays the current configuration of the installed IP stack on a networked computer.








-------------------------------
## System Network Connections Discovery

[System Network Connections Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1049)
* Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 

[Netstat - technet](https://technet.microsoft.com/en-us/library/bb490947.aspx)
* Displays active TCP connections, ports on which the computer is listening, Ethernet statistics, the IP routing table, IPv4 statistics (for the IP, ICMP, TCP, and UDP protocols), and IPv6 statistics (for the IPv6, ICMPv6, TCP over IPv6, and UDP over IPv6 protocols). Used without parameters, netstat displays active TCP connections.

[netstat - Wikipedia](https://en.wikipedia.org/wiki/Netstat)







-------------------------------
## System Owner/User Discovery

[System Owner/User Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1033)
* Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. 

[List All User Accounts on a Windows System via Command Line](https://superuser.com/questions/608931/list-all-user-accounts-on-a-windows-system-via-command-line)

[WINDOWS ENUMERATION: USERINFO AND USERDUMP - old](http://www.carnal0wnage.com/papers/userinfouserdump.pdf)

[How To Accurately Enumerate Windows User Profiles With PowerShell](https://blog.ipswitch.com/how-to-accurately-enumerate-windows-user-profiles-with-powershell)



-------------------------------
## System Service Discovery
[System Service Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1007)
* Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are "sc," "tasklist /svc" using Tasklist, and "net start" using Net, but adversaries may also use other tools as well. 

[Net Commands On Windows Operating Systems - support ms](https://support.microsoft.com/en-us/help/556003)

[NET.exe - ss64](https://ss64.com/nt/net-service.html)

[SC - technet](https://technet.microsoft.com/en-us/library/bb490995.aspx)
* Communicates with the Service Controller and installed services. SC.exe retrieves and sets control information about services. You can use SC.exe for testing and debugging service programs. Service properties stored in the registry can be set to control how service applications are started at boot time and run as background processes. SC.exe parameters can configure a specific service, retrieve the current status of a service, as well as stop and start a service. You can create batch files that call various SC.exe commands to automate the startup or shutdown sequence of services. SC.exe provides capabilities similar to Services in the Administrative Tools item in Control Panel. 

[Tasklist](https://technet.microsoft.com/en-us/library/bb491010.aspx)
* Displays a list of applications and services with their Process ID (PID) for all tasks running on either a local or a remote computer.



-------------------------------
## System Time Discovery
[System Time Discovery - ATT&CK](https://attack.mitre.org/wiki/Technique/T1124)
* The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network. An adversary may gather the system time and/or time zone from a local or remote system. This information may be gathered in a number of ways, such as with Net on Windows by performing net time \\hostname to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using w32tm /tz. The information could be useful for performing other techniques, such as executing a file with a Scheduled Task, or to discover locality information based on time zone to assist in victim targeting. 

[W32tm - technet](https://technet.microsoft.com/en-us/library/bb491016.aspx)
* A tool used to diagnose problems occurring with Windows Time

[W32tm](https://technet.microsoft.com/en-us/library/ff799054(v=ws.11).aspx)
* W32tm command reference










