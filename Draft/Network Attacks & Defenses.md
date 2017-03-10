##Network Attacks & Defenses



[Fundamentals That Time Forgot - Jup1t3r  - BSides SLC](https://www.youtube.com/watch?v=PQvUWImljOw)
TOC

*Cull

*[Attacking Windows Networks](#attackw)
* [Tools](#tools)
* [Writeups](#writeup)
* [Presentations/Talks](#talks)
* [IPv4 info](#ipv4)
* [IPv6 info](#ipv6)
* [IDS/IPS Evasion](#evasion)
* [UPNP](#upnp)



#####To be sorted

[More on HNAP - What is it, How to Use it,How to Find it](https://isc.sans.edu/diary/More+on+HNAP+-+What+is+it%2C+How+to+Use+it%2C+How+to+Find+it/17648)

[iv-wrt](https://github.com/iv-wrt/iv-wrt)
* An Intentionally Vulnerable Router Firmware Distribution[

http://www.pentest-standard.org/index.php/Intelligence_Gathering

#####sort end





### General

[NMAP - Port-Scanning: A Practical Approach Modified for better](https://www.exploit-db.com/papers/35425/)

[A Curated list of assigned ports relevant to pen testing](http://www.vulnerabilityassessment.co.uk/ports.htm)

[pynessus](https://github.com/rmusser01/pynessus)
* Python Parser for Nessus Output
* [Examples](http://www.hackwhackandsmack.com/?p=422)

[TCPDump Primer](http://danielmiessler.com/study/tcpdump/)

[IANA Complete list of assigned ports](http://www.vulnerabilityassessment.co.uk/port-numbers.txt)

[Simple Network Management Pwnd](http://www.irongeek.com/i.php?page=videos/derbycon4/t221-simple-network-management-pwnd-deral-heiland-and-matthew-kienow)





###<a name="attackw">Attacking Windows Networks</a>

[ *Puff* *Puff* PSExec - Lateral Movement: An Overview](https://www.toshellandback.com/2017/02/11/psexec/)

[Ditch PsExec, SprayWMI is here ;)](http://www.pentest.guru/index.php/2015/10/19/ditch-psexec-spraywmi-is-here/)


[WMIOps](https://github.com/ChrisTruncer/WMIOps)
* WMIOps is a powershell script that uses WMI to perform a variety of actions on hosts, local or remote, within a Windows environment. It's designed primarily for use on penetration tests or red team engagements.

[Dumping a Domain’s Worth of Passwords With Mimikatz pt. 2](http://www.harmj0y.net/blog/powershell/dumping-a-domains-worth-of-passwords-with-mimikatz-pt-2/)

[spraywmi](https://github.com/trustedsec/spraywmi)
* SprayWMI is a method for mass spraying Unicorn PowerShell injection to CIDR notations.

[psexec](https://github.com/pentestgeek/smbexec)
* A rapid psexec style attack with samba tools
* [Blogpost that inspired it](http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html)

[Sparty - MS Sharepoint and Frontpage Auditing Tool](http://sparty.secniche.org/)
*  Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture. The motivation behind this tool is to provide an easy and robust way to scrutinize the security configurations of sharepoint and frontpage based web applications. Due to the complex nature of these web administration software, it is required to have a simple and efficient tool that gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. A number of automated scanners fall short of this and Sparty is a solution to that.

[Responder](https://github.com/SpiderLabs/Responder/)
* Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.

[SPScan]http://sourceforge.net/projects/spscan/)
* SPScan is a tool written in Ruby that enumerates a SharePoint installation gathering information about the version and installed plugins.

[SPartan](https://github.com/sensepost/SPartan)
* SPartan is a Frontpage and Sharepoint fingerprinting and attack tool

[MS Network Level Authentication](https://technet.microsoft.com/en-us/magazine/hh750380.aspx)

[Dragon: A Windows, non-binding, passive download / exec backdoor](http://www.shellntel.com/blog/2015/6/11/dragon-a-windows-non-binding-passive-downloadexec-backdoor)

[ms15-034.nse Script](https://github.com/pr4jwal/quick-scripts/blob/master/ms15-034.nse)









###<a name="tools">Tools</a>

[digbit](https://github.com/mnmnc/digbit/blob/master/README.md)
* Automatic domain generation for BitSquatting

[discover - Kali Scripts](https://github.com/leebaird/discover)
* For use with Kali Linux - custom bash scripts used to automate various portions of a pentest.

[w3af](https://github.com/andresriancho/w3af)
* w3af: web application attack and audit framework, the open source web vulnerability scanner.

[Yersinia](http://www.yersinia.net/)
* Yersinia is a network tool designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. 
[CiscoRouter - tool](https://github.com/ajohnston9/ciscorouter)
* CiscoRouter is a tool for scanning Cisco-based routers over SSH. Rules can be created using accompanying CiscoRule application (see this repo) and stored in the "rules" directory.

[UPnP Pentest Toolkit](https://github.com/nccgroup/UPnP-Pentest-Toolkit)

[NbtScan](http://www.unixwiz.net/tools/nbtscan.html)
* This is a command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network, and this is a first step in finding of open shares. It is based on the functionality of the standard Windows tool nbtstat, but it operates on a range of addresses instead of just one. I wrote this tool because the existing tools either didn't do what I wanted or ran only on the Windows platforms: mine runs on just about everything. 

[netcat](http://nc110.sourceforge.net/)
* Network Swiss army knife. Ncat’s predecessor. Does everything and the kitchen sink.

[Ncat](http://nmap.org/)
* Ncat is a feature-packed networking utility which reads and writes data across networks from the command line. Ncat was written for the Nmap Project as a much-improved reimplementation of the venerable Netcat. It uses both TCP and UDP for communication and is designed to be a reliable back-end tool to instantly provide network connectivity to other applications and users. Ncat will not only work with IPv4 and IPv6 but provides the user with a virtually limitless number of potential uses. 

[DNSEnum](https://github.com/fwaeytens/dnsenum)
* Multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.

[Enum4Linux](https://labs.portcullis.co.uk/tools/enum4linux/)
* Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com. It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. The tool usage can be found below followed by examples, previous versions of the tool can be found at the bottom of the page.

[TXTDNS](http://www.txdns.net/)
* TXDNS is a Win32 aggressive multithreaded DNS digger. Capable of placing, on the wire, thousands of DNS queries per minute. TXDNS main goal is to expose a domain namespace trough a number of techniques: Typos: Mised, doouble and transposde keystrokes; TLD/ccSLD rotation; Dictionary attack; Full Brute-force attack using alpha, numeric or alphanumeric charsets; Reverse grinding.

[JXplorer](http://jxplorer.org/)
* JXplorer is a cross platform LDAP browser and editor. It is a standards compliant general purpose LDAP client that can be used to search, read and edit any standard LDAP directory, or any directory service with an LDAP or DSML interface. It is highly flexible and can be extended and customised in a number of ways. JXplorer is written in java, and the source code and Ant build system are available via svn or as a packaged build for users who want to experiment or further develop the program. 	

[LDAPMfINER](http://ldapminer.sourceforge.net/)
* This is a tool I wrote to collect information from different LDAP Server implementation. This was written in C with the Netscape C 


[Firewalk](http://packetfactory.openwall.net/projects/firewalk/)
* Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a  given IP forwarding device will pass. Firewalk  works  by sending out TCP or UDP packets with a TTL one greater than the targeted gateway.  If the gateway allows the traffic, it will forward the packets to the next hop where they will expire and elicit an ICMP_TIME_EXCEEDED  message.  If the gateway hostdoes not allow the traffic, it will likely drop the packets on  the floor and we will see no response. To get  the  correct  IP  TTL that will result in expired packets one beyond the gateway we need  to  ramp  up  hop-counts.   We  do  this  in the same manner that traceroute works.  Once we have the gateway hopcount (at  that point the scan is said to be `bound`) we can begin our scan.

[Softera LDAP Browser](http://www.ldapbrowser.com/info_softerra-ldap-browser.htm)
* LDAP Browser that supports most LDAP implementations. Non-free software, 30-day free trial 

[Tinfoleak](http://vicenteaguileradiaz.com/tools/)
* tinfoleak is a simple Python script that allow to obtain:
..* basic information about a Twitter user (name, picture, location, followers, etc.)
..* devices and operating systems used by the Twitter user
..* applications and social networks used by the Twitter user
..* place and geolocation coordinates to generate a tracking map of locations visited
..* show user tweets in Google Earth!
..* download all pics from a Twitter user
..* hashtags used by the Twitter user and when are used (date and time)
..* user mentions by the the Twitter user and when are occurred (date and time)
..* topics used by the Twitter user

[net-creds](https://github.com/DanMcInerney/net-creds)
* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification
* It sniffs: URLs visited; POST loads sent; HTTP form logins/passwords; HTTP basic auth logins/passwords; HTTP searches; FTP logins/passwords; IRC logins/passwords; POP logins/passwords; IMAP logins/passwords; Telnet logins/passwords; SMTP logins/passwords; SNMP community string; NTLMv1/v2 all supported protocols like HTTP, SMB, LDAP, etc; Kerberos.

[RANCID - Really Awesome New Cisco confIg Differ](http://www.shrubbery.net/rancid/)
* RANCID monitors a router's (or more generally a device's) configuration, including software and hardware (cards, serial numbers, etc) and uses CVS (Concurrent Version System) or Subversion to maintain history of changes.
* RANCID does this by the very simple process summarized as: login to each device in the router table (router.db), run various commands to get the information that will be saved, cook the output; re-format, remove oscillating or incrementing data, email any differences (sample) from the previous collection to a mail list, and finally commit those changes to the revision control system

[Stenographer](https://github.com/google/stenographer/blob/master/README.md)
* Stenographer is a full-packet-capture utility for buffering packets to disk for intrusion detection and incident response purposes. It provides a high-performance implementation of NIC-to-disk packet writing, handles deleting those files as disk fills up, and provides methods for reading back specific sets of packets quickly and easily.

[Netview](https://github.com/mubix/netview)
* Netview is a enumeration tool. It uses (with the -d) the current domain or a specified domain (with the -d domain) to enumerate hosts

[DNS Recon](https://github.com/darkoperator/dnsrecon)

[DNS Dumpster](DNSdumpster.com is a free domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process.)










###MitM Tools
[Ettercap](https://ettercap.github.io/ettercap/)
Ettercap is a comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.

[Dsniff](http://www.monkey.org/~dugsong/dsniff/)
dsniff is a collection of tools for network auditing and penetration testing. dsniff, filesnarf, mailsnarf, msgsnarf, urlsnarf, and webspy passively monitor a network for interesting data (passwords, e-mail, files, etc.). arpspoof, dnsspoof, and macof facilitate the interception of network traffic normally unavailable to an attacker (e.g, due to layer-2 switching). sshmitm and webmitm implement active monkey-in-the-middle attacks against redirected SSH and HTTPS sessions by exploiting weak bindings in ad-hoc PKI. 

[SSLsplit - transparent and scalable SSL/TLS interception](https://www.roe.ch/SSLsplit)
* SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit. SSLsplit terminates SSL/TLS and initiates a new SSL/TLS connection to the original destination address, while logging all data transmitted. SSLsplit is intended to be useful for network forensics and penetration testing.  SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6.







###Scanners

[SQLMap](https://github.com/sqlmapproject/sqlmap)
* sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

[DNSRecon](https://github.com/darkoperator/dnsrecon)
* [Quick Reference Guide](http://pentestlab.wordpress.com/2012/11/13/dns-reconnaissance-dnsrecon/)

[WPScan](https://github.com/wpscanteam/wpscan)
* WPScan is a black box WordPress vulnerability scanner.


[Enumerator](https://pypi.python.org/pypi/enumerator/0.1.4)
* enumerator is a tool built to assist in automating the often tedious task of enumerating a target or list of targets during a penetration test.

[Unicornscan](http://www.unicornscan.org/)
* Unicornscan is a new information gathering and correlation engine built for and by members of the security research and testing communities. It was designed to provide an engine that is Scalable, Accurate, Flexible, and Efficient. It is released for the community to use under the terms of the GPL license. 

[hostmap](https://github.com/jekil/hostmap)
* hostmap is a free, automatic, hostnames and virtual hosts discovery tool written in Ruby by Alessandro Tanasi

[Nmap](http://nmap.org/)
* Nmap ("Network Mapper") is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping). 

[Angry IP Scanner](http://angryip.org/
* Angry IP Scanner (or simply ipscan) is an open-source and cross-platform network scanner designed to be fast and simple to use. It scans IP addresses and ports as well as has many other features. 

[UnicornScan](http://www.unicornscan.org/)
* Unicornscan is a new information gathering and correlation engine built for and by members of the security research and testing communities. It was designed to provide an engine that is Scalable, Accurate, Flexible, and Efficient. It is released for the community to use under the terms of the GPL license. 
* My note: Use this to mass scan networks. It’s faster than nmap at scanning large host lists and allows you to see live hosts quickly.

[hping](http://www.hping.org/)
* hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface is inspired to the ping(8) unix command, but hping isn't only able to send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode, the ability to send files between a covered channel, and many other features. 

[Onesixtyone](http://www.phreedom.org/software/onesixtyone/)
* onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance. It can scan an entire class B network in under 13 minutes. It can be used to discover devices responding to well-known community names or to mount a dictionary attack against one or more SNMP devices.

[WhatWeb](https://github.com/urbanadventurer/WhatWeb)
* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.

[Consul](https://github.com/hashicorp/consul)
* Consul is a tool for service discovery and configuration. Consul is distributed, highly available, and extremely scalable.

[SNMPWALK](http://net-snmp.sourceforge.net/docs/man/snmpwalk.html)
*  snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests

[webDisco](https://github.com/joeybelans/webDisco)
* Web discovery tool to capture screenshots from a list of hosts & vhosts.  Requests are made via IP address and vhosts to determine differences. Additionallty checks for common administrative interfaces and web server  misconfigurations. 









####Proxies

[Mallory](https://bitbucket.org/IntrepidusGroup/mallory)
*  Mallory is an extensible TCP/UDP man in the middle proxy that is designed  to be run as a gateway. Unlike other tools of its kind, Mallory supports  modifying non-standard protocols on the fly.

[SSLStrip](http://www.thoughtcrime.org/software/sslstrip/)
* This tool provides a demonstration of the HTTPS stripping attacks that I presented at Black Hat DC 2009. It will transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.

[Zed Attack Proxy (ZAP) Community Scripts](https://github.com/zaproxy/community-scripts)
* A collection of ZAP scripts provided by the community - pull requests very welcome! 

[Echo Mirage](http://www.wildcroftsecurity.com/echo-mirage)
* Echo Mirage is a generic network proxy. It uses DLL injection and function hooking techniques to redirect network related function calls so that data transmitted and received by local applications can be observed and modified. Windows encryption and OpenSSL functions are also hooked so that plain text of data being sent and received over an encrypted session is also available. Traffic can be intercepted in real-time, or manipulated with regular expressions and a number of action directives


[Burp Proxy](http://portswigger.net/burp/proxy.html)
* Burp Proxy is an intercepting proxy server for security testing of web applications. It operates as a man-in-the-middle between your browser and the target application

[Phreebird](http://dankaminsky.com/phreebird/) 
* Phreebird is a DNSSEC proxy that operates in front of an existing DNS server (such as BIND, Unbound, PowerDNS, Microsoft DNS, or QIP) and supplements its records with DNSSEC responses. Features of Phreebird include automatic key generation, realtime record signing, support for arbitrary responses, zero configuration, NSEC3 “White Lies”, caching and rate limiting to deter DoS attacks, and experimental support for both Coarse Time over DNS and HTTP Virtual Channels. The suite also contains a large amount of sample code, including support for federated identity over OpenSSH. Finally, “Phreeload” enhances existing OpenSSL applications with DNSSEC support.

[TCP Catcher](http://www.tcpcatcher.org/)
* TcpCatcher is a free TCP, SOCKS, HTTP and HTTPS proxy monitor server software. 





###<a name="talks">Presentations/Talks/Videos</a>

[Mass Scanning the Internet: Tips, Tricks, Results - DEF CON 22 - Graham, Mcmillan, and Tentler](https://www.youtube.com/watch?v=nX9JXI4l3-E)


[DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
* Great talk on attacking DNS

[DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
* Great talk on attacking DNS

[ C3CM: Defeating the Command - Control - and Communications of Digital Assailants](http://www.irongeek.com/i.php?page=videos/derbycon4/t206-c3cm-defeating-the-command-control-and-communications-of-digital-assailants-russ-mcree)
* C3CM: the acronym for command- control- and communi - cations countermeasures. Ripe for use in the information security realm, C3CM takes us past C2 analysis and to the next level. Initially, C3CM was most often intended to wreck the command and control of enemy air defense networks, a very specific military mission. We’ll apply that mindset in the context of combating bots and other evil. Our version of C3CM therefore is to identify, interrupt, and counter the command, control, and communications capabilities of our digital assailants. The three phases of C3CM will utilize: Nfsight with Nfdump, Nfsen, and fprobe to conduct our identification phase, Bro with Logstash and Kibana for the interruption phase, and ADHD for the counter phase. Converge these on one useful platform and you too might have a chance deter those who would do you harm. We’ll discuss each of these three phases (identify, interrupt, and counter) with tooling and tactics, complete with demonstrations and methodology attendees can put to use in their environments. Based on the three part ISSA Journal Toolsmith series: http://holisticinfosec. blogspot.com/search?q=c3cm&max-results=20&by-date=true





###<a name="writeup">Writeups & Tutorials</a>

[Enumerating DNSSEC NSEC and NSEC3 Records](https://www.altsci.com/concepts/page.php?s=dnssec&p=1

[DNS database espionage](http://dnscurve.org/espionage2.html)

[Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)

* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it’s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What’s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."

[Enumerating DNSSEC NSEC and NSEC3 Records](https://www.altsci.com/concepts/page.php?s=dnssec&p=1)

[Bitsquatting: DNS Hijacking without exploitation](http://dinaburg.org/bitsquatting.html)







###<a name="ipv6">IPv6 Related</a>

IPv6: Basic Attacks and Defences - Christopher Werny[TROOPERS15]
 * [Part 1](https://www.youtube.com/watch?v=Y8kjQEGHbAU)
* [Part 2](https://www.youtube.com/watch?v=V-GYPp-j-lE)

[Exploiting Tomorrow's Internet Today: Penetration testing with IPv6](http://uninformed.org/?v=all&a=46&t=sumry)
* This paper illustrates how IPv6-enabled systems with link-local and auto-configured addresses can be compromised using existing security tools. While most of the techniques described can apply to "real" IPv6 networks, the focus of this paper is to target IPv6-enabled systems on the local network. 

[IPv6 Toolkit](https://github.com/fgont/ipv6toolkit)
* SI6 Networks' IPv6 Toolkit

[THC-IPv6](https://www.thc.org/thc-ipv6/)
*  A complete tool set to attack the inherent protocol weaknesses of IPV6
 and ICMP6, and includes an easy to use packet factory library.

[[TROOPERS15] Merike Kaeo - Deploying IPv6 Securely - Avoiding Mistakes Others Have Made](https://www.youtube.com/watch?v=rQg4y78xHf8)






###<a name="evasion">IDS/IPS Evasion</a>


[Intrusion detection evasion:  How Attackers get past the burglar alarm](http://www.sans.org/reading-room/whitepapers/detection/intrusion-detection-evasion-attackers-burglar-alarm-1284)
* The purpose of this paper is to show methods that attackers can use to fool IDS systems into thinking their attack is legitimate traffic. With techniques like obfuscation, fragmentation, Denial of Service, and application hijacking the attacker can pass traffic under the nose of an IDS to prevent their detection. These are techniques that the next generation of IDS needs to be able to account for and prevent. Since it would be almost impossible to create a product that was not vulnerable to one of these deceptions.


[Beating the IPS](http://www.sans.org/reading-room/whitepapers/intrusion/beating-ips-34137) 
* This paper introduces various Intrusion Prevention System (IPS) evasion techniques and shows how they can be used to successfully evade detection by widely used products from major security vendors. By manipulating the header, payload, and traffic flow of a well-known attack, it is possible to trick the IPS inspection engines into passing the traffic - allowing the attacker shell access to the target system protected by the IPS.

[Firewall/IDS Evasion and Spoofing](https://nmap.org/book/man-bypass-firewalls-ids.html)

[IDS/IPS Evasion Techniques - Alan Neville](http://www.redbrick.dcu.ie/~anev/IDS_IPS_Evasion_Techniques.pdf)

[Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://insecure.org/stf/secnet_ids/secnet_ids.html)http://insecure.org/stf/secnet_ids/secnet_ids.html)

[Evading IDS/IPS by Exploiting IPv6 Features - TROOPERS15] Antonios Atlasis, Rafael Schaefer](https://www.youtube.com/watch?v=avMeYIaU8DA&list=PL1eoQr97VfJni4_O1c3kBCCWwxu-6-lqy)

[wafw00f](https://github.com/sandrogauci/wafw00f) *  WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.

[HTTP Evasions Explained - Part 6 - Attack of the White-Space](http://noxxi.de/research/http-evader-explained-6-whitespace.html)
* This is part six in a series which will explain the evasions done by HTTP Evader. This part is about misusing white-space to bypass the firewall.

[Evading IDS/IPS by Exploiting IPv6 Features - Antonios Atlasis, Rafael Schaefer](https://www.youtube.com/watch?v=avMeYIaU8DA&list=PL1eoQr97VfJni4_O1c3kBCCWwxu-6-lqy)





###D/DOS



###Frameworks
[BackDoor Factory](https://github.com/secretsquirrel/the-backdoor-factory)
* The goal of BDF is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state.
* [Wiki](https://github.com/secretsquirrel/the-backdoor-factory/wiki)
* [Video](http://www.youtube.com/watch?v=jXLb2RNX5xs)

[Man-in-the-Middle Framework](https://github.com/byt3bl33d3r/MITMf)
*Framework for Man-In-The-Middle attacks

TCPDump 
[Command Examples](http://www.thegeekstuff.com/2010/08/tcpdump-command-examples/)


###<a name="upnp">UPNP</a>
Ufuzz - https://github.com/phikshun/ufuzz
UFuzz, or Universal Plug and Fuzz, is an automatic UPnP fuzzing tool. It will enumerate all UPnP endpoints on the network, find the available services and fuzz them. It also has the capability to fuzz HTTP using Burp proxy logs.

miranda-upnp - https://github.com/0x90/miranda-upnp







