##Network Attacks & Defenses


IPv4 info
IPv6 info

Firewalls
DMZs
VLAN
VPN


Nessus
Ncat
Hping
Nikto


###Cull
[TCPDump Primer](http://danielmiessler.com/study/tcpdump/)



Arp spoofing

Evilgrade installer injection

[Mallory](https://bitbucket.org/IntrepidusGroup/mallory)
*  Mallory is an extensible TCP/UDP man in the middle proxy that is designed  to be run as a gateway. Unlike other tools of its kind, Mallory supports  modifying non-standard protocols on the fly.



###IPv6 Related
[Exploiting Tomorrow's Internet Today: Penetration testing with IPv6](http://uninformed.org/?v=all&a=46&t=sumry)
* This paper illustrates how IPv6-enabled systems with link-local and auto-configured addresses can be compromised using existing security tools. While most of the techniques described can apply to "real" IPv6 networks, the focus of this paper is to target IPv6-enabled systems on the local network. 

[IPv6 Toolkit](https://github.com/fgont/ipv6toolkit)
* SI6 Networks' IPv6 Toolkit

[THC-IPv6](https://www.thc.org/thc-ipv6/)
*  A complete tool set to attack the inherent protocol weaknesses of IPV6
 and ICMP6, and includes an easy to use packet factory library.




###Tools


[Yersinia](http://www.yersinia.net/)
* Yersinia is a network tool designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. 
[CiscoRouter - tool](https://github.com/ajohnston9/ciscorouter)
* CiscoRouter is a tool for scanning Cisco-based routers over SSH. Rules can be created using accompanying CiscoRule application (see this repo) and stored in the "rules" directory.

[UPnP Pentest Toolkit](https://github.com/nccgroup/UPnP-Pentest-Toolkit)

[Responder](https://github.com/SpiderLabs/Responder/)
* Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.


###MitM Tools
[Ettercap](https://ettercap.github.io/ettercap/)
Ettercap is a comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.

[Dsniff](http://www.monkey.org/~dugsong/dsniff/)
dsniff is a collection of tools for network auditing and penetration testing. dsniff, filesnarf, mailsnarf, msgsnarf, urlsnarf, and webspy passively monitor a network for interesting data (passwords, e-mail, files, etc.). arpspoof, dnsspoof, and macof facilitate the interception of network traffic normally unavailable to an attacker (e.g, due to layer-2 switching). sshmitm and webmitm implement active monkey-in-the-middle attacks against redirected SSH and HTTPS sessions by exploiting weak bindings in ad-hoc PKI. 


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

####Proxies

[SSLStrip](http://www.thoughtcrime.org/software/sslstrip/)
* This tool provides a demonstration of the HTTPS stripping attacks that I presented at Black Hat DC 2009. It will transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.

[Zed Attack Proxy (ZAP) Community Scripts](https://github.com/zaproxy/community-scripts)
* A collection of ZAP scripts provided by the community - pull requests very welcome! 

[Echo Mirage](http://www.wildcroftsecurity.com/echo-mirage)
* Echo Mirage is a generic network proxy. It uses DLL injection and function hooking techniques to redirect network related function calls so that data transmitted and received by local applications can be observed and modified. Windows encryption and OpenSSL functions are also hooked so that plain text of data being sent and received over an encrypted session is also available. Traffic can be intercepted in real-time, or manipulated with regular expressions and a number of action directives

[Burp Proxy](http://portswigger.net/burp/proxy.html)
* Burp Proxy is an intercepting proxy server for security testing of web applications. It operates as a man-in-the-middle between your browser and the target application



###Presentations/Videos
[DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
* Great talk on attacking DNS



###IDS/IPS Evasion


[Intrusion detection evasion:  How Attackers get past the burglar alarm](http://www.sans.org/reading-room/whitepapers/detection/intrusion-detection-evasion-attackers-burglar-alarm-1284)
* The purpose of this paper is to show methods that attackers can use to fool IDS systems into thinking their attack is legitimate traffic. With techniques like obfuscation, fragmentation, Denial of Service, and application hijacking the attacker can pass traffic under the nose of an IDS to prevent their detection. These are techniques that the next generation of IDS needs to be able to account for and prevent. Since it would be almost impossible to create a product that was not vulnerable to one of these deceptions.

[Beating the IPS](http://www.sans.org/reading-room/whitepapers/intrusion/beating-ips-34137) * This paper introduces various Intrusion Prevention System (IPS) evasion techniques and shows how they can be used to successfully evade detection by widely used products from major security vendors. By manipulating the header, payload, and traffic flow of a well-known attack, it is possible to trick the IPS inspection engines into passing the traffic - allowing the attacker shell access to the target system protected by the IPS.

[Firewall/IDS Evasion and Spoofing](https://nmap.org/book/man-bypass-firewalls-ids.html)

[IDS/IPS Evasion Techniques - Alan Neville](http://www.redbrick.dcu.ie/~anev/IDS_IPS_Evasion_Techniques.pdf)

[Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://insecure.org/stf/secnet_ids/secnet_ids.html)http://insecure.org/stf/secnet_ids/secnet_ids.html)



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












