# Command and Control

* [MITRE ATT&CK - Command and Control](https://attack.mitre.org/wiki/Command_and_Control)
	* The command and control tactic represents how adversaries communicate with systems under their control within a target network. There are many ways an adversary can establish command and control with various levels of covertness, depending on system configuration and network topology. Due to the wide degree of variation available to the adversary at the network level, only the most common factors were used to describe the differences in command and control. There are still a great many specific techniques within the documented methods, largely due to how easy it is to define new protocols and use existing, legitimate protocols and network services for communication. 
	* The resulting breakdown should help convey the concept that detecting intrusion through command and control protocols without prior knowledge is a difficult proposition over the long term. Adversaries' main constraints in network-level defense avoidance are testing and deployment of tools to rapidly change their protocols, awareness of existing defensive technologies, and access to legitimate Web services that, when used appropriately, make their tools difficult to distinguish from benign traffic. 



## Commonly Used Port
-------------------------------
* [Commonly Used Port - ATT&CK](https://attack.mitre.org/wiki/Technique/T1043)
	* Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection.
* [List of TCP and UDP port numbers - Wikipedia](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)



## Communication Through Removable Media
-------------------------------
* [Communication Through Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1092)
	* Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access. 







## Connection Proxy
-------------------------------
* [Connection Proxy - ATT&CK](https://attack.mitre.org/wiki/Technique/T1090)
	* A connection proxy is used to direct network traffic between systems or act as an intermediary for network communications. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.Trend Micro APT Attack Tools 
	* The definition of a proxy can also be expanded out to encompass trust relationships between networks in peer-to-peer, mesh, or trusted connections between networks consisting of hosts or systems that regularly communicate with each other. 
	*  The network may be within a single organization or across organizations with trust relationships. Adversaries could use these types of relationships to manage command and control communications, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. 

* **TCP/UDP**
	* [Mallory](https://bitbucket.org/IntrepidusGroup/mallory)
		* Mallory is an extensible TCP/UDP man in the middle proxy that is designed  to be run as a gateway. Unlike other tools of its kind, Mallory supports  modifying non-standard protocols on the fly.
	* [TCP Catcher](http://www.tcpcatcher.org/)
		* TcpCatcher is a free TCP, SOCKS, HTTP and HTTPS proxy monitor server software. 
	* [Squid Proxy](http://www.squid-cache.org/)
		* Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator. It runs on most available operating systems, including Windows and is licensed under the GNU GPL.
	* [PowerCat](https://github.com/secabstraction/PowerCat)
		* A PowerShell TCP/IP swiss army knife that works with Netcat & Ncat
* **DNS(SEC)**
	* [Phreebird](http://dankaminsky.com/phreebird/) 
		* Phreebird is a DNSSEC proxy that operates in front of an existing DNS server (such as BIND, Unbound, PowerDNS, Microsoft DNS, or QIP) and supplements its records with DNSSEC responses. Features of Phreebird include automatic key generation, realtime record signing, support for arbitrary responses, zero configuration, NSEC3 -White Lies-, caching and rate limiting to deter DoS attacks, and experimental support for both Coarse Time over DNS and HTTP Virtual Channels. The suite also contains a large amount of sample code, including support for federated identity over OpenSSH. Finally, -Phreeload- enhances existing OpenSSL applications with DNSSEC support.
	* [DNS Chef](https://github.com/amckenna/DNSChef)
		* This is a fork of the DNSChef project v0.2.1 hosted at: http://thesprawl.org/projects/dnschef/
* **HTTP/HTTPS**
	* [SSLStrip](http://www.thoughtcrime.org/software/sslstrip/)
		* This tool provides a demonstration of the HTTPS stripping attacks that I presented at Black Hat DC 2009. It will transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.
	* [SharpSocks](https://github.com/nettitude/SharpSocks)
		* Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
* **Host Based**
	* [Echo Mirage](http://www.wildcroftsecurity.com/echo-mirage)
		* Echo Mirage is a generic network proxy. It uses DLL injection and function hooking techniques to redirect network related function calls so that data transmitted and received by local applications can be observed and modified. Windows encryption and OpenSSL functions are also hooked so that plain text of data being sent and received over an encrypted session is also available. Traffic can be intercepted in real-time, or manipulated with regular expressions and a number of action directives
* **Local**
	* [Burp Proxy](http://portswigger.net/burp/proxy.html)
		* Burp Proxy is an intercepting proxy server for security testing of web applications. It operates as a man-in-the-middle between your browser and the target application
	* [Charles Proxy](https://www.charlesproxy.com/)
		* Charles is an HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet. This includes requests, responses and the HTTP headers (which contain the cookies and caching information).
	* [OWASP Zed Attack Proxy](http://www.zaproxy.org/)
		* [Zed Attack Proxy (ZAP) Community Scripts](https://github.com/zaproxy/community-scripts)
		* A collection of ZAP scripts provided by the community - pull requests very welcome! 
* **Pivot Proxy**
	* Netcat
	* Ncat
	* Socat
	* [ssf - Secure Socket Funneling](https://github.com/securesocketfunneling/ssf)
		* Network tool and toolkit. It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS tunnel to a remote computer. SSF is cross platform (Windows, Linux, OSX) and comes as standalone executables.




## Custom Command and Control Protocol
-------------------------------
* [Custom Command and Control Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1094)
	* Adversaries may communicate using a custom command and control protocol instead of using existing Standard Application Layer Protocol to encapsulate commands. Implementations could mimic well-known protocols.
* See Red_Team.md 'C2 Examples'





## Custom Cryptographic Protocol
-------------------------------
* [Custom Cryptographic Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1024)
	* Adversaries may use a custom cryptographic protocol or algorithm to hide command and control traffic. A simple scheme, such as XOR-ing the plaintext with a fixed key, will produce a very weak ciphertext. 
	* Custom encryption schemes may vary in sophistication. Analysis and reverse engineering of malware samples may be enough to discover the algorithm and encryption key used. 
	*  Some adversaries may also attempt to implement their own version of a well-known cryptographic algorithm instead of using a known implementation library, which may lead to unintentional errors.F-Secure Cosmicduke 
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)








## Data Encoding
-------------------------------
* [Data Encoding - ATT&CK](https://attack.mitre.org/wiki/Technique/T1132)
	* Command and control (C2) information is encoded using a standard data encoding system. Use of data encoding may be to adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, UTF-8, or other binary-to-text and character encoding systems.Wikipedia Binary-to-text EncodingWikipedia Character Encoding Some data encoding systems may also result in data compression, such as gzip.
* [Binary-to-text encoding - wikipedia](https://en.wikipedia.org/wiki/Binary-to-text_encoding)
* [Character encoding - wikipedia](https://en.wikipedia.org/wiki/Character_encoding)
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)




## Data Obfuscation
-------------------------------
* [Data Obfuscation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1001)
	* Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, commingling legitimate traffic with C2 communications traffic, or using a non-standard data encoding system, such as a modified Base64 encoding for the message body of an HTTP request.
* [Redirectors](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki#redirectors)
* [CloakifyFactory](https://github.com/TryCatchHCF/Cloakify)
	* CloakifyFactory & the Cloakify Toolset - Data Exfiltration & Infiltration In Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat Data Whitelisting Controls; Evade AV Detection. Text-based steganography usings lists. Convert any file type (e.g. executables, Office, Zip, images) into a list of everyday strings. Very simple tools, powerful concept, limited only by your imagination.
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)




## Domain Fronting
* [Domain Fronting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1172)
	* Domain fronting takes advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS.1 The technique involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, "domainless" fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored). 	
	* For example, if domain-x and domain-y are customers of the same CDN, it is possible to place domain-x in the TLS header and domain-y in the HTTP header. Traffic will appear to be going to domain-x, however the CDN may route it to domain-y.
	* [FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains)
		* Search for potential frontable domains
	* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
	* [Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/talks/fronting-pets2015/)
	* [Camouflage at encryption layer: domain fronting](https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/)
	* [Domain Fronting - Infosec Institute](http://resources.infosecinstitute.com/domain-fronting/)
	* [Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
		* In this entry we continue with domain fronting; on this occasion we will explore how to implement a simple PoC of a command and control and exfiltration server on Google App Engine (GAE), and we will see how to do the domain fronting from Windows, with a VBS or PowerShell script, to hide interactions with the C2 server.
	* [TOR Fronting – Utilising Hidden Services for Privacy](https://www.mdsec.co.uk/2017/02/tor-fronting-utilising-hidden-services-for-privacy/)
	* [Finding Domain frontable Azure domains - thoth / Fionnbharr (@a_profligate)](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
	* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)
	* [Domain Fronting Via Cloudfront Alternate Domains](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
* **Domain Tools**
	* [Domain Hunter](https://github.com/minisllc/domainhunter)
		* Checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names
	* [AIRMASTER](https://github.com/t94j0/AIRMASTER)
		* Use ExpiredDomains.net and BlueCoat to find useful domains for red team.
	* [Chameleon](https://github.com/mdsecactivebreach/Chameleon)
		* A tool for evading Proxy categorisation
	* [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish)
		* Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C.  It relies on expireddomains.net to obtain a list of expired domains. The domain availability is validated using checkdomain.com
	* [Finding Frontable Domain](https://github.com/rvrsh3ll/FindFrontableDomains)
* **Domain Reputation Sites**
	* [Alien Vault](http://www.alienvault.com)
	* [Isithacked?](http://www.isithacked.com)
	* [Robtex](https://dns.robtex.com)
	* [Scan4You](http://scan4you.net/)
	* [Sucuri](http://sitecheck.sucuri.net/scanner/)
	* [Trustedsource](http://www.trustedsource.org/)
	* [urlQuery](http://urlquery.net/search.php)
	* [URLVoid](http://www.urlvoid.com/scan/)
	* [VirusTotal](https://www.virustotal.com/)
	* [WOT](http://www.mywot.com/en/scorecard)
	* [Zeltser BL](http://zeltser.com)
* Redirectors
	* [Apache2Mod Rewrite Setup](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup)
	* [Redirecting Cobalt Strike DNS Beacons](http://www.rvrsh3ll.net/blog/offensive/redirecting-cobalt-strike-dns-beacons/)
	* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
	* [Cobalt Strike HTTP C2 Redirectors with Apache mod_rewrite - Jeff Dimmock](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)


## Fallback Channels
-------------------------------
* [Fallback Channels - ATT&CK](https://attack.mitre.org/wiki/Technique/T1008)
	* Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.






## Multi-Stage Channels
-------------------------------
* [Multi-Stage Channels - ATT&CK](https://attack.mitre.org/wiki/Technique/T1104)
	* Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult. 
	* Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features. 
	*  The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or Fallback Channels in case the original first-stage communication path is discovered and blocked.
* [Redirectors](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki#redirectors)
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)





## Multiband Communication
-------------------------------
* [Multiband Communication - ATT&CK](https://attack.mitre.org/wiki/Technique/T1026)
	* Some adversaries may split communications between different protocols. There could be one protocol for inbound command and control and another for outbound data, allowing it to bypass certain firewall restrictions. The split could also be random to simply avoid data threshold alerts on any one communication. 

----------------------
## Multi-hop Proxy
* [Multi-hop Proxy - ATT&CK](https://attack.mitre.org/wiki/Technique/T1188)
	* To disguise the source of malicious traffic, adversaries may chain together multiple proxies. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source. 


## Multilayer Encryption
-------------------------------
* [Multilayer Encryption - ATT&CK](https://attack.mitre.org/wiki/Technique/T1079)
	* An adversary performs C2 communications using multiple layers of encryption, typically (but not exclusively) tunneling a custom encryption scheme within a protocol encryption scheme such as HTTPS or SMTPS.





## Remote File Copy
-------------------------------
* [Remote File Copy - ATT&CK](https://attack.mitre.org/wiki/Technique/T1105)
	* Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp. Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with Windows Admin Shares or Remote Desktop Protocol. 





## Standard Application Layer Protocol
-------------------------------
* [Standard Application Layer Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1071)
	* Adversaries may communicate using a common, standardized application layer protocol such as HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are RPC, SSH, or RDP. 
* [dnscat2](https://github.com/iagox86/dnscat2)
	* Welcome to dnscat2, a DNS tunnel that WON'T make you sick and kill you!  This tool is designed to create a command-and-control (C&C) channel over the DNS protocol, which is an effective tunnel out of almost every network.
* [fraud-bridge](https://github.com/stealth/fraud-bridge) 
	* fraud-bridge allows to tunnel TCP connections through ICMP, ICMPv6, DNS via UDP or DNS via UDP6. Project, not stable
* [tcpovericmp](https://github.com/Maksadbek/tcpovericmp)
	* TCP implementation over ICMP protocol to bypass firewalls
* [icmptunnel](https://github.com/DhavalKapil/icmptunnel)
	* Transparently tunnel your IP traffic through ICMP echo and reply packets.
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)



## Standard Cryptographic Protocol
-------------------------------
* [Standard Cryptographic Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1032)
	* Adversaries use command and control over an encrypted channel using a known encryption protocol like HTTPS or SSL/TLS. The use of strong encryption makes it difficult for defenders to detect signatures within adversary command and control traffic. Some adversaries may use other encryption protocols and algorithms with symmetric keys, such as RC4, that rely on encryption keys encoded into malware configuration files and not public key cryptography. Such keys may be obtained through malware reverse engineering.









## Standard Non-Application Layer Protocol
-------------------------------
* [Standard Non-Application Layer Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1095)
	* Use of a standard non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.Wikipedia OSI Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), and transport layer protocols, such as the User Datagram Protocol (UDP). ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts;Microsoft ICMP however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)






## Uncommonly Used Port
-------------------------------
* [Uncommonly Used Port - ATT&CK](https://attack.mitre.org/wiki/Technique/T1065)
	* Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls that have been improperly configured.
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)









## Web Service
-------------------------------
* [Web Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1102)
	* Adversaries may use an existing, legitimate external Web service as a means for relaying commands to a compromised system. Popular websites and social media can act as a mechanism for command and control and give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.
* [C2 with twitter](https://pentestlab.blog/2017/09/26/command-and-control-twitter/)
* [C2 with DNS](https://pentestlab.blog/2017/09/06/command-and-control-dns/)
* [ICMP C2](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
* [C2 with Dropbox](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/)
* [C2 with https](https://pentestlab.blog/2017/10/04/command-and-control-https/)
* [C2 with webdav](https://pentestlab.blog/2017/09/12/command-and-control-webdav/)
* [C2 with gmail](https://pentestlab.blog/2017/08/03/command-and-control-gmail/)
* [“Tasking” Office 365 for Cobalt Strike C2](https://labs.mwrinfosecurity.com/blog/
* [JSBN](https://github.com/Plazmaz/JSBN)
	* JSBN is a bot client which interprets commands through Twitter, requiring no hosting of servers or infected hosts from the command issuer. It is written purely in javascript as a Proof-of-Concept for javascript's botnet potentials.
* [See 'Exfiltration' under '/Docs'](../../Exfiltration.md)







