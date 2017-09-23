# Network Attacks & Defenses

### ToC
* General
	* Lateral Movement
	* Active Directory
	* Sharepoint
* General tools
* DNS
* D/DOS
* Email
* IDS/IPS Evasion
* IPv6 Related
* LDAP
* Netbios
* Network Host/Service Discovery
* Pivoting
* Proxies
* SSH
* SQL
* SNMP
* SIP/VOIP
* STP
* MISC
* Talks/
* UPNP
* Web
* Writeups
* Other

--------
##### To be sorted
http://www.pentest-standard.org/index.php/Intelligence_Gathering

[MQTT](http://mqtt.org/)
* MQTT is a machine-to-machine (M2M)/"Internet of Things" connectivity protocol. It was designed as an extremely lightweight publish/subscribe messaging transport. 

[Enteletaor](https://github.com/cr0hn/enteletaor)
* Message Queue & Broker Injection tool that implements attacks to Redis, RabbitMQ and ZeroMQ.


[Nmap (XML) Parser documentation](https://nmap-parser.readthedocs.io/en/latest/)


[OpenSSH User Enumeration Time-Based Attack](http://seclists.org/fulldisclosure/2013/Jul/88)

[Collection of Symantec Endpoint Protection Vulnerabilities + some exploits](http://codewhitesec.blogspot.nl/2015/07/symantec-endpoint-protection.html)
 
[reGeorg](https://github.com/sensepost/reGeorg)
* The successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.

[NfSpy](https://github.com/bonsaiviking/NfSpy)
* NfSpy is a Python library for automating the falsification of NFS credentials when mounting an NFS share.




##### sort end


###### To Do
* Active Directory Section?
* Pivoting Section
* Add RFCs
* Add sslscan/similar
* IPMI section






------------
### General

[Fundamentals That Time Forgot - Jup1t3r  - BSides SLC](https://www.youtube.com/watch?v=PQvUWImljOw)

[NMAP - Port-Scanning: A Practical Approach Modified for better](https://www.exploit-db.com/papers/35425/)

[NSEInfo](https://github.com/christophetd/nmap-nse-info/blob/master/README.md)
* NSEInfo is a tool to interactively search through nmap's NSE scripts.

[pynessus](https://github.com/rmusser01/pynessus)
* Python Parser for Nessus Output
* [Examples](http://www.hackwhackandsmack.com/?p=422)

[TCPDump Primer](http://danielmiessler.com/study/tcpdump/)

[IANA Complete list of assigned ports](http://www.vulnerabilityassessment.co.uk/port-numbers.txt)

[which-cloud](https://github.com/bcoe/which-cloud)
* Given an ip address, return which cloud provider it belongs to (AWS, GCE, etc)  

[RFC 2827 -  Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing](https://tools.ietf.org/html/rfc2827)

[RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246)

[TCPDump Command Examples](http://www.thegeekstuff.com/2010/08/tcpdump-command-examples/)

[The Eavesdropper’s Dillemma](http://www.crypto.com/papers/internet-tap.pdf)



------------
### <a name="attackw">Attacking Windows Networks</a>

[Introducing PowerShell into your Arsenal with PS>Attack - Jared Haight](http://www.irongeek.com/i.php?page=videos/derbycon6/119-introducing-powershell-into-your-arsenal-with-psattack-jared-haight)

[Get-Help: An Intro to PowerShell and How to Use it for Evil - Jared Haight](https://www.psattack.com/presentations/get-help-an-intro-to-powershell-and-how-to-use-it-for-evil/)

[ShareCheck Windows Enumeration Tool v2.0 - sec1](http://www.sec-1.com/blog/2014/sharecheck)





------------
#### Lateral Movement

[*Puff* *Puff* PSExec - Lateral Movement: An Overview](https://www.toshellandback.com/2017/02/11/psexec/)

[Ditch PsExec, SprayWMI is here ;)](http://www.pentest.guru/index.php/2015/10/19/ditch-psexec-spraywmi-is-here/)

[WMIOps](https://github.com/ChrisTruncer/WMIOps)
* WMIOps is a powershell script that uses WMI to perform a variety of actions on hosts, local or remote, within a Windows environment. It's designed primarily for use on penetration tests or red team engagements.

[spraywmi](https://github.com/trustedsec/spraywmi)
* SprayWMI is a method for mass spraying Unicorn PowerShell injection to CIDR notations.

[psexec](https://github.com/pentestgeek/smbexec)
* A rapid psexec style attack with samba tools
* [Blogpost that inspired it](http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html)

[sshuttle](https://github.com/apenwarr/sshuttle)
* Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.

[PowerShell PSRemoting Pwnage](https://pentestn00b.wordpress.com/2016/08/22/powershell-psremoting-pwnage/)

[PowerShell Remoting for Penetration Testers ](https://lockboxx.blogspot.com/2015/07/powershell-remoting-for-penetration.html)


##### Pass-the-Hash
[Pass the hash attacks: Tools and Mitigation - 2010 SANS paper](https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283)

[Pass the hash - Wikipedia](https://en.wikipedia.org/wiki/Pass_the_hash)

[Performing Pass-the-Hash Attacks with Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)

[Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)

[Still Passing the Hash 15 Years Later](https://passing-the-hash.blogspot.com/)
* Providing all the extra info that didn't make it into the BlackHat 2012 USA Presentation "Still Passing the Hash 15 Years Later? Using the Keys to the Kingdom to Access All Your Data" by Alva Lease 'Skip' Duckwall IV and Christopher Campbell.


##### Passing the Ticket Attacks

[Mimikatz and Active Directory Kerberos Attacks ](https://adsecurity.org/?p=556)

[The Secret Life of KRBTGT](https://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf)

[Kerberos Golden Ticket Protection Mitigating Pass-the-Ticket on Active Directory - CERT-EU](https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf)

[From Pass-the-Hash to Pass-the-Ticket with No Pain](http://resources.infosecinstitute.com/pass-hash-pass-ticket-no-pain/)

[mimikatz - Golden Ticket](http://rycon.hu/papers/goldenticket.html)

[THE GOLDEN TICKET ATTACK- A LOOK UNDER THE HOOD](http://cybersecology.com/wp-content/uploads/2016/05/Golden_Ticket-v1.13-Final.pdf)

[How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)

[The path to the Golden Ticket](https://countuponsecurity.com/tag/pass-the-ticket/)

[How To Pass the Ticket Through SSH Tunnels](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)


##### RDP
[RDP hijacking-how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)

[RDP Man-in-The-Middle attack ](https://theevilbit.blogspot.com/2014/04/rdp-man-in-middle-attack.html)

[ATTACKING RDP How to Eavesdrop on Poorly Secured RDP Connections - Adrian Vollmer 2017](https://www.exploit-db.com/docs/41621.pdf)

[RDPY](https://github.com/citronneur/rdpy)
* RDPY is a pure Python implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (client and server side). RDPY is built over the event driven network engine Twisted. RDPY support standard RDP security layer, RDP over SSL and NLA authentication (through ntlmv2 authentication protocol).

[SSL -Man-In-The-Middle- attacks on RDP](https://web.archive.org/web/20161007044945/https://labs.portcullis.co.uk/blog/ssl-man-in-the-middle-attacks-on-rdp/)

[rdps2rdp](https://github.com/DiabloHorn/rdps2rdp)
* Decrypt MITM SSL RDP and save to pcap










------------
#### Active Directory

[Dumping a Domain-s Worth of Passwords With Mimikatz pt. 2](http://www.harmj0y.net/blog/powershell/dumping-a-domains-worth-of-passwords-with-mimikatz-pt-2/)

[Windows Attacks AT is the new black](https://www.slideshare.net/mubix/windows-attacks-at-is-the-new-black-26665607)

[Attacking ADFS Endpoints with PowerShell](http://www.irongeek.com/i.php?page=videos/derbycon6/118-attacking-adfs-endpoints-with-powershell-karl-fosaaen)

[PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
* AD PowerShell Recon Scripts

[Netview](https://github.com/mubix/netview)
* Netview is a enumeration tool. It uses (with the -d) the current domain or a specified domain (with the -d domain) to enumerate hosts

[LLMNR and NBT-NS Poisoning Using Responder](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)

[Attack Methods for Gaining Domain Admin Rights in Active Directory - hackingandsecurity](https://hackingandsecurity.blogspot.com/2017/07/attack-methods-for-gaining-domain-admin.html?view=timeslide)

[Abusing Kerberos](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It-wp.pdf)

[krb5-enum-users - nse script](https://nmap.org/nsedoc/scripts/krb5-enum-users.html)
* Discovers valid usernames by brute force querying likely usernames against a Kerberos service. When an invalid username is requested the server will respond using the Kerberos error code KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, allowing us to determine that the user name was invalid. Valid user names will illicit either the TGT in a AS-REP response or the error KRB5KDC_ERR_PREAUTH_REQUIRED, signaling that the user is required to perform pre authentication. 





------------
#### Sharepoint
[Sparty - MS Sharepoint and Frontpage Auditing Tool](http://sparty.secniche.org/)
*  Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture. The motivation behind this tool is to provide an easy and robust way to scrutinize the security configurations of sharepoint and frontpage based web applications. Due to the complex nature of these web administration software, it is required to have a simple and efficient tool that gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. A number of automated scanners fall short of this and Sparty is a solution to that.

[SPScan](http://sourceforge.net/projects/spscan/)
* SPScan is a tool written in Ruby that enumerates a SharePoint installation gathering information about the version and installed plugins.

[SPartan](https://github.com/sensepost/SPartan)
* SPartan is a Frontpage and Sharepoint fingerprinting and attack tool

#### Network based

[Responder](https://github.com/SpiderLabs/Responder/)
* Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.

[MS Network Level Authentication](https://technet.microsoft.com/en-us/magazine/hh750380.aspx)

[Enum4Linux](https://labs.portcullis.co.uk/tools/enum4linux/)
* Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com. It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. The tool usage can be found below followed by examples, previous versions of the tool can be found at the bottom of the page.




------------
### <a name="tools">General Tools</a>



[digbit](https://github.com/mnmnc/digbit/blob/master/README.md)
* Automatic domain generation for BitSquatting

[Yersinia](http://www.yersinia.net/)
* Yersinia is a network tool designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. 

[netcat](http://nc110.sourceforge.net/)
* Network Swiss army knife. Ncat-s predecessor. Does everything and the kitchen sink.

[Ncat](http://nmap.org/)
* Ncat is a feature-packed networking utility which reads and writes data across networks from the command line. Ncat was written for the Nmap Project as a much-improved reimplementation of the venerable Netcat. It uses both TCP and UDP for communication and is designed to be a reliable back-end tool to instantly provide network connectivity to other applications and users. Ncat will not only work with IPv4 and IPv6 but provides the user with a virtually limitless number of potential uses.

[RANCID - Really Awesome New Cisco confIg Differ](http://www.shrubbery.net/rancid/)
* RANCID monitors a router's (or more generally a device's) configuration, including software and hardware (cards, serial numbers, etc) and uses CVS (Concurrent Version System) or Subversion to maintain history of changes.
* RANCID does this by the very simple process summarized as: login to each device in the router table (router.db), run various commands to get the information that will be saved, cook the output; re-format, remove oscillating or incrementing data, email any differences (sample) from the previous collection to a mail list, and finally commit those changes to the revision control system







------------
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

[DNS Reference Information - technet](https://technet.microsoft.com/en-us/library/dd197499(v=ws.10).aspx)

[DNS Records: an Introduction](https://www.linode.com/docs/networking/dns/dns-records-an-introduction)

[DNS Cache Snooping or Snooping the Cache for Fun and Profit - Luis Grangeia](http://cs.unc.edu/~fabian/course_papers/cache_snooping.pdf)

[nsec3map](https://github.com/anonion0/nsec3map)
* a tool to enumerate the resource records of a DNS zone using its DNSSEC NSEC or NSEC3 chain







------------
### D/DOS


[Davoset](https://github.com/MustLive/DAVOSET) 
* DAVOSET - it is console (command line) tool for conducting DDoS attacks on the sites via Abuse of Functionality and XML External Entities vulnerabilities at other sites.





------------
#### Email

[SIMPLYEMAIL](https://github.com/killswitch-GUI/SimplyEmail)
* What is the simple email recon tool? This tool was based off the work of theHarvester and kind of a port of the functionality. This was just an expansion of what was used to build theHarvester and will incorporate his work but allow users to easily build Modules for the Framework. Which I felt was desperately needed after building my first module for theHarvester.

[Swaks - Swiss Army Knife for SMTP](http://www.jetmore.org/john/code/swaks/)


###Frameworks
[BackDoor Factory](https://github.com/secretsquirrel/the-backdoor-factory)
* The goal of BDF is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state.
* [Wiki](https://github.com/secretsquirrel/the-backdoor-factory/wiki)
* [Video](http://www.youtube.com/watch?v=jXLb2RNX5xs)

[Man-in-the-Middle Framework](https://github.com/byt3bl33d3r/MITMf)
*Framework for Man-In-The-Middle attacks

[Veil](https://github.com/Veil-Framework/Veil)
* Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions.

Veil Tutorials:
* [Framework Usage Tutorial](https://www.veil-framework.com/veil-tutorial/)
* [Payload Creation Tutorial](https://www.veil-framework.com/tutorial-veil-payload-development/)
* [Customizing backdoors with Veil](https://www.veil-framework.com/how-to-customize-backdoor-factory-payloads-within-veil/)
* [Creating a windows payload](https://www.youtube.com/watch?v=v1OXNP_bl8U)

[Adventures in Asymmetric Warfare by Will Schroeder](https://www.youtube.com/watch?v=53qQfCkVM_o)

[DomainTrustExplorer](https://github.com/sixdub/DomainTrustExplorer)
* Python script for analyis of the "Trust.csv" file generated by Veil PowerView. Provides graph based analysis and output. The graph output will represent access direction (opposite of trust direction) 

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net *" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.




------------
### <a name="evasion">IDS/IPS Evasion</a>


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




### IPMI
[Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)



------------
### <a name="ipv6">IPv6 Related</a>

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

[IPv6 Local Neighbor Discovery Using Router Advertisement](https://www.rapid7.com/db/modules/auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement)
* Send a spoofed router advertisement with high priority to force hosts to start the IPv6 address auto-config. Monitor for IPv6 host advertisements, and try to guess the link-local address by concatinating the prefix, and the host portion of the IPv6 address. Use NDP host solicitation to determine if the IP address is valid'

[IPv6 - Playing with IPv6 for fun and profit](https://github.com/zbetcheckin/IPv6)




------------
#### LDAP

[JXplorer](http://jxplorer.org/)
* JXplorer is a cross platform LDAP browser and editor. It is a standards compliant general purpose LDAP client that can be used to search, read and edit any standard LDAP directory, or any directory service with an LDAP or DSML interface. It is highly flexible and can be extended and customised in a number of ways. JXplorer is written in java, and the source code and Ant build system are available via svn or as a packaged build for users who want to experiment or further develop the program. 	

[LDAPMfINER](http://ldapminer.sourceforge.net/)
* This is a tool I wrote to collect information from different LDAP Server implementation. This was written in C with the Netscape C 

[Softera LDAP Browser](http://www.ldapbrowser.com/info_softerra-ldap-browser.htm)
* LDAP Browser that supports most LDAP implementations. Non-free software, 30-day free trial



### MitM Tools
[Ettercap](https://ettercap.github.io/ettercap/)
Ettercap is a comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.

[Dsniff](http://www.monkey.org/~dugsong/dsniff/)
dsniff is a collection of tools for network auditing and penetration testing. dsniff, filesnarf, mailsnarf, msgsnarf, urlsnarf, and webspy passively monitor a network for interesting data (passwords, e-mail, files, etc.). arpspoof, dnsspoof, and macof facilitate the interception of network traffic normally unavailable to an attacker (e.g, due to layer-2 switching). sshmitm and webmitm implement active monkey-in-the-middle attacks against redirected SSH and HTTPS sessions by exploiting weak bindings in ad-hoc PKI. 

[SSLsplit - transparent and scalable SSL/TLS interception](https://www.roe.ch/SSLsplit)
* SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit. SSLsplit terminates SSL/TLS and initiates a new SSL/TLS connection to the original destination address, while logging all data transmitted. SSLsplit is intended to be useful for network forensics and penetration testing.  SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6.

[Seth](https://github.com/SySS-Research/Seth)
* Seth is a tool written in Python and Bash to MitM RDP connections. It attempts to downgrade the connection and extract clear text credentials.

[WSUXploit](https://github.com/pimps/wsuxploit)
* This is a MiTM weaponized exploit script to inject 'fake' updates into non-SSL WSUS traffic. It is based on the WSUSpect Proxy application that was introduced to public on the Black Hat USA 2015 presentation, 'WSUSpect - Compromising the Windows Enterprise via Windows Update'

[net-creds](https://github.com/DanMcInerney/net-creds)
* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification
* It sniffs: URLs visited; POST loads sent; HTTP form logins/passwords; HTTP basic auth logins/passwords; HTTP searches; FTP logins/passwords; IRC logins/passwords; POP logins/passwords; IMAP logins/passwords; Telnet logins/passwords; SMTP logins/passwords; SNMP community string; NTLMv1/v2 all supported protocols like HTTP, SMB, LDAP, etc; Kerberos.







------------
#### Netbios

[NbtScan](http://www.unixwiz.net/tools/nbtscan.html)
* This is a command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network, and this is a first step in finding of open shares. It is based on the functionality of the standard Windows tool nbtstat, but it operates on a range of addresses instead of just one. I wrote this tool because the existing tools either didn't do what I wanted or ran only on the Windows platforms: mine runs on just about everything.










------------
#### Network Host Discovery/Service Discovery:

[Nmap](http://nmap.org/)
* Nmap ("Network Mapper") is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping). 

[Scanning Effectively Through a SOCKS Pivot with Nmap and Proxychains](https://cybersyndicates.com/2015/12/nmap-and-proxychains-scanning-through-a-socks-piviot/)
* [Script](https://github.com/killswitch-GUI/PenTesting-Scripts/blob/master/Proxychains-Nmap.py)

[Enumerator](https://pypi.python.org/pypi/enumerator/0.1.4)
* enumerator is a tool built to assist in automating the often tedious task of enumerating a target or list of targets during a penetration test.

[hostmap](https://github.com/jekil/hostmap)
* hostmap is a free, automatic, hostnames and virtual hosts discovery tool written in Ruby by Alessandro Tanasi

[Angry IP Scanner](http://angryip.org/)
* Angry IP Scanner (or simply ipscan) is an open-source and cross-platform network scanner designed to be fast and simple to use. It scans IP addresses and ports as well as has many other features. 

[UnicornScan](http://www.unicornscan.org/)
* Unicornscan is a new information gathering and correlation engine built for and by members of the security research and testing communities. It was designed to provide an engine that is Scalable, Accurate, Flexible, and Efficient. It is released for the community to use under the terms of the GPL license. 
* My note: Use this to mass scan networks. It-s faster than nmap at scanning large host lists and allows you to see live hosts quickly.

[hping](http://www.hping.org/)
* hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface is inspired to the ping(8) unix command, but hping isn't only able to send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode, the ability to send files between a covered channel, and many other features. 

[Consul](https://github.com/hashicorp/consul)
* Consul is a tool for service discovery and configuration. Consul is distributed, highly available, and extremely scalable.

[CloudFail](https://github.com/m0rtem/CloudFail)
* CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by CloudFlare in the hopes of discovering the location of the server.

[HatCloud](https://github.com/HatBashBR/HatCloud)
* HatCloud build in Ruby. It makes bypass in CloudFlare for discover real IP. This can be useful if you need test your server and website. Testing your protection against Ddos (Denial of Service) or Dos. CloudFlare is services and distributed domain name server services, sitting between the visitor and the Cloudflare user's hosting provider, acting as a reverse proxy for websites. Your network protects, speeds up and improves availability for a website or the mobile application with a DNS change.

[discover - Kali Scripts](https://github.com/leebaird/discover)
* For use with Kali Linux - custom bash scripts used to automate various portions of a pentest.

[Firewalk](http://packetfactory.openwall.net/projects/firewalk/)
* Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a  given IP forwarding device will pass. Firewalk  works  by sending out TCP or UDP packets with a TTL one greater than the targeted gateway.  If the gateway allows the traffic, it will forward the packets to the next hop where they will expire and elicit an ICMP_TIME_EXCEEDED  message.  If the gateway hostdoes not allow the traffic, it will likely drop the packets on  the floor and we will see no response. To get  the  correct  IP  TTL that will result in expired packets one beyond the gateway we need  to  ramp  up  hop-counts.   We  do  this  in the same manner that traceroute works.  Once we have the gateway hopcount (at  that point the scan is said to be `bound`) we can begin our scan.

[CiscoRouter - tool](https://github.com/ajohnston9/ciscorouter)
* CiscoRouter is a tool for scanning Cisco-based routers over SSH. Rules can be created using accompanying CiscoRule application (see this repo) and stored in the "rules" directory.

[scanless](https://github.com/vesche/scanless)
* Command-line utility for using websites that can perform port scans on your behalf. Useful for early stages of a penetration test or if you'd like to run a port scan on a host and have it not come from your IP address.

[ms15-034.nse Script](https://github.com/pr4jwal/quick-scripts/blob/master/ms15-034.nse)

[OnionScan](https://github.com/s-rah/onionscan)
* [What OnionScan Scans for](https://github.com/s-rah/onionscan/blob/master/doc/what-is-scanned-for.md)

[Ever wanted to scan the internet in a few hours?](http://blog.erratasec.com/2013/10/faq-from-where-can-i-scan-internet.html)

[device-pharmer](https://github.com/DanMcInerney/device-pharmer)
* Opens 1K+ IPs or Shodan search results and attempts to login 

[Adding your protocol to Masscan](http://blog.erratasec.com/2014/11/adding-protocols-to-masscan.html)




------------
### Pivoting

[A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/#corporate-http-proxy-as-a-way-out)

[Udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel)
* A Tunnel which tunnels UDP via FakeTCP/UDP/ICMP Traffic by using Raw Socket, helps you Bypass UDP FireWalls(or Unstable UDP Environment). Its Encrypted, Anti-Replay and Multiplexed. It also acts as a Connection Stabilizer.)










------------
#### Proxies

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
* Phreebird is a DNSSEC proxy that operates in front of an existing DNS server (such as BIND, Unbound, PowerDNS, Microsoft DNS, or QIP) and supplements its records with DNSSEC responses. Features of Phreebird include automatic key generation, realtime record signing, support for arbitrary responses, zero configuration, NSEC3 -White Lies-, caching and rate limiting to deter DoS attacks, and experimental support for both Coarse Time over DNS and HTTP Virtual Channels. The suite also contains a large amount of sample code, including support for federated identity over OpenSSH. Finally, -Phreeload- enhances existing OpenSSL applications with DNSSEC support.

[TCP Catcher](http://www.tcpcatcher.org/)
* TcpCatcher is a free TCP, SOCKS, HTTP and HTTPS proxy monitor server software. 









------------
#### SSH: 

[SSH for Fun and Profit](https://karla.io/2016/04/30/ssh-for-fun-and-profit.html)

[ssh-audit](https://github.com/arthepsy/ssh-audit)
* SSH server auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)







------------
#### SQL:

[SQLMap](https://github.com/sqlmapproject/sqlmap)
* sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

[PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server](https://github.com/NetSPI/PowerUpSQL)
* The PowerUpSQL module includes functions that support SQL Server discovery, auditing for common weak configurations, and privilege escalation on scale. It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that could be used by administrators to quickly inventory the SQL Servers in their ADS domain.
* [Documentation](https TLS/SSL Vulnerabilities ://github.com/NetSPI/PowerUpSQL/wiki)
* [Overview of PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki/Overview-of-PowerUpSQL)










------------
#### SMTP:






------------
#### SNMP:

[Onesixtyone](http://www.phreedom.org/software/onesixtyone/)
* onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance. It can scan an entire class B network in under 13 minutes. It can be used to discover devices responding to well-known community names or to mount a dictionary attack against one or more SNMP devices.

[SNMPWALK](http://net-snmp.sourceforge.net/docs/man/snmpwalk.html)
*  snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests

[Simple Network Management Pwnd](http://www.irongeek.com/i.php?page=videos/derbycon4/t221-simple-network-management-pwnd-deral-heiland-and-matthew-kienow)

[Cisc0wn - Cisco SNMP Script](https://github.com/nccgroup/cisco-SNMP-enumeration)
* Automated Cisco SNMP Enumeration, Brute Force, Configuration Download and Password Cracking


------------
#### SIP/VOIP:

[sipvicious](https://github.com/EnableSecurity/sipvicious)

[bluebox-ng](https://github.com/jesusprubio/bluebox-ng)
* Pentesting framework using Node.js powers, focused in VoIP.






--------------
#### SSL/TLS


[testssl.sh](https://github.com/drwetter/testssl.sh)
* testssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.

[SSL & TLS Penetration Testing [Definitive Guide]](https://www.aptive.co.uk/blog/tls-ssl-security-testing/)

[ SSL/TLS and PKI History ](https://www.feistyduck.com/ssl-tls-and-pki-history/)
*  A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem. Based on Bulletproof SSL and TLS, by Ivan Ristić.








------------
#### STP: 

[STP MiTM Attack and L2 Mitigation Techniques on the Cisco Catalyst 6500 ](http://www.ndm.net/ips/pdf/cisco/Catalyst-6500/white_paper_c11_605972.pdf)








------------
### <a name="talks">Presentations/Talks/Videos</a>

[Mass Scanning the Internet: Tips, Tricks, Results - DEF CON 22 - Graham, Mcmillan, and Tentler](https://www.youtube.com/watch?v=nX9JXI4l3-E)


[DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
* Great talk on attacking DNS

[DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
* Great talk on attacking DNS

[ C3CM: Defeating the Command - Control - and Communications of Digital Assailants](http://www.irongeek.com/i.php?page=videos/derbycon4/t206-c3cm-defeating-the-command-control-and-communications-of-digital-assailants-russ-mcree)
* C3CM: the acronym for command- control- and communi - cations countermeasures. Ripe for use in the information security realm, C3CM takes us past C2 analysis and to the next level. Initially, C3CM was most often intended to wreck the command and control of enemy air defense networks, a very specific military mission. We-ll apply that mindset in the context of combating bots and other evil. Our version of C3CM therefore is to identify, interrupt, and counter the command, control, and communications capabilities of our digital assailants. The three phases of C3CM will utilize: Nfsight with Nfdump, Nfsen, and fprobe to conduct our identification phase, Bro with Logstash and Kibana for the interruption phase, and ADHD for the counter phase. Converge these on one useful platform and you too might have a chance deter those who would do you harm. We-ll discuss each of these three phases (identify, interrupt, and counter) with tooling and tactics, complete with demonstrations and methodology attendees can put to use in their environments. Based on the three part ISSA Journal Toolsmith series: http://holisticinfosec. blogspot.com/search?q=c3cm&max-results=20&by-date=true

[DNS Dark Matter Discovery Theres Evil In Those Queries - Jim Nitterauer](https://www.youtube.com/watch?v=-A2Wqagz73Y)

[Passive IPS Reconnaissance and Enumeration - false positive (ab)use - Arron Finnon](https://vimeo.com/108775823)
* Network Intrusion Prevention Systems or NIPS have been plagued by "False Positive" issues almost since their first deployment. A "False Positive" could simply be described as incorrectly or mistakenly detecting a threat that is not real. A large amount of research has gone into using "False Positive" as an attack vector either to attack the very validity of an IPS system or to conduct forms of Denial of Service attacks. However the very reaction to a "False Positive" in the first place may very well reveal more detailed information about defences than you might well think.

[Attacking Nextgen Firewalls](https://www.youtube.com/watch?v=ZoCf9yWC32g)

[DNS hijacking using cloud providers - Frans Ros-n](https://www.youtube.com/watch?v=HhJv8CU-RIk)

[VLAN hopping, ARP Poisoning and Man-In-The-Middle Attacks in Virtualized Environments - Ronny L. Bull - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/110-vlan-hopping-arp-poisoning-and-man-in-the-middle-attacks-in-virtualized-environments-dr-ronny-l-bull)
* Cloud service providers and data centers offer their customers the ability to deploy virtual machines within multi-tenant environments. These virtual machines are typically connected to the physical network via a virtualized network configuration. This could be as simple as a bridged interface to each virtual machine or as complicated as a virtual switch providing more robust networking features such as VLANs, QoS, and monitoring. In this talk I will demonstrate the effects of VLAN hopping, ARP poisoning and Man-in-the-Middle attacks across every major hypervisor platform, including results of attacks originating from the physically connected network as well as within the virtual networks themselves. Each attack category that is discussed will be accompanied by a detailed proof of concept demonstration of the attack.








------------
### <a name="upnp">UPNP</a>

[Ufuzz](https://github.com/phikshun/ufuzz)
* UFuzz, or Universal Plug and Fuzz, is an automatic UPnP fuzzing tool. It will enumerate all UPnP endpoints on the network, find the available services and fuzz them. It also has the capability to fuzz HTTP using Burp proxy logs.

[miranda-upnp](https://github.com/0x90/miranda-upnp)

[UPnP Pentest Toolkit](https://github.com/nccgroup/UPnP-Pentest-Toolkit)




------------
#### Web:

[WPScan](https://github.com/wpscanteam/wpscan)
* WPScan is a black box WordPress vulnerability scanner.

[WhatWeb](https://github.com/urbanadventurer/WhatWeb)
* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.

[webDisco](https://github.com/joeybelans/webDisco)
* Web discovery tool to capture screenshots from a list of hosts & vhosts.  Requests are made via IP address and vhosts to determine differences. Additionallty checks for common administrative interfaces and web server  misconfigurations.

[w3af](https://github.com/andresriancho/w3af)
* w3af: web application attack and audit framework, the open source web vulnerability scanner.


------------
### <a name="writeup">Writeups & Tutorials</a>

[Enumerating DNSSEC NSEC and NSEC3 Records](https://www.altsci.com/concepts/page.php?s=dnssec&p=1)

[DNS database espionage](http://dnscurve.org/espionage2.html)

[Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it-s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What-s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."

[Enumerating DNSSEC NSEC and NSEC3 Records](https://www.altsci.com/concepts/page.php?s=dnssec&p=1)

[Bitsquatting: DNS Hijacking without exploitation](http://dinaburg.org/bitsquatting.html)

[Hunting Bugs in AIX : Pentesting writeup](https://rhinosecuritylabs.com/2016/11/03/unix-nostalgia-hunting-zeroday-vulnerabilities-ibm-aix/)

[From Zero to ZeroDay Journey: Router Hacking (WRT54GL Linksys Case)](http://www.defensecode.com/whitepapers/From_Zero_To_ZeroDay_Network_Devices_Exploitation.txt)

[Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
* In this entry we continue with domain fronting; on this occasion we will explore how to implement a simple PoC of a command and control and exfiltration server on Google App Engine (GAE), and we will see how to do the domain fronting from Windows, with a VBS or PowerShell script, to hide interactions with the C2 server.

[State of IP Spoofing](https://spoofer.caida.org/summary.php)

[Use DHCP to detect UEFI or Legacy BIOS system and PXE boot to SCCM](http://www.itfaq.dk/2016/07/27/use-dhcp-to-detect-uefi-or-legacy-bios-system-and-pxe-boot-to-sccm/)

[Too Many Cooks; Exploiting the Internet of Tr-069](http://mis.fortunecook.ie/) 



------------
### <a name="other">Other</a>

[exitmap](https://github.com/NullHypothesis/exitmap)
* A fast and modular scanner for Tor exit relays. http://www.cs.kau.se/philwint/spoiled_onions/ 

[More on HNAP - What is it, How to Use it,How to Find it](https://isc.sans.edu/diary/More+on+HNAP+-+What+is+it%2C+How+to+Use+it%2C+How+to+Find+it/17648)

[Modbus interface tutorial](https://www.lammertbies.nl/comm/info/modbus.html)

[TLS/SSL Vulnerabilities](https://www.gracefulsecurity.com/tls-ssl-vulnerabilities/)



------------
#### MISC:
[t50 - the fastest packet injector.](https://github.com/fredericopissarra/t50)
* T50 was designed to perform -Stress Testing-  on a variety of infra-structure
network devices (Version 2.45), using widely implemented protocols, and after
some requests it was was re-designed to extend the tests (as of Version 5.3),
covering some regular protocols (ICMP,  TCP  and  UDP),  some infra-structure
specific protocols (GRE,  IPSec  and  RSVP), and some routing protocols (RIP,
EIGRP and OSPF).

[gateway-finder](https://github.com/pentestmonkey/gateway-finder)
* Gateway-finder is a scapy script that will help you determine which of the systems on the local LAN has IP forwarding enabled and which can reach the Internet.

[a](https://github.com/fmtn/a)
* ActiveMQ CLI testing and message management

