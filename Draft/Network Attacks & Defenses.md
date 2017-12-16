# Network Attacks & Defenses

### ToC
* [General](#general)
* [Attacking Windows Networks](#attackw)
	* [Lateral Movement](#lateral)
	* [Active Directory](#AD)
	* [Sharepoint](#sharepoint)
* [General tools](#generaltools)
* [DNS](#dns)
* [D/DOS](#ddos)
* [Email](#email)
* [Frameworks](#frameworks)
* [IDS/IPS Evasion](#evasion)
* [IPMI](#ipmi)
* [IPv6 Related](#ipv6)
* [LDAP](#ldap)
* [Man-in-the-Middle Tools](#mitm)
* [Netbios](#netbios)
* [Network Host/Service Discovery](#host)
* [NFS](#nfs)
* [Pivoting](#pivot)
* [Proxies](#proxy)
* [Software Defined Networking(SDN)](#sdn)
* [SSH](#ssh)
* [SQL](#sql)
* [SNMP](#snmp)
* [SIP/VOIP](#sip)
* [SSL/TLS](#ssl)
* [STP](#stp)
* [MISC](#misc)
* [Talks/Videos](#videos)
* [UPNP](#upnp)
* [Web](#web)
* [Writeups](#writeups)
* [Other](#other)

--------
##### To be sorted
http://www.pentest-standard.org/index.php/Intelligence_Gathering
* [CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494)
	* Remote root exploit for the SAMBA CVE-2017-7494 vulnerability
* [10 Places to Stick Your UNC Path - NetSPI](https://blog.netspi.com/10-places-to-stick-your-unc-path/)
* [HackerOne H1-212 Capture the Flag Solution - Corben Douglas](http://www.sxcurity.pro/H1-212%20CTF%20Solution.pdf)
##### sort end

------------
### <a name="general"></a>General
* [Fundamentals That Time Forgot - Jup1t3r  - BSides SLC](https://www.youtube.com/watch?v=PQvUWImljOw)
* [pynessus](https://github.com/rmusser01/pynessus)
	* Python Parser for Nessus Output
* [Examples](http://www.hackwhackandsmack.com/?p=422)
* [TCPDump Primer](http://danielmiessler.com/study/tcpdump/)
* [IANA Complete list of assigned ports](http://www.vulnerabilityassessment.co.uk/port-numbers.txt)
* [which-cloud](https://github.com/bcoe/which-cloud)
	* Given an ip address, return which cloud provider it belongs to (AWS, GCE, etc)  
* [RFC 2827 -  Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing](https://tools.ietf.org/html/rfc2827)
* [RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246)
* [TCPDump Command Examples](http://www.thegeekstuff.com/2010/08/tcpdump-command-examples/)
* [The Eavesdropper’s Dillemma](http://www.crypto.com/papers/internet-tap.pdf)
* [Strange Attractors and TCP/IP Sequence Number Analysis  - Michal Zalewski](http://lcamtuf.coredump.cx/oldtcp/tcpseq.html)

------------
### <a name="attackw">Attacking Windows Networks</a>
* [Introducing PowerShell into your Arsenal with PS>Attack - Jared Haight](http://www.irongeek.com/i.php?page=videos/derbycon6/119-introducing-powershell-into-your-arsenal-with-psattack-jared-haight)
* [Get-Help: An Intro to PowerShell and How to Use it for Evil - Jared Haight](https://www.psattack.com/presentations/get-help-an-intro-to-powershell-and-how-to-use-it-for-evil/)
* [ShareCheck Windows Enumeration Tool v2.0 - sec1](http://www.sec-1.com/blog/2014/sharecheck)
* Lateral Movement
	* [*Puff* *Puff* PSExec - Lateral Movement: An Overview](https://www.toshellandback.com/2017/02/11/psexec/)
	* [Ditch PsExec, SprayWMI is here ;)](http://www.pentest.guru/index.php/2015/10/19/ditch-psexec-spraywmi-is-here/)
	* [WMIOps](https://github.com/ChrisTruncer/WMIOps)
		* WMIOps is a powershell script that uses WMI to perform a variety of actions on hosts, local or remote, within a Windows environment. It's designed primarily for use on penetration tests or red team engagements.
	* [spraywmi](https://github.com/trustedsec/spraywmi)
		* SprayWMI is a method for mass spraying Unicorn PowerShell injection to CIDR notations.
	* [psexec](https://github.com/pentestgeek/smbexec)
		* A rapid psexec style attack with samba tools
		* [Blogpost that inspired it](http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html)
	* [sshuttle](https://github.com/apenwarr/sshuttle)
		* Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.
	* [PowerShell PSRemoting Pwnage](https://pentestn00b.wordpress.com/2016/08/22/powershell-psremoting-pwnage/)
	* [PowerShell Remoting for Penetration Testers ](https://lockboxx.blogspot.com/2015/07/powershell-remoting-for-penetration.html)
* Pass-the-Hash
	* [Pass the hash - Wikipedia](https://en.wikipedia.org/wiki/Pass_the_hash)
	* [Pass the hash attacks: Tools and Mitigation - 2010 SANS paper](https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283)
	* [Performing Pass-the-Hash Attacks with Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
	* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
	* [Still Passing the Hash 15 Years Later](https://passing-the-hash.blogspot.com/)
		* Providing all the extra info that didn't make it into the BlackHat 2012 USA Presentation "Still Passing the Hash 15 Years Later? Using the Keys to the Kingdom to Access All Your Data" by Alva Lease 'Skip' Duckwall IV and Christopher Campbell.
	* [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)
		* Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB services are accessed through .NET TCPClient connections. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
* Passing the Ticket Attacks
	* [How To Pass the Ticket Through SSH Tunnels](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
	* [Mimikatz and Active Directory Kerberos Attacks ](https://adsecurity.org/?p=556)
	* Silver Tickets
		* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
	* Gold Tickets
		* [mimikatz - Golden Ticket](http://rycon.hu/papers/goldenticket.html)
		* [The Golden Ticket Attack - A Look Under The Hood](http://cybersecology.com/wp-content/uploads/2016/05/Golden_Ticket-v1.13-Final.pdf)
		* [Kerberos Golden Ticket Protection Mitigating Pass-the-Ticket on Active Directory - CERT-EU](https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf)
		* [The path to the Golden Ticket](https://countuponsecurity.com/tag/pass-the-ticket/)
	* [The Secret Life of KRBTGT](https://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf)
	* [From Pass-the-Hash to Pass-the-Ticket with No Pain](http://resources.infosecinstitute.com/pass-hash-pass-ticket-no-pain/)
* RDP
	* [RDP hijacking-how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
	* [RDP Man-in-The-Middle attack ](https://theevilbit.blogspot.com/2014/04/rdp-man-in-middle-attack.html)
	* [ATTACKING RDP How to Eavesdrop on Poorly Secured RDP Connections - Adrian Vollmer 2017](https://www.exploit-db.com/docs/41621.pdf)
	* [RDPY](https://github.com/citronneur/rdpy)
		* RDPY is a pure Python implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (client and server side). RDPY is built over the event driven network engine Twisted. RDPY support standard RDP security layer, RDP over SSL and NLA authentication (through ntlmv2 authentication protocol).
	* [SSL -Man-In-The-Middle- attacks on RDP](https://web.archive.org/web/20161007044945/https://labs.portcullis.co.uk/blog/ssl-man-in-the-middle-attacks-on-rdp/)
	* [rdps2rdp](https://github.com/DiabloHorn/rdps2rdp)
		* Decrypt MITM SSL RDP and save to pcap
* Active Directory
	* Check under privesc/postex for More info
	* [Active Directory - Wikipedia](https://en.wikipedia.org/wiki/Active_Directory)
	* [AD Security Active Directory Resources](https://adsecurity.org/?page_id=41)
	* [AD Reading: Active Directory Core Concepts](http://adsecurity.org/?p=15)
	* [AD Reading: Active Directory Authentication & Logon](http://adsecurity.org/?p=20)
	* [MS Network Level Authentication](https://technet.microsoft.com/en-us/magazine/hh750380.aspx)
* Recon
	* [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
		* PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net *" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.
	* [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
		* AD PowerShell Recon Scripts
	* [Netview](https://github.com/mubix/netview)
		* Netview is a enumeration tool. It uses (with the -d) the current domain or a specified domain (with the -d domain) to enumerate hosts
	* [DomainTrustExplorer](https://github.com/sixdub/DomainTrustExplorer)
		* Python script for analyis of the "Trust.csv" file generated by Veil PowerView. Provides graph based analysis and output. The graph output will represent access direction (opposite of trust direction) 
* Getting Credentials	
	* [Dumping a Domain-s Worth of Passwords With Mimikatz pt. 2](http://www.harmj0y.net/blog/powershell/dumping-a-domains-worth-of-passwords-with-mimikatz-pt-2/)
	* [LLMNR and NBT-NS Poisoning Using Responder](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)
	* [Attacking ADFS Endpoints with PowerShell](http://www.irongeek.com/i.php?page=videos/derbycon6/118-attacking-adfs-endpoints-with-powershell-karl-fosaaen)
* Getting Domain Admin
	* [Attack Methods for Gaining Domain Admin Rights in Active Directory - hackingandsecurity](https://hackingandsecurity.blogspot.com/2017/07/attack-methods-for-gaining-domain-admin.html?view=timeslide)
* Kerberos
	* [Abusing Kerberos](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It-wp.pdf)
	* [krb5-enum-users - nse script](https://nmap.org/nsedoc/scripts/krb5-enum-users.html)
		* Discovers valid usernames by brute force querying likely usernames against a Kerberos service. When an invalid username is requested the server will respond using the Kerberos error code KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, allowing us to determine that the user name was invalid. Valid user names will illicit either the TGT in a AS-REP response or the error KRB5KDC_ERR_PREAUTH_REQUIRED, signaling that the user is required to perform pre authentication. 
* Slides
	* [Windows Attacks AT is the new black](https://www.slideshare.net/mubix/windows-attacks-at-is-the-new-black-26665607)
* Tools
	* [Responder](https://github.com/SpiderLabs/Responder/)
		* Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
	* [Enum4Linux](https://labs.portcullis.co.uk/tools/enum4linux/)
		* Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com. It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. The tool usage can be found below followed by examples, previous versions of the tool can be found at the bottom of the page.
* Sharepoint
	* [MS Sharepoint - Wikipedia](https://en.wikipedia.org/wiki/SharePoint)
* Tools
	* [Sparty - MS Sharepoint and Frontpage Auditing Tool](http://sparty.secniche.org/)
		* Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture. The motivation behind this tool is to provide an easy and robust way to scrutinize the security configurations of sharepoint and frontpage based web applications. Due to the complex nature of these web administration software, it is required to have a simple and efficient tool that gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. A number of automated scanners fall short of this and Sparty is a solution to that.
	* [SPScan](http://sourceforge.net/projects/spscan/)
		* SPScan is a tool written in Ruby that enumerates a SharePoint installation gathering information about the version and installed plugins.
	* [SPartan](https://github.com/sensepost/SPartan)
		* SPartan is a Frontpage and Sharepoint fingerprinting and attack tool


------------
### <a name="tools">General Tools</a>
* [Yersinia](http://www.yersinia.net/)
	* Yersinia is a network tool designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. 
* [netcat](http://nc110.sourceforge.net/)
	* Network Swiss army knife. Ncat-s predecessor. Does everything and the kitchen sink.
* [Ncat](http://nmap.org/)
	* Ncat is a feature-packed networking utility which reads and writes data across networks from the command line. Ncat was written for the Nmap Project as a much-improved reimplementation of the venerable Netcat. It uses both TCP and UDP for communication and is designed to be a reliable back-end tool to instantly provide network connectivity to other applications and users. Ncat will not only work with IPv4 and IPv6 but provides the user with a virtually limitless number of potential uses.
* [RANCID - Really Awesome New Cisco confIg Differ](http://www.shrubbery.net/rancid/)
	* RANCID monitors a router's (or more generally a device's) configuration, including software and hardware (cards, serial numbers, etc) and uses CVS (Concurrent Version System) or Subversion to maintain history of changes. RANCID does this by the very simple process summarized as: login to each device in the router table (router.db), run various commands to get the information that will be saved, cook the output; re-format, remove oscillating or incrementing data, email any differences (sample) from the previous collection to a mail list, and finally commit those changes to the revision control system





------------
#### <a name="activemq"></a>Apache ActiveMQ
* [a](https://github.com/fmtn/a)
	* ActiveMQ CLI testing and message management
* [Apache ActiveMQ - Wikipedia](https://en.wikipedia.org/wiki/Apache_ActiveMQ)
* [ActiveMQ](http://activemq.apache.org/)
* [Getting Started](http://activemq.apache.org/getting-started.html)
* [What is ActiveMQ used for? - StackOverflow](https://stackoverflow.com/questions/12805377/what-is-activemq-used-for)




------------
#### <a name="bitsquat"></a>BitSquatting:
* [DEFCON 19: Bit-squatting: DNS Hijacking Without Exploitation (w speaker)](https://www.youtube.com/watch?v=aT7mnSstKGs)
	* [Bitsquatting - DNS Hijacking without Exploitation - Artem Dinaburg](https://media.blackhat.com/bh-us-11/Dinaburg/BH_US_11_Dinaburg_Bitsquatting_WP.pdf)
	* [Blogpost - Bitsquatting: DNS Hijacking without exploitation](http://dinaburg.org/bitsquatting.html)
[Bitsquatting - benjaminpetrin](https://github.com/benjaminpetrin/bitsquatting)
	* This repository includes a simple toy DNS server written in Python3 for use in conducting research in bitsquatting (bitsquat_dns.py). It also includes a helper script for generating the necessary permutations of a domain (domain_gen.py). The remainder of this README includes further documentation of the included DNS server, and a brief summary of my results running this on the web for a period in 2015.
* [Bitsquatting: Exploiting Bit-flips for Fun, or Profit?](http://www.securitee.org/files/bitsquatting_www2013.pdf)
* [digbit](https://github.com/mnmnc/digbit/blob/master/README.md)
	* Automatic domain generation for BitSquatting


------------
#### <a name="dns"></a>DNS:
* Attacks
	* [DNS Cache Snooping or Snooping the Cache for Fun and Profit - Luis Grangeia](http://cs.unc.edu/~fabian/course_papers/cache_snooping.pdf)
	* [DNS Dark Matter Discovery Theres Evil In Those Queries - Jim Nitterauer](https://www.youtube.com/watch?v=-A2Wqagz73Y)
	* [DNS hijacking using cloud providers - Frans Ros-n](https://www.youtube.com/watch?v=HhJv8CU-RIk)
	* [Enumerating DNSSEC NSEC and NSEC3 Records](https://www.altsci.com/concepts/page.php?s=dnssec&p=1)
	* [DNS database espionage](http://dnscurve.org/espionage2.html)
	* [DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
		* Great talk on attacking DNS
	* [A penetration tester’s guide to sub-domain enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
	* [Secrets of DNS Ron Bowes - Derbycon4](https://www.youtube.com/watch?v=MgO-gPiVTSc)
* Educational
	* [DNS RFC - Domain Name System RFC's (IETF)](http://www.bind9.net/rfc)
	* [RFC 1034 - DOMAIN NAMES - CONCEPTS AND FACILITIES](https://www.ietf.org/rfc/rfc1034.txt)
	* [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://www.ietf.org/rfc/rfc1035.txt)
	* [DNS Reference Information - technet](https://technet.microsoft.com/en-us/library/dd197499(v=ws.10).aspx)
	* [DNS Records: an Introduction](https://www.linode.com/docs/networking/dns/dns-records-an-introduction)
* SubDomain
	* [Sub-domain enumeration - Reference](https://gist.github.com/yamakira/2a36d3ae077558ac446e4a89143c69ab)
	* [Altdns](https://github.com/infosec-au/altdns)
		* Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.
	* [AQUATONE](https://github.com/michenriksen/aquatone)
		* AQUATONE is a set of tools for performing reconnaissance on domain names. It can discover subdomains on a given domain by using open sources as well as the more common subdomain dictionary brute force approach. After subdomain discovery, AQUATONE can then scan the hosts for common web ports and HTTP headers, HTML bodies and screenshots can be gathered and consolidated into a report for easy analysis of the attack surface.
	* [Sublist3r](https://github.com/aboul3la/Sublist3r)
		* Fast subdomains enumeration tool for penetration testers
	* [dns-parallel-prober](https://github.com/lorenzog/dns-parallel-prober)
		* This script is a proof of concept for a parallelised domain name prober. It creates a queue of threads and tasks each one to probe a sub-domain of the given root domain. At every iteration step each dead thread is removed and the queue is replenished as necessary.
	* [enumall](https://github.com/Dhayalan96/enumall)
		* Script to enumerate subdomains, leveraging recon-ng. Uses google scraping, bing scraping, baidu scraping, yahoo scarping, netcraft, and bruteforces to find subdomains. Plus resolves to IP.
	* [Knockpy](https://github.com/guelfoweb/knock)
		* Knockpy is a python tool designed to enumerate subdomains on a target domain through a wordlist. It is designed to scan for DNS zone transfer and to try to bypass the wildcard DNS record automatically if it is enabled.
	* [sub6](https://github.com/YasserGersy/sub6)
		* subdomain take over detector and crawler
* Service
	* [DNS Dumpster](DNSdumpster.com)
		* free domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process
* Tools
	* [DNSRecon](https://github.com/darkoperator/dnsrecon)
		* [Quick Reference Guide](http://pentestlab.wordpress.com/2012/11/13/dns-reconnaissance-dnsrecon/)
	* [dns-discovery](https://github.com/mafintosh/dns-discovery)
		* Discovery peers in a distributed system using regular dns and multicast dns.
	* [TXTDNS](http://www.txdns.net/)
		* TXDNS is a Win32 aggressive multithreaded DNS digger. Capable of placing, on the wire, thousands of DNS queries per minute. TXDNS main goal is to expose a domain namespace trough a number of techniques: Typos: Mised, doouble and transposde keystrokes; TLD/ccSLD rotation; Dictionary attack; Full Brute-force attack using alpha, numeric or alphanumeric charsets; Reverse grinding.
	* [nsec3map](https://github.com/anonion0/nsec3map)
		* a tool to enumerate the resource records of a DNS zone using its DNSSEC NSEC or NSEC3 chain
	* [passivedns](https://github.com/gamelinux/passivedns)
		* A tool to collect DNS records passively
	* [DNS Recon](https://github.com/darkoperator/dnsrecon)
	* [DNSEnum](https://github.com/fwaeytens/dnsenum)
		* Multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.





------------
### <a name="ddos"></a>D/DOS
* [Denial-of-service attack - Wikipedia](https://en.wikipedia.org/wiki/Denial-of-service_attack)
* [Davoset](https://github.com/MustLive/DAVOSET) 
	* DAVOSET - it is console (command line) tool for conducting DDoS attacks on the sites via Abuse of Functionality and XML External Entities vulnerabilities at other sites.



-------------
### <a name="frameworks"></a>Frameworks
* [BackDoor Factory](https://github.com/secretsquirrel/the-backdoor-factory)
	* The goal of BDF is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state.
	* [Wiki](https://github.com/secretsquirrel/the-backdoor-factory/wiki)
	* [Video](http://www.youtube.com/watch?v=jXLb2RNX5xs)
* [Man-in-the-Middle Framework](https://github.com/byt3bl33d3r/MITMf)
	* Framework for Man-In-The-Middle attacks
* [Veil](https://github.com/Veil-Framework/Veil)
	* Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions.
	* Veil Tutorials:
		* [Framework Usage Tutorial](https://www.veil-framework.com/veil-tutorial/)
		* [Payload Creation Tutorial](https://www.veil-framework.com/tutorial-veil-payload-development/)
		* [Customizing backdoors with Veil](https://www.veil-framework.com/how-to-customize-backdoor-factory-payloads-within-veil/)
		* [Creating a windows payload](https://www.youtube.com/watch?v=v1OXNP_bl8U)
* [Adventures in Asymmetric Warfare by Will Schroeder](https://www.youtube.com/watch?v=53qQfCkVM_o)



------------
### <a name="evasion">icmp</a>ICMP
* [ICMP RFC - Network Sorcery](http://www.networksorcery.com/enp/protocol/icmp.htm)
* [RFC 792 - Internet Control Message Protocol](https://tools.ietf.org/html/rfc792)
* [Internet Control Message Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
* [BlackNurse attack PoC](https://github.com/jedisct1/blacknurse)
	* A simple PoC for the Blacknurse attack. "Blacknurse is a low bandwidth ICMP attack that is capable of doing denial of service to well known firewalls".


------------
### <a name="evasion">IDS/IPS Evasion</a>
* [Intrusion Detection System](https://en.wikipedia.org/wiki/Intrusion_detection_system)
* [Intrusion detection evasion:  How Attackers get past the burglar alarm](http://www.sans.org/reading-room/whitepapers/detection/intrusion-detection-evasion-attackers-burglar-alarm-1284)
	* The purpose of this paper is to show methods that attackers can use to fool IDS systems into thinking their attack is legitimate traffic. With techniques like obfuscation, fragmentation, Denial of Service, and application hijacking the attacker can pass traffic under the nose of an IDS to prevent their detection. These are techniques that the next generation of IDS needs to be able to account for and prevent. Since it would be almost impossible to create a product that was not vulnerable to one of these deceptions.
* [Beating the IPS](http://www.sans.org/reading-room/whitepapers/intrusion/beating-ips-34137) 
	* This paper introduces various Intrusion Prevention System (IPS) evasion techniques and shows how they can be used to successfully evade detection by widely used products from major security vendors. By manipulating the header, payload, and traffic flow of a well-known attack, it is possible to trick the IPS inspection engines into passing the traffic - allowing the attacker shell access to the target system protected by the IPS.
* [Firewall/IDS Evasion and Spoofing](https://nmap.org/book/man-bypass-firewalls-ids.html)
* [IDS/IPS Evasion Techniques - Alan Neville](http://www.redbrick.dcu.ie/~anev/IDS_IPS_Evasion_Techniques.pdf)
* [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://insecure.org/stf/secnet_ids/secnet_ids.html)http://insecure.org/stf/secnet_ids/secnet_ids.html)
* [Evading IDS/IPS by Exploiting IPv6 Features - Antonios Atlasis, Rafael Schaefer](https://www.youtube.com/watch?v=avMeYIaU8DA&list=PL1eoQr97VfJni4_O1c3kBCCWwxu-6-lqy)
* [wafw00f](https://github.com/sandrogauci/wafw00f) *  WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.
* [HTTP Evasions Explained - Part 6 - Attack of the White-Space](http://noxxi.de/research/http-evader-explained-6-whitespace.html)
	* This is part six in a series which will explain the evasions done by HTTP Evader. This part is about misusing white-space to bypass the firewall.
* [Fire Away Sinking the Next Gen Firewall Russell Butturini - Derbycon6](https://www.youtube.com/watch?v=Qpty_f0Eu7Y)
* [Passive IPS Reconnaissance and Enumeration - false positive (ab)use - Arron Finnon](https://vimeo.com/108775823)
	* Network Intrusion Prevention Systems or NIPS have been plagued by "False Positive" issues almost since their first deployment. A "False Positive" could simply be described as incorrectly or mistakenly detecting a threat that is not real. A large amount of research has gone into using "False Positive" as an attack vector either to attack the very validity of an IPS system or to conduct forms of Denial of Service attacks. However the very reaction to a "False Positive" in the first place may very well reveal more detailed information about defences than you might well think.
* [Attacking Nextgen Firewalls](https://www.youtube.com/watch?v=ZoCf9yWC32g)
* [Dalton](https://github.com/secureworks/dalton)
	* Dalton is a system that allows a user to quickly and easily run network packet captures ("pcaps") against an intrusion detection system ("IDS") sensor of his choice (e.g. Snort, Suricata) using defined rulesets and/or bespoke rules.



------------
### <a name="ipspoofing"></a>IP Spoofing
* [State of IP Spoofing](https://spoofer.caida.org/summary.php)





------------
### <a name="ipmi"></a>IPMI
* [Intelligent Platform Managment Interface Documentation - Intel](https://www.intel.com/content/www/us/en/servers/ipmi/ipmi-home.html)
* [IPMI Basics](https://www.thomas-krenn.com/en/wiki/IPMI_Basics)
* [Intelligent Platform Management Interface - Wikipedia](https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface)
* [A Penetration Tester's Guide to IPMI and BMCs](https://blog.rapid7.com/2013/07/02/a-penetration-testers-guide-to-ipmi/)
* [OpenIPMI](http://openipmi.sourceforge.net/)
* [Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)
* [IPMI – A Gentle Introduction with OpenIPMI](http://openipmi.sourceforge.net/IPMI.pdf)




------------
### <a name="ipv6">IPv6 Related</a>
[IPv6—101: Introduction - F5](http://securite.net.au/wp-content/uploads/2014/05/F5s-IPV6-Introduction.pdf)
* [Introduction to IPv6 Fundamentals - Cisco](https://www.youtube.com/watch?v=PdGLmeq-6Bg)
* [IPv6 - Wikipedia](https://en.wikipedia.org/wiki/IPv6)
* [RFC 2460 - Internet Protocol, Version 6 (IPv6)](https://tools.ietf.org/html/rfc2460)
* IPv6: Basic Attacks and Defences - Christopher Werny[TROOPERS15]
	* [Part 1](https://www.youtube.com/watch?v=Y8kjQEGHbAU)
	* [Part 2](https://www.youtube.com/watch?v=V-GYPp-j-lE)
	* [Exploiting Tomorrow's Internet Today: Penetration testing with IPv6](http://uninformed.org/?v=all&a=46&t=sumry)
	* This paper illustrates how IPv6-enabled systems with link-local and auto-configured addresses can be compromised using existing security tools. While most of the techniques described can apply to "real" IPv6 networks, the focus of this paper is to target IPv6-enabled systems on the local network. 
* [IPv6 Toolkit](https://github.com/fgont/ipv6toolkit)
	* SI6 Networks' IPv6 Toolkit
* [THC-IPv6](https://www.thc.org/thc-ipv6/)
	*  A complete tool set to attack the inherent protocol weaknesses of IPV6
 and ICMP6, and includes an easy to use packet factory library.
* [[TROOPERS15] Merike Kaeo - Deploying IPv6 Securely - Avoiding Mistakes Others Have Made](https://www.youtube.com/watch?v=rQg4y78xHf8)
* [IPv6 Local Neighbor Discovery Using Router Advertisement](https://www.rapid7.com/db/modules/auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement)
	* Send a spoofed router advertisement with high priority to force hosts to start the IPv6 address auto-config. Monitor for IPv6 host advertisements, and try to guess the link-local address by concatinating the prefix, and the host portion of the IPv6 address. Use NDP host solicitation to determine if the IP address is valid'
* [IPv6 - Playing with IPv6 for fun and profit](https://github.com/zbetcheckin/IPv6)



------------
#### <a name="kerberos"></a>Kerberos
Kerberos
* 

------------
#### <a name="ldap"></a>LDAP
* [Lightweight Directory Access Protocol - Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
* [Basic LDAP Concepts - ldap.com](https://www.ldap.com/basic-ldap-concepts)
* [Lightweight Directory Access Protocol (LDAP): Technical Specification Road Map](https://tools.ietf.org/html/rfc4510)
* [Lightweight Directory Access Protocol (LDAP): The Protocol](https://tools.ietf.org/html/rfc4511)
* Attacking
	* [Public Facing LDAP Enumeration](https://www.lanmaster53.com/2013/05/24/public-facing-ldap-enumeration/)
	* [Dangers of LDAP NULL Base and Bind](https://securitysynapse.blogspot.com/2013/09/dangers-of-ldap-null-base-and-bind.html)
* Tools
	* [JXplorer](http://jxplorer.org/)
		* JXplorer is a cross platform LDAP browser and editor. It is a standards compliant general purpose LDAP client that can be used to search, read and edit any standard LDAP directory, or any directory service with an LDAP or DSML interface. It is highly flexible and can be extended and customised in a number of ways. JXplorer is written in java, and the source code and Ant build system are available via svn or as a packaged build for users who want to experiment or further develop the program. 
	* [LDAPMfINER](http://ldapminer.sourceforge.net/)
		* This is a tool I wrote to collect information from different LDAP Server implementation. This was written in C with the Netscape C 
	* [Softera LDAP Browser](http://www.ldapbrowser.com/info_softerra-ldap-browser.htm)
		* LDAP Browser that supports most LDAP implementations. Non-free software, 30-day free trial


### <a name="mitm"></a>MitM Tools
* [Dsniff](http://www.monkey.org/~dugsong/dsniff/)
	* dsniff is a collection of tools for network auditing and penetration testing. dsniff, filesnarf, mailsnarf, msgsnarf, urlsnarf, and webspy passively monitor a network for interesting data (passwords, e-mail, files, etc.). arpspoof, dnsspoof, and macof facilitate the interception of network traffic normally unavailable to an attacker (e.g, due to layer-2 switching). sshmitm and webmitm implement active monkey-in-the-middle attacks against redirected SSH and HTTPS sessions by exploiting weak bindings in ad-hoc PKI. 
* [Ettercap](https://ettercap.github.io/ettercap/)
	* Ettercap is a comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.
* [net-creds](https://github.com/DanMcInerney/net-creds)
	* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification. It sniffs: URLs visited; POST loads sent; HTTP form logins/passwords; HTTP basic auth logins/passwords; HTTP searches; FTP logins/passwords; IRC logins/passwords; POP logins/passwords; IMAP logins/passwords; Telnet logins/passwords; SMTP logins/passwords; SNMP community string; NTLMv1/v2 all supported protocols like HTTP, SMB, LDAP, etc; Kerberos.
* RDP
	* [Seth](https://github.com/SySS-Research/Seth)
		* Seth is a tool written in Python and Bash to MitM RDP connections. It attempts to downgrade the connection and extract clear text credentials.
* NTLM/SMB/NTBS
	* [NTLMssp-Extract](https://github.com/sinnaj-r/NTLMssp-Extract)
		* A small Python-Script to extract NetNTLMv2 Hashes from NTMLssp-HTTP-Authentications, which were captured in a pcap.
	* [ntlmRelayToEWS](https://github.com/Arno0x/NtlmRelayToEWS)
		* ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS). It spawns an SMBListener on port 445 and an HTTPListener on port 80, waiting for incoming connection from the victim. Once the victim connects to one of the listeners, an NTLM negociation occurs and is relayed to the target EWS server.
* SSL/TLS
	* [SSLsplit - transparent and scalable SSL/TLS interception](https://www.roe.ch/SSLsplit)
		* SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit. SSLsplit terminates SSL/TLS and initiates a new SSL/TLS connection to the original destination address, while logging all data transmitted. SSLsplit is intended to be useful for network forensics and penetration testing.  SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6.
	* [SSLStrip](http://www.thoughtcrime.org/software/sslstrip/)
		* This tool provides a demonstration of the HTTPS stripping attacks that I presented at Black Hat DC 2009. It will transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.
* WSUS(Windows Server Updater Serice)
	* [WSUXploit](https://github.com/pimps/wsuxploit)
		* This is a MiTM weaponized exploit script to inject 'fake' updates into non-SSL WSUS traffic. It is based on the WSUSpect Proxy application that was introduced to public on the Black Hat USA 2015 presentation, 'WSUSpect - Compromising the Windows Enterprise via Windows Update'





------------
#### <a name="modbus"></a>Modbus
* See 'Modbus' in 'SCADA/Heavy Machinery'
* [Modbus interface tutorial](https://www.lammertbies.nl/comm/info/modbus.html)


------------
#### <a name="MQTT"></a>MQTT
* [MQTT](http://mqtt.org/)
	* MQTT is a machine-to-machine (M2M)/"Internet of Things" connectivity protocol. It was designed as an extremely lightweight publish/subscribe messaging transport. 
* [MQTT - Wikipedia](https://en.wikipedia.org/wiki/MQTT)
* [MQTT 101 – How to Get Started with the lightweight IoT Protocol](https://www.hivemq.com/blog/how-to-get-started-with-mqtt)




------------
#### <a name="netbios"></a>Netbios
* [NetBIOS - Wikipedia](https://en.wikipedia.org/wiki/NetBIOS)
* [NetBIOS - rhyshaden.com](http://www.rhyshaden.com/netbios.htm)
* [Local Network Attacks: LLMNR and NBT-NS Poisoning](https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning)
* [NbtScan](http://www.unixwiz.net/tools/nbtscan.html)
	* This is a command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network, and this is a first step in finding of open shares. It is based on the functionality of the standard Windows tool nbtstat, but it operates on a range of addresses instead of just one. I wrote this tool because the existing tools either didn't do what I wanted or ran only on the Windows platforms: mine runs on just about everything.
* [Responder](https://github.com/lgandx/Responder)
	* Responder an LLMNR, NBT-NS and MDNS poisoner. It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answer to File Server Service request, which is for SMB. The concept behind this is to target our answers, and be stealthier on the network. This also helps to ensure that we don't break legitimate NBT-NS behavior. You can set the -r option via command line if you want to answer to the Workstation Service request name suffix.




------------
#### <a name="host"></a>Network Host Discovery/Service Discovery:
* Informational
	* [Nmap you’re doing it wrong - sneakerhax](https://sneakerhax.com/nmap-yourre-doing-it-wrong/)
	* [Recon at scale - sneakerhax](https://sneakerhax.com/recon-at-scale/)
	* [Nmap Reference Guide](https://nmap.org/book/man.html)
	* [Security.StackExchange Answer detailing Nmap Scanning tips and tactics - very good](https://security.stackexchange.com/questions/373/open-source-penetration-test-automation/82529#82529)
	* [Massively Scaling your Scanning - SANS](https://pen-testing.sans.org/blog/2017/10/25/massively-scaling-your-scanning)
	* [Mass Scanning the Internet: Tips, Tricks, Results - DEF CON 22 - Graham, Mcmillan, and Tentler](https://www.youtube.com/watch?v=nX9JXI4l3-E)
* Firewall
	* [Firewalk](http://packetfactory.openwall.net/projects/firewalk/)
		* Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a  given IP forwarding device will pass. Firewalk  works  by sending out TCP or UDP packets with a TTL one greater than the targeted gateway.  If the gateway allows the traffic, it will forward the packets to the next hop where they will expire and elicit an ICMP_TIME_EXCEEDED  message.  If the gateway hostdoes not allow the traffic, it will likely drop the packets on  the floor and we will see no response. To get  the  correct  IP  TTL that will result in expired packets one beyond the gateway we need  to  ramp  up  hop-counts.   We  do  this  in the same manner that traceroute works.  Once we have the gateway hopcount (at  that point the scan is said to be `bound`) we can begin our scan.
* General
	* [Nmap](http://nmap.org/)
		* Nmap ("Network Mapper") is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping). 
	* [NMAP - Port-Scanning: A Practical Approach Modified for better](https://www.exploit-db.com/papers/35425/)
	* [NSEInfo](https://github.com/christophetd/nmap-nse-info/blob/master/README.md)
	* NSEInfo is a tool to interactively search through nmap's NSE scripts.
	* [Nmap (XML) Parser documentation](https://nmap-parser.readthedocs.io/en/latest/)
	* [Scanning Effectively Through a SOCKS Pivot with Nmap and Proxychains](https://cybersyndicates.com/2015/12/nmap-and-proxychains-scanning-through-a-socks-piviot/)
			* [Script](https://github.com/killswitch-GUI/PenTesting-Scripts/blob/master/Proxychains-Nmap.py)
		* [ms15-034.nse Script](https://github.com/pr4jwal/quick-scripts/blob/master/ms15-034.nse)
	* [Angry IP Scanner](http://angryip.org/)
		* Angry IP Scanner (or simply ipscan) is an open-source and cross-platform network scanner designed to be fast and simple to use. It scans IP addresses and ports as well as has many other features. 
	* [ScanCannon](https://github.com/johnnyxmas/ScanCannon)
	* The speed of masscan with the reliability and detailed enumeration of nmap!
	* [UnicornScan](http://www.unicornscan.org/)
		* Unicornscan is a new information gathering and correlation engine built for and by members of the security research and testing communities. It was designed to provide an engine that is Scalable, Accurate, Flexible, and Efficient. It is released for the community to use under the terms of the GPL license. 
		* Editor note: Use this to mass scan networks. It-s faster than nmap at scanning large host lists and allows you to see live hosts quickly.
	* [hping](http://www.hping.org/)
		* hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface is inspired to the ping(8) unix command, but hping isn't only able to send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode, the ability to send files between a covered channel, and many other features. 
	* [Ever wanted to scan the internet in a few hours?](http://blog.erratasec.com/2013/10/faq-from-where-can-i-scan-internet.html)
	* [Adding your protocol to Masscan](http://blog.erratasec.com/2014/11/adding-protocols-to-masscan.html)
	* [Consul](https://github.com/hashicorp/consul)
		* Consul is a tool for service discovery and configuration. Consul is distributed, highly available, and extremely scalable.
	* [gateway-finder](https://github.com/pentestmonkey/gateway-finder)
		* Gateway-finder is a scapy script that will help you determine which of the systems on the local LAN has IP forwarding enabled and which can reach the Internet.
* Tor
	* [exitmap](https://github.com/NullHypothesis/exitmap)
		* A fast and modular scanner for Tor exit relays. http://www.cs.kau.se/philwint/spoiled_onions/ 
	* [OnionScan](https://github.com/s-rah/onionscan)
		* [What OnionScan Scans for](https://github.com/s-rah/onionscan/blob/master/doc/what-is-scanned-for.md)
* VHost Scanning
	* [hostmap](https://github.com/jekil/hostmap)
		* hostmap is a free, automatic, hostnames and virtual hosts discovery tool written in Ruby by Alessandro Tanasi
* Cloudflare
	* [CloudFail](https://github.com/m0rtem/CloudFail)
		* CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by CloudFlare in the hopes of discovering the location of the server.
	* [HatCloud](https://github.com/HatBashBR/HatCloud)
		* HatCloud build in Ruby. It makes bypass in CloudFlare for discover real IP. This can be useful if you need test your server and website. Testing your protection against Ddos (Denial of Service) or Dos. CloudFlare is services and distributed domain name server services, sitting between the visitor and the Cloudflare user's hosting provider, acting as a reverse proxy for websites. Your network protects, speeds up and improves availability for a website or the mobile application with a DNS change.
* Cisco
	* [CiscoRouter - tool](https://github.com/ajohnston9/ciscorouter)
		* CiscoRouter is a tool for scanning Cisco-based routers over SSH. Rules can be created using accompanying CiscoRule application (see this repo) and stored in the "rules" directory.
	* [discover - Kali Scripts](https://github.com/leebaird/discover)
		* For use with Kali Linux - custom bash scripts used to automate various portions of a pentest.
	* [changeme - A default credential scanner.](https://github.com/ztgrace/changeme)
		* changeme picks up where commercial scanners leave off. It focuses on detecting default and backdoor credentials and not necessarily common credentials. It's default mode is to scan HTTP default credentials, but has support for other credentials. changeme is designed to be simple to add new credentials without having to write any code or modules. changeme keeps credential data separate from code. All credentials are stored in yaml files so they can be both easily read by humans and processed by changeme. Credential files can be created by using the ./changeme.py --mkcred tool and answering a few questions. changeme supports the http/https, mssql, mysql, postgres, ssh, ssh w/key, snmp, mongodb and ftp protocols. Use ./changeme.py --dump to output all of the currently available credentials.
* [scanless](https://github.com/vesche/scanless)
	* Command-line utility for using websites that can perform port scans on your behalf. Useful for early stages of a penetration test or if you'd like to run a port scan on a host and have it not come from your IP address.
* [device-pharmer](https://github.com/DanMcInerney/device-pharmer)
	* Opens 1K+ IPs or Shodan search results and attempts to login 


* [Sn1per](https://github.com/1N3/Sn1per)
	* Sn1per is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities.
------------
### <a name="nfs"></a>NFS
* [Network File System](https://en.wikipedia.org/wiki/Network_File_System)
* [NFS - ArchWiki](https://wiki.archlinux.org/index.php/NFS)
* [Linux NFS Documentation](http://nfs.sourceforge.net/)
	* This document provides an introduction to NFS as implemented in the Linux kernel. It links to developers' sites, mailing list archives, and relevant RFCs, and provides guidance for quickly configuring and getting started with NFS on Linux. A Frequently Asked Questions section is also included. This document assumes the reader is already familiar with generic NFS terminology.
* [NfSpy](https://github.com/bonsaiviking/NfSpy)
	* NfSpy is a Python library for automating the falsification of NFS credentials when mounting an NFS share.
* [Using nfsshell to compromise older environments](https://www.pentestpartners.com/security-blog/using-nfsshell-to-compromise-older-environments/)
* [Abusing Hardlinks Via NFS](http://pentestmonkey.net/blog/nfs-hardlink)
* [Exploiting Network File System, (NFS), shares - vulnerabilityassessment.co.uk](http://www.vulnerabilityassessment.co.uk/nfs.htm)
* [NFS: Network File System Protocol Specification - rfc1094](https://tools.ietf.org/html/rfc1094)


------------
### <a name="pivot"></a>Pivoting
* Really, look at the Pivoting section in Post Exploitation/Privilege Escalation




------------
#### <a name="proxy"></a>Proxies


* [Mallory](https://bitbucket.org/IntrepidusGroup/mallory)
	* Mallory is an extensible TCP/UDP man in the middle proxy that is designed  to be run as a gateway. Unlike other tools of its kind, Mallory supports  modifying non-standard protocols on the fly.
* [SSLStrip](http://www.thoughtcrime.org/software/sslstrip/)
	* This tool provides a demonstration of the HTTPS stripping attacks that I presented at Black Hat DC 2009. It will transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.
* [Echo Mirage](http://www.wildcroftsecurity.com/echo-mirage)
	* Echo Mirage is a generic network proxy. It uses DLL injection and function hooking techniques to redirect network related function calls so that data transmitted and received by local applications can be observed and modified. Windows encryption and OpenSSL functions are also hooked so that plain text of data being sent and received over an encrypted session is also available. Traffic can be intercepted in real-time, or manipulated with regular expressions and a number of action directives
* [Burp Proxy](http://portswigger.net/burp/proxy.html)
	* Burp Proxy is an intercepting proxy server for security testing of web applications. It operates as a man-in-the-middle between your browser and the target application
* [Charles Proxy](https://www.charlesproxy.com/)
	* Charles is an HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet. This includes requests, responses and the HTTP headers (which contain the cookies and caching information).
* [OWASP Zed Attack Proxy](http://www.zaproxy.org/)
	* [Zed Attack Proxy (ZAP) Community Scripts](https://github.com/zaproxy/community-scripts)
		* A collection of ZAP scripts provided by the community - pull requests very welcome! 
* [Phreebird](http://dankaminsky.com/phreebird/) 
	* Phreebird is a DNSSEC proxy that operates in front of an existing DNS server (such as BIND, Unbound, PowerDNS, Microsoft DNS, or QIP) and supplements its records with DNSSEC responses. Features of Phreebird include automatic key generation, realtime record signing, support for arbitrary responses, zero configuration, NSEC3 -White Lies-, caching and rate limiting to deter DoS attacks, and experimental support for both Coarse Time over DNS and HTTP Virtual Channels. The suite also contains a large amount of sample code, including support for federated identity over OpenSSH. Finally, -Phreeload- enhances existing OpenSSL applications with DNSSEC support.
* [TCP Catcher](http://www.tcpcatcher.org/)
	* TcpCatcher is a free TCP, SOCKS, HTTP and HTTPS proxy monitor server software. 
* [DNS Chef](https://github.com/amckenna/DNSChef)
	* This is a fork of the DNSChef project v0.2.1 hosted at: http://thesprawl.org/projects/dnschef/
* [Squid Proxy](http://www.squid-cache.org/)
	* Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator. It runs on most available operating systems, including Windows and is licensed under the GNU GPL.
* [SharpSocks](https://github.com/nettitude/SharpSocks)
	* Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
* [ssf - Secure Socket Funneling](https://github.com/securesocketfunneling/ssf)
	* Network tool and toolkit. It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS tunnel to a remote computer. SSF is cross platform (Windows, Linux, OSX) and comes as standalone executables.
* [PowerCat](https://github.com/secabstraction/PowerCat)
	* A PowerShell TCP/IP swiss army knife that works with Netcat & Ncat





-------------
### <a name="pxe"></a>PXE
* [Use DHCP to detect UEFI or Legacy BIOS system and PXE boot to SCCM](http://www.itfaq.dk/2016/07/27/use-dhcp-to-detect-uefi-or-legacy-bios-system-and-pxe-boot-to-sccm/)



RabbitMQ/ZeroMQ
* [Enteletaor](https://github.com/cr0hn/enteletaor)
	* Message Queue & Broker Injection tool that implements attacks to Redis, RabbitMQ and ZeroMQ.
* [RabbitMQ - Wikipedia](https://en.wikipedia.org/wiki/RabbitMQ)






-------------
### <a name="sdn"></a>Software Defined Networking (SDN)
* [DELTA: SDN SECURITY EVALUATION FRAMEWORK](https://github.com/OpenNetworkingFoundation/DELTA)
	* DELTA is a penetration testing framework that regenerates known attack scenarios for diverse test cases. This framework also provides the capability of discovering unknown security problems in SDN by employing a fuzzing technique.






------------
#### <a name="SIP"></a>SIP/VOIP:
* [A Hitchhiker's Guide to the Session Initiation Protocol (SIP)](https://tools.ietf.org/html/rfc5411)
* [Session Initiation Protocol - Wikipedia](https://en.wikipedia.org/wiki/Session_Initiation_Protocol)
* [sipvicious](https://github.com/EnableSecurity/sipvicious)
* [bluebox-ng](https://github.com/jesusprubio/bluebox-ng)
	* Pentesting framework using Node.js powers, focused in VoIP.






------------
#### <a name="smb"></a>SMB

* [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
* [Microsoft SMB Protocol and CIFS Protocol Overview](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx)
* [WinNT/Win95 Automatic Authentication Vulnerability (IE Bug #4)](http://insecure.org/sploits/winnt.automatic.authentication.html)
* [SMB: Sharing More than Just Your Files - BH USA 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Brossard-SMBv2-Sharing-More-Than-Just-Your-Files.pdf)
* [Stealing Windows Credentials Using Google Chrome](http://www.defensecode.com/whitepapers/Stealing-Windows-Credentials-Using-Google-Chrome.pdf)
* [SMB Relay Demystified and NTLMv2 Pwnage with Python](https://pen-testing.sans.org/blog/2013/04/25/smb-relay-demystified-and-ntlmv2-pwnage-with-python)
* [Responder](https://github.com/lgandx/Responder)
	* Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
* [SPEAR: Redirect to SMB](https://blog.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf)
* [Resurrection of the Living Dead: The “Redirect to SMB” Vulnerability](http://blog.trendmicro.com/trendlabs-security-intelligence/resurrection-of-the-living-dead-the-redirect-to-smb-vulnerability/)

------------
#### <a name="smtp"></a>SMTP:
* [RFC 821 - SIMPLE MAIL TRANSFER PROTOCOL](https://tools.ietf.org/html/rfc821)
* [RFC 5321 - Simple Mail Transfer Protocol](https://tools.ietf.org/html/rfc5321)
* [Simple Mail Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)
* [Simple Mail Transfer Protocol - msdn](https://msdn.microsoft.com/en-us/library/aa480435.aspx)
* [SMTP User Enumeration](https://pentestlab.blog/2012/11/20/smtp-user-enumeration/)
* [Swaks - Swiss Army Knife for SMTP](http://www.jetmore.org/john/code/swaks/)




------------
#### <a name="snmp"></a>SNMP:
* [Simple Network Management Protocol - Wikipedia](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
* [SNMP Attacks and Security - Mauno Pihelgas](https://home.cyber.ee/~ahtbu/CDS2011/MaunoPihelgasSlides.pdf)
* [SNMP REFLECTION/AMPLIFICATION](https://www.incapsula.com/ddos/attack-glossary/snmp-reflection.html)*
* [Onesixtyone](http://www.phreedom.org/software/onesixtyone/)
	* onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance. It can scan an entire class B network in under 13 minutes. It can be used to discover devices responding to well-known community names or to mount a dictionary attack against one or more SNMP devices.
* [SNMPWALK](http://net-snmp.sourceforge.net/docs/man/snmpwalk.html)
	*  snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests
* [Simple Network Management Pwnd](http://www.irongeek.com/i.php?page=videos/derbycon4/t221-simple-network-management-pwnd-deral-heiland-and-matthew-kienow)
* [Cisc0wn - Cisco SNMP Script](https://github.com/nccgroup/cisco-SNMP-enumeration)
	* Automated Cisco SNMP Enumeration, Brute Force, Configuration Download and Password Cracking





------------
#### <a name="sql"></a>SQL:
* See 'SQL' in the Web Section.
* [SQLMap](https://github.com/sqlmapproject/sqlmap)

	* sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.
* [PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server](https://github.com/NetSPI/PowerUpSQL)
	* The PowerUpSQL module includes functions that support SQL Server discovery, auditing for common weak configurations, and privilege escalation on scale. It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that could be used by administrators to quickly inventory the SQL Servers in their ADS domain.
	* [Documentation](https TLS/SSL Vulnerabilities ://github.com/NetSPI/PowerUpSQL/wiki)
* [Overview of PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki/Overview-of-PowerUpSQL)
* [Using Metasploit to Find Vulnerable MSSQL Systems](https://www.offensive-security.com/metasploit-unleashed/hunting-mssql/)
* [nmap ms-sql-info.nse](https://nmap.org/nsedoc/scripts/ms-sql-info.html)





------------
#### <a name="ssh"></a>SSH: 
* [The Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4253)
* [OpenSSH Specs](https://www.openssh.com/specs.html)
* [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
* [The SSH Protocol - Snailbook](http://www.snailbook.com/protocols.html)
* [SSH for Fun and Profit](https://karla.io/2016/04/30/ssh-for-fun-and-profit.html)
* [OpenSSH User Enumeration Time-Based Attack](http://seclists.org/fulldisclosure/2013/Jul/88)
* [ssh-audit](https://github.com/arthepsy/ssh-audit)
	* SSH server auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)




--------------
#### <a name="ssl"></a>SSL/TLS
* [RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2 ]
* [Transport Layer Security - Wikipedia](https://en.wikipedia.org/wiki/Transport_Layer_Security)
[TLS/SSL Vulnerabilities](https://www.gracefulsecurity.com/tls-ssl-vulnerabilities/)
* [SSL/TLS and PKI History](https://www.feistyduck.com/ssl-tls-and-pki-history/)
	* A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem. Based on Bulletproof SSL and TLS, by Ivan Ristić.
* [testssl.sh](https://github.com/drwetter/testssl.sh)
	* testssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.
* [SSL & TLS Penetration Testing [Definitive Guide]](https://www.aptive.co.uk/blog/tls-ssl-security-testing/)


------------
#### <a name="stp"></a>STP: 
* [Spanning Tree Protocol - Wikipedia](https://en.wikipedia.org/wiki/Spanning_Tree_Protocol)
* [STP MiTM Attack and L2 Mitigation Techniques on the Cisco Catalyst 6500 ](http://www.ndm.net/ips/pdf/cisco/Catalyst-6500/white_paper_c11_605972.pdf)
* [Spanning Tree Protocol (STP) Introduction](http://www.dummies.com/programming/networking/cisco/spanning-tree-protocol-stp-introduction/)


------------
#### Telnet
* [Shellshock and the Telnet USER Variable](https://digi.ninja/blog/telnet_shellshock.php)
	* `telnet 10.1.1.1 -l "() { :;}; /usr/bin/id"`

------------
### <a name="upnp">TR-069</a>
* [TR-069 - Wikipedia](https://en.wikipedia.org/wiki/TR-069)
* [Too Many Cooks; Exploiting the Internet of Tr-069](http://mis.fortunecook.ie/) 
* [TR-069 – A Crash Course University of New Hampshire Interoperability Laboratory 2009](https://www.iol.unh.edu/sites/default/files/knowledgebase/hnc/TR-069_Crash_Course.pdf)



------------
### <a name="upnp">UPnP</a>
* [Universal Plug and Play (UPnP) Internet Gateway Device - Port Control Protocol Interworking Function (IGD-PCP IWF)](https://tools.ietf.org/html/rfc6970)
* [UPnP™ Device Architecture 1.1 - upnp.org]
* [UPNP Hacks](http://www.upnp-hacks.org/igd.html)
* [Universal Plug and Play - Wikipedia](https://en.wikipedia.org/wiki/Universal_Plug_and_Play)
* [Ufuzz](https://github.com/phikshun/ufuzz)
	* UFuzz, or Universal Plug and Fuzz, is an automatic UPnP fuzzing tool. It will enumerate all UPnP endpoints on the network, find the available services and fuzz them. It also has the capability to fuzz HTTP using Burp proxy logs.
* [miranda-upnp](https://github.com/0x90/miranda-upnp)
* [UPnP Pentest Toolkit](https://github.com/nccgroup/UPnP-Pentest-Toolkit)


------------
#### <a name="vlan"></a>VLANs
* [Virtual LAN](https://en.wikipedia.org/wiki/Virtual_LAN)
* [Virtual Local Area Networks](https://www.cse.wustl.edu/~jain/cis788-97/ftp/virtual_lans/index.html)
* [VLAN hopping, ARP Poisoning and Man-In-The-Middle Attacks in Virtualized Environments - Ronny L. Bull - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/110-vlan-hopping-arp-poisoning-and-man-in-the-middle-attacks-in-virtualized-environments-dr-ronny-l-bull)
	* Cloud service providers and data centers offer their customers the ability to deploy virtual machines within multi-tenant environments. These virtual machines are typically connected to the physical network via a virtualized network configuration. This could be as simple as a bridged interface to each virtual machine or as complicated as a virtual switch providing more robust networking features such as VLANs, QoS, and monitoring. In this talk I will demonstrate the effects of VLAN hopping, ARP poisoning and Man-in-the-Middle attacks across every major hypervisor platform, including results of attacks originating from the physically connected network as well as within the virtual networks themselves. Each attack category that is discussed will be accompanied by a detailed proof of concept demonstration of the attack.






------------
#### <a name="web"></a>Web:
* [WPScan](https://github.com/wpscanteam/wpscan)
	* WPScan is a black box WordPress vulnerability scanner.
* [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
	* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
* [webDisco](https://github.com/joeybelans/webDisco)
	* Web discovery tool to capture screenshots from a list of hosts & vhosts.  Requests are made via IP address and vhosts to determine differences. Additionallty checks for common administrative interfaces and web server  misconfigurations.
* [w3af](https://github.com/andresriancho/w3af)
	* w3af: web application attack and audit framework, the open source web vulnerability scanner.
* [PowerWebShot](https://github.com/dafthack/PowerWebShot)
	* A PowerShell tool for taking screenshots of multiple web servers quickly.

* [Event Tracing for Windows and Network Monitor](http://blogs.technet.com/b/netmon/archive/2009/05/13/event-tracing-for-windows-and-network-monitor.aspx)
	* "Event Tracing for Windows, (ETW), has been around for quite a while now as it was introduced in Windows 2000. It's basically instrumented logging that describes what a component is doing. Conceptually, it-s something like the proverbial printf("here1") concept used by programmers, but it is present in retail builds. When you enable logging in a component the result is an ETL (Event Trace Log) file. What-s new is that that Network Monitor can read any ETL file. And with the supplied parsers many network oriented ETW providers can be decoded."






------------
### <a name="other">Other</a>


* [Home Network Administration Protocol - Wikipedia](https://en.wikipedia.org/wiki/Home_Network_Administration_Protocol)
	* Home Network Administration Protocol (HNAP) is a proprietary network protocol invented[1] by Pure Networks, Inc. and acquired by Cisco Systems which allows identification, configuration, and management of network devices. HNAP is based on SOAP.[2]
* [More on HNAP - What is it, How to Use it,How to Find it](https://isc.sans.edu/diary/More+on+HNAP+-+What+is+it%2C+How+to+Use+it%2C+How+to+Find+it/17648)
* [HNAP - Router Security](https://www.routersecurity.org/hnap.php)
* [More on HNAP - What is it, How to Use it, How to Find it](https://isc.sans.edu/forums/diary/More+on+HNAP+What+is+it+How+to+Use+it+How+to+Find+it/17648/)
* [Home Network Administration Protocol (HNAP) Whitepaper](https://www.cisco.com/web/partners/downloads/guest/hnap_protocol_whitepaper.pdf)
* [Hacking D-Link Routers With HNAP](https://regmedia.co.uk/2016/11/07/dlink_hnap_captcha.pdf)


------------
#### <a name="misc"></a>MISC:
* [t50 - the fastest packet injector.](https://github.com/fredericopissarra/t50)
	* T50 was designed to perform -Stress Testing-  on a variety of infra-structure
network devices (Version 2.45), using widely implemented protocols, and after
some requests it was was re-designed to extend the tests (as of Version 5.3),
covering some regular protocols (ICMP,  TCP  and  UDP),  some infra-structure
specific protocols (GRE,  IPSec  and  RSVP), and some routing protocols (RIP,
EIGRP and OSPF).
* [C3CM: Defeating the Command - Control - and Communications of Digital Assailants](http://www.irongeek.com/i.php?page=videos/derbycon4/t206-c3cm-defeating-the-command-control-and-communications-of-digital-assailants-russ-mcree)
	* C3CM: the acronym for command- control- and communi - cations countermeasures. Ripe for use in the information security realm, C3CM takes us past C2 analysis and to the next level. Initially, C3CM was most often intended to wreck the command and control of enemy air defense networks, a very specific military mission. We-ll apply that mindset in the context of combating bots and other evil. Our version of C3CM therefore is to identify, interrupt, and counter the command, control, and communications capabilities of our digital assailants. The three phases of C3CM will utilize: Nfsight with Nfdump, Nfsen, and fprobe to conduct our identification phase, Bro with Logstash and Kibana for the interruption phase, and ADHD for the counter phase. Converge these on one useful platform and you too might have a chance deter those who would do you harm. We-ll discuss each of these three phases (identify, interrupt, and counter) with tooling and tactics, complete with demonstrations and methodology attendees can put to use in their environments. Based on the three part ISSA Journal Toolsmith series: http://holisticinfosec. blogspot.com/search?q=c3cm&max-results=20&by-date=true
