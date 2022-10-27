# Network Attacks & Defenses

--------------------------------------------------------
## Table of Contents
- [General](#general)
- [Protocols(Mostly)](#protocols)
    - [Advanced Query Message Protocol](#amqp)
    - [ARP](#arp)
    - [BGP](#bgp)
    - [DHCP](#dhcp)
    - [DNS](#dns)
        - [mDNS](#mdns)
        - [DNS over HTTPS(DoH)](#doh)
    - [gRPC](#grpc)
    - [HNAP](#hnap)
    - [ICMP](#icmp)
    - [IPMI](#ipmi)
    - [IPv4](#ipv4)
    - [IPv6 Related](#ipv6)
    - [IPSEC](#ipsec)
    - [Kerberos](#kerberos)
    - [LDAP](#ldap)
    - [Modbus](#modbus)
    - [MQTT](#mqtt)
    - [Network Address Translation](#nat)
    - [Netbios](#netbios)
    - [Network Host/Service Discovery](#host)
    - [NFS](#nfs)
    - [NTLM](#ntlm)
    - [PAC/WPAD](#pac)
    - [PXE](#pxe)
    - [RPC](#rpc)
    - [RTSP](#rtsp)
    - [SIP/VoIP](#sip)
    - [SMB](#smb)
    - [SMTP](#smtp)
    - [SNMP](#snmp)
    - [SSH](#ssh)
    - [SSL/TLS](#ssl)
    - [STP](#stp)
    - [Telnet](#telnet)
    - [TFTP](#tftp)
    - [TR-069](#tr69)
    - [UPNP](#upnp)
- [Attacks](#attacks)
    - [Attacking Windows Networks](#attackw)
    - [Bitsquatting](#bitsquat)
    - [Cross-Application/Cross Protocol Scripting](#xaps)
    - [D/DOS](#ddos)
    - [IDS/IPS Evasion](#evasion)
    - [IP Spoofing](#ipspoofing)
    - [IP Obfuscation](#ipobf)
    - [Man-in-the-Middle Tools](#mitm)
    - [Pivoting](#pivot)
- [Technologies](#technologies)
    - [802.1x & NAC](#8021x)
    - [Captive Portals](#captive-portal)
    - [Hadoop](#hadoop)
    - [NAT](#nat)
    - [Printers](#printers)
    - [Proxies](#proxy)
    - [PXE](#pxe)
    - [Redis](#redis)
    - [Preboot Execution Environment (PXE)](#pxe)
    - [Software Defined Networking(SDN)](#sdn)
    - [Switches](#switches)
    - [VLANs](#vlan)
    - [WebDAV](#webdav)
    - [Vendor Specific Stuff](#vendor)
- [Miscellaneous Stuff](#misc)
    - [Talks/Videos](#videos)
    - [Other](#other)
    - [MISC](#misc2)




* Need to Add 
    * BGP
    * Captive portals
    * DNSSEC
    * Fax
    * ICE
    * IP spoofing
    * IPSEC Stuff
    * memcache
    * NAT
    * NTLM things
    * OCSP
    * Packet sniffers
    * QUIC
    * r* protocols
    * STUN
    * WebDAV


------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="general"></a>General
* **101**
    * [Fundamentals That Time Forgot - Jup1t3r  - BSides SLC](https://www.youtube.com/watch?v=PQvUWImljOw)
    * [TCPDump Primer](http://danielmiessler.com/study/tcpdump/)
    * [IANA Complete list of assigned ports](http://www.vulnerabilityassessment.co.uk/port-numbers.txt)
    * [RFC 2827 -  Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing](https://tools.ietf.org/html/rfc2827)
    * [RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246)
    * [TCPDump Command Examples](http://www.thegeekstuff.com/2010/08/tcpdump-command-examples/)
* **Educational/History**
    * [Ethernet Briefings in April 1978 by Bob Metcalfe](https://www.youtube.com/watch?v=Fj7r3vYAjGY)
* **General/Articles/Writeups**
    * [Examples](http://www.hackwhackandsmack.com/?p=422)
    * [The Eavesdropper’s Dillemma](http://www.crypto.com/papers/internet-tap.pdf)
    * [Strange Attractors and TCP/IP Sequence Number Analysis  - Michal Zalewski](http://lcamtuf.coredump.cx/oldtcp/tcpseq.html)
    * [Signaling vulnerabilities in wiretapping systems](http://www.crypto.com/papers/wiretap.pdf)
* **Tools**
    * [pynessus](https://github.com/rmusser01/pynessus)
        * Python Parser for Nessus Output
    * [which-cloud](https://github.com/bcoe/which-cloud)
        * Given an ip address, return which cloud provider it belongs to (AWS, GCE, etc)  
    * [Zarp](https://github.com/hatRiot/zarp)
        * Zarp is a network attack tool centered around the exploitation of local networks. This does not include system exploitation, but rather abusing networking protocols and stacks to take over, infiltrate, and knock out. Sessions can be managed to quickly poison and sniff multiple systems at once, dumping sensitive information automatically or to the attacker directly. Various sniffers are included to automatically parse usernames and passwords from various protocols, as well as view HTTP traffic and more. DoS attacks are included to knock out various systems and applications. These tools open up the possibility for very complex attack scenarios on live networks quickly, cleanly, and quietly.
    * [Yersinia](http://www.yersinia.net/)
        * Yersinia is a network tool designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. 
        * [Attacks Supported](http://www.yersinia.net/attacks.htm)
    * [comcast](https://github.com/tylertreat/comcast)
        * Simulating shitty network connections so you can build better systems.
    * [TCPCopy](https://github.com/session-replay-tools/tcpcopy)
        * TCPCopy is a TCP stream replay tool to support real testing of Internet server applications.
    * [nessusporter](https://github.com/Tw1sm/nessporter)
        * Easily download entire folders of Nessus scans in the format(s) of your choosing. This script uses provided credentials to connect to a Nessus server and store a session token, which is then used for all subsquent requests.
    * [nessaws](https://github.com/TerbiumLabs/nessaws?files=1)
        * Automate Nessus scans against AWS EC2/RDS endpoints.







------------------------------------------------------------------------------------------------------------------------------------
## <a name="protocols"></a>Protocols


------------
#### <a name="amqp"></a> Advanced Message Query Protocol (AMQP)
* **101**
    * [Advanced Message Queuing Protocol - Wikipedia](https://en.wikipedia.org/wiki/Advanced_Message_Queuing_Protocol)
    * [AMQP.org Homepage](https://www.amqp.org)
    * [AMQP v1.0(2011) Protocol Document](http://www.amqp.org/sites/amqp.org/files/amqp.pdf)
* **Articles/Blogposts/Writeups**
    * [A Quick Guide To Understanding RabbitMQ & AMQP - Luke Mwila](https://medium.com/swlh/a-quick-guide-to-understanding-rabbitmq-amqp-ba25fdfe421d)
    * [Understanding AMQP, the protocol used by RabbitMQ - Peter Ledbrook]



------------
#### <a name="arp"></a> ARP
* **101**
    * [Address Resolution Protocol - Wikipedia](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
    * [RFC 826 - An Ethernet Address Resolution Protocol or Converting Network Protocol Addresses to 48.bit Ethernet Address for Transmission on Ethernet Hardware](https://tools.ietf.org/html/rfc826)
* **Articles/Blogposts/Writeups**
    * [Analyzing ARP to Discover & Exploit Stale Network Address Configurations - Justin Angel](https://www.blackhillsinfosec.com/analyzing-arp-to-discover-exploit-stale-network-address-configurations/)
* **Tools**
    * [kickthemout](https://github.com/k4m4/kickthemout)
        * A tool to kick devices out of your network and enjoy all the bandwidth for yourself. It allows you to select specific or all devices and ARP spoofs them off your local area network.
    * [Eavesarp](https://github.com/arch4ngel/eavesarp)
        * A reconnaissance tool that analyzes ARP requests to identify hosts that are likely communicating with one another, which is useful in those dreaded situations where LLMNR/NBNS aren't in use for name resolution.
        * [Blogpost](https://blackhillsinfosec.com/analyzing-arp-to-discover-exploit-stale-network-address-configurations/)

------------
#### <a name="bgp"></a> BGP
* **101**
* **Educational**
    * [isbgpsafeyet.com](https://isbgpsafeyet.com/)
* **Attacking**
    * **Articles/Blogposts/Writeups**
        * [BGP Hijacking overview. Routing incidents prevention and defense mechanisms - noction](https://www.noction.com/blog/bgp-hijacking)
        * [BGP Vulnerability Testing: Separating Fact from FUD - Sean Covery, Matthew Franz(BHUSA03)](https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v2.pdf)
* **Tools**




------------
#### <a name="dhcp"></a>Dynamic Host Configuration Protocol (DHCP)
* **101**
    * [Dynamic Host Configuration Protocol - Wikipedia](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)
    * [DHCPv6 - Wikipedia](https://en.wikipedia.org/wiki/DHCPv6)
    * [Understanding the Basic Operations of DHCP - netmanias(2013)](https://www.netmanias.com/en/post/techdocs/5998/dhcp-network-protocol/understanding-the-basic-operations-of-dhcp)
    * [DHCP Overview - Juniper](https://www.juniper.net/documentation/en_US/junos/topics/topic-map/dhcp-overview.html)
* **RFCs**
    * [RFC2131: Dynamic Host Configuration Protocol](https://tools.ietf.org/html/rfc2131)
    * [RFC4339: IPv6 Host Configuration of DNS Server Information Approaches](https://tools.ietf.org/html/rfc4339)
* **Educational**
* **Attacking**
* **Tools**
    * [DHCP Discovery - Chris Dent](https://www.indented.co.uk/dhcp-discovery/)
        * A PowerShell script to send a DHCP Discover request and listen for DHCP Offer responses, it can be used for finding DHCP servers (including rogue servers), or for testing DHCP servers and relays. The output from this script is an object containing a decode of the DHCP packet and a number of options.




------------
#### <a name="dns"></a>Domain Name System(DNS)
* **101**
    * [DNS 101: An introduction to Domain Name Servers - Alex Callejas](https://www.redhat.com/sysadmin/dns-domain-name-servers)
    * [A Cat Explains DNS - ](https://www.youtube.com/watch?v=4ZtFk2dtqv0)
        * Maybe NSFW(language)? Good content.
* **Educational**
    * [DNS RFC - Domain Name System RFC's (IETF)](http://www.bind9.net/rfc)
    * [RFC 1034 - DOMAIN NAMES - CONCEPTS AND FACILITIES](https://www.ietf.org/rfc/rfc1034.txt)
    * [RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://www.ietf.org/rfc/rfc1035.txt)
    * [DNS Reference Information - technet](https://technet.microsoft.com/en-us/library/dd197499(v=ws.10).aspx)
    * [DNS Records: an Introduction](https://www.linode.com/docs/networking/dns/dns-records-an-introduction)
    * [How DNS Works](https://howdns.works/)
        * A fun and colorful explanation of how DNS works.
    * [Google on DNS Security](https://developers.google.com/speed/public-dns/docs/security)
        * For Google Public DNS
    * [Anatomy of a Linux DNS Lookup – Part I - zwischenzugs(2018)](https://zwischenzugs.com/2018/06/08/anatomy-of-a-linux-dns-lookup-part-i/)
* **DIY**
    * [Setup your Out-of-Band DNS Server - Juxhin Dyrmishi Brigjaj](https://blog.digital-horror.com/setting-up-your-out-of-band-dns-resolver/)
* **Recon**
    * **Articles/Blogposts/Writeups**
        * [Enumerating DNSSEC NSEC and NSEC3 Records](https://www.altsci.com/concepts/page.php?s=dnssec&p=1)
        * [DNS database espionage](http://dnscurve.org/espionage2.html)
        * [How to resolve a million domains](https://idea.popcount.org/2013-11-28-how-to-resolve-a-million-domains/)
    * **Subdomain Enumeration**
        * [Sub-domain enumeration - Reference](https://gist.github.com/yamakira/2a36d3ae077558ac446e4a89143c69ab)
        * [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/)
        * [A penetration tester’s guide to sub-domain enumeration - appseco](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
        * **Tools**
            * [amass](https://github.com/caffix/amass)
                * The amass tool searches Internet data sources, performs brute force subdomain enumeration, searches web archives, and uses machine learning to generate additional subdomain name guesses. DNS name resolution is performed across many public servers so the authoritative server will see the traffic coming from different locations.)
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
            * [Anubis](https://github.com/jonluca/Anubis)
                * Anubis is a subdomain enumeration and information gathering tool. Anubis collates data from a variety of sources, including HackerTarget, DNSDumpster, x509 certs, VirusTotal, Google, Pkey, and NetCraft. Anubis also has a sister project, [AnubisDB](https://github.com/jonluca/Anubis-DB), which serves as a centralized repository of subdomains.
    * **Domain Resolution**
        * [Bass](https://github.com/Abss0x7tbh/bass)
            * bass aim's at maximizing your resolver count wherever it can by combining different valid dns servers from the targets DNS Providers & adding them to your initial set of public resolvers (here located in /resolvers/public.txt), thereby allowing you to use the maximum number of resolvers obtainable for your target. This is more of a best-case-scenario per target. More the resolvers, lesser the traffic to each resolver when using tools like massdns that perform concurrent lookups using internal hash table. So easier it is to scale your target list
        * [MassDNS](https://github.com/blechschmidt/massdns)
            * MassDNS is a simple high-performance DNS stub resolver targetting those who seek to resolve a massive amount of domain names in the order of millions or even billions. Without special configuration, MassDNS is capable of resolving over 350,000 names per second using publicly available resolvers.
        * [TXTDNS](http://www.txdns.net/)
           * TXDNS is a Win32 aggressive multithreaded DNS digger. Capable of placing, on the wire, thousands of DNS queries per minute. TXDNS main goal is to expose a domain namespace trough a number of techniques: Typos: Mised, doouble and transposde keystrokes; TLD/ccSLD rotation; Dictionary attack; Full Brute-force attack using alpha, numeric or alphanumeric charsets; Reverse grinding.
    * **Services**
        * [DNS Dumpster](https://www.DNSdumpster.com)
            * free domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process
        * [DNS-Trails](https://securitytrails.com/dns-trails)
            * The World's Largest Repository of historical DNS data
* **Attacking**
    * **Articles/Blogposts/Writeups**
        * [An Illustrated Guide to the Kaminsky DNS Vulnerability - Steve Friedl](http://unixwiz.net/techtips/iguide-kaminsky-dns-vuln.html)
            * This paper covers how DNS works: first at a high level, then by picking apart an individual packet exchange field by field. Next, we'll use this knowledge to see how weaknesses in common implementations can lead to cache poisoning.
        * [Respect My Authority – Hijacking Broken Nameservers to Compromise Your Target - thehackerblog](https://thehackerblog.com/respect-my-authority-hijacking-broken-nameservers-to-compromise-your-target/)
    * **Presentations/Talks/Videos**
        * [DNS Dark Matter Discovery Theres Evil In Those Queries - Jim Nitterauer](https://www.youtube.com/watch?v=-A2Wqagz73Y)
        * [DNS hijacking using cloud providers - Frans Ros-n](https://www.youtube.com/watch?v=HhJv8CU-RIk)
        * [DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
            * Great talk on attacking DNS
        * [Secrets of DNS Ron Bowes - Derbycon4](https://www.youtube.com/watch?v=MgO-gPiVTSc)
    * **Cache Poisoning**
        * **101**
            * [DNS Spoofing - Wikipedia](https://en.wikipedia.org/wiki/DNS_spoofing)
            * [What is DNS cache poisoning? | DNS spoofing - Cloudflare](https://www.cloudflare.com/learning/dns/dns-cache-poisoning/)
        * **Articles/Blogposts/Writeups**
            * [DNSTrust – 28 queries later: an example attack on .fr](https://web.archive.org/web/20090614054817/http://shinobi.dempsky.org/~matthew/dnstrust/example.html)
    * **Cache Snooping***
        * **101**
        * **Articles/Blogposts/Writeups**
            * [DNS Cache Snooping or Snooping the Cache for Fun and Profit - Luis Grangeia](http://cs.unc.edu/~fabian/course_papers/cache_snooping.pdf)
            * [DNS and The Bit 0x20 - Hypothetical.me](https://hypothetical.me/short/dns-0x20/)
                * While writing a post on Certificate Authority Authorization (CAA) DNS record, I’ve learned about this other DNS thing — a neat hack that makes cache poisoning attacks harder.
    * **DNS Rebinding**
        * **101**
            * [DNS Rebinding - Wikipedia](https://en.wikipedia.org/wiki/DNS_rebinding)
            * [DNS Rebinding Attacks Explained - Daniel Miessler](https://danielmiessler.com/blog/dns-rebinding-explained/)
            * [Protecting Browsers from DNS Rebinding Attacks - Stanford Web Security Research](https://crypto.stanford.edu/dns/)
        * **Articles/Blogposts/Writeups**
            * [The power of DNS rebinding: stealing WiFi passwords with a website - Michele Spagnuolo](https://miki.it/blog/2015/4/20/the-power-of-dns-rebinding-stealing-wifi-passwords-with-a-website/)
            * [Rails Webconsole DNS Rebinding - benmmurphy.github.io](https://web.archive.org/web/20161211232606/http://benmmurphy.github.io/blog/2016/07/11/rails-webconsole-dns-rebinding/)
            * [Attacking Private Networks from the Internet with DNS Rebinding - Brannon Dorsey](https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325)
            * [Practical Attacks with DNS Rebinding - Craig Young](https://www.tripwire.com/state-of-security/vert/practical-attacks-dns-rebinding/)
            * [I can see your local web servers - James Fisher](http://http.jameshfisher.com/2019/05/26/i-can-see-your-local-web-servers/)
            * [How to steal any developer's local database - Bouke van der Bijl](https://bou.ke/blog/hacking-developers/)
                * If you’re reading this and you’re a software developer, you’re probably running some services locally. Redis, Memcached, and Elasticsearch are software products that many rely on. What you might not know, is that these locally running services are accessible by any website you visit, making it possible for bad guys to steal the data you have locally!
        * **Tools**
            * [ReDTunnel: Explore Internal Networks via DNS Rebinding Tunnel - Nimrod Levy & Tomer Zait(BHUSA19)](https://www.youtube.com/watch?v=sqUxeiqq0xE)
                * [Tool](https://github.com/ReDTunnel/redtunnel)
            * [Singularity](https://github.com/nccgroup/singularity)
                * Singularity of Origin is a tool to perform DNS rebinding attacks. It includes the necessary components to rebind the IP address of the attack server DNS name to the target machine's IP address and to serve attack payloads to exploit vulnerable software on the target machine.
                * [Blogpost](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/august/singularity-of-origin-a-dns-rebinding-attack-framework/)
            * [DNS Rebind Toolkit](https://github.com/brannondorsey/dns-rebind-toolkit)
                * DNS Rebind Toolkit is a frontend JavaScript framework for developing DNS Rebinding exploits against vulnerable hosts and services on a local area network (LAN).
            * [A DNS rebinding implementation](https://github.com/lorenzog/dns-rebinding)
                * This tool will exfiltrate data cross-domains using a DNS rebinding attack, bypassing the browser's same-origin policy.
            * [whonow](https://github.com/brannondorsey/whonow)
                * A "malicious" DNS server for executing DNS Rebinding attacks on the fly
    * **Tools**
        * [DNSRecon](https://github.com/darkoperator/dnsrecon)
            * [Quick Reference Guide](http://pentestlab.wordpress.com/2012/11/13/dns-reconnaissance-dnsrecon/)
        * [dns-discovery](https://github.com/mafintosh/dns-discovery)
            * Discovery peers in a distributed system using regular dns and multicast dns.
        * [DNSEnum](https://github.com/fwaeytens/dnsenum)
            * Multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.
        * [Bluto](https://github.com/darryllane/Bluto)
            * DNS Recon | Brute Forcer | DNS Zone Transfer | DNS Wild Card Checks | DNS Wild Card Brute Forcer | Email Enumeration | Staff Enumeration | Compromised Account Enumeration | MetaData Harvesting
        * [nsec3map](https://github.com/anonion0/nsec3map)
            * a tool to enumerate the resource records of a DNS zone using its DNSSEC NSEC or NSEC3 chain
* **Tools**
    * **Logging**
        * [passivedns](https://github.com/gamelinux/passivedns)
            * A tool to collect DNS records passively
    * **MitM**
    * [Judas DNS](https://github.com/mandatoryprogrammer/JudasDNS)
        * A DNS proxy server built to be deployed in place of a taken over nameserver to perform targeted exploitation. Judas works by proxying all DNS queries to the legitimate nameservers for a domain. The magic comes with Judas's rule configurations which allow you to change DNS responses depending on source IP or DNS query type. This allows an attacker to configure a malicious nameserver to do things like selectively re-route inbound email coming from specified source IP ranges (via modified MX records), set extremely long TTLs to keep poisoned records cached, and more.



#### Multicast DNS <a name="mdns"></a>
* **101**
    * [Multicast DNS - Wikipedia](https://en.wikipedia.org/wiki/Multicast_DNS)
* **Educational**
* **Attacking**
    * **Articles/Blogposts/Writeups**
       * [Name (mDNS) Poisoning Attacks Inside The LAN(2008)](https://www.gnucitizen.org/blog/name-mdns-poisoning-attacks-inside-the-lan/)


---------------------
### <a name="hnap"></a>HNAP
* **101**
    * [gRPC and Protocol Buffers: an Alternative to REST APIs and JSON - Andrew Connell](http://www.andrewconnell.com/blog/grpc-and-protocol-buffers-an-alternative-to-rest-apis-and-json)
    * [Awesome gRPC](https://github.com/grpc-ecosystem/awesome-grpc)
        * A curated list of useful resources for gRPC
* **Articles/Blogposts/Writeups**
    * [Building High Performance APIs In Go Using gRPC And Protocol Buffers - Shiju Varghese](https://medium.com/@shijuvar/building-high-performance-apis-in-go-using-grpc-and-protocol-buffers-2eda5b80771b)
* **Presentations/Talks/Videos**
* **Tools**









---------------------
### <a name="hnap"></a>HNAP
* **101**

* **Articles/Blogposts/Writeups
* **Presentations/Talks/Videos**
* **Tools**

* [Home Network Administration Protocol - Wikipedia](https://en.wikipedia.org/wiki/Home_Network_Administration_Protocol)
    * Home Network Administration Protocol (HNAP) is a proprietary network protocol invented by Pure Networks, Inc. and acquired by Cisco Systems which allows identification, configuration, and management of network devices. HNAP is based on SOAP.
* [HNAP - Router Security](https://www.routersecurity.org/hnap.php)
* [More on HNAP - What is it, How to Use it, How to Find it](https://isc.sans.edu/forums/diary/More+on+HNAP+What+is+it+How+to+Use+it+How+to+Find+it/17648/)
* [Home Network Administration Protocol (HNAP) Whitepaper](https://www.cisco.com/web/partners/downloads/guest/hnap_protocol_whitepaper.pdf)
* [Hacking D-Link Routers With HNAP](https://regmedia.co.uk/2016/11/07/dlink_hnap_captcha.pdf)






------------
### <a name="icmp"></a>ICMP
* **101**
    * [ICMP RFC - Network Sorcery](http://www.networksorcery.com/enp/protocol/icmp.htm)
    * [RFC 792 - Internet Control Message Protocol](https://tools.ietf.org/html/rfc792)
    * [Internet Control Message Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
* **Articles/Blogposts/Writeups
* **Presentations/Talks/Videos**
* **Tools**
    * [BlackNurse attack PoC](https://github.com/jedisct1/blacknurse)
        * A simple PoC for the Blacknurse attack. "Blacknurse is a low bandwidth ICMP attack that is capable of doing denial of service to well known firewalls".





------------
### <a name="ipsec"></a>IPSEC
* **101**
    * [IPSec - Wikipedia](https://en.wikipedia.org/wiki/IPsec)
    * [IPSec RFCs - docs.oracle](https://docs.oracle.com/cd/E19253-01/816-4554/ipsec-ov-14/index.html)
* **Attacking*** 
    * **Articles/Blogposts/Writeups**
    * **Presentations/Talks/Videos**
* **Papers**
* **Tools**
* IKEForce
    * IKEForce is a command line IPSEC VPN brute forcing tool for Linux that allows group name/ID enumeration and XAUTH brute forcing capabilities.
    * [Cracking IKE Mission:Improbable (Part 1)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part-1)/)
    * [Cracking IKE Mission:Improbable (Part 2) ](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part-2)/)
    * [Cracking IKE Mission:Improbable (Part3) ](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cracking-IKE-Mission-Improbable-(Part3)/)



------------
### <a name="ipmi"></a>BMCs/IPMI/iDRAC/Similar
* **101**
    * [Intelligent Platform Management Interface Documentation - Intel](https://www.intel.com/content/www/us/en/servers/ipmi/ipmi-home.html)
    * [IPMI Basics](https://www.thomas-krenn.com/en/wiki/IPMI_Basics)
    * [Intelligent Platform Management Interface - Wikipedia](https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface)
    * [Redfish](https://www.dmtf.org/standards/redfish)
        * DMTF’s Redfish® is a standard designed to deliver simple and secure management for converged, hybrid IT and the Software Defined Data Center (SDDC). Both human readable and machine capable, Redfish leverages common Internet and web services standards to expose information directly to the modern tool chain.
* **Educational**
    * [IPMI Basics - Thomas Krenn](https://www.thomas-krenn.com/en/wiki/IPMI_Basics)
* **Attacking*** 
    * **Articles/Blogposts/Writeups**
        * [A Penetration Tester's Guide to IPMI and BMCs - HD Moore](https://blog.rapid7.com/2013/07/02/a-penetration-testers-guide-to-ipmi/)
        * [one packet auditing - trouble.org](http://trouble.org/?p=712)
        * [IPMI - fish2.com](http://fish2.com/ipmi/)
        * [CVE-2019-6260: Gaining control of BMC from the host processor - Stewart Smith](https://www.flamingspork.com/blog/2019/01/23/cve-2019-6260-gaining-control-of-bmc-from-the-host-processor/)
        * [A Penetration Tester's Guide to IPMI and BMCs](https://blog.rapid7.com/2013/07/02/a-penetration-testers-guide-to-ipmi/)
        * [Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)
        * [IPMI – A Gentle Introduction with OpenIPMI](http://openipmi.sourceforge.net/IPMI.pdf)
    * **Presentations/Talks/Videos**
* **Papers**
    * [Sold Down the River - Dan Farmer](http://fish2.com/ipmi/river.pdf)
    * [IPMI: FREIGHT TRAIN TO HELL OR LINDA WU & THE NIGHT OF THE LEECHES - Dan Farmer](http://fish2.com/ipmi/itrain.pdf)
    * [IPMI++ Security Best Practices  - Dan Farmer](http://fish2.com/ipmi/bp.pdf)
* **Tools**
    * [OpenIPMI](http://openipmi.sourceforge.net/)



-------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="ipv4">IPv4 Related</a>
* **101**
    * [A Brief History of the IPv4 Address Space - Enno Rey](https://insinuator.net/2019/08/a-brief-history-of-the-ipv4-address-space/)
* **General**
* **Articles/Blogposts/Writeups**
    * [IPv4 Address](https://www.scaler.com/topics/computer-network/ipv4-address/)
* **Talks/Videos**





------------
### <a name="ipv6">IPv6 Related</a>
* **101**
    * [IPv6—101: Introduction - F5](http://securite.net.au/wp-content/uploads/2014/05/F5s-IPV6-Introduction.pdf)
    * [Introduction to IPv6 Fundamentals - Cisco](https://www.youtube.com/watch?v=PdGLmeq-6Bg)
    * [IPv6 - Wikipedia](https://en.wikipedia.org/wiki/IPv6)
* **RFCs**
    * [RFC 2460 - Internet Protocol, Version 6 (IPv6)](https://tools.ietf.org/html/rfc2460)
    * [RFC 3041: Privacy Extensions for Stateless Address Autoconfiguration in IPv6](https://tools.ietf.org/html/rfc3041)
    * [RFC 4861: Neighbor Discovery for IP version 6 (IPv6)](https://tools.ietf.org/html/rfc4861)
    * [RFC 7710: Captive-Portal Identification Using DHCP or Router Advertisements (RAs)](https://tools.ietf.org/html/rfc7710)
* **Educational**
* **Attacking**
    * **Articles/Blogposts/Writeups**
        * [Exploiting Tomorrow's Internet Today: Penetration testing with IPv6](http://uninformed.org/?v=all&a=46&t=sumry)
            * This paper illustrates how IPv6-enabled systems with link-local and auto-configured addresses can be compromised using existing security tools. While most of the techniques described can apply to "real" IPv6 networks, the focus of this paper is to target IPv6-enabled systems on the local network. 
        * [mitm6 – compromising IPv4 networks via IPv6 - FOX-IT](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
        * [Penetration Testing Tools that (do not) Support](https://www.ernw.de/download/newsletter/ERNW_Newsletter_45_PenTesting_Tools_that_Support_IPv6_v.1.1_en.pdf)
            * Find out which of our favorite penetration testing tools can be used natively using IPv6 as an underlying layer-3 protocol. Find alternative solutions for the rest.
        * [IPv6 Local Neighbor Discovery Using Router Advertisement](https://www.rapid7.com/db/modules/auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement)
            * Send a spoofed router advertisement with high priority to force hosts to start the IPv6 address auto-config. Monitor for IPv6 host advertisements, and try to guess the link-local address by concatinating the prefix, and the host portion of the IPv6 address. Use NDP host solicitation to determine if the IP address is valid'
        * [IPv6 - Playing with IPv6 for fun and profit](https://github.com/zbetcheckin/IPv6)
    * **Presentations/Talks/Videos**
        * IPv6: Basic Attacks and Defences - Christopher Werny[TROOPERS15]
            * [Part 1](https://www.youtube.com/watch?v=Y8kjQEGHbAU)
            * [Part 2](https://www.youtube.com/watch?v=V-GYPp-j-lE)
        * [MITM All The IPv6 Things - DEFCON 21 - Scott Behrens and Brent Bandelgar](https://www.youtube.com/watch?v=9fJGVVuG8Pc)
        * [[TROOPERS15] Merike Kaeo - Deploying IPv6 Securely - Avoiding Mistakes Others Have Made](https://www.youtube.com/watch?v=rQg4y78xHf8)
* **Tools**
    * [ipv666](https://github.com/lavalamp-/ipv666)
        * ipv666 is a set of tools that enables the discovery of IPv6 addresses both in the global IPv6 address space and in more narrow IPv6 network ranges. These tools are designed to work out of the box with minimal knowledge of their workings.
    * [IPv6 Toolkit](https://github.com/fgont/ipv6toolkit)
        * SI6 Networks' IPv6 Toolkit
    * [THC-IPv6](https://www.thc.org/thc-ipv6/)
        *  A complete tool set to attack the inherent protocol weaknesses of IPV6 and ICMP6, and includes an easy to use packet factory library.
    * [Sudden Six](https://github.com/Neohapsis/suddensix)
        * An automation script for conducting the SLAAC attack outlined in [Alec Water's blog post](https://wirewatcher.wordpress.com/2011/04/04/the-slaac-attack-using-ipv6-as-a-weapon-against-ipv4/). This attack can be used to build an IPv6 overlay network on an IPv4 infrastructure to perform man-in-the-middle attacks.
    * [Chiron](https://github.com/aatlasis/Chiron)
        * Chiron is an IPv6 Security Assessment Framework, written in Python and employing Scapy. It is comprised of the following modules: • IPv6 Scanner • IPv6 Local Link • IPv4-to-IPv6 Proxy • IPv6 Attack Module • IPv6 Proxy. All the above modules are supported by a common library that allows the creation of completely arbitrary IPv6 header chains, fragmented or not.
    * [fi6s](https://github.com/sfan5/fi6s)
        * IPv6 network scanner designed to be fast
    * [mitm6](https://github.com/fox-it/mitm6)
        * mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. It does this by replying to DHCPv6 messages, providing victims with a link-local IPv6 address and setting the attackers host as default DNS server. As DNS server, mitm6 will selectively reply to DNS queries of the attackers choosing and redirect the victims traffic to the attacker machine instead of the legitimate server.









------------
#### <a name="kerberos"></a>Kerberos
* **101**
    * [Kerberos - Wikipedia](https://en.wikipedia.org/wiki/Kerberos_(protocol))
    * [Kerberos Explained - msdn.ms](https://msdn.microsoft.com/en-us/library/bb742516.aspx)
* **General**
    * [Kerberos: The Network Authentication Protocol - MIT](https://web.mit.edu/kerberos/)
    * [Explain like I’m 5: Kerberos](http://www.roguelynn.com/words/explain-like-im-5-kerberos/)

------------
#### <a name="ldap"></a>LDAP
* **101**
    * [Lightweight Directory Access Protocol - Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
    * [Basic LDAP Concepts - ldap.com](https://www.ldap.com/basic-ldap-concepts)
    * [Lightweight Directory Access Protocol (LDAP): Technical Specification Road Map](https://tools.ietf.org/html/rfc4510)
    * [Lightweight Directory Access Protocol (LDAP): The Protocol](https://tools.ietf.org/html/rfc4511)
    * [Understanding the LDAP](https://n0where.net/understanding-the-ldap/)
* **Attacking**
    * [Public Facing LDAP Enumeration](https://www.lanmaster53.com/2013/05/24/public-facing-ldap-enumeration/)
    * [Dangers of LDAP NULL Base and Bind](https://securitysynapse.blogspot.com/2013/09/dangers-of-ldap-null-base-and-bind.html)
    * [LDAP Injection Cheat Sheet, Attack Examples & Protection - Checkmarx](https://www.checkmarx.com/knowledge/knowledgebase/LDAP)
* **Tools**
    * [JXplorer](http://jxplorer.org/)
        * JXplorer is a cross platform LDAP browser and editor. It is a standards compliant general purpose LDAP client that can be used to search, read and edit any standard LDAP directory, or any directory service with an LDAP or DSML interface. It is highly flexible and can be extended and customised in a number of ways. JXplorer is written in java, and the source code and Ant build system are available via svn or as a packaged build for users who want to experiment or further develop the program. 
    * [LDAPMfINER](http://ldapminer.sourceforge.net/)
        * This is a tool I wrote to collect information from different LDAP Server implementation. This was written in C with the Netscape C 
    * [Softera LDAP Browser](http://www.ldapbrowser.com/info_softerra-ldap-browser.htm)
        * LDAP Browser that supports most LDAP implementations. Non-free software, 30-day free trial
    * [ad-ldap-enum](https://github.com/CroweCybersecurity/ad-ldap-enum)
        * An LDAP based Active Directory user and group enumeration tool



------------
#### <a name="modbus"></a>Modbus
* See 'Modbus' under 'SCADA/Heavy Machinery'




--------------------
#### <a name="mqtt"></a>MQTT (Message Query Transport Protocol)
* **101**
    * [MQTT FAQ](http://mqtt.org/faq)
    * [MQTT Official Documentation](http://mqtt.org/documentation)
    * [MQTT](http://mqtt.org/)
        * MQTT is a machine-to-machine (M2M)/"Internet of Things" connectivity protocol. It was designed as an extremely lightweight publish/subscribe messaging transport. 
    * [MQTT - Wikipedia](https://en.wikipedia.org/wiki/MQTT)
* **Articles/Blogposts/Writeups**
    * [Beginners Guide To The MQTT Protocol - steves-internet-guide.com](http://www.steves-internet-guide.com/mqtt/)
    * [Understanding the MQTT Protocol Packet Structure - steves-internet-guide.com](http://www.steves-internet-guide.com/mqtt-protocol-messages-overview/)
    * [Introduction to MQTT Security Mechanisms - steves-internet-guide.com](http://www.steves-internet-guide.com/mqtt-security-mechanisms/)
    * [Lightweight messaging with MQTT 3.1.1 and Mosquitto - Gaston C. Hillar](https://hub.packtpub.com/lightweight-messaging-mqtt-311-and-mosquitto/)
    * [MQTT – The Nerve System of IoT - Abhinaya Balaji](http://blog.catchpoint.com/2017/05/30/protocol-for-internet-of-things/)
    * [Dissecting MQTT using Wireshark - Abhinaya Balaji](http://blog.catchpoint.com/2017/07/06/dissecting-mqtt-using-wireshark/)
    * [MQTT Security Fundamentals - HiveMQ](https://www.hivemq.com/mqtt-security-fundamentals/)
    * [punching messages in the q - leon](https://sensepost.com/blog/2018/punching-messages-in-the-q/)
    * [MQTT Security: What You Did Not Consider - Wilfred Nilsen](https://dzone.com/articles/mqtt-security)
    * [Exploiting MQTT Using Lua - Wilfred Nilsen](https://dzone.com/articles/exploiting-mqtt-using-lua)
    * [Yankee Swapped: MQTT Primer, Exposure, Exploitation, and Exploration - Rapid7](https://blog.rapid7.com/2018/01/02/yankee-swapped-mqtt-primer-exposure-exploitation-and-exploration/)
* **Papers**
    * [MQTT Security: A Novel Fuzzing Approach](https://www.hindawi.com/journals/wcmc/2018/8261746/)
        * "we propose the creation of a framework that allows for performing a novel, template-based fuzzing technique on the MQTT protocol. The first experimental results showed that performance of the fuzzing technique presented here makes it a good candidate for use in network architectures with low processing power sensors, such as Smart Cities. In addition, the use of this fuzzer in widely used applications that implement MQTT has led to the discovery of several new security flaws not hitherto reported, demonstrating its usefulness as a tool for finding security vulnerabilities."
    * [Attack scenarios and security analysis of MQTT communication protocol in IoT system - Syaiful Andy, Budi Rahardjo, Bagus Hanindhito](https://ieeexplore.ieee.org/document/8239179)
        * Various communication protocols are currently used in the Internet of Things (IoT) devices. One of the protocols that are already standardized by ISO is MQTT protocol (ISO / IEC 20922: 2016). Many IoT developers use this protocol because of its minimal bandwidth requirement and low memory consumption. Sometimes, IoT device sends confidential data that should only be accessed by authorized people or devices. Unfortunately, the MQTT protocol only provides authentication for the security mechanism which, by default, does not encrypt the data in transit thus data privacy, authentication, and data integrity become problems in MQTT implementation. This paper discusses several reasons on why there are many IoT system that does not implement adequate security mechanism. Next, it also demonstrates and analyzes how we can attack this protocol easily using several attack scenarios. Finally, after the vulnerabilities of this protocol have been examined, we can improve our security awareness especially in MQTT protocol and then implement security mechanism in our MQTT system to prevent such attack.
* **Presentations/Talks/Videos**
    * [A Guide to MQTT by Hacking a Doorbell to send Push Notifications - Robin Reiter](https://www.youtube.com/watch?v=J_BAXVSVPVI&feature=youtu.be)
        * In this video I'll use a cheap wireless doorbell and hack it so it sends me a push notification when someone is at the door. I used this project to explain the basics of the IoT by setting up an MQTT broker on a raspberry pi.
    * [Light Weight Protocol: Critical Implications - Lucas Lundgren, Neal Hindocha - Defcon24](https://www.youtube.com/watch?v=o7qDVZr0t2c)
* **Tools**
    * [punch-q](https://github.com/sensepost/punch-q)
        * punch-q is a small Python utility used to play with IBM MQ instances. Using punch-q, it is possible to perform security related tasks such as manipulating messages on an IBM MQ queue granting one the ability to tamper with business processes at an integration layer.
    * [Joffrey](https://github.com/zombiesam/joffrey)
        * Stupid MQTT Brute Forcer
    * [MQTT NSE Library](https://nmap.org/nsedoc/lib/mqtt.html)
        * An implementation of MQTT 3.1.1 https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html This library does not currently implement the entire MQTT protocol, only those control packets which are necessary for existing scripts are included. Extending to accommodate additional control packets should not be difficult.
* **ActiveMQ**
    * **101**
        * [Apache ActiveMQ - Wikipedia](https://en.wikipedia.org/wiki/Apache_ActiveMQ)
        * [ActiveMQ](http://activemq.apache.org/)
    * **Articles/Blogposts/Writeups**
        * [Getting Started](http://activemq.apache.org/getting-started.html)
        * [What is ActiveMQ used for? - StackOverflow](https://stackoverflow.com/questions/12805377/what-is-activemq-used-for)
        * [A Pentesters Guide to Hacking  ActiveMQ-Based JMS Applications - Gursev Singh Kalra](https://www.mcafee.com/enterprise/en-us/assets/white-papers/wp-pentesters-guide-hacking-activemq-jms-applications.pdf)
    * **Talks/Presentations/Videos**
        * [Light Weight Protocol: Critical Implications - Lucas Lundgren, Neal Hindocha - Defcon24](https://www.youtube.com/watch?v=o7qDVZr0t2c&app=desktop)
    * **Tools**
        * [a](https://github.com/fmtn/a)
            * ActiveMQ CLI testing and mescaptsage management
* **RabbitMQ**
    * **101**
        * [RabbitMQ - Wikipedia](https://en.wikipedia.org/wiki/RabbitMQ)
        * [Access Control (Authentication, Authorisation) in RabbitMQ](https://www.rabbitmq.com/access-control.html)
        * [Credentials and Passwords](https://www.rabbitmq.com/passwords.html)
        * [Management Plugin](https://www.rabbitmq.com/management.html)
        * [File and Directory Locations](https://www.rabbitmq.com/relocate.html)
        * [Credentials and Passwords](https://www.rabbitmq.com/passwords.html)
    * **Tools**
        * [Enteletaor](https://github.com/cr0hn/enteletaor)
            * Message Queue & Broker Injection tool that implements attacks to Redis, RabbitMQ and ZeroMQ.









------------
#### <a name="netbios"></a>Netbios/Link-Local Multicast Name Resolution (LLMNR)
* **101**
    * [NetBIOS - Wikipedia](https://en.wikipedia.org/wiki/NetBIOS)
    * [NetBIOS - rhyshaden.com](http://www.rhyshaden.com/netbios.htm)
    * [NetBIOS Name Resolution - technet.ms](https://technet.microsoft.com/library/cc958811.aspx)
    * [Link-Local Multicast Name Resolution - Wikipedia](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution)
    * [Link-Local Multicast Name Resolution - The cable guy - technet](https://technet.microsoft.com/library/bb878128)
* **Articles/Blogposts/Writeups**
    * [Local Network Attacks: LLMNR and NBT-NS Poisoning](https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning)
    * [Local Network Attacks: LLMNR and NBT-NS Poisoning](https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning)
    * [Bypassing LLMNR/NBT-NS honeypot - blog.redteam.pl](https://blog.redteam.pl/2019/10/bypassing-llmnr-nbns-honeypot.html)
* **Tools**
    * [NbtScan](http://www.unixwiz.net/tools/nbtscan.html)
        * This is a command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network, and this is a first step in finding of open shares. It is based on the functionality of the standard Windows tool nbtstat, but it operates on a range of addresses instead of just one. I wrote this tool because the existing tools either didn't do what I wanted or ran only on the Windows platforms: mine runs on just about everything.
    * [Responder](https://github.com/lgandx/Responder)
        * Responder an LLMNR, NBT-NS and MDNS poisoner. It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answer to File Server Service request, which is for SMB. The concept behind this is to target our answers, and be stealthier on the network. This also helps to ensure that we don't break legitimate NBT-NS behavior. You can set the -r option via command line if you want to answer to the Workstation Service request name suffix.







------------
### <a name="nfs"></a>NFS
* **101**
    * [Network File System](https://en.wikipedia.org/wiki/Network_File_System)
    * [NFS - ArchWiki](https://wiki.archlinux.org/index.php/NFS)
    * [Linux NFS Documentation](http://nfs.sourceforge.net/)
        * This document provides an introduction to NFS as implemented in the Linux kernel. It links to developers' sites, mailing list archives, and relevant RFCs, and provides guidance for quickly configuring and getting started with NFS on Linux. A Frequently Asked Questions section is also included. This document assumes the reader is already familiar with generic NFS terminology.
    * [NFS: Network File System Protocol Specification - rfc1094](https://tools.ietf.org/html/rfc1094)
* **General/Articles**
    * NFS Abuse for Fun and Profit - m0noc.com
        * [Part 1](http://blog.m0noc.com/2016/05/nfs-abuse-for-fun-and-profit-part-1_12.html)
        * [Part 2](http://blog.m0noc.com/2016/05/nfs-abuse-for-fun-and-profit-part-2.html)
        * [Part 3](http://blog.m0noc.com/2016/05/nfs-abuse-for-fun-and-profit-part-3.html?m=1)
    * [Using nfsshell to compromise older environments](https://www.pentestpartners.com/security-blog/using-nfsshell-to-compromise-older-environments/)
    * [Abusing Hardlinks Via NFS](http://pentestmonkey.net/blog/nfs-hardlink)
    * [Exploiting Network File System, (NFS), shares - vulnerabilityassessment.co.uk](http://www.vulnerabilityassessment.co.uk/nfs.htm)
    * [NFS - pentestacademy.wordpress](https://pentestacademy.wordpress.com/2017/09/20/nfs/)
* **Tools**
    * [NfSpy](https://github.com/bonsaiviking/NfSpy)
        * NfSpy is a Python library for automating the falsification of NFS credentials when mounting an NFS share.






------------
## <a name="ntlm"></a> NTLM
* **101**
    * [Microsoft NTLM - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378749%28v=vs.85%29.aspx)
    * [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge.net](http://davenport.sourceforge.net/ntlm.html)
* **Educational**
    * **Articles/Blogposts/Writeups**
    * **Talks/Presentations/Videos**
* **Attacking**
    * **Articles/Blogposts/Writeups**
        * [LLMNR/NBT-NS Poisoning Using Responder](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)
        * [Drop The MIC 2 (CVE 2019-1166) & Exploiting LMv2 Clients (CVE-2019-1338) - Yaron Zinar, Marina Simakov](https://www.preempt.com/blog/drop-the-mic-2-active-directory-open-to-more-ntlm-attacks/)
        * [Your Session Key is My Session Key: How to Retrieve the Session Key for Any Authentication - Marina Simakov](https://www.preempt.com/blog/your-session-key-is-my-session-key-how-to-retrieve-the-session-key-for-any-authentication/)
        * [How to Easily Bypass EPA to Compromise any Web Server that Supports Windows Integrated Authentication - Yaron Zinar](https://www.preempt.com/blog/how-to-easily-bypass-epa-to-compromise-any-web-server-that-supports-windows-integrated-authentication/)
        * [Security Advisory: Critical Vulnerabilities in NTLM Allow Remote Code Execution and Cloud Resources Compromise - Yaron Zinar](https://blog.preempt.com/security-advisory-critical-vulnerabilities-in-ntlm)
            * On June 2019 Patch Tuesday, Microsoft released patches for CVE-2019-1040 and CVE-2019-1019, two vulnerabilities discovered by Preempt researchers. The critical vulnerabilities consist of three logical flaws in NTLM (Microsoft’s proprietary authentication protocol). Preempt researchers were able to bypass all major NTLM protection mechanisms. These vulnerabilities allow attackers to remotely execute malicious code on any Windows machine or authenticate to any HTTP server that supports Windows Integrated Authentication (WIA) such as Exchange or ADFS. All Windows versions are vulnerable.
        * [Downgrade SPNEGO Authentication - Carsten Sandker(2018)](https://www.contextis.com/en/blog/downgrade-spnego-authentication)   
            * Microsoft’s SPNEGO protocol is a less well known sub protocol used by better known protocols to negotiate authentication. This blog post covers weaknesses Context have discovered in SPNEGO and leverages this to highlight an inconsistency in the SMBv2 protocol, both of which lead to user credentials being sent over the wire in a way which makes them vulnerable to offline cracking. 
            * [spnegoDown](https://github.com/csandker/spnegoDown)
            * PoC Tool for SPNEGO Downgrade
    * **Talks/Presentations/Videos**
        * [How We Bypassed All NTLM Relay Mitigations - And How To Ensure You're Protected - ](https://www.youtube.com/watch?v=b9yMR6hSPzk)
            * In an encore presentation of one of Black Hat 2019’s and DEFCON27’s most popular talks, members of our research team will: Alert you to several new ways to abuse NTLM, including a critical zero-day vulnerability we have discovered which enables attackers to perform NTLM Relay and take over any machine in the domain, even with the strictest security configuration, while bypassing all of today’s offered mitigations. Tell you why the risks of this protocol are not limited to the boundaries of the on-premises environment, and show another vulnerability which allows to bypass various AD-FS restrictions in order to take over cloud resources as well.
* **'Leaking' Hashes**
    * **Articles/Blogposts/Writeups**
        * [A Pentesters Guide - Part 4 (Grabbing Hashes and Forging External Footholds) - Ben Bidmead](https://delta.navisec.io/a-pentesters-guide-part-4-grabbing-hashes-and-forging-external-footholds/)
        * [From XML External Entity to NTLM Domain Hashes - Gianluca Baldi](https://techblog.mediaservice.net/2018/02/from-xml-external-entity-to-ntlm-domain-hashes/)
        * [Stealing NTLMv2 hash by abusing SQL injection in File download functionality - mannulinux.org](http://www.mannulinux.org/2020/01/stealing-ntlmv2-hash-by-abusing-sqlInjection.html)
            * In this blog post, I am going to explain about a scenario in which an attacker can take advantage of SQL Injection vulnerability and can force Web server to leak NTLMv2 hash.
        * [PDFiD: GoToE and GoToR Detection (“NTLM Credential Theft”) - Didier Stevens](https://blog.didierstevens.com/2018/05/31/pdfid-gotoe-and-gotor-detection-ntlm-credential-theft/)
            * The article [“NTLM Credentials Theft via PDF Files”](https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/) explains how PDF documents can refer to a resource via UNC paths. This is done using  PDF names /GoToE or /GoToR. My tool pdfid.py can now be extended to report /GoToE and /GoToR usage in a PDF file, without having to change the source code
        * [Capturing NetNTLM Hashes with Office [DOT] XML Documents - bohops](https://bohops.com/2018/08/04/capturing-netntlm-hashes-with-office-dot-xml-documents/)
        * [Love letters from the red team: from e-mail to NTLM hashes with Microsoft Outlook - WildFire Labs](https://wildfire.blazeinfosec.com/love-letters-from-the-red-team-from-e-mail-to-ntlm-hashes-with-microsoft-outlook/)
        * [Leveraging web application vulnerabilities to steal NTLM hashes - WildFire Labs](https://blog.blazeinfosec.com/leveraging-web-application-vulnerabilities-to-steal-ntlm-hashes-2/)
        * [Automatically Stealing Password Hashes with Microsoft Outlook and OLE - Will Dormann](https://insights.sei.cmu.edu/cert/2018/04/automatically-stealing-password-hashes-with-microsoft-outlook-and-ole.html)
        * [SMB hash hijacking & user tracking in MS Outlook - Soroush Dalili](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/may/smb-hash-hijacking-and-user-tracking-in-ms-outlook/)
        * [Capturing NetNTLM Hashes with Office [DOT] XML Documents - bohops](https://bohops.com/2018/08/04/capturing-netntlm-hashes-with-office-dot-xml-documents/)
        * [Stealing Windows Credentials Using Google Chrome - Bosko Stankovic](http://www.defensecode.com/whitepapers/Stealing-Windows-Credentials-Using-Google-Chrome.pdf)
        * [Windows Credential Theft: RDP & Internet Explorer 11](https://vdalabs.com/2019/09/25/windows-credential-theft-rdp-internet-explorer-11/)
            * NTLM Hashes/relay through RDP files/IE11 XXE explained
        * [SMB hash hijacking & user tracking in MS Outlook - Soroush Dalili](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/may/smb-hash-hijacking-and-user-tracking-in-ms-outlook/)
        * [Places of Interest in Stealing NetNTLM Hashes - osandamalith.com/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
        * [Document Tracking: What You Should Know - justhaifei1](https://justhaifei1.blogspot.com/2013/10/document-tracking-what-you-should-know.html)
        * [Microsoft Office – NTLM Hashes via Frameset - pentestlab.blog](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
        * [Automatically Stealing Password Hashes with Microsoft Outlook and OLE - Will Dormann](https://insights.sei.cmu.edu/cert/2018/04/automatically-stealing-password-hashes-with-microsoft-outlook-and-ole.html)
    * **Talks/Presentations/Videos**
    * **Tools**
* **Tools**
    * [NTLM scanner](https://github.com/preempt/ntlm-scanner)
        * Checks for various NTLM vulnerabilities over SMB. The script will establish a connection to the target host(s) and send an invalid NTLM authentication. If this is accepted, the host is vulnerable to the applied NTLM vulnerability and you can execute the relevant NTLM attack.




-----------------------------------------------------------------------------------------------------------------------------------------------
### <a name="rpc"></a>RPC
* **101**
* **Articles/Blogposts/Writeups**
    * [More of using rpcclient to find usernames - carnal0wnage](http://carnal0wnage.attackresearch.com/2007/08/more-of-using-rpcclient-to-find.html)
    * [more with rpcclient - carnal0wnage](http://carnal0wnage.attackresearch.com/2010/06/more-with-rpcclient.html)
* **Talks/Videos**
* **Papers**


------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="rtsp"></a> RTSP(Real Time Streaming Protocol)
* **101**
    * [Real Time Streaming Protocol - Wikipedia](https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol)
    * [RFC2326: Real Time Streaming Protocol (RTSP) ](https://tools.ietf.org/html/rfc2326)
* **Tools**
    * [rtsp_authgrinder.py](https://github.com/Tek-Security-Group/rtsp_authgrinder)
        * rtsp_authgrind.py - A quick and simple tool to brute force credentials on RTSP services and devices. This is a multi-threaded brute forcing tool for testing, assessment and audit purposes only.
    * [CameraRadar](https://github.com/Ullaakut/cameradar)
        * An RTSP stream access tool that comes with its library
    * [rtsp-url-brute.nse](https://nmap.org/nsedoc/scripts/rtsp-url-brute.html)
        *  Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras. The script attempts to discover valid RTSP URLs by sending a DESCRIBE request for each URL in the dictionary. It then parses the response, based on which it determines whether the URL is valid or not.




------------
#### <a name="sip"></a>SIP/VOIP:
* **101** 
    * [A Hitchhiker's Guide to the Session Initiation Protocol (SIP)](https://tools.ietf.org/html/rfc5411)
    * [Session Initiation Protocol - Wikipedia](https://en.wikipedia.org/wiki/Session_Initiation_Protocol)
* **Articles/Presentations/Talks/Writeups**
* **Tools**
    * [sipvicious](https://github.com/EnableSecurity/sipvicious)
    * [bluebox-ng](https://github.com/jesusprubio/bluebox-ng)
        * Pentesting framework using Node.js powers, focused in VoIP.
    * [SIP Proxy](https://sourceforge.net/projects/sipproxy/)
        * With SIP Proxy you will have the opportunity to eavesdrop and manipulate SIP traffic. Furthermore, predefined security test cases can be executed to find weak spots in VoIP devices. Security analysts can add and execute custom test cases.
    * [Sip Vicious](https://github.com/EnableSecurity/sipvicious)
        * SIPVicious suite is a set of tools that can be used to audit SIP based VoIP systems. 
    * [Mr.SIP](https://github.com/meliht/mr.sip)
        * Mr.SIP is a tool developed to audit and simulate SIP-based attacks. Originally it was developed to be used in academic work to help developing novel SIP-based DDoS attacks and defense approaches and then as an idea to convert it to a fully functional SIP-based penetration testing tool, it has been redeveloped into the current version.






------------
#### <a name="smb"></a>SMB
* **101**
    * [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
    * [Microsoft SMB Protocol and CIFS Protocol Overview](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx)
    * [An Introduction to SMB for Network Security Analysts - 401trg.com](https://401trg.com/an-introduction-to-smb-for-network-security-analysts/)
* **Educational**
* **Attacking**
    **Articles/Blogposts/Writeups**
        * [A new look at null sessions and user enumeration - Reino Mostert(2018)](https://sensepost.com/blog/2018/a-new-look-at-null-sessions-and-user-enumeration/)
    * **Talks/Presentations/Videos**
        * [SMBv2 - Sharing More Than Just Your Files - Hormazd Billimoria, Jonathan Brossard - BHUSA2015](https://www.blackhat.com/docs/us-15/materials/us-15-Brossard-SMBv2-Sharing-More-Than-Just-Your-Files.pdf)
    * **Specific Exploits/Vulns**
        **Articles/Blogposts/Writeups**
            * [Practically Exploiting MS15-014 and MS15-011 - MWR](https://labs.mwrinfosecurity.com/blog/practically-exploiting-ms15-014-and-ms15-011/)
            * [MS15-011 - Microsoft Windows Group Policy real exploitation via a SMB MiTM attack - coresecurity](https://www.coresecurity.com/blog/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack)
            * [Windows: SMB Server (v1 and v2) Mount Point Arbitrary Device Open EoP](https://bugs.chromium.org/p/project-zero/issues/detail?id=1416&t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&refsrc=email&iid=0ba06fc942c7473c8c3669dfc193d5e0&fl=4&uid=150127534&nid=244+293670920)
            * [Windows: Local WebDAV NTLM Reflection Elevation of Privilege](https://bugs.chromium.org/p/project-zero/issues/detail?id=222&redir=1)
        * **Talks/Presentations/Videos**
    * **Redirect**
        * [WinNT/Win95 Automatic Authentication Vulnerability (IE Bug #4)](http://insecure.org/sploits/winnt.automatic.authentication.html) 
        * [Resurrection of the Living Dead: The “Redirect to SMB” Vulnerability](http://blog.trendmicro.com/trendlabs-security-intelligence/resurrection-of-the-living-dead-the-redirect-to-smb-vulnerability/)
        * [SPEAR: Redirect to SMB](https://blog.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf)
        * [10 Places to Stick Your UNC Path - NetSPI](https://blog.netspi.com/10-places-to-stick-your-unc-path/)
    * **Re(p)lay Attack**
        * **Articles/Blogposts/Writeups**
            * [ADV170014 NTLM SSO: Exploitation Guide - sysadminjd.com](http://www.sysadminjd.com/adv170014-ntlm-sso-exploitation-guide/)
            * [SMB Relay with Snarf - Making the Most of Your MitM(2016)](https://bluescreenofjeff.com/2016-02-19-smb-relay-with-snarfjs-making-the-most-of-your-mitm/)
            * [Remote NTLM relaying through meterpreter on Windows port 445 - Diablohorn(2018)](https://diablohorn.com/2018/08/25/remote-ntlm-relaying-through-meterpreter-on-windows-port-445/)
            * [SMB Relay Demystified and NTLMv2 Pwnage with Python - Ed Skoudis(2013)](https://pen-testing.sans.org/blog/2013/04/25/smb-relay-demystified-and-ntlmv2-pwnage-with-python)
            * [What is old is new again: The Relay Attack - SecureAuth(2020)](https://www.secureauth.com/blog/what-old-new-again-relay-attack)
        * **Talks/Presentations/Videos**
            * [Ntlm Relay Reloaded: Attack methods you do not know - Jianing Wang, Junyu Zhou - zeronights18](https://www.youtube.com/watch?v=BrSS_0a0vzQ)
        * **Tools**
            * [Responder](https://github.com/lgandx/Responder)
                * Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.            
            * [Relayer - SMB Relay Attack Script.](https://github.com/Jsitech/relayer)
                * Relayer is an SMB relay Attack Script that automates all the necessary steps to scan for systems with SMB signing disabled and relaying authentication request to these systems with the objective of gaining a shell. Great when performing Penetration testing.
            * [Chuckle](https://github.com/nccgroup/chuckle)
                * An automated SMB Relay Script
    * **Potatoes**
        * [Hot Potato](https://foxglovesecurity.com/2016/01/16/hot-potato/)
            * Hot Potato (aka: Potato) takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.
        * [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM - foxglove security](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
        * [Rotten Potato Privilege Escalation from Service Accounts to SYSTEM - Stephen Breen Chris Mallz - Derbycon6](https://www.youtube.com/watch?v=8Wjs__mWOKI)
        * [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)
            * New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.
        * [Juicy Potato](https://github.com/ohpe/juicy-potato)
        * [SmashedPotato](https://github.com/Cn33liz/SmashedPotato)
        * [Ghost Potato - Danyal Drew(2019)](https://shenaniganslabs.io/2019/11/12/Ghost-Potato.html)
* **Tools**
    * **File Discovery**
        * [SMB Spider](https://github.com/T-S-A/smbspider)
            * SMB Spider is a lightweight utility for searching SMB/CIFS/Samba file shares. This project was born during a penetration test, via the need to search hundreds of hosts quickly for sensitive password files. Simply run "python smbspider.py -h" to get started.
        * [Snaffler](https://github.com/SnaffCon/Snaffler/)
            * Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly, but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment).
        * [sharesniffer](https://github.com/shirosaidev/sharesniffer)
            * sharesniffer is a network analysis tool for finding open and closed file shares on your local network. It includes auto-network discovery and auto-mounting of any open cifs and nfs shares.
        * [SMBCrunch](https://github.com/Raikia/SMBCrunch)
            * 3 tools that work together to simplify reconaissance of Windows File Shares 
        * [winsharecrawler](https://github.com/peacand/winsharecrawler)
            * Python crawler for remote Windows shares
    * [Gladius](https://github.com/praetorian-inc/gladius)
        * Gladius provides an automated method for cracking credentials from various sources during an engagement. We currently crack hashes from Responder, secretsdump.py, and smart_hashdump.
    * [SMBrute](https://github.com/m4ll0k/SMBrute)
        * SMBrute is a program that can be used to bruteforce username and passwords of servers that are using SMB (Samba).
    * [smbmap](https://github.com/ShawnDEvans/smbmap)
        * SMBMap allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks.
    * [nullinux](https://github.com/m8r0wn/nullinux)
        * nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. If no username and password are provided, nullinux will attempt to connect to the target using an SMB null session. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation.This script uses Python 2.7 and the smbclient package, run the setup.sh script to get started.





------------
#### <a name="smtp"></a>SMTP
* **101**
    * [RFC 821 - SIMPLE MAIL TRANSFER PROTOCOL](https://tools.ietf.org/html/rfc821)
    * [RFC 5321 - Simple Mail Transfer Protocol](https://tools.ietf.org/html/rfc5321)
    * [RFC 8461: SMTP MTA Strict Transport Security (MTA-STS)](https://tools.ietf.org/html/rfc8461)
    * [Simple Mail Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)
    * [Simple Mail Transfer Protocol - msdn](https://msdn.microsoft.com/en-us/library/aa480435.aspx)
* **General/Articles/Writeups**
    * [SMTP User Enumeration](https://pentestlab.blog/2012/11/20/smtp-user-enumeration/)
* **Tools** 
    * [Swaks - Swiss Army Knife for SMTP](http://www.jetmore.org/john/code/swaks/)
    * [Papercut](https://github.com/changemakerstudios/papercut)
        * Simple Desktop SMTP Server



------------
#### <a name="snmp"></a>SNMP:
* **101**
    * [Simple Network Management Protocol - Wikipedia](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
* **General/Articles/Writeups**
    * [SNMP Attacks and Security - Mauno Pihelgas](https://home.cyber.ee/~ahtbu/CDS2011/MaunoPihelgasSlides.pdf)
    * [SNMP REFLECTION/AMPLIFICATION](https://www.incapsula.com/ddos/attack-glossary/snmp-reflection.html)
    * [Simple Network Management Pwnd](http://www.irongeek.com/i.php?page=videos/derbycon4/t221-simple-network-management-pwnd-deral-heiland-and-matthew-kienow)
    * [SNMP Config File Injection to Shell - digi.ninja](https://digi.ninja/blog/snmp_to_shell.php)
* **Tools**
    * [Onesixtyone](http://www.phreedom.org/software/onesixtyone/)
        * onesixtyone is an SNMP scanner which utilizes a sweep technique to achieve very high performance. It can scan an entire class B network in under 13 minutes. It can be used to discover devices responding to well-known community names or to mount a dictionary attack against one or more SNMP devices.
    * [SNMPWALK](http://net-snmp.sourceforge.net/docs/man/snmpwalk.html)
        *  snmpwalk - retrieve a subtree of management values using SNMP GETNEXT requests
    * [Cisc0wn - Cisco SNMP Script](https://github.com/nccgroup/cisco-SNMP-enumeration)
        * Automated Cisco SNMP Enumeration, Brute Force, Configuration Download and Password Cracking
    * [SNMPwn](https://github.com/hatlord/snmpwn)
        * SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with "Unknown user name" when an SNMP user does not exist, allowing us to cycle through large lists of users to find the ones that do.




------------
#### <a name="sql"></a>SQL:
* See 'SQL' in the Web Section.
* **General/Articles/Writeups**
    * [Using Metasploit to Find Vulnerable MSSQL Systems](https://www.offensive-security.com/metasploit-unleashed/hunting-mssql/)
* **Tools**
    * [SQLMap](https://github.com/sqlmapproject/sqlmap)
        * sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.
    * [PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server](https://github.com/NetSPI/PowerUpSQL)
        * The PowerUpSQL module includes functions that support SQL Server discovery, auditing for common weak configurations, and privilege escalation on scale. It is intended to be used during internal penetration tests and red team engagements. However, PowerUpSQL also includes many functions that could be used by administrators to quickly inventory the SQL Servers in their ADS domain.
        * [Documentation](https TLS/SSL Vulnerabilities ://github.com/NetSPI/PowerUpSQL/wiki)
        * [Overview of PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/wiki/Overview-of-PowerUpSQL)
    * [nmap ms-sql-info.nse](https://nmap.org/nsedoc/scripts/ms-sql-info.html)
    * [DbDat](https://github.com/foospidy/DbDat)
        * DbDat performs numerous checks on a database to evaluate security. The categories of checks performed are configuration, privileges, users, and information. Checks are performed by running queries or reading database configuration files. The goal of this tool is to highlight issues that need immediate attention and identify configuration settings that should be reviewed for appropriateness. This tool is not for identifying SQL Injection vulnerabilities in an application, there are good tools available for that already (e.g. https://github.com/sqlmapproject). Also, this tool does not attempt to determine what CVEs may impact the version of the target database (but may do so in the future - maybe). Rather, this tool can help you better understand the potential impact of a successful SQL Injection attack due to weak configuration or access controls. A majority of the checks are from the CIS (https://cisecurity.org) Security Benchmarks for databases, so thanks to the CIS! The benchmark documents can be found here: https://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.servers.database


------------
#### <a name="ssh"></a>SSH: 
* **101**
    * [The Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4253)
    * [OpenSSH Specs](https://www.openssh.com/specs.html)
    * [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
    * [The SSH Protocol - Snailbook](http://www.snailbook.com/protocols.html)
* **General/Articles/Writeups**
    * [SSH for Fun and Profit](https://karla.io/2016/04/30/ssh-for-fun-and-profit.html)
    * [OpenSSH User Enumeration Time-Based Attack](http://seclists.org/fulldisclosure/2013/Jul/88)
* **Tools**
    * [ssh-audit](https://github.com/arthepsy/ssh-audit)
        * SSH server auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)





--------------
#### <a name="ssl"></a>SSL/TLS
* **101**
    * [RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246)
    * [Transport Layer Security - Wikipedia](https://en.wikipedia.org/wiki/Transport_Layer_Security)
    * [Application-Layer TLS - draft-friel-tls-atls-02](https://tools.ietf.org/html/draft-friel-tls-atls-02)
        * This document specifies how TLS sessions can be established at the application layer over untrusted transport between clients and services for the purposes of establishing secure end-to-end encrypted communications channels.Transport layer encodings for applicationlayer TLS records are specified for HTTP and CoAP transport. Explicit identification of application layer TLS packets enablesmiddleboxes to provide transport services and enforce suitable transport policies for these payloads, without requiring access to the unencrypted payload content. Multiple scenarios are presented identifying the need for end-to-end application layer encryption between clients and services, and the benefits of reusing the well-defined TLS protocol, and a standard TLS stack, to accomplish thisare described.Application software architectures for building, and network architectures for deploying application layer TLS are outlined.
    * [The Illustrated TLS Connection - @XargsNotBombs](https://tls.ulfheim.net/)
* **General**
    * [OWASP Transport Layer Protection Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
    * [SSL/TLS and PKI History](https://www.feistyduck.com/ssl-tls-and-pki-history/)
        * A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem.
* **Articles/Blogposts/Writeups**
    * [SSL & TLS Penetration Testing [Definitive Guide]](https://www.aptive.co.uk/blog/tls-ssl-security-testing/)
    * [TLS/SSL Vulnerabilities](https://www.gracefulsecurity.com/tls-ssl-vulnerabilities/)
    * [SSL/TLS and PKI History](https://www.feistyduck.com/ssl-tls-and-pki-history/)
        * A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem. Based on Bulletproof SSL and TLS, by Ivan Ristić.
    * [Security/Server Side TLS - Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS)
        * The goal of this document is to help operational teams with the configuration of TLS on servers. All Mozilla sites and deployment should follow the recommendations below. The Operations Security (OpSec) team maintains this document as a reference guide to navigate the TLS landscape. It contains information on TLS protocols, known issues and vulnerabilities, configuration examples and testing tools. Changes are reviewed and merged by the OpSec team, and broadcasted to the various Operational teams. 
* **Attacks On**
    * **BEAST**
        * [An Illustrated Guide to the BEAST Attack - Joshua Davies](http://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art027)
    * **CRIME**
* **TLS Fingerprinting**
    * **Articles/Blogposts/Writeups**
        * [Stealthier Attacks and Smarter Defending with TLS Fingerprinting - Lee Brotherston(SecTor 2015)](http://2015.video.sector.ca/video/144175700)
        * [Hunting SSL/TLS clients using JA3 - Remco Verhoef(SANS)](https://isc.sans.edu/forums/diary/Hunting+SSLTLS+clients+using+JA3/23972/)
        * [JA3 Fingerprints - ssl.abuse.ch](https://sslbl.abuse.ch/ja3-fingerprints/)
            * Here you can browse a list of malicious JA3 fingerprints identified by SSLBL.
        * [Inspecting Encrypted Network Traffic with JA3 - Bryant Smith](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/inspecting-encrypted-network-traffic-with-ja3/)
        * [Fingerprinting TLS clients with JA3 - jwlss.pw](https://jwlss.pw/ja3/)
            * This article is a short guide to using JA3 for fingerprinting TLS clients, with possible use cases and a simple demo.
        * [Hunting with JA3 - mbsecure.nl](https://www.mbsecure.nl/blog/2018/06/hunting-with-ja3)
            * Within this blog post I will explain how JA3 can be used in Threat Hunting. I will discuss a relative simple hunt on a possible way to identify malicious PowerShell using JA3 and a more advanced hunt that involves the use of Darktrace and JA3.
        * [JA3/S Signatures and How to Avoid Them - Jacob Krasnov, Anthony Rose](https://www.bc-security.org/post/ja3-s-signatures-and-how-to-avoid-them)
        * [DETECTION ENGINEERING: Passive TLS Fingerprinting - Experience from adopting JA3 - Kjell Fossbakk](https://www.nsm.stat.no/globalassets/dokumenter/ncss/2019-06-05-helsecert---norcert-forum-2019.pdf)
        * [HTTP client fingerprinting using SSL handshake analysis - Ivan Ristic(2009)](https://blog.ivanristic.com/2009/06/http-client-fingerprinting-using-ssl-handshake-analysis.html)
        * [Impersonating JA3 Fingerprints - Matthew Rinaldi](https://medium.com/cu-cyber/impersonating-ja3-fingerprints-b9f555880e42)
    * **Presentations/Talks/Videos**
        * [TLS Fingerprinting - Lee Brotherston](https://github.com/LeeBrotherston/tls-fingerprinting)
        * [Profiling And Detecting All Things SSL With JA3 - John Althouse and Jeff Atkinson](https://www.youtube.com/watch?v=oprPu7UIEuk)
            * In this talk we will show the benefits of SSL fingerprinting, JA3’s capabilities, and how best to utilize it in your detection and response operations. We will show how to utilize JA3 to find and detect SSL malware on your network. Imagine detecting every Meterpreter shell, regardless of C2 and without the need for SSL interception. We will also announce JA3S, JA3 for SSL server fingerprinting. Imagine detecting every Metasploit Multi Handler or [REDACTED] C2s on AWS. Then we’ll tie it all together, making you armed to the teeth for detecting all things SSL.
        * [Using JA3. Asking for a friend? - Justin Warner, Ed Miles(BSides DC 2019)](https://www.youtube.com/watch?v=HrP6Ep3xgQM)
            * The number one question every single network detection person gets asked: how do you deal with encrypted traffic? Threat actors leverage encryption to obfuscate their activities, sneaking past the border guards in their enchanted cloak, leveraging legitimate certificates or even worse, legitimate services to operate their C2. In 2017, a method for fingerprinting SSL clients and servers was released titled JA3 and JA3s respectively and with their release, network detection engineers rejoiced. JA3/JA3S seeks to profile the client and server software involved in an SSL/TLS session through fingerprinting their “hello” messages and the involved cryptographic exchange. This method is not without its’ nuances and in our experience putting it to the use, the nuances are critical to understand. This talk will give insights into our challenges, failures and successes with JA3 and JA3S while sharing tips for those seeking to begin using it for network detection.
* **Tools**
    * [testssl.sh](https://github.com/drwetter/testssl.sh)
        * testssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.
    * [JA3](https://github.com/salesforce/ja3)
        * JA3 is a standard for creating SSL client fingerprints in an easy to produce and shareable way.
    * [JA3 SSL Fingerprint](https://ja3er.com)
        * Find out your fingerprint
    * [JA3Transport](https://github.com/CUCyber/ja3transport)
        * A Go library that makes it easy to mock JA3 signatures.













------------
#### <a name="stp"></a>STP
* **101**
    * [Spanning Tree Protocol - Wikipedia](https://en.wikipedia.org/wiki/Spanning_Tree_Protocol)
    * [Spanning Tree Protocol (STP) Introduction](http://www.dummies.com/programming/networking/cisco/spanning-tree-protocol-stp-introduction/)
* **General/Articles/Writeups**
    * [STP MiTM Attack and L2 Mitigation Techniques on the Cisco Catalyst 6500 ](http://www.ndm.net/ips/pdf/cisco/Catalyst-6500/white_paper_c11_605972.pdf)



### <a name="tftp"></a> TFTP(Trivial File Transfer Protocol)
* **101**
    * [RFC1350: THE TFTP PROTOCOL (REVISION 2)](https://tools.ietf.org/html/rfc1350)
* **Articles/Blogposts/Writeups**
* **Presentations/Talks/videos**
* **Tools**

------------
#### <a name="telnet"></a>Telnet 
* **101**
* **General/Articles/Writeups**
    * [Shellshock and the Telnet USER Variable](https://digi.ninja/blog/telnet_shellshock.php)
        * `telnet 10.1.1.1 -l "() { :;}; /usr/bin/id"`

------------
### <a name="tr69">TR-069</a>
* **101**
    * [TR-069 - Wikipedia](https://en.wikipedia.org/wiki/TR-069)
* **General/Articles/Writeups**
    * [Too Many Cooks; Exploiting the Internet of Tr-069](http://mis.fortunecook.ie/) 
    * [TR-069 – A Crash Course University of New Hampshire Interoperability Laboratory 2009](https://www.iol.unh.edu/sites/default/files/knowledgebase/hnc/TR-069_Crash_Course.pdf)
    * [I Hunt TR-069 Admins - Pwning ISPs Like a Boss - Defcon 22](https://media.defcon.org/DEF%20CON%2022/DEF%20CON%2022%20video%20and%20slides/DEF%20CON%2022%20Hacking%20Conference%20Presentation%20By%20Shahar%20Tal%20-%20I%20Hunt%20TR%20-%20069%20Admins%20-%20Pwning%20ISPs%20Like%20a%20Boss%20-%20Video%20and%20Slides.m4v)
    * [Brief Survey of CWMP Security](http://blog.3slabs.com/2012/12/a-brief-survey-of-cwmp-security.html)


------------
### <a name="upnp">UPnP</a>
* **101**
    * [Universal Plug and Play (UPnP) Internet Gateway Device - Port Control Protocol Interworking Function (IGD-PCP IWF)](https://tools.ietf.org/html/rfc6970)
    * [UPnP™ Device Architecture 1.1 - upnp.org]
    * [Universal Plug and Play - Wikipedia](https://en.wikipedia.org/wiki/Universal_Plug_and_Play)
* **General**
    * **Articles/Blogposts/Writeups**
* **Attacking**
    * **Articles/Blogposts/Writeups**
        * [Exploiting UPnP, literally childsplay. - KN100](https://kn100.me/exploiting-upnp-literally-childsplay/)
        * [UPNP Hacks](http://www.upnp-hacks.org/igd.html)
        * [Security Issues Discovered in MiniUPnP - Ben Barnea(2019)](https://www.vdoo.com/blog/security-issues-discovered-in-miniupnp)
* **Tools**
    * [Ufuzz](https://github.com/phikshun/ufuzz)
        * UFuzz, or Universal Plug and Fuzz, is an automatic UPnP fuzzing tool. It will enumerate all UPnP endpoints on the network, find the available services and fuzz them. It also has the capability to fuzz HTTP using Burp proxy logs.
    * [miranda-upnp](https://github.com/0x90/miranda-upnp)
    * [UPnP Pentest Toolkit](https://github.com/nccgroup/UPnP-Pentest-Toolkit)





-----------------------
### <a name="webdav"></a> WebDAV
* **101**
* **General/Articles/Writeups**
* **Tools**
    * [WsgiDAV](https://github.com/mar10/wsgidav)
        * WsgiDAV is a generic WebDAV server written in Python and based on WSGI.






------------
### <a name="pac"></a>PAC/WPAD
* **101/Educational**
     * [IETF: Web Proxy Auto-Discovery Protocol](https://tools.ietf.org/html/draft-ietf-wrec-wpad-01)
    * [Web Proxy Auto-Discovery Protocol - Wikipedia](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol)
    * [Proxy auto-config - Wikipedia](https://en.wikipedia.org/wiki/Proxy_auto-config)
    * [Proxy Auto-Configuration (PAC) file - dev.mozilla](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_(PAC)\_file)
        * A Proxy Auto-Configuration (PAC) file is a JavaScript function that determines whether web browser requests (HTTP, HTTPS, and FTP) go directly to the destination or are forwarded to a web proxy server. The JavaScript function contained in the PAC file defines the function:
* **Articles/Blogposts/Writeups**
    * [Sample proxy auto-configuration (PAC) file](https://support.symantec.com/en_US/article.HOWTO54198.html)
    * [wpadblock.com](https://www.wpadblock.com/)
        * WPADblock initiative: monitoring and blocking WPAD traffic since 2007.
    * [aPAColypse now: Exploiting Windows 10 in a Local Network with WPAD/PAC and JScript - Ivan Fratric, Thomas Dullien, James Forshaw and Steven Vittitoe](https://googleprojectzero.blogspot.com/2017/12/apacolypse-now-exploiting-windows-10-in_18.html)
    * [WPAD Man In The Middle (Clear Text Passwords) - Larry Spohn](https://www.trustedsec.com/blog/wpad-man-in-the-middle-clear-text-passwords/)
    * [WPAD Man in the Middle - Erik Hjelmvik](http://netresec.com/?page=Blog&month=2012-07&post=WPAD-Man-in-the-Middle)
    * [WPAD: instruction manual - cdump(Russian text)](https://habr.com/en/company/mailru/blog/259521/)
* **Presentations/Talks/Videos**
    * [aPAColypse now: Exploiting Windows 10 in a Local Network with WPAD/PAC and JScript](https://googleprojectzero.blogspot.com/2017/12/apacolypse-now-exploiting-windows-10-in_18.html?m=1)
    * [badWPAD - Maxim Goncharov(BHUSA16-slides)](https://www.blackhat.com/docs/us-16/materials/us-16-Goncharov-BadWpad.pdf)
    * [badWPAD: The Lasting Menace of a Bad Protocol - Max Goncharov](https://www.trendmicro.co.uk/media/misc/wp-badwpad.pdf)
    * [Crippling HTTPs With Unholy PAC - Itzik Kotler & Amit Klein](https://www.youtube.com/watch?v=7q40RLilXKw)
        * [Slides](https://www.blackhat.com/docs/us-16/materials/us-16-Kotler-Crippling-HTTPS-With-Unholy-PAC.pdf)
    * [Toxic Proxies - Bypassing HTTPS - Defcon24 - Alex Chapman, Paul Stone](https://www.youtube.com/watch?v=3vegxj5a1Rw&app=desktop)
        * In this talk we'll reveal how recent improvements in online security and privacy can be undermined by decades old design flaws in obscure specifications. These design weakness can be exploited to intercept HTTPS URLs and proxy VPN tunneled traffic. We will demonstrate how a rogue access point or local network attacker can use these new techniques to bypass encryption, monitor your search history and take over your online accounts. No logos, no acronyms; this is not a theoretical crypto attack. We will show our techniques working on $30 hardware in under a minute. Online identity? Compromised. OAuth? Forget about it. Cloud file storage? Now we're talking. 
        * [Slides](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Chapman-Stone-Toxic-Proxies-Bypassing-HTTPS-and-VPNs.pdf)
        * [PAC HTTPS Leak Demos](https://github.com/ctxis/pac-leak-demo)
            * This is the code for the demos from our DEF CON 24 talk, [Toxic Proxies - Bypassing HTTPS and VPNs to Pwn Your Online Identity](https://defcon.org/html/defcon-24/dc-24-speakers.html#Chapman) The demos use the [PAC HTTPS leak](http://www.contextis.com/resources/blog/leaking-https-urls-20-year-old-vulnerability/) to steal data and do various fun things. Our demos worked in Chrome on Windows with default settings, until the issue was fixed in Chrome 52. You can use Chrome 52+ to try out these demos if you launch it with the --unsafe-pac-url flag.




-----------------------
### <a name="wmi"></a> Windows Management Instrumentation(WMI)
* **101**
    * [Windows Management Instrumentation - Wikipedia](https://en.wikipedia.org/wiki/Windows_Management_Instrumentation)
    * [Windows Management Instrumentation - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
    * [About WMI - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi)
    * [WMIC - Take Command-line Control over WMI - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742610(v=technet.10))
* **Official Documentation**
    * [WMI Reference - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-reference)
    * [Introduction to CIM Cmdlets - MS](https://devblogs.microsoft.com/powershell/introduction-to-cim-cmdlets/)
    * [A Description of the Windows Management Instrumentation (WMI) Command-Line Utility (Wmic.exe) - support.ms](https://support.microsoft.com/en-us/help/290216/a-description-of-the-windows-management-instrumentation-wmi-command-li)
    * [wmic - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic)
    * [WMIC - Take Command-line Control over WMI - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742610(v=technet.10))
    * [Using Windows Management Instrumentation Command-line - docs.ms(2009)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc779482(v=ws.10))
    * [WMI Classes - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-classes)
    * [Access to WMI Namespaces - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces)
    * [WMI Tasks: Accounts and Domains - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--accounts-and-domains)
    * [WMI Tasks -- Services - docs.ms ](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--services)
    * [WMI Tasks: Files and Folders - docs.ms](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--files-and-folders)
    * [Search for files using WMI - Jaap Brasser](https://www.jaapbrasser.com/search-for-files-using-wmi/)
    * [Using the PowerShell CIM cmdlets for fun and profit - Dr Scripto](https://devblogs.microsoft.com/scripting/using-the-powershell-cim-cmdlets-for-fun-and-profit/)
    * [Use PowerShell and WMI to Get Processor Information - Dr Scripto](https://devblogs.microsoft.com/scripting/use-powershell-and-wmi-to-get-processor-information/)
    * [Using the Get-Member Cmdlet - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-powershell-1.0/ee176854(v=technet.10))
    * [Get-Process - docs.ms](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Management/Get-Process?view=powershell-5.1)
* **General**
    * (Book) Understanding WMI Scripting: Exploiting Microsoft's Windows Management Instrumentation in Mission-Critical Computing Infrastructures - Alain Lissoir
* **Articles/Blogposts/Writeups**
    * [Getting Started with WMI Weaponization – Part 5 - Alexander Leary](https://blog.netspi.com/getting-started-wmi-weaponization-part-5/)
    * [Introduction to WMI Basics with PowerShell Part 1 (What it is and exploring it with a GUI) - Carlos Perez](https://www.darkoperator.com/blog/2013/1/31/introduction-to-wmi-basics-with-powershell-part-1-what-it-is.html)
    * [Post Exploitation Using WMIC (System Command) - hackingarticles.in](https://www.hackingarticles.in/post-exploitation-using-wmic-system-command/)
    * [WMIC Command Line Kung-Fu - tech-wreck.blogspot.com](https://tech-wreckblog.blogspot.com/2009/11/wmic-command-line-kung-fu.html)
    * [Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY) - Matthew Dunwoody](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html)
    * [Creeping on Users with WMI Events: Introducing PowerLurk - Sw4mp_f0x](https://pentestarmoury.com/2016/07/13/151/)
    * [PowerShell and Events: WMI Temporary Event Subscriptions - Boe Prox](https://learn-powershell.net/2013/08/02/powershell-and-events-wmi-temporary-event-subscriptions/)
    * [Windows Userland Persistence Fundamentals - FuzzySecurity](http://www.fuzzysecurity.com/tutorials/19.html)
    * [Detecting & Removing an Attacker’s WMI Persistence - David French](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96)
    * [An intro into abusing and identifying WMI Event Subscriptions for persistence - @rebootuser](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)
    * [A Brief Usage Guide for Wmic - xorrior](https://www.xorrior.com/wmic-the-enterprise/)
    * [Lateral Movement Using WinRM and WMI - Tony Lambert](https://redcanary.com/blog/lateral-movement-winrm-wmi/)
    * [Getting Started with WMI Weaponization – Part 2 - Alexander Leary](https://blog.netspi.com/getting-started-wmi-weaponization-part-2/)
    * [Examples of WMIC commands for Windows .NET SERVER Family - cs.cmu.edu](https://www.cs.cmu.edu/~tgp/scsadmins/winadmin/WMIC_Queries.txt)
    * [WMIS: The Missing Piece of the Ownage Puzzle - Christopher Campbell, Exorcyst](http://passing-the-hash.blogspot.com/2013/07/WMIS-PowerSploit-Shells.html)
* **Papers**
    * [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor - Matt Graeber(BHUSA15)](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
    * [Windows Management Instrumentation(WMI) Offense, Defense, and Forensics - William Ballenthin, Matt Graeber, Claudiu Teodorescu](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)
* **Presentations/Talks/Videos**
    * [Abusing Windows Management Instrumentation (WMI) - Matthew Graeber(BH USA 2015)](https://www.youtube.com/watch?v=0SjMgnGwpq8)
        * Imagine a technology that is built into every Windows operating system going back to Windows 95, runs as System, executes arbitrary code, persists across reboots, and does not drop a single file to disk. Such a thing does exist and it's called Windows Management Instrumentation (WMI). With increased scrutiny from anti-virus and 'next-gen' host endpoints, advanced red teams and attackers already know that the introduction of binaries into a high-security environment is subject to increased scrutiny. WMI enables an attacker practicing a minimalist methodology to blend into their target environment without dropping a single utility to disk. WMI is also unlike other persistence techniques in that rather than executing a payload at a predetermined time, WMI conditionally executes code asynchronously in response to operating system events. This talk will introduce WMI and demonstrate its offensive uses. We will cover what WMI is, how attackers are currently using it in the wild, how to build a full-featured backdoor, and how to detect and prevent these attacks from occurring.

* **Reference**
    * [Connecting to WMI Remotely with C# - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/connecting-to-wmi-remotely-with-c-)
    * [Windows Command Line cheatsheet (part 1): some useful tips - Andrea Fortuna](https://www.andreafortuna.org/2017/08/03/windows-command-line-cheatsheet-part-1-some-useful-tips/)
    * [Windows Command Line cheatsheet (part 2): WMIC - Andrea Fortuna](https://www.andreafortuna.org/2017/08/09/windows-command-line-cheatsheet-part-2-wmic/)
* **Tools**
    * [WMI_Backdoor](https://github.com/mattifestation/WMI_Backdoor)
        * A PoC WMI backdoor presented at Black Hat 2015


































------------------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------------------------------------
## <a name="------------
### <a name="pivot"></a>Pivoting
* Look at the Pivoting section in Post Exploitation/Privilege Escalation


---------------------------
### <a name="vendor"></a> Vendor Specific Stuff
* **Non-Specific**
    * [Vendor/Ethernet/Bluetooth MAC Address Lookup and Search - coffer.com](http://www.coffer.com/mac_find/)
    * [IP Cameras Default Passwords Directory](https://ipvm.com/reports/ip-cameras-default-passwords-directory)
* **Cisco**
    * **Application Centric Infrastructure**
        * [Through the Looking Glass Own the Data Center - Chris McCoy(Defcon27 - RT Village)](https://www.youtube.com/watch?v=G-heFh4t-Pk&list=PL9fPq3eQfaaChXmQKpp1YO19Gw-6SxBDs&index=4)
            * [Slides]()
            * The data center embodies the heart of many businesses on the Internet. It contains much of the information in a centralized location which provides a huge incentive for those who would wish harm. The data centers in the realm of Cloud may no longer contain just a single entity, but many individual tenants that attach to a common fabric. The Cisco Application Centric Infrastructure (ACI) aims to meet these needs with a multi-tenant, scalable fabric that interconnects physical hosts, VMs and containers. ACI is Cisco's answer to the centrally-managed Software Defined Network (SDN). The Application Policy Infrastructure Controller (APIC) and Nexus 9000 series switches form the brains and backbone of ACI. A member of Cisco's Advanced Security Initiatives Group (ASIG) will demonstrate their findings during an evaluation of ACI and the APIC, more than three years before the BH2019 talk "APIC's Adventures in Wonderland." Step into the mind of an attacker and scan, probe, and interact with the network fabric to progress from an unauthenticated user to administrator and root of the data center switch fabric. Once inside the system, see how the APIC can be modified in a nearly undetectable manner to provide the attacker unfettered internal access to all the interconnected hosts and VMs in the data center. The target audience for this talk includes those with a technical interest in offensive discovery and secure product development. Participants will receive an overview of how a data center product is viewed in an offensive light.
    * **Smart Install**
        * [Cisco Smart Installs and Why They’re Not “Informational” - Jordan Drysdale](https://www.blackhillsinfosec.com/cisco-smart-installs-and-why-theyre-not-informational/)
        * [Smart Install Description - cisco.com](https://www.cisco.com/c/en/us/td/docs/switches/lan/smart_install/configuration/guide/smart_install/concepts.html)
        * [Action Required to Secure the Cisco IOS and IOS XE Smart Install Feature](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180409-smi)
    * **Misc**
        * [CVE-2016-6366](https://github.com/RiskSense-Ops/CVE-2016-6366/blob/master/README.md)
            * Public repository for improvements to the EXTRABACON exploit, a remote code execution for Cisco ASA written by the Equation Group (NSA) and leaked by the Shadow Brokers.
        * [Pentesting Cisco SD-WAN Part 1: Attacking VManage - Julien Legras, Thomas Etrillard(2020)](https://www.synacktiv.com/posts/pentest/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
* **F5**
    * [BigIP Security - dnkolegov](https://github.com/dnkolegov/bigipsecurity/blob/master/README.md)
        * This document describes common misconfigurations of F5 Networks BigIP systems.
* **IBM**
    * [Domi-Owned](https://github.com/coldfusion39/domi-owned)
        * Domi-Owned is a tool used for compromising IBM/Lotus Domino servers. Tested on IBM/Lotus Domino 8.5.2, 8.5.3, 9.0.0, and 9.0.1 running on Windows and Linux.



* **Distributed Systems**
    * [Garfield](https://github.com/tunnelshade/garfield)
        * Garfield is and open source framework for scanning and exploiting Distributed Systems. The framework currently being in it's alpha stage and is undergoing rapid development.
* [IVRE](https://github.com/cea-sec/ivre)
    * IVRE (Instrument de veille sur les réseaux extérieurs) or DRUNK (Dynamic Recon of UNKnown networks) is a network recon framework, including tools for passive recon (flow analytics relying on Bro, Argus, Nfdump, fingerprint analytics based on Bro and p0f and active recon (IVRE uses Nmap to run scans, can use ZMap as a pre-scanner; IVRE can also import XML output from Nmap and Masscan).
    http://www.pentest-standard.org/index.php/Intelligence_Gathering

></a>Attacks


------------
### <a name="attackw">Attacking Windows Networks</a>
* **General**
    * Also check out the Privilege Escalation/Post-Exploitation Document as well
    * [Introducing PowerShell into your Arsenal with PS>Attack - Jared Haight](http://www.irongeek.com/i.php?page=videos/derbycon6/119-introducing-powershell-into-your-arsenal-with-psattack-jared-haight)
    * [Get-Help: An Intro to PowerShell and How to Use it for Evil - Jared Haight](https://www.psattack.com/presentations/get-help-an-intro-to-powershell-and-how-to-use-it-for-evil/)
* **Active Directory**
    * Check under privesc/postex for More info
    * [Active Directory - Wikipedia](https://en.wikipedia.org/wiki/Active_Directory)
    * [AD Security Active Directory Resources](https://adsecurity.org/?page_id=41)
    * [AD Reading: Active Directory Core Concepts](http://adsecurity.org/?p=15)
    * [AD Reading: Active Directory Authentication & Logon](http://adsecurity.org/?p=20)
    * [MS Network Level Authentication](https://technet.microsoft.com/en-us/magazine/hh750380.aspx)
    * **Pass-the-Hash**
        * [Pass the hash - Wikipedia](https://en.wikipedia.org/wiki/Pass_the_hash)
        * [Pass the hash attacks: Tools and Mitigation - 2010 SANS paper](https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283)
        * [Performing Pass-the-Hash Attacks with Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
        * [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
        * [Still Passing the Hash 15 Years Later](https://passing-the-hash.blogspot.com/)
            * Providing all the extra info that didn't make it into the BlackHat 2012 USA Presentation "Still Passing the Hash 15 Years Later? Using the Keys to the Kingdom to Access All Your Data" by Alva Lease 'Skip' Duckwall IV and Christopher Campbell.
        * [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)
            * Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB tasks. WMI and SMB services are accessed through .NET TCPClient connections. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.
        * [Why Crack When You Can Pass the Hash? - Chris Hummel(2009)](https://www.sans.org/reading-room/whitepapers/testing/crack-pass-hash-33219)
        * [Passing-the-Hash to NTLM Authenticated Web Applications - Christopher Panayi](https://labs.mwrinfosecurity.com/blog/pth-attacks-against-ntlm-authenticated-web-applications/)
            * A blog post detailing the practical steps involved in executing a Pass-the-Hash (PtH) attack in Windows/Active Directory environments against web applications that use domain-backed NTLM authentication. The fundamental technique detailed here was previously discussed by Alva 'Skip' Duckwall and Chris Campbell in their excellent 2012 Blackhat talk, "Still Passing the Hash 15 Years Later…" 
    * **Passing the Ticket Attacks**
        * [How To Pass the Ticket Through SSH Tunnels](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
        * [Mimikatz and Active Directory Kerberos Attacks ](https://adsecurity.org/?p=556)
        * **Silver Tickets**
            * [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
        * **Gold Tickets**
            * [mimikatz - Golden Ticket](http://rycon.hu/papers/goldenticket.html)
            * [The Golden Ticket Attack - A Look Under The Hood](http://cybersecology.com/wp-content/uploads/2016/05/Golden_Ticket-v1.13-Final.pdf)
            * [Kerberos Golden Ticket Protection Mitigating Pass-the-Ticket on Active Directory - CERT-EU](https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf)
            * [The path to the Golden Ticket](https://countuponsecurity.com/tag/pass-the-ticket/)
        * [The Secret Life of KRBTGT](https://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf)
        * [From Pass-the-Hash to Pass-the-Ticket with No Pain](http://resources.infosecinstitute.com/pass-hash-pass-ticket-no-pain/)
    * **Lateral Movement**
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
* **RDP**
    * [RDP hijacking-how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
    * [RDP Man-in-The-Middle attack ](https://theevilbit.blogspot.com/2014/04/rdp-man-in-middle-attack.html)
    * [ATTACKING RDP How to Eavesdrop on Poorly Secured RDP Connections - Adrian Vollmer 2017](https://www.exploit-db.com/docs/41621.pdf)
    * [RDPY](https://github.com/citronneur/rdpy)
        * RDPY is a pure Python implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (client and server side). RDPY is built over the event driven network engine Twisted. RDPY support standard RDP security layer, RDP over SSL and NLA authentication (through ntlmv2 authentication protocol).
    * [SSL -Man-In-The-Middle- attacks on RDP](https://web.archive.org/web/20161007044945/https://labs.portcullis.co.uk/blog/ssl-man-in-the-middle-attacks-on-rdp/)
    * [rdps2rdp](https://github.com/DiabloHorn/rdps2rdp)
        * Decrypt MITM SSL RDP and save to pcap
* **Recon**
    * [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
        * PowerView is a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows `net *` commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.
    * [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon)
        * AD PowerShell Recon Scripts
    * [Netview](https://github.com/mubix/netview)
        * Netview is a enumeration tool. It uses (with the -d) the current domain or a specified domain (with the -d domain) to enumerate hosts
    * [DomainTrustExplorer](https://github.com/sixdub/DomainTrustExplorer)
        * Python script for analyis of the "Trust.csv" file generated by Veil PowerView. Provides graph based analysis and output. The graph output will represent access direction (opposite of trust direction) 
    * [ShareCheck Windows Enumeration Tool v2.0 - sec1](http://www.sec-1.com/blog/2014/sharecheck)
* **Getting Credentials**
    * [Dumping a Domain-s Worth of Passwords With Mimikatz pt. 2](http://www.harmj0y.net/blog/powershell/dumping-a-domains-worth-of-passwords-with-mimikatz-pt-2/)
    * [LLMNR and NBT-NS Poisoning Using Responder](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)
    * [Attacking ADFS Endpoints with PowerShell](http://www.irongeek.com/i.php?page=videos/derbycon6/118-attacking-adfs-endpoints-with-powershell-karl-fosaaen)
    * [hashjacking](https://github.com/hob0/hashjacking)
* **Getting Domain Admin**
    * [Attack Methods for Gaining Domain Admin Rights in Active Directory - hackingandsecurity](https://hackingandsecurity.blogspot.com/2017/07/attack-methods-for-gaining-domain-admin.html?view=timeslide)
* **Kerberos**
    * [Abusing Kerberos](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It-wp.pdf)
    * [krb5-enum-users - nse script](https://nmap.org/nsedoc/scripts/krb5-enum-users.html)
        * Discovers valid usernames by brute force querying likely usernames against a Kerberos service. When an invalid username is requested the server will respond using the Kerberos error code KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, allowing us to determine that the user name was invalid. Valid user names will illicit either the TGT in a AS-REP response or the error KRB5KDC_ERR_PREAUTH_REQUIRED, signaling that the user is required to perform pre authentication. 
* **Slides**
    * [Windows Attacks AT is the new black](https://www.slideshare.net/mubix/windows-attacks-at-is-the-new-black-26665607)
* **Tools**
    * [Responder](https://github.com/SpiderLabs/Responder/)
        * Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
        * [Where are my hashes? (Responder Observations) - markclayton](https://markclayton.github.io/where-are-my-hashes-responder-observations.html)
    * [Enum4Linux](https://labs.portcullis.co.uk/tools/enum4linux/)
        * Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com. It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. The tool usage can be found below followed by examples, previous versions of the tool can be found at the bottom of the page.
* **MS SQL Server**
    * [Authentication in SQL Server - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/authentication-in-sql-server)
* **Sharepoint**
    * [MS Sharepoint - Wikipedia](https://en.wikipedia.org/wiki/SharePoint)
    * [Technical Advisory: Bypassing Workflows Protection Mechanisms - Remote Code Execution on SharePoint - nccgroup](https://www.nccgroup.trust/uk/our-research/technical-advisory-bypassing-workflows-protection-mechanisms-remote-code-execution-on-sharepoint/)
        * "authenticated users of SharePoint could execute commands on the server.""
    * **Tools**
        * [Sparty - MS Sharepoint and Frontpage Auditing Tool](http://sparty.secniche.org/)
            * Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture. The motivation behind this tool is to provide an easy and robust way to scrutinize the security configurations of sharepoint and frontpage based web applications. Due to the complex nature of these web administration software, it is required to have a simple and efficient tool that gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. A number of automated scanners fall short of this and Sparty is a solution to that.
        * [SPScan](http://sourceforge.net/projects/spscan/)
            * SPScan is a tool written in Ruby that enumerates a SharePoint installation gathering information about the version and installed plugins.
        * [SPartan](https://github.com/sensepost/SPartan)
            * SPartan is a Frontpage and Sharepoint fingerprinting and attack tool
        * [SharePwn](https://github.com/0rigen/SharePwn)
            * A tool for auditing SharePoint security settings and identifying common security holes.





------------------------------------------------------------------------------------------------------------------------------------
#### <a name="bitsquat"></a>BitSquatting:
* **General**
    * [DEFCON 19: Bit-squatting: DNS Hijacking Without Exploitation (w speaker)](https://www.youtube.com/watch?v=aT7mnSstKGs)
        * [Bitsquatting - DNS Hijacking without Exploitation - Artem Dinaburg](https://media.blackhat.com/bh-us-11/Dinaburg/BH_US_11_Dinaburg_Bitsquatting_WP.pdf)
        * [Blogpost - Bitsquatting: DNS Hijacking without exploitation](http://dinaburg.org/bitsquatting.html)
    * [Bitsquatting: Exploiting Bit-flips for Fun, or Profit?](http://www.securitee.org/files/bitsquatting_www2013.pdf)
* **Tools**
    * [Bitsquatting - benjaminpetrin](https://github.com/benjaminpetrin/bitsquatting)
        * This repository includes a simple toy DNS server written in Python3 for use in conducting research in bitsquatting (bitsquat_dns.py). It also includes a helper script for generating the necessary permutations of a domain (domain_gen.py). The remainder of this README includes further documentation of the included DNS server, and a brief summary of my results running this on the web for a period in 2015.
    * [digbit](https://github.com/mnmnc/digbit/blob/master/README.md)
        * Automatic domain generation for BitSquatting


--------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="xaps"></a> Cross-Application/Cross Protocol Scripting
* **101**
    * [Cross-application scripting - Wikipedia](https://en.wikipedia.org/wiki/Cross-application_scripting)
* **Articles/Blogposts/Writeups**
    * 
* **Presentations/Talks/Videos**
    * [Cross Application Scripting (Security Summit 2010 Milano) - Emanuele Gentili, Alessandro Scoscia, Emanuele Acri](https://vimeo.com/10258669)
        * [Slides](https://web.archive.org/web/20101227234436/http://www.backtrack.it/~emgent/talks/16032010_-_SecuritySummit_CAS.pdf)
* **Papers**
    * [The HTML Form Protocol Attack - Jochen Topf](https://www.jochentopf.com/hfpa/hfpa.pdf)
        * This paper describes how some HTML browsers can be tricked through the use of HTML forms into sending more or less arbitrary data to any TCP port. This can be used to send commands to servers using ASCII based protocols like SMTP, NNTP, POP3, IMAP, IRC, and others. By sending HTML email to unsuspecting users or using a trojan HTML page, an attacker might be able to send mail or post Usenet News through servers normally not accessible to him. In special cases an attacker might be able to do other harm, e.g. deleting mail from a POP3 mailbox.


------------
### <a name="ddos"></a>D/DOS
* **101**
    * [Denial-of-service attack - Wikipedia](https://en.wikipedia.org/wiki/Denial-of-service_attack)
* **General/Articles/Writeups/Talks**
    * [Novel session initiation protocol-based distributed denial-of-service attacks and effective defense strategies](http://www.sciencedirect.com/science/article/pii/S0167404816300980)
    * [Sockstress](https://github.com/defuse/sockstress)
        * Sockstress is a Denial of Service attack on TCP services discovered in 2008 by Jack C. Louis from Outpost24 [1]. It works by using RAW sockets to establish many TCP connections to a listening service. Because the connections are established using RAW sockets, connections are established without having to save any per-connection state on the attacker's machine. Like SYN flooding, sockstress is an asymmetric resource consumption attack: It requires very little resources (time, memory, and bandwidth) to run a sockstress attack, but uses a lot of resources on the victim's machine. Because of this asymmetry, a weak attacker (e.g. one bot behind a cable modem) can bring down a rather large web server. Unlike SYN flooding, sockstress actually completes the connections, and cannot be thwarted using SYN cookies. In the last packet of the three-way handshake a ZERO window size is advertised -- meaning that the client is unable to accept data -- forcing the victim to keep the connection alive and periodically probe the client to see if it can accept data yet. This implementation of sockstress takes the idea a little further by allowing the user to specify a payload, which will be sent along with the last packet of the three-way handshake, so in addition to opening a connection, the attacker can request a webpage, perform a DNS lookup, etc.
* **Tools**
    * [Davoset](https://github.com/MustLive/DAVOSET) 
        * DAVOSET - it is console (command line) tool for conducting DDoS attacks on the sites via Abuse of Functionality and XML External Entities vulnerabilities at other sites.
    * [beeswithmachineguns](https://github.com/newsapps/beeswithmachineguns)
        * A utility for arming (creating) many bees (micro EC2 instances) to attack (load test) targets (web applications).
    * [t50 - the fastest packet injector.](https://github.com/fredericopissarra/t50)
        * T50 was designed to perform -Stress Testing-  on a variety of infra-structure network devices (Version 2.45), using widely implemented protocols, and after some requests it was was re-designed to extend the tests (as of Version 5.3), covering some regular protocols (ICMP, TCP and UDP), some infra-structure specific protocols (GRE, IPSec and RSVP), and some routing protocols (RIP, EIGRP and OSPF).







------------
### <a name="evasion">IDS/IPS Evasion</a>
* **101**
    * [Intrusion Detection System](https://en.wikipedia.org/wiki/Intrusion_detection_system)
* **General/Articles/Writeups/Talks**
    * [Intrusion detection evasion:  How Attackers get past the burglar alarm](http://www.sans.org/reading-room/whitepapers/detection/intrusion-detection-evasion-attackers-burglar-alarm-1284)
        * The purpose of this paper is to show methods that attackers can use to fool IDS systems into thinking their attack is legitimate traffic. With techniques like obfuscation, fragmentation, Denial of Service, and application hijacking the attacker can pass traffic under the nose of an IDS to prevent their detection. These are techniques that the next generation of IDS needs to be able to account for and prevent. Since it would be almost impossible to create a product that was not vulnerable to one of these deceptions.
    * [Beating the IPS](http://www.sans.org/reading-room/whitepapers/intrusion/beating-ips-34137) 
        * This paper introduces various Intrusion Prevention System (IPS) evasion techniques and shows how they can be used to successfully evade detection by widely used products from major security vendors. By manipulating the header, payload, and traffic flow of a well-known attack, it is possible to trick the IPS inspection engines into passing the traffic - allowing the attacker shell access to the target system protected by the IPS.
    * [Firewall/IDS Evasion and Spoofing](https://nmap.org/book/man-bypass-firewalls-ids.html)
    * [IDS/IPS Evasion Techniques - Alan Neville](http://www.redbrick.dcu.ie/~anev/IDS_IPS_Evasion_Techniques.pdf)
    * [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://insecure.org/stf/secnet_ids/secnet_ids.html)http://insecure.org/stf/secnet_ids/secnet_ids.html)
    * [Evading IDS/IPS by Exploiting IPv6 Features - Antonios Atlasis, Rafael Schaefer](https://www.youtube.com/watch?v=avMeYIaU8DA&list=PL1eoQr97VfJni4_O1c3kBCCWwxu-6-lqy)
    * [Fire Away Sinking the Next Gen Firewall - Russell Butturini - Derbycon6](https://www.youtube.com/watch?v=Qpty_f0Eu7Y)
    * [Network Application Firewalls: Exploits and Defense - Brad Woodberg](https://www.youtube.com/watch?v=jgS74o-TVIw)
        * In the last few years, a so called whole new generation of firewalls have been released by various vendors, most notably Network Application Firewalling. While this technology has gained a lot of market attention, little is actually known by the general public about how it actually works, what limitations it has, and what you really need to do to ensure that you're not exposing yourself. This presentation will examine/demystify the technology, the implementation, demonstrate some of the technology and implementation specific vulnerabilities, exploits, what it can and can't do for you, and how to defend yourself against potential weaknesses.
    * [HTTP Evasions Explained - Part 6 - Attack of the White-Space](http://noxxi.de/research/http-evader-explained-6-whitespace.html)
        * This is part six in a series which will explain the evasions done by HTTP Evader. This part is about misusing white-space to bypass the firewall.
    * [Fire Away Sinking the Next Gen Firewall Russell Butturini - Derbycon6](https://www.youtube.com/watch?v=Qpty_f0Eu7Y)
    * [Passive IPS Reconnaissance and Enumeration - false positive (ab)use - Arron Finnon](https://vimeo.com/108775823)
        * Network Intrusion Prevention Systems or NIPS have been plagued by "False Positive" issues almost since their first deployment. A "False Positive" could simply be described as incorrectly or mistakenly detecting a threat that is not real. A large amount of research has gone into using "False Positive" as an attack vector either to attack the very validity of an IPS system or to conduct forms of Denial of Service attacks. However the very reaction to a "False Positive" in the first place may very well reveal more detailed information about defences than you might well think.
    * [Attacking Nextgen Firewalls](https://www.youtube.com/watch?v=ZoCf9yWC32g)
    * [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://cs.unc.edu/~fabian/course_papers/PtacekNewsham98.pdf)
    * [Covert Channels in the TCP/IP Protocol Suite](http://ojphi.org/ojs/index.php/fm/article/view/528/449)
* **Tools**
    * [wafw00f](https://github.com/sandrogauci/wafw00f) *  WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.
    * [Dalton](https://github.com/secureworks/dalton)
        * Dalton is a system that allows a user to quickly and easily run network packet captures ("pcaps") against an intrusion detection system ("IDS") sensor of his choice (e.g. Snort, Suricata) using defined rulesets and/or bespoke rules.
    * [Fireaway](https://github.com/tcstool/Fireaway)
        * Fireaway is a tool for auditing, bypassing, and exfiltrating data against layer 7/AppID inspection rules on next generation firewalls, as well as other deep packet inspection defense mechanisms, such as data loss prevention (DLP) and application aware proxies. These tactics are based on the principle of having to allow connections to establish through the NGFW in order to see layer 7 data to filter, as well as spoofing applications to hide communication channels inside the firewall logs as normal user traffic, such as Internet surfing. In the case of bypassing data loss prevention tools, Fireaway sends data in small "chunks", which do not match regular expression triggers and other DLP rules, as well as embedding data in spoofed HTTP headers of legitimate applications which most data loss prevention technologies are not designed to inspect. The tool also has had success defeating anomaly detection and heursitics engines through its ability to spoof application headers and hide data inside them.













------------------------------------------------------------------------------------------------------------------
### <a name="ipobf"></a>IP Obfuscation
* **Tools**
    * [IPFuscator](https://github.com/vysec/IPFuscator)
        * IPFuscation is a technique that allows for IP addresses to be represented in hexadecimal or decimal instead of the decimal encoding we are used to. IPFuscator allows us to easily convert to these alternative formats that are interpreted in the same way.
        * [Blogpost](https://vincentyiu.co.uk/ipfuscation/)
    * [Cuteit](https://github.com/D4Vinci/Cuteit)
        * A simple python tool to help you to social engineer, bypass whitelisting firewalls, potentially break regex rules for command line logging looking for IP addresses and obfuscate cleartext strings to C2 locations within the payload.
    * [IP Obfuscator](https://stuff.soumikghosh.com/ipobfuscator/)
        * Simple site to obfuscate IPs


------------
### <a name="ipspoofing"></a>IP Spoofing
* [State of IP Spoofing](https://spoofer.caida.org/summary.php)



-----------------------
### <a name="mitm"></a>MitM Tools
* **General/Suites of tools**
    * [Dsniff](http://www.monkey.org/~dugsong/dsniff/)
        * dsniff is a collection of tools for network auditing and penetration testing. dsniff, filesnarf, mailsnarf, msgsnarf, urlsnarf, and webspy passively monitor a network for interesting data (passwords, e-mail, files, etc.). arpspoof, dnsspoof, and macof facilitate the interception of network traffic normally unavailable to an attacker (e.g, due to layer-2 switching). sshmitm and webmitm implement active monkey-in-the-middle attacks against redirected SSH and HTTPS sessions by exploiting weak bindings in ad-hoc PKI. 
    * [Ettercap](https://ettercap.github.io/ettercap/)
        * Ettercap is a comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.
    * [striptls - auditing proxy](https://github.com/tintinweb/striptls)
        * A generic tcp proxy implementation and audit tool to perform protocol independent ssl/tls interception and STARTTLS stripping attacks on SMTP, POP3, IMAP, FTP, NNTP, XMPP, ACAP and IRC.
    * [BackDoor Factory](https://github.com/secretsquirrel/the-backdoor-factory)
        * The goal of BDF is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state.
        * [Wiki](https://github.com/secretsquirrel/the-backdoor-factory/wiki)
        * [Video](http://www.youtube.com/watch?v=jXLb2RNX5xs)
    * [Man-in-the-Middle Framework](https://github.com/byt3bl33d3r/MITMf)
        * Framework for Man-In-The-Middle attacks
    * [Xeroxsploit](https://github.com/LionSec/xerosploit)
        * Xerosploit is a penetration testing toolkit whose goal is to perform man in the middle attacks for testing purposes. It brings various modules that allow to realise efficient attacks, and also allows to carry out denial of service attacks and port scanning. Powered by bettercap and nmap.
    * [bettercap](https://github.com/evilsocket/bettercap) 
        * A complete, modular, portable and easily extensible MITM framework. 
        * [Elbsides 2019 Workshop](https://github.com/ceicke/bettercap-elbsides)
            * This repository holds stuff which might be useful to the participants of the Bettercap workshop on the Elbsides 2019.
    * [NetRipper](https://github.com/NytroRST/NetRipper)
        * NetRipper is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.
    * [An Auditing Tool for Wi-Fi or Wired Ethernet Connections - Matthew Sullivan](https://www.cookiecadger.com/wp-content/uploads/Cookie%20Cadger.pdf)
    * [Polymorph](https://github.com/shramos/polymorph)
        * Polymorph is a framework written in Python 3 that allows the modification of network packets in real time, providing maximum control to the user over the contents of the packet. This framework is intended to provide an effective solution for real-time modification of network packets that implement practically any existing protocol, including private protocols that do not have a public specification. In addition to this, one of its main objectives is to provide the user with the maximum possible control over the contents of the packet and with the ability to perform complex processing on this information.
* **DNS**
    * [FakeDNS](https://github.com/Crypt0s/FakeDns)
        * A regular-expression based python MITM DNS server with support for DNS Rebinding attacks
    * [CopyCat](https://github.com/compewter/CopyCat)
        * CopyCat is a Node.js based universal MITM web server. Used with DNS spoofing or another redirect attack, this server will act as a MITM for web traffic between the victim and a real server.
* **Dumping from an interface**
    * [net-creds](https://github.com/DanMcInerney/net-creds)
        * Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification. It sniffs: URLs visited; POST loads sent; HTTP form logins/passwords; HTTP basic auth logins/passwords; HTTP searches; FTP logins/passwords; IRC logins/passwords; POP logins/passwords; IMAP logins/passwords; Telnet logins/passwords; SMTP logins/passwords; SNMP community string; NTLMv1/v2 all supported protocols like HTTP, SMB, LDAP, etc; Kerberos.
    * [pcredz](https://github.com/lgandx/PCredz)
        * This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
* **HTTP**
    * [Injectify](https://github.com/samdenty99/injectify)
        * Perform advanced MiTM attacks on websites with ease.
    * [node-http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy)
        * HTTP Man In The Middle (MITM) Proxy written in node.js. Supports capturing and modifying the request and response data.
    * [hyperfox](https://github.com/malfunkt/hyperfox)
        * HTTP/HTTPs MITM proxy and traffic recorder with on-the-fly TLS cert generation. 
    * [warcproxy](https://github.com/internetarchive/warcprox)
        * WARC writing MITM HTTP/S proxy
* **IPv6**
    * [suddensix](https://github.com/Neohapsis/suddensix)
        * IPV6 MITM attack tool
* **Local**
    * [Datajack Proxy](https://github.com/nccgroup/DatajackProxy)
        * Datajack Proxy a tool to intercept non-HTTP traffic between a native application and a server. This would allow for communications interception and modification, even if encryption and certificate pinning were in use. This is done by hooking the application and intercepting calls to common socket and TLS libraries, and reading the data prior to encryption (for outbound) and after decryption (for inbound).
        * [Blogpost](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/august/datajack-proxy-intercepting-tls-in-native-applications/)
    * [Trudy](https://github.com/praetorian-code/trudy)
        * Trudy is a transparent proxy that can modify and drop traffic for arbitrary TCP connections. Trudy can be used to programmatically modify TCP traffic for proxy-unaware clients. Trudy creates a 2-way "pipe" for each connection it proxies. The device you are proxying (the "client") connects to Trudy (but doesn't know this) and Trudy connects to the client's intended destination (the "server"). Traffic is then passed between these pipes. Users can create Go functions to mangle data between pipes. See it in action! For a practical overview, check out @tsusanka's very good blog post on using Trudy to analyze Telegram's MTProto. Trudy can also proxy TLS connections. Obviously, you will need a valid certificate or a client that does not validate certificates. Trudy was designed for monitoring and modifying proxy-unaware devices that use non-HTTP protocols. If you want to monitor, intercept, and modify HTTP traffic, Burp Suite is probably the better option.
* **Maven**
    * [Dilettante](https://github.com/mveytsman/dilettante)
        * Maven central doesn't do SSL when serving you JARs. Dilettante is a MiTM proxy for exploiting that.
* **RDP**
    * [Seth](https://github.com/SySS-Research/Seth)
        * Seth is a tool written in Python and Bash to MitM RDP connections. It attempts to downgrade the connection and extract clear text credentials.
* **NTLM/SMB/NTBS**
    * [NTLMssp-Extract](https://github.com/sinnaj-r/NTLMssp-Extract)
        * A small Python-Script to extract NetNTLMv2 Hashes from NTMLssp-HTTP-Authentications, which were captured in a pcap.
    * [ntlmRelayToEWS](https://github.com/Arno0x/NtlmRelayToEWS)
        * ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS). It spawns an SMBListener on port 445 and an HTTPListener on port 80, waiting for incoming connection from the victim. Once the victim connects to one of the listeners, an NTLM negociation occurs and is relayed to the target EWS server.
    * [CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494)
        * Remote root exploit for the SAMBA CVE-2017-7494 vulnerability
* **Postgres**
    * [postgres-mitm](https://github.com/thusoy/postgres-mitm)
        * Test whether your Postgres connections are vulnerable to MitM attacks.
* **SSH**
    * [ssh-mitm](https://github.com/jtesta/ssh-mitm)
        * This penetration testing tool allows an auditor to intercept SSH connections. A patch applied to the OpenSSH v7.5p1 source code causes it to act as a proxy between the victim and their intended SSH server; all plaintext passwords and sessions are logged to disk.
* **SSL/TLS**
    * [SSLsplit - transparent and scalable SSL/TLS interception](https://www.roe.ch/SSLsplit)
        * SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit. SSLsplit terminates SSL/TLS and initiates a new SSL/TLS connection to the original destination address, while logging all data transmitted. SSLsplit is intended to be useful for network forensics and penetration testing.  SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6.
    * [SSLStrip](http://www.thoughtcrime.org/software/sslstrip/)
        * This tool provides a demonstration of the HTTPS stripping attacks that I presented at Black Hat DC 2009. It will transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.
    * [tiny-mitm-proxy](https://github.com/floyd-fuh/tiny-mitm-proxy)
        * Probably one of the smallest SSL MITM proxies you can make
* **WSUS(Windows Server Updater Serice)**
    * [WSUXploit](https://github.com/pimps/wsuxploit)
        * This is a MiTM weaponized exploit script to inject 'fake' updates into non-SSL WSUS traffic. It is based on the WSUSpect Proxy application that was introduced to public on the Black Hat USA 2015 presentation, 'WSUSpect - Compromising the Windows Enterprise via Windows Update'
    * [WSUSpect Proxy](https://github.com/pdjstone/wsuspect-proxy)
        * This is a proof of concept script to inject 'fake' updates into non-SSL WSUS traffic. It is based on the BlackHat USA 2015 presentation, 'WSUSpect – Compromising the Windows Enterprise via Windows Update'
        - White paper: http://www.contextis.com/documents/161/CTX_WSUSpect_White_Paper.pdf
        - Slides: http://www.contextis.com/documents/162/WSUSpect_Presentation.pdf




















------------
#### <a name="host"></a>Network Host Discovery/Service Discovery:
* **Educational/Informational**
    * **Articles/Blogposts/Writeups**
        * [Port scanning without an IP address - DiabloHorn](https://diablohorn.com/2017/10/26/port-scanning-without-an-ip-address/)
        * [They see me scannin'; they hatin'](http://blog.bonsaiviking.com/2015/07/they-see-me-scannin-they-hatin.html)
        * [They see me scannin' (part 2)](http://blog.bonsaiviking.com/2015/07/they-see-me-scannin-part-2.html)
        * [Inspecting Remote Network Topography by Monitoring Response Time-To-Live](http://howto.hackallthethings.com/2015/04/inspecting-remote-network-topography-by.html)
        * [Saving Polar Bears When Banner Grabbing](http://blog.ioactive.com/2015/07/saving-polar-bears-when-banner-grabbing.html)
        * [fragroute](https://www.monkey.org/~dugsong/fragroute/fragroute.8.txt)
        * [Ask and you shall receive (Part 2)](https://securityhorror.blogspot.com/2012/07/ask-and-you-shall-receive-part-2.html)
    * **Talks/Presentations/Videos**
        * [Mass Scanning the Internet: Tips, Tricks, Results - DEF CON 22 - Graham, Mcmillan, and Tentler](https://www.youtube.com/watch?v=nX9JXI4l3-E)
        * [Post Exploitation: Striking Gold with Covert Recon - Derek Rook(WWHF19)](https://www.youtube.com/watch?v=04H1s9z0JDo)
            * You're on a covert penetration test focusing on the client's monitoring and alerting capabilities. You've just established a foothold, maybe even elevated to admin, but now what? You want to know more about the internal network but careless packet slinging will get you caught. Join me on a mining expedition where you can't swing your pick axe without striking gold. We'll be mining logs, pilfering connection statistics, and claim jumping process network connections. Without leaving the comfort of your beachhead, you'll be shouting "Eureka!" in no time.
    * **Nmap Related**
        * [Nmap XML Parser Documentation](https://nmap-parser.readthedocs.io/en/latest/)
        * [Nmap you’re doing it wrong - sneakerhax](https://sneakerhax.com/nmap-yourre-doing-it-wrong/)
        * [Recon at scale - sneakerhax](https://sneakerhax.com/recon-at-scale/)
        * [Nmap Reference Guide](https://nmap.org/book/man.html)
        * [Security.StackExchange Answer detailing Nmap Scanning tips and tactics - very good](https://security.stackexchange.com/questions/373/open-source-penetration-test-automation/82529#82529)
        * [Massively Scaling your Scanning - SANS](https://pen-testing.sans.org/blog/2017/10/25/massively-scaling-your-scanning)
        * [StackOverflow Post on Scanning](https://security.stackexchange.com/questions/373/open-source-penetration-test-automation/82529#82529)
        * [Got slow portscans on CTF’s? - reedphish](https://reedphish.wordpress.com/2018/08/02/got-slow-portscans-on-ctfs/)
* **Detecting Honeypots**
    * [CSRecon - Censys and Shodan Reconnasiance Tool](https://github.com/markclayton/csrecon)
    * [ICS Honeypot Detection using Shodan](https://asciinema.org/a/38992)
    * [Honeypot Or Not? - shodanhq](https://honeyscore.shodan.io/)
* **Distributed Scanning**
        * **Articles/Blogposts/Writeups/Papers**
        * **Tools**
            * [Natlas](https://github.com/natlas/natlas)
                * You've got a lot of maps and they are getting pretty unruly. What do you do? You put them in a book and call it an atlas. This is like that, except it's a website and it's a collection of nmaps. The Natlas server doubles as a task manager for the agents to get work, allowing you to control the scanning scope in one centralized place.
            * [Scantron](https://github.com/rackerlabs/scantron)
                * Scantron is a distributed nmap and masscan scanner comprised of two components. The first is a Master node that consists of a web front end used for scheduling scans and storing nmap scan targets and results. The second component is an agent that pulls scan jobs from Master and conducts the actual nmap scanning. A majority of the application's logic is purposely placed on Master to make the agent(s) as "dumb" as possible. All nmap target files and nmap results reside on Master and are shared through a network file share (NFS) leveraging SSH tunnels. The agents call back to Master periodically using a REST API to check for scan tasks and provide scan status updates.
                * [Blogpost(2018)](https://developer.rackspace.com/blog/scantron-a-distributed-nmap-scanner/)
* **Tools**
    * **Nmap**
        * [Nmap](http://nmap.org/)
            * Nmap ("Network Mapper") is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping). 
        * [WebMap](https://github.com/Rev3rseSecurity/WebMap/blob/v2/master/README.md)
            * Nmap Web Dashboard and Reporting
        * **Articles/Papers**
            * [NMAP - Port-Scanning: A Practical Approach Modified for better](https://www.exploit-db.com/papers/35425/)
            * [NSEInfo](https://github.com/christophetd/nmap-nse-info/blob/master/README.md)
                * NSEInfo is a tool to interactively search through nmap's NSE scripts.
            * [Nmap (XML) Parser documentation](https://nmap-parser.readthedocs.io/en/latest/)
            * [Scanning Effectively Through a SOCKS Pivot with Nmap and Proxychains](https://cybersyndicates.com/2015/12/nmap-and-proxychains-scanning-through-a-socks-piviot/)
                * [Script](https://github.com/killswitch-GUI/PenTesting-Scripts/blob/master/Proxychains-Nmap.py)
        * **NSE**
            * [Chapter 9. Nmap Scripting Engine - Nmap book](https://nmap.org/book/nse.html)
            * [Script Writing Tutorial - Nmap Book](https://nmap.org/book/nse-tutorial.html)
            * [Writing NMAP Scripts Like A Super-Hero - Peter Benjamin](https://medium.com/@petermbenjamin/writing-nmap-scripts-like-a-super-hero-e4b0dc4c782)
            * [Nmap Script Writing Tutorial - nmap.org](https://nmap.org/book/nse-tutorial.html)
            * [NSE Scripts – More Than Scanning - Paula ](https://cqureacademy.com/blog/penetration-testing/nse-scripts)
            * [Extending Nmap With Lua - citizen428](https://citizen428.net/blog/extending-nmap-with-lua/)
        * **Scripts**
            * [Official NSE Repo](https://github.com/nmap/nmap/tree/master/scripts)
            * [raikia-screenshot.nse](https://github.com/Raikia/Nmap-scripts)
                * This nmap script will take a screenshot of http[s]://ip:port, as well as http[s]://hostname:port AND https://sslcert_name:port. This differs from other screenshot nmap utilities because it will allow javascript execution, and it will have a timeout on the screenshot request, so the scan won't hang.
            * [ms15-034.nse Script](https://github.com/pr4jwal/quick-scripts/blob/master/ms15-034.nse)
            * [nmap-nse-scripts - cldrn](https://github.com/cldrn/nmap-nse-scripts)
            * [nse-scripts - b4ldr](https://github.com/b4ldr/nse-scripts)
            * [nmap-nse-scripts - hackertarget](https://github.com/hackertarget/nmap-nse-scripts)
            * [nse - aerissecure](https://github.com/aerissecure/nse)
            * [Nmap Elasticsearch NSE - theMiddleBlue](https://github.com/theMiddleBlue/nmap-elasticsearch-nse)
                * Nmap NSE script for enumerate indices, plugins and cluster nodes on an elasticsearch target
            * [hassh-utils](https://github.com/0x4D31/hassh-utils)
                * Nmap NSE Script and Docker image for HASSH - the SSH client/server fingerprinting method
                * [Relevant Blogpost](https://dmfrsecurity.com/2019/10/29/nmap-hassh-3/)
        * **Manipulating the Scan Data**
            * [nmapdb - Parse nmap's XML output files and insert them into an SQLite database](https://census.gr/research/sw/nmapdb/)
                * nmapdb parses nmap's XML output files and inserts them into an SQLite database.
                * [NmapDB](https://github.com/mainframed/nmapdb)
            * [Nmap-Scan-to-CSV](https://github.com/laconicwolf/Nmap-Scan-to-CSV)
                * Converts Nmap XML output to csv file, and other useful functions
            * [nmapautoanalyzer.rb - raesene](https://github.com/raesene/TestingScripts/blob/master/nmapautoanalyzer.rb)
                * This script is designed to co-ordinate parsing of nmap xml files and production of a concise report, just listing ports that are open on hosts, with whatever supplementary information nmap provide about them (service, product name, reason nmap thinks the port is open).
            * [Gnmap-Parser](https://github.com/ChrisTruncer/gnmap-parser)
                * Gnmap-Parser takes multiple Nmap scans exported in greppable (.gnmap) format and parses them into various types of plain-text files for easy analysis.
        * **Storing/Parsing the scan data**
            * [Offensive ELK: Elasticsearch for Offensive Security - Marco Lancini](https://www.marcolancini.it/2018/blog-elk-for-nmap/)
            * [Using Nmap + Logstash to Gain Insight Into Your Network - Andrew Cholakian(2016)](https://www.elastic.co/blog/using-nmap-logstash-to-gain-insight-into-your-network)
                * In this post we'll look at a brand new logstash codec plugin: logstash-codec-nmap. This plugin lets you directly import Nmap scan results into Elasticsearch where you can then visualize them with Kibana. Nmap is somewhat hard to describe because its a sort of swiss army knife of network tools. It crams many different features into a single small executable. I've put together a small list of things you can do with Nmap below, though it is by no means complete!
            * [How to Index NMAP Port Scan Results into Elasticsearch - Adam Vanderbush](https://qbox.io/blog/how-to-index-nmap-port-scan-results-into-elasticsearch)
        * **Helpful Tools**
            * [pentest-machine](https://github.com/DanMcInerney/pentest-machine)
                * Automates some pentest jobs via nmap xml file
            * [Autorecon](https://github.com/Tib3rius/AutoRecon)
                * AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services. It is intended as a time-saving tool for use in CTFs and other penetration testing environments (e.g. OSCP). It may also be useful in real-world engagements. The tool works by firstly performing port scans / service detection scans. From those initial results, the tool will launch further enumeration scans of those services using a number of different tools. For example, if HTTP is found, nikto will be launched (as well as many others).
            * [Raccoon](https://github.com/evyatarmeged/Raccoon)
                * Raccoon is a tool made for reconnaissance and information gathering with an emphasis on simplicity. It will do everything from fetching DNS records, retrieving WHOIS information, obtaining TLS data, detecting WAF presence and up to threaded dir busting and subdomain enumeration. Every scan outputs to a corresponding file. As most of Raccoon's scans are independent and do not rely on each other's results, it utilizes Python's asyncio to run most scans asynchronously.
    * **Firewall**
        * [Firewalk](http://packetfactory.openwall.net/projects/firewalk/)
            * Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a  given IP forwarding device will pass. Firewalk  works  by sending out TCP or UDP packets with a TTL one greater than the targeted gateway.  If the gateway allows the traffic, it will forward the packets to the next hop where they will expire and elicit an ICMP_TIME_EXCEEDED  message.  If the gateway hostdoes not allow the traffic, it will likely drop the packets on  the floor and we will see no response. To get  the  correct  IP  TTL that will result in expired packets one beyond the gateway we need  to  ramp  up  hop-counts.   We  do  this  in the same manner that traceroute works.  Once we have the gateway hopcount (at  that point the scan is said to be `bound`) we can begin our scan.
        * [Fireaway](https://github.com/tcstool/Fireaway)
            * Fireaway is a tool for auditing, bypassing, and exfiltrating data against layer 7/AppID inspection rules on next generation firewalls, as well as other deep packet inspection defense mechanisms, such as data loss prevention (DLP) and application aware proxies. These tactics are based on the principle of having to allow connections to establish through the NGFW in order to see layer 7 data to filter, as well as spoofing applications to hide communication channels inside the firewall logs as normal user traffic, such as Internet surfing. In the case of bypassing data loss prevention tools, Fireaway sends data in small "chunks", which do not match regular expression triggers and other DLP rules, as well as embedding data in spoofed HTTP headers of legitimate applications which most data loss prevention technologies are not designed to inspect.
    * **Load-Balancers**
        * [halberd](https://github.com/jmbr/halberd)
            * Load balancer detection tool
    * **MassScan**
        * **Articles/Blogposts/Writeups**
            * [Ever wanted to scan the internet in a few hours?](http://blog.erratasec.com/2013/10/faq-from-where-can-i-scan-internet.html)
            * [Adding your protocol to Masscan](http://blog.erratasec.com/2014/11/adding-protocols-to-masscan.html)
        * **Talks/Presentations/Videos**
        * **Tools**
            * [ScanCannon](https://github.com/johnnyxmas/ScanCannon)
                * The speed of masscan with the reliability and detailed enumeration of nmap!
    * **Other IP Scanners**
        * [polarbearscan](http://santarago.org/pbscan.html)
            * polarbearscan is an attempt to do faster and more efficient banner grabbing and port scanning. It combines two different ideas which hopefully will make it somewhat worthy of your attention and time.  The first of these ideas is to use stateless SYN scanning using cryptographically protected cookies to parse incoming acknowledgements. To the best of the author's knowledge this technique was pioneered by Dan Kaminsky in scanrand. Scanrand was itself part of Paketto Keiretsu, a collection of scanning utilities, and it was released somewhere in 2001-2002. A mirror of this code can be found at Packet Storm. The second idea is use a patched userland TCP/IP stack such that the scanner can restore state immediately upon receiving a cryptographically verified packet with both the SYN and ACK flags set. The userland stack being used here by polarbearscan is called libuinet[2](http://wanproxy.org/libuinet.shtml). Unlike some of the other userland TCP/IP stacks out there this one is very mature as it's simply a port of FreeBSD's TCP/IP stack. By patching the libuinet stack one can then construct a socket and complete the standard TCP 3-way handshake by replying with a proper ACK. Doing it this way a fully functional TCP connection is immediately established. This as opposed to other scanners (such as nmap) who would have to, after noting that a TCP port is open, now perform a full TCP connect via the kernel to do things such as banner grabbing or version scanning. A full TCP connect leads to a whole new TCP 3-way handshake being performed. This completely discards the implicit state which was built up by the initial two packets being exchanged between the hosts. By avoiding this one can reduce bandwidth usage and immediately go from detecting that a port is open to connecting to it. This connection can then simply sit back and receive data in banner grab mode or it could send out an HTTP request.
        * [Angry IP Scanner](http://angryip.org/)
            * Angry IP Scanner (or simply ipscan) is an open-source and cross-platform network scanner designed to be fast and simple to use. It scans IP addresses and ports as well as has many other features.
        * [UnicornScan](http://www.unicornscan.org/)
            * Unicornscan is a new information gathering and correlation engine built for and by members of the security research and testing communities. It was designed to provide an engine that is Scalable, Accurate, Flexible, and Efficient. It is released for the community to use under the terms of the GPL license. 
            * Editor note: Use this to mass scan networks. It-s faster than nmap at scanning large host lists and allows you to see live hosts quickly.
        * [hping](http://www.hping.org/)
            * hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface is inspired to the ping(8) unix command, but hping isn't only able to send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode, the ability to send files between a covered channel, and many other features.
        * [fi6s](https://github.com/sfan5/fi6s)
            * fi6s is an IPv6 port scanner designed to be fast. This is achieved by sending and processing raw packets asynchronously. The design and goal is pretty similar to Masscan, though it is not as full-featured yet.
    * **Other**
        * [ttl-monitor](https://github.com/hack-all-the-things/ttl-monitor)
            * A TTL monitor utility for identifying route changes, port forwards, intrusion responses, and more
        * [Layer Four Traceroute (LFT) and WhoB](http://pwhois.org/lft/)
            * The alternative traceroute and whois tools for network (reverse) engineers
        * [gateway-finder](https://github.com/pentestmonkey/gateway-finder)
            * Gateway-finder is a scapy script that will help you determine which of the systems on the local LAN has IP forwarding enabled and which can reach the Internet.
        * [Consul](https://github.com/hashicorp/consul)
            * Consul is a tool for service discovery and configuration. Consul is distributed, highly available, and extremely scalable.
        * [GTScan](https://github.com/SigPloiter/GTScan)
            * The Nmap Scanner for Telco. With the current focus on telecom security, there used tools in day to day IT side penetration testing should be extended to telecom as well. From here came the motivation for an nmap-like scanner but for telco. The current security interconnect security controls might fail against reconnaissance, although mobile operators might implement SMS firewalls/proxies, Interconnect firewalls, some of those leak information that could be used for further information gathering process. The motivation behind this project, first adding a new toolking into the arsenal of telecom penetration testers. Second give the mobile operators a way to test their controls to a primitive methodology such as information gathering and reconnaissance.
* **Tor**
    * [exitmap](https://github.com/NullHypothesis/exitmap)
        * A fast and modular scanner for Tor exit relays. http://www.cs.kau.se/philwint/spoiled_onions/ 
    * [OnionScan](https://github.com/s-rah/onionscan)
        * [What OnionScan Scans for](https://github.com/s-rah/onionscan/blob/master/doc/what-is-scanned-for.md)
* **VHost Scanning**
    * **Articles/Blogposts/Writeups**
        * [Virtual host and DNS names enumeration techniques](https://jekil.sexy/blog/2009/virtual-host-and-dns-names-enumeration-techniques.html)
    * **Tools**
        * [hostmap](https://github.com/jekil/hostmap)
            * hostmap is a free, automatic, hostnames and virtual hosts discovery tool written in Ruby by Alessandro Tanasi
        * [blacksheepwall](https://github.com/tomsteele/blacksheepwall)
            * blacksheepwall is a hostname reconnaissance tool written in Go. It can also be used as a stand-alone package in your tools.
        * [gobuster](https://github.com/OJ/gobuster)
* **Cloudflare**
    * [CloudFail](https://github.com/m0rtem/CloudFail)
        * CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by CloudFlare in the hopes of discovering the location of the server.
    * [HatCloud](https://github.com/HatBashBR/HatCloud)
        * HatCloud build in Ruby. It makes bypass in CloudFlare for discover real IP. This can be useful if you need test your server and website. Testing your protection against Ddos (Denial of Service) or Dos. CloudFlare is services and distributed domain name server services, sitting between the visitor and the Cloudflare user's hosting provider, acting as a reverse proxy for websites. Your network protects, speeds up and improves availability for a website or the mobile application with a DNS change.
    * [CloudFire](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/cfire)
        * This project focuses on discovering potential IP's leaking from behind cloud-proxied services, e.g. Cloudflare. Although there are many ways to tackle this task, we are focusing right now on CrimeFlare database lookups, search engine scraping and other enumeration techniques.
* **Cisco**
    * [CiscoRouter - tool](https://github.com/ajohnston9/ciscorouter)
        * CiscoRouter is a tool for scanning Cisco-based routers over SSH. Rules can be created using accompanying CiscoRule application (see this repo) and stored in the "rules" directory.
    * [discover - Kali Scripts](https://github.com/leebaird/discover)
        * For use with Kali Linux - custom bash scripts used to automate various portions of a pentest.
    * [changeme - A default credential scanner.](https://github.com/ztgrace/changeme)
        * changeme picks up where commercial scanners leave off. It focuses on detecting default and backdoor credentials and not necessarily common credentials. It's default mode is to scan HTTP default credentials, but has support for other credentials. changeme is designed to be simple to add new credentials without having to write any code or modules. changeme keeps credential data separate from code. All credentials are stored in yaml files so they can be both easily read by humans and processed by changeme. Credential files can be created by using the ./changeme.py --mkcred tool and answering a few questions. changeme supports the http/https, mssql, mysql, postgres, ssh, ssh w/key, snmp, mongodb and ftp protocols. Use ./changeme.py --dump to output all of the currently available credentials.
    * [RANCID - Really Awesome New Cisco confIg Differ](http://www.shrubbery.net/rancid/)
        * RANCID monitors a router's (or more generally a device's) configuration, including software and hardware (cards, serial numbers, etc) and uses CVS (Concurrent Version System) or Subversion to maintain history of changes. RANCID does this by the very simple process summarized as: login to each device in the router table (router.db), run various commands to get the information that will be saved, cook the output; re-format, remove oscillating or incrementing data, email any differences (sample) from the previous collection to a mail list, and finally commit those changes to the revision control system
    * [SIET Smart Install Exploitation Toolkit](https://github.com/Sab0tag3d/SIET)
        * Cisco Smart Install is a plug-and-play configuration and image-management feature that provides zero-touch deployment for new switches. You can ship a switch to a location, place it in the network and power it on with no configuration required on the device.
* **Misc**
    * [scanless](https://github.com/vesche/scanless)
        * Command-line utility for using websites that can perform port scans on your behalf. Useful for early stages of a penetration test or if you'd like to run a port scan on a host and have it not come from your IP address.
    * [device-pharmer](https://github.com/DanMcInerney/device-pharmer)
        * Opens 1K+ IPs or Shodan search results and attempts to login 
    * [Sn1per](https://github.com/1N3/Sn1per)
        * Sn1per is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities.
    * [metasploitHelper](https://github.com/milo2012/metasploitHelper)
        * metasploitHelper (msfHelper) communicates with Metasploit via msrpc. It uses both port and web related exploits from Metasploit. You can point msfHelper at an IP address/Nmap XML file/File containing list of Ip addresses. First, it performs a Nmap scan of the target host(s) and then attempt to find compatible and possible Metasploit modules based on 1) nmap service banner and 2) service name and run them against the targets.
        * [Slides](https://docs.google.com/presentation/d/1No9K1OsuYy5mDP0FmRzb2fNWeuyyq2R41N0p7qu8r_0/edit#slide=id.g20261039dc_2_48)


------------
### <a name="pivot"></a>Pivoting
* Look at the Pivoting section in Post Exploitation/Privilege Escalation


---------------------------
### <a name="vendor"></a> Vendor Specific Stuff
* **Non-Specific**
    * [Vendor/Ethernet/Bluetooth MAC Address Lookup and Search - coffer.com](http://www.coffer.com/mac_find/)
    * [IP Cameras Default Passwords Directory](https://ipvm.com/reports/ip-cameras-default-passwords-directory)
* **Cisco**
    * [CVE-2016-6366](https://github.com/RiskSense-Ops/CVE-2016-6366/blob/master/README.md)
        * Public repository for improvements to the EXTRABACON exploit, a remote code execution for Cisco ASA written by the Equation Group (NSA) and leaked by the Shadow Brokers.
* **F5**
    * [BigIP Security - dnkolegov](https://github.com/dnkolegov/bigipsecurity/blob/master/README.md)
        * This document describes common misconfigurations of F5 Networks BigIP systems.
* **IBM**
    * [Domi-Owned](https://github.com/coldfusion39/domi-owned)
        * Domi-Owned is a tool used for compromising IBM/Lotus Domino servers. Tested on IBM/Lotus Domino 8.5.2, 8.5.3, 9.0.0, and 9.0.1 running on Windows and Linux.



* **Distributed Systems**
    * [Garfield](https://github.com/tunnelshade/garfield)
        * Garfield is and open source framework for scanning and exploiting Distributed Systems. The framework currently being in it's alpha stage and is undergoing rapid development.
* [IVRE](https://github.com/cea-sec/ivre)
    * IVRE (Instrument de veille sur les réseaux extérieurs) or DRUNK (Dynamic Recon of UNKnown networks) is a network recon framework, including tools for passive recon (flow analytics relying on Bro, Argus, Nfdump, fingerprint analytics based on Bro and p0f and active recon (IVRE uses Nmap to run scans, can use ZMap as a pre-scanner; IVRE can also import XML output from Nmap and Masscan).
    http://www.pentest-standard.org/index.php/Intelligence_Gathering






------------------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------------------------------------
## <a name="tech"></a>Technologies

------------------------------------------------------------------------------------------------------------------------------------
### <a name="8021x"></a> 802.1x & NAC(Netork Access Control)
* **101**
    * [Network Access Control - Wikipedia](https://en.wikipedia.org/wiki/Network_Access_Control)
    * [IEEE 802.1x - Wikipedia](https://en.wikipedia.org/wiki/IEEE_802.1X)
        * IEEE 802.1X is an IEEE Standard for port-based Network Access Control (PNAC). It is part of the IEEE 802.1 group of networking protocols. It provides an authentication mechanism to devices wishing to attach to a LAN or WLAN. IEEE 802.1X defines the encapsulation of the Extensible Authentication Protocol (EAP) over IEEE 802, which is known as "EAP over LAN" or EAPOL. EAPOL was originally designed for IEEE 802.3 Ethernet in 802.1X-2001, but was clarified to suit other IEEE 802 LAN technologies such as IEEE 802.11 wireless and Fiber Distributed Data Interface (ISO 9314-2) in 802.1X-2004. The EAPOL was also modified for use with IEEE 802.1AE ("MACsec") and IEEE 802.1AR (Secure Device Identity, DevID) in 802.1X-2010 to support service identification and optional point to point encryption over the internal LAN segment. 
    * [802.1X: Port-Based Network Access Control](https://1.ieee802.org/security/802-1x/)
    * [Network Access Control: What's Important To Remember With NAC? - Dominik Altermatt](https://www.scip.ch/en/?labs.20180222)
* **Articles/Blogposts/Writeups**
    * [Bypass NAC(Network Access Control) - inc0byte](https://incogbyte.github.io/bypass_nac/)
    * [Bypassing NAC a Handy How-To Guide - Michael Schneider](https://www.scip.ch/en/?labs.20190207)
    * [Bypassing NAC Captive Portals - 0Katz](https://blog.0katz.ca/bypassing_nac.html)
    * [Case Study – NAC bypass & ARP spoofing - Lifars](https://lifars.com/wp-content/uploads/2020/02/case-study-NAC-Bypass-and-ARP-Spoofing.pdf)
    * [NAC-Hacking – Bypassing Network Access Control - Suraj Prakash](https://resources.infosecinstitute.com/nac-hacking-bypassing-network-access-control/)
    * [Bypassing Gogo’s Inflight Internet Authentication - Bryce Boe](https://bryceboe.com/2012/03/12/bypassing-gogos-inflight-internet-authentication/)
* **Presentations/Talks/Videos**
    * [Bypassing NAC v2.0 - Ofir Arkin(BHUSA07)](https://www.blackhat.com/presentations/bh-dc-07/Arkin/Presentation/bh-dc-07-Arkin-ppt-up.pdf)
    * [802.1x NAC & Bypass Techniques - Valerian Legrand(Hack in Paris 2017)](https://hackinparis.com/data/slides/2017/2017_Legrand_Valerian_802.1x_Network_Access_Control_and_Bypass_Techniques.pdf)
    * [Bypassing nac solutions and mitigations - Suraj Khetani](https://www.slideshare.net/funkyfreestyler/bypassing-nac-solutions-and-mitigations)
* **Tools**
    * [nac_bypass](https://github.com/scipag/nac_bypass)
        * Script collection to bypass Network Access Control (NAC, 802.1x)
    * [Tapping 802.1x Links with Marvin - abb(2011)](https://www.gremwell.com/marvin-mitm-tapping-dot1x-links)
    * [PacketFence](https://packetfence.org/)
        * PacketFence is a fully supported, trusted, Free and Open Source network access control (NAC) solution. Boasting an impressive feature set including a captive-portal for registration and remediation, centralized wired, wireless and VPN management, industry-leading BYOD capabilities, 802.1X and RBAC support, integrated network anomaly detection with layer-2 isolation of problematic devices; PacketFence can be used to effectively secure small to very large heterogeneous networks.



------------
### <a name="captive-portal"></a>Captive Portals
* **101**
    * [IETF RFC 7710: Captive-Portal Identification Using DHCP or Router Advertisements (RAs)](https://tools.ietf.org/html/rfc7710)
* **Educational**
* **Attacking**
    * **Articles/Blogposts/Writeups**
        * [CAPTIVE PORTAL: The Definitive Guide - rootsh3ll(2019)](https://rootsh3ll.com/captive-portal-guide/)
        * [Bypassing Wireless Captive Portals - jreppiks(2020)](https://jreppiks.github.io/pentest/wireless/bypass/2020/02/13/BypassingWirelessCaptivePortals.html)
    * **Presentations/Talks/Videos**
* **Tools**
    * [cpscam](https://github.com/codewatchorg/cpscam)
        * Bypass captive portals by impersonating inactive users



---------------------
### <a name="fax"></a> Fax
* [What the Fax?! - Eyal Itkin, Yaniv Balmas - DEF CON 26](https://www.youtube.com/watch?v=qLCE8spVX9Q)
    * Join us as we take you through the strange world of embedded operating systems, 30-year-old protocols, museum grade compression algorithms, weird extensions and undebuggable environments. See for yourself first-hand as we give a live demonstration of the first ever full fax exploitation, leading to complete control over the entire device as well as the network, using nothing but a standard telephone line. 


---------------------
### <a name="hadoop"></a>Hadoop
* **101**
    * [Introduction to Apache Hadoop - Melissa Anderson](https://www.digitalocean.com/community/tutorials/an-introduction-to-hadoop)
    * [What is Hadoop? Introduction to Big Data & Hadoop - Shubham Sinha](https://www.edureka.co/blog/what-is-hadoop/)
    * [Apache Hadopo - Introduction - hadoop.apache.org](https://hadoop.apache.org/docs/r3.2.0/hadoop-project-dist/hadoop-common/filesystem/introduction.html)
    * [Hadoop Starter Kit - Hadoop in Real World(Udemy)](https://www.udemy.com/course/hadoopstarterkit/)
        * The objective of this course is to walk you through step by step of all the core components in Hadoop but more importantly make Hadoop learning experience easy and fun.
    * [The Hadoop Ecosystem Table](https://hadoopecosystemtable.github.io/)
        * This page is a summary to keep the track of Hadoop related projects, focused on FLOSS environment.
* **Articles/Blogposts/Writeups**
    * [Hadoop Safari Hunting for Vulnerabilities - Thomas Debize, Mehdi Braik - PHDays](https://www.slideshare.net/phdays/hadoop-76515903)
    * [Cloud Security in Map/Reduce - An Analysis - Jason Schlesinger(2009)](http://hackedexistence.com/downloads/Cloud_Security_in_Map_Reduce.pdf)
    * [Securing Hadoop: Security Recommendations for Hadoop Environments - Securosis(2016)](https://securosis.com/assets/library/reports/Securing_Hadoop_Final_V2.pdf)
    * [SANS Cloudera Hadoop Hardening Checklist Guide](https://www.sans.org/score/checklists/cloudera-security-hardening)
    * [Ports Used by Components of CDH 5 - cloudera.com](https://www.cloudera.com/documentation/enterprise/latest/topics/cdh_ig_ports_cdh5.html)
* **Talks & Presentations**
    * [Big problems with big data - Hadoop interfaces security - AppSecEU16](https://www.youtube.com/watch?v=ClXKGI8AzTk)
       * [Slides - Big problems with big data – Hadoop interfaces security - Jakub Kaluzny - ZeroNights, Moscow 2015](http://2015.zeronights.org/assets/files/03-Kaluzny.pdf)
    * [Hadoop Security Design? Just Add Kerberos? Really? - Andrew Becherer - BHUSA2010](https://www.youtube.com/watch?v=Z-1KESMfLKg)
        * This talk will describe the types of attacks the Hadoop team attempted to prevent as well as the types of attacks the Hadoop team decided to ignore. We will determine whether Hadoop was made any more secure through the application of copious amounts of kerberos. We will complete the talk with a short discussion of how to approach a Hadoop deployment from the perspective of an penetration tester. 
        * [Slides](https://media.blackhat.com/bh-us-10/presentations/Becherer/BlackHat-USA-2010-Becherer-Andrew-Hadoop-Security-slides.pdf)
* **Tools**
    * [Hadoop Attack Library](https://github.com/wavestone-cdt/hadoop-attack-library)
        * A collection of pentest tools and resources targeting Hadoop environments





------------------------------------------------------------------------------------------------------------------------------------
### <a name="memcache"></a> Memcache
* **101**
* **Articles/Blogposts/Writeups**
    * [Memcache Exploit - Rohit Salecha](http://niiconsulting.com/checkmate/2013/05/memcache-exploit/)
* **Presentations/Talks/Videos**
* **Tools**







------------------------------------------------------------------------------------------------------------------------------------
### <a name="nat"></a> NAT(Netork Address Translation)
* **101**
* **Articles/Blogposts/Writeups**
    * [A Tale From Defcon and the Fun of BNAT](https://blog.rapid7.com/2011/08/26/a-tale-from-defcon-and-the-fun-of-bnat/)
    * [Advanced BNAT in the Wild - Jonathan Claudius](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/advanced-bnat-in-the-wild/)
    * [NAT-PMP Implementation and Configuration Vulnerabilities - Rapid7](https://blog.rapid7.com/2014/10/21/r7-2014-17-nat-pmp-implementation-and-configuration-vulnerabilities/)
* **Presentations/Talks/Videos**
    * [BNAT Hijacking: Repairing Broken Communication Channels - Jonathan Claudius - AIDE 2012](http://www.irongeek.com/i.php?page=videos/aide2012/bnat-hijacking-repairing-broken-communication-channels-jonathan-claudius)
* **Tools**
    * [bnat](https://github.com/claudijd/bnat)
        * "Broken NAT" - A suite of tools focused on detecting and interacting with publicly available BNAT scenerios







--------------
### <a name="printers"></a> Printers
* **101**
    * [Hacking Printers Wiki](http://hacking-printers.net/wiki/index.php/Main_Page)
* **Articles/Blogposts/Writeups**
    * [Printer Security - Jens Müller, Juraj Somorovsky, Vladislav Mladenov](https://web-in-security.blogspot.com/2017/01/printer-security.html)
* **Papers**
    * [Exploiting Network Printers: A Survey of Security Flaws in Laser Printers and Multi-Function Devices - ](https://www.nds.ruhr-uni-bochum.de/media/ei/arbeiten/2017/01/30/exploiting-printers.pdf)
        * Over the last decades printers have evolved from mechanic devices with microchips to full blown computer systems. From a security point of view these machines remained unstudied for a long time. This work is a survey of weaknesses in the standards and various proprietary extensions of two popular printing languages: PostScript and PJL. Based on tests with twenty laser printer models from various vendors practical attacks were systematically performed and evaluated including denial of service, resetting the device to factory defaults, bypassing accounting systems, obtaining and manipulating print jobs, accessing the printers’ file system and memory as well as code execution through malicious firmware updates and software packages. A generic way to capture PostScript print jobs was discovered. Even weak attacker models like a web attacker are capable of performing the attacks using advanced cross-site printing techniques.
* **Talks & Presentations**
    * [Attacking *multifunction* printers and getting creds from them](http://www.irongeek.com/i.php?page=videos/bsidescleveland2014/plunder-pillage-and-print-the-art-of-leverage-multifunction-printers-during-penetration-testing-deral-heiland)
    * [Print Me If You Dare Firmware Modification Attacks and the Rise of Printer Malware - Ang Cui, Jonathan Voris - 28C3](https://www.youtube.com/watch?v=njVv7J2azY8&feature=youtu.be)
        * We first present several generic firmware modification attacks against HP printers. Weaknesses within the firmware update process allows the attacker to make arbitrary modifications to the NVRAM contents of the device. The attacks we present exploit a functional vulnerability common to all HP printers, and do not depend on any specific code vulnerability. These attacks cannot be prevented by any authentication mechanism on the printer, and can be delivered over the network, either directly or through a print server (active attack) and as hidden payloads within documents (reflexive attack). Next, we describe the design and operation a sophisticated piece of malware for HP (P2050) printers. Essentially a VxWorks rootkit, this malware is equipped with: port scanner, covert reverse-IP proxy, print-job snooper that can monitor, intercept, manipulate and exfiltrate incoming print-jobs, a live code update mechanism, and more (see presentation outline below). Lastly, we will demonstrate a self-propagation mechanism, turning this malware into a full-blown printer worm. Lastly, we present an accurate distribution of all HP printers vulnerable to our attack, as determined by our global embedded device vulnerability scanner (see [1](http://www.ids.cs.columbia.edu/sites/default/files/paper-acsac.pdf)). Our scan is still incomplete, but extrapolating from available data, we estimate that there exist at least 100,000 HP printers that can be compromised through an active attack, and several million devices that can be compromised through reflexive attacks. We will present a detailed breakdown of the geographical and organizational distribution of observable vulnerable printers in the world.
* **Tools**
    * [PRET](https://github.com/RUB-NDS/PRET)
        * PRET is a new tool for printer security testing developed in the scope of a Master's Thesis at Ruhr University Bochum. It connects to a device via network or USB and exploits the features of a given printer language. Currently PostScript, PJL and PCL are supported which are spoken by most laser printers. This allows cool stuff like capturing or manipulating print jobs, accessing the printer's file system and memory or even causing physical damage to the device. All attacks are documented in detail in the Hacking Printers Wiki.
    * [HPwn - HP printer security research code](https://github.com/foxglovesec/HPwn)
        * This repository contains varios scripts and projects referenced in FoxGlove security's HP printer blogpost.




------------
### <a name="proxy"></a>Proxies
* **Tools**
    * **General(Not designed for attackers)**
        * [Squid Proxy](http://www.squid-cache.org/)
            * Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator. It runs on most available operating systems, including Windows and is licensed under the GNU GPL.
    * **TCP/UDP**
        * [Mallory](https://bitbucket.org/IntrepidusGroup/mallory)
            * Mallory is an extensible TCP/UDP man in the middle proxy that is designed  to be run as a gateway. Unlike other tools of its kind, Mallory supports  modifying non-standard protocols on the fly.
        * [Echo Mirage](http://www.wildcroftsecurity.com/echo-mirage)
            * Echo Mirage is a generic network proxy. It uses DLL injection and function hooking techniques to redirect network related function calls so that data transmitted and received by local applications can be observed and modified. Windows encryption and OpenSSL functions are also hooked so that plain text of data being sent and received over an encrypted session is also available. Traffic can be intercepted in real-time, or manipulated with regular expressions and a number of action directives
        * [TCP Catcher](http://www.tcpcatcher.org/)
            * TcpCatcher is a free TCP, SOCKS, HTTP and HTTPS proxy monitor server software. 
        * [SharpSocks](https://github.com/nettitude/SharpSocks)
            * Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        * [ssf - Secure Socket Funneling](https://github.com/securesocketfunneling/ssf)
            * Network tool and toolkit. It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS tunnel to a remote computer. SSF is cross platform (Windows, Linux, OSX) and comes as standalone executables.
        * [PowerCat](https://github.com/secabstraction/PowerCat)
            * A PowerShell TCP/IP swiss army knife that works with Netcat & Ncat
        * [goprox](https://github.com/3lpsy/goprox)
            * Just need a simple proxy that supports unauthenticated or authenticated connections? Don't want to edit another squid config? Need simple pivoting in, out, or within a network? This may be the proxy for you!
        * [chisel](https://github.com/jpillora/chisel)
           * Chisel is a fast TCP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network. Chisel is very similar to crowbar though achieves much higher performance.
    * **DNS**
        * [Phreebird](http://dankaminsky.com/phreebird/) 
            * Phreebird is a DNSSEC proxy that operates in front of an existing DNS server (such as BIND, Unbound, PowerDNS, Microsoft DNS, or QIP) and supplements its records with DNSSEC responses. Features of Phreebird include automatic key generation, realtime record signing, support for arbitrary responses, zero configuration, NSEC3 -White Lies-, caching and rate limiting to deter DoS attacks, and experimental support for both Coarse Time over DNS and HTTP Virtual Channels. The suite also contains a large amount of sample code, including support for federated identity over OpenSSH. Finally, -Phreeload- enhances existing OpenSSL applications with DNSSEC support.
        * [DNS Chef](https://github.com/amckenna/DNSChef)
            * This is a fork of the DNSChef project v0.2.1 hosted at: http://thesprawl.org/projects/dnschef/
    * **HTTP/HTTPS**
        * [Burp Proxy](http://portswigger.net/burp/proxy.html)
            * Burp Proxy is an intercepting proxy server for security testing of web applications. It operates as a man-in-the-middle between your browser and the target application
        * [OWASP Zed Attack Proxy](http://www.zaproxy.org/)
        * [Zed Attack Proxy (ZAP) Community Scripts](https://github.com/zaproxy/community-scripts)
            * A collection of ZAP scripts provided by the community - pull requests very welcome! 
        * [Charles Proxy](https://www.charlesproxy.com/)
            * Charles is an HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet. This includes requests, responses and the HTTP headers (which contain the cookies and caching information).
    * **SSL/TLS**
        * [SSLStrip](http://www.thoughtcrime.org/software/sslstrip/)
            * This tool provides a demonstration of the HTTPS stripping attacks that I presented at Black Hat DC 2009. It will transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.










-----------------------------------------------------------------------------------------------------------------------------------------------
### <a name="pxe"></a>PXE
* **101** 
    * [Preboot Execution Environment - Wikipedia](https://en.wikipedia.org/wiki/Preboot_Execution_Environment)
    * [NetworkBoot.org](https://networkboot.org/)
        * A place where beginners can learn the fundamentals of network booting.
* **Educational**
* **Attacks**
    * **Articles/Presentations/Talks/Writeups**
        * [Use DHCP to detect UEFI or Legacy BIOS system and PXE boot to SCCM](http://www.itfaq.dk/2016/07/27/use-dhcp-to-detect-uefi-or-legacy-bios-system-and-pxe-boot-to-sccm/)
        * [Attacks Against Windows PXE Boot Images - Thomas Elling](https://blog.netspi.com/attacks-against-windows-pxe-boot-images/)
        * [Network Nightmare – PXE talk at Defcon - scriptjunkie.us](https://www.scriptjunkie.us/2011/08/network-nightmare/)
* **Tools**
    * [PowerPXE](https://github.com/wavestone-cdt/powerpxe)
    * PowerPXE is a PowerShell script that extracts interesting data from insecure PXE boot.
    * [BCD](https://github.com/mattifestation/BCD)
        * BCD is a module to interact with boot configuration data (BCD) either locally or remotely using the ROOT/WMI:Bcd* WMI classes. The functionality of the functions in this module mirror that of bcdedit.exe.





-------------------------------------------------------------------------------------------------------------------------------------------------
### <a name="redis"></a>Redis
* **101** 
    * [redis - Wikipedia](https://en.wikipedia.org/wiki/Redis)
    * [Introduction to redis - redis.io](https://redis.io/topics/introduction)
* **Articles/Presentations/Talks/Writeups**
    * [redis security - redis.io](https://redis.io/topics/security)
    * [A Few Things About redis Security - antirez](http://antirez.com/news/96)
    * [Securing redis - redis.io](https://redis.io/topics/quickstart#securing-redis)
    * [Pentesting Redis Servers - averagesecurityguy](https://averagesecurityguy.github.io/code/pentest/2015/09/17/pentesting-redis-servers/)
* **Tools**
    * [redis-dump](http://delanotes.com/redis-dump/)
    * [Script attempted to create global variable - Stackoverflow](https://stackoverflow.com/questions/19997647/script-attempted-to-create-global-variable)




-------------
### <a name="sdn"></a>Software Defined Networking (SDN)
* **101** 
* **Articles/Presentations/Talks/Writeups**
    * [Finding the Low-Hanging Route](https://labs.mwrinfosecurity.com/blog/routing-101/)
* **Tools**
    * [DELTA: SDN SECURITY EVALUATION FRAMEWORK](https://github.com/OpenNetworkingFoundation/DELTA)
        * DELTA is a penetration testing framework that regenerates known attack scenarios for diverse test cases. This framework also provides the capability of discovering unknown security problems in SDN by employing a fuzzing technique.


-------------
### <a name="switches"></a>Switches(Network Hardware)
* **101** 
* **Articles/Presentations/Talks/Writeups**
    * [Switches Get Stitches (or: Switches Get DNA Helicased) - Dale Peterson](https://dale-peterson.com/2015/06/15/switches-get-stitches-or-switches-get-dna-helicased/)
* **Talks/Presentations/Videos**
    * [Switches Get Stitches - Eireann Leverett(31c3)](https://www.youtube.com/watch?v=GaeLWpow-u8)
        * This talk will introduce you to Industrial Ethernet Switches and their vulnerabilities. These are switches used in industrial environments, like substations, factories, refineries, ports, or other other homes of industrial automation. In other words: DCS, PCS, ICS & SCADA switches. It is a very good companion talk to Damn Vulnerable Chemical Process? Own your own critical infrastructures today!
    * [Switches Get Stitches - Colin Cassidy, Robert Lee, Eireann Leverett(BHUSA15)](https://www.youtube.com/watch?v=urjKkQaspHQ)
        * This talk will introduce you to Industrial Ethernet Switches and their vulnerabilities. These are switches used in industrial environments, like substations, factories, refineries, ports, or other homes of industrial automation. In other words: DCS, PCS, ICS & SCADA switches. The researchers focus on attacking the management plane of these switches, because we all know that industrial system protocols lack authentication or cryptographic integrity. Thus, compromising any switch allows the creation of malicious firmwares for further MITM manipulation of a live process. Such MITM manipulation can lead to the plant or process shutting down (think: nuclear reactor SCRAM) or getting into a unknown and hazardous state (think: damaging a blast furnace at a steel mill). Not only will vulnerabilities be disclosed for the first time (exclusively at Black Hat), but the methods of finding those vulnerabilities will be shared. All vulnerabilities disclosed will be in the default configuration state of the devices. While these vulnerabilities have been responsibly disclosed to the vendors, SCADA/ICS patching in live environments tends to take 1-3 years. Because of this patching lag, the researchers will also be providing live mitigations that owner/operators can use immediately to protect themselves. At least four vendors switches will be examined: Siemens, GE, Garrettcom, and Opengear.
* **Tools**





------------
#### <a name="vlan"></a>VLANs
* **101**
    * [Virtual LAN](https://en.wikipedia.org/wiki/Virtual_LAN)
    * [Virtual Local Area Networks](https://www.cse.wustl.edu/~jain/cis788-97/ftp/virtual_lans/index.html)
* **General/Articles/Writeups**
    * [VLAN hopping, ARP Poisoning and Man-In-The-Middle Attacks in Virtualized Environments - Ronny L. Bull - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/110-vlan-hopping-arp-poisoning-and-man-in-the-middle-attacks-in-virtualized-environments-dr-ronny-l-bull)
        * Cloud service providers and data centers offer their customers the ability to deploy virtual machines within multi-tenant environments. These virtual machines are typically connected to the physical network via a virtualized network configuration. This could be as simple as a bridged interface to each virtual machine or as complicated as a virtual switch providing more robust networking features such as VLANs, QoS, and monitoring. In this talk I will demonstrate the effects of VLAN hopping, ARP poisoning and Man-in-the-Middle attacks across every major hypervisor platform, including results of attacks originating from the physically connected network as well as within the virtual networks themselves. Each attack category that is discussed will be accompanied by a detailed proof of concept demonstration of the attack.
    * [Frogger2 - VLAN Hopping](https://github.com/commonexploits/vlan-hopping)
        * Simple VLAN enumeration and hopping script. Developed by Daniel Compton
