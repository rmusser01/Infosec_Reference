### Exfiltration


##### TOC

* [General](#general)
* [Methodologies](#methods)
* [Tools](#tools)
* [Papers](#papers)


### Cull
Stunnel
[Learn how to hide your trojans, backdoors, etc from anti virus.](https://www.hellboundhackers.org/articles/read-article.php?article_id=842)

[[Virus] Self-modifying code-short overview for beginners](http://phimonlinemoinhat.blogspot.com/2010/12/virus-self-modifying-code-short.html)

[PlugBot-C2C](https://github.com/redteamsecurity/PlugBot-C2C)
* This is the Command & Control component of the PlugBot project

[Data Exfiltration (Tunneling) Attacks against Corporate Network](https://pentest.blog/data-exfiltration-tunneling-attacks-against-corporate-network/)

[canisrufus](https://github.com/maldevel/canisrufus)
* A stealthy Python based Windows backdoor that uses Github as a command and control server

https://github.com/sensepost/det


iodine


http://windowsir.blogspot.com/2013/07/howto-data-exfiltration.html

### <a name="general">General</a>




### <a name="methods">Methodologies</a>



Gmail/other email services Draft emails
Draft emails




### <a name="tools">Tools</a>

[iodine](https://github.com/yarrick/iodine)
* This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed.

[dnscat2](https://github.com/iagox86/dnscat2)
* Welcome to dnscat2, a DNS tunnel that WON'T make you sick and kill you!  This tool is designed to create a command-and-control (C&C) channel over the DNS protocol, which is an effective tunnel out of almost every network.

[fraud-bridge](https://github.com/stealth/fraud-bridge) 
* fraud-bridge allows to tunnel TCP connections through ICMP, ICMPv6, DNS via UDP or DNS via UDP6. Project, not stable

[PyExfil](https://ytisf.github.io/PyExfil/)
* Exfiltration tools inspired by Regin. Alpha Status.

[Exfil - Modular tool to test exfiltration techniques](https://github.com/averagesecurityguy/exfil)
* Exfil is a tool designed to exfiltrate data using various techniques, which allows a security team to test whether its monitoring system can effectively catch the exfiltration. The idea for Exfil came from a Twitter conversation between @averagesecguy, @ChrisJohnRiley, and @Ben0xA and was sparked by the TrustWave POS malware whitepaper available at https://gsr.trustwave.com/topics/placeholder-topic/point-of-sale-malware/.

[Multitun](https://github.com/covertcodes/multitun) 
* Efficiently and securely tunnel everything over a harmless looking WebSocket!


### Papers
[Self-Exfiltration: The Dangers of Browser-Enforced Information Flow Control](http://ericchen.me/self_exfiltration.pdf)
* Abstract —Since the early days of Netscape, browser vendors and web security researchers have restricted out-going data based on its destination. The security argument accompanying these mechanisms is that they prevent sensitive user data from being sent to the attacker’s domain. However, in this paper, we show that regulating web information flow based on its destination server is an inherently flawed security practice. It is vulnerable to self-exfiltration attacks, where an adversary stashes stolen information in the database of a whitelisted site, then later independently connects to the whitelisted site to retrieve the information. We describe eight existing browser security mechanisms that are vulnerable to these “self-exfiltration” attacks. Furthermore, we discovered at least one exfiltration channel for each of the Alexa top 100 websites. None of the existing information flow control mechanisms we surveyed are sufficient to protect data from being leaked to the attacker. Our goal is to prevent browser vendors and researchers from falling into this trap by designing more systems that are vulnerable to self-exfiltration.

