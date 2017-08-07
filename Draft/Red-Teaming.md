# Red Teaming & Explicitly Pen testing stuff



#### ToC
* Sort
* Talks/Videos
* Articles/Blogposts
* Papers
* Tools

### Sort


#### End sort



### General

[Common Ground Part 1: Red Team History & Overview](https://www.sixdub.net/?p=705)

[Red Teaming Tips - Vincent Yiu](https://threatintel.eu/2017/06/03/red-teaming-tips-by-vincent-yiu/)

[Red Team Tips as posted by @vysecurity on Twitter](https://github.com/vysec/RedTips)

[Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
* Wiki to collect Red Team infrastructure hardening resources
* Accompanying Presentation: [Doomsday Preppers: Fortifying Your Red Team Infrastructure](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure)




### Talks/Videos

[Laurent Desaulniers - Stupid RedTeamer Tricks](https://www.youtube.com/watch?v=2g_8oHM0nwA&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=11)

[Dimitry Snezhkov - Abusing Webhooks for Command and Control](https://www.youtube.com/watch?v=1d3QCA2cR8o&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=12)

[Finding Diamonds in the Rough- Parsing for Pentesters](https://bluescreenofjeff.com/2016-07-26-finding-diamonds-in-the-rough-parsing-for-pentesters/)

[Attacking EvilCorp: Anatomy of a Corporate Hack](http://www.irongeek.com/i.php?page=videos/derbycon6/111-attacking-evilcorp-anatomy-of-a-corporate-hack-sean-metcalf-will-schroeder)

[Looping Surveillance Cameras through Live Editing - Van Albert and Banks - Defcon23](https://www.youtube.com/watch?v=RoOqznZUClI)
* This project consists of the hardware and software necessary to hijack wired network communications. The hardware allows an attacker to splice into live network cabling without ever breaking the physical connection. This allows the traffic on the line to be passively tapped and examined. Once the attacker has gained enough knowledge about the data being sent, the device switches to an active tap topology, where data in both directions can be modified on the fly. Through our custom implementation of the network stack, we can accurately mimic the two devices across almost all OSI layers.
* We have developed several applications for this technology. Most notable is the editing of live video streams to produce a “camera loop,” that is, hijacking the feed from an Ethernet surveillance camera so that the same footage repeats over and over again. More advanced video transformations can be applied if necessary. This attack can be executed and activated with practically no interruption in service, and when deactivated, is completely transparent.

[Richard Thieme - The Impact of Dark Knowledge and Secrets on Security and Intelligence Professionals](https://www.youtube.com/watch?v=0MzcPBAj88A&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe)
* Dismissing or laughing off concerns about what it does to a person to know critical secrets does not lessen the impact on life, work, and relationships of building a different map of reality than “normal people” use. One has to calibrate narratives to what another believes. One has to live defensively, warily. This causes at the least cognitive dissonance which some manage by denial. But refusing to feel the pain does not make it go away. It just intensifies the consequences when they erupt.
Philip K. Dick said, reality is that which, when you no longer believe in it, does not go away. When cognitive dissonance evolves into symptoms of traumatic stress, one ignores those symptoms at one’s peril. But the very constraints of one’s work often make it impossible to speak aloud about those symptoms, because that might threaten one’s clearances, work, and career. And whistle blower protection is often non-existent.

[303 Hacks Lies Nation States Mario DiNatale](https://www.youtube.com/watch?v=nyh_ORq1Qwk)



### Slides

[Make It Count: Progressing through Pentesting - Bálint Varga-Perke -Silent Signal](https://silentsignal.hu/docs/Make_It_Count_-_Progressing_through_Pentesting_Balint_Varga-Perke_Silent_Signal.pdf)






### Articles / Blogposts

[Fools of Golden Gate](https://blog.silentsignal.eu/2017/05/08/fools-of-golden-gate/)
* How major vulnerabilities/large amounts of publicly vulnerable systems can exist without public recognition for long periods of time. (i.e. CVEs(10.0) exist, but no mapping in nessus/metasploit/etc)

[how-to-make-communication-profiles-for-empire](https://github.com/bluscreenofjeff/bluscreenofjeff.github.io/blob/master/_posts/2017-03-01-how-to-make-communication-profiles-for-empire.md)

[Empire – Modifying Server C2 Indicators](http://threatexpress.com/2017/05/empire-modifying-server-c2-indicators/)

[Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)

[Hiding Malicious Traffic Under the HTTP 404 Error](https://blog.fortinet.com/2015/04/09/hiding-malicious-traffic-under-the-http-404-error)

[How to Build a 404 page not found C2](https://www.blackhillsinfosec.com/?p=5134)

[404 File not found C2 PoC](https://github.com/theG3ist/404)

[#OLEOutlook - bypass almost every Corporate security control with a point’n’click GUI](https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0)


[Penetration Testing considered Harmful Today](http://blog.thinkst.com/p/penetration-testing-considered-harmful.html)




### Papers

[Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/papers/fronting/)



### Tools

[PenTesting-Scripts - killswitch-GUI](https://github.com/killswitch-GUI/PenTesting-Scripts)

[stupid_malware](https://github.com/andrew-morris/stupid_malware)
* Python malware for pentesters that bypasses most antivirus (signature and heuristics) and IPS using sheer stupidity








##### HW
[DigiDucky - How to setup a Digispark like a rubber ducky](http://www.redteamr.com/2016/08/digiducky/)

[How to Build Your Own Penetration Testing Drop Box - BHIS](https://www.blackhillsinfosec.com/?p=5156&)

###### SW

[FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains)
* Search for potential frontable domains

[Domain Hunter](https://github.com/minisllc/domainhunter)
* Checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names

[Chameleon](https://github.com/mdsecactivebreach/Chameleon)
* A tool for evading Proxy categorisation






